"""Async BLE client for Bluetti devices (plaintext and encrypted).

Implements the connection + handshake state machine reverse-engineered from
net.poweroak.bluetticloud.ui.connect.ConnectManager.  Designed for polling /
monitoring: reads are serialised through a single request lock.
"""

from __future__ import annotations

import asyncio
import logging

from bleak import BleakClient, BleakScanner

from . import const, crypto
from .protocol import (
    ModbusError,
    build_read_command,
    build_write_single,
    expected_response_length,
    parse_read_response,
)

log = logging.getLogger(__name__)


class BluettiClientError(Exception):
    pass


class BluettiClient:
    """Connect to one Bluetti device and read/write Modbus registers."""

    def __init__(self, address: str, encrypted: bool | None = None, name: str | None = None,
                 timeout: float = 20.0):
        self.address = address
        self.name = name
        # If unspecified, infer from advertised name prefix.
        if encrypted is None and name is not None:
            encrypted = name.upper().startswith(const.ADV_NAME_ENCRYPTED)
        self.encrypted = bool(encrypted)
        self.timeout = timeout

        self._client: BleakClient | None = None
        self._write_char = None
        self._mtu = const.WRITE_SPLIT_COUNT + 3

        self._rx = bytearray()
        self._lock = asyncio.Lock()
        self._response: asyncio.Future | None = None
        self._expected_len: int | None = None

        # Encryption session state.
        self._aes_key: bytes | None = None        # handshake key (AES-128)
        self._shared_key: bytes | None = None      # ECDH key (AES-256)
        self._random_md5: bytes | None = None
        self._ecdh_priv = None
        self._handshake_done = asyncio.Event()

    # -- connection ---------------------------------------------------------
    async def connect(self) -> None:
        # A previous (killed) run can leave the device connected at the BlueZ
        # level — which also stops it advertising, so the scan below fails with
        # "not found".  Proactively drop any lingering connection first.
        await self._clear_stale_bluez_connection()

        # Resolve the address to a device first: BlueZ will not connect to an
        # address it has not recently discovered.  Falls back to connecting by
        # raw address (e.g. a cached CoreBluetooth UUID on macOS).
        target = await BleakScanner.find_device_by_address(self.address, timeout=self.timeout)
        self._client = BleakClient(target or self.address, timeout=self.timeout)
        await self._client.connect()
        log.info("connected to %s", self.address)

        service = self._client.services.get_service(const.SERVICE_UUID)
        if service is None:
            raise BluettiClientError("Bluetti service ff00 not found")
        self._write_char = service.get_characteristic(const.WRITE_UUID)
        if self._write_char is None:
            raise BluettiClientError("write characteristic ff02 not found")
        try:
            self._mtu = self._client.mtu_size
        except Exception:  # pragma: no cover - backend dependent
            pass

        await self._client.start_notify(const.NOTIFY_UUID, self._on_notify)

        if self.encrypted:
            log.info("performing encrypted handshake")
            try:
                await asyncio.wait_for(self._handshake_done.wait(), timeout=self.timeout)
            except asyncio.TimeoutError as exc:
                raise BluettiClientError("encrypted handshake timed out") from exc
            log.info("handshake complete")

    async def _clear_stale_bluez_connection(self) -> None:
        """Best-effort: if BlueZ still holds a connection to our device (e.g.
        from a killed run), disconnect it so we can reconnect and so it resumes
        advertising.  Linux/BlueZ only; silently skipped elsewhere.
        """
        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast.constants import BusType
        except Exception:
            return  # not a dbus-fast/BlueZ platform (e.g. macOS)
        bus = None
        try:
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            intro = await bus.introspect("org.bluez", "/")
            mgr = bus.get_proxy_object("org.bluez", "/", intro).get_interface(
                "org.freedesktop.DBus.ObjectManager"
            )
            target = self.address.upper()
            for path, ifaces in (await mgr.call_get_managed_objects()).items():
                dev = ifaces.get("org.bluez.Device1")
                if not dev:
                    continue
                addr = dev.get("Address")
                connected = dev.get("Connected")
                if addr and addr.value.upper() == target and connected and connected.value:
                    dintro = await bus.introspect("org.bluez", path)
                    di = bus.get_proxy_object("org.bluez", path, dintro).get_interface(
                        "org.bluez.Device1"
                    )
                    await di.call_disconnect()
                    log.info("cleared stale BlueZ connection to %s", self.address)
                    await asyncio.sleep(2)  # let it start advertising again
        except Exception as exc:  # noqa: BLE001 - best effort
            log.debug("stale-connection clear skipped: %s", exc)
        finally:
            if bus is not None:
                try:
                    bus.disconnect()
                except Exception:
                    pass

    async def disconnect(self) -> None:
        if self._client is not None and self._client.is_connected:
            try:
                await self._client.stop_notify(const.NOTIFY_UUID)
            except Exception:
                pass
            await self._client.disconnect()

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *exc):
        await self.disconnect()

    # -- low-level write ----------------------------------------------------
    async def _write(self, payload: bytes) -> None:
        chunk = max(self._mtu - 3, 20)
        for i in range(0, len(payload), chunk):
            await self._client.write_gatt_char(self._write_char, payload[i : i + chunk], response=False)
            await asyncio.sleep(0.01)

    # -- notification handling ---------------------------------------------
    def _on_notify(self, _char, data: bytearray) -> None:
        self._rx.extend(data)
        try:
            self._consume()
        except Exception:  # pragma: no cover - defensive
            log.exception("error handling notification")

    def _consume(self) -> None:
        # Handshake control frames are raw 0x2A2A frames; data responses are
        # either raw Modbus (plaintext devices) or length-prefixed encrypted
        # frames (after the handshake completes).
        if self.encrypted and not self._handshake_done.is_set():
            self._consume_handshake()
            return

        if self.encrypted:
            self._consume_encrypted_response()
        else:
            self._consume_plain_response()

    # ---- plaintext --------------------------------------------------------
    def _plain_frame_len(self) -> int | None:
        """Total length of the Modbus response currently at the front of rx.

        Sized from the frame itself: a 5-byte exception frame when the function
        code has the high bit set, otherwise 3 (slave+func+bytecount) + payload
        + 2 (CRC).  Returns None until enough bytes are present to decide.
        """
        if len(self._rx) < 2:
            return None
        function = self._rx[1]
        if function & 0x80:
            return 5  # slave, func|0x80, exception code, CRC(2)
        if function in (const.FUNC_WRITE_SINGLE, const.FUNC_WRITE_MULTI):
            return 8  # slave, func, addr(2), value/count(2), CRC(2) — echo, no byte-count
        if len(self._rx) < 3:
            return None
        return 3 + self._rx[2] + 2

    def _consume_plain_response(self) -> None:
        if self._response is None:
            self._rx.clear()
            return
        total = self._plain_frame_len()
        if total is None or len(self._rx) < total:
            return
        frame = bytes(self._rx[:total])
        del self._rx[:total]
        self._resolve(frame)

    # ---- encrypted response ----------------------------------------------
    def _encrypted_frame_len(self, has_rand: bool) -> int | None:
        if len(self._rx) < 2:
            return None
        plain_len = int.from_bytes(self._rx[:2], "big")
        blocks = ((plain_len + 15) // 16) * 16
        return 2 + (4 if has_rand else 0) + blocks

    def _consume_encrypted_response(self) -> None:
        if self._response is None:
            self._rx.clear()
            return
        total = self._encrypted_frame_len(has_rand=True)
        if total is None or len(self._rx) < total:
            return
        frame = bytes(self._rx[:total])
        del self._rx[:total]
        plain = crypto.parse_encrypted_frame(frame, self._shared_key, iv=None)
        self._resolve(plain)

    # ---- handshake --------------------------------------------------------
    def _consume_handshake(self) -> None:
        # Hello: 2A 2A 01 .. (plaintext).  Encrypted control frames after that
        # are length-prefixed with IV = randomMd5.
        if len(self._rx) >= 3 and self._rx[0:2] == const.HS_MAGIC and self._rx[2] == const.HS_HELLO:
            if len(self._rx) < 8:
                return
            info = crypto.parse_hello(bytes(self._rx))
            self._random_md5 = info.random_md5
            self._aes_key = info.aes_key
            self._rx.clear()
            asyncio.create_task(self._send_ack())
            return

        # Encrypted handshake frames (type 0x04 pubkey, 0x06 done).
        total = self._encrypted_frame_len(has_rand=False)
        if total is None or len(self._rx) < total:
            return
        frame = bytes(self._rx[:total])
        del self._rx[:total]
        plain = crypto.parse_encrypted_frame(frame, self._aes_key, iv=self._random_md5)
        if len(plain) < 3 or plain[0:2] != const.HS_MAGIC:
            return
        ftype = plain[2]
        if ftype == const.HS_PUBKEY:
            iot_pub = plain[4:68]
            asyncio.create_task(self._send_sign(iot_pub))
        elif ftype == const.HS_DONE:
            self._handshake_done.set()

    async def _send_ack(self) -> None:
        await self._write(crypto.build_ack_frame(self._random_md5))

    async def _send_sign(self, iot_pub: bytes) -> None:
        self._ecdh_priv = crypto.generate_ecdh_keypair()
        our_pub = crypto.public_key_raw(self._ecdh_priv)
        # The app signs hexStringToBytes(pubKeyHex + randomMd5Hex), i.e. the raw
        # 64-byte public point concatenated with the 16-byte randomMd5 digest.
        signed = our_pub + self._random_md5
        signature = crypto.sign_p1363(signed)
        payload = crypto.build_sign_payload(our_pub, signature)
        frame = crypto.build_encrypted_frame(payload, self._aes_key, iv=self._random_md5)
        # Derive the shared key *before* sending so it is ready by the time the
        # device replies with the "done" frame (avoids an ordering race).
        self._shared_key = crypto.ecdh_shared_secret(self._ecdh_priv, iot_pub)
        await self._write(frame)

    # -- request / response -------------------------------------------------
    def _resolve(self, frame: bytes) -> None:
        if self._response is not None and not self._response.done():
            self._response.set_result(frame)

    async def read_registers(self, addr: int, count: int, retries: int = 2):
        """Read ``count`` registers from ``addr``; returns ``ReadResponse``."""
        async with self._lock:
            cmd = build_read_command(addr, count)
            for attempt in range(retries + 1):
                loop = asyncio.get_running_loop()
                self._response = loop.create_future()
                self._expected_len = expected_response_length(count)
                self._rx.clear()
                payload = cmd
                if self.encrypted:
                    payload = crypto.build_encrypted_frame(cmd, self._shared_key, iv=None)
                await self._write(payload)
                try:
                    frame = await asyncio.wait_for(self._response, timeout=self.timeout)
                    return parse_read_response(frame)
                except (asyncio.TimeoutError, ModbusError) as exc:
                    if attempt >= retries:
                        raise BluettiClientError(f"read {addr}/{count} failed: {exc}") from exc
                    await asyncio.sleep(0.3)
                finally:
                    self._response = None

    async def write_register(self, addr: int, value: int, confirm: bool = True) -> None:
        """Write a single register (function 0x06).

        When ``confirm`` is set, wait for the device's echo response and verify
        it matches the address and value we wrote.
        """
        async with self._lock:
            cmd = build_write_single(addr, value)
            loop = asyncio.get_running_loop()
            self._response = loop.create_future() if confirm else None
            self._rx.clear()
            payload = cmd
            if self.encrypted:
                payload = crypto.build_encrypted_frame(cmd, self._shared_key, iv=None)
            await self._write(payload)
            if not confirm:
                await asyncio.sleep(0.2)
                return
            try:
                frame = await asyncio.wait_for(self._response, timeout=self.timeout)
            except asyncio.TimeoutError as exc:
                raise BluettiClientError(f"write {addr}={value}: no response") from exc
            finally:
                self._response = None
            # Echo: [slave][06][addr:2][value:2][crc].  Verify it round-trips.
            if len(frame) >= 6 and (frame[1] & 0x80):
                raise BluettiClientError(f"write {addr}={value}: modbus exception {frame[2]:#x}")
            echoed_addr = int.from_bytes(frame[2:4], "big")
            echoed_val = int.from_bytes(frame[4:6], "big")
            if echoed_addr != addr or echoed_val != (value & 0xFFFF):
                raise BluettiClientError(
                    f"write {addr}={value}: unexpected echo addr={echoed_addr} val={echoed_val}"
                )


async def scan(timeout: float = 10.0) -> list:
    """Return discovered Bluetti devices as ``(address, name, encrypted)``."""
    found = []
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    for address, (device, adv) in devices.items():
        name = adv.local_name or device.name or ""
        upper = name.upper()
        if upper.startswith(const.ADV_NAME_PLAINTEXT) or upper.startswith(const.ADV_NAME_ENCRYPTED):
            found.append((device.address, name, upper.startswith(const.ADV_NAME_ENCRYPTED)))
    return found
