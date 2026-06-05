"""End-to-end test of the encrypted handshake + an encrypted read.

A fake BleakClient plays the *device* side, faithfully mirroring the protocol
reverse-engineered from the app: it derives the same handshake key, verifies
*our* ECDSA signature with the client public key, completes the ECDH exchange,
and answers an encrypted Modbus read.  This exercises the whole client state
machine (crypto + framing + request/response) without real hardware.
"""

import asyncio
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

import bluetti_monitor.client as client_mod
from bluetti_monitor import const, crypto
from bluetti_monitor.crc import append_crc
from bluetti_monitor.client import BluettiClient


class _Char:
    def __init__(self, uuid):
        self.uuid = uuid


class _Service:
    def __init__(self):
        self._chars = {const.WRITE_UUID: _Char(const.WRITE_UUID),
                       const.NOTIFY_UUID: _Char(const.NOTIFY_UUID)}

    def get_characteristic(self, uuid):
        return self._chars.get(uuid)


class _Services:
    def __init__(self):
        self._svc = _Service()

    def get_service(self, uuid):
        return self._svc if uuid == const.SERVICE_UUID else None


class FakeDevice:
    """Device-side protocol simulator."""

    def __init__(self):
        self.random4 = os.urandom(4)
        self.random_md5 = crypto.random_md5_from_hello(self.random4)
        self.aes_key = crypto.handshake_key(self.random_md5)
        self.iot_priv = crypto.generate_ecdh_keypair()
        self.iot_pub = crypto.public_key_raw(self.iot_priv)
        self.shared_key = None
        self.notify = None  # set by client.start_notify

    # -- frames the device emits -------------------------------------------
    def hello(self) -> bytes:
        return const.HS_MAGIC + bytes([const.HS_HELLO, 0x04]) + self.random4

    def pubkey_frame(self) -> bytes:
        sig = bytes(64)  # client does not verify the device signature
        payload = self.iot_pub + sig
        body = const.HS_MAGIC + bytes([const.HS_PUBKEY, len(payload) & 0xFF]) + payload
        body += crypto.hex_sum(body[2:], 2)
        return crypto.build_encrypted_frame(body, self.aes_key, iv=self.random_md5)

    def done_frame(self) -> bytes:
        body = const.HS_MAGIC + bytes([const.HS_DONE, 0x00])
        return crypto.build_encrypted_frame(body, self.aes_key, iv=self.random_md5)

    # -- handle a write from the client ------------------------------------
    def handle(self, data: bytes):
        out = []
        if data[0:2] == const.HS_MAGIC and data[2] == const.HS_ACK:
            # ACK received -> send our public key + signature.
            out.append(self.pubkey_frame())
        elif self.shared_key is None:
            # Expect the encrypted sign frame.
            plain = crypto.parse_encrypted_frame(data, self.aes_key, iv=self.random_md5)
            assert plain[0:2] == const.HS_MAGIC and plain[2] == const.HS_SIGN
            our_pub = plain[4:68]
            sig = plain[68:132]
            self._verify_client_sig(our_pub, sig)
            self.shared_key = crypto.ecdh_shared_secret(self.iot_priv, our_pub)
            out.append(self.done_frame())
        else:
            # Encrypted Modbus read -> answer with a home-data payload.
            cmd = crypto.parse_encrypted_frame(data, self.shared_key, iv=None)
            out.append(self._modbus_response(cmd))
        return out

    def _verify_client_sig(self, our_pub, sig):
        pub = ec.derive_private_key(int(const.CLIENT_PRIVATE_KEY_HEX, 16),
                                    ec.SECP256R1()).public_key()
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        signed = our_pub + self.random_md5
        pub.verify(encode_dss_signature(r, s), signed, ec.ECDSA(hashes.SHA256()))

    def _modbus_response(self, cmd: bytes) -> bytes:
        # cmd = 01 03 addr(2) count(2) crc(2)
        count = int.from_bytes(cmd[4:6], "big")
        payload = bytearray(count * 2)
        payload[66:68] = (91).to_bytes(2, "big")  # battery_soc = 91
        frame = append_crc(bytes([0x01, 0x03, len(payload)]) + bytes(payload))
        return crypto.build_encrypted_frame(frame, self.shared_key, iv=None)


class FakeBleakClient:
    def __init__(self, address, timeout=None):
        self.address = address
        self.is_connected = False
        self.mtu_size = 247
        self.services = _Services()
        self.device = FakeDevice()
        self._notify_cb = None

    async def connect(self):
        self.is_connected = True

    async def disconnect(self):
        self.is_connected = False

    async def start_notify(self, uuid, cb):
        self._notify_cb = cb
        # Device greets immediately after notifications are enabled.
        asyncio.get_running_loop().call_soon(self._emit, self.device.hello())

    async def stop_notify(self, uuid):
        self._notify_cb = None

    def _emit(self, frame: bytes):
        if self._notify_cb:
            self._notify_cb(None, bytearray(frame))

    async def write_gatt_char(self, char, data, response=False):
        for frame in self.device.handle(bytes(data)):
            self._emit(frame)


@pytest.mark.asyncio
async def test_encrypted_handshake_and_read(monkeypatch):
    monkeypatch.setattr(client_mod, "BleakClient", FakeBleakClient)
    client = BluettiClient("FA:KE:00:00:00:01", encrypted=True)
    await client.connect()
    assert client._shared_key is not None
    resp = await client.read_registers(0x0A, 0x3B)
    assert resp.registers[33] == 91  # battery_soc at register offset 33
    await client.disconnect()


class FakePlainBleakClient(FakeBleakClient):
    """Plaintext device: no handshake, raw Modbus reads."""

    async def start_notify(self, uuid, cb):
        self._notify_cb = cb  # no hello frame

    async def write_gatt_char(self, char, data, response=False):
        data = bytes(data)
        count = int.from_bytes(data[4:6], "big")
        payload = bytearray(count * 2)
        payload[66:68] = (77).to_bytes(2, "big")
        frame = append_crc(bytes([0x01, 0x03, len(payload)]) + bytes(payload))
        self._emit(frame)


@pytest.mark.asyncio
async def test_plaintext_read(monkeypatch):
    monkeypatch.setattr(client_mod, "BleakClient", FakePlainBleakClient)
    client = BluettiClient("FA:KE:00:00:00:02", encrypted=False)
    await client.connect()
    resp = await client.read_registers(0x0A, 0x3B)
    assert resp.registers[33] == 77
    await client.disconnect()
