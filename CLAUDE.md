# CLAUDE.md — bluetti-monitor

## What this is

Python library and Home Assistant MQTT bridge for **Bluetti** power stations
(hardware-verified on an **AC180P**; ~40 models share the protocol). Provides
live monitoring and on/off control of the AC and DC outputs.

The protocol was reverse-engineered from the official Bluetti Android app
(`net.poweroak.bluetticloud`, v3.0.9) using jadx. No official API exists.
Full write-up in [PROTOCOL.md](PROTOCOL.md).

## Repository layout

```
bluetti_monitor/         # importable Python library
  const.py               # BLE UUIDs, hardcoded crypto keys, Modbus function codes
  crc.py                 # CRC16/Modbus
  protocol.py            # Modbus frame build (read/write) + response parsing
  crypto.py              # AES-CBC framing, ECDH (P-256), ECDSA, handshake builders
  fields.py              # field maps (legacy 0x0A + v2 base-100) and Switch defs
  client.py              # BluettiClient — bleak BLE client + handshake state machine
  device.py              # BluettiDevice — poll(), layout auto-detect, set_output()
  mqtt_bridge.py         # MqttBridge — HA discovery, state publish, switch commands
  __main__.py            # CLI: scan / monitor / mqtt
Dockerfile               # python:3.13-slim-bookworm, user=bluetti
docker-compose.yml       # network_mode host, /var/run/dbus, NET_ADMIN/NET_RAW
config.yml.example       # nested config (mqtt:, bluetti:, log_level:)
requirements.txt         # bleak, cryptography, paho-mqtt, pyyaml
tests/                   # pytest: crc, protocol, crypto, fields, handshake e2e
```

## BLE protocol essentials

- **Service** `0000ff00-…`; **Notify** `0000ff01-…` (device→app); **Write**
  `0000ff02-…` (app→device); writes are `response=False`, split to MTU.
- Advertised marker in manufacturer data (company `0x4c42` "BL"): `BLUETTI`
  (hex `…49`) = plaintext, `BLUETTE` (hex `…45`) = encrypted. Some units also
  advertise by model name.
- **Plaintext = standard Modbus RTU**: read `01 03 addr(2) count(2) crc(2)`;
  write single `01 06 addr(2) val(2) crc`; CRC16/Modbus, low byte first
  (check value of "123456789" = 0x4B37).
- **Encrypted** devices do a `2A2A` handshake → ECDH(P-256) shared secret, then
  every Modbus frame is AES-CBC wrapped. Client signing key + AES base key are
  hardcoded in the app and reproduced in `const.py`, so it works offline. See
  `crypto.py` / PROTOCOL.md.

## Register maps — there are two

Devices fall into two families; `BluettiDevice` auto-detects by trying the v2
read first and falling back to legacy (`device.py:_detect`).

**v2** (AC180/AC180P, AC60, AC2A, AC200L, EP600, …) — sparse map, home page read
from **register 100** (`APP_HOME_DATA`, ~60 regs max per read). Byte offsets into
the response payload (`fields.py:V2_FIELDS`):

| Field | Offset | Notes |
|-------|--------|-------|
| pack voltage | 0–1 | u16 ÷100 V (app uses ÷10 but that's 10× too high) |
| pack current | 2–3 | i16 ÷10 A |
| battery SOC | 4–5 | u16 % (register 102) |
| device model | 20–31 | ASCII, **byte-swapped within each 16-bit word** |
| DC/AC/PV/grid/inverter power | 80–99 | 32-bit, **word-swapped** (first reg = low 16 bits) |

**legacy** (EB3A, AC200M, AC300, AC500, EP500, …) — monolithic read of register
0x0A (`fields.py:HOME_FIELDS`). These reject the v2 read with ILLEGAL DATA ADDRESS.

## Controls (writable)

Single-register writes (Modbus 0x06), value `1`=on / `0`=off:

| Output | v2 register | legacy register |
|--------|-------------|-----------------|
| AC output | 2011 | 3007 |
| DC output | 2012 | 3008 |

`client.write_register` waits for and validates the device's echo (function 0x06
responses are a fixed 8 bytes with **no byte-count field** — see
`_plain_frame_len`). Switch state is read back from these same registers each poll
and published as `ac_output`/`dc_output` = `"ON"`/`"OFF"`.

## Configuration

`mqtt --config config.yml` reads the nested form (sections `mqtt:`, `bluetti:`,
top-level `log_level:`). CLI flags and a flat config are also accepted as
fallbacks (`__main__.py:_cmd_mqtt`). `config.yml` is gitignored — never commit it.

## Deployment

Docker (`docker compose up -d --build`). Container needs `network_mode: host`,
`/var/run/dbus` mounted, and `NET_ADMIN`/`NET_RAW` caps. `restart:
unless-stopped` + docker enabled on boot = survives reboots. To update an
existing checkout: `git pull && docker compose up -d --build`.

## Testing

`pytest` (24 fast tests + 1 BLE-simulator e2e). The e2e test
(`tests/test_handshake_e2e.py`) stands up a fake device that verifies *our*
ECDSA signature and completes the ECDH exchange, exercising the whole encrypted
client path without hardware. Keep new pure logic (framing/crypto/fields) covered.

## Known gotchas (already handled — don't regress)

- **Modbus response sizing**: size each frame from the frame itself, not a
  precomputed length. Function 0x03 = `3 + byte_count + 2`; **0x06/0x10 echoes
  are a fixed 8 bytes with no byte-count**; exceptions (`func & 0x80`) are 5
  bytes. Getting this wrong hangs the poll loop waiting for bytes that never come.
- **BlueZ connect**: resolve the address via `BleakScanner.find_device_by_address`
  before `BleakClient.connect()` — BlueZ won't connect to an address it hasn't
  recently discovered. A killed run leaves the device connected (not advertising),
  which blocks reconnect; `connect()` auto-clears this over the BlueZ D-Bus API
  (`_clear_stale_bluez_connection`, best-effort, Linux only), so container
  restarts and reboots self-recover. `bluetoothctl disconnect <addr>` is the
  manual equivalent.
- **Encrypted handshake signature** signs the *raw bytes* `our_pub(64) ||
  randomMd5(16)`, not the ASCII hex. And derive the ECDH shared key *before*
  sending the sign frame — the device's "done" reply can arrive first.
- **v2 quirks**: 32-bit values are word-swapped; the model string is byte-swapped
  per 16-bit word; wide contiguous reads fail because the map is sparse (read the
  specific home page at register 100).
- **MQTT command thread**: paho's `on_message` runs in paho's network thread;
  marshal the BLE write onto the asyncio loop with
  `asyncio.run_coroutine_threadsafe`. All BLE I/O is serialized by
  `BluettiClient._lock` (one notify stream / one write char), so poll and command
  transactions never interleave.

## Safety

Writing the output switches changes the **real** device output. On the reference
deployment the host (a Raspberry Pi) is powered from the battery's **DC output**,
so turning DC off kills the host and this bridge. Never toggle an output that
powers something you can't afford to interrupt; prefer testing with a known-idle
output and read the state back to confirm.
