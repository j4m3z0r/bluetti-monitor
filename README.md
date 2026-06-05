# bluetti-monitor

A Python library and MQTT bridge for monitoring **Bluetti** power stations over
Bluetooth Low Energy, with **Home Assistant** auto-discovery and on/off control
of the AC and DC outputs.

The BLE protocol was reverse-engineered from the official Bluetti Android app
(v3.0.9). It supports the older **plaintext** Modbus devices, the newer
**encrypted** (ECDH + AES) devices, and both the legacy and the newer "v2"
register maps — see [PROTOCOL.md](PROTOCOL.md) for the full write-up.

> ⚠️ **Status / honesty note.** Every layer (CRC, Modbus framing, the AES-CBC
> handshake, ECDH key agreement, and ECDSA signing) is implemented directly from
> the decompiled app and covered by unit tests, including an end-to-end test
> where a simulated device verifies our signature and completes the key exchange.
>
> **Hardware-verified** against a plaintext **AC180P** (Raspberry Pi 5 / BlueZ):
> live monitoring (SOC, input/output power, voltage) reads correctly and AC
> output on/off control was confirmed by switching a real 105 W load. The newer
> devices use a sparse **v2** register map (home page at register 100) which the
> library auto-detects; older devices use the monolithic 0x0A page. The
> **encrypted** (`BLUETTE`) path is implemented and tested in software but has
> not yet met real encrypted hardware — please report results. The field map is
> easy to extend (see `bluetti_monitor/fields.py`).

## Supported devices

The app ships configuration for 40+ models (AC2A, AC60(P), AC180(P/T), AC200L/M/P/PL,
AC240(P), AC300, AC500, AC70(P), EB3A, EB55, EP500(P), Elite 200 V2, EL series,
AORA series, PR/PV series, …). Devices advertise with a `BLUETTI` (plaintext) or
`BLUETTE` (encrypted) marker in their manufacturer data; some also advertise by
model name (e.g. `AC180P…`). Encryption is auto-detected.

The register/field map currently decodes the **v2 home page** (AC180/AC180P,
AC60, AC2A, AC200L, EP600, …) and the **legacy home page** (EB3A, AC200M, AC300,
AC500, EP500, …). Both are exercised by the bridge automatically.

## Run with Docker (recommended)

This is how the project is intended to run on an always-on host near the device
(e.g. a Raspberry Pi). The container talks to the host's BlueZ stack over D-Bus.

```bash
git clone https://github.com/j4m3z0r/bluetti-monitor.git
cd bluetti-monitor
cp config.yml.example config.yml      # edit broker + BLE address (see below)
docker compose up -d --build
docker compose logs -f
```

`config.yml` (gitignored — never commit it):

```yaml
mqtt:
  host: "homeassistant.home.arpa"     # your MQTT broker
  port: 1883
  username: "mqtt"
  password: "mqtt"
  discovery_prefix: "homeassistant"

bluetti:
  ble_address: "AA:BB:CC:DD:EE:FF"    # find with: bluetti-monitor scan
  device_name: "Bluetti AC180P"       # name shown in Home Assistant
  poll_interval: 10
  # encrypted: false                  # auto-detected; set to override

log_level: "INFO"
```

`docker-compose.yml` already mounts `/var/run/dbus`, runs with `network_mode:
host`, adds the `NET_ADMIN`/`NET_RAW` caps BLE needs, and sets `restart:
unless-stopped` so it survives reboots.

## Run from the CLI

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .        # requires Python 3.10+
```

**1. Find your device** (powered on and *not* connected in the Bluetti phone app
— BLE allows only one connection at a time):

```bash
bluetti-monitor scan
#   AA:BB:CC:DD:EE:FF  AC180P2340000229156  [plaintext]
```

On macOS the "address" is a CoreBluetooth UUID; on Linux it is a MAC address.

**2. Read live data** to confirm the connection:

```bash
bluetti-monitor monitor AA:BB:CC:DD:EE:FF --count 1
# {
#   "device_model": "AC180P",
#   "battery_soc": 96,
#   "pack_voltage": 33.4,
#   "ac_output_power": 105,
#   "dc_output_power": 22,
#   "pv_input_power": 159,
#   "ac_output": "ON",
#   "dc_output": "ON"
# }
```

**3. Run the bridge** (alternative to Docker):

```bash
bluetti-monitor mqtt --config config.yml
# or fully from flags:
bluetti-monitor mqtt AA:BB:CC:DD:EE:FF --mqtt-host 192.168.1.10 \
    --mqtt-username ha --mqtt-password secret
```

> **BlueZ note (Linux):** a killed run can leave the device BLE-connected, so it
> stops advertising and new connects fail with "device not found". The bridge
> clears this automatically on (re)connect, so container restarts and reboots
> recover on their own. To clear it by hand: `bluetoothctl disconnect
> AA:BB:CC:DD:EE:FF` (a BLE disconnect does not affect the power station's outputs).

## Home Assistant

The bridge publishes [MQTT discovery](https://www.home-assistant.io/integrations/mqtt/#mqtt-discovery)
messages, so a single **Bluetti** device with all its entities appears
automatically — no YAML editing in Home Assistant. Just make sure HA's MQTT
integration points at the same broker.

State is published as JSON at `bluetti/<id>/state`, availability at
`bluetti/<id>/availability`, and switch commands are accepted at
`bluetti/<id>/<switch>/set`.

**Sensors (v2 devices):** battery SOC (%), pack voltage (V) & current (A), and
power for AC output, DC output, PV/charging input, grid, and inverter (W).
Legacy devices expose a similar set with slightly different names.

**Switches:**

| Switch | Command topic | Effect |
|--------|---------------|--------|
| **AC Output** | `bluetti/<id>/ac_output/set` | turns the AC inverter output on/off |
| **DC Output** | `bluetti/<id>/dc_output/set` | turns the 12 V / USB DC output on/off |

Each write is confirmed against the device's echo response and the new state is
read back and republished immediately.

> ⚠️ **Control safety.** Writing these switches changes the real device output.
> If something important is powered from an output — **including the host running
> this bridge** — turning it off will cut its power (and may drop this bridge).
> Consider renaming or removing the switch for any output you must not toggle.

## Library usage

```python
import asyncio
from bluetti_monitor.client import BluettiClient
from bluetti_monitor.device import BluettiDevice

async def main():
    async with BluettiClient("AA:BB:CC:DD:EE:FF") as client:
        device = BluettiDevice(client)          # auto-detects v2 vs legacy
        print(await device.poll())
        await device.set_output("ac_output", True)   # turn AC on
        # raw register access:
        print((await client.read_registers(100, 8)).registers)

asyncio.run(main())
```

## Development

```bash
pip install -e '.[dev]'
pytest
```

The tests cover CRC vectors, Modbus read/write framing, field decoding for both
register maps, the AES-CBC frame round-trip, ECDH symmetry, the P1363 signature,
and a full encrypted handshake + read against a device simulator.

## Credits & legal

Protocol details were obtained by decompiling the Bluetti Android app for
personal interoperability and monitoring. "Bluetti" is a trademark of its owner;
this project is unaffiliated and provided as-is. Use at your own risk — writing
to registers changes device behaviour. Inspired by the community
[`bluetti_mqtt`](https://github.com/warhammerkid/bluetti_mqtt) project.
