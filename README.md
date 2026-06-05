# bluetti-monitor

A Python library and MQTT bridge for monitoring **Bluetti** power stations over
Bluetooth Low Energy, with **Home Assistant** auto-discovery.

The BLE protocol was reverse-engineered from the official Bluetti Android app
(v3.0.9). It supports both the older **plaintext** Modbus devices and the
newer **encrypted** (ECDH + AES) devices — see [PROTOCOL.md](PROTOCOL.md) for the
full protocol write-up.

> ⚠️ **Status / honesty note.** Every layer (CRC, Modbus framing, the AES-CBC
> handshake, ECDH key agreement, and ECDSA signing) is implemented directly from
> the decompiled app and covered by unit tests, including an end-to-end test
> where a simulated device verifies our signature and completes the key exchange.
>
> **Hardware-verified** against a plaintext **AC180P** (Raspberry Pi 5 / BlueZ):
> battery SOC, output power, and model decode correctly. The newer devices use a
> sparse **v2** register map (home page at register 100) which the library
> auto-detects; older devices use the monolithic 0x0A page. The **encrypted**
> (`BLUETTE`) path is implemented and tested in software but has not yet met
> real encrypted hardware — please report results. The field map is easy to
> extend (see `bluetti_monitor/fields.py`).

## Supported devices

The app ships configuration for 40+ models (AC2A, AC60(P), AC180(P/T), AC200L/M/P/PL,
AC240(P), AC300, AC500, AC70(P), EB3A, EB55, EP500(P), Elite 200 V2, EL series,
AORA series, PR/PV series, …). Plaintext devices advertise as `BLUETTI…`;
encrypted devices advertise as `BLUETTE…` (auto-detected from the name).

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Requires Python 3.10+. Dependencies: `bleak`, `paho-mqtt`, `cryptography`, `pyyaml`.

## Quick start

**1. Find your device** (make sure it is powered on and *not* connected in the
Bluetti phone app — BLE allows only one connection):

```bash
bluetti-monitor scan
# Found 1 device(s):
#   AA:BB:CC:DD:EE:FF  BLUETTE1234567890  [encrypted]
```

On macOS the "address" is a CoreBluetooth UUID; on Linux it is a MAC address.

**2. Read live data** to confirm the connection works:

```bash
bluetti-monitor monitor AA:BB:CC:DD:EE:FF --count 1
# {
#   "device_model": "AC180",
#   "battery_soc": 87,
#   "ac_output_power": 350,
#   "pv_charge_power": 120,
#   ...
# }
```

If auto-detection of the encrypted protocol is wrong, pass `--encrypted` (or the
advertised `--name BLUETTE...`).

**3. Run the MQTT bridge:**

```bash
cp config.example.yaml config.yaml      # edit broker + address
bluetti-monitor mqtt --config config.yaml
```

or entirely from the command line:

```bash
bluetti-monitor mqtt AA:BB:CC:DD:EE:FF --mqtt-host 192.168.1.10 \
    --mqtt-username ha --mqtt-password secret
```

## Home Assistant

The bridge publishes [MQTT discovery](https://www.home-assistant.io/integrations/mqtt/#mqtt-discovery)
messages, so sensors appear automatically under a single **Bluetti** device once
the bridge connects. No YAML editing in Home Assistant is required — just make
sure the MQTT integration is configured and pointed at the same broker.

Published entities (state JSON at `bluetti/<serial>/state`, availability at
`bluetti/<serial>/availability`):

| Entity | Unit | Device class |
|--------|------|--------------|
| Battery SOC | % | battery |
| AC output power | W | power |
| DC output power | W | power |
| PV charge power | W | power |
| Grid charge power | W | power |
| Grid feedback power | W | power |
| Total PV power | W | power |
| Pack voltage / current | V / A | voltage / current |

Plus controllable switches:

| Switch | Notes |
|--------|-------|
| **AC Output** | turns the AC inverter output on/off |
| **DC Output** | turns the 12 V / USB DC output on/off |

> ⚠️ **Control safety.** Writing these switches changes the real device output.
> If something important is powered from an output (e.g. the very host running
> this bridge), turning it off will cut its power. Use the switches deliberately.

## Library usage

```python
import asyncio
from bluetti_monitor.client import BluettiClient
from bluetti_monitor.device import BluettiDevice

async def main():
    async with BluettiClient("AA:BB:CC:DD:EE:FF", encrypted=True) as client:
        device = BluettiDevice(client)
        print(await device.poll())
        # raw register access:
        resp = await client.read_registers(0x0A, 0x3B)
        print(resp.registers)

asyncio.run(main())
```

## Running on a Raspberry Pi / always-on host

Run the bridge under systemd or in a container near the device (BLE range). A
minimal systemd unit:

```ini
[Unit]
Description=Bluetti MQTT bridge
After=bluetooth.target network-online.target

[Service]
ExecStart=/opt/bluetti/.venv/bin/bluetti-monitor mqtt --config /opt/bluetti/config.yaml
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
```

## Development

```bash
pip install -e '.[dev]'
pytest
```

The tests cover CRC vectors, Modbus framing, the AES-CBC frame round-trip, ECDH
symmetry, the P1363 signature, and a full encrypted handshake + read against a
device simulator.

## Credits & legal

Protocol details were obtained by decompiling the Bluetti Android app for
personal interoperability/monitoring. "Bluetti" is a trademark of its owner;
this project is unaffiliated. Use at your own risk — writing to registers can
change device behaviour.
