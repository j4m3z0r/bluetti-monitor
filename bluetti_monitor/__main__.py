"""Command-line interface for bluetti_monitor.

Subcommands:
  scan                       discover nearby Bluetti devices
  monitor <address>          connect and print decoded home data
  mqtt <address>             run the MQTT / Home Assistant bridge
  mqtt --config config.yaml  run the bridge from a YAML config file
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from .client import BluettiClient, scan
from .device import BluettiDevice
from .mqtt_bridge import MqttBridge


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


async def _cmd_scan(args) -> int:
    print(f"Scanning for {args.timeout:.0f}s ...")
    devices = await scan(timeout=args.timeout)
    if not devices:
        print("No Bluetti devices found. Ensure the device is on and not "
              "connected in the Bluetti app.")
        return 1
    print(f"\nFound {len(devices)} device(s):")
    for address, name, encrypted in devices:
        kind = "encrypted" if encrypted else "plaintext"
        print(f"  {address}  {name:<24} [{kind}]")
    return 0


async def _cmd_monitor(args) -> int:
    client = BluettiClient(args.address, encrypted=args.encrypted, name=args.name)
    async with client:
        device = BluettiDevice(client)
        polls = 0
        while True:
            values = await device.poll()
            print(json.dumps(values, indent=2))
            polls += 1
            if args.count and polls >= args.count:
                break
            await asyncio.sleep(args.interval)
    return 0


async def _cmd_mqtt(args) -> int:
    cfg = {}
    if args.config:
        import yaml
        with open(args.config) as fh:
            cfg = yaml.safe_load(fh) or {}

    # Support both a flat config and the nested form used by the sibling
    # integrations (mqtt: {...}, bluetti: {...}, log_level:).
    mqtt_cfg = cfg.get("mqtt", {})
    dev_cfg = cfg.get("bluetti", {})
    if isinstance(cfg.get("log_level"), str):
        logging.getLogger().setLevel(cfg["log_level"].upper())

    address = dev_cfg.get("ble_address") or cfg.get("address") or args.address
    if not address:
        print("error: device address required (positional arg, 'address', or bluetti.ble_address)")
        return 2
    bridge = MqttBridge(
        address,
        encrypted=dev_cfg.get("encrypted", cfg.get("encrypted", args.encrypted)),
        name=dev_cfg.get("name", cfg.get("name", args.name)),
        device_name=dev_cfg.get("device_name"),
        mqtt_host=mqtt_cfg.get("host", cfg.get("mqtt_host", args.mqtt_host)),
        mqtt_port=mqtt_cfg.get("port", cfg.get("mqtt_port", args.mqtt_port)),
        mqtt_username=mqtt_cfg.get("username", cfg.get("mqtt_username", args.mqtt_username)) or None,
        mqtt_password=mqtt_cfg.get("password", cfg.get("mqtt_password", args.mqtt_password)) or None,
        discovery_prefix=mqtt_cfg.get("discovery_prefix", cfg.get("discovery_prefix", args.discovery_prefix)),
        base_topic=cfg.get("base_topic", args.base_topic),
        poll_interval=dev_cfg.get("poll_interval", cfg.get("poll_interval", args.interval)),
    )
    await bridge.run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bluetti_monitor", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="discover nearby Bluetti devices")
    s.add_argument("--timeout", type=float, default=10.0)
    s.set_defaults(func=_cmd_scan)

    m = sub.add_parser("monitor", help="connect and print decoded home data")
    m.add_argument("address")
    m.add_argument("--name", default=None, help="advertised name (to auto-detect encryption)")
    m.add_argument("--encrypted", action="store_true", default=None)
    m.add_argument("--interval", type=float, default=5.0)
    m.add_argument("--count", type=int, default=0, help="number of polls (0 = forever)")
    m.set_defaults(func=_cmd_monitor)

    q = sub.add_parser("mqtt", help="run the MQTT / Home Assistant bridge")
    q.add_argument("address", nargs="?", default=None)
    q.add_argument("--config", default=None, help="YAML config file")
    q.add_argument("--name", default=None)
    q.add_argument("--encrypted", action="store_true", default=None)
    q.add_argument("--mqtt-host", default="localhost")
    q.add_argument("--mqtt-port", type=int, default=1883)
    q.add_argument("--mqtt-username", default=None)
    q.add_argument("--mqtt-password", default=None)
    q.add_argument("--discovery-prefix", default="homeassistant")
    q.add_argument("--base-topic", default="bluetti")
    q.add_argument("--interval", type=float, default=10.0)
    q.set_defaults(func=_cmd_mqtt)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    try:
        return asyncio.run(args.func(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
