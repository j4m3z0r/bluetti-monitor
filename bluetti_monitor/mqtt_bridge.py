"""MQTT bridge with Home Assistant discovery for Bluetti devices."""

from __future__ import annotations

import asyncio
import json
import logging

import paho.mqtt.client as mqtt

from . import __version__
from .client import BluettiClient
from .device import BluettiDevice

log = logging.getLogger(__name__)


class MqttBridge:
    def __init__(
        self,
        address: str,
        *,
        encrypted: bool | None = None,
        name: str | None = None,
        device_name: str | None = None,
        mqtt_host: str = "localhost",
        mqtt_port: int = 1883,
        mqtt_username: str | None = None,
        mqtt_password: str | None = None,
        discovery_prefix: str = "homeassistant",
        base_topic: str = "bluetti",
        poll_interval: float = 10.0,
    ):
        self.address = address
        self.encrypted = encrypted
        self.name = name
        self.device_name = device_name
        self.discovery_prefix = discovery_prefix
        self.base_topic = base_topic
        self.poll_interval = poll_interval

        self._mqtt = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"bluetti-{address}")
        if mqtt_username:
            self._mqtt.username_pw_set(mqtt_username, mqtt_password)
        self._mqtt_host = mqtt_host
        self._mqtt_port = mqtt_port

        self._device: BluettiDevice | None = None
        self._discovery_sent = False
        self._availability_topic = f"{base_topic}/{self._slug()}/availability"
        self._loop: asyncio.AbstractEventLoop | None = None
        self._command_topics: dict[str, str] = {}  # topic -> switch name
        self._mqtt.on_message = self._on_message
        self._mqtt.on_connect = self._on_connect

    def _on_connect(self, _client, _userdata, _flags, _reason, _props=None) -> None:
        # Re-subscribe to command topics after an MQTT (re)connect.
        for topic in self._command_topics:
            self._mqtt.subscribe(topic)

    # -- topics -------------------------------------------------------------
    def _slug(self) -> str:
        if self._device is not None:
            return self._device.unique_id
        return self.address.replace(":", "").lower()

    def _state_topic(self) -> str:
        return f"{self.base_topic}/{self._slug()}/state"

    def _command_topic(self, name: str) -> str:
        return f"{self.base_topic}/{self._slug()}/{name}/set"

    # -- MQTT lifecycle -----------------------------------------------------
    def _connect_mqtt(self) -> None:
        self._mqtt.will_set(self._availability_topic, "offline", retain=True)
        self._mqtt.connect(self._mqtt_host, self._mqtt_port)
        self._mqtt.loop_start()
        log.info("connected to MQTT %s:%s", self._mqtt_host, self._mqtt_port)

    def _publish_discovery(self) -> None:
        dev = self._device
        device_block = {
            "identifiers": [f"bluetti_{dev.unique_id}"],
            "name": self.device_name or f"Bluetti {dev.model or ''}".strip(),
            "manufacturer": "Bluetti",
            "model": dev.model or "Unknown",
            "sw_version": f"bluetti_monitor {__version__}",
        }
        for f in dev.measurement_fields():
            cfg = {
                "name": f.name.replace("_", " ").title(),
                "unique_id": f"bluetti_{dev.unique_id}_{f.name}",
                "state_topic": self._state_topic(),
                "value_template": f"{{{{ value_json.{f.name} }}}}",
                "availability_topic": self._availability_topic,
                "device": device_block,
            }
            if f.unit:
                cfg["unit_of_measurement"] = f.unit
            if f.device_class:
                cfg["device_class"] = f.device_class
            if f.state_class:
                cfg["state_class"] = f.state_class
            topic = f"{self.discovery_prefix}/sensor/bluetti_{dev.unique_id}/{f.name}/config"
            self._mqtt.publish(topic, json.dumps(cfg), retain=True)

        # Switches (controllable outputs).
        self._command_topics.clear()
        for sw in dev.switches():
            command_topic = self._command_topic(sw.name)
            self._command_topics[command_topic] = sw.name
            cfg = {
                "name": sw.label,
                "unique_id": f"bluetti_{dev.unique_id}_{sw.name}",
                "command_topic": command_topic,
                "state_topic": self._state_topic(),
                "value_template": f"{{{{ value_json.{sw.name} }}}}",
                "payload_on": "ON",
                "payload_off": "OFF",
                "state_on": "ON",
                "state_off": "OFF",
                "availability_topic": self._availability_topic,
                "device": device_block,
            }
            if sw.icon:
                cfg["icon"] = sw.icon
            topic = f"{self.discovery_prefix}/switch/bluetti_{dev.unique_id}/{sw.name}/config"
            self._mqtt.publish(topic, json.dumps(cfg), retain=True)
            self._mqtt.subscribe(command_topic)
        log.info("published HA discovery for %s (%d switches)", dev.unique_id, len(dev.switches()))

    # -- command handling ---------------------------------------------------
    def _on_message(self, _client, _userdata, msg) -> None:
        name = self._command_topics.get(msg.topic)
        if name is None or self._loop is None:
            return
        payload = msg.payload.decode("utf-8", "ignore").strip().upper()
        if payload not in ("ON", "OFF"):
            log.warning("ignoring command %s on %s", payload, msg.topic)
            return
        # Marshal the BLE write onto the asyncio loop (we're in paho's thread).
        asyncio.run_coroutine_threadsafe(
            self._handle_command(name, payload == "ON"), self._loop
        )

    async def _handle_command(self, name: str, on: bool) -> None:
        if self._device is None or not self._device.client.is_connected:
            log.warning("command for %s dropped: device not connected", name)
            return
        try:
            await self._device.set_output(name, on)
            # Re-poll and publish so the new state is reflected promptly.
            self._publish_state(await self._device.poll())
        except Exception as exc:  # noqa: BLE001
            log.error("failed to set %s=%s: %s", name, on, exc)

    # -- main loop ----------------------------------------------------------
    async def run(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._connect_mqtt()
        while True:
            try:
                await self._session()
            except Exception as exc:  # noqa: BLE001 - keep the bridge alive
                log.warning("session ended: %s; reconnecting in 10s", exc)
                self._mqtt.publish(self._availability_topic, "offline", retain=True)
                await asyncio.sleep(10)

    async def _session(self) -> None:
        client = BluettiClient(self.address, encrypted=self.encrypted, name=self.name)
        async with client:
            self._device = BluettiDevice(client)
            # First poll establishes serial/model for discovery topics.
            values = await self._device.poll()
            if not self._discovery_sent:
                self._publish_discovery()
                self._discovery_sent = True
            self._mqtt.publish(self._availability_topic, "online", retain=True)
            self._publish_state(values)

            while client.is_connected:
                await asyncio.sleep(self.poll_interval)
                values = await self._device.poll()
                self._publish_state(values)

    def _publish_state(self, values: dict) -> None:
        self._mqtt.publish(self._state_topic(), json.dumps(values), retain=False)
        log.debug("state: %s", values)
