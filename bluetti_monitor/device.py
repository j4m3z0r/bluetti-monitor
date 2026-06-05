"""High-level device polling: turn raw register reads into value dicts.

Two register layouts exist in the wild:

* **legacy** — a single monolithic read of register 0x0A (EB3A, AC200M, AC300,
  AC500, EP500, …).
* **v2** — a sparse map read from register 100 (AC180/AC180P, AC60, AC2A,
  AC200L, EP600, …); these reject the 0x0A read with ILLEGAL DATA ADDRESS.

The layout is auto-detected on the first poll and then cached.
"""

from __future__ import annotations

import logging

from .client import BluettiClient, BluettiClientError
from .fields import (
    HOME_REGISTER,
    HOME_REGISTER_COUNT,
    LEGACY_SWITCHES,
    V2_HOME_REGISTER,
    V2_HOME_REGISTER_COUNT,
    V2_SWITCHES,
    Switch,
    decode_home,
    decode_home_v2,
    measurement_fields,
    v2_measurement_fields,
)
from .protocol import ModbusError

log = logging.getLogger(__name__)


class BluettiDevice:
    """Wraps a :class:`BluettiClient` and exposes decoded polls."""

    def __init__(self, client: BluettiClient, layout: str | None = None):
        self.client = client
        self.layout = layout  # "v2" | "legacy" | None (auto-detect)
        self.serial: str | None = None
        self.model: str | None = None

    async def _detect(self) -> None:
        """Probe which register layout the device speaks (v2 first)."""
        try:
            await self.client.read_registers(V2_HOME_REGISTER, 8, retries=0)
            self.layout = "v2"
        except (ModbusError, BluettiClientError):
            self.layout = "legacy"
        log.info("detected %s register layout", self.layout)

    async def poll(self) -> dict:
        """Read the home-data page and return decoded ``{field: value}``."""
        if self.layout is None:
            await self._detect()

        if self.layout == "v2":
            resp = await self.client.read_registers(V2_HOME_REGISTER, V2_HOME_REGISTER_COUNT)
            values = decode_home_v2(resp.data)
        else:
            resp = await self.client.read_registers(HOME_REGISTER, HOME_REGISTER_COUNT)
            values = decode_home(resp.data)

        values.update(await self._read_switches())

        if values.get("device_sn"):
            self.serial = values["device_sn"]
        if values.get("device_model"):
            self.model = values["device_model"]
        return values

    async def _read_switches(self) -> dict:
        """Read the on/off control registers, returning {name: "ON"|"OFF"}."""
        switches = self.switches()
        if not switches:
            return {}
        regs = [s.register for s in switches]
        start, count = min(regs), max(regs) - min(regs) + 1
        try:
            resp = await self.client.read_registers(start, count)
        except (ModbusError, BluettiClientError) as exc:
            log.debug("switch state read failed: %s", exc)
            return {}
        out = {}
        for s in switches:
            out[s.name] = "ON" if resp.registers[s.register - start] else "OFF"
        return out

    async def set_output(self, name: str, on: bool) -> None:
        """Turn a named output (e.g. 'ac_output', 'dc_output') on or off."""
        switch = next((s for s in self.switches() if s.name == name), None)
        if switch is None:
            raise ValueError(f"unknown switch {name!r}")
        log.info("setting %s -> %s", name, "ON" if on else "OFF")
        await self.client.write_register(switch.register, 1 if on else 0)

    def switches(self) -> list[Switch]:
        return V2_SWITCHES if self.layout == "v2" else LEGACY_SWITCHES

    def measurement_fields(self):
        """Fields with units, for building Home Assistant discovery configs."""
        return v2_measurement_fields() if self.layout == "v2" else measurement_fields()

    @property
    def unique_id(self) -> str:
        return self.serial or self.client.address.replace(":", "").lower()
