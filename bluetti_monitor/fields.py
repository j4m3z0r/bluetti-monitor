"""Field decoding for the Bluetti "home data" page (BASE_REAL_DATA, addr 0x0A).

Byte offsets are taken directly from ProtocolParse.getDeviceRealtimeData in the
v3.0.9 app: a single read of register 0x0A returns a block whose layout is the
same across the supported device range (older devices simply return a shorter
block).  Offsets below index into the response *data payload* (the bytes after
the Modbus slave/func/bytecount header).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

# The home page lives at register 0x0A.  Reading 0x3B (59) registers = 118 bytes
# covers every field we decode while remaining valid for all firmware versions.
HOME_REGISTER = 0x0A
HOME_REGISTER_COUNT = 0x3B


@dataclass(frozen=True)
class Field:
    """One decoded value within the home-data block."""

    name: str
    offset: int
    length: int  # bytes
    kind: str = "uint"  # uint | int | ascii
    scale: float = 1.0
    unit: Optional[str] = None
    device_class: Optional[str] = None
    state_class: Optional[str] = None
    decoder: Optional[Callable[[bytes], object]] = field(default=None, compare=False)

    def decode(self, data: bytes):
        chunk = data[self.offset : self.offset + self.length]
        if len(chunk) < self.length:
            return None
        if self.decoder is not None:
            return self.decoder(chunk)
        if self.kind == "ascii":
            return chunk.split(b"\x00", 1)[0].decode("ascii", "ignore").strip()
        signed = self.kind == "int"
        value = int.from_bytes(chunk, "big", signed=signed)
        if self.scale != 1.0:
            return round(value * self.scale, 3)
        return value


# Ordered list of fields we publish.  device_class / state_class follow
# Home Assistant MQTT sensor conventions.
HOME_FIELDS: list[Field] = [
    Field("device_model", 0, 12, kind="ascii"),
    Field("protocol_version", 12, 2),
    Field("device_sn", 14, 8, decoder=lambda b: str(int.from_bytes(b, "big"))),
    Field("pv_charge_power", 52, 2, unit="W", device_class="power", state_class="measurement"),
    Field("grid_charge_power", 54, 2, unit="W", device_class="power", state_class="measurement"),
    Field("ac_output_power", 56, 2, unit="W", device_class="power", state_class="measurement"),
    Field("dc_output_power", 58, 2, unit="W", device_class="power", state_class="measurement"),
    Field("grid_feedback_power", 60, 2, unit="W", device_class="power", state_class="measurement"),
    Field("total_pv_power", 62, 4, unit="W", device_class="power", state_class="measurement"),
    Field("battery_soc", 66, 2, unit="%", device_class="battery", state_class="measurement"),
    Field("battery_discharging", 86, 2),
]


def decode_home(data: bytes) -> dict:
    """Decode a home-data payload into ``{field_name: value}``."""
    out: dict = {}
    for f in HOME_FIELDS:
        value = f.decode(data)
        if value is not None and value != "":
            out[f.name] = value
    # Convenience derived fields.
    if "battery_discharging" in out:
        out["battery_charging"] = 1 if out["battery_discharging"] == 0 else 0
    return out


# Sensors that are numeric measurements (used to build HA discovery configs).
def measurement_fields() -> list[Field]:
    return [f for f in HOME_FIELDS if f.unit is not None]


# ===========================================================================
# V2 protocol "home data" page (APP_HOME_DATA, register 100).
#
# Used by the newer "v2" device generation (AC180/AC180P, AC60, AC2A, AC200L,
# AC500 newer fw, EP600, …).  These devices have a sparse register map and do
# NOT support the monolithic 0x0A read.  Layout from
# ProtocolParserV2.parseHomeData; 32-bit values are word-swapped (the first
# register holds the low 16 bits) and the model string is byte-swapped within
# each 16-bit word.
# ===========================================================================
V2_HOME_REGISTER = 100
V2_HOME_REGISTER_COUNT = 60  # 120 bytes: covers SOC + all power fields


def _u16(d: bytes, o: int) -> int:
    return int.from_bytes(d[o : o + 2], "big")


def _u32_swapped(d: bytes, o: int) -> int:
    return _u16(d, o) | (_u16(d, o + 2) << 16)


def _i32_swapped(d: bytes, o: int) -> int:
    v = _u32_swapped(d, o)
    return v - 0x100000000 if v >= 0x80000000 else v


def _ascii_word_swapped(chunk: bytes) -> str:
    out = bytearray()
    for i in range(0, len(chunk) - 1, 2):
        out.append(chunk[i + 1])
        out.append(chunk[i])
    return out.split(b"\x00", 1)[0].decode("ascii", "ignore").strip()


V2_FIELDS: list[Field] = [
    Field("pack_voltage", 0, 2, scale=0.01, unit="V", device_class="voltage", state_class="measurement"),
    Field("pack_current", 2, 2, kind="int", scale=0.1, unit="A", device_class="current", state_class="measurement"),
    Field("battery_soc", 4, 2, unit="%", device_class="battery", state_class="measurement"),
    Field("charging_status", 6, 2),
    Field("device_model", 20, 12, decoder=_ascii_word_swapped),
    Field("dc_output_power", 80, 4, unit="W", device_class="power", state_class="measurement",
          decoder=lambda b: _u32_swapped(b, 0)),
    Field("ac_output_power", 84, 4, unit="W", device_class="power", state_class="measurement",
          decoder=lambda b: _i32_swapped(b, 0)),
    Field("pv_input_power", 88, 4, unit="W", device_class="power", state_class="measurement",
          decoder=lambda b: _u32_swapped(b, 0)),
    Field("grid_power", 92, 4, unit="W", device_class="power", state_class="measurement",
          decoder=lambda b: _i32_swapped(b, 0)),
    Field("inverter_power", 96, 4, unit="W", device_class="power", state_class="measurement",
          decoder=lambda b: _i32_swapped(b, 0)),
]


def decode_home_v2(data: bytes) -> dict:
    out: dict = {}
    for f in V2_FIELDS:
        value = f.decode(data)
        if value is not None and value != "":
            out[f.name] = value
    return out


def v2_measurement_fields() -> list[Field]:
    return [f for f in V2_FIELDS if f.unit is not None]


# ===========================================================================
# Writable on/off controls (single-register writes, value 1=on / 0=off).
# Register addresses differ between the legacy and v2 layouts.
# ===========================================================================
@dataclass(frozen=True)
class Switch:
    name: str       # topic / unique_id slug and the state-JSON key
    label: str      # Home Assistant display name
    register: int
    icon: str | None = None


V2_SWITCHES: list[Switch] = [
    Switch("ac_output", "AC Output", 2011, "mdi:power-socket"),
    Switch("dc_output", "DC Output", 2012, "mdi:current-dc"),
]

LEGACY_SWITCHES: list[Switch] = [
    Switch("ac_output", "AC Output", 3007, "mdi:power-socket"),
    Switch("dc_output", "DC Output", 3008, "mdi:current-dc"),
]
