"""Plaintext Modbus framing for Bluetti BLE devices (ProtocolParse).

Frames are the standard Modbus RTU layout used over the FF02 write
characteristic; responses arrive (possibly fragmented) on FF01.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import const
from .crc import append_crc, check_crc


def build_read_command(addr: int, count: int, slave: int = const.DEFAULT_SLAVE_ADDR) -> bytes:
    """Read ``count`` holding registers starting at ``addr`` (function 0x03)."""
    body = bytes([slave, const.FUNC_READ]) + addr.to_bytes(2, "big") + count.to_bytes(2, "big")
    return append_crc(body)


def build_write_single(addr: int, value: int, slave: int = const.DEFAULT_SLAVE_ADDR) -> bytes:
    """Write a single register (function 0x06).  ``value`` may be signed."""
    body = bytes([slave, const.FUNC_WRITE_SINGLE]) + addr.to_bytes(2, "big") + (value & 0xFFFF).to_bytes(2, "big")
    return append_crc(body)


def build_write_multiple(addr: int, values: list[int], slave: int = const.DEFAULT_SLAVE_ADDR) -> bytes:
    """Write multiple consecutive registers (function 0x10)."""
    data = b"".join((v & 0xFFFF).to_bytes(2, "big") for v in values)
    body = (
        bytes([slave, const.FUNC_WRITE_MULTI])
        + addr.to_bytes(2, "big")
        + len(values).to_bytes(2, "big")
        + bytes([len(data)])
        + data
    )
    return append_crc(body)


class ModbusError(Exception):
    """Raised for a Modbus exception response or malformed frame."""


@dataclass
class ReadResponse:
    slave: int
    function: int
    data: bytes  # the register payload (byteCount bytes)

    @property
    def registers(self) -> list[int]:
        return [int.from_bytes(self.data[i : i + 2], "big") for i in range(0, len(self.data) - 1, 2)]


def expected_response_length(register_count: int) -> int:
    """Total bytes of a read response: slave+func+bytecount + data + crc."""
    return 3 + register_count * 2 + 2


def parse_read_response(frame: bytes) -> ReadResponse:
    """Validate and unpack a function-0x03 read response frame."""
    if len(frame) < 5:
        raise ModbusError(f"response too short: {frame.hex()}")
    slave, function = frame[0], frame[1]
    if function & 0x80:
        raise ModbusError(f"modbus exception code {frame[2]:#x}")
    if not check_crc(frame):
        raise ModbusError(f"bad CRC: {frame.hex()}")
    byte_count = frame[2]
    data = frame[3 : 3 + byte_count]
    if len(data) != byte_count:
        raise ModbusError(f"truncated payload: have {len(data)} want {byte_count}")
    return ReadResponse(slave=slave, function=function, data=data)
