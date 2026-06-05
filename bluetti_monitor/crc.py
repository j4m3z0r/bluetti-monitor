"""CRC16/Modbus, matching net.poweroak.lib_ble.utils.CRC16.

Polynomial 0xA001 (reflected 0x8005), init 0xFFFF.  On the wire Modbus
appends the checksum low byte first.
"""


def crc16(data: bytes) -> int:
    """Return the CRC16/Modbus of ``data`` as a 16-bit integer."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def crc16_bytes(data: bytes) -> bytes:
    """Return the 2-byte little-endian (low byte first) Modbus CRC suffix."""
    value = crc16(data)
    return bytes([value & 0xFF, (value >> 8) & 0xFF])


def append_crc(data: bytes) -> bytes:
    """Return ``data`` with its Modbus CRC suffix appended."""
    return data + crc16_bytes(data)


def check_crc(frame: bytes) -> bool:
    """Validate a frame whose final two bytes are a Modbus CRC suffix."""
    if len(frame) < 3:
        return False
    body, suffix = frame[:-2], frame[-2:]
    return crc16_bytes(body) == suffix
