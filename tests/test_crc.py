from bluetti_monitor.crc import crc16, crc16_bytes, append_crc, check_crc


def test_known_check_value():
    # Documented CRC-16/MODBUS check value for ASCII "123456789".
    assert crc16(b"123456789") == 0x4B37


def test_low_byte_first_suffix():
    # 0x4B37 -> low byte 0x37 then high byte 0x4B (Modbus wire order).
    assert crc16_bytes(b"123456789") == bytes([0x37, 0x4B])


def test_roundtrip_append_check():
    body = bytes.fromhex("010300140002")
    frame = append_crc(body)
    assert check_crc(frame)
    assert not check_crc(frame[:-1] + b"\x00")
