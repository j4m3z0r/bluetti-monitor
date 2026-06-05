import pytest

from bluetti_monitor import const
from bluetti_monitor.protocol import (
    ModbusError,
    build_read_command,
    build_write_single,
    build_write_multiple,
    expected_response_length,
    parse_read_response,
)
from bluetti_monitor.crc import append_crc, check_crc


def test_read_command_layout():
    cmd = build_read_command(0x000A, 0x003B)
    # slave 01, func 03, addr 000A, count 003B, then CRC
    assert cmd[:6] == bytes.fromhex("0103000A003B")
    assert check_crc(cmd)
    assert len(cmd) == 8


def test_write_single_signed_value():
    cmd = build_write_single(3000, 1)
    assert cmd[:6] == bytes.fromhex("0106") + (3000).to_bytes(2, "big") + b"\x00\x01"
    assert check_crc(cmd)
    neg = build_write_single(3000, -1)
    assert neg[4:6] == b"\xff\xff"


def test_write_multiple_layout():
    cmd = build_write_multiple(3023, [8, 0])
    # slave 01 func 10 addr 0BCF count 0002 bytecount 04 data 0008 0000
    assert cmd[1] == const.FUNC_WRITE_MULTI
    assert cmd[6] == 4  # byte count
    assert check_crc(cmd)


def test_expected_response_length():
    assert expected_response_length(2) == 3 + 4 + 2


def test_parse_read_response_roundtrip():
    payload = bytes.fromhex("00210064")  # two registers: 0x0021, 0x0064
    frame = append_crc(bytes([0x01, 0x03, len(payload)]) + payload)
    resp = parse_read_response(frame)
    assert resp.registers == [0x0021, 0x0064]


def test_parse_read_response_exception():
    frame = append_crc(bytes([0x01, 0x83, 0x02]))
    with pytest.raises(ModbusError):
        parse_read_response(frame)


def test_parse_read_response_bad_crc():
    payload = bytes.fromhex("0021")
    frame = bytes([0x01, 0x03, 2]) + payload + b"\x00\x00"
    with pytest.raises(ModbusError):
        parse_read_response(frame)


def test_write_single_on_off_frames():
    on = build_write_single(2011, 1)
    assert on[:6] == bytes.fromhex("0106") + (2011).to_bytes(2, "big") + (1).to_bytes(2, "big")
    assert check_crc(on)
    off = build_write_single(2012, 0)
    assert off[:6] == bytes.fromhex("0106") + (2012).to_bytes(2, "big") + b"\x00\x00"
    assert check_crc(off)
