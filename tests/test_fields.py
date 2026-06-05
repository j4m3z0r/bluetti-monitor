from bluetti_monitor.fields import decode_home, HOME_FIELDS, measurement_fields


def _build_payload() -> bytes:
    # 118-byte home-data payload (0x3B registers) with known values placed at
    # the documented byte offsets.
    buf = bytearray(118)
    buf[0:6] = b"AC180\x00"          # model ASCII
    buf[12:14] = (1023).to_bytes(2, "big")  # protocol version
    buf[14:22] = (1234567890).to_bytes(8, "big")  # serial
    buf[52:54] = (120).to_bytes(2, "big")   # pv_charge_power
    buf[54:56] = (200).to_bytes(2, "big")   # grid_charge_power
    buf[56:58] = (350).to_bytes(2, "big")   # ac_output_power
    buf[58:60] = (40).to_bytes(2, "big")    # dc_output_power
    buf[60:62] = (0).to_bytes(2, "big")     # grid_feedback_power
    buf[62:66] = (480).to_bytes(4, "big")   # total_pv_power
    buf[66:68] = (87).to_bytes(2, "big")    # battery_soc
    buf[86:88] = (1).to_bytes(2, "big")     # discharging
    return bytes(buf)


def test_decode_home_values():
    values = decode_home(_build_payload())
    assert values["device_model"] == "AC180"
    assert values["protocol_version"] == 1023
    assert values["device_sn"] == "1234567890"
    assert values["pv_charge_power"] == 120
    assert values["ac_output_power"] == 350
    assert values["battery_soc"] == 87
    assert values["total_pv_power"] == 480
    assert values["battery_charging"] == 0  # discharging == 1


def test_battery_charging_derived():
    buf = bytearray(_build_payload())
    buf[86:88] = (0).to_bytes(2, "big")
    values = decode_home(bytes(buf))
    assert values["battery_charging"] == 1


def test_measurement_fields_have_units():
    for f in measurement_fields():
        assert f.unit is not None
    names = {f.name for f in HOME_FIELDS}
    assert "battery_soc" in names


def test_decode_home_v2():
    from bluetti_monitor.fields import decode_home_v2, V2_HOME_REGISTER
    assert V2_HOME_REGISTER == 100
    buf = bytearray(120)
    buf[0:2] = (3321).to_bytes(2, "big")    # pack voltage -> 33.21
    buf[2:4] = (14).to_bytes(2, "big")      # pack current -> 1.4
    buf[4:6] = (100).to_bytes(2, "big")     # SOC
    # model "AC180P" byte-swapped within each 16-bit word -> "CA81P0"
    buf[20:26] = b"CA81P0"
    # dc output power 28 W, word-swapped (low word first)
    buf[80:82] = (28).to_bytes(2, "big")
    buf[82:84] = (0).to_bytes(2, "big")
    # ac output power -5 W, signed word-swapped
    buf[84:86] = (0xFFFB).to_bytes(2, "big")
    buf[86:88] = (0xFFFF).to_bytes(2, "big")
    v = decode_home_v2(bytes(buf))
    assert v["battery_soc"] == 100
    assert v["pack_voltage"] == 33.21
    assert v["pack_current"] == 1.4
    assert v["device_model"] == "AC180P"
    assert v["dc_output_power"] == 28
    assert v["ac_output_power"] == -5


def test_v2_switches_registers():
    from bluetti_monitor.fields import V2_SWITCHES
    by_name = {s.name: s.register for s in V2_SWITCHES}
    assert by_name["ac_output"] == 2011
    assert by_name["dc_output"] == 2012
