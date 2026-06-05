# Bluetti BLE protocol (reverse-engineered)

Derived from the official Android app **BLUETTI v3.0.9**
(package `net.poweroak.bluetticloud`, BLE library `net.poweroak.lib_ble`),
decompiled with jadx. This documents what `bluetti_monitor` implements.

## GATT layer

| Role | UUID |
|------|------|
| Service | `0000ff00-0000-1000-8000-00805f9b34fb` |
| Notify (device → app) | `0000ff01-…` |
| Write (app → device) | `0000ff02-…` |
| CCCD | `00002902-…` |

Devices advertise a local name beginning with `BLUETTI` (plaintext protocol) or
`BLUETTE` (encrypted protocol). Writes are split to the negotiated MTU
(`response=False`).

## Plaintext framing — Modbus RTU

Standard Modbus over the write characteristic; responses (possibly fragmented)
arrive on the notify characteristic.

```
Read:           [slave:1=0x01][0x03][addr:2][regCount:2][CRC:2]
Read response:  [slave][0x03][byteCount:1][data: byteCount][CRC:2]
Write single:   [slave][0x06][addr:2][value:2][CRC:2]
Write multiple: [slave][0x10][addr:2][regCount:2][byteCount:1][data][CRC:2]
```

**CRC16/Modbus** (`lib_ble/utils/CRC16.java`): poly `0xA001`, init `0xFFFF`,
appended **low byte first**. Check value of ASCII `"123456789"` = `0x4B37`.

## Encrypted framing — `BLUETTE` devices

ESP32/IoT devices wrap Modbus frames in AES-CBC after an ECDH handshake. All
control frames are prefixed with the magic `2A 2A`. Crypto lives in
`ui/connect/utils/{AESUtils,ECDHUtils,SignatureCrypt}.java` and the state machine
in `ui/connect/ConnectManager.java`.

### Hardcoded keys (extracted from the app)

```
LOCAL_AES_KEY      = 459FC535808941F17091E0993EE3E93D            (16 B, AES-128)
CLIENT_PRIVATE_KEY = 4F19A16E3E87BDD9BD24D3E5495B88041511943CBC8B969ADE9641D0F56AF337
                     (secp256r1 / P-256 ECDSA private key — authorises us to the device)
SERVER_PUBLIC_KEY  = 3059…A73ABF5D…  (verifies the device's signature; optional for us)
```

### Handshake

```
0.  device → app   2A2A 01 04 <rand:4>
      randomMd5  = MD5( reverse(rand) )            (16 bytes)
      aesKey     = randomMd5 XOR LOCAL_AES_KEY     (AES-128)
    app → device   2A2A 02 04 <randomMd5[8:12]> <sum16>        (plaintext)

1.  device → app   ENC(aesKey, iv=randomMd5):
                     2A2A 04 <len> <iotPub:64> <deviceSig> <sum16>
    app generates an ephemeral secp256r1 key pair, signs
      ( ourPub:64 || randomMd5:16 )  with CLIENT_PRIVATE_KEY (SHA256withECDSA, raw r||s)
    app → device   ENC(aesKey, iv=randomMd5):
                     2A2A 05 80 <ourPub:64> <sig:64> <sum16>

2.  device → app   ENC(aesKey, iv=randomMd5):  2A2A 06 00
      sharedKey = ECDH(ourPriv, iotPub)         (32 bytes → AES-256)
```

After the handshake every Modbus frame is wrapped with `sharedKey`.

### AES-CBC frame format (`buildAESCBCCmd` / `parseAESCBCData`)

Plaintext is zero-padded to a 16-byte multiple and encrypted with AES/CBC
(NoPadding). The wire frame is:

```
handshake phase (explicit IV = randomMd5):
    [plaintextLen:2 BE][ciphertext]
shared phase (IV derived per-message):
    [plaintextLen:2 BE][rand:4][ciphertext]      IV = MD5(rand)
```

The receiver decrypts and keeps the first `plaintextLen` bytes.

Public keys are exchanged as the raw uncompressed point `X||Y` (64 bytes, no
`0x04` prefix); the X.509 SPKI prefix for P-256 is
`3059301306072a8648ce3d020106082a8648ce3d03010703420004`.

## Register map

| Name | Address | Notes |
|------|---------|-------|
| Base config | 1 | specs/voltage/protocol version |
| **Home / real-time data** | **0x0A (10)** | universal status page (decoded below) |
| MCU status | 22 | |
| BMS pack | 91 | |
| PV charge data | 157 | |
| Fault history | 2000 | |
| Settings block | 3000–3090 | switches & limits (see below) |
| IoT / internet | 5000–5049 | |

### Home page (read 0x0A, ~0x3B registers) — byte offsets into the payload

| Field | Offset | Type |
|-------|--------|------|
| device model | 0–11 | ASCII |
| protocol version | 12–13 | u16 |
| serial number | 14–21 | u64 |
| PV charge power | 52–53 | u16 W |
| grid charge power | 54–55 | u16 W |
| AC output power | 56–57 | u16 W |
| DC output power | 58–59 | u16 W |
| grid feedback power | 60–61 | u16 W |
| total PV power | 62–65 | u32 W |
| battery SOC | 66–67 | u16 % |
| discharging status | 86–87 | u16 |

(Alarm/fault bitmaps follow at offsets 88–95 and 96+.)

### v2 register map (newer devices — AC180/AC180P, AC60, AC2A, AC200L, EP600 …)

Hardware-verified against an **AC180P**. These devices have a **sparse** register
map and reject the monolithic 0x0A read with ILLEGAL DATA ADDRESS (0x02). The
home page is read from **register 100** (`APP_HOME_DATA`), max ~60 registers per
read. `bluetti_monitor` auto-detects this layout on the first poll.

Layout from `ProtocolParserV2.parseHomeData`, byte offsets into the payload.
**32-bit values are word-swapped** (first register = low 16 bits); the model
string is **byte-swapped within each 16-bit word** (e.g. wire `CA81P0` → `AC180P`).

| Field | Offset | Type |
|-------|--------|------|
| pack voltage | 0–1 | u16 ÷100 V (app uses ÷10, but ÷100 matches the real ~33 V pack) |
| pack current | 2–3 | i16 ÷10 A |
| **battery SOC** | **4–5 (register 102)** | u16 % |
| charging status | 6–7 | u16 |
| device model | 20–31 | ASCII, word byte-swapped |
| serial | 32–39 | — |
| DC output power | 80–83 | u32 word-swapped W |
| AC output power | 84–87 | i32 word-swapped W |
| PV input power | 88–91 | u32 word-swapped W |
| grid power | 92–95 | i32 word-swapped W |
| inverter power | 96–99 | i32 word-swapped W |

### Useful settings registers (function 0x06 write)

| Register | Function |
|----------|----------|
| 3000 | main switch |
| 3007 | AC output switch |
| 3008 | DC output switch |
| 3011 | grid charging switch |
| 3010 | feed-to-grid switch |
| 3065 | charging/silent mode |
| 3066 | power-lifting mode |
| 3057 / 3058 | max charge / discharge power |

Writing registers changes device behaviour — use with care.
