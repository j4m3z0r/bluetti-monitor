"""Constants reverse-engineered from the Bluetti Android app (v3.0.9).

Source: net.poweroak.bluetticloud / net.poweroak.lib_ble decompiled with jadx.
See README.md and the project memory for the full protocol write-up.
"""

# ---------------------------------------------------------------------------
# BLE GATT (net.poweroak.lib_ble.BleConfig)
# ---------------------------------------------------------------------------
SERVICE_UUID = "0000ff00-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"
WRITE_UUID = "0000ff02-0000-1000-8000-00805f9b34fb"
CCCD_UUID = "00002902-0000-1000-8000-00805f9b34fb"

# Advertised local-name prefixes.  Plaintext devices advertise as "BLUETTI…",
# encrypted (ESP32 / IoT) devices advertise as "BLUETTE…".
ADV_NAME_PLAINTEXT = "BLUETTI"
ADV_NAME_ENCRYPTED = "BLUETTE"

DEFAULT_SLAVE_ADDR = 0x01
FUNC_READ = 0x03           # read holding registers
FUNC_WRITE_SINGLE = 0x06   # write single register
FUNC_WRITE_MULTI = 0x10    # write multiple registers

# Max characteristic write payload before MTU negotiation.
WRITE_SPLIT_COUNT = 20

# ---------------------------------------------------------------------------
# Encryption (ui/connect/utils + connectv2/tools/ConnConstantsV2)
# ---------------------------------------------------------------------------
# AES-128 base key XOR'd with the per-session MD5 to form the handshake key.
LOCAL_AES_KEY = bytes.fromhex("459FC535808941F17091E0993EE3E93D")

# Hardcoded client ECDSA/ECDH key pair material (secp256r1 / P-256).
# The device firmware verifies the client signature against the matching
# public key, so this private key is what authorises us to the device.
CLIENT_PRIVATE_KEY_HEX = (
    "4F19A16E3E87BDD9BD24D3E5495B88041511943CBC8B969ADE9641D0F56AF337"
)
# Server public key used by the app to verify the *device's* signature.
# We can optionally verify with it; the device does not require us to.
SERVER_PUBLIC_KEY_HEX = (
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
    "A73ABF5D2232C8C1C72E68304343C272495E3A8FD6F30EA96DE2F4B3CE60B251"
    "EE21AC667CF8A71E18B46B664EAEFFE3C489F24F695B6411DB7E22CCC85A8594"
)

# X.509 SubjectPublicKeyInfo prefix for an uncompressed P-256 public key.
# Prepend to a raw 64-byte X||Y to obtain a DER SPKI.
SECP256R1_SPKI_PREFIX = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
)

# Handshake frame type bytes (after the 0x2A2A magic).
HS_HELLO = 0x01       # device -> app, carries 4 random bytes
HS_ACK = 0x02         # app -> device, carries md5[8:12]
HS_PUBKEY = 0x04      # device -> app, iot pubkey + signature (encrypted)
HS_SIGN = 0x05        # app -> device, our pubkey + signature
HS_DONE = 0x06        # device -> app, key exchange complete
HS_MAGIC = b"\x2a\x2a"
