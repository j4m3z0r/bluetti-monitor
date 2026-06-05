"""Encryption layer for BLUETTE (encrypted) Bluetti devices.

Faithfully reimplements the handshake and AES-CBC framing from
net.poweroak.bluetticloud.ui.connect (ProtocolParse / AESUtils / ECDHUtils /
SignatureCrypt).  See README for the protocol description.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import const

_CURVE = ec.SECP256R1()


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def hex_sum(data: bytes, length: int = 2) -> bytes:
    """Sum of the bytes, returned big-endian in ``length`` bytes (hexStrSum)."""
    total = sum(data)
    return total.to_bytes(8, "big")[-length:]


def _zero_pad(data: bytes, block: int = 16) -> bytes:
    rem = len(data) % block
    if rem:
        data = data + b"\x00" * (block - rem)
    return data


# ---------------------------------------------------------------------------
# AES-CBC (NoPadding) framing
# ---------------------------------------------------------------------------
def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(_zero_pad(plaintext)) + enc.finalize()


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(ciphertext) + dec.finalize()


def build_encrypted_frame(plaintext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
    """Wrap a plaintext modbus frame for transmission (buildAESCBCCmd).

    ``iv`` provided  -> handshake phase: ``LEN(2) || ciphertext``.
    ``iv`` is None   -> shared-key phase: ``LEN(2) || RAND(4) || ciphertext``
                        where the real IV is ``MD5(RAND)``.
    """
    length = len(plaintext).to_bytes(2, "big")
    if iv is None:
        rand = os.urandom(4)
        real_iv = md5(rand)
        ct = aes_cbc_encrypt(plaintext, key, real_iv)
        return length + rand + ct
    ct = aes_cbc_encrypt(plaintext, key, iv)
    return length + ct


def parse_encrypted_frame(frame: bytes, key: bytes, iv: bytes | None = None) -> bytes:
    """Inverse of :func:`build_encrypted_frame` (parseAESCBCData)."""
    length = int.from_bytes(frame[0:2], "big")
    if iv is None:
        rand = frame[2:6]
        real_iv = md5(rand)
        ct = frame[6:]
    else:
        real_iv = iv
        ct = frame[2:]
    plain = aes_cbc_decrypt(ct, key, real_iv)
    return plain[:length]


# ---------------------------------------------------------------------------
# Handshake key derivation
# ---------------------------------------------------------------------------
def random_md5_from_hello(random4: bytes) -> bytes:
    """randomMd5 = MD5(reverse(4 random bytes)).  Returns the 16-byte digest."""
    return md5(random4[::-1])


def handshake_key(random_md5: bytes) -> bytes:
    """bleConnAESKey = randomMd5 XOR LOCAL_AES_KEY (both 16 bytes)."""
    return bytes(a ^ b for a, b in zip(random_md5, const.LOCAL_AES_KEY))


# ---------------------------------------------------------------------------
# ECDH / ECDSA (secp256r1)
# ---------------------------------------------------------------------------
def _client_private_key() -> ec.EllipticCurvePrivateKey:
    secret = int(const.CLIENT_PRIVATE_KEY_HEX, 16)
    return ec.derive_private_key(secret, _CURVE)


def generate_ecdh_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(_CURVE)


def public_key_raw(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Return the uncompressed public point without the 0x04 prefix (X||Y, 64B)."""
    point = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return point[1:]  # strip 0x04


def public_key_from_raw(raw_xy: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, b"\x04" + raw_xy)


def ecdh_shared_secret(private_key: ec.EllipticCurvePrivateKey, peer_raw_xy: bytes) -> bytes:
    """32-byte ECDH shared secret (the X coordinate), used as the AES-256 key."""
    peer = public_key_from_raw(peer_raw_xy)
    return private_key.exchange(ec.ECDH(), peer)


def sign_p1363(data: bytes) -> bytes:
    """SHA256withECDSA over ``data`` with the hardcoded client key, raw r||s (64B)."""
    der = _client_private_key().sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_device_signature(raw_sig: bytes, signed_data: bytes) -> bool:
    """Verify a device r||s signature against the cached server public key."""
    pub = serialization.load_der_public_key(bytes.fromhex(const.SERVER_PUBLIC_KEY_HEX))
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:64], "big")
    try:
        pub.verify(encode_dss_signature(r, s), signed_data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Handshake frame builders
# ---------------------------------------------------------------------------
def build_ack_frame(random_md5: bytes) -> bytes:
    """2A2A 02 04 <md5[8:12]> <sum16>  (plaintext, app -> device)."""
    body = bytes([const.HS_ACK, 0x04]) + random_md5[8:12]
    return const.HS_MAGIC + body + hex_sum(body, 2)


def build_sign_payload(our_pub_raw: bytes, signature: bytes) -> bytes:
    """2A2A 05 80 <ourPub 64B> <sig 64B> <sum16>  (plaintext, before AES)."""
    payload = our_pub_raw + signature
    body = bytes([const.HS_SIGN, len(payload) & 0xFF]) + payload
    return const.HS_MAGIC + body + hex_sum(body, 2)


@dataclass
class HelloInfo:
    random4: bytes
    random_md5: bytes
    aes_key: bytes


def parse_hello(frame: bytes) -> HelloInfo:
    """Parse a 2A2A 01 .. hello (random bytes start at offset 4)."""
    random4 = frame[4:8]
    rmd5 = random_md5_from_hello(random4)
    return HelloInfo(random4=random4, random_md5=rmd5, aes_key=handshake_key(rmd5))
