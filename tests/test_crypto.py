import hashlib

from bluetti_monitor import const, crypto


def test_handshake_key_xor():
    rmd5 = bytes(range(16))
    key = crypto.handshake_key(rmd5)
    assert key == bytes(a ^ b for a, b in zip(rmd5, const.LOCAL_AES_KEY))
    assert len(key) == 16


def test_random_md5_reversed():
    r = bytes([1, 2, 3, 4])
    assert crypto.random_md5_from_hello(r) == hashlib.md5(bytes([4, 3, 2, 1])).digest()


def test_aes_frame_roundtrip_handshake_phase():
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    plaintext = bytes.fromhex("0103000A003B1234")  # arbitrary, non block-aligned
    frame = crypto.build_encrypted_frame(plaintext, key, iv)
    # LEN prefix then ciphertext (multiple of 16)
    assert int.from_bytes(frame[:2], "big") == len(plaintext)
    assert (len(frame) - 2) % 16 == 0
    out = crypto.parse_encrypted_frame(frame, key, iv)
    assert out == plaintext


def test_aes_frame_roundtrip_shared_phase():
    key = bytes(range(32))  # AES-256 shared secret
    plaintext = bytes.fromhex("01030200210064")
    frame = crypto.build_encrypted_frame(plaintext, key, iv=None)
    # LEN(2) + RAND(4) + ciphertext
    assert int.from_bytes(frame[:2], "big") == len(plaintext)
    assert (len(frame) - 6) % 16 == 0
    out = crypto.parse_encrypted_frame(frame, key, iv=None)
    assert out == plaintext


def test_ecdh_shared_secret_symmetry():
    a = crypto.generate_ecdh_keypair()
    b = crypto.generate_ecdh_keypair()
    a_raw = crypto.public_key_raw(a)
    b_raw = crypto.public_key_raw(b)
    assert len(a_raw) == 64
    s1 = crypto.ecdh_shared_secret(a, b_raw)
    s2 = crypto.ecdh_shared_secret(b, a_raw)
    assert s1 == s2
    assert len(s1) == 32


def test_sign_p1363_verifies_with_client_pubkey():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    data = b"hello bluetti"
    sig = crypto.sign_p1363(data)
    assert len(sig) == 64
    # Reconstruct the client public key and verify.
    priv = ec.derive_private_key(int(const.CLIENT_PRIVATE_KEY_HEX, 16), ec.SECP256R1())
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    priv.public_key().verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))


def test_ack_frame_structure():
    rmd5 = bytes(range(16))
    frame = crypto.build_ack_frame(rmd5)
    assert frame[:2] == const.HS_MAGIC
    assert frame[2] == const.HS_ACK
    assert frame[3] == 0x04
    assert frame[4:8] == rmd5[8:12]


def test_sign_payload_length_byte():
    pub = bytes(range(64))
    sig = bytes(range(64))
    frame = crypto.build_sign_payload(pub, sig)
    assert frame[:2] == const.HS_MAGIC
    assert frame[2] == const.HS_SIGN
    assert frame[3] == 128  # 0x80, payload length
    assert frame[4:4 + 128] == pub + sig
