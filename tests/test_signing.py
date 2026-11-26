import hashlib

import pytest
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from crypto import generate_user_keypair
from crypto_sign import sign_digest, verify_digest

PASSWORD = "passwordA"


@pytest.fixture(scope="module")
def keypair():
    # Generate sekali buat semua test (RSA-3072 mahal)
    return generate_user_keypair(PASSWORD)


def _digest(message: bytes) -> bytes:
    return hashlib.sha256(message).digest()


def test_sign_then_verify_ok(keypair):
    pub, priv = keypair
    d = _digest(b"paket NSTFY1 rahasia banget")

    sig = sign_digest(priv, PASSWORD, d)

    assert len(sig) == 384  # RSA-3072
    assert verify_digest(pub, d, sig) is True


def test_modified_hash_fails(keypair):
    pub, priv = keypair
    d_asli = _digest(b"paket asli")

    sig = sign_digest(priv, PASSWORD, d_asli)

    # Hash diubah -> signature tidak berlaku lagi
    assert verify_digest(pub, _digest(b"paket diubah"), sig) is False


def test_wrong_key_fails(keypair):
    pub, priv = keypair
    pub_lain, _ = generate_user_keypair("passwordB")

    d = _digest(b"data")
    sig = sign_digest(priv, PASSWORD, d)

    # Verifikasi pakai public key orang lain -> harus gagal
    assert verify_digest(pub_lain, d, sig) is False


def test_wrong_password_raises(keypair):
    _, priv = keypair

    # Private key terenkripsi password lain -> import_key gagal
    with pytest.raises(ValueError):
        sign_digest(priv, "passwordSalah", _digest(b"data"))


def test_malformed_digest_raises(keypair):
    pub, priv = keypair

    with pytest.raises(ValueError):
        sign_digest(priv, PASSWORD, b"terlalu pendek")

    with pytest.raises(ValueError):
        verify_digest(pub, b"terlalu pendek", b"\x00" * 384)


def test_malformed_signature_raises(keypair):
    pub, _ = keypair

    # Panjang signature bukan 384 byte
    with pytest.raises(ValueError):
        verify_digest(pub, _digest(b"data"), b"\x00" * 10)


def test_signature_bit_flip_fails(keypair):
    pub, priv = keypair
    d = _digest(b"data")

    sig = bytearray(sign_digest(priv, PASSWORD, d))
    sig[-1] ^= 0x01  # rusak 1 bit

    assert verify_digest(pub, d, bytes(sig)) is False


def test_interop_with_pycryptodome(keypair):
    # Bukti padding manual kita persis PKCS#1 v1.5 (RFC 8017 §9.2):
    # signature buatan kita harus diterima verifier library standar.
    pub, priv = keypair
    pesan = b"data yang mau ditandatangani"

    sig = sign_digest(priv, PASSWORD, _digest(pesan))

    key = RSA.import_key(pub)
    # verify() return None kalau valid, raise ValueError kalau tidak
    assert pkcs1_15.new(key).verify(SHA256.new(pesan), sig) is None


def test_interop_verify_library_signature(keypair):
    # Arah sebaliknya: signature buatan library harus diterima verify_digest kita.
    pub, priv = keypair
    pesan = b"balik arah"

    key = RSA.import_key(priv, passphrase=PASSWORD)
    sig_lib = pkcs1_15.new(key).sign(SHA256.new(pesan))

    assert verify_digest(pub, _digest(pesan), sig_lib) is True


def test_interop_rejects_tampered_signature(keypair):
    # Verifier standar harus MENOLAK signature yang dirusak -> perlu pytest.raises
    pub, priv = keypair
    pesan = b"data"

    sig = bytearray(sign_digest(priv, PASSWORD, _digest(pesan)))
    sig[-1] ^= 0x01

    key = RSA.import_key(pub)
    with pytest.raises(ValueError):
        pkcs1_15.new(key).verify(SHA256.new(pesan), bytes(sig))
