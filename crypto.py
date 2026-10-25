"""
Modul enkripsi simetris untuk Nestiefy.

Cipher yang didukung:
- AES-GCM         : authenticated encryption (AEAD)
- DES-CBC + HMAC  : encrypt-then-MAC (DES sendiri tidak authenticated)
- RC4 + HMAC      : encrypt-then-MAC (RC4 stream cipher, tidak authenticated)

Key management: envelope encryption.
- Setiap file punya data key random sendiri (AES 32B / DES 8B / RC4 32B).
- Data key di-wrap pakai master key dari environment variable.
- Master key TIDAK pernah disimpan di DB, hanya di env.
"""

import os
import hmac
import hashlib
import secrets
from typing import TypedDict

from Crypto.Cipher import AES, DES, ARC4
from Crypto.Util.Padding import pad, unpad


# Konfigurasi master key (dari environment)

def _load_master_key(env_name: str, expected_len: int) -> bytes:
    raw = os.environ.get(env_name)
    if not raw:
        raise RuntimeError(f"{env_name} belum diatur di environment.")
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise RuntimeError(f"{env_name} harus berupa hex string.")
    if len(key) != expected_len:
        raise RuntimeError(
            f"{env_name} harus {expected_len} byte (hex {expected_len * 2} karakter)."
        )
    return key


def get_master_key_aes() -> bytes:
    return _load_master_key("MASTER_KEY_AES", 32)  # 256-bit


def get_master_key_des() -> bytes:
    return _load_master_key("MASTER_KEY_DES", 8)   # 64-bit (56-bit efektif)


def get_master_key_rc4() -> bytes:
    return _load_master_key("MASTER_KEY_RC4", 32)  # 256-bit


# Tipe hasil enkripsi

class EncryptedBlob(TypedDict):
    ciphertext: bytes
    iv_or_nonce: bytes
    auth_tag: bytes
    wrapped_key: bytes
    key_wrap_iv: bytes
    sha256_plaintext: str


# Helper: wrap / unwrap data key

def _wrap_key_aes_gcm(data_key: bytes) -> tuple[bytes, bytes, bytes]:
    """Wrap data key pakai AES-GCM (authenticated, ideal)."""
    master = get_master_key_aes()
    nonce = secrets.token_bytes(12)  # 96-bit nonce untuk GCM
    cipher = AES.new(master, AES.MODE_GCM, nonce=nonce)
    wrapped, tag = cipher.encrypt_and_digest(data_key)
    # Gabungkan nonce + wrapped + tag jadi satu blob
    # Tapi kita return terpisah biar DB rapi
    return nonce, wrapped, tag


def _unwrap_key_aes_gcm(nonce: bytes, wrapped: bytes, tag: bytes) -> bytes:
    master = get_master_key_aes()
    cipher = AES.new(master, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(wrapped, tag)


def _wrap_key_cbc_hook(data_key: bytes, master: bytes, block_size: int) -> tuple[bytes, bytes]:
    """
    Wrap data key pakai AES-CBC + HMAC (untuk DES & RC4 yang tidak punya AEAD).
    Return: (iv, wrapped_with_tag)
    Format wrapped_with_tag = ciphertext || hmac_tag (32 byte).
    """
    iv = secrets.token_bytes(16)
    cipher = AES.new(master, AES.MODE_CBC, iv=iv)
    padded = pad(data_key, AES.block_size)
    ciphertext = cipher.encrypt(padded)
    # Encrypt-then-MAC: HMAC atas iv || ciphertext
    mac = hmac.new(master, iv + ciphertext, hashlib.sha256).digest()
    return iv, ciphertext + mac


def _unwrap_key_cbc_hook(iv: bytes, wrapped_with_tag: bytes, master: bytes) -> bytes:
    if len(wrapped_with_tag) < 32:
        raise ValueError("Wrapped key terlalu pendek.")
    ciphertext = wrapped_with_tag[:-32]
    mac_received = wrapped_with_tag[-32:]
    mac_expected = hmac.new(master, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_received, mac_expected):
        raise ValueError("HMAC wrapped key tidak valid (mungkin master key salah atau data dirusak).")
    cipher = AES.new(master, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


def _wrap_data_key(cipher_name: str, data_key: bytes) -> tuple[bytes, bytes]:
    """
    Wrap data key sesuai cipher. Return: (wrapped_key, key_wrap_iv)
    - Untuk AES: wrapped_key = ciphertext + tag, key_wrap_iv = nonce
    - Untuk DES/RC4: wrapped_key = ciphertext + hmac_tag, key_wrap_iv = iv
    """
    if cipher_name == "AES":
        nonce, wrapped, tag = _wrap_key_aes_gcm(data_key)
        return wrapped + tag, nonce
    elif cipher_name == "DES":
        iv, wrapped = _wrap_key_cbc_hook(data_key, get_master_key_aes(), 8)
        return wrapped, iv
    elif cipher_name == "RC4":
        iv, wrapped = _wrap_key_cbc_hook(data_key, get_master_key_aes(), 32)
        return wrapped, iv
    else:
        raise ValueError(f"Cipher tidak dikenal: {cipher_name}")


def _unwrap_data_key(cipher_name: str, wrapped_key: bytes, key_wrap_iv: bytes) -> bytes:
    if cipher_name == "AES":
        if len(wrapped_key) < 16:
            raise ValueError("Wrapped key AES terlalu pendek.")
        wrapped, tag = wrapped_key[:-16], wrapped_key[-16:]
        return _unwrap_key_aes_gcm(key_wrap_iv, wrapped, tag)
    elif cipher_name == "DES":
        return _unwrap_key_cbc_hook(key_wrap_iv, wrapped_key, get_master_key_aes())
    elif cipher_name == "RC4":
        return _unwrap_key_cbc_hook(key_wrap_iv, wrapped_key, get_master_key_aes())
    else:
        raise ValueError(f"Cipher tidak dikenal: {cipher_name}")


# Enkripsi / Dekripsi per cipher

def _encrypt_aes_gcm(plaintext: bytes) -> EncryptedBlob:
    data_key = secrets.token_bytes(32)  # AES-256
    nonce = secrets.token_bytes(12)     # 96-bit nonce (rekomendasi GCM)

    cipher = AES.new(data_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    wrapped_key, key_wrap_iv = _wrap_data_key("AES", data_key)

    return EncryptedBlob(
        ciphertext=ciphertext,
        iv_or_nonce=nonce,
        auth_tag=tag,
        wrapped_key=wrapped_key,
        key_wrap_iv=key_wrap_iv,
        sha256_plaintext=hashlib.sha256(plaintext).hexdigest(),
    )


def _decrypt_aes_gcm(blob: EncryptedBlob) -> bytes:
    data_key = _unwrap_data_key("AES", blob["wrapped_key"], blob["key_wrap_iv"])
    cipher = AES.new(data_key, AES.MODE_GCM, nonce=blob["iv_or_nonce"])
    plaintext = cipher.decrypt_and_verify(blob["ciphertext"], blob["auth_tag"])

    if hashlib.sha256(plaintext).hexdigest() != blob["sha256_plaintext"]:
        raise ValueError("Integritas plaintext AES-GCM gagal (hash tidak cocok).")
    return plaintext


def _encrypt_des_cbc(plaintext: bytes) -> EncryptedBlob:
    data_key = secrets.token_bytes(8)   # DES-64 (56-bit efektif)
    iv = secrets.token_bytes(8)         # DES block 8 byte

    cipher = DES.new(data_key, DES.MODE_CBC, iv=iv)
    padded = pad(plaintext, DES.block_size)
    ciphertext = cipher.encrypt(padded)

    # HMAC pakai data_key (encrypt-then-MAC)
    hmac_tag = hmac.new(data_key, iv + ciphertext, hashlib.sha256).digest()

    wrapped_key, key_wrap_iv = _wrap_data_key("DES", data_key)

    return EncryptedBlob(
        ciphertext=ciphertext,
        iv_or_nonce=iv,
        auth_tag=hmac_tag,
        wrapped_key=wrapped_key,
        key_wrap_iv=key_wrap_iv,
        sha256_plaintext=hashlib.sha256(plaintext).hexdigest(),
    )


def _decrypt_des_cbc(blob: EncryptedBlob) -> bytes:
    data_key = _unwrap_data_key("DES", blob["wrapped_key"], blob["key_wrap_iv"])

    mac_expected = hmac.new(
        data_key, blob["iv_or_nonce"] + blob["ciphertext"], hashlib.sha256
    ).digest()
    if not hmac.compare_digest(mac_expected, blob["auth_tag"]):
        raise ValueError("HMAC DES tidak valid (data dirusak atau kunci salah).")

    cipher = DES.new(data_key, DES.MODE_CBC, iv=blob["iv_or_nonce"])
    plaintext = unpad(cipher.decrypt(blob["ciphertext"]), DES.block_size)

    if hashlib.sha256(plaintext).hexdigest() != blob["sha256_plaintext"]:
        raise ValueError("Integritas plaintext DES gagal (hash tidak cocok).")
    return plaintext


def _encrypt_rc4(plaintext: bytes) -> EncryptedBlob:
    data_key = secrets.token_bytes(32)
    cipher = ARC4.new(data_key)
    ciphertext = cipher.encrypt(plaintext)

    # HMAC pakai data_key (encrypt-then-MAC)
    hmac_tag = hmac.new(data_key, ciphertext, hashlib.sha256).digest()

    wrapped_key, key_wrap_iv = _wrap_data_key("RC4", data_key)

    return EncryptedBlob(
        ciphertext=ciphertext,
        iv_or_nonce=b"",  # RC4 tidak pakai IV
        auth_tag=hmac_tag,
        wrapped_key=wrapped_key,
        key_wrap_iv=key_wrap_iv,
        sha256_plaintext=hashlib.sha256(plaintext).hexdigest(),
    )


def _decrypt_rc4(blob: EncryptedBlob) -> bytes:
    data_key = _unwrap_data_key("RC4", blob["wrapped_key"], blob["key_wrap_iv"])

    mac_expected = hmac.new(data_key, blob["ciphertext"], hashlib.sha256).digest()
    if not hmac.compare_digest(mac_expected, blob["auth_tag"]):
        raise ValueError("HMAC RC4 tidak valid (data dirusak atau kunci salah).")

    cipher = ARC4.new(data_key)
    plaintext = cipher.decrypt(blob["ciphertext"])

    if hashlib.sha256(plaintext).hexdigest() != blob["sha256_plaintext"]:
        raise ValueError("Integritas plaintext RC4 gagal (hash tidak cocok).")
    return plaintext


# API Publik

SUPPORTED_CIPHERS = ("AES", "DES", "RC4")


def encrypt_file(plaintext: bytes, cipher_name: str) -> EncryptedBlob:
    """Enkripsi plaintext pakai cipher yang dipilih, return blob terstruktur."""
    if cipher_name == "AES":
        return _encrypt_aes_gcm(plaintext)
    elif cipher_name == "DES":
        return _encrypt_des_cbc(plaintext)
    elif cipher_name == "RC4":
        return _encrypt_rc4(plaintext)
    else:
        raise ValueError(f"Cipher tidak didukung: {cipher_name}")


def decrypt_file(blob: EncryptedBlob, cipher_name: str) -> bytes:
    """Dekripsi blob dan verifikasi integritas."""
    if cipher_name == "AES":
        return _decrypt_aes_gcm(blob)
    elif cipher_name == "DES":
        return _decrypt_des_cbc(blob)
    elif cipher_name == "RC4":
        return _decrypt_rc4(blob)
    else:
        raise ValueError(f"Cipher tidak didukung: {cipher_name}")