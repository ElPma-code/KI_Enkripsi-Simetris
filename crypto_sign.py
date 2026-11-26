"""
Tanda tangan digital RSA PKCS#1 v1.5 (RSASSA-PKCS1-v1_5) untuk Nestiefy.

Fokus modul ini: membuktikan keaslian paket NSTFY1 yang dikirim lewat WA
(bahwa paket benar dibuat pemilik private key, dan isinya tidak diubah).

Yang dibuat manual:
- EMSA-PKCS1-v1_5 encoding/decoding (RFC 8017 §9.2), termasuk DigestInfo DER
  prefix untuk SHA-256 dan string PS berisi 0xFF.
- RSASP1 / RSAVP1 (RFC 8017 §5.2) memakai pow() bawaan Python, bukan
  PKCS1_v1_5.new() dari library.

Key management mengikuti pola Tugas 2 di crypto.py:
private key disimpan sebagai PEM PKCS#8 terenkripsi password user
(scryptAndAES256-CBC), jadi harus di-load ulang tiap kali mau menandatangani.

Pemakaian:
    digest = hashlib.sha256(pesan).digest()
    sig = sign_digest(private_enc, password, digest)      # 384 byte (RSA-3072)
    verify_digest(public_pem, digest, sig)                # -> bool
"""

import hmac

from Crypto.PublicKey import RSA


# ASN.1 DER DigestInfo untuk SHA-256 (RFC 8017 §9.2, catatan 1):
#   SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }, OCTET STRING }
# Panjang 19 byte, ditambah digest 32 byte = 51 byte.
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

DIGEST_LEN = 32  # SHA-256


# --- Helper: load key -------------------------------------------------------

def _load_private_key(private_enc: str, password: str) -> RSA.RsaKey:
    """Import private key PEM terenkripsi. ValueError kalau password salah/PEM rusak."""
    try:
        key = RSA.import_key(private_enc, passphrase=password)
    except (ValueError, TypeError, IndexError) as exc:
        raise ValueError(
            "Private key gagal dibuka (password salah atau berkas PEM rusak)."
        ) from exc
    if not key.has_private():
        raise ValueError("Kunci yang diberikan bukan private key.")
    return key


def _load_public_key(public_pem: str) -> RSA.RsaKey:
    try:
        return RSA.import_key(public_pem)
    except (ValueError, TypeError, IndexError) as exc:
        raise ValueError("Public key tidak bisa dibaca (PEM rusak).") from exc


def _modulus_len(key: RSA.RsaKey) -> int:
    """k = panjang modulus dalam byte (ceil(bitlen/8))."""
    return key.size_in_bytes()


# --- Helper: EMSA-PKCS1-v1_5 (manual) --------------------------------------

def _emsa_pkcs1_v1_5_encode(digest: bytes, k: int) -> bytes:
    """Bentuk EM = 0x00 || 0x01 || PS(0xFF...) || 0x00 || DigestInfo.

    RFC 8017 §9.2 step 2-5. PS minimal 8 byte, jadi k >= len(T) + 11.
    """
    if len(digest) != DIGEST_LEN:
        raise ValueError(f"Digest harus {DIGEST_LEN} byte (SHA-256), bukan {len(digest)}.")

    t = SHA256_DIGEST_INFO_PREFIX + digest
    if k < len(t) + 11:
        raise ValueError(
            f"Modulus terlalu pendek ({k} byte) untuk PKCS#1 v1.5 + SHA-256."
        )

    ps = b"\xff" * (k - len(t) - 3)
    return b"\x00\x01" + ps + b"\x00" + t


def _emsa_pkcs1_v1_5_verify(em: bytes, digest: bytes, k: int) -> bool:
    """Cek apakah EM hasil dekripsi RSA persis sesuai format PKCS#1 v1.5.

    Perbandingan byte-per-byte dengan EM yang diharapkan (constant-time via
    hmac.compare_digest). Kalau formatnya beda sedikit saja -> invalid.
    """
    expected = _emsa_pkcs1_v1_5_encode(digest, k)
    return hmac.compare_digest(em, expected)


# --- API publik -------------------------------------------------------------

def sign_digest(private_enc: str, password: str, digest: bytes) -> bytes:
    """Tandatangani digest SHA-256 (32 byte) dengan private key + password.

    Digest TIDAK di-hash ulang di sini; pemanggil yang menyiapkannya.
    Return: signature raw, sepanjang k byte (384 byte untuk RSA-3072).
    """
    if len(digest) != DIGEST_LEN:
        raise ValueError(
            f"Digest harus {DIGEST_LEN} byte (SHA-256), bukan {len(digest)}."
        )

    key = _load_private_key(private_enc, password)
    k = _modulus_len(key)

    em = _emsa_pkcs1_v1_5_encode(digest, k)
    m = int.from_bytes(em, "big")

    # RSASP1: s = m^d mod n
    s = pow(m, key.d, key.n)
    return s.to_bytes(k, "big")


def verify_digest(public_pem: str, digest: bytes, signature: bytes) -> bool:
    """Verifikasi signature terhadap digest SHA-256.

    Return True kalau valid, False kalau signature/kunci/digest tidak cocok.
    ValueError hanya untuk input malformed (panjang digest/signature salah).
    """
    if len(digest) != DIGEST_LEN:
        raise ValueError(
            f"Digest harus {DIGEST_LEN} byte (SHA-256), bukan {len(digest)}."
        )

    key = _load_public_key(public_pem)
    k = _modulus_len(key)

    if len(signature) != k:
        raise ValueError(
            f"Panjang signature harus {k} byte (sesuai modulus), bukan {len(signature)}."
        )

    s = int.from_bytes(signature, "big")
    if s >= key.n:
        # Signature representative di luar range -> invalid (RFC 8017 §8.2.2 step 1)
        return False

    # RSAVP1: m = s^e mod n
    em = pow(s, key.e, key.n).to_bytes(k, "big")
    return _emsa_pkcs1_v1_5_verify(em, digest, k)
