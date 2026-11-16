# tests/test_crypto.py (contoh isi)
import pytest
from crypto import generate_user_keypair, encrypt_share_key_for, decrypt_share_key

def test_round_trip_share_key():
    # 1. User A bikin keypair
    pub, priv = generate_user_keypair("passwordA")
    k_share = b"ini_kunci_rahasia_32_byte_abcde"
    
    # 2. Enkripsi k_share pakai public key A
    ct = encrypt_share_key_for(pub, k_share)
    
    # 3. A buka pakai private key + password
    decrypted = decrypt_share_key(priv, "passwordA", ct)
    assert decrypted == k_share

def test_wrong_password_fails():
    pub, priv = generate_user_keypair("passwordA")
    ct = encrypt_share_key_for(pub, b"rahasia")
    
    # Password salah harus error
    with pytest.raises(ValueError):
        decrypt_share_key(priv, "passwordSalah", ct)