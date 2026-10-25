import sqlite3
from pathlib import Path
from getpass import getpass

from argon2 import PasswordHasher

# Lokasi database
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "instance" / "nestiefy.db"

# Objek untuk hashing password
password_hasher = PasswordHasher()


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
                    CHECK (role IN ('tenant', 'landlord'))
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                category TEXT NOT NULL,
                mime_type TEXT,
                size_bytes INTEGER NOT NULL,
                cipher TEXT NOT NULL
                    CHECK (cipher IN ('AES', 'DES', 'RC4')),
                iv_or_nonce BLOB NOT NULL,
                auth_tag BLOB NOT NULL,
                wrapped_key BLOB NOT NULL,
                key_wrap_iv BLOB NOT NULL,
                sha256_plaintext TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        connection.commit()
    finally:
        connection.close()

    print("Database berhasil diinisialisasi.")


def seed_users():
    accounts = [
        ("tenant@test.com", "tenant"),
        ("owner@test.com", "landlord"),
    ]

    connection = sqlite3.connect(DB_PATH)

    try:
        for email, role in accounts:
            existing = connection.execute(
                "SELECT id FROM users WHERE email = ?",
                (email,)
            ).fetchone()

            if existing:
                print(f"Akun {email} sudah ada, dilewati.")
                continue

            password = getpass(f"Masukkan password untuk {email}: ")

            if len(password) < 12:
                raise ValueError(
                    "Password dummy minimal 12 karakter."
                )

            hashed_password = password_hasher.hash(password)

            connection.execute(
                """
                INSERT INTO users (email, password_hash, role)
                VALUES (?, ?, ?)
                """,
                (email, hashed_password, role)
            )

            print(f"Akun {email} berhasil dibuat.")

        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    init_db()
    seed_users()
