import secrets
import sqlite3
from pathlib import Path
from getpass import getpass

from argon2 import PasswordHasher
from dotenv import load_dotenv

# Lokasi file
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "instance" / "nestiefy.db"
ENV_PATH = BASE_DIR / ".env"

# Objek untuk hashing password
password_hasher = PasswordHasher()


def get_connection():
    """Buka koneksi ke database.
    - row_factory = sqlite3.Row  -> kolom bisa diakses pakai nama, mis. row["email"]
    - PRAGMA foreign_keys = ON   -> wajib di SQLite agar ON DELETE CASCADE benar-benar jalan
    - PRAGMA secure_delete = ON  -> data yang dihapus/diubah ditimpa nol di file .db,
                                    bukan sekadar ditandai kosong (sisa data tidak bisa diintip)
    """
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA secure_delete = ON")
    return connection


def init_env():
    """Buat file .env berisi key acak kalau belum ada.
    Kalau .env sudah ada, tidak diubah (supaya file lama tetap bisa didekripsi)."""
    if ENV_PATH.exists():
        print(".env sudah ada, dilewati.")
        return

    ENV_PATH.write_text(
        f"FLASK_SECRET_KEY={secrets.token_hex(32)}\n"
        f"MASTER_KEY_AES={secrets.token_hex(32)}\n",
        encoding="utf-8",
    )
    print(".env berhasil dibuat dengan key acak.")


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
                    CHECK (role IN ('tenant', 'landlord')),
                -- Untuk tenant: id landlord pemilik properti yang ia sewa.
                -- Untuk landlord: NULL.
                landlord_id INTEGER REFERENCES users(id) ON DELETE SET NULL
            )
        """)

        # Migrasi untuk database lama yang belum punya kolom landlord_id
        columns = [row[1] for row in connection.execute("PRAGMA table_info(users)")]
        if "landlord_id" not in columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN landlord_id INTEGER "
                "REFERENCES users(id) ON DELETE SET NULL"
            )
            print("Kolom landlord_id ditambahkan ke tabel users.")

        connection.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                -- Kolom lama, sekarang selalu diisi '' (nama asli TIDAK disimpan polos).
                original_name TEXT NOT NULL,
                -- Nama file asli terenkripsi AES-GCM (lihat crypto.encrypt_text).
                original_name_enc BLOB,
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

        # Migrasi: tambah kolom original_name_enc untuk database lama
        doc_columns = [row[1] for row in connection.execute("PRAGMA table_info(documents)")]
        if "original_name_enc" not in doc_columns:
            connection.execute("ALTER TABLE documents ADD COLUMN original_name_enc BLOB")
            print("Kolom original_name_enc ditambahkan ke tabel documents.")

        connection.commit()
    finally:
        connection.close()

    print("Database berhasil diinisialisasi.")


def migrate_encrypt_filenames():
    """Enkripsi nama file lama yang masih tersimpan polos di kolom original_name.
    Aman dijalankan berkali-kali: baris yang sudah terenkripsi dilewati."""
    import crypto  # import di sini karena butuh MASTER_KEY_AES dari .env

    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT id, original_name FROM documents "
            "WHERE original_name_enc IS NULL AND original_name != ''"
        ).fetchall()

        for row in rows:
            connection.execute(
                "UPDATE documents SET original_name_enc = ?, original_name = '' WHERE id = ?",
                (crypto.encrypt_text(row["original_name"]), row["id"])
            )
        connection.commit()
    finally:
        connection.close()

    if rows:
        # VACUUM menulis ulang seluruh file .db, sehingga sisa nama polos yang lama
        # benar-benar hilang dari disk (SQLite tidak langsung menimpa data lama).
        connection = sqlite3.connect(DB_PATH)
        try:
            connection.execute("VACUUM")
        finally:
            connection.close()
        print(f"{len(rows)} nama file lama berhasil dienkripsi.")


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

        # Hubungkan tenant dummy dengan landlord dummy (opsi A:
        # landlord bisa melihat semua dokumen milik tenant-nya)
        connection.execute(
            """
            UPDATE users
            SET landlord_id = (SELECT id FROM users WHERE email = ?)
            WHERE email = ? AND landlord_id IS NULL
            """,
            ("owner@test.com", "tenant@test.com")
        )

        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    init_env()
    load_dotenv(ENV_PATH)       # supaya MASTER_KEY_AES terbaca untuk migrasi
    init_db()
    migrate_encrypt_filenames()
    seed_users()