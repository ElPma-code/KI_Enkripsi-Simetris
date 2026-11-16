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

        # ===== Fitur berbagi dokumen (request -> approve -> unlock) =====

        # Keypair RSA-3072 per user. Dibuat otomatis saat login pertama
        # (hanya saat login server tahu password untuk mengenkripsi private key).
        connection.execute("""
            CREATE TABLE IF NOT EXISTS user_keys (
                user_id INTEGER PRIMARY KEY
                    REFERENCES users(id) ON DELETE CASCADE,
                public_pem TEXT NOT NULL,      -- boleh polos, memang publik
                private_enc TEXT NOT NULL,     -- PKCS#8 terenkripsi password (scrypt + AES-256-CBC)
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Satu baris = satu permintaan akses dari requester (A) ke owner (B, pemilik data)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS access_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                -- JSON list kategori yang diminta, mis. ["ID Document", "Payment Proof"].
                -- A memilih KATEGORI, bukan dokumen: A tidak boleh melihat daftar dokumen B.
                requested_categories TEXT NOT NULL,
                message TEXT,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'unlocked',
                                      'rejected', 'revoked', 'expired')),
                -- Diisi saat approve. K_share disimpan TERBUNGKUS master key (AES-GCM, AAD=id)
                k_share_wrapped BLOB,
                k_share_nonce BLOB,
                -- Paket NSTFY1.<id>.<base64> (K_share terenkripsi RSA-OAEP untuk A).
                -- Aman disimpan karena hanya bisa dibuka private key A.
                package TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                decided_at TIMESTAMP,
                expires_at TIMESTAMP,          -- UTC, format 'YYYY-MM-DD HH:MM:SS'
                CHECK (requester_id != owner_id)
            )
        """)

        # Dokumen yang DISETUJUI B, beserta data key yang di-rewrap ke K_share
        connection.execute("""
            CREATE TABLE IF NOT EXISTS share_grants (
                request_id INTEGER NOT NULL
                    REFERENCES access_requests(id) ON DELETE CASCADE,
                document_id INTEGER NOT NULL
                    REFERENCES documents(id) ON DELETE CASCADE,
                rewrapped_key BLOB NOT NULL,   -- data key terbungkus K_share (AES-GCM)
                rewrap_nonce BLOB NOT NULL,
                PRIMARY KEY (request_id, document_id)
            )
        """)

        # ===== Audit Log untuk akses dokumen bersama =====
        connection.execute("""
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                request_id INTEGER
                    REFERENCES access_requests(id)
                    ON DELETE SET NULL,

                user_id INTEGER
                    REFERENCES users(id)
                    ON DELETE SET NULL,

                document_id INTEGER
                    REFERENCES documents(id)
                    ON DELETE SET NULL,

                action TEXT NOT NULL
                    CHECK (action IN (
                        'unlock',
                        'unlock_failed',
                        'download'
                    )),

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_access_logs_request
            ON access_logs(request_id, created_at)
        """)

        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_requests_owner ON access_requests(owner_id, status)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_requests_requester ON access_requests(requester_id, status)"
        )

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