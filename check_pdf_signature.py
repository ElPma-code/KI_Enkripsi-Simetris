"""Cek tanda tangan di dalam file PDF (di luar web app), pakai kode tim sendiri.

Pemakaian (dari folder project):
    python check_pdf_signature.py <file.pdf> <email penanda tangan> [--db path/ke/nestiefy.db]

Default database: instance/nestiefy.db (sama dengan web app).
"""
import argparse
import sqlite3
import sys

import crypto_sign
import database
import pdf_sign


def main() -> int:
    parser = argparse.ArgumentParser(description="Cek tanda tangan Nestiefy di dalam file PDF.")
    parser.add_argument("pdf", help="file PDF yang dicek")
    parser.add_argument("email", help="email penanda tangan (pemilik signing key)")
    parser.add_argument("--db", default=str(database.DB_PATH), help="path database SQLite")
    args = parser.parse_args()

    data = open(args.pdf, "rb").read()

    info = pdf_sign.extract_signature(data)          # baca /ByteRange + /Contents dari PDF
    if info is None:
        print("NOT SIGNED: tidak ada tanda tangan di PDF ini.")
        return 1

    # Hanya kunci PUBLIK yang dibutuhkan untuk verifikasi -> tidak perlu password.
    conn = sqlite3.connect(args.db)
    try:
        row = conn.execute(
            "SELECT k.public_pem FROM signing_keys k JOIN users u ON u.id = k.user_id WHERE u.email = ?",
            (args.email,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        print(f"Tidak ada signing key untuk {args.email}.")
        return 1

    print("File       :", args.pdf)
    print("Signer     :", info.signer_name)
    print("ByteRange  :", list(info.byte_range))
    print("SHA-256    :", info.digest.hex())
    print("Struktur OK:", info.is_intact)

    valid = info.is_intact and crypto_sign.verify_digest(row[0], info.digest, info.signature)
    print("RESULT     :", "VALID - isi PDF cocok dengan tanda tangan" if valid
          else "INVALID - isi PDF TIDAK cocok dengan tanda tangan (file sudah diubah)")
    return 0 if valid else 2


if __name__ == "__main__":
    sys.exit(main())
