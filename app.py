from dotenv import load_dotenv
load_dotenv()
import os
import sqlite3
import uuid
import secrets
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_file, jsonify, abort
)
from argon2.exceptions import VerifyMismatchError, VerificationError

from database import password_hasher, get_connection
import crypto

app = Flask(__name__)

# Kunci untuk menandatangani cookie session Flask.
# Simpan di environment variable, bukan source code.
secret_key = os.environ.get("FLASK_SECRET_KEY")

if not secret_key:
    raise RuntimeError("FLASK_SECRET_KEY belum diatur.")

app.config["SECRET_KEY"] = secret_key
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Folder penyimpanan file terenkripsi
BASE_DIR = Path(__file__).resolve().parent
ENCRYPTED_FILES_DIR = BASE_DIR / "encrypted_files"
ENCRYPTED_FILES_DIR.mkdir(parents=True, exist_ok=True)

# Batas ukuran upload (500 MB, sesuai UI)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024

@app.context_processor
def inject_csrf_token():
    def csrf_token():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(32)

        return session["_csrf_token"]

    return {"csrf_token": csrf_token}

# Halaman utama
@app.route("/")
def home():
    return render_template("index.html")


# Halaman login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    connection = get_connection()

    try:

        user = connection.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()
    finally:
        connection.close()

    if user:
        try:
            password_hasher.verify(user["password_hash"], password)

        except (VerifyMismatchError, VerificationError):
            pass

        else:
            session.clear()
            session["user_id"] = user["id"]

            return redirect(url_for("dashboard"))

    return render_template(
        "login.html",
        error="Email atau password salah."
    ), 401


# Halaman dashboard
@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")
    if user_id is None:
        return redirect(url_for("login"))

    connection = get_connection()
    try:
        user = connection.execute(
            "SELECT id, email, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if user is None:
            session.clear()
            return redirect(url_for("login"))

        # Statistik
        stats_rows = connection.execute(
            """
            SELECT cipher, COUNT(*) as cnt
            FROM documents WHERE user_id = ?
            GROUP BY cipher
            """,
            (user_id,)
        ).fetchall()
        stats_by_cipher = {row["cipher"]: row["cnt"] for row in stats_rows}

        total_files = sum(stats_by_cipher.values())

        # Recent documents (limit 10)
        recent = connection.execute(
            """
            SELECT id, original_name, category, mime_type, size_bytes,
                   cipher, datetime(created_at, 'localtime') AS created_at
            FROM documents
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 10
            """,
            (user_id,)
        ).fetchall()

        # Khusus landlord: semua dokumen milik tenant-nya (opsi A)
        tenant_documents = []
        tenant_count = 0
        if user["role"] == "landlord":
            tenant_documents = connection.execute(
                """
                SELECT d.id, d.original_name, d.category, d.mime_type,
                       d.size_bytes, d.cipher, datetime(d.created_at, 'localtime') AS created_at,
                       u.email AS tenant_email
                FROM documents d
                JOIN users u ON u.id = d.user_id
                WHERE u.landlord_id = ?
                ORDER BY d.created_at DESC
                """,
                (user_id,)
            ).fetchall()

            tenant_count = connection.execute(
                "SELECT COUNT(*) FROM users WHERE landlord_id = ?",
                (user_id,)
            ).fetchone()[0]
    finally:
        connection.close()

    return render_template(
        "dashboard.html",
        email=user["email"],
        role=user["role"],
        total_files=total_files,
        stats_by_cipher=stats_by_cipher,
        recent_documents=recent,
        tenant_documents=tenant_documents,
        tenant_count=tenant_count,
    )

# Upload & enkripsi
@app.route("/upload", methods=["POST"])
def upload_document():
    user_id = session.get("user_id")
    if user_id is None:
        return redirect(url_for("login"))

    # CSRF
    token = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    if not expected or not secrets.compare_digest(token, expected):
        abort(400)

    file = request.files.get("file")
    cipher_name = request.form.get("cipher", "").strip().upper()
    category = request.form.get("category", "").strip()
    file_name = request.form.get("file_name", "").strip()

    if not file or not file.filename:
        return _upload_error("File belum dipilih.")
    if cipher_name not in crypto.SUPPORTED_CIPHERS:
        return _upload_error("Cipher tidak valid.")
    if not category:
        return _upload_error("Category wajib dipilih.")

    # Pastikan nama file tetap punya ekstensi aslinya (.pdf, .jpg, dst.)
    original_ext = Path(file.filename).suffix
    if not file_name:
        file_name = file.filename
    elif original_ext and not file_name.lower().endswith(original_ext.lower()):
        file_name += original_ext

    plaintext = file.read()
    if not plaintext:
        return _upload_error("File kosong.")

    try:
        blob = crypto.encrypt_file(plaintext, cipher_name)
    except Exception as exc:
        app.logger.exception("Enkripsi gagal")
        return _upload_error(f"Enkripsi gagal: {exc}")

    # Simpan ciphertext ke disk
    stored_name = f"{uuid.uuid4().hex}.enc"
    target = ENCRYPTED_FILES_DIR / stored_name
    target.write_bytes(blob["ciphertext"])

    # Insert metadata ke DB
    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT INTO documents (
                user_id, original_name, stored_name, category, mime_type,
                size_bytes, cipher, iv_or_nonce, auth_tag,
                wrapped_key, key_wrap_iv, sha256_plaintext
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id, file_name, stored_name, category,
                file.mimetype, len(plaintext), cipher_name,
                blob["iv_or_nonce"], blob["auth_tag"],
                blob["wrapped_key"], blob["key_wrap_iv"],
                blob["sha256_plaintext"],
            )
        )
        connection.commit()
    finally:
        connection.close()

    return redirect(url_for("dashboard") + "#dashboard")


def _upload_error(message: str):
    # Render ulang dashboard dengan pesan error
    user_id = session.get("user_id")
    # Sederhana: redirect dengan flash-style query param
    return render_template("dashboard.html",
        email="", role="tenant",
        total_files=0, stats_by_cipher={}, recent_documents=[],
        upload_error=message,
    ), 400


# Download & dekripsi
@app.route("/documents/<int:doc_id>/download")
def download_document(doc_id: int):
    user_id = session.get("user_id")
    if user_id is None:
        return redirect(url_for("login"))

    connection = get_connection()
    try:
        # Boleh download kalau:
        # 1. dokumen ini milik user yang login, ATAU
        # 2. user yang login adalah landlord dari pemilik dokumen (opsi A)
        doc = connection.execute(
            """
            SELECT d.*
            FROM documents d
            JOIN users owner ON owner.id = d.user_id
            WHERE d.id = ?
              AND (d.user_id = ? OR owner.landlord_id = ?)
            """,
            (doc_id, user_id, user_id)
        ).fetchone()
    finally:
        connection.close()

    # Anti-enumeration: tidak berhak = 404, bukan 403
    if doc is None:
        abort(404)

    target = ENCRYPTED_FILES_DIR / doc["stored_name"]
    if not target.exists():
        abort(404)

    ciphertext = target.read_bytes()
    blob = {
        "ciphertext": ciphertext,
        "iv_or_nonce": doc["iv_or_nonce"],
        "auth_tag": doc["auth_tag"],
        "wrapped_key": doc["wrapped_key"],
        "key_wrap_iv": doc["key_wrap_iv"],
        "sha256_plaintext": doc["sha256_plaintext"],
    }

    try:
        plaintext = crypto.decrypt_file(blob, doc["cipher"])
    except Exception:
        app.logger.exception("Dekripsi gagal untuk doc %s", doc_id)
        abort(500)

    # Kirim sebagai file attachment
    from io import BytesIO
    return send_file(
        BytesIO(plaintext),
        mimetype=doc["mime_type"] or "application/octet-stream",
        as_attachment=True,
        download_name=doc["original_name"],
    )


# Delete
@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
def delete_document(doc_id: int):
    user_id = session.get("user_id")
    if user_id is None:
        return redirect(url_for("login"))

    token = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    if not expected or not secrets.compare_digest(token, expected):
        abort(400)

    connection = get_connection()
    try:
        doc = connection.execute(
            "SELECT * FROM documents WHERE id = ?", (doc_id,)
        ).fetchone()
        if doc is None or doc["user_id"] != user_id:
            abort(404)

        connection.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
        connection.commit()
    finally:
        connection.close()

    # Hapus file dari disk
    target = ENCRYPTED_FILES_DIR / doc["stored_name"]
    if target.exists():
        target.unlink()

    return redirect(url_for("dashboard") + "#dashboard")

# Logout
@app.route("/logout", methods=["POST"])
def logout():
    token = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")

    if not expected or not secrets.compare_digest(token, expected):
        abort(400)

    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)