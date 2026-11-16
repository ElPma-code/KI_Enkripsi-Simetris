
"""
Unlock dan Access Control untuk dokumen yang dibagikan.
"""

import secrets
import crypto
import access_requests
from database import get_connection
import hmac
from io import BytesIO
from flask import current_app, send_file
import base64
import binascii
import re

from flask import Blueprint, abort, request, session

bp = Blueprint("shared", __name__, url_prefix="/shared")

def record_access_log(connection, request_id, user_id,
                      action, document_id=None):
    """Catat aktivitas tanpa menyimpan informasi rahasia."""
    connection.execute(
        """
        INSERT INTO access_logs
            (request_id, user_id, document_id, action)
        VALUES (?, ?, ?, ?)
        """,
        (request_id, user_id, document_id, action)
    )


def unlock_failure(user_id, request_id=None, connection=None):
    """Catat kegagalan Unlock tanpa menyimpan informasi rahasia."""
    own_connection = connection is None

    if own_connection:
        connection = get_connection()

    try:
        record_access_log(
            connection,
            request_id,
            user_id,
            "unlock_failed"
        )
        connection.commit()
    finally:
        if own_connection:
            connection.close()

    return "Paket atau password tidak valid.", 400

@bp.route("/unlock", methods=["POST"])
def unlock():
    # 1. Pastikan pengguna sudah login
    user_id = session.get("user_id")

    if user_id is None:
        abort(401)

    # 2. Validasi CSRF token
    token = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    # Belum ada request_id yang terverifikasi kepemilikannya
    safe_request_id = None
    if not expected or not secrets.compare_digest(token, expected):
        abort(400)


    # 3. Ambil paket dan password dari form
    package = request.form.get("package", "")
    password = request.form.get("password", "")


    # 4. Validasi ketat format paket Nestiefy
    try:
        # Batasi ukuran input untuk mencegah paket berlebihan
        if len(package) > 1024:
            raise ValueError("Paket terlalu panjang")

        parts = package.split(".")

        if len(parts) != 3 or parts[0] != "NSTFY1":
            raise ValueError("Format paket salah")

        # Request ID hanya menerima angka positif
        if not re.fullmatch(r"[1-9][0-9]{0,18}", parts[1]):
            raise ValueError("Request ID tidak valid")

        request_id = int(parts[1])

        if request_id > 2**63 - 1:
            raise ValueError("Request ID terlalu besar")

        # Validasi Base64 tanpa mengabaikan karakter asing
        ciphertext = base64.b64decode(
            parts[2], validate=True
        )

        # RSA-3072 menghasilkan ciphertext 384 byte
        if len(ciphertext) != 384:
            raise ValueError("Panjang ciphertext tidak valid")

        # Pastikan encoding Base64 berbentuk kanonis
        if base64.b64encode(ciphertext).decode("ascii") != parts[2]:
            raise ValueError("Encoding paket tidak valid")

        # Decode menggunakan fungsi resmi dari crypto.py
        decoded_id, encrypted_share_key = crypto.decode_package(
            package
        )

        if int(decoded_id) != request_id:
            raise ValueError("Request ID tidak cocok")

    except (ValueError, TypeError, binascii.Error):
        return unlock_failure(user_id, safe_request_id)

    # 5. Periksa request di database
    connection = get_connection()

    try:
        # Perbarui request yang sudah kedaluwarsa
        access_requests.expire_old_requests(connection)
        connection.commit()

        # Request harus ditujukan kepada user yang sedang login

        access_row = connection.execute(
            """
            SELECT id, requester_id, owner_id, status, expires_at,
                   k_share_wrapped, k_share_nonce
            FROM access_requests
            WHERE id = ? AND requester_id = ?
            """,
            (request_id, user_id)
        ).fetchone()

        if access_row is not None:
            safe_request_id = request_id

        # Tolak request yang tidak ditemukan atau belum approved
        if access_row is None or access_row["status"] != "approved":
            return unlock_failure(user_id, safe_request_id)

        # Pastikan masa berlaku belum habis
        if (
            access_row["expires_at"] is None
            or connection.execute(
                "SELECT ? <= datetime('now')",
                (access_row["expires_at"],)
            ).fetchone()[0]
        ):
            return unlock_failure(user_id, safe_request_id)
        # 6. Ambil private key terenkripsi milik penerima
        user_key = connection.execute(
            """
            SELECT private_enc
            FROM user_keys
            WHERE user_id = ?
            """,
            (user_id,)
        ).fetchone()

        if user_key is None:
            return unlock_failure(user_id, safe_request_id)

        # 7. Dekripsi K_share menggunakan RSA private key
        try:
            k_share = crypto.decrypt_share_key(
                user_key["private_enc"],
                password,
                encrypted_share_key
            )
        except (ValueError, TypeError):
            return unlock_failure(user_id, safe_request_id)

        # RSA berhasil, tetapi K_share belum diverifikasi
        if len(k_share) != crypto.SHARE_KEY_LEN:
            return unlock_failure(user_id, safe_request_id)

        # 8. Ambil K_share yang tersimpan terenkripsi
        if (
            access_row["k_share_nonce"] is None
            or access_row["k_share_wrapped"] is None
        ):
            return unlock_failure(user_id, safe_request_id)

        try:
            stored_k_share = crypto.unwrap_share_key(
                access_row["k_share_nonce"],
                access_row["k_share_wrapped"],
                request_id
            )
        except (ValueError, TypeError):
            return unlock_failure(user_id, safe_request_id)

        # 9. Bandingkan kedua kunci secara aman
        if not hmac.compare_digest(k_share, stored_k_share):
            return unlock_failure(user_id, safe_request_id)

        # 10. Ambil grant dokumen dari request yang disetujui
        grants = connection.execute(
            """
            SELECT
                g.document_id,
                g.rewrapped_key,
                g.rewrap_nonce,
                d.cipher
            FROM share_grants g
            JOIN documents d
                ON d.id = g.document_id
            WHERE g.request_id = ?
            AND d.user_id = ?
            """,
            ((request_id, access_row["owner_id"]))
        ).fetchall()

        if not grants:
            return unlock_failure(user_id, safe_request_id)

        # 11. Pastikan K_share bisa membuka minimal satu data key
        valid_data_key = False

        for grant in grants:
            try:
                data_key = crypto.unwrap_rewrapped_data_key(
                    k_share,
                    grant["rewrap_nonce"],
                    grant["rewrapped_key"],
                    crypto.share_doc_aad(
                        request_id,
                        grant["document_id"]
                    )
                )

                expected_lengths = {
                    "AES": 32,
                    "DES": 8,
                    "RC4": 32,
                }

                if len(data_key) == expected_lengths.get(grant["cipher"]):
                    valid_data_key = True
                    break


            except (ValueError, TypeError):
                continue

        if not valid_data_key:
            return unlock_failure(user_id, safe_request_id)

        # 12. Aktifkan akses setelah seluruh verifikasi berhasil
        updated = connection.execute(
            """
            UPDATE access_requests
            SET status = 'unlocked'
            WHERE id = ?
              AND requester_id = ?
              AND status = 'approved'
              AND expires_at > datetime('now')
            """,
            (request_id, user_id)
        ).rowcount

        if updated != 1:
            connection.rollback()
            return unlock_failure(user_id, safe_request_id)

        # Catat Unlock berhasil dalam transaksi yang sama
        record_access_log(
            connection,
            request_id,
            user_id,
            "unlock"
        )

        connection.commit()

    finally:
        connection.close()

    return "Paket berhasil diverifikasi. Akses dokumen dibuka.", 200

def shared_context(connection, user_id: int) -> list[dict]:
    """
    Ambil dokumen yang dibagikan kepada user.

    Hanya request unlocked, belum expired,
    dan memiliki share_grants yang ditampilkan.
    """

    # Perbarui status request yang kedaluwarsa
    access_requests.expire_old_requests(connection)
    connection.commit()

    rows = connection.execute(
        """
        SELECT
            r.id AS request_id,
            d.id AS doc_id,
            d.original_name,
            d.original_name_enc,
            d.category,
            d.size_bytes,
            d.cipher,
            u.email AS owner_email,
            datetime(r.expires_at, 'localtime') AS expires_at

        FROM access_requests r

        JOIN share_grants g
            ON g.request_id = r.id

        JOIN documents d
            ON d.id = g.document_id
            AND d.user_id = r.owner_id

        JOIN users u
            ON u.id = r.owner_id

        WHERE r.requester_id = ?
          AND r.status = 'unlocked'
          AND r.expires_at > datetime('now')

        ORDER BY r.id DESC, d.id DESC
        """,
        (user_id,)
    ).fetchall()

    documents = []

    for row in rows:
        item = dict(row)

        # Nama file disimpan terenkripsi di database
        if item["original_name_enc"] is not None:
            try:
                item["original_name"] = crypto.decrypt_text(
                    item["original_name_enc"]
                )
            except (ValueError, UnicodeError):
                item["original_name"] = (
                    "(nama file tidak dapat didekripsi)"
                )

        # Jangan kirim ciphertext nama file ke frontend
        item.pop("original_name_enc", None)

        documents.append(item)

    return documents

@bp.route(
    "/<int:request_id>/documents/<int:doc_id>/download",
    methods=["GET"]
)
def download_shared(request_id: int, doc_id: int):
    """Download dokumen melalui grant sharing yang masih aktif."""

    user_id = session.get("user_id")
    if user_id is None:
        abort(401)

    connection = get_connection()

    try:
        # 1. Perbarui request yang sudah expired
        access_requests.expire_old_requests(connection)
        connection.commit()

        # 2. Periksa request, pemilik, dan grant dokumen
        row = connection.execute(
            """
            SELECT
                r.id AS request_id,
                r.k_share_nonce,
                r.k_share_wrapped,
                g.rewrapped_key,
                g.rewrap_nonce,
                d.*

            FROM access_requests r

            JOIN share_grants g
                ON g.request_id = r.id

            JOIN documents d
                ON d.id = g.document_id
                AND d.user_id = r.owner_id

            WHERE r.id = ?
              AND r.requester_id = ?
              AND r.status = 'unlocked'
              AND r.expires_at > datetime('now')
              AND g.document_id = ?
            """,
            (request_id, user_id, doc_id)
        ).fetchone()

        # Tidak ada izin = dokumen tidak ditemukan
        if row is None:
            abort(404)

        if (
            row["k_share_nonce"] is None
            or row["k_share_wrapped"] is None
        ):
            abort(404)

        # 3. Buka K_share menggunakan master key aplikasi
        try:
            k_share = crypto.unwrap_share_key(
                row["k_share_nonce"],
                row["k_share_wrapped"],
                request_id
            )

            # 4. Buka data key dokumen melalui K_share
            data_key = crypto.unwrap_rewrapped_data_key(
                k_share,
                row["rewrap_nonce"],
                row["rewrapped_key"],
                crypto.share_doc_aad(request_id, doc_id)
            )

            # Validasi panjang key sesuai algoritma


            # Validasi panjang key sesuai algoritma
            expected_lengths = {
                "AES": 32,
                "DES": 8,
                "RC4": 32,
            }

            if len(data_key) != expected_lengths.get(row["cipher"]):
                abort(404)

        except (ValueError, TypeError):
            current_app.logger.warning(
                "Gagal membuka shared key untuk request %s",
                request_id
            )
            abort(404)

        # 5. Ambil ciphertext dari penyimpanan
        from app import ENCRYPTED_FILES_DIR

        target = ENCRYPTED_FILES_DIR / row["stored_name"]

        if not target.is_file():
            abort(404)

        ciphertext = target.read_bytes()

        blob = {
            "ciphertext": ciphertext,
            "iv_or_nonce": row["iv_or_nonce"],
            "auth_tag": row["auth_tag"],
            "wrapped_key": row["wrapped_key"],
            "key_wrap_iv": row["key_wrap_iv"],
            "sha256_plaintext": row["sha256_plaintext"]
        }

        # 6. Dekripsi file dan verifikasi integritas
        try:
            plaintext = crypto.decrypt_file(
                blob,
                row["cipher"],
                data_key=data_key
            )

            if row["original_name_enc"] is not None:
                filename = crypto.decrypt_text(
                    row["original_name_enc"]
                )
            else:
                filename = row["original_name"]

        except (ValueError, TypeError, UnicodeError):
            current_app.logger.warning(
                "Dekripsi shared document %s gagal",
                doc_id
            )
            abort(404)

        # 7. Catat download setelah dekripsi dan integritas valid
        record_access_log(
            connection,
            request_id,
            user_id,
            "download",
            doc_id
        )
        connection.commit()

    finally:
        connection.close()

    # 7. Kirim file asli kepada penerima
    return send_file(
        BytesIO(plaintext),
        mimetype=row["mime_type"] or "application/octet-stream",
        as_attachment=True,
        download_name=filename
    )


def owner_audit_context(connection, owner_id: int) -> list[dict]:
    """
    Ambil audit log untuk permintaan akses yang ditujukan
    kepada dokumen milik owner.

    Jangan tampilkan password, paket RSA, atau key material.
    """
    rows = connection.execute(
        """
        SELECT
            l.id,
            l.request_id,
            l.document_id,
            l.action,
            datetime(l.created_at, 'localtime') AS created_at,
            u.email AS accessor_email

        FROM access_logs l

        JOIN access_requests r
            ON r.id = l.request_id

        JOIN users u
            ON u.id = l.user_id

        WHERE r.owner_id = ?

        ORDER BY l.created_at DESC, l.id DESC
        LIMIT 100
        """,
        (owner_id,)
    ).fetchall()

    return [dict(row) for row in rows]
