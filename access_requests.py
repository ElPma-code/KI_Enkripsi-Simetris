"""
Lifecycle permintaan akses dokumen (bagian Nathania).

Alur:
    A (requester) ── POST /requests ──────────────► pending
    B (owner)     ── POST /requests/<id>/approve ─► approved   (+ paket NSTFY1 untuk A)
    B (owner)     ── POST /requests/<id>/reject ──► rejected
    A             ── unlock (route milik Araafya) ─► unlocked
    B (owner)     ── POST /requests/<id>/revoke ──► revoked
    otomatis      ── expire_old_requests() ───────► expired

Prinsip keamanan:
- Semua POST wajib CSRF token.
- Akses ke request milik orang lain -> 404 (anti-enumeration), bukan 403.
- A hanya memilih KATEGORI. B yang memilih dokumen spesifik saat approve
  (A tidak pernah melihat daftar dokumen B sebelum disetujui; minimisasi data UU PDP).
- K_share mentah TIDAK pernah disimpan (DB maupun session). Yang disimpan:
    * K_share terbungkus master key (AES-GCM, AAD = request_id)
    * paket untuk A (K_share terenkripsi RSA-OAEP dengan public key A)
- Saat revoke/expired, semua material kunci (share_grants, K_share terbungkus,
  paket) dihapus, sehingga akses tidak bisa dipulihkan.

Dipasang di app.py:
    import access_requests
    app.register_blueprint(access_requests.bp)
"""

import json
import secrets

from flask import Blueprint, abort, current_app, flash, redirect, request, session, url_for

import crypto
from database import get_connection

bp = Blueprint("access", __name__, url_prefix="/requests")

# Kategori yang sama dengan dropdown upload di dashboard.html
ALLOWED_CATEGORIES = (
    "Rental Agreement",
    "ID Document",
    "Payment Proof",
    "Property Photo / Video",
    "Other",
)
DEFAULT_EXPIRY_DAYS = 7
MAX_EXPIRY_DAYS = 30
MAX_MESSAGE_LEN = 500

# Status yang masih memberi akses (dipakai juga oleh Araafya)
ACTIVE_STATUSES = ("approved", "unlocked")


# -----------------------------------------------------------------------------
# Helper umum
# -----------------------------------------------------------------------------
def _current_user_id():
    user_id = session.get("user_id")
    if user_id is None:
        abort(401)
    return user_id


def _check_csrf():
    token = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    if not expected or not secrets.compare_digest(token, expected):
        abort(400)


def _back(message=None, category="request_success"):
    if message:
        flash(message, category)
    return redirect(url_for("dashboard") + "#requests")


def _decrypt_name(row) -> str:
    if row["original_name_enc"] is None:
        return row["original_name"]
    try:
        return crypto.decrypt_text(row["original_name_enc"])
    except Exception:
        current_app.logger.exception("Gagal mendekripsi nama file doc %s", row["id"])
        return "(nama file tidak dapat didekripsi)"


def _purge_key_material(connection, request_ids):
    """Hapus semua kunci yang memberi akses: data key ter-rewrap, K_share terbungkus, paket."""
    for request_id in request_ids:
        connection.execute("DELETE FROM share_grants WHERE request_id = ?", (request_id,))
        connection.execute(
            "UPDATE access_requests SET k_share_wrapped = NULL, k_share_nonce = NULL, "
            "package = NULL WHERE id = ?",
            (request_id,),
        )


def _get_owned_request(connection, request_id, owner_id):
    """Ambil request yang owner-nya user ini. Kalau bukan miliknya -> 404."""
    row = connection.execute(
        "SELECT * FROM access_requests WHERE id = ? AND owner_id = ?",
        (request_id, owner_id),
    ).fetchone()
    if row is None:
        abort(404)
    return row


# -----------------------------------------------------------------------------
# Keypair (dipanggil dari route /login)
# -----------------------------------------------------------------------------
def ensure_user_keypair(user_id: int, password: str) -> bool:
    """Buat keypair RSA-3072 untuk user kalau belum ada.

    Harus dipanggil SETELAH password terverifikasi, karena private key dienkripsi
    dengan password itu. Password hanya dipakai di sini dan tidak disimpan.
    Return True kalau keypair baru dibuat.
    """
    connection = get_connection()
    try:
        exists = connection.execute(
            "SELECT 1 FROM user_keys WHERE user_id = ?", (user_id,)
        ).fetchone()
        if exists:
            return False

        public_pem, private_enc = crypto.generate_user_keypair(password)
        connection.execute(
            "INSERT OR IGNORE INTO user_keys (user_id, public_pem, private_enc) VALUES (?, ?, ?)",
            (user_id, public_pem, private_enc),
        )
        connection.commit()
        return True
    finally:
        connection.close()


# -----------------------------------------------------------------------------
# Expiry (dipanggil di inbox, dan oleh Araafya sebelum setiap akses dokumen bersama)
# -----------------------------------------------------------------------------
def expire_old_requests(connection) -> int:
    """Ubah request approved/unlocked yang sudah lewat expires_at menjadi expired,
    lalu hapus material kuncinya. Caller yang melakukan commit. Return jumlah yang kedaluwarsa."""
    rows = connection.execute(
        """
        SELECT id FROM access_requests
        WHERE status IN ('approved', 'unlocked')
          AND expires_at IS NOT NULL
          AND expires_at <= datetime('now')
        """
    ).fetchall()
    ids = [row["id"] for row in rows]
    if ids:
        connection.executemany(
            "UPDATE access_requests SET status = 'expired' WHERE id = ?",
            [(i,) for i in ids],
        )
        _purge_key_material(connection, ids)
    return len(ids)


# -----------------------------------------------------------------------------
# Data untuk halaman inbox (dipakai ElPma di template)
# -----------------------------------------------------------------------------
def inbox_context(connection, user_id: int) -> dict:
    """Variabel template untuk halaman request.

    incoming_requests  : request yang masuk ke user ini (user = owner/B)
    outgoing_requests  : request yang dikirim user ini (user = requester/A)
    shareable_documents: dokumen milik user ini, untuk checkbox di modal approve

    Paket (package) HANYA dikirim ke owner, supaya distribusinya tetap lewat
    jalur lain (WA/email) sesuai desain.
    """
    expire_old_requests(connection)
    connection.commit()

    def _rows(query, params):
        result = []
        for row in connection.execute(query, params).fetchall():
            item = dict(row)
            item["requested_categories"] = json.loads(item["requested_categories"])
            for col in ("k_share_wrapped", "k_share_nonce"):
                item.pop(col, None)
            result.append(item)
        return result

    common = """
        r.id, r.status, r.message, r.requested_categories, r.package,
        datetime(r.created_at, 'localtime') AS created_at,
        datetime(r.decided_at, 'localtime') AS decided_at,
        datetime(r.expires_at, 'localtime') AS expires_at,
        (SELECT COUNT(*) FROM share_grants g WHERE g.request_id = r.id) AS shared_count
    """
    incoming = _rows(
        f"""
        SELECT {common}, u.email AS requester_email
        FROM access_requests r JOIN users u ON u.id = r.requester_id
        WHERE r.owner_id = ?
        ORDER BY r.created_at DESC
        """,
        (user_id,),
    )
    outgoing = _rows(
        f"""
        SELECT {common}, u.email AS owner_email
        FROM access_requests r JOIN users u ON u.id = r.owner_id
        WHERE r.requester_id = ?
        ORDER BY r.created_at DESC
        """,
        (user_id,),
    )
    for item in outgoing:
        item.pop("package", None)  # A menerima paket lewat WA/email, bukan dari UI

    docs = connection.execute(
        """
        SELECT id, original_name, original_name_enc, category, size_bytes, cipher
        FROM documents WHERE user_id = ? ORDER BY created_at DESC
        """,
        (user_id,),
    ).fetchall()
    shareable = [
        {"id": d["id"], "name": _decrypt_name(d), "category": d["category"],
         "size_bytes": d["size_bytes"], "cipher": d["cipher"]}
        for d in docs
    ]

    return {
        "incoming_requests": incoming,
        "outgoing_requests": outgoing,
        "shareable_documents": shareable,
        "request_categories": ALLOWED_CATEGORIES,
        "pending_incoming_count": sum(1 for r in incoming if r["status"] == "pending"),
    }


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@bp.route("", methods=["POST"])
def create_request():
    """A meminta akses ke data B.
    Form: owner_email, categories (boleh lebih dari satu), message (opsional)."""
    user_id = _current_user_id()
    _check_csrf()

    owner_email = request.form.get("owner_email", "").strip().lower()
    categories = request.form.getlist("categories")
    message = request.form.get("message", "").strip()[:MAX_MESSAGE_LEN]

    categories = [c for c in dict.fromkeys(categories) if c in ALLOWED_CATEGORIES]
    if not categories:
        return _back("Pilih minimal satu kategori dokumen.", "request_error")

    connection = get_connection()
    try:
        me = connection.execute(
            "SELECT id, landlord_id FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        owner = connection.execute(
            "SELECT id, landlord_id FROM users WHERE email = ?", (owner_email,)
        ).fetchone()

        # Hanya boleh ke pasangan tenant-landlord yang terhubung. Pesan error dibuat
        # sama untuk "tidak ada" dan "tidak terhubung" supaya email tidak bisa ditebak.
        linked = owner is not None and owner["id"] != user_id and (
            owner["landlord_id"] == user_id or me["landlord_id"] == owner["id"]
        )
        if not linked:
            return _back("Pengguna tidak ditemukan atau tidak terhubung dengan Anda.", "request_error")

        duplicate = connection.execute(
            "SELECT 1 FROM access_requests WHERE requester_id = ? AND owner_id = ? AND status = 'pending'",
            (user_id, owner["id"]),
        ).fetchone()
        if duplicate:
            return _back("Masih ada permintaan yang menunggu persetujuan ke pengguna ini.", "request_error")

        connection.execute(
            """
            INSERT INTO access_requests (requester_id, owner_id, requested_categories, message)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, owner["id"], json.dumps(categories), message or None),
        )
        connection.commit()
    finally:
        connection.close()

    return _back("Permintaan akses terkirim. Menunggu persetujuan pemilik data.")


@bp.route("/<int:request_id>/approve", methods=["POST"])
def approve_request(request_id: int):
    """B menyetujui request dan memilih dokumen yang dibagikan.
    Form: document_ids (boleh lebih dari satu), expires_days (1-30, default 7)."""
    user_id = _current_user_id()
    _check_csrf()

    try:
        document_ids = sorted({int(x) for x in request.form.getlist("document_ids")})
        expires_days = int(request.form.get("expires_days", DEFAULT_EXPIRY_DAYS))
    except ValueError:
        abort(400)
    expires_days = max(1, min(MAX_EXPIRY_DAYS, expires_days))

    connection = get_connection()
    try:
        req = _get_owned_request(connection, request_id, user_id)
        if req["status"] != "pending":
            return _back("Permintaan ini sudah diproses.", "request_error")
        if not document_ids:
            return _back("Pilih minimal satu dokumen untuk dibagikan.", "request_error")

        # Dokumen harus benar-benar milik owner (jangan percaya ID dari form)
        placeholders = ",".join("?" * len(document_ids))
        docs = connection.execute(
            f"SELECT id, cipher, wrapped_key, key_wrap_iv FROM documents "
            f"WHERE user_id = ? AND id IN ({placeholders})",
            (user_id, *document_ids),
        ).fetchall()
        if len(docs) != len(document_ids):
            abort(404)

        requester_key = connection.execute(
            "SELECT public_pem FROM user_keys WHERE user_id = ?", (req["requester_id"],)
        ).fetchone()
        if requester_key is None:
            return _back(
                "Peminta belum memiliki kunci enkripsi. Minta peminta untuk login ulang, lalu coba lagi.",
                "request_error",
            )

        # Semua langkah di bawah dalam satu transaksi: gagal di tengah -> rollback total
        k_share = crypto.generate_share_key()
        try:
            for doc in docs:
                nonce, rewrapped = crypto.rewrap_data_key(
                    doc["cipher"], doc["wrapped_key"], doc["key_wrap_iv"],
                    k_share, crypto.share_doc_aad(request_id, doc["id"]),
                )
                connection.execute(
                    "INSERT INTO share_grants (request_id, document_id, rewrapped_key, rewrap_nonce) "
                    "VALUES (?, ?, ?, ?)",
                    (request_id, doc["id"], rewrapped, nonce),
                )

            wrap_nonce, k_share_wrapped = crypto.wrap_share_key(k_share, request_id)
            package = crypto.encode_package(
                str(request_id),
                crypto.encrypt_share_key_for(requester_key["public_pem"], k_share),
            )

            updated = connection.execute(
                """
                UPDATE access_requests
                SET status = 'approved',
                    k_share_wrapped = ?, k_share_nonce = ?, package = ?,
                    decided_at = datetime('now'),
                    expires_at = datetime('now', ?)
                WHERE id = ? AND status = 'pending'
                """,
                (k_share_wrapped, wrap_nonce, package, f"+{expires_days} days", request_id),
            ).rowcount
            if updated != 1:
                raise RuntimeError("Status request berubah saat diproses.")
            connection.commit()
        except Exception:
            connection.rollback()
            current_app.logger.exception("Approve request %s gagal", request_id)
            return _back("Gagal memproses persetujuan. Silakan coba lagi.", "request_error")
        finally:
            del k_share
    finally:
        connection.close()

    return _back(
        f"Permintaan disetujui ({len(docs)} dokumen, berlaku {expires_days} hari). "
        "Salin paket akses lalu kirim ke peminta lewat WhatsApp atau email."
    )


@bp.route("/<int:request_id>/reject", methods=["POST"])
def reject_request(request_id: int):
    user_id = _current_user_id()
    _check_csrf()

    connection = get_connection()
    try:
        req = _get_owned_request(connection, request_id, user_id)
        if req["status"] != "pending":
            return _back("Permintaan ini sudah diproses.", "request_error")
        connection.execute(
            "UPDATE access_requests SET status = 'rejected', decided_at = datetime('now') WHERE id = ?",
            (request_id,),
        )
        connection.commit()
    finally:
        connection.close()

    return _back("Permintaan ditolak.")


@bp.route("/<int:request_id>/revoke", methods=["POST"])
def revoke_request(request_id: int):
    """B mencabut akses kapan saja. Semua material kunci dihapus permanen."""
    user_id = _current_user_id()
    _check_csrf()

    connection = get_connection()
    try:
        req = _get_owned_request(connection, request_id, user_id)
        if req["status"] not in ACTIVE_STATUSES:
            return _back("Akses ini sudah tidak aktif.", "request_error")
        connection.execute(
            "UPDATE access_requests SET status = 'revoked' WHERE id = ?", (request_id,)
        )
        _purge_key_material(connection, [request_id])
        connection.commit()
    finally:
        connection.close()

    return _back("Akses dicabut. Peminta tidak bisa lagi membuka dokumen tersebut.")