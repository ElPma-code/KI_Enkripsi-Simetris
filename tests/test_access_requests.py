"""
Test lifecycle permintaan akses.

Jalankan dari folder utama project:
    python -m pytest tests/test_access_requests.py -v

Test memakai database & folder file SEMENTARA, jadi data asli tidak tersentuh.
Keypair RSA-3072 dibuat sekali per sesi test (agak lama, ~beberapa detik).
"""

import io
import json
import os
import re
import secrets
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Key sementara KHUSUS test (tidak memakai .env asli)
os.environ["FLASK_SECRET_KEY"] = secrets.token_hex(32)
os.environ["MASTER_KEY_AES"] = secrets.token_hex(32)

import database  # noqa: E402
import app as app_module  # noqa: E402
import access_requests  # noqa: E402
import crypto  # noqa: E402

PASSWORDS = {
    "tenant@test.com": "password-tenant-123",
    "owner@test.com": "password-owner-1234",
    "other@test.com": "password-other-1234",   # landlord lain, tidak terhubung
    "nokey@test.com": "password-nokey-1234",   # tenant yang belum pernah login
}


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------
@pytest.fixture(scope="session")
def world(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("nestiefy")
    database.DB_PATH = tmp / "test.db"
    app_module.ENCRYPTED_FILES_DIR = tmp / "encrypted_files"
    app_module.ENCRYPTED_FILES_DIR.mkdir()
    app_module.app.config["TESTING"] = True
    database.init_db()

    conn = database.get_connection()
    for email, role in [("owner@test.com", "landlord"), ("other@test.com", "landlord"),
                        ("tenant@test.com", "tenant"), ("nokey@test.com", "tenant")]:
        conn.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
            (email, database.password_hasher.hash(PASSWORDS[email]), role),
        )
    owner_id = conn.execute("SELECT id FROM users WHERE email='owner@test.com'").fetchone()[0]
    conn.execute("UPDATE users SET landlord_id=? WHERE role='tenant'", (owner_id,))
    conn.commit()
    ids = {r["email"]: r["id"] for r in conn.execute("SELECT id, email FROM users")}
    conn.close()

    # Login sekali per user supaya keypair dibuat (kecuali nokey)
    for email in ("tenant@test.com", "owner@test.com", "other@test.com"):
        login(email)

    # Dokumen milik tenant & owner
    tenant, owner = login("tenant@test.com"), login("owner@test.com")
    files = {"KTP.jpg": os.urandom(3000), "Bukti.pdf": os.urandom(5000), "Video.mp4": os.urandom(9000)}
    upload(tenant, "KTP.jpg", files["KTP.jpg"], "AES", "ID Document")
    upload(tenant, "Bukti.pdf", files["Bukti.pdf"], "DES", "Payment Proof")
    upload(tenant, "Video.mp4", files["Video.mp4"], "RC4", "Property Photo / Video")
    upload(owner, "Sertifikat.pdf", b"sertifikat", "AES", "Other")
    conn = database.get_connection()
    docs = {}
    for r in conn.execute("SELECT id, original_name_enc FROM documents"):
        docs[crypto.decrypt_text(r["original_name_enc"])] = r["id"]
    conn.close()
    return {"ids": ids, "docs": docs, "files": files}


@pytest.fixture(autouse=True)
def clean_requests(world):
    yield
    conn = database.get_connection()
    conn.execute("DELETE FROM access_requests")
    conn.commit()
    conn.close()


def login(email):
    client = app_module.app.test_client()
    r = client.post("/login", data={"email": email, "password": PASSWORDS[email]})
    assert r.status_code == 302, f"login gagal untuk {email}"
    client.csrf = secrets.token_hex(32)
    with client.session_transaction() as s:
        s["_csrf_token"] = client.csrf
    return client


def upload(client, name, data, cipher, category):
    r = client.post("/upload", data={
        "csrf_token": client.csrf, "cipher": cipher, "category": category, "file_name": "",
        "file": (io.BytesIO(data), name)}, content_type="multipart/form-data")
    assert r.status_code == 302 and "#dashboard" in r.location


def post(client, url, **data):
    data.setdefault("csrf_token", client.csrf)
    return client.post(url, data=data)


def db_one(sql, *params):
    conn = database.get_connection()
    try:
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


def flashes(client):
    with client.session_transaction() as s:
        return [msg for _, msg in s.get("_flashes", [])]


def make_request(requester, owner_email="tenant@test.com", categories=("ID Document",), message="Untuk kontrak"):
    r = post(requester, "/requests", owner_email=owner_email, categories=list(categories), message=message)
    assert r.status_code == 302
    row = db_one("SELECT * FROM access_requests ORDER BY id DESC LIMIT 1")
    return row


# -----------------------------------------------------------------------------
# Keypair
# -----------------------------------------------------------------------------
def test_keypair_dibuat_saat_login(world):
    row = db_one("SELECT * FROM user_keys WHERE user_id = ?", world["ids"]["owner@test.com"])
    assert row is not None
    assert "BEGIN PUBLIC KEY" in row["public_pem"]
    assert "BEGIN ENCRYPTED PRIVATE KEY" in row["private_enc"]
    assert PASSWORDS["owner@test.com"] not in row["private_enc"]


def test_keypair_tidak_dibuat_ulang_saat_login_kedua(world):
    before = db_one("SELECT public_pem FROM user_keys WHERE user_id = ?", world["ids"]["tenant@test.com"])[0]
    login("tenant@test.com")
    after = db_one("SELECT public_pem FROM user_keys WHERE user_id = ?", world["ids"]["tenant@test.com"])[0]
    assert before == after


def test_user_yang_belum_login_belum_punya_keypair(world):
    assert db_one("SELECT 1 FROM user_keys WHERE user_id = ?", world["ids"]["nokey@test.com"]) is None


# -----------------------------------------------------------------------------
# Create request
# -----------------------------------------------------------------------------
def test_request_dibuat_dengan_status_pending(world):
    owner = login("owner@test.com")
    row = make_request(owner, categories=("ID Document", "Payment Proof"))
    assert row["status"] == "pending"
    assert row["requester_id"] == world["ids"]["owner@test.com"]
    assert row["owner_id"] == world["ids"]["tenant@test.com"]
    assert json.loads(row["requested_categories"]) == ["ID Document", "Payment Proof"]
    assert row["k_share_wrapped"] is None and row["package"] is None


def test_request_ke_user_tidak_terhubung_ditolak(world):
    other = login("other@test.com")
    post(other, "/requests", owner_email="tenant@test.com", categories=["ID Document"])
    msg_unlinked = flashes(other)[-1]
    post(other, "/requests", owner_email="tidakada@test.com", categories=["ID Document"])
    msg_missing = flashes(other)[-1]
    assert db_one("SELECT COUNT(*) FROM access_requests")[0] == 0
    assert msg_unlinked == msg_missing, "pesan harus sama supaya email tidak bisa ditebak"


def test_request_ke_diri_sendiri_ditolak(world):
    owner = login("owner@test.com")
    post(owner, "/requests", owner_email="owner@test.com", categories=["ID Document"])
    assert db_one("SELECT COUNT(*) FROM access_requests")[0] == 0


def test_request_tanpa_kategori_valid_ditolak(world):
    owner = login("owner@test.com")
    post(owner, "/requests", owner_email="tenant@test.com", categories=["Kategori Palsu"])
    assert db_one("SELECT COUNT(*) FROM access_requests")[0] == 0


def test_request_pending_dobel_ditolak(world):
    owner = login("owner@test.com")
    make_request(owner)
    post(owner, "/requests", owner_email="tenant@test.com", categories=["ID Document"])
    assert db_one("SELECT COUNT(*) FROM access_requests")[0] == 1


def test_csrf_wajib(world):
    owner = login("owner@test.com")
    r = owner.post("/requests", data={"owner_email": "tenant@test.com", "categories": ["ID Document"]})
    assert r.status_code == 400


def test_tanpa_login_ditolak(world):
    r = app_module.app.test_client().post("/requests", data={})
    assert r.status_code == 401


# -----------------------------------------------------------------------------
# Approve (inti kriptografi)
# -----------------------------------------------------------------------------
def test_approve_alur_lengkap(world):
    owner, tenant = login("owner@test.com"), login("tenant@test.com")
    req = make_request(owner)
    rid = req["id"]
    ktp, bukti = world["docs"]["KTP.jpg"], world["docs"]["Bukti.pdf"]

    r = post(tenant, f"/requests/{rid}/approve", document_ids=[str(ktp), str(bukti)], expires_days="7")
    assert r.status_code == 302

    row = db_one("SELECT * FROM access_requests WHERE id = ?", rid)
    assert row["status"] == "approved"
    assert row["expires_at"] is not None

    # 1. Paket berformat NSTFY1.<id>.<base64> dan id-nya cocok
    pkg_id, ct = crypto.decode_package(row["package"])
    assert int(pkg_id) == rid

    # 2. Hanya private key requester (+ password-nya) yang bisa membuka K_share
    owner_keys = db_one("SELECT private_enc FROM user_keys WHERE user_id = ?", world["ids"]["owner@test.com"])
    k_share = crypto.decrypt_share_key(owner_keys["private_enc"], PASSWORDS["owner@test.com"], ct)
    assert len(k_share) == 32

    # 3. K_share yang tersimpan (terbungkus master key) sama dengan isi paket
    assert crypto.unwrap_share_key(row["k_share_nonce"], row["k_share_wrapped"], rid) == k_share

    # 4. Lewat jalur K_share, data key bisa didapat dan file kembali UTUH
    for name in ("KTP.jpg", "Bukti.pdf"):
        doc = db_one("SELECT * FROM documents WHERE id = ?", world["docs"][name])
        grant = db_one("SELECT * FROM share_grants WHERE request_id = ? AND document_id = ?", rid, doc["id"])
        data_key = crypto.unwrap_rewrapped_data_key(
            k_share, grant["rewrap_nonce"], grant["rewrapped_key"], crypto.share_doc_aad(rid, doc["id"]))
        ciphertext = (app_module.ENCRYPTED_FILES_DIR / doc["stored_name"]).read_bytes()
        blob = {"ciphertext": ciphertext, "iv_or_nonce": doc["iv_or_nonce"], "auth_tag": doc["auth_tag"],
                "wrapped_key": doc["wrapped_key"], "key_wrap_iv": doc["key_wrap_iv"],
                "sha256_plaintext": doc["sha256_plaintext"]}
        assert crypto.decrypt_file(blob, doc["cipher"], data_key=data_key) == world["files"][name]

    # 5. Dokumen yang TIDAK dipilih tidak ikut dibagikan
    assert db_one("SELECT COUNT(*) FROM share_grants WHERE request_id = ?", rid)[0] == 2


def test_paket_tidak_bisa_dibuka_password_salah_atau_orang_lain(world):
    owner, tenant = login("owner@test.com"), login("tenant@test.com")
    rid = make_request(owner)["id"]
    post(tenant, f"/requests/{rid}/approve", document_ids=[str(world["docs"]["KTP.jpg"])])
    _, ct = crypto.decode_package(db_one("SELECT package FROM access_requests WHERE id = ?", rid)[0])

    owner_priv = db_one("SELECT private_enc FROM user_keys WHERE user_id = ?", world["ids"]["owner@test.com"])[0]
    with pytest.raises(Exception):
        crypto.decrypt_share_key(owner_priv, "password-salah-123", ct)

    other_priv = db_one("SELECT private_enc FROM user_keys WHERE user_id = ?", world["ids"]["other@test.com"])[0]
    with pytest.raises(Exception):
        crypto.decrypt_share_key(other_priv, PASSWORDS["other@test.com"], ct)


def test_data_key_terikat_ke_pasangan_request_dan_dokumen(world):
    owner, tenant = login("owner@test.com"), login("tenant@test.com")
    rid = make_request(owner)["id"]
    ktp = world["docs"]["KTP.jpg"]
    post(tenant, f"/requests/{rid}/approve", document_ids=[str(ktp)])
    row = db_one("SELECT * FROM access_requests WHERE id = ?", rid)
    k_share = crypto.unwrap_share_key(row["k_share_nonce"], row["k_share_wrapped"], rid)
    grant = db_one("SELECT * FROM share_grants WHERE request_id = ?", rid)
    with pytest.raises(ValueError):  # AAD dokumen lain
        crypto.unwrap_rewrapped_data_key(k_share, grant["rewrap_nonce"], grant["rewrapped_key"],
                                         crypto.share_doc_aad(rid, ktp + 1))
    with pytest.raises(ValueError):  # K_share dipindah ke request lain
        crypto.unwrap_share_key(row["k_share_nonce"], row["k_share_wrapped"], rid + 1)


def test_hanya_owner_yang_bisa_approve(world):
    owner, other = login("owner@test.com"), login("other@test.com")
    rid = make_request(owner)["id"]
    doc = str(world["docs"]["KTP.jpg"])
    assert post(owner, f"/requests/{rid}/approve", document_ids=[doc]).status_code == 404  # peminta
    assert post(other, f"/requests/{rid}/approve", document_ids=[doc]).status_code == 404  # orang lain
    assert db_one("SELECT status FROM access_requests WHERE id = ?", rid)[0] == "pending"


def test_approve_dokumen_milik_orang_lain_ditolak(world):
    owner, tenant = login("owner@test.com"), login("tenant@test.com")
    rid = make_request(owner)["id"]
    r = post(tenant, f"/requests/{rid}/approve",
             document_ids=[str(world["docs"]["KTP.jpg"]), str(world["docs"]["Sertifikat.pdf"])])
    assert r.status_code == 404
    assert db_one("SELECT status FROM access_requests WHERE id = ?", rid)[0] == "pending"
    assert db_one("SELECT COUNT(*) FROM share_grants")[0] == 0


def test_approve_tanpa_dokumen_ditolak(world):
    owner, tenant = login("owner@test.com"), login("tenant@test.com")
    rid = make_request(owner)["id"]
    post(tenant, f"/requests/{rid}/approve")
    assert db_one("SELECT status FROM access_requests WHERE id = ?", rid)[0] == "pending"


def test_approve_dua_kali_ditolak(world):
    owner, tenant = login("owner@test.com"), login("tenant@test.com")
    rid = make_request(owner)["id"]
    post(tenant, f"/requests/{rid}/approve", document_ids=[str(world["docs"]["KTP.jpg"])])
    pkg1 = db_one("SELECT package FROM access_requests WHERE id = ?", rid)[0]
    post(tenant, f"/requests/{rid}/approve", document_ids=[str(world["docs"]["Bukti.pdf"])])
    assert db_one("SELECT package FROM access_requests WHERE id = ?", rid)[0] == pkg1
    assert db_one("SELECT COUNT(*) FROM share_grants WHERE request_id = ?", rid)[0] == 1


def test_approve_ditolak_jika_peminta_belum_punya_keypair(world):
    tenant = login("tenant@test.com")
    conn = database.get_connection()
    conn.execute("INSERT INTO access_requests (requester_id, owner_id, requested_categories) VALUES (?, ?, ?)",
                 (world["ids"]["nokey@test.com"], world["ids"]["tenant@test.com"], '["ID Document"]'))
    conn.commit()
    rid = conn.execute("SELECT MAX(id) FROM access_requests").fetchone()[0]
    conn.close()
    post(tenant, f"/requests/{rid}/approve", document_ids=[str(world["docs"]["KTP.jpg"])])
    row = db_one("SELECT * FROM access_requests WHERE id = ?", rid)
    assert row["status"] == "pending" and row["package"] is None
    assert db_one("SELECT COUNT(*) FROM share_grants")[0] == 0


def test_masa_berlaku_dibatasi_maksimal_30_hari(world):
    owner, tenant = login("owner@test.com"), login("tenant@test.com")
    rid = make_request(owner)["id"]
    post(tenant, f"/requests/{rid}/approve", document_ids=[str(world["docs"]["KTP.jpg"])], expires_days="999")
    days = db_one("SELECT julianday(expires_at) - julianday(decided_at) FROM access_requests WHERE id = ?", rid)[0]
    assert round(days) == 30


# -----------------------------------------------------------------------------
# Reject, revoke, expiry
# -----------------------------------------------------------------------------
def test_reject(world):
    owner, tenant = login("owner@test.com"), login("tenant@test.com")
    rid = make_request(owner)["id"]
    post(tenant, f"/requests/{rid}/reject")
    row = db_one("SELECT * FROM access_requests WHERE id = ?", rid)
    assert row["status"] == "rejected" and row["decided_at"] is not None
    assert post(owner, f"/requests/{rid}/reject").status_code == 404  # peminta tidak bisa reject


def test_revoke_menghapus_semua_material_kunci(world):
    owner, tenant = login("owner@test.com"), login("tenant@test.com")
    rid = make_request(owner)["id"]
    post(tenant, f"/requests/{rid}/approve", document_ids=[str(world["docs"]["KTP.jpg"])])
    assert post(owner, f"/requests/{rid}/revoke").status_code == 404  # hanya owner yang bisa revoke
    post(tenant, f"/requests/{rid}/revoke")
    row = db_one("SELECT * FROM access_requests WHERE id = ?", rid)
    assert row["status"] == "revoked"
    assert row["k_share_wrapped"] is None and row["k_share_nonce"] is None and row["package"] is None
    assert db_one("SELECT COUNT(*) FROM share_grants WHERE request_id = ?", rid)[0] == 0


def test_revoke_request_pending_ditolak(world):
    owner, tenant = login("owner@test.com"), login("tenant@test.com")
    rid = make_request(owner)["id"]
    post(tenant, f"/requests/{rid}/revoke")
    assert db_one("SELECT status FROM access_requests WHERE id = ?", rid)[0] == "pending"


def test_expired_menghapus_material_kunci(world):
    owner, tenant = login("owner@test.com"), login("tenant@test.com")
    rid = make_request(owner)["id"]
    post(tenant, f"/requests/{rid}/approve", document_ids=[str(world["docs"]["KTP.jpg"])])
    conn = database.get_connection()
    conn.execute("UPDATE access_requests SET expires_at = datetime('now', '-1 minute') WHERE id = ?", (rid,))
    assert access_requests.expire_old_requests(conn) == 1
    conn.commit()
    conn.close()
    row = db_one("SELECT * FROM access_requests WHERE id = ?", rid)
    assert row["status"] == "expired" and row["k_share_wrapped"] is None and row["package"] is None
    assert db_one("SELECT COUNT(*) FROM share_grants WHERE request_id = ?", rid)[0] == 0


def test_hapus_dokumen_ikut_menghapus_grant(world):
    owner, tenant = login("owner@test.com"), login("tenant@test.com")
    upload(tenant, "Sementara.pdf", b"hapus saya", "AES", "Other")
    doc_id = db_one("SELECT MAX(id) FROM documents")[0]
    rid = make_request(owner)["id"]
    post(tenant, f"/requests/{rid}/approve", document_ids=[str(doc_id)])
    assert db_one("SELECT COUNT(*) FROM share_grants WHERE document_id = ?", doc_id)[0] == 1
    post(tenant, f"/documents/{doc_id}/delete")
    assert db_one("SELECT COUNT(*) FROM share_grants WHERE document_id = ?", doc_id)[0] == 0


# -----------------------------------------------------------------------------
# Data inbox untuk template
# -----------------------------------------------------------------------------
def test_inbox_paket_hanya_terlihat_oleh_owner(world):
    owner, tenant = login("owner@test.com"), login("tenant@test.com")
    rid = make_request(owner)["id"]
    post(tenant, f"/requests/{rid}/approve", document_ids=[str(world["docs"]["KTP.jpg"])])
    conn = database.get_connection()
    try:
        ctx_owner_data = access_requests.inbox_context(conn, world["ids"]["tenant@test.com"])
        ctx_requester = access_requests.inbox_context(conn, world["ids"]["owner@test.com"])
    finally:
        conn.close()
    incoming = ctx_owner_data["incoming_requests"][0]
    outgoing = ctx_requester["outgoing_requests"][0]
    assert incoming["package"].startswith("NSTFY1.")
    assert "package" not in outgoing
    assert incoming["requested_categories"] == ["ID Document"]
    assert {d["name"] for d in ctx_owner_data["shareable_documents"]} >= {"KTP.jpg", "Bukti.pdf"}
    assert all("k_share_wrapped" not in r for r in ctx_owner_data["incoming_requests"])


def test_dashboard_tetap_bisa_dibuka(world):
    owner = login("owner@test.com")
    make_request(owner)
    assert owner.get("/dashboard").status_code == 200
    assert login("tenant@test.com").get("/dashboard").status_code == 200