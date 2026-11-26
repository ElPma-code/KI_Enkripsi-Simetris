import pytest
from tests.test_access_requests import login, world
import database

@pytest.fixture(autouse=True)
def cleanup_share_requests(world):
    # Bersihkan request dari pengujian sebelumnya
    conn = database.get_connection()
    try:
        conn.execute("DELETE FROM access_requests")
        conn.commit()
    finally:
        conn.close()

    yield

    # Bersihkan kembali setelah setiap pengujian
    conn = database.get_connection()
    try:
        conn.execute("DELETE FROM access_requests")
        conn.commit()
    finally:
        conn.close()

def test_landlord_tidak_bisa_download_tanpa_izin(world):
    landlord = login("owner@test.com")

    doc_id = world["docs"]["KTP.jpg"]

    response = landlord.get(
        f"/documents/{doc_id}/download"
    )

    assert response.status_code == 404

def test_pemilik_tetap_bisa_download_dokumen(world):
    tenant = login("tenant@test.com")

    doc_id = world["docs"]["KTP.jpg"]

    response = tenant.get(
        f"/documents/{doc_id}/download"
    )

    assert response.status_code == 200
    assert response.data == world["files"]["KTP.jpg"]

def test_unlock_tanpa_login_ditolak(world):
    from app import app

    client = app.test_client()

    response = client.post(
        "/shared/unlock",
        data={
            "package": "paket-dummy",
            "password": "password-dummy",
        }
    )

    assert response.status_code == 401


def test_unlock_tanpa_csrf_ditolak(world):
    tenant = login("tenant@test.com")

    response = tenant.post(
        "/shared/unlock",
        data={
            "package": "paket-dummy",
            "password": "password-dummy",
        }
    )

    assert response.status_code == 400

def test_unlock_dengan_csrf_valid(world):
    tenant = login("tenant@test.com")

    response = tenant.post(
        "/shared/unlock",
        data={
            "csrf_token": tenant.csrf,
            "package": "paket-dummy",
            "password": "password-dummy",
        }
    )

    assert response.status_code == 400
    assert b"Paket atau password tidak valid." in response.data

def test_unlock_password_salah_ditolak(world):
    from tests.test_access_requests import post, make_request, db_one

    # Login sebagai peminta dan pemilik dokumen
    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")

    # Landlord meminta akses
    req = make_request(landlord)
    request_id = req["id"]

    # Tenant menyetujui dokumen yang diminta
    doc_id = world["docs"]["KTP.jpg"]

    response = post(
        tenant,
        f"/requests/{request_id}/approve",
        document_ids=[str(doc_id)]
    )

    assert response.status_code == 302

    # Ambil paket yang dihasilkan saat approval
    approved = db_one(
        "SELECT package, status FROM access_requests WHERE id = ?",
        request_id
    )

    assert approved["status"] == "approved"
    assert approved["package"] is not None

    # Coba Unlock menggunakan password salah
    response = post(
        landlord,
        "/shared/unlock",
        package=approved["package"],
        password="password-yang-salah"
    )

    # Server wajib menolak
    assert response.status_code == 400
    assert b"Paket atau password tidak valid." in response.data

    # Status request harus tetap approved
    after = db_one(
        "SELECT status FROM access_requests WHERE id = ?",
        request_id
    )

    assert after["status"] == "approved"

def test_unlock_rsa_dengan_password_benar(world):
    from tests.test_access_requests import post, make_request, db_one, PASSWORDS

    # Login sebagai peminta dan pemilik dokumen
    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")

    # Landlord meminta akses dokumen
    req = make_request(landlord)
    request_id = req["id"]

    # Tenant menyetujui permintaan
    doc_id = world["docs"]["KTP.jpg"]

    response = post(
        tenant,
        f"/requests/{request_id}/approve",
        document_ids=[str(doc_id)]
    )

    assert response.status_code == 302

    # Ambil paket hasil approval
    approved = db_one(
        "SELECT package, status FROM access_requests WHERE id = ?",
        request_id
    )

    assert approved["status"] == "approved"

    # Unlock menggunakan paket dan password yang benar
    response = post(
        landlord,
        "/shared/unlock",
        package=approved["package"],
        password=PASSWORDS["owner@test.com"]
    )

    # Respons sementara sebelum verifikasi K_share lengkap
    assert response.status_code == 200
    assert b"Paket berhasil diverifikasi." in response.data

    # Status belum boleh berubah sebelum seluruh validasi selesai
    after = db_one(
        "SELECT status FROM access_requests WHERE id = ?",
        request_id
    )

    assert after["status"] == "unlocked"

def test_unlock_paket_milik_user_lain_ditolak(world):
    from tests.test_access_requests import post, make_request, db_one, PASSWORDS

    # Landlord A meminta akses dokumen Tenant
    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")

    req = make_request(landlord)
    request_id = req["id"]

    # Tenant menyetujui permintaan Landlord A
    doc_id = world["docs"]["KTP.jpg"]

    response = post(
        tenant,
        f"/requests/{request_id}/approve",
        document_ids=[str(doc_id)]
    )

    assert response.status_code == 302

    # Ambil paket yang memang ditujukan kepada Landlord A
    approved = db_one(
        "SELECT package FROM access_requests WHERE id = ?",
        request_id
    )

    # User C mencoba menggunakan paket Landlord A
    other = login("other@test.com")

    response = post(
        other,
        "/shared/unlock",
        package=approved["package"],
        password=PASSWORDS["other@test.com"]
    )

    # Paket harus ditolak
    assert response.status_code == 400
    assert b"Paket atau password tidak valid." in response.data

    # Status request tetap approved
    after = db_one(
        "SELECT status FROM access_requests WHERE id = ?",
        request_id
    )

    assert after["status"] == "approved"

def test_unlock_paket_dimodifikasi_ditolak(world):
    import base64
    from tests.test_access_requests import post, make_request, db_one, PASSWORDS

    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")

    # Landlord meminta akses dan Tenant menyetujuinya
    req = make_request(landlord)
    request_id = req["id"]
    doc_id = world["docs"]["KTP.jpg"]

    response = post(
        tenant,
        f"/requests/{request_id}/approve",
        document_ids=[str(doc_id)]
    )
    assert response.status_code == 302

    approved = db_one(
        "SELECT package FROM access_requests WHERE id = ?",
        request_id
    )

    # Ubah satu byte ciphertext RSA, tetapi pertahankan format paket
    parts = approved["package"].split(".")
    ciphertext = bytearray(base64.b64decode(parts[2]))
    ciphertext[0] ^= 0x01

    tampered_package = (
        f"{parts[0]}.{parts[1]}."
        f"{base64.b64encode(ciphertext).decode('ascii')}"
    )

    # Coba Unlock dengan paket rusak dan password benar
    response = post(
        landlord,
        "/shared/unlock",
        package=tampered_package,
        password=PASSWORDS["owner@test.com"]
    )

    assert response.status_code == 400
    assert b"Paket atau password tidak valid." in response.data

    # Paket rusak tidak boleh mengubah status request
    after = db_one(
        "SELECT status FROM access_requests WHERE id = ?",
        request_id
    )
    assert after["status"] == "approved"

def test_unlock_setelah_revoke_ditolak(world):
    from tests.test_access_requests import post, make_request, db_one, PASSWORDS

    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")

    request_id = make_request(landlord)["id"]
    doc_id = world["docs"]["KTP.jpg"]

    assert post(
        tenant,
        f"/requests/{request_id}/approve",
        document_ids=[str(doc_id)]
    ).status_code == 302

    package = db_one(
        "SELECT package FROM access_requests WHERE id = ?",
        request_id
    )["package"]

    # Pemilik mencabut izin sebelum Unlock
    assert post(
        tenant,
        f"/requests/{request_id}/revoke"
    ).status_code == 302

    response = post(
        landlord,
        "/shared/unlock",
        package=package,
        password=PASSWORDS["owner@test.com"]
    )

    assert response.status_code == 400
    assert b"Paket atau password tidak valid." in response.data

    row = db_one(
        "SELECT status FROM access_requests WHERE id = ?",
        request_id
    )
    assert row["status"] == "revoked"


def test_unlock_setelah_expired_ditolak(world):
    from tests.test_access_requests import post, make_request, db_one
    import database

    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")

    request_id = make_request(landlord)["id"]
    doc_id = world["docs"]["KTP.jpg"]

    assert post(
        tenant,
        f"/requests/{request_id}/approve",
        document_ids=[str(doc_id)]
    ).status_code == 302

    package = db_one(
        "SELECT package FROM access_requests WHERE id = ?",
        request_id
    )["package"]

    # Simulasikan masa berlaku yang sudah habis
    conn = database.get_connection()
    try:
        conn.execute(
            """
            UPDATE access_requests
            SET expires_at = datetime('now', '-1 minute')
            WHERE id = ?
            """,
            (request_id,)
        )
        conn.commit()
    finally:
        conn.close()

    response = post(
        landlord,
        "/shared/unlock",
        package=package,
        password="password-owner-1234"
    )

    assert response.status_code == 400

    row = db_one(
        "SELECT status, k_share_wrapped FROM access_requests WHERE id = ?",
        request_id
    )

    assert row["status"] == "expired"
    assert row["k_share_wrapped"] is None

    assert db_one(
        "SELECT COUNT(*) FROM share_grants WHERE request_id = ?",
        request_id
    )[0] == 0

def test_shared_context_sebelum_unlock_kosong(world):
    import database
    import shared_access
    from tests.test_access_requests import post, make_request

    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")

    request_id = make_request(landlord)["id"]
    doc_id = world["docs"]["KTP.jpg"]

    post(
        tenant,
        f"/requests/{request_id}/approve",
        document_ids=[str(doc_id)]
    )

    conn = database.get_connection()
    try:
        documents = shared_access.shared_context(
            conn,
            world["ids"]["owner@test.com"]
        )
    finally:
        conn.close()

    assert documents == []


def test_shared_context_setelah_unlock(world):
    import database
    import shared_access
    from tests.test_access_requests import (
        post, make_request, db_one, PASSWORDS
    )

    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")

    request_id = make_request(landlord)["id"]
    doc_id = world["docs"]["KTP.jpg"]

    post(
        tenant,
        f"/requests/{request_id}/approve",
        document_ids=[str(doc_id)]
    )

    package = db_one(
        "SELECT package FROM access_requests WHERE id = ?",
        request_id
    )["package"]

    response = post(
        landlord,
        "/shared/unlock",
        package=package,
        password=PASSWORDS["owner@test.com"]
    )

    assert response.status_code == 200

    conn = database.get_connection()
    try:
        documents = shared_access.shared_context(
            conn,
            world["ids"]["owner@test.com"]
        )
    finally:
        conn.close()

    assert len(documents) == 1
    assert documents[0]["request_id"] == request_id
    assert documents[0]["doc_id"] == doc_id
    assert documents[0]["original_name"] == "KTP.jpg"
    assert documents[0]["owner_email"] == "tenant@test.com"

@pytest.mark.parametrize(
    "filename",
    ["KTP.jpg", "Bukti.pdf", "Video.mp4"]
)
def test_shared_download_file_identik(world, filename):
    from tests.test_access_requests import (
        post, make_request, db_one, PASSWORDS
    )

    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")

    request_id = make_request(
        landlord,
        categories=(
            "ID Document",
            "Payment Proof",
            "Property Photo / Video"
        )
    )["id"]

    doc_id = world["docs"][filename]

    # Pemilik menyetujui dokumen
    response = post(
        tenant,
        f"/requests/{request_id}/approve",
        document_ids=[str(doc_id)]
    )
    assert response.status_code == 302

    package = db_one(
        "SELECT package FROM access_requests WHERE id = ?",
        request_id
    )["package"]

    # Penerima melakukan Unlock
    response = post(
        landlord,
        "/shared/unlock",
        package=package,
        password=PASSWORDS["owner@test.com"]
    )
    assert response.status_code == 200

    # Download melalui route shared
    response = landlord.get(
        f"/shared/{request_id}/documents/{doc_id}/download"
    )

    assert response.status_code == 200

    # Isi hasil download harus identik dengan file asli
    assert response.data == world["files"][filename]

    # Pastikan nama file asli dipertahankan
    assert filename in response.headers["Content-Disposition"]

def test_shared_download_dokumen_tanpa_grant_ditolak(world):
    from tests.test_access_requests import (
        post, make_request, db_one, PASSWORDS
    )

    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")

    request_id = make_request(landlord)["id"]

    ktp_id = world["docs"]["KTP.jpg"]
    bukti_id = world["docs"]["Bukti.pdf"]

    # Hanya KTP yang disetujui
    post(
        tenant,
        f"/requests/{request_id}/approve",
        document_ids=[str(ktp_id)]
    )

    package = db_one(
        "SELECT package FROM access_requests WHERE id = ?",
        request_id
    )["package"]

    post(
        landlord,
        "/shared/unlock",
        package=package,
        password=PASSWORDS["owner@test.com"]
    )

    # Coba download dokumen lain
    response = landlord.get(
        f"/shared/{request_id}/documents/{bukti_id}/download"
    )

    assert response.status_code == 404

@pytest.mark.parametrize("action", ["revoke", "expire"])
def test_shared_download_setelah_akses_nonaktif(world, action):
    import database
    from tests.test_access_requests import (
        post, make_request, db_one, PASSWORDS
    )

    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")

    request_id = make_request(landlord)["id"]
    doc_id = world["docs"]["KTP.jpg"]

    assert post(
        tenant,
        f"/requests/{request_id}/approve",
        document_ids=[str(doc_id)]
    ).status_code == 302

    package = db_one(
        "SELECT package FROM access_requests WHERE id = ?",
        request_id
    )["package"]

    assert post(
        landlord,
        "/shared/unlock",
        package=package,
        password=PASSWORDS["owner@test.com"]
    ).status_code == 200

    # Pastikan download awal berhasil
    url = f"/shared/{request_id}/documents/{doc_id}/download"
    assert landlord.get(url).status_code == 200

    if action == "revoke":
        assert post(
            tenant,
            f"/requests/{request_id}/revoke"
        ).status_code == 302
    else:
        conn = database.get_connection()
        try:
            conn.execute(
                """
                UPDATE access_requests
                SET expires_at = datetime('now', '-1 minute')
                WHERE id = ?
                """,
                (request_id,)
            )
            conn.commit()
        finally:
            conn.close()

    # Izin sudah tidak aktif, download wajib ditolak
    response = landlord.get(url)
    assert response.status_code == 404

    row = db_one(
        "SELECT status FROM access_requests WHERE id = ?",
        request_id
    )

    assert row["status"] == (
        "revoked" if action == "revoke" else "expired"
    )


def test_shared_download_pengguna_lain_ditolak(world):
    from tests.test_access_requests import (
        post, make_request, db_one, PASSWORDS
    )

    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")
    other = login("other@test.com")

    request_id = make_request(landlord)["id"]
    doc_id = world["docs"]["KTP.jpg"]

    post(
        tenant,
        f"/requests/{request_id}/approve",
        document_ids=[str(doc_id)]
    )

    package = db_one(
        "SELECT package FROM access_requests WHERE id = ?",
        request_id
    )["package"]

    post(
        landlord,
        "/shared/unlock",
        package=package,
        password=PASSWORDS["owner@test.com"]
    )

    # User lain mencoba memakai URL milik penerima
    response = other.get(
        f"/shared/{request_id}/documents/{doc_id}/download"
    )

    assert response.status_code == 404


def test_shared_download_tanpa_login_ditolak(world):
    from app import app

    client = app.test_client()

    response = client.get(
        "/shared/999/documents/999/download"
    )

    assert response.status_code == 401

def test_audit_unlock_berhasil_dan_download(world):
    from tests.test_access_requests import (
        post, make_request, db_one, PASSWORDS
    )

    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")

    rid = make_request(landlord)["id"]
    doc_id = world["docs"]["KTP.jpg"]

    assert post(
        tenant,
        f"/requests/{rid}/approve",
        document_ids=[str(doc_id)]
    ).status_code == 302

    package = db_one(
        "SELECT package FROM access_requests WHERE id = ?",
        rid
    )["package"]

    assert post(
        landlord,
        "/shared/unlock",
        package=package,
        password=PASSWORDS["owner@test.com"]
    ).status_code == 200

    assert landlord.get(
        f"/shared/{rid}/documents/{doc_id}/download"
    ).status_code == 200

    unlock_log = db_one(
        """
        SELECT * FROM access_logs
        WHERE request_id = ? AND action = 'unlock'
        ORDER BY id DESC LIMIT 1
        """,
        rid
    )

    download_log = db_one(
        """
        SELECT * FROM access_logs
        WHERE request_id = ? AND action = 'download'
        ORDER BY id DESC LIMIT 1
        """,
        rid
    )

    assert unlock_log is not None
    assert unlock_log["user_id"] == world["ids"]["owner@test.com"]
    assert download_log is not None
    assert download_log["document_id"] == doc_id


def test_audit_unlock_password_salah(world):
    from tests.test_access_requests import (
        post, make_request, db_one
    )

    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")

    rid = make_request(landlord)["id"]
    doc_id = world["docs"]["KTP.jpg"]

    assert post(
        tenant,
        f"/requests/{rid}/approve",
        document_ids=[str(doc_id)]
    ).status_code == 302

    package = db_one(
        "SELECT package FROM access_requests WHERE id = ?",
        rid
    )["package"]

    response = post(
        landlord,
        "/shared/unlock",
        package=package,
        password="password-salah"
    )

    assert response.status_code == 400

    log = db_one(
        """
        SELECT * FROM access_logs
        WHERE request_id = ? AND action = 'unlock_failed'
        ORDER BY id DESC LIMIT 1
        """,
        rid
    )

    assert log is not None

    status = db_one(
        "SELECT status FROM access_requests WHERE id = ?",
        rid
    )
    assert status["status"] == "approved"

@pytest.mark.parametrize("package", [
    "paket-asal",
    "NSTFY1.abc.YWJj",
    "NSTFY1.1.@@@@",
    "NSTFY1.1.YWJj",
    "NSTFY1.1." + "A" * 2000,
    "NSTFY1.-1.YWJj",
])
def test_unlock_format_paket_invalid(world, package):
    tenant = login("tenant@test.com")

    response = tenant.post(
        "/shared/unlock",
        data={
            "csrf_token": tenant.csrf,
            "package": package,
            "password": "password-dummy"
        }
    )

    assert response.status_code == 400
    assert (
        b"Paket atau password tidak valid."
        in response.data
    )

def test_owner_audit_hanya_melihat_log_miliknya(world):
    import database
    import shared_access

    from tests.test_access_requests import (
        post, make_request, db_one, PASSWORDS
    )

    landlord = login("owner@test.com")
    tenant = login("tenant@test.com")

    request_id = make_request(landlord)["id"]
    doc_id = world["docs"]["KTP.jpg"]

    assert post(
        tenant,
        f"/requests/{request_id}/approve",
        document_ids=[str(doc_id)]
    ).status_code == 302

    package = db_one(
        "SELECT package FROM access_requests WHERE id = ?",
        request_id
    )["package"]

    assert post(
        landlord,
        "/shared/unlock",
        package=package,
        password=PASSWORDS["owner@test.com"]
    ).status_code == 200

    assert landlord.get(
        f"/shared/{request_id}/documents/{doc_id}/download"
    ).status_code == 200

    conn = database.get_connection()
    try:
        # Tenant adalah pemilik dokumen
        tenant_logs = shared_access.owner_audit_context(
            conn,
            world["ids"]["tenant@test.com"]
        )

        # Landlord lain tidak boleh melihat aktivitas tenant
        other_logs = shared_access.owner_audit_context(
            conn,
            world["ids"]["other@test.com"]
        )
    finally:
        conn.close()

    assert len(tenant_logs) == 2
    assert {log["action"] for log in tenant_logs} == {
        "unlock", "download"
    }
    assert all(
        log["accessor_email"] == "owner@test.com"
        for log in tenant_logs
    )

    assert other_logs == []
