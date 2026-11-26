"""
Test modul pdf_sign.py dan tabel tanda tangan.

Jalankan dari folder utama project:
    python -m pytest tests/test_pdf_sign.py -v

Tanda tangan RSA di test ini memakai pycryptodome langsung (PKCS#1 v1.5 + SHA-256),
yang terbukti interoperabel dengan crypto_sign.sign_digest milik Rafa
(lihat test interoperabilitas di tests/test_signing.py).
Tidak butuh .env maupun MASTER_KEY_AES.
"""

import io
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from pypdf import PdfReader, PdfWriter
from pypdf.generic import ArrayObject, DictionaryObject, NameObject, TextStringObject

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pdf_sign  # noqa: E402


# -----------------------------------------------------------------------------
# Helper
# -----------------------------------------------------------------------------
class _PrecomputedSha256:
    """Objek hash palsu supaya pkcs1_15 menandatangani digest yang sudah jadi
    (sama seperti kontrak sign_digest: masuk digest 32 byte)."""
    oid = SHA256.new().oid
    digest_size = 32

    def __init__(self, digest):
        self._digest = digest

    def digest(self):
        return self._digest


@pytest.fixture(scope="module")
def key():
    return RSA.generate(3072)


def sign(key, digest):
    return pkcs1_15.new(key).sign(_PrecomputedSha256(digest))


def verify(public_key, digest, signature):
    try:
        pkcs1_15.new(public_key).verify(_PrecomputedSha256(digest), signature)
        return True
    except (ValueError, TypeError):
        return False


def make_pdf(pages=2, with_form_field=False, incremental_extra=False):
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(595, 842)
    if with_form_field:
        field = DictionaryObject({
            NameObject("/FT"): NameObject("/Tx"),
            NameObject("/T"): TextStringObject("nama_penyewa"),
        })
        ref = writer._add_object(field)
        writer._root_object[NameObject("/AcroForm")] = DictionaryObject({
            NameObject("/Fields"): ArrayObject([ref]),
        })
    buf = io.BytesIO()
    writer.write(buf)
    data = buf.getvalue()
    if incremental_extra:
        # PDF yang sudah pernah di-update (bagian akhirnya memakai xref stream)
        w = PdfWriter(io.BytesIO(data), incremental=True)
        w.add_metadata({"/Title": "Kontrak Sewa"})
        out = io.BytesIO()
        w.write(out)
        data = out.getvalue()
    return data


def sign_pdf(key, pdf, **kwargs):
    prepared = pdf_sign.prepare_pdf(pdf, **kwargs)
    return prepared, pdf_sign.embed_signature(prepared, sign(key, prepared.digest))


def is_valid(public_key, signed_pdf):
    info = pdf_sign.extract_signature(signed_pdf)
    return info is not None and info.is_intact and verify(public_key, info.digest, info.signature)


# -----------------------------------------------------------------------------
# Alur normal
# -----------------------------------------------------------------------------
def test_tanda_tangan_valid(key):
    pdf = make_pdf()
    prepared, signed = sign_pdf(key, pdf, signer_name="tenant@test.com",
                                reason="Persetujuan kontrak", location="Surabaya")
    info = pdf_sign.extract_signature(signed)

    assert info.is_intact
    assert verify(key.publickey(), info.digest, info.signature)
    assert len(info.signature) == 384                       # RSA-3072
    assert info.digest == prepared.digest and len(info.digest) == 32
    assert info.signer_name == "tenant@test.com"
    assert info.reason == "Persetujuan kontrak" and info.location == "Surabaya"
    assert info.signing_time.startswith("D:")
    assert info.sub_filter == pdf_sign.SUBFILTER_RAW


def test_byte_pdf_asli_tidak_diubah(key):
    pdf = make_pdf()
    _, signed = sign_pdf(key, pdf)
    assert signed.startswith(pdf)                           # incremental update
    assert len(PdfReader(io.BytesIO(signed)).pages) == 2    # tetap bisa dibuka


def test_byterange_menutupi_seluruh_file_kecuali_contents(key):
    _, signed = sign_pdf(key, make_pdf())
    a, b, c, d = pdf_sign.extract_signature(signed).byte_range
    assert a == 0 and c + d == len(signed)
    gap = signed[b:c]
    assert gap.startswith(b"<") and gap.endswith(b">")


def test_digest_sama_dengan_hitungan_manual(key):
    import hashlib
    _, signed = sign_pdf(key, make_pdf())
    a, b, c, d = pdf_sign.extract_signature(signed).byte_range
    expected = hashlib.sha256(signed[a:a + b] + signed[c:c + d]).digest()
    assert pdf_sign.extract_signature(signed).digest == expected


def test_panjang_file_tidak_berubah_saat_embed(key):
    prepared, signed = sign_pdf(key, make_pdf())
    assert len(signed) == len(prepared.data)


def test_pdf_dengan_form_dan_update_sebelumnya(key):
    pdf = make_pdf(with_form_field=True, incremental_extra=True)
    _, signed = sign_pdf(key, pdf)
    assert is_valid(key.publickey(), signed)
    fields = PdfReader(io.BytesIO(signed)).trailer["/Root"]["/AcroForm"]["/Fields"]
    names = {str(f.get_object()["/T"]) for f in fields}
    assert {"nama_penyewa", "NestiefySignature"} <= names    # field lama tidak hilang


@pytest.mark.skipif(shutil.which("qpdf") is None, reason="qpdf tidak terpasang")
def test_pdf_modern_dengan_object_stream(key, tmp_path):
    """PDF modern (Word/Chrome) menyimpan objek di dalam object stream + xref stream."""
    src, dst = tmp_path / "a.pdf", tmp_path / "b.pdf"
    src.write_bytes(make_pdf())
    subprocess.run(["qpdf", "--object-streams=generate", str(src), str(dst)], check=True)
    _, signed = sign_pdf(key, dst.read_bytes())
    assert is_valid(key.publickey(), signed)
    check = subprocess.run(["qpdf", "--check", "-"], input=signed, capture_output=True)
    assert b"WARNING" not in check.stdout + check.stderr


def test_halaman_dengan_annots_sebagai_objek_terpisah(key):
    writer = PdfWriter()
    writer.add_blank_page(595, 842)
    link = writer._add_object(DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"), NameObject("/Subtype"): NameObject("/Link"),
        NameObject("/Rect"): ArrayObject([pdf_sign.NumberObject(0)] * 4)}))
    annots_ref = writer._add_object(ArrayObject([link]))
    writer.pages[0][NameObject("/Annots")] = annots_ref
    buf = io.BytesIO()
    writer.write(buf)
    _, signed = sign_pdf(key, buf.getvalue())
    assert is_valid(key.publickey(), signed)
    annots = PdfReader(io.BytesIO(signed)).pages[0]["/Annots"]
    assert len(annots) == 2                                  # anotasi lama tetap ada


def test_signature_berakhir_byte_nol_tidak_terpotong():
    prepared = pdf_sign.prepare_pdf(make_pdf())
    fake = bytes(range(1, 256)) + b"\x07" * 128 + b"\x00"   # 384 byte, berakhir 0x00
    info = pdf_sign.extract_signature(pdf_sign.embed_signature(prepared, fake))
    assert info.signature == fake


def test_mode_cms():
    prepared = pdf_sign.prepare_pdf(make_pdf(), sub_filter=pdf_sign.SUBFILTER_CMS)
    fake_cms = b"\x30\x82\x01\x00" + b"\xab" * 256           # DER SEQUENCE 256 byte
    info = pdf_sign.extract_signature(pdf_sign.embed_signature(prepared, fake_cms, container="cms"))
    assert info.signature == fake_cms
    assert info.sub_filter == pdf_sign.SUBFILTER_CMS


# -----------------------------------------------------------------------------
# Serangan & manipulasi (harus terdeteksi)
# -----------------------------------------------------------------------------
def test_isi_diubah_setelah_tanda_tangan(key):
    _, signed = sign_pdf(key, make_pdf())
    tampered = bytearray(signed)
    tampered[200] ^= 0x01                                    # 1 bit di bagian yang ditandatangani
    assert not is_valid(key.publickey(), bytes(tampered))


def test_isi_ditambah_di_akhir_file(key):
    _, signed = sign_pdf(key, make_pdf())
    appended = signed + b"\n% isi tambahan setelah ditandatangani\n"
    info = pdf_sign.extract_signature(appended)
    # Tanda tangannya sendiri masih cocok untuk bagian lama...
    assert verify(key.publickey(), info.digest, info.signature)
    # ...tapi struktur WAJIB dianggap rusak
    assert not info.covers_whole_file and not info.is_intact
    assert not is_valid(key.publickey(), appended)


def test_update_incremental_setelah_tanda_tangan(key):
    _, signed = sign_pdf(key, make_pdf())
    w = PdfWriter(io.BytesIO(signed), incremental=True)
    w.add_metadata({"/Title": "diubah setelah ditandatangani"})
    out = io.BytesIO()
    w.write(out)
    assert not is_valid(key.publickey(), out.getvalue())


def test_byterange_dimanipulasi(key):
    _, signed = sign_pdf(key, make_pdf())
    a, b, c, d = pdf_sign.extract_signature(signed).byte_range
    old = ("/ByteRange [ %d %d %d %d" % (a, b, c, d)).encode()
    new = ("/ByteRange [ %d %d %d %d" % (a, b - 10, c, d)).encode()
    assert len(old) == len(new)
    tampered = signed.replace(old, new)
    info = pdf_sign.extract_signature(tampered)
    assert not info.gap_matches_contents and not is_valid(key.publickey(), tampered)


def test_signature_diubah(key):
    prepared, _ = sign_pdf(key, make_pdf())
    bad = bytearray(sign(key, prepared.digest))
    bad[10] ^= 0xFF
    assert not is_valid(key.publickey(), pdf_sign.embed_signature(prepared, bytes(bad)))


def test_kunci_salah(key):
    _, signed = sign_pdf(key, make_pdf())
    other = RSA.generate(3072)
    assert not is_valid(other.publickey(), signed)


# -----------------------------------------------------------------------------
# Input tidak valid
# -----------------------------------------------------------------------------
def test_bukan_pdf_ditolak():
    with pytest.raises(ValueError):
        pdf_sign.prepare_pdf(b"bukan pdf sama sekali")


def test_pdf_rusak_ditolak():
    with pytest.raises(ValueError):
        pdf_sign.prepare_pdf(b"%PDF-1.7\nini bukan isi pdf yang valid")


def test_pdf_yang_sudah_ditandatangani_ditolak(key):
    _, signed = sign_pdf(key, make_pdf())
    with pytest.raises(ValueError):
        pdf_sign.prepare_pdf(signed)


def test_signature_terlalu_besar_ditolak():
    prepared = pdf_sign.prepare_pdf(make_pdf(), contents_size=256)
    with pytest.raises(ValueError):
        pdf_sign.embed_signature(prepared, b"\x01" * 384)


def test_embed_dua_kali_ditolak(key):
    prepared, signed = sign_pdf(key, make_pdf())
    again = pdf_sign.PreparedPdf(signed, prepared.byte_range, prepared.digest, prepared.contents_size)
    with pytest.raises(ValueError):
        pdf_sign.embed_signature(again, sign(key, prepared.digest))


def test_pdf_tanpa_tanda_tangan():
    assert pdf_sign.extract_signature(make_pdf()) is None


def test_placeholder_belum_diisi_tidak_intact():
    prepared = pdf_sign.prepare_pdf(make_pdf())
    info = pdf_sign.extract_signature(prepared.data)
    assert info.signature is None and not info.is_intact


# -----------------------------------------------------------------------------
# Validasi dengan tool eksternal (dilewati kalau tidak terpasang)
# -----------------------------------------------------------------------------
@pytest.mark.skipif(shutil.which("pdfsig") is None, reason="pdfsig (poppler-utils) tidak terpasang")
def test_struktur_diakui_pdfsig_dengan_cms(tmp_path):
    """Isi /Contents dengan CMS asli lalu validasi pakai Poppler: membuktikan struktur
    /Sig + /ByteRange buatan modul ini sesuai standar PDF."""
    crypto_lib = pytest.importorskip("cryptography")  # noqa: F841
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import NameOID

    k = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Nestiefy Test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(k.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(k, hashes.SHA256()))

    prepared = pdf_sign.prepare_pdf(make_pdf(), sub_filter=pdf_sign.SUBFILTER_CMS)
    a, b, c, d = prepared.byte_range
    cms = (pkcs7.PKCS7SignatureBuilder()
           .set_data(prepared.data[a:a + b] + prepared.data[c:c + d])
           .add_signer(cert, k, hashes.SHA256())
           .sign(serialization.Encoding.DER,
                 [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary]))
    path = tmp_path / "signed.pdf"
    path.write_bytes(pdf_sign.embed_signature(prepared, cms, container="cms"))

    out = subprocess.run(["pdfsig", str(path)], capture_output=True, text=True).stdout
    assert "Signature is Valid" in out
    assert "Total document signed" in out


# -----------------------------------------------------------------------------
# Database
# -----------------------------------------------------------------------------
def test_tabel_tanda_tangan_dan_migrasi(tmp_path, monkeypatch):
    import database
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    database.init_db()
    database.init_db()                                      # aman dijalankan dua kali

    conn = database.get_connection()
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"signing_keys", "document_signatures"} <= tables

    conn.execute("INSERT INTO users (email, password_hash, role) VALUES ('t@x', 'h', 'tenant')")
    doc = ("INSERT INTO documents (user_id, original_name, stored_name, category, size_bytes, cipher, "
           "iv_or_nonce, auth_tag, wrapped_key, key_wrap_iv, sha256_plaintext) "
           "VALUES (1, '', ?, 'Rental Agreement', 1, 'AES', x'00', x'00', x'00', x'00', '')")
    conn.execute(doc, ("asli.enc",))
    conn.execute(doc, ("signed.enc",))
    conn.execute("INSERT INTO signing_keys (user_id, public_pem, private_enc) VALUES (1, 'pub', 'priv')")
    conn.execute(
        "INSERT INTO document_signatures (document_id, source_document_id, signer_id, signer_public_pem, "
        "sub_filter, byte_range, digest_sha256, signature) VALUES (2, 1, 1, 'pub', ?, '[0,1,2,3]', 'ab', x'01')",
        (pdf_sign.SUBFILTER_RAW,),
    )
    conn.commit()

    # Satu dokumen hasil tanda tangan hanya boleh punya satu baris
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO document_signatures (document_id, signer_id, signer_public_pem, sub_filter, "
            "byte_range, digest_sha256, signature) VALUES (2, 1, 'pub', 's', '[]', 'ab', x'01')")

    # Hapus PDF asli -> catatan tanda tangan tetap ada, source jadi NULL
    conn.execute("DELETE FROM documents WHERE id = 1")
    assert conn.execute("SELECT source_document_id FROM document_signatures").fetchone()[0] is None
    # Hapus PDF bertanda tangan -> catatannya ikut terhapus
    conn.execute("DELETE FROM documents WHERE id = 2")
    assert conn.execute("SELECT COUNT(*) FROM document_signatures").fetchone()[0] == 0
    conn.close()