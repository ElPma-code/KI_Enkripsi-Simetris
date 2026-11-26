"""
Tanda tangan digital di dalam file PDF.

Modul ini HANYA mengurus struktur PDF. Operasi kriptografinya (RSA, padding,
SHA-256 sign/verify) ada di crypto_sign.py milik Rafa.

ALUR TANDA TANGAN
    prepared = prepare_pdf(pdf_bytes, signer_name="tenant@test.com")
    signature = crypto_sign.sign_digest(private_enc, password, prepared.digest)
    signed_pdf = embed_signature(prepared, signature)

ALUR VERIFIKASI
    info = extract_signature(signed_pdf)
    ok = (info is not None
          and info.is_intact                                  # struktur /ByteRange aman
          and crypto_sign.verify_digest(public_pem, info.digest, info.signature))

CARA KERJA (ringkas)
1. prepare_pdf menambahkan kamus /Sig lewat INCREMENTAL UPDATE: byte PDF asli
   tidak diubah sama sekali, objek baru + xref baru (dengan /Prev ke xref lama)
   ditulis di akhir file. Bagian ini ditulis sendiri (pypdf hanya dipakai untuk
   MEMBACA), karena mode incremental pypdf memberi nomor objek yang bentrok pada
   PDF yang sudah pernah di-update dengan xref stream (umum di PDF dari Word/Chrome).
   Kamus /Sig berisi:
     /ByteRange [0 a b c]   bagian file yang ditandatangani (semua byte KECUALI /Contents)
     /Contents <000...0>    tempat kosong berukuran TETAP untuk tanda tangan
2. Digest SHA-256 dihitung dari gabungan dua rentang /ByteRange:
     byte [0, a)  +  byte [b, b + c)
   Celah [a, b) adalah string hex /Contents itu sendiri (termasuk < dan >),
   karena tanda tangan tidak mungkin menandatangani dirinya sendiri.
3. embed_signature mengisi celah tadi. Panjangnya tidak berubah, sehingga
   offset /ByteRange tetap valid dan digest tetap sama.

FORMAT ISI /Contents
- Mode "raw"  : tanda tangan RSA PKCS#1 v1.5 (384 byte untuk RSA-3072) dibungkus
                DER OCTET STRING, sama seperti konvensi adbe.x509.rsa_sha1.
                Pembungkus DER diperlukan karena /Contents diisi nol sampai penuh:
                tanpa panjang yang tercatat, tanda tangan yang kebetulan berakhir
                dengan byte 0x00 akan terpotong saat dibaca.
- Mode "cms"  : blob CMS/PKCS#7 (DER SEQUENCE) dimasukkan apa adanya.
                Ini format yang dikenali pembaca PDF standar (adbe.pkcs7.detached).

BATASAN YANG DISADARI
- Hanya mendukung SATU tanda tangan per PDF (prepare_pdf menolak PDF yang sudah
  ditandatangani). Tanda tangan bersama (tenant + landlord) butuh aturan DocMDP.
- PDF yang terenkripsi password (fitur PDF, bukan enkripsi Nestiefy) ditolak.
- Waktu /M hanya klaim dari jam server, bukan dari Timestamp Authority (TSA).
"""

from __future__ import annotations

import hashlib
import io
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from pypdf import PdfReader
from pypdf.errors import PdfReadError
from pypdf.generic import (
    ArrayObject,
    ByteStringObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    NumberObject,
    TextStringObject,
)

# Tempat kosong /Contents dalam BYTE (string hex-nya 2x lebih panjang).
# 8 KB cukup untuk raw (388 B) maupun CMS + sertifikat self-signed (~1-3 KB).
DEFAULT_CONTENTS_SIZE = 8192

# /Filter = nama handler tanda tangan. /SubFilter = format isi /Contents.
FILTER = "/Adobe.PPKLite"
# Raw PKCS#1 + SHA-256 tanpa sertifikat: format internal Nestiefy (diverifikasi
# dengan public key dari database). Sengaja TIDAK memakai nama adbe.x509.rsa_sha1
# karena format itu mewajibkan entri /Cert dan secara historis SHA-1.
SUBFILTER_RAW = "/Nestiefy.rsa_sha256"
# CMS/PKCS#7 detached: format standar yang dikenali Adobe Reader dkk.
SUBFILTER_CMS = "/adbe.pkcs7.detached"

# Placeholder /ByteRange: angka 10 digit supaya panjang teksnya cukup untuk
# offset sebenarnya (file sampai ~9 GB), lalu diganti tanpa mengubah panjang file.
_BYTERANGE_PLACEHOLDER = 9_999_999_999
_BYTERANGE_PATTERN = re.compile(rb"/ByteRange\s*\[\s*0\s+9999999999\s+9999999999\s+9999999999\s*\]")


@dataclass(frozen=True)
class PreparedPdf:
    """PDF yang sudah punya tempat kosong untuk tanda tangan."""
    data: bytes                     # isi PDF lengkap (dengan /Contents masih nol)
    byte_range: tuple[int, int, int, int]
    digest: bytes                   # SHA-256 (32 byte) dari bagian yang ditandatangani
    contents_size: int              # kapasitas /Contents dalam byte


@dataclass(frozen=True)
class SignatureInfo:
    """Hasil pembacaan satu tanda tangan dari PDF."""
    field_name: str
    sub_filter: str
    byte_range: tuple[int, int, int, int]
    signature: bytes | None         # raw: 384 byte tanda tangan; cms: blob DER; None kalau masih kosong
    digest: bytes                   # SHA-256 yang DIHITUNG ULANG dari /ByteRange file ini
    signer_name: str | None
    signing_time: str | None        # nilai /M mentah, mis. "D:20261126055200Z"
    reason: str | None
    location: str | None
    covers_whole_file: bool         # /ByteRange menutupi seluruh file (tidak ada byte tambahan di akhir)
    gap_matches_contents: bool      # celah /ByteRange tepat = string hex /Contents

    @property
    def is_intact(self) -> bool:
        """Struktur aman untuk diverifikasi. Kalau False, tanda tangan HARUS dianggap tidak valid
        walaupun verify_digest bernilai True (contoh: ada isi tambahan setelah ditandatangani)."""
        return self.signature is not None and self.covers_whole_file and self.gap_matches_contents


# -----------------------------------------------------------------------------
# Helper DER (cukup untuk membaca panjang TLV; tidak perlu library ASN.1)
# -----------------------------------------------------------------------------
def _der_encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_octet_string(value: bytes) -> bytes:
    return b"\x04" + _der_encode_length(len(value)) + value


def _der_read_tlv(data: bytes) -> tuple[int, int, int]:
    """Kembalikan (tag, offset_isi, panjang_isi) untuk TLV DER di awal data."""
    if len(data) < 2:
        raise ValueError("Data DER terlalu pendek.")
    tag, first = data[0], data[1]
    if first < 0x80:
        return tag, 2, first
    count = first & 0x7F
    if count == 0 or count > 4 or len(data) < 2 + count:
        raise ValueError("Panjang DER tidak valid.")
    length = int.from_bytes(data[2:2 + count], "big")
    if 2 + count + length > len(data):
        raise ValueError("Panjang DER melebihi isi /Contents.")
    return tag, 2 + count, length


# -----------------------------------------------------------------------------
# Helper umum
# -----------------------------------------------------------------------------
def byte_range_digest(data: bytes, byte_range) -> bytes:
    """SHA-256 dari gabungan semua rentang (offset, panjang) di /ByteRange."""
    values = [int(x) for x in byte_range]
    if len(values) % 2 or not values:
        raise ValueError("/ByteRange harus berisi pasangan offset dan panjang.")
    h = hashlib.sha256()
    for offset, length in zip(values[0::2], values[1::2]):
        if offset < 0 or length < 0 or offset + length > len(data):
            raise ValueError("/ByteRange keluar dari batas file.")
        h.update(data[offset:offset + length])
    return h.digest()


def _pdf_date(now: datetime | None = None) -> str:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return now.strftime("D:%Y%m%d%H%M%SZ")


def _open_reader(pdf_bytes: bytes) -> PdfReader:
    if not pdf_bytes.startswith(b"%PDF-"):
        raise ValueError("File bukan PDF.")
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        _ = len(reader.pages)
    except PdfReadError as exc:
        raise ValueError("PDF rusak atau tidak bisa dibaca.") from exc
    if reader.is_encrypted:
        raise ValueError("PDF yang diproteksi password tidak didukung.")
    return reader


def _signature_fields(reader: PdfReader):
    """Yield (nama_field, kamus /Sig) untuk setiap field tanda tangan yang sudah terisi /V."""
    acroform = reader.trailer["/Root"].get("/AcroForm")
    if acroform is None:
        return
    acroform = acroform.get_object()
    stack = list(acroform.get("/Fields", []))
    while stack:
        field = stack.pop(0).get_object()
        if "/Kids" in field and "/FT" not in field:
            stack.extend(field["/Kids"])
            continue
        if field.get("/FT") == "/Sig" and "/V" in field:
            yield str(field.get("/T", "")), field["/V"].get_object()


def _raw_bytes(obj) -> bytes:
    """Ambil byte asli string PDF. pypdf kadang mengubah string hex menjadi
    TextStringObject (teks) kalau isinya kebetulan bisa didekode."""
    if obj is None:
        return b""
    original = getattr(obj, "original_bytes", None)
    if original is not None:
        return bytes(original)
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj)
    return str(obj).encode("latin-1")


def _serialize(obj) -> bytes:
    buf = io.BytesIO()
    obj.write_to_stream(buf)
    return buf.getvalue()


def _copy_dict(d) -> DictionaryObject:
    """Salin dictionary dengan nilai MENTAH (referensi tidak di-resolve)."""
    return DictionaryObject({NameObject(k): d.raw_get(k) for k in d.keys()})


def _last_startxref(pdf_bytes: bytes) -> int:
    found = re.findall(rb"startxref\s+(\d+)", pdf_bytes[-2048:])
    if not found:
        raise ValueError("PDF tidak punya startxref.")
    return int(found[-1])


def _max_object_number(reader: PdfReader) -> int:
    highest = int(reader.trailer.get("/Size", 0)) - 1
    for table in reader.xref.values():
        if table:
            highest = max(highest, max(table))
    if reader.xref_objStm:
        highest = max(highest, max(reader.xref_objStm))
    return highest


def _write_incremental(pdf_bytes: bytes, reader: PdfReader,
                       objects: dict[int, tuple[int, object]]) -> tuple[bytes, dict[int, int]]:
    """Tulis objek baru/yang diubah + xref + trailer di akhir PDF.
    objects: {nomor_objek: (generation, objek_pdf)}.
    Return (pdf_baru, {nomor_objek: offset})."""
    prev = _last_startxref(pdf_bytes)
    uses_xref_stream = not pdf_bytes[prev:prev + 4].startswith(b"xref")

    out = bytearray(pdf_bytes)
    if not out.endswith(b"\n"):
        out += b"\n"

    offsets = {}
    for num in sorted(objects):
        gen, obj = objects[num]
        offsets[num] = len(out)
        out += b"%d %d obj\n" % (num, gen) + _serialize(obj) + b"\nendobj\n"

    trailer_extra = DictionaryObject()
    trailer_extra[NameObject("/Root")] = reader.trailer.raw_get("/Root")
    for key in ("/Info", "/ID"):
        if key in reader.trailer:
            trailer_extra[NameObject(key)] = reader.trailer.raw_get(key)
    trailer_extra[NameObject("/Prev")] = NumberObject(prev)

    def _sections(numbers):
        numbers = sorted(numbers)
        groups, start = [], numbers[0]
        for a, b in zip(numbers, numbers[1:] + [None]):
            if b != a + 1:
                groups.append((start, a - start + 1))
                start = b
        return groups

    if uses_xref_stream:
        xref_num = max(max(objects) + 1, _max_object_number(reader) + 1)
        xref_offset = len(out)
        offsets_all = dict(offsets)
        offsets_all[xref_num] = xref_offset
        gens = {n: objects[n][0] for n in objects}
        gens[xref_num] = 0
        rows = b"".join(
            b"\x01" + offsets_all[n].to_bytes(4, "big") + gens[n].to_bytes(2, "big")
            for start, count in _sections(list(offsets_all))
            for n in range(start, start + count)
        )
        index = ArrayObject()
        for start, count in _sections(list(offsets_all)):
            index += [NumberObject(start), NumberObject(count)]
        xref_dict = trailer_extra
        xref_dict[NameObject("/Type")] = NameObject("/XRef")
        xref_dict[NameObject("/Size")] = NumberObject(xref_num + 1)
        xref_dict[NameObject("/W")] = ArrayObject([NumberObject(1), NumberObject(4), NumberObject(2)])
        xref_dict[NameObject("/Index")] = index
        xref_dict[NameObject("/Length")] = NumberObject(len(rows))
        out += (b"%d 0 obj\n" % xref_num + _serialize(xref_dict)
                + b"\nstream\n" + rows + b"\nendstream\nendobj\n")
    else:
        xref_offset = len(out)
        out += b"xref\n"
        for start, count in _sections(list(offsets)):
            out += b"%d %d\n" % (start, count)
            for n in range(start, start + count):
                out += b"%010d %05d n\r\n" % (offsets[n], objects[n][0])
        trailer_extra[NameObject("/Size")] = NumberObject(
            max(int(reader.trailer.get("/Size", 0)), max(objects) + 1))
        out += b"trailer\n" + _serialize(trailer_extra) + b"\n"

    out += b"startxref\n%d\n%%%%EOF\n" % xref_offset
    return bytes(out), offsets


# -----------------------------------------------------------------------------
# API publik
# -----------------------------------------------------------------------------
def prepare_pdf(
    pdf_bytes: bytes,
    *,
    signer_name: str | None = None,
    reason: str | None = None,
    location: str | None = None,
    sub_filter: str = SUBFILTER_RAW,
    contents_size: int = DEFAULT_CONTENTS_SIZE,
    signing_time: datetime | None = None,
) -> PreparedPdf:
    """Tambahkan kamus /Sig, tempat kosong /Contents, dan /ByteRange ke PDF.

    Tidak ada byte PDF asli yang diubah (incremental update).
    Raise ValueError kalau input bukan PDF, rusak, terproteksi password,
    atau sudah punya tanda tangan.
    """
    if contents_size < 64:
        raise ValueError("contents_size terlalu kecil.")
    reader = _open_reader(pdf_bytes)
    if any(True for _ in _signature_fields(reader)):
        raise ValueError("PDF sudah ditandatangani. Hanya satu tanda tangan per dokumen yang didukung.")

    next_num = _max_object_number(reader) + 1
    sig_num, widget_num = next_num, next_num + 1
    objects: dict[int, tuple[int, object]] = {}

    sig_dict = DictionaryObject({
        NameObject("/Type"): NameObject("/Sig"),
        NameObject("/Filter"): NameObject(FILTER),
        NameObject("/SubFilter"): NameObject(sub_filter),
        NameObject("/ByteRange"): ArrayObject([NumberObject(0)] + [NumberObject(_BYTERANGE_PLACEHOLDER)] * 3),
        NameObject("/Contents"): ByteStringObject(b"\x00" * contents_size),
        NameObject("/M"): TextStringObject(_pdf_date(signing_time)),
    })
    if signer_name:
        sig_dict[NameObject("/Name")] = TextStringObject(signer_name)
    if reason:
        sig_dict[NameObject("/Reason")] = TextStringObject(reason)
    if location:
        sig_dict[NameObject("/Location")] = TextStringObject(location)
    objects[sig_num] = (0, sig_dict)

    # Field tanda tangan tak terlihat (Rect 0) di halaman pertama
    page = reader.pages[0]
    page_ref = page.indirect_reference
    widget_ref = IndirectObject(widget_num, 0, reader)
    objects[widget_num] = (0, DictionaryObject({
        NameObject("/FT"): NameObject("/Sig"),
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Widget"),
        NameObject("/T"): TextStringObject("NestiefySignature"),
        NameObject("/V"): IndirectObject(sig_num, 0, reader),
        NameObject("/F"): NumberObject(132),            # Print + Locked
        NameObject("/Rect"): ArrayObject([NumberObject(0)] * 4),
        NameObject("/P"): page_ref,
    }))

    # /Annots halaman: kalau berupa objek terpisah, ubah objek itu; kalau langsung, ubah halamannya
    annots_raw = page.raw_get("/Annots") if "/Annots" in page else None
    if isinstance(annots_raw, IndirectObject):
        annots = ArrayObject(list(annots_raw.get_object()) + [widget_ref])
        objects[annots_raw.idnum] = (annots_raw.generation, annots)
    else:
        new_page = _copy_dict(page)
        new_page[NameObject("/Annots")] = ArrayObject(list(annots_raw or []) + [widget_ref])
        objects[page_ref.idnum] = (page_ref.generation, new_page)

    # /AcroForm: sama, ubah objeknya kalau terpisah, kalau tidak ubah katalog /Root
    root_ref = reader.trailer.raw_get("/Root")
    root = root_ref.get_object()
    acro_raw = root.raw_get("/AcroForm") if "/AcroForm" in root else None
    acroform = _copy_dict(acro_raw.get_object()) if acro_raw is not None else DictionaryObject()
    fields_raw = acroform.raw_get("/Fields") if "/Fields" in acroform else None
    if isinstance(fields_raw, IndirectObject):
        objects[fields_raw.idnum] = (fields_raw.generation,
                                     ArrayObject(list(fields_raw.get_object()) + [widget_ref]))
    else:
        acroform[NameObject("/Fields")] = ArrayObject(list(fields_raw or []) + [widget_ref])
    acroform[NameObject("/SigFlags")] = NumberObject(3)       # SignaturesExist + AppendOnly
    if isinstance(acro_raw, IndirectObject):
        objects[acro_raw.idnum] = (acro_raw.generation, acroform)
    else:
        new_root = _copy_dict(root)
        new_root[NameObject("/AcroForm")] = acroform
        objects[root_ref.idnum] = (root_ref.generation, new_root)

    data, offsets = _write_incremental(pdf_bytes, reader, objects)
    data = bytearray(data)

    # Posisi placeholder diketahui pasti: cari di dalam objek /Sig saja
    sig_start = offsets[sig_num]
    sig_end = data.index(b"endobj", sig_start)
    contents_match = re.compile(rb"<(?:00){%d}>" % contents_size).search(bytes(data), sig_start, sig_end)
    br_match = _BYTERANGE_PATTERN.search(bytes(data), sig_start, sig_end)
    if contents_match is None or br_match is None:
        raise RuntimeError("Placeholder tanda tangan tidak ditemukan.")

    gap_start, gap_end = contents_match.start(), contents_match.end()
    byte_range = (0, gap_start, gap_end, len(data) - gap_end)

    # Ganti placeholder /ByteRange dengan angka sebenarnya, panjang teks tetap sama
    new_text = ("/ByteRange [ %d %d %d %d" % byte_range).encode("ascii")
    filler = (br_match.end() - br_match.start()) - len(new_text) - 2
    if filler < 0:
        raise RuntimeError("Placeholder /ByteRange terlalu pendek.")
    data[br_match.start():br_match.end()] = new_text + b" " * filler + b" ]"

    data = bytes(data)
    return PreparedPdf(
        data=data,
        byte_range=byte_range,
        digest=byte_range_digest(data, byte_range),
        contents_size=contents_size,
    )


def embed_signature(prepared: PreparedPdf, signature: bytes, *, container: str = "raw") -> bytes:
    """Isi tempat kosong /Contents dengan tanda tangan.

    container="raw": signature = tanda tangan PKCS#1 v1.5 mentah (dari sign_digest).
    container="cms": signature = blob CMS/PKCS#7 DER (dipakai dengan SUBFILTER_CMS).
    Panjang file tidak berubah, jadi /ByteRange dan digest tetap valid.
    """
    if container == "raw":
        blob = _der_octet_string(signature)
    elif container == "cms":
        if not signature or signature[0] != 0x30:
            raise ValueError("Blob CMS harus diawali DER SEQUENCE (0x30).")
        blob = signature
    else:
        raise ValueError("container harus 'raw' atau 'cms'.")
    if len(blob) > prepared.contents_size:
        raise ValueError(
            f"Tanda tangan ({len(blob)} byte) lebih besar dari tempat /Contents ({prepared.contents_size} byte)."
        )

    _, gap_start, gap_end, _ = prepared.byte_range
    data = bytearray(prepared.data)
    expected = b"<" + b"0" * (2 * prepared.contents_size) + b">"
    if bytes(data[gap_start:gap_end]) != expected:
        raise ValueError("Tempat /Contents sudah terisi atau tidak ditemukan.")

    hex_value = blob.hex().encode("ascii").ljust(2 * prepared.contents_size, b"0")
    data[gap_start + 1:gap_end - 1] = hex_value
    return bytes(data)


def extract_signatures(pdf_bytes: bytes) -> list[SignatureInfo]:
    """Baca semua tanda tangan di PDF beserta hasil pengecekan strukturnya.
    Kembalikan list kosong kalau PDF tidak punya tanda tangan."""
    reader = _open_reader(pdf_bytes)
    results = []
    for field_name, sig in _signature_fields(reader):
        byte_range = tuple(int(x) for x in sig.get("/ByteRange", []))
        if len(byte_range) != 4:
            raise ValueError("/ByteRange tidak valid.")

        try:
            digest = byte_range_digest(pdf_bytes, byte_range)
        except ValueError:
            digest = b""

        start0, len0, start1, len1 = byte_range
        covers = (
            start0 == 0 and len0 > 0 and start1 > len0 and len1 >= 0
            and start1 + len1 == len(pdf_bytes)
        )

        contents = _raw_bytes(sig.get("/Contents"))
        gap = pdf_bytes[len0:start1] if 0 < len0 < start1 <= len(pdf_bytes) else b""
        gap_ok = (
            len(gap) >= 2 and gap[:1] == b"<" and gap[-1:] == b">"
            and re.fullmatch(rb"[0-9a-fA-F]*", gap[1:-1]) is not None
            and len(gap) - 2 == 2 * len(contents)
            and bytes.fromhex(gap[1:-1].decode("ascii")) == contents
        )

        signature = None
        sub_filter = str(sig.get("/SubFilter", ""))
        if contents.strip(b"\x00"):
            tag, offset, length = _der_read_tlv(contents)
            if tag == 0x04:                         # OCTET STRING -> raw PKCS#1
                signature = contents[offset:offset + length]
            elif tag == 0x30:                       # SEQUENCE -> CMS
                signature = contents[:offset + length]
            else:
                raise ValueError("Format isi /Contents tidak dikenali.")

        def _text(key):
            value = sig.get(key)
            return str(value) if value is not None else None

        results.append(SignatureInfo(
            field_name=field_name,
            sub_filter=sub_filter,
            byte_range=byte_range,
            signature=signature,
            digest=digest,
            signer_name=_text("/Name"),
            signing_time=_text("/M"),
            reason=_text("/Reason"),
            location=_text("/Location"),
            covers_whole_file=covers,
            gap_matches_contents=gap_ok,
        ))
    return results


def extract_signature(pdf_bytes: bytes) -> SignatureInfo | None:
    """Tanda tangan terakhir di PDF, atau None kalau belum ditandatangani."""
    signatures = extract_signatures(pdf_bytes)
    return signatures[-1] if signatures else None