"""Focused unit tests for verification of independently re-uploaded signed PDFs.

These tests mock PDF parsing and RSA verification to exercise signer lookup and
status handling; run the full repository suite for end-to-end integration.
"""
import sqlite3
from types import SimpleNamespace

import pytest

import signing_routes


@pytest.fixture
def signer_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE)")
    conn.execute("CREATE TABLE signing_keys (user_id INTEGER, public_pem BLOB)")
    conn.executemany("INSERT INTO users VALUES (?, ?)", [
        (1, "tenant@test.com"), (2, "owner@test.com")
    ])
    conn.executemany("INSERT INTO signing_keys VALUES (?, ?)", [
        (1, b"tenant-public"), (2, b"owner-public")
    ])
    yield conn
    conn.close()


@pytest.mark.parametrize(
    "name,digest,expected",
    [
        ("tenant@test.com", b"original", ("valid", "verified_copy")),
        ("tenant@test.com", b"tampered", ("invalid", "signature_mismatch")),
        ("owner@test.com", b"original", ("invalid", "signature_mismatch")),
        ("missing@test.com", b"original", ("invalid", "unknown_signer")),
    ],
)
def test_reuploaded_signature_lookup(monkeypatch, signer_db, name, digest, expected):
    info = SimpleNamespace(
        is_intact=True,
        sub_filter=signing_routes.pdf_sign.SUBFILTER_RAW,
        signer_name=name,
        digest=digest,
        signature=b"signature",
        signing_time="D:20261126120000Z",
    )
    monkeypatch.setattr(signing_routes.pdf_sign, "extract_signatures", lambda _: [info])
    monkeypatch.setattr(
        signing_routes.crypto_sign, "verify_digest",
        lambda public_pem, actual_digest, signature: (
            public_pem == b"tenant-public" and actual_digest == b"original"
            and signature == b"signature"
        ),
    )
    assert signing_routes.verify_pdf(b"pdf", None, 2, signer_db) == expected


def test_reuploaded_invalid_structure_rejected_before_lookup(monkeypatch, signer_db):
    info = SimpleNamespace(
        is_intact=False,
        sub_filter=signing_routes.pdf_sign.SUBFILTER_RAW,
        signer_name="tenant@test.com",
        digest=b"original",
        signature=b"signature",
    )
    monkeypatch.setattr(signing_routes.pdf_sign, "extract_signatures", lambda _: [info])
    assert signing_routes.verify_pdf(b"pdf", None, 2, signer_db) == (
        "invalid", "byte_range_or_integrity"
    )
