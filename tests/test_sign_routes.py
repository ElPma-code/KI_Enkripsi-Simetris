import io
import secrets

import pytest
from pypdf import PdfWriter
from Crypto.PublicKey import RSA
import app as app_module
import database
import crypto
import pdf_sign
from tests.test_access_requests import world, login, upload, post, db_one, make_request, PASSWORDS


@pytest.fixture(autouse=True)
def cleanup_requests(world):
    for phase in (0, 1):
        conn = database.get_connection()
        try:
            with conn:
                conn.execute('DELETE FROM access_requests')
        finally:
            conn.close()
        if phase == 0:
            yield


@pytest.fixture
def signed(world):
    owner = login('tenant@test.com')
    writer = PdfWriter()
    writer.add_blank_page(595, 842)
    stream = io.BytesIO()
    writer.write(stream)
    original = stream.getvalue()
    name = secrets.token_hex(8) + '.pdf'
    upload(owner, name, original, 'AES', 'ID Document')
    source = db_one('SELECT MAX(id) FROM documents')[0]
    response = post(owner, f'/documents/{source}/sign', password=PASSWORDS['tenant@test.com'])
    assert response.status_code == 201, response.data
    doc_id = response.json['document_id']
    yield owner, source, doc_id, original


def verify(client, doc_id):
    return post(client, f'/documents/{doc_id}/verify')


def test_login_keys(world):
    uid = world['ids']['tenant@test.com']
    first = db_one('SELECT * FROM signing_keys WHERE user_id=?', uid)
    assert first is not None
    assert RSA.import_key(first['private_enc'], passphrase=PASSWORDS['tenant@test.com']).publickey() == RSA.import_key(first['public_pem'])
    assert first['public_pem'] != db_one('SELECT public_pem FROM user_keys WHERE user_id=?', uid)[0]
    login('tenant@test.com')
    assert db_one('SELECT public_pem FROM signing_keys WHERE user_id=?', uid)[0] == first['public_pem']


def test_sign_and_verify(signed):
    owner, source, doc_id, original = signed
    assert doc_id != source
    assert owner.get(f'/documents/{source}/download').data == original
    result = owner.get(f'/documents/{doc_id}/download').data
    assert result.startswith(original)
    assert pdf_sign.extract_signature(result).is_intact
    row = db_one('SELECT * FROM documents WHERE id=?', doc_id)
    stored = (app_module.ENCRYPTED_FILES_DIR / row['stored_name']).read_bytes()
    assert row['cipher'] == 'AES' and stored != result and not stored.startswith(b'%PDF-')
    assert verify(owner, doc_id).json['status'] == 'valid'
    assert verify(owner, source).json['status'] == 'unsigned'
    assert db_one("SELECT COUNT(*) FROM signature_logs WHERE document_id=? AND action='sign'", doc_id)[0] == 1
    assert db_one("SELECT COUNT(*) FROM signature_logs WHERE document_id=? AND action='verify'", doc_id)[0] >= 1


def test_sign_security(signed):
    owner, source, doc_id, _ = signed
    other = login('owner@test.com')
    url = f'/documents/{source}/sign'
    assert post(owner, url, password='wrong').status_code == 400
    assert post(other, url, password=PASSWORDS['owner@test.com']).status_code == 404
    assert app_module.app.test_client().post(url).status_code == 401
    assert owner.post(url, data={'password': PASSWORDS['tenant@test.com']}).status_code == 400
    assert verify(other, doc_id).status_code == 404
    assert post(owner, f'/documents/{doc_id}/sign', password=PASSWORDS['tenant@test.com']).status_code == 400


def test_non_pdf(world):
    owner = login('tenant@test.com')
    assert post(owner, f"/documents/{world['docs']['Bukti.pdf']}/sign", password=PASSWORDS['tenant@test.com']).status_code == 400


def replace_plaintext(doc_id, data):
    row = db_one('SELECT * FROM documents WHERE id=?', doc_id)
    blob = crypto.encrypt_file(data, 'AES')
    (app_module.ENCRYPTED_FILES_DIR / row['stored_name']).write_bytes(blob['ciphertext'])
    conn = database.get_connection()
    try:
        with conn:
            conn.execute('UPDATE documents SET size_bytes=?, iv_or_nonce=?, auth_tag=?, wrapped_key=?, key_wrap_iv=?, sha256_plaintext=? WHERE id=?', (len(data), blob['iv_or_nonce'], blob['auth_tag'], blob['wrapped_key'], blob['key_wrap_iv'], blob['sha256_plaintext'], doc_id))
    finally:
        conn.close()


@pytest.mark.parametrize('mutation', ['byte', 'append', 'signature', 'range', 'wrong_key'])
def test_tamper(signed, mutation):
    owner, _, doc_id, _ = signed
    data = owner.get(f'/documents/{doc_id}/download').data
    info = pdf_sign.extract_signature(data)
    if mutation == 'wrong_key':
        conn = database.get_connection()
        try:
            with conn:
                conn.execute('UPDATE document_signatures SET signer_public_pem=? WHERE document_id=?', (db_one('SELECT public_pem FROM signing_keys WHERE user_id=?', db_one("SELECT id FROM users WHERE email='owner@test.com'")[0])[0], doc_id))
        finally:
            conn.close()
    else:
        if mutation == 'append':
            data += b'\n% added after signing\n'
        elif mutation == 'byte':
            data = data.replace(b'%PDF-1.', b'%PDF-2.', 1)
        elif mutation == 'signature':
            pos = info.byte_range[1] + 15
            data = data[:pos] + (b'1' if data[pos:pos+1] != b'1' else b'2') + data[pos+1:]
        else:
            import re
            data = re.sub(rb'/ByteRange\s*\[\s*0', b'/ByteRange [ 1', data, count=1)
        replace_plaintext(doc_id, data)
    response = verify(owner, doc_id)
    assert response.status_code == 200 and response.json['status'] == 'invalid', response.data


@pytest.mark.parametrize('end_state', ['revoked', 'expired'])
def test_shared_verification(signed, end_state):
    owner, _, doc_id, _ = signed
    recipient = login('owner@test.com')
    req = make_request(recipient)
    rid = req['id']
    assert post(owner, f'/requests/{rid}/approve', document_ids=[str(doc_id)]).status_code == 302
    package = db_one('SELECT package FROM access_requests WHERE id=?', rid)[0]
    assert post(recipient, '/shared/unlock', package=package, password=PASSWORDS['owner@test.com']).status_code == 200
    assert verify(recipient, doc_id).json['status'] == 'valid'
    if end_state == 'revoked':
        assert post(owner, f'/requests/{rid}/revoke').status_code == 302
    else:
        conn = database.get_connection()
        try:
            with conn:
                conn.execute("UPDATE access_requests SET expires_at=datetime('now','-1 day') WHERE id=?", (rid,))
        finally:
            conn.close()
    assert verify(recipient, doc_id).status_code == 404
