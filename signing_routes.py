"""PDF signing routes; raw RSA-SHA256, separate signing keys."""
import json
import re
import secrets
import uuid
from pathlib import Path
from contextlib import closing

from flask import Blueprint, current_app, jsonify, request, session
from argon2.exceptions import VerificationError
from pypdf.errors import PdfReadError

import crypto
import crypto_sign
import pdf_sign
import access_requests
from database import get_connection, password_hasher

bp = Blueprint('signing', __name__)


def ensure_signing_keypair(user_id, password):
    with closing(get_connection()) as conn:
        if conn.execute('SELECT 1 FROM signing_keys WHERE user_id=?', (user_id,)).fetchone():
            return False
        public, private = crypto.generate_user_keypair(password)
        with conn:
            result = conn.execute('INSERT INTO signing_keys(user_id, public_pem, private_enc) VALUES (?, ?, ?) ON CONFLICT(user_id) DO NOTHING', (user_id, public, private))
        return result.rowcount == 1


def error(message, status):
    return jsonify(error=message), status


def identity():
    from flask import abort
    uid = session.get('user_id')
    if uid is None:
        abort(401)
    token = request.form.get('csrf_token', '')
    expected = session.get('_csrf_token', '')
    if not expected or not secrets.compare_digest(token, expected):
        abort(400)
    return uid


def storage_path(name):
    from app import ENCRYPTED_FILES_DIR
    if not re.fullmatch(r'[0-9a-f]{32}\.enc', name):
        raise ValueError('Invalid storage name')
    root = Path(ENCRYPTED_FILES_DIR).resolve()
    path = root / name
    if path.is_symlink():
        raise ValueError('Invalid storage path')
    return path


def decrypt(doc, data_key=None):
    blob = {k: doc[k] for k in ('iv_or_nonce', 'auth_tag', 'wrapped_key', 'key_wrap_iv', 'sha256_plaintext')}
    blob['ciphertext'] = storage_path(doc['stored_name']).read_bytes()
    return crypto.decrypt_file(blob, doc['cipher'], data_key=data_key)


def audit(conn, uid, doc_id, action, result):
    conn.execute('INSERT INTO signature_logs(user_id, document_id, action, result) VALUES (?, ?, ?, ?)', (uid, doc_id, action, result))


@bp.post('/documents/<int:doc_id>/sign')
def sign_document(doc_id):
    uid = identity()
    target = None
    created = False
    committed = False
    try:
        with closing(get_connection()) as conn:
            doc = conn.execute('SELECT * FROM documents WHERE id=? AND user_id=?', (doc_id, uid)).fetchone()
            if doc is None:
                return error('Dokumen tidak ditemukan.', 404)
            user = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
            password = request.form.get('password', '')
            try:
                password_hasher.verify(user['password_hash'], password)
            except VerificationError:
                return error('Password salah.', 400)
            key = conn.execute('SELECT * FROM signing_keys WHERE user_id=?', (uid,)).fetchone()
            if key is None:
                return error('Login ulang untuk menyiapkan kunci.', 409)
            try:
                original = decrypt(doc)
                prepared = pdf_sign.prepare_pdf(original, signer_name=user['email'])
            except (ValueError, OSError, TypeError, PdfReadError):
                return error('PDF tidak valid atau tidak dapat ditandatangani.', 400)
            signature = crypto_sign.sign_digest(key['private_enc'], password, prepared.digest)
            signed = pdf_sign.embed_signature(prepared, signature)
            info = pdf_sign.extract_signature(signed)
            if not info or not info.is_intact or not crypto_sign.verify_digest(key['public_pem'], info.digest, info.signature):
                raise ValueError('Generated signature failed self-check')
            blob = crypto.encrypt_file(signed, 'AES')
            name = crypto.decrypt_text(doc['original_name_enc']) if doc['original_name_enc'] is not None else doc['original_name']
            name = Path(name).stem + '_signed.pdf'
            stored = uuid.uuid4().hex + '.enc'
            target = storage_path(stored)
            with conn:
                new_id = conn.execute('''INSERT INTO documents(user_id, original_name, original_name_enc, stored_name, category, mime_type, size_bytes, cipher, iv_or_nonce, auth_tag, wrapped_key, key_wrap_iv, sha256_plaintext) VALUES (?, '', ?, ?, ?, 'application/pdf', ?, 'AES', ?, ?, ?, ?, ?)''', (uid, crypto.encrypt_text(name), stored, doc['category'], len(signed), blob['iv_or_nonce'], blob['auth_tag'], blob['wrapped_key'], blob['key_wrap_iv'], blob['sha256_plaintext'])).lastrowid
                conn.execute('''INSERT INTO document_signatures(document_id, source_document_id, signer_id, signer_public_pem, sub_filter, byte_range, digest_sha256, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', (new_id, doc_id, uid, key['public_pem'], info.sub_filter, json.dumps(info.byte_range), info.digest.hex(), signature))
                with target.open('xb') as stream:
                    created = True
                    stream.write(blob['ciphertext'])
                    stream.flush()
                    import os
                    os.fsync(stream.fileno())
                audit(conn, uid, new_id, 'sign', 'success')
            committed = True
            return jsonify(status='signed', document_id=new_id, source_document_id=doc_id), 201
    except Exception:
        current_app.logger.exception('PDF signing failed')
        return error('Gagal menandatangani PDF.', 500)
    finally:
        if created and not committed:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                current_app.logger.exception('Encrypted file cleanup failed')


def verify_pdf(data, meta, owner_id):
    try:
        infos = pdf_sign.extract_signatures(data)
        if not infos:
            return ('invalid', 'missing_signature') if meta else ('unsigned', 'no_signature')
        if len(infos) != 1:
            return 'invalid', 'multiple_signatures'
        info = infos[0]
        if not info.is_intact:
            return 'invalid', 'byte_range_or_integrity'
        if meta is None or meta['signer_id'] != owner_id:
            return 'invalid', 'unknown_signer'
        if info.sub_filter != pdf_sign.SUBFILTER_RAW or meta['sub_filter'] != info.sub_filter:
            return 'invalid', 'unsupported_format'
        if not crypto_sign.verify_digest(meta['signer_public_pem'], info.digest, info.signature):
            return 'invalid', 'signature_mismatch'
        if (info.digest.hex() != meta['digest_sha256'] or info.signature != meta['signature'] or list(info.byte_range) != json.loads(meta['byte_range'])):
            return 'invalid', 'metadata_mismatch'
        return 'valid', 'verified'
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, PdfReadError):
        return 'invalid', 'malformed_signature'


@bp.post('/documents/<int:doc_id>/verify')
def verify_document(doc_id):
    uid = identity()
    try:
        with closing(get_connection()) as conn:
            # Serialize with revoke/delete while checking and recording access.
            with conn:
                conn.execute('BEGIN IMMEDIATE')
                access_requests.expire_old_requests(conn)
                doc = conn.execute('SELECT * FROM documents WHERE id=? AND user_id=?', (doc_id, uid)).fetchone()
                data_key = None
                if doc is None:
                    doc = conn.execute('''SELECT d.*, r.id AS request_id, r.k_share_nonce, r.k_share_wrapped, g.rewrap_nonce, g.rewrapped_key FROM documents d JOIN share_grants g ON g.document_id=d.id JOIN access_requests r ON r.id=g.request_id AND r.owner_id=d.user_id WHERE d.id=? AND r.requester_id=? AND r.status='unlocked' AND r.expires_at > datetime('now') ORDER BY r.id DESC LIMIT 1''', (doc_id, uid)).fetchone()
                    if doc is None:
                        return error('Dokumen tidak ditemukan.', 404)
                    try:
                        share = crypto.unwrap_share_key(doc['k_share_nonce'], doc['k_share_wrapped'], doc['request_id'])
                        data_key = crypto.unwrap_rewrapped_data_key(share, doc['rewrap_nonce'], doc['rewrapped_key'], crypto.share_doc_aad(doc['request_id'], doc_id))
                        if len(data_key) != {'AES':32,'DES':8,'RC4':32}.get(doc['cipher']):
                            raise ValueError('Invalid key length')
                    except (ValueError, TypeError):
                        return error('Dokumen tidak ditemukan.', 404)
                meta = conn.execute('''SELECT s.*, u.email AS signer_email FROM document_signatures s JOIN users u ON u.id=s.signer_id WHERE s.document_id=?''', (doc_id,)).fetchone()
                try:
                    data = decrypt(doc, data_key)
                    status, reason = verify_pdf(data, meta, doc['user_id'])
                except (ValueError, OSError, TypeError, PdfReadError):
                    status, reason = 'invalid', 'storage_integrity'
                audit(conn, uid, doc_id, 'verify', status)
                response = jsonify(status=status, reason=reason, signer=meta['signer_email'] if status=='valid' else None, signed_at=meta['signed_at'] if status=='valid' else None)
                response.headers['Cache-Control'] = 'no-store'
                return response
    except Exception:
        current_app.logger.exception('PDF verification failed')
        return error('Gagal memverifikasi PDF.', 500)
