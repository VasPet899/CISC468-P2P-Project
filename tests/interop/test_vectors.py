"""Cross-language test vector validation.

Verifies that Python's crypto output matches the pre-computed fixtures,
which Go must also produce identically. When Go is available, the Go
test suite (go-client/tests/) validates the same fixture values from
the Go side, completing the cross-language verification.
"""

import json
import os
import sys
import pytest

from helpers import load_fixture, FIXTURES_DIR
from p2pshare.crypto.keys import (
    b64url_encode,
    b64url_decode,
    seed_to_private_key,
    public_key_to_bytes,
    bytes_to_public_key,
)
from p2pshare.crypto.signing import canonical_json, sign, verify
from p2pshare.crypto.handshake import derive_session_key
from p2pshare.crypto.storage import derive_vault_key
from p2pshare.crypto.session import decrypt_raw, encrypt_raw
from p2pshare.storage.file_store import verify_manifest, verify_file_integrity
from p2pshare.protocol.migration import verify_migration
from p2pshare.errors import IntegrityError


# ── Ed25519 / canonical JSON ──────────────────────────────────────────────────

class TestEdDSAVectors:
    def setup_method(self):
        self.fx = load_fixture("sample_keypair_ed25519.json")

    def test_public_key_from_seed(self):
        seed = b64url_decode(self.fx["seed"])
        sk = seed_to_private_key(seed)
        pk_bytes = public_key_to_bytes(sk.public_key())
        assert b64url_encode(pk_bytes) == self.fx["public_key"]

    def test_signature_verification(self):
        """Python can verify the signature produced when the fixtures were generated."""
        pk_bytes = b64url_decode(self.fx["public_key"])
        pk = bytes_to_public_key(pk_bytes)
        msg = b64url_decode(self.fx["test_message"])
        sig = b64url_decode(self.fx["test_signature"])
        verify(pk, msg, sig)  # Must not raise

    def test_canonical_json_output(self):
        """Python canonical JSON matches the fixture's expected bytes."""
        cj_fx = self.fx["canonical_json_test"]
        obj = cj_fx["input"]
        expected = cj_fx["expected_bytes"]
        actual = b64url_encode(canonical_json(obj))
        assert actual == expected

    def test_canonical_json_string(self):
        cj_fx = self.fx["canonical_json_test"]
        result = canonical_json(cj_fx["input"]).decode("utf-8")
        assert result == cj_fx["expected_string"]


# ── HKDF session key derivation ───────────────────────────────────────────────

class TestHKDFVectors:
    def setup_method(self):
        self.fx = load_fixture("sample_hkdf_vectors.json")

    def test_session_key_matches_fixture(self):
        shared = b64url_decode(self.fx["shared_secret"])
        nonce_i = b64url_decode(self.fx["nonce_initiator"])
        nonce_r = b64url_decode(self.fx["nonce_responder"])
        key = derive_session_key(shared, nonce_i, nonce_r)
        assert b64url_encode(key) == self.fx["expected_session_key"]


# ── Argon2id ──────────────────────────────────────────────────────────────────

class TestArgon2idVectors:
    def setup_method(self):
        self.fx = load_fixture("sample_argon2id_vectors.json")

    def test_vault_key_matches_fixture(self):
        password = self.fx["password"]
        salt = b64url_decode(self.fx["salt"])
        key = derive_vault_key(password, salt)
        assert b64url_encode(key) == self.fx["expected_key"]


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

class TestAESGCMVectors:
    def setup_method(self):
        self.fx = load_fixture("sample_aes_gcm_vectors.json")

    def test_decrypt_fixture_payload(self):
        key = b64url_decode(self.fx["key"])
        payload = b64url_decode(self.fx["payload"])
        plaintext = decrypt_raw(key, payload)
        assert plaintext == b64url_decode(self.fx["plaintext"])

    def test_plaintext_string(self):
        key = b64url_decode(self.fx["key"])
        payload = b64url_decode(self.fx["payload"])
        plaintext = decrypt_raw(key, payload)
        assert plaintext.decode("utf-8") == self.fx["plaintext_string"]

    def test_re_encrypt_decrypt(self):
        """Verify that encrypt_raw + decrypt_raw round-trips (different nonce each time)."""
        key = b64url_decode(self.fx["key"])
        plaintext = b64url_decode(self.fx["plaintext"])
        enc = encrypt_raw(key, plaintext)
        dec = decrypt_raw(key, enc)
        assert dec == plaintext

    def test_tampered_tag_fails(self):
        key = b64url_decode(self.fx["key"])
        payload = bytearray(b64url_decode(self.fx["payload"]))
        payload[-1] ^= 0xFF
        with pytest.raises(IntegrityError):
            decrypt_raw(key, bytes(payload))


# ── File manifest / offline relay ─────────────────────────────────────────────

class TestManifestVectors:
    def setup_method(self):
        self.fx = load_fixture("sample_manifest.json")

    def test_owner_signature_verifies(self):
        pk_bytes = b64url_decode(self.fx["owner_public_key"])
        pk = bytes_to_public_key(pk_bytes)
        manifest = self.fx["manifest"]
        verify_manifest(manifest, pk)  # Must not raise

    def test_file_hash_matches(self):
        file_data = b64url_decode(self.fx["file_data"])
        expected_hash = self.fx["manifest"]["sha256"]
        verify_file_integrity(file_data, expected_hash)  # Must not raise

    def test_tampered_file_fails(self):
        file_data = b64url_decode(self.fx["file_data"])
        expected_hash = self.fx["manifest"]["sha256"]
        with pytest.raises(IntegrityError):
            verify_file_integrity(file_data + b"extra", expected_hash)

    def test_tampered_manifest_fails(self):
        pk_bytes = b64url_decode(self.fx["owner_public_key"])
        pk = bytes_to_public_key(pk_bytes)
        manifest = dict(self.fx["manifest"])
        manifest["filename"] = "evil.exe"
        with pytest.raises(IntegrityError):
            verify_manifest(manifest, pk)


# ── Key migration ─────────────────────────────────────────────────────────────

class TestMigrationVectors:
    def setup_method(self):
        self.fx = load_fixture("sample_migration.json")

    def test_migration_verifies(self):
        old_pk_bytes = b64url_decode(self.fx["old_public_key"])
        msg = self.fx["migration_message"]
        new_pk_bytes = verify_migration(msg, old_pk_bytes)
        assert b64url_encode(new_pk_bytes) == self.fx["new_public_key"]

    def test_migration_wrong_old_key_fails(self):
        from p2pshare.errors import MigrationError
        _, wrong_pk = __import__("p2pshare.crypto.keys", fromlist=["generate_identity_keypair"]).generate_identity_keypair()
        from p2pshare.crypto.keys import generate_identity_keypair, public_key_to_bytes as pk2b
        _, wrong_pk = generate_identity_keypair()
        msg = self.fx["migration_message"]
        with pytest.raises(MigrationError):
            verify_migration(msg, pk2b(wrong_pk))
