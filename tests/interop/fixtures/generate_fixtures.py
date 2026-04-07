"""Generate shared interop test fixtures for cross-language validation.

Run this once to produce fixture files used by both Python and Go tests.
"""

import json
import os
import sys
import hashlib
import time

# Ensure the python-client package is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "python-client"))

from p2pshare.crypto.keys import (
    generate_identity_keypair,
    private_key_to_seed,
    public_key_to_bytes,
    b64url_encode,
    b64url_decode,
)
from p2pshare.crypto.signing import canonical_json, sign
from p2pshare.crypto.handshake import (
    generate_ephemeral_keypair,
    x25519_public_key_to_bytes,
    compute_shared_secret,
    derive_session_key,
    build_auth_transcript,
)
from p2pshare.crypto.storage import derive_vault_key
from p2pshare.crypto.session import encrypt_raw, decrypt_raw
from p2pshare.storage.file_store import create_manifest, compute_file_hash


FIXTURES_DIR = os.path.dirname(__file__)


def write_fixture(name, data):
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  Written: {name}")


def generate_keypair_fixture():
    """Fixed Ed25519 keypair with known seed."""
    # Use a deterministic seed for reproducibility
    seed = bytes(range(32))  # 0x00..0x1f
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key()

    msg = b"test message for cross-language signature verification"
    sig = sign(sk, msg)

    write_fixture("sample_keypair_ed25519.json", {
        "description": "Ed25519 keypair with known seed for cross-language test vectors",
        "seed": b64url_encode(seed),
        "public_key": b64url_encode(public_key_to_bytes(pk)),
        "peer_id": b64url_encode(public_key_to_bytes(pk)),
        "test_message": b64url_encode(msg),
        "test_signature": b64url_encode(sig),
        "canonical_json_test": {
            "input": {"z": 1, "a": 2, "m": 3},
            "expected_bytes": b64url_encode(canonical_json({"z": 1, "a": 2, "m": 3})),
            "expected_string": canonical_json({"z": 1, "a": 2, "m": 3}).decode("utf-8"),
        }
    })


def generate_hkdf_fixture():
    """HKDF test vector for session key derivation."""
    shared = bytes(range(32))         # 0x00..0x1f
    nonce_i = bytes(range(32, 64))    # 0x20..0x3f
    nonce_r = bytes(range(64, 96))    # 0x40..0x5f

    session_key = derive_session_key(shared, nonce_i, nonce_r)

    write_fixture("sample_hkdf_vectors.json", {
        "description": "HKDF-SHA256 test vectors for session key derivation",
        "shared_secret": b64url_encode(shared),
        "nonce_initiator": b64url_encode(nonce_i),
        "nonce_responder": b64url_encode(nonce_r),
        "expected_session_key": b64url_encode(session_key),
        "hkdf_info": "p2pshare-session-v1",
    })


def generate_argon2_fixture():
    """Argon2id test vector for vault key derivation."""
    password = "test-password-123"
    salt = bytes(range(16))  # 0x00..0x0f

    vault_key = derive_vault_key(password, salt)

    write_fixture("sample_argon2id_vectors.json", {
        "description": "Argon2id test vector for vault key derivation",
        "password": password,
        "salt": b64url_encode(salt),
        "params": {"time": 3, "memory": 65536, "parallelism": 4, "keylen": 32},
        "expected_key": b64url_encode(vault_key),
    })


def generate_manifest_fixture():
    """Signed file manifest for offline relay verification tests."""
    seed = bytes(range(32))
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key()

    file_data = b"Hello, this is the content of the shared file."
    manifest = create_manifest(sk, pk, "hello.txt", file_data, "A test file for relay")

    write_fixture("sample_manifest.json", {
        "description": "Signed file manifest for cross-language relay verification",
        "owner_seed": b64url_encode(seed),
        "owner_public_key": b64url_encode(public_key_to_bytes(pk)),
        "file_data": b64url_encode(file_data),
        "manifest": manifest,
    })


def generate_migration_fixture():
    """Key migration announcement for cross-language verification."""
    import time
    from p2pshare.protocol.migration import create_migration

    old_seed = bytes(range(32))
    new_seed = bytes(range(1, 33))

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    old_sk = Ed25519PrivateKey.from_private_bytes(old_seed)
    old_pk = old_sk.public_key()
    new_sk = Ed25519PrivateKey.from_private_bytes(new_seed)
    new_pk = new_sk.public_key()

    msg = create_migration(old_sk, old_pk, new_sk, new_pk, "scheduled_rotation")

    write_fixture("sample_migration.json", {
        "description": "KEY_MIGRATION announcement for cross-language verification",
        "old_seed": b64url_encode(old_seed),
        "old_public_key": b64url_encode(public_key_to_bytes(old_pk)),
        "new_seed": b64url_encode(new_seed),
        "new_public_key": b64url_encode(public_key_to_bytes(new_pk)),
        "migration_message": msg,
    })


def generate_aes_gcm_fixture():
    """AES-256-GCM test vector for cross-language validation."""
    key = bytes(range(32))       # 0x00..0x1f
    nonce = bytes(range(12))     # 0x00..0x0b
    plaintext = b"The quick brown fox jumps over the lazy dog."

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    gcm = AESGCM(key)
    ct_with_tag = gcm.encrypt(nonce, plaintext, None)
    # Wire format: nonce || ct || tag
    payload = nonce + ct_with_tag

    write_fixture("sample_aes_gcm_vectors.json", {
        "description": "AES-256-GCM test vector — wire format: nonce(12B) || ciphertext || tag(16B)",
        "key": b64url_encode(key),
        "nonce": b64url_encode(nonce),
        "plaintext": b64url_encode(plaintext),
        "plaintext_string": plaintext.decode("utf-8"),
        "payload": b64url_encode(payload),
        "note": "nonce is NOT prepended by the library — must be prepended manually in wire format",
    })


if __name__ == "__main__":
    print("Generating interop test fixtures...")
    generate_keypair_fixture()
    generate_hkdf_fixture()
    generate_argon2_fixture()
    generate_manifest_fixture()
    generate_migration_fixture()
    generate_aes_gcm_fixture()
    print("Done.")
