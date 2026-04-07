"""Encrypted file storage and manifest management.

Files are stored encrypted at rest:
  file_key = HKDF-SHA256(ikm=vault_key, salt=file_id_bytes, info="p2pshare-file-v1", len=32)
  .enc file = nonce (12B) || AES-256-GCM(file_key, plaintext) || tag (16B)
  .meta file = plaintext JSON manifest entry (owner signature verifiable without vault)
"""

import os
import json
import hashlib
import time

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from p2pshare.crypto.keys import (
    b64url_encode,
    b64url_decode,
    public_key_to_bytes,
    peer_id_from_public_key,
)
from p2pshare.crypto.signing import canonical_json, sign, verify
from p2pshare.crypto.session import encrypt_raw, decrypt_raw
from p2pshare.errors import IntegrityError

FILE_KEY_INFO = b"p2pshare-file-v1"


def derive_file_key(vault_key: bytes, file_id: str) -> bytes:
    """Derive a per-file AES-256-GCM key from the vault key and file_id."""
    file_id_bytes = b64url_decode(file_id)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=file_id_bytes,
        info=FILE_KEY_INFO,
    )
    return hkdf.derive(vault_key)


def compute_file_id(owner_id_bytes: bytes, filename: str, upload_timestamp: int) -> str:
    """Compute a file_id: base64url(SHA256(owner_id || utf8(filename) || timestamp_bytes))."""
    ts_bytes = upload_timestamp.to_bytes(8, "big")
    digest = hashlib.sha256(owner_id_bytes + filename.encode("utf-8") + ts_bytes).digest()
    return b64url_encode(digest)


def compute_file_hash(data: bytes) -> str:
    """Compute base64url(SHA256(data))."""
    return b64url_encode(hashlib.sha256(data).digest())


def create_manifest(identity_sk, identity_pk, filename: str, file_data: bytes, description: str = "") -> dict:
    """Create a signed file manifest entry for a file the local peer owns."""
    owner_id_bytes = public_key_to_bytes(identity_pk)
    upload_ts = int(time.time() * 1000)
    file_id = compute_file_id(owner_id_bytes, filename, upload_ts)
    file_hash = compute_file_hash(file_data)

    manifest = {
        "file_id": file_id,
        "filename": filename,
        "size_bytes": len(file_data),
        "sha256": file_hash,
        "owner_id": peer_id_from_public_key(identity_pk),
        "upload_timestamp": upload_ts,
        "description": description,
        "version": 1,
    }
    sig = sign(identity_sk, canonical_json(manifest))
    manifest["owner_signature"] = b64url_encode(sig)
    return manifest


def verify_manifest(manifest: dict, owner_pk) -> None:
    """Verify the owner_signature on a manifest entry.

    Raises IntegrityError if invalid.
    """
    sig_b64 = manifest["owner_signature"]
    sig = b64url_decode(sig_b64)

    manifest_without_sig = {k: v for k, v in manifest.items() if k != "owner_signature"}
    verify(owner_pk, canonical_json(manifest_without_sig), sig)


def verify_file_integrity(file_data: bytes, expected_hash_b64: str) -> None:
    """Verify a downloaded file's SHA-256 matches the manifest. Raises IntegrityError."""
    actual = compute_file_hash(file_data)
    if actual != expected_hash_b64:
        raise IntegrityError("Downloaded file is corrupted or was tampered with. File discarded.")


class FileStore:
    """Manages encrypted file storage on disk."""

    def __init__(self, data_dir: str, vault_key: bytes):
        self.files_dir = os.path.join(data_dir, "files")
        self.vault_key = vault_key
        os.makedirs(self.files_dir, exist_ok=True)

    def store_file(self, file_id: str, file_data: bytes, manifest: dict) -> None:
        """Encrypt and store a file and its manifest."""
        file_key = derive_file_key(self.vault_key, file_id)
        encrypted = encrypt_raw(file_key, file_data)

        enc_path = os.path.join(self.files_dir, f"{file_id}.enc")
        with open(enc_path, "wb") as f:
            f.write(encrypted)

        meta_path = os.path.join(self.files_dir, f"{file_id}.meta")
        with open(meta_path, "w") as f:
            json.dump(manifest, f, indent=2)

    def load_file(self, file_id: str) -> bytes:
        """Decrypt and return a stored file's plaintext content."""
        enc_path = os.path.join(self.files_dir, f"{file_id}.enc")
        if not os.path.exists(enc_path):
            raise FileNotFoundError(f"File {file_id} not found in store")

        file_key = derive_file_key(self.vault_key, file_id)
        with open(enc_path, "rb") as f:
            encrypted = f.read()
        return decrypt_raw(file_key, encrypted)

    def load_manifest(self, file_id: str) -> dict:
        """Load a file's manifest entry."""
        meta_path = os.path.join(self.files_dir, f"{file_id}.meta")
        if not os.path.exists(meta_path):
            raise FileNotFoundError(f"Manifest {file_id} not found")
        with open(meta_path, "r") as f:
            return json.load(f)

    def list_manifests(self) -> list[dict]:
        """List all stored file manifests."""
        manifests = []
        for name in os.listdir(self.files_dir):
            if name.endswith(".meta"):
                path = os.path.join(self.files_dir, name)
                with open(path, "r") as f:
                    manifests.append(json.load(f))
        return manifests

    def has_file(self, file_id: str) -> bool:
        """Check if a file is stored locally."""
        return os.path.exists(os.path.join(self.files_dir, f"{file_id}.enc"))

    def store_own_file(self, identity_sk, identity_pk, filepath: str, description: str = "") -> dict:
        """Read a file from disk, create a signed manifest, encrypt and store it.

        Returns the manifest entry.
        """
        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            file_data = f.read()

        manifest = create_manifest(identity_sk, identity_pk, filename, file_data, description)
        self.store_file(manifest["file_id"], file_data, manifest)
        return manifest
