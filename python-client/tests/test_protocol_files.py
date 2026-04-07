"""Tests for file manifest creation, verification, and transfer operations."""

import os
import tempfile
import pytest

from p2pshare.crypto.keys import (
    generate_identity_keypair,
    public_key_to_bytes,
    b64url_decode,
)
from p2pshare.storage.file_store import (
    FileStore,
    create_manifest,
    verify_manifest,
    verify_file_integrity,
    compute_file_hash,
)
from p2pshare.protocol.files import (
    build_file_chunks,
    reassemble_file,
    verify_received_file,
)
from p2pshare.errors import IntegrityError


@pytest.fixture
def identity():
    return generate_identity_keypair()


@pytest.fixture
def file_data():
    return b"Hello, this is test file content for the P2P sharing app."


@pytest.fixture
def temp_store(identity):
    sk, pk = identity
    with tempfile.TemporaryDirectory() as tmpdir:
        vault_key = os.urandom(32)
        fs = FileStore(tmpdir, vault_key)
        yield fs, sk, pk, tmpdir, vault_key


def test_create_manifest(identity, file_data):
    sk, pk = identity
    manifest = create_manifest(sk, pk, "test.txt", file_data, "A test file")
    assert manifest["filename"] == "test.txt"
    assert manifest["size_bytes"] == len(file_data)
    assert manifest["description"] == "A test file"
    assert manifest["version"] == 1
    assert "owner_signature" in manifest
    assert "file_id" in manifest
    assert "sha256" in manifest


def test_verify_manifest(identity, file_data):
    sk, pk = identity
    manifest = create_manifest(sk, pk, "test.txt", file_data)
    verify_manifest(manifest, pk)  # Should not raise


def test_verify_manifest_tampered(identity, file_data):
    sk, pk = identity
    manifest = create_manifest(sk, pk, "test.txt", file_data)
    manifest["filename"] = "tampered.txt"
    with pytest.raises(IntegrityError):
        verify_manifest(manifest, pk)


def test_verify_manifest_wrong_key(identity, file_data):
    sk, pk = identity
    _, other_pk = generate_identity_keypair()
    manifest = create_manifest(sk, pk, "test.txt", file_data)
    with pytest.raises(IntegrityError):
        verify_manifest(manifest, other_pk)


def test_verify_file_integrity(file_data):
    expected_hash = compute_file_hash(file_data)
    verify_file_integrity(file_data, expected_hash)  # Should not raise


def test_verify_file_integrity_tampered(file_data):
    expected_hash = compute_file_hash(file_data)
    tampered = file_data + b"extra"
    with pytest.raises(IntegrityError):
        verify_file_integrity(tampered, expected_hash)


def test_file_store_roundtrip(temp_store, identity, file_data):
    fs, sk, pk, tmpdir, vault_key = temp_store
    manifest = create_manifest(sk, pk, "doc.pdf", file_data)
    file_id = manifest["file_id"]

    fs.store_file(file_id, file_data, manifest)
    assert fs.has_file(file_id)

    loaded = fs.load_file(file_id)
    assert loaded == file_data

    loaded_manifest = fs.load_manifest(file_id)
    assert loaded_manifest["filename"] == "doc.pdf"


def test_file_store_list(temp_store, identity):
    fs, sk, pk, tmpdir, vault_key = temp_store
    m1 = create_manifest(sk, pk, "a.txt", b"content a")
    m2 = create_manifest(sk, pk, "b.txt", b"content b")
    fs.store_file(m1["file_id"], b"content a", m1)
    fs.store_file(m2["file_id"], b"content b", m2)
    manifests = fs.list_manifests()
    assert len(manifests) == 2
    names = {m["filename"] for m in manifests}
    assert names == {"a.txt", "b.txt"}


def test_build_and_reassemble_chunks(temp_store, identity, file_data):
    fs, sk, pk, tmpdir, vault_key = temp_store
    manifest = create_manifest(sk, pk, "test.bin", file_data)
    file_id = manifest["file_id"]
    fs.store_file(file_id, file_data, manifest)

    chunk_msgs = build_file_chunks(fs, file_id, 0)
    # Last message is TRANSFER_COMPLETE
    assert chunk_msgs[-1]["type"] == "TRANSFER_COMPLETE"
    chunks = [m for m in chunk_msgs if m["type"] == "TRANSFER_CHUNK"]
    reassembled = reassemble_file(chunks)
    assert reassembled == file_data


def test_verify_received_file(identity, file_data):
    sk, pk = identity
    manifest = create_manifest(sk, pk, "test.txt", file_data)
    pk_bytes = public_key_to_bytes(pk)
    verify_received_file(file_data, manifest, pk_bytes)  # Should not raise


def test_verify_received_file_tampered(identity, file_data):
    sk, pk = identity
    manifest = create_manifest(sk, pk, "test.txt", file_data)
    pk_bytes = public_key_to_bytes(pk)
    with pytest.raises(IntegrityError):
        verify_received_file(file_data + b"tampered", manifest, pk_bytes)
