"""Integration test: offline relay — owner signature survives relay hops.

Protocol flow being tested:
  1. Owner creates a file and signs its manifest with their Ed25519 key.
  2. Owner uploads the file (with manifest) to a relay peer.
  3. Requester connects to the relay, lists files, requests the file.
  4. Relay forwards the file and the ORIGINAL manifest (no re-signing).
  5. Requester verifies:
       a. File SHA-256 matches manifest.
       b. Manifest owner_signature is valid against the owner's public key.
       c. The relay's public key does NOT validate the signature.

This test is Python-only but mirrors the cross-language guarantee:
a Go relay must also forward manifests without modification.
"""

import os
import socket
import threading
import tempfile
import pytest

from helpers import load_fixture
from p2pshare.crypto.keys import (
    generate_identity_keypair,
    public_key_to_bytes,
    b64url_encode,
    b64url_decode,
)
from p2pshare.crypto.session import SessionCipher
from p2pshare.crypto.handshake import HandshakeInitiator, HandshakeResponder
from p2pshare.storage.file_store import (
    FileStore,
    create_manifest,
    verify_manifest,
    verify_file_integrity,
)
from p2pshare.protocol.files import (
    handle_list_request,
    build_file_chunks,
    reassemble_file,
    verify_received_file,
)
from p2pshare.protocol.messages import (
    list_request,
    transfer_request,
    transfer_response,
)
from p2pshare.network.transport import (
    send_json, recv_json, send_encrypted, recv_encrypted,
)
from p2pshare.errors import IntegrityError


# ── handshake helpers ─────────────────────────────────────────────────────────

def _handshake_responder(conn, sk, pk):
    hs = HandshakeResponder(sk, pk)
    hs.process_hello(recv_json(conn))
    send_json(conn, hs.create_hello_ack())
    session_key = hs.derive_session()
    tmp = SessionCipher(session_key)
    hs.verify_auth(recv_encrypted(conn, tmp))
    auth_ack, cipher = hs.create_auth_ack(session_key)
    send_encrypted(conn, cipher, auth_ack)
    return cipher, public_key_to_bytes(hs.peer_identity_pk)


def _handshake_initiator(conn, sk, pk):
    hs = HandshakeInitiator(sk, pk)
    send_json(conn, hs.create_hello())
    hs.process_hello_ack(recv_json(conn))
    session_key = hs.derive_session()
    auth, cipher = hs.create_auth(session_key)
    send_encrypted(conn, cipher, auth)
    hs.verify_auth_ack(recv_encrypted(conn, cipher))
    return cipher, public_key_to_bytes(hs.peer_identity_pk)


# ── core relay test ───────────────────────────────────────────────────────────

def test_relay_owner_signature_verified_by_requester():
    """Requester can verify the original owner's signature on a file stored at a relay."""
    sk_owner, pk_owner = generate_identity_keypair()
    sk_relay, pk_relay = generate_identity_keypair()
    sk_requester, pk_requester = generate_identity_keypair()

    file_data = b"Original file content. Owner is the only signer."
    vault_key = os.urandom(32)

    # Step 1: owner creates and signs the file
    original_manifest = create_manifest(sk_owner, pk_owner, "document.txt", file_data)
    owner_pk_bytes = public_key_to_bytes(pk_owner)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    errors = {}
    relay_received_manifest = {}

    def relay_thread():
        """Relay: holds owner's file, serves it verbatim to requester."""
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                conn, _ = server_sock.accept()
                cipher, _ = _handshake_responder(conn, sk_relay, pk_relay)

                # Relay has the owner's file (pre-stored, as if owner sent it earlier)
                fs = FileStore(tmpdir, vault_key)
                fs.store_file(original_manifest["file_id"], file_data, original_manifest)
                relay_received_manifest["manifest"] = original_manifest

                # Handle LIST_REQUEST
                msg = recv_encrypted(conn, cipher)
                assert msg["type"] == "LIST_REQUEST"
                seq = [0]
                send_encrypted(conn, cipher, handle_list_request(msg, fs, seq))

                # Handle TRANSFER_REQUEST
                msg = recv_encrypted(conn, cipher)
                assert msg["type"] == "TRANSFER_REQUEST"
                send_encrypted(conn, cipher, transfer_response(2, msg["file_id"], True))

                # Send file chunks — relay does NOT re-sign the manifest
                for chunk_msg in build_file_chunks(fs, msg["file_id"], seq_start=2):
                    send_encrypted(conn, cipher, chunk_msg)

                conn.close()
        except Exception as e:
            errors["relay"] = e
        finally:
            server_sock.close()

    t = threading.Thread(target=relay_thread, daemon=True)
    t.start()

    # Requester connects to relay
    received_chunks = []
    complete_msg = None

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    cipher_r, relay_pk_bytes = _handshake_initiator(client, sk_requester, pk_requester)

    send_encrypted(client, cipher_r, list_request(1))
    list_resp = recv_encrypted(client, cipher_r)
    assert list_resp["type"] == "LIST_RESPONSE"
    assert len(list_resp["files"]) == 1
    received_manifest = list_resp["files"][0]

    file_id = received_manifest["file_id"]
    send_encrypted(client, cipher_r, transfer_request(
        2, file_id, b64url_encode(public_key_to_bytes(pk_requester))
    ))
    resp = recv_encrypted(client, cipher_r)
    assert resp["accepted"] is True

    while True:
        msg = recv_encrypted(client, cipher_r)
        if msg["type"] == "TRANSFER_CHUNK":
            received_chunks.append(msg)
        elif msg["type"] == "TRANSFER_COMPLETE":
            complete_msg = msg
            break

    client.close()
    t.join(timeout=5)
    assert "relay" not in errors, f"Relay error: {errors['relay']}"

    # Requester verifies the received file
    assembled = reassemble_file(received_chunks)
    assert assembled == file_data

    # SHA-256 integrity via TRANSFER_COMPLETE
    verify_file_integrity(assembled, complete_msg["sha256"])

    # CRITICAL: signature must be valid against OWNER'S key, not relay's key
    verify_received_file(assembled, received_manifest, owner_pk_bytes)

    # Relay key must NOT validate owner's signature
    with pytest.raises(IntegrityError):
        verify_received_file(assembled, received_manifest, relay_pk_bytes)


def test_relay_tampered_manifest_rejected():
    """Relay cannot forge a manifest — altering any field breaks the owner signature."""
    sk_owner, pk_owner = generate_identity_keypair()
    owner_pk_bytes = public_key_to_bytes(pk_owner)

    file_data = b"Authentic content."
    manifest = create_manifest(sk_owner, pk_owner, "auth.txt", file_data)

    # Relay (malicious) tries to change the filename
    tampered = dict(manifest)
    tampered["filename"] = "malware.exe"

    from p2pshare.crypto.keys import bytes_to_public_key
    owner_pk = bytes_to_public_key(owner_pk_bytes)
    with pytest.raises(IntegrityError):
        verify_manifest(tampered, owner_pk)


def test_relay_tampered_file_data_rejected():
    """Relay cannot substitute different file content — SHA-256 check catches it."""
    sk_owner, pk_owner = generate_identity_keypair()
    owner_pk_bytes = public_key_to_bytes(pk_owner)

    original_data = b"Original file data."
    manifest = create_manifest(sk_owner, pk_owner, "original.txt", original_data)
    tampered_data = b"Substituted malicious content."

    with pytest.raises(IntegrityError):
        verify_received_file(tampered_data, manifest, owner_pk_bytes)


def test_relay_fixture_manifest_verifiable():
    """The pre-generated fixture manifest can be relayed and verified by requester."""
    from p2pshare.crypto.keys import bytes_to_public_key

    fx = load_fixture("sample_manifest.json")
    owner_pk_bytes = b64url_decode(fx["owner_public_key"])
    owner_pk = bytes_to_public_key(owner_pk_bytes)
    file_data = b64url_decode(fx["file_data"])
    manifest = fx["manifest"]

    # Simulate relay forwarding manifest verbatim
    relayed_manifest = dict(manifest)

    # Requester verifies using owner's key (from contact book, not from relay)
    verify_received_file(file_data, relayed_manifest, owner_pk_bytes)


def test_relay_multi_hop_signature_survives():
    """Owner signature remains valid across multiple relay hops (manifest passed unchanged)."""
    sk_owner, pk_owner = generate_identity_keypair()
    owner_pk_bytes = public_key_to_bytes(pk_owner)

    file_data = b"Multi-hop relay test content."
    manifest = create_manifest(sk_owner, pk_owner, "multihop.txt", file_data)

    # Simulate 3 relay hops — each just copies the manifest dict
    hop1 = dict(manifest)
    hop2 = dict(hop1)
    hop3 = dict(hop2)

    # Final requester verifies
    verify_received_file(file_data, hop3, owner_pk_bytes)
