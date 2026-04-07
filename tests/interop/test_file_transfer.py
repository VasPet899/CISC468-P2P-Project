"""Integration test: file listing and transfer protocol.

Simulates the full file transfer flow over real sockets:
  1. Responder registers a file in its FileStore.
  2. Initiator connects, completes handshake, sends LIST_REQUEST.
  3. Responder replies with LIST_RESPONSE containing the manifest.
  4. Initiator sends TRANSFER_REQUEST; responder sends chunks + TRANSFER_COMPLETE.
  5. Initiator reassembles, verifies SHA-256, verifies owner signature.
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
    list_response,
    transfer_request,
    transfer_response,
)
from p2pshare.network.transport import (
    send_json, recv_json, send_encrypted, recv_encrypted,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _do_handshake_as_responder(conn, sk_r, pk_r):
    """Run responder side of handshake, return (session_cipher, peer_pk_bytes)."""
    hs = HandshakeResponder(sk_r, pk_r)
    hs.process_hello(recv_json(conn))
    send_json(conn, hs.create_hello_ack())
    sk = hs.derive_session()
    tmp = SessionCipher(sk)
    hs.verify_auth(recv_encrypted(conn, tmp))
    auth_ack, cipher = hs.create_auth_ack(sk)
    send_encrypted(conn, cipher, auth_ack)
    return cipher, public_key_to_bytes(hs.peer_identity_pk)


def _do_handshake_as_initiator(conn, sk_i, pk_i):
    """Run initiator side of handshake, return (session_cipher, peer_pk_bytes)."""
    hs = HandshakeInitiator(sk_i, pk_i)
    send_json(conn, hs.create_hello())
    hs.process_hello_ack(recv_json(conn))
    sk = hs.derive_session()
    auth, cipher = hs.create_auth(sk)
    send_encrypted(conn, cipher, auth)
    hs.verify_auth_ack(recv_encrypted(conn, cipher))
    return cipher, public_key_to_bytes(hs.peer_identity_pk)


# ── test: list + transfer round-trip ─────────────────────────────────────────

def test_file_list_and_transfer():
    """Initiator can list files from responder and receive a file correctly."""
    sk_i, pk_i = generate_identity_keypair()
    sk_r, pk_r = generate_identity_keypair()

    file_data = b"Hello, this is the content of the test file for transfer."
    vault_key = os.urandom(32)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    errors = {}
    responder_state = {}

    def responder_thread():
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                conn, _ = server_sock.accept()
                cipher, _ = _do_handshake_as_responder(conn, sk_r, pk_r)

                # Set up file store with one file
                fs = FileStore(tmpdir, vault_key)
                manifest = create_manifest(sk_r, pk_r, "hello.txt", file_data)
                fs.store_file(manifest["file_id"], file_data, manifest)
                responder_state["file_id"] = manifest["file_id"]
                responder_state["manifest"] = manifest

                # Handle LIST_REQUEST
                msg = recv_encrypted(conn, cipher)
                assert msg["type"] == "LIST_REQUEST"
                seq = [0]
                resp = handle_list_request(msg, fs, seq)
                send_encrypted(conn, cipher, resp)

                # Handle TRANSFER_REQUEST
                msg = recv_encrypted(conn, cipher)
                assert msg["type"] == "TRANSFER_REQUEST"
                assert msg["file_id"] == manifest["file_id"]

                # Send accepted response
                send_encrypted(conn, cipher, transfer_response(2, manifest["file_id"], True))

                # Send chunks + complete
                chunks = build_file_chunks(fs, manifest["file_id"], seq_start=2)
                for chunk_msg in chunks:
                    send_encrypted(conn, cipher, chunk_msg)

                conn.close()
        except Exception as e:
            errors["r"] = e
        finally:
            server_sock.close()

    t = threading.Thread(target=responder_thread, daemon=True)
    t.start()

    received_chunks = []
    complete_msg = None
    received_manifest = None

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", port))
    cipher_i, peer_pk_bytes = _do_handshake_as_initiator(client_sock, sk_i, pk_i)

    # Send LIST_REQUEST
    send_encrypted(client_sock, cipher_i, list_request(1))
    list_resp = recv_encrypted(client_sock, cipher_i)
    assert list_resp["type"] == "LIST_RESPONSE"
    assert len(list_resp["files"]) == 1
    received_manifest = list_resp["files"][0]

    # Send TRANSFER_REQUEST
    file_id = received_manifest["file_id"]
    send_encrypted(client_sock, cipher_i, transfer_request(2, file_id, b64url_encode(public_key_to_bytes(pk_i))))

    # Receive accepted
    resp = recv_encrypted(client_sock, cipher_i)
    assert resp["accepted"] is True

    # Receive chunks + complete
    while True:
        msg = recv_encrypted(client_sock, cipher_i)
        if msg["type"] == "TRANSFER_CHUNK":
            received_chunks.append(msg)
        elif msg["type"] == "TRANSFER_COMPLETE":
            complete_msg = msg
            break

    client_sock.close()
    t.join(timeout=5)

    assert "r" not in errors, f"Responder error: {errors['r']}"

    # Reassemble and verify
    assembled = reassemble_file(received_chunks)
    assert assembled == file_data

    # Verify SHA-256 from TRANSFER_COMPLETE
    verify_file_integrity(assembled, complete_msg["sha256"])

    # Verify owner signature from manifest (responder is the owner; peer_pk_bytes is their PK)
    verify_received_file(assembled, received_manifest, peer_pk_bytes)


def test_file_transfer_integrity_check_fails_on_corruption():
    """verify_file_integrity raises IntegrityError if data is tampered."""
    from p2pshare.errors import IntegrityError
    from p2pshare.storage.file_store import compute_file_hash

    file_data = b"Original file content."
    good_hash = compute_file_hash(file_data)

    verify_file_integrity(file_data, good_hash)  # Must not raise

    with pytest.raises(IntegrityError):
        verify_file_integrity(file_data + b"\x00", good_hash)


def test_manifest_signature_fails_if_owner_key_wrong():
    """verify_received_file raises IntegrityError if wrong owner key used."""
    from p2pshare.errors import IntegrityError

    sk_owner, pk_owner = generate_identity_keypair()
    _, pk_wrong = generate_identity_keypair()

    file_data = b"Sensitive document content."
    manifest = create_manifest(sk_owner, pk_owner, "doc.txt", file_data)

    with pytest.raises(IntegrityError):
        verify_received_file(file_data, manifest, public_key_to_bytes(pk_wrong))


def test_manifest_fixture_round_trip():
    """Fixture manifest verifies correctly with the correct owner key."""
    from p2pshare.crypto.keys import bytes_to_public_key

    fx = load_fixture("sample_manifest.json")
    owner_pk_bytes = b64url_decode(fx["owner_public_key"])
    owner_pk = bytes_to_public_key(owner_pk_bytes)
    file_data = b64url_decode(fx["file_data"])

    # Verify manifest owner signature
    verify_manifest(fx["manifest"], owner_pk)

    # Verify file hash
    verify_file_integrity(file_data, fx["manifest"]["sha256"])


def test_relay_preserves_manifest_signature():
    """A relay peer can forward a manifest without invalidating the owner's signature.

    The owner creates and signs a manifest. The relay stores it without re-signing.
    The requester verifies the original owner's signature — relay is untrusted.
    """
    sk_owner, pk_owner = generate_identity_keypair()
    _, pk_relay = generate_identity_keypair()  # relay has its own identity but doesn't re-sign

    file_data = b"File originally created by owner, stored at relay."
    original_manifest = create_manifest(sk_owner, pk_owner, "relayed.txt", file_data)

    # Relay forwards manifest verbatim (no changes, no re-signing)
    relayed_manifest = dict(original_manifest)

    # Requester only knows the owner's public key (from contact book)
    owner_pk_bytes = public_key_to_bytes(pk_owner)
    verify_received_file(file_data, relayed_manifest, owner_pk_bytes)

    # Verify the relay's key does NOT validate the owner's signature
    from p2pshare.errors import IntegrityError
    with pytest.raises(IntegrityError):
        verify_received_file(file_data, relayed_manifest, public_key_to_bytes(pk_relay))


def test_multi_chunk_file_transfer():
    """Files larger than 64KB are split into multiple chunks and reassembled correctly."""
    from p2pshare.protocol.messages import CHUNK_SIZE

    sk_owner, pk_owner = generate_identity_keypair()
    vault_key = os.urandom(32)

    # Create a file larger than one chunk
    file_data = os.urandom(CHUNK_SIZE + 1024)

    with tempfile.TemporaryDirectory() as tmpdir:
        fs = FileStore(tmpdir, vault_key)
        manifest = create_manifest(sk_owner, pk_owner, "large.bin", file_data)
        fs.store_file(manifest["file_id"], file_data, manifest)

        chunks = build_file_chunks(fs, manifest["file_id"], seq_start=0)

        # Last message is TRANSFER_COMPLETE, preceding are TRANSFER_CHUNK
        complete = chunks[-1]
        chunk_msgs = chunks[:-1]

        assert complete["type"] == "TRANSFER_COMPLETE"
        assert len(chunk_msgs) == 2  # ceil((CHUNK_SIZE + 1024) / CHUNK_SIZE) == 2

        assembled = reassemble_file(chunk_msgs)
        assert assembled == file_data
        verify_file_integrity(assembled, complete["sha256"])
