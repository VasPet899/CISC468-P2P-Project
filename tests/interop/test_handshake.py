"""Integration test: full 4-step handshake between two in-process peers.

Also serves as the specification for what a Go-Python handshake must achieve:
identical session keys, mutual authentication, replay protection.
"""

import os
import socket
import threading
import tempfile
import pytest

from helpers import load_fixture
from p2pshare.crypto.keys import generate_identity_keypair, public_key_to_bytes, b64url_encode
from p2pshare.crypto.handshake import HandshakeInitiator, HandshakeResponder
from p2pshare.crypto.session import SessionCipher
from p2pshare.network.transport import (
    send_json, recv_json, send_encrypted, recv_encrypted
)
from p2pshare.errors import AuthenticationError, HandshakeError


def run_handshake(initiator_sk, initiator_pk, responder_sk, responder_pk):
    """Run a full in-process handshake. Returns (session_key_i, session_key_r, peer_id_i_at_r, peer_id_r_at_i)."""
    # Create a connected socket pair
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    results = {}
    errors = {}

    def responder_thread():
        try:
            conn, _ = server_sock.accept()
            hs = HandshakeResponder(responder_sk, responder_pk)
            hello = recv_json(conn)
            hs.process_hello(hello)
            hello_ack = hs.create_hello_ack()
            send_json(conn, hello_ack)
            session_key = hs.derive_session()
            # Receive AUTH using a temporary cipher
            tmp_cipher = SessionCipher(session_key)
            auth = recv_encrypted(conn, tmp_cipher)
            hs.verify_auth(auth)
            auth_ack, cipher = hs.create_auth_ack(session_key)
            send_encrypted(conn, cipher, auth_ack)
            results["session_key_r"] = session_key
            results["peer_id_initiator"] = b64url_encode(public_key_to_bytes(hs.peer_identity_pk))
            conn.close()
        except Exception as e:
            errors["responder"] = e
        finally:
            server_sock.close()

    t = threading.Thread(target=responder_thread, daemon=True)
    t.start()

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", port))
    hs_i = HandshakeInitiator(initiator_sk, initiator_pk)
    hello = hs_i.create_hello()
    send_json(client_sock, hello)
    hello_ack = recv_json(client_sock)
    hs_i.process_hello_ack(hello_ack)
    session_key_i = hs_i.derive_session()
    auth, cipher_i = hs_i.create_auth(session_key_i)
    send_encrypted(client_sock, cipher_i, auth)
    auth_ack = recv_encrypted(client_sock, cipher_i)
    hs_i.verify_auth_ack(auth_ack)
    results["session_key_i"] = session_key_i
    results["peer_id_responder"] = b64url_encode(public_key_to_bytes(hs_i.peer_identity_pk))
    client_sock.close()

    t.join(timeout=5)
    if "responder" in errors:
        raise errors["responder"]

    return results


def test_handshake_session_keys_match():
    sk_i, pk_i = generate_identity_keypair()
    sk_r, pk_r = generate_identity_keypair()
    results = run_handshake(sk_i, pk_i, sk_r, pk_r)
    assert results["session_key_i"] == results["session_key_r"]
    assert len(results["session_key_i"]) == 32


def test_handshake_mutual_peer_id_exchange():
    sk_i, pk_i = generate_identity_keypair()
    sk_r, pk_r = generate_identity_keypair()
    results = run_handshake(sk_i, pk_i, sk_r, pk_r)
    # Each side correctly learned the other's peer_id
    assert results["peer_id_initiator"] == b64url_encode(public_key_to_bytes(pk_i))
    assert results["peer_id_responder"] == b64url_encode(public_key_to_bytes(pk_r))


def test_handshake_each_produces_unique_session_key():
    """Two separate handshakes between the same peers produce different session keys (PFS)."""
    sk_i, pk_i = generate_identity_keypair()
    sk_r, pk_r = generate_identity_keypair()
    r1 = run_handshake(sk_i, pk_i, sk_r, pk_r)
    r2 = run_handshake(sk_i, pk_i, sk_r, pk_r)
    assert r1["session_key_i"] != r2["session_key_i"]


def test_handshake_encrypted_message_exchange():
    """After handshake, messages can be sent encrypted in both directions."""
    sk_i, pk_i = generate_identity_keypair()
    sk_r, pk_r = generate_identity_keypair()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    errors = {}
    received_by_responder = {}

    def responder_thread():
        try:
            conn, _ = server_sock.accept()
            hs = HandshakeResponder(sk_r, pk_r)
            hello = recv_json(conn)
            hs.process_hello(hello)
            send_json(conn, hs.create_hello_ack())
            sk = hs.derive_session()
            tmp = SessionCipher(sk)
            hs.verify_auth(recv_encrypted(conn, tmp))
            auth_ack, cipher = hs.create_auth_ack(sk)
            send_encrypted(conn, cipher, auth_ack)
            # Receive a post-handshake message
            msg = recv_encrypted(conn, cipher)
            received_by_responder["msg"] = msg
            # Send a reply
            send_encrypted(conn, cipher, {"type": "REPLY", "echo": msg["data"]})
            conn.close()
        except Exception as e:
            errors["r"] = e
        finally:
            server_sock.close()

    t = threading.Thread(target=responder_thread, daemon=True)
    t.start()

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", port))
    hs_i = HandshakeInitiator(sk_i, pk_i)
    send_json(client_sock, hs_i.create_hello())
    hs_i.process_hello_ack(recv_json(client_sock))
    sk = hs_i.derive_session()
    auth, cipher_i = hs_i.create_auth(sk)
    send_encrypted(client_sock, cipher_i, auth)
    hs_i.verify_auth_ack(recv_encrypted(client_sock, cipher_i))

    # Send a message
    send_encrypted(client_sock, cipher_i, {"type": "PING", "data": "hello"})
    reply = recv_encrypted(client_sock, cipher_i)
    client_sock.close()
    t.join(timeout=5)

    assert "r" not in errors, f"Responder error: {errors['r']}"
    assert received_by_responder["msg"]["data"] == "hello"
    assert reply["echo"] == "hello"


def test_handshake_tampered_auth_rejected():
    """Tampered AUTH signature causes authentication failure."""
    sk_i, pk_i = generate_identity_keypair()
    sk_r, pk_r = generate_identity_keypair()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    responder_error = {}

    def responder_thread():
        try:
            conn, _ = server_sock.accept()
            hs = HandshakeResponder(sk_r, pk_r)
            hs.process_hello(recv_json(conn))
            send_json(conn, hs.create_hello_ack())
            sk = hs.derive_session()
            tmp = SessionCipher(sk)
            auth = recv_encrypted(conn, tmp)
            auth["signature"] = b64url_encode(bytes(64))  # bad sig
            hs.verify_auth(auth)  # Should raise
            conn.close()
        except AuthenticationError as e:
            responder_error["err"] = str(e)
        except Exception as e:
            responder_error["err"] = str(e)
        finally:
            server_sock.close()

    t = threading.Thread(target=responder_thread, daemon=True)
    t.start()

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", port))
    hs_i = HandshakeInitiator(sk_i, pk_i)
    send_json(client_sock, hs_i.create_hello())
    hs_i.process_hello_ack(recv_json(client_sock))
    sk = hs_i.derive_session()
    auth, cipher_i = hs_i.create_auth(sk)
    send_encrypted(client_sock, cipher_i, auth)
    client_sock.close()
    t.join(timeout=5)

    assert "err" in responder_error, "Responder should have caught an authentication error"
