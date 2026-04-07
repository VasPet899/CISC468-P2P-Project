"""Tests for the 4-step handshake protocol."""

import pytest
from p2pshare.crypto.keys import generate_identity_keypair, public_key_to_bytes, b64url_encode
from p2pshare.crypto.handshake import (
    HandshakeInitiator,
    HandshakeResponder,
    generate_ephemeral_keypair,
    compute_shared_secret,
    derive_session_key,
    x25519_public_key_to_bytes,
    build_auth_transcript,
)
from p2pshare.errors import HandshakeError, AuthenticationError


def test_full_handshake():
    """Test the complete 4-step handshake between initiator and responder."""
    sk_i, pk_i = generate_identity_keypair()
    sk_r, pk_r = generate_identity_keypair()

    initiator = HandshakeInitiator(sk_i, pk_i)
    responder = HandshakeResponder(sk_r, pk_r)

    # Step 1: Initiator creates HELLO
    hello = initiator.create_hello()
    assert hello["type"] == "HELLO"
    assert hello["version"] == "1"

    # Step 1: Responder processes HELLO
    responder.process_hello(hello)

    # Step 2: Responder creates HELLO_ACK
    hello_ack = responder.create_hello_ack()
    assert hello_ack["type"] == "HELLO_ACK"
    assert hello_ack["hello_nonce"] == hello["nonce"]

    # Step 2: Initiator processes HELLO_ACK
    initiator.process_hello_ack(hello_ack)

    # Both derive session key — must be identical
    session_key_i = initiator.derive_session()
    session_key_r = responder.derive_session()
    assert session_key_i == session_key_r
    assert len(session_key_i) == 32

    # Step 3: Initiator creates AUTH
    auth, cipher_i = initiator.create_auth(session_key_i)
    assert auth["type"] == "AUTH"

    # Step 3: Responder verifies AUTH
    responder.verify_auth(auth)  # Should not raise

    # Step 4: Responder creates AUTH_ACK
    auth_ack, cipher_r = responder.create_auth_ack(session_key_r)
    assert auth_ack["type"] == "AUTH_ACK"

    # Step 4: Initiator verifies AUTH_ACK
    initiator.verify_auth_ack(auth_ack)  # Should not raise


def test_handshake_different_session_keys():
    """Each handshake produces a different session key (ephemeral keys differ)."""
    sk_i, pk_i = generate_identity_keypair()
    sk_r, pk_r = generate_identity_keypair()

    keys = []
    for _ in range(3):
        init = HandshakeInitiator(sk_i, pk_i)
        resp = HandshakeResponder(sk_r, pk_r)
        hello = init.create_hello()
        resp.process_hello(hello)
        hello_ack = resp.create_hello_ack()
        init.process_hello_ack(hello_ack)
        keys.append(init.derive_session())

    # All keys should be different (PFS)
    assert keys[0] != keys[1]
    assert keys[1] != keys[2]


def test_handshake_wrong_hello_nonce():
    """HELLO_ACK with mismatched nonce should be rejected."""
    sk_i, pk_i = generate_identity_keypair()
    sk_r, pk_r = generate_identity_keypair()

    initiator = HandshakeInitiator(sk_i, pk_i)
    responder = HandshakeResponder(sk_r, pk_r)

    hello = initiator.create_hello()
    responder.process_hello(hello)
    hello_ack = responder.create_hello_ack()
    hello_ack["hello_nonce"] = b64url_encode(b"\x00" * 32)  # Wrong nonce

    with pytest.raises(HandshakeError):
        initiator.process_hello_ack(hello_ack)


def test_auth_wrong_signature():
    """AUTH with an invalid signature should be rejected."""
    sk_i, pk_i = generate_identity_keypair()
    sk_r, pk_r = generate_identity_keypair()
    sk_attacker, _ = generate_identity_keypair()

    # Set up a legitimate handshake
    initiator = HandshakeInitiator(sk_i, pk_i)
    responder = HandshakeResponder(sk_r, pk_r)

    hello = initiator.create_hello()
    responder.process_hello(hello)
    hello_ack = responder.create_hello_ack()
    initiator.process_hello_ack(hello_ack)

    session_key = initiator.derive_session()
    auth, _ = initiator.create_auth(session_key)

    # Tamper with signature
    auth["signature"] = b64url_encode(b"\x00" * 64)

    with pytest.raises(AuthenticationError):
        responder.verify_auth(auth)


def test_ephemeral_key_exchange():
    """X25519 shared secret is identical on both sides."""
    eph_sk_a, eph_pk_a = generate_ephemeral_keypair()
    eph_sk_b, eph_pk_b = generate_ephemeral_keypair()

    shared_a = compute_shared_secret(eph_sk_a, eph_pk_b)
    shared_b = compute_shared_secret(eph_sk_b, eph_pk_a)
    assert shared_a == shared_b
    assert len(shared_a) == 32


def test_session_key_derivation_deterministic():
    """Same inputs produce the same session key."""
    shared = b"\xab" * 32
    nonce_i = b"\x01" * 32
    nonce_r = b"\x02" * 32

    key1 = derive_session_key(shared, nonce_i, nonce_r)
    key2 = derive_session_key(shared, nonce_i, nonce_r)
    assert key1 == key2


def test_session_key_derivation_different_nonces():
    """Different nonces produce different session keys."""
    shared = b"\xab" * 32
    key1 = derive_session_key(shared, b"\x01" * 32, b"\x02" * 32)
    key2 = derive_session_key(shared, b"\x03" * 32, b"\x04" * 32)
    assert key1 != key2
