"""Tests for Ed25519 key generation, serialization, and base64url encoding."""

import pytest
from p2pshare.crypto.keys import (
    generate_identity_keypair,
    private_key_to_seed,
    seed_to_private_key,
    public_key_to_bytes,
    bytes_to_public_key,
    b64url_encode,
    b64url_decode,
    peer_id_from_public_key,
    fingerprint,
)


def test_generate_keypair():
    sk, pk = generate_identity_keypair()
    seed = private_key_to_seed(sk)
    assert len(seed) == 32
    pk_bytes = public_key_to_bytes(pk)
    assert len(pk_bytes) == 32


def test_seed_roundtrip():
    sk, pk = generate_identity_keypair()
    seed = private_key_to_seed(sk)
    sk2 = seed_to_private_key(seed)
    assert private_key_to_seed(sk2) == seed
    assert public_key_to_bytes(sk2.public_key()) == public_key_to_bytes(pk)


def test_public_key_roundtrip():
    _, pk = generate_identity_keypair()
    pk_bytes = public_key_to_bytes(pk)
    pk2 = bytes_to_public_key(pk_bytes)
    assert public_key_to_bytes(pk2) == pk_bytes


def test_invalid_seed_length():
    with pytest.raises(ValueError):
        seed_to_private_key(b"\x00" * 16)


def test_invalid_pubkey_length():
    with pytest.raises(ValueError):
        bytes_to_public_key(b"\x00" * 16)


def test_b64url_roundtrip():
    data = b"\x00\x01\x02\xff\xfe\xfd"
    encoded = b64url_encode(data)
    assert "=" not in encoded  # no padding
    assert "+" not in encoded  # url-safe
    assert "/" not in encoded  # url-safe
    decoded = b64url_decode(encoded)
    assert decoded == data


def test_b64url_various_lengths():
    for length in [0, 1, 2, 3, 4, 31, 32, 33, 64]:
        data = bytes(range(length % 256)) * (length // 256 + 1)
        data = data[:length]
        assert b64url_decode(b64url_encode(data)) == data


def test_peer_id():
    _, pk = generate_identity_keypair()
    pid = peer_id_from_public_key(pk)
    # base64url of 32 bytes = 43 chars (no padding)
    assert len(pid) == 43
    decoded = b64url_decode(pid)
    assert decoded == public_key_to_bytes(pk)


def test_fingerprint():
    _, pk = generate_identity_keypair()
    fp = fingerprint(pk)
    assert len(fp) == 8
    # All hex chars
    assert all(c in "0123456789abcdef" for c in fp)
