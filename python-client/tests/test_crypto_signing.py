"""Tests for Ed25519 signing/verification and canonical JSON."""

import pytest
from p2pshare.crypto.keys import generate_identity_keypair
from p2pshare.crypto.signing import (
    canonical_json,
    sign,
    verify,
    sign_dict,
    verify_dict,
)
from p2pshare.errors import IntegrityError


def test_canonical_json_sorted_keys():
    obj = {"z": 1, "a": 2, "m": 3}
    result = canonical_json(obj)
    assert result == b'{"a":2,"m":3,"z":1}'


def test_canonical_json_no_whitespace():
    obj = {"key": "value", "list": [1, 2, 3]}
    result = canonical_json(obj)
    assert b" " not in result
    assert b"\n" not in result


def test_canonical_json_nested():
    obj = {"outer": {"z": 1, "a": 2}, "b": "val"}
    result = canonical_json(obj)
    assert result == b'{"b":"val","outer":{"a":2,"z":1}}'


def test_canonical_json_null():
    obj = {"a": None, "b": 1}
    result = canonical_json(obj)
    assert result == b'{"a":null,"b":1}'


def test_sign_verify():
    sk, pk = generate_identity_keypair()
    msg = b"hello world"
    sig = sign(sk, msg)
    assert len(sig) == 64
    verify(pk, msg, sig)  # Should not raise


def test_verify_wrong_message():
    sk, pk = generate_identity_keypair()
    sig = sign(sk, b"hello")
    with pytest.raises(IntegrityError):
        verify(pk, b"different message", sig)


def test_verify_wrong_key():
    sk1, pk1 = generate_identity_keypair()
    _, pk2 = generate_identity_keypair()
    sig = sign(sk1, b"test")
    with pytest.raises(IntegrityError):
        verify(pk2, b"test", sig)


def test_sign_dict_verify_dict():
    sk, pk = generate_identity_keypair()
    obj = {"action": "test", "value": 42}
    sig = sign_dict(sk, obj)
    verify_dict(pk, obj, sig)  # Should not raise


def test_verify_dict_tampered():
    sk, pk = generate_identity_keypair()
    obj = {"action": "test", "value": 42}
    sig = sign_dict(sk, obj)
    obj["value"] = 43
    with pytest.raises(IntegrityError):
        verify_dict(pk, obj, sig)
