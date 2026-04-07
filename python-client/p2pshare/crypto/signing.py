"""Ed25519 signing/verification and canonical JSON serialization.

Canonical JSON rules (must match Go implementation exactly):
- Keys sorted lexicographically
- No whitespace (separators=(',', ':'))
- UTF-8 encoded
"""

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from p2pshare.errors import IntegrityError


def canonical_json(obj: dict) -> bytes:
    """Serialize a dict to canonical JSON bytes.

    Rules: sorted keys, no whitespace, UTF-8 encoding.
    This must produce byte-identical output to the Go canonicalJSON() function.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign a message with Ed25519. Returns 64-byte signature."""
    return private_key.sign(message)


def verify(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> None:
    """Verify an Ed25519 signature. Raises IntegrityError on failure."""
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        raise IntegrityError("Ed25519 signature verification failed")


def sign_dict(private_key: Ed25519PrivateKey, obj: dict) -> bytes:
    """Sign the canonical JSON encoding of a dict."""
    return sign(private_key, canonical_json(obj))


def verify_dict(public_key: Ed25519PublicKey, obj: dict, signature: bytes) -> None:
    """Verify a signature over the canonical JSON encoding of a dict."""
    verify(public_key, canonical_json(obj), signature)
