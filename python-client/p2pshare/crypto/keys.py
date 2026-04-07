"""Ed25519 identity key generation, serialization, and loading.

All keys are represented as raw 32-byte values:
- Private key: 32-byte Ed25519 seed
- Public key: 32-byte Ed25519 public key
"""

import secrets
import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)


def generate_identity_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 identity keypair."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def private_key_to_seed(private_key: Ed25519PrivateKey) -> bytes:
    """Extract the 32-byte seed from an Ed25519 private key."""
    raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return raw  # 32 bytes


def seed_to_private_key(seed: bytes) -> Ed25519PrivateKey:
    """Reconstruct an Ed25519 private key from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_to_bytes(public_key: Ed25519PublicKey) -> bytes:
    """Serialize an Ed25519 public key to 32 raw bytes."""
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def bytes_to_public_key(data: bytes) -> Ed25519PublicKey:
    """Deserialize 32 raw bytes into an Ed25519 public key."""
    if len(data) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 bytes")
    return Ed25519PublicKey.from_public_bytes(data)


def b64url_encode(data: bytes) -> str:
    """URL-safe base64 encode without padding (matches Go's RawURLEncoding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """URL-safe base64 decode without padding."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def peer_id_from_public_key(public_key: Ed25519PublicKey) -> str:
    """Compute the peer ID: base64url of the raw 32-byte public key."""
    return b64url_encode(public_key_to_bytes(public_key))


def fingerprint(public_key: Ed25519PublicKey) -> str:
    """Compute a human-readable fingerprint: first 8 hex chars of SHA-256(pubkey)."""
    digest = hashlib.sha256(public_key_to_bytes(public_key)).hexdigest()
    return digest[:8]
