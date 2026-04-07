"""Argon2id password KDF and vault-level encryption helpers.

Vault key derivation:
  vault_key = Argon2id(password, salt, time=3, memory=65536, parallelism=4, keylen=32)

Vault encryption uses AES-256-GCM (via session.encrypt_raw / decrypt_raw).
"""

import secrets
from argon2.low_level import hash_secret_raw, Type

from p2pshare.crypto.session import encrypt_raw, decrypt_raw

# Argon2id parameters — must match Go implementation exactly
ARGON2_TIME = 3
ARGON2_MEMORY = 65536  # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_KEYLEN = 32
ARGON2_SALT_LEN = 16


def derive_vault_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte vault key from a password using Argon2id."""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_KEYLEN,
        type=Type.ID,
    )


def generate_salt() -> bytes:
    """Generate a random 16-byte salt for Argon2id."""
    return secrets.token_bytes(ARGON2_SALT_LEN)


def encrypt_vault(vault_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt vault plaintext with AES-256-GCM. Returns nonce || ct || tag."""
    return encrypt_raw(vault_key, plaintext)


def decrypt_vault(vault_key: bytes, payload: bytes) -> bytes:
    """Decrypt vault payload. Raises IntegrityError on wrong password / corruption."""
    return decrypt_raw(vault_key, payload)
