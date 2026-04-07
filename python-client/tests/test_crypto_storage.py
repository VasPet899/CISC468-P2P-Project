"""Tests for Argon2id KDF and vault encryption."""

import pytest
from p2pshare.crypto.storage import (
    derive_vault_key,
    generate_salt,
    encrypt_vault,
    decrypt_vault,
)
from p2pshare.errors import IntegrityError


def test_derive_vault_key_deterministic():
    salt = b"\x00" * 16
    key1 = derive_vault_key("password123", salt)
    key2 = derive_vault_key("password123", salt)
    assert key1 == key2
    assert len(key1) == 32


def test_derive_vault_key_different_passwords():
    salt = b"\x00" * 16
    key1 = derive_vault_key("password1", salt)
    key2 = derive_vault_key("password2", salt)
    assert key1 != key2


def test_derive_vault_key_different_salts():
    key1 = derive_vault_key("password", b"\x00" * 16)
    key2 = derive_vault_key("password", b"\x01" * 16)
    assert key1 != key2


def test_generate_salt():
    salt1 = generate_salt()
    salt2 = generate_salt()
    assert len(salt1) == 16
    assert len(salt2) == 16
    assert salt1 != salt2  # Overwhelmingly likely


def test_vault_encrypt_decrypt():
    key = derive_vault_key("test", generate_salt())
    plaintext = b'{"identity": "test_data"}'
    encrypted = encrypt_vault(key, plaintext)
    decrypted = decrypt_vault(key, encrypted)
    assert decrypted == plaintext


def test_vault_wrong_password():
    salt = generate_salt()
    key1 = derive_vault_key("correct", salt)
    key2 = derive_vault_key("wrong", salt)
    encrypted = encrypt_vault(key1, b"secret data")
    with pytest.raises(IntegrityError):
        decrypt_vault(key2, encrypted)
