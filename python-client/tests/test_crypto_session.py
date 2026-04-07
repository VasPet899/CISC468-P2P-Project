"""Tests for AES-256-GCM session encryption/decryption."""

import os
import pytest
from p2pshare.crypto.session import (
    SessionCipher,
    encrypt_raw,
    decrypt_raw,
    NONCE_SIZE,
    TAG_SIZE,
)
from p2pshare.errors import IntegrityError, ProtocolError


def test_session_cipher_roundtrip():
    key = os.urandom(32)
    cipher = SessionCipher(key)
    plaintext = b"Hello, encrypted world!"
    encrypted = cipher.encrypt(plaintext)
    assert encrypted != plaintext
    assert len(encrypted) == NONCE_SIZE + len(plaintext) + TAG_SIZE

    cipher2 = SessionCipher(key)
    decrypted = cipher2.decrypt(encrypted)
    assert decrypted == plaintext


def test_session_cipher_seq_tracking():
    key = os.urandom(32)
    cipher = SessionCipher(key)
    assert cipher.send_seq == 0
    cipher.encrypt(b"msg1")
    assert cipher.send_seq == 1
    cipher.encrypt(b"msg2")
    assert cipher.send_seq == 2


def test_session_cipher_wrong_key():
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    cipher1 = SessionCipher(key1)
    encrypted = cipher1.encrypt(b"secret")
    cipher2 = SessionCipher(key2)
    with pytest.raises(IntegrityError):
        cipher2.decrypt(encrypted)


def test_session_cipher_tampered():
    key = os.urandom(32)
    cipher = SessionCipher(key)
    encrypted = bytearray(cipher.encrypt(b"important data"))
    encrypted[-1] ^= 0xFF  # Flip last byte (in the tag)
    cipher2 = SessionCipher(key)
    with pytest.raises(IntegrityError):
        cipher2.decrypt(bytes(encrypted))


def test_session_cipher_too_short():
    key = os.urandom(32)
    cipher = SessionCipher(key)
    with pytest.raises((IntegrityError, ProtocolError)):
        cipher.decrypt(b"\x00" * 10)


def test_encrypt_raw_roundtrip():
    key = os.urandom(32)
    plaintext = b"raw encryption test"
    encrypted = encrypt_raw(key, plaintext)
    decrypted = decrypt_raw(key, encrypted)
    assert decrypted == plaintext


def test_encrypt_raw_wrong_key():
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    encrypted = encrypt_raw(key1, b"data")
    with pytest.raises(IntegrityError):
        decrypt_raw(key2, encrypted)


def test_encrypt_raw_invalid_key_length():
    with pytest.raises(ValueError):
        encrypt_raw(b"short", b"data")


def test_empty_plaintext():
    key = os.urandom(32)
    encrypted = encrypt_raw(key, b"")
    decrypted = decrypt_raw(key, encrypted)
    assert decrypted == b""


def test_large_plaintext():
    key = os.urandom(32)
    plaintext = os.urandom(1024 * 1024)  # 1 MB
    encrypted = encrypt_raw(key, plaintext)
    decrypted = decrypt_raw(key, encrypted)
    assert decrypted == plaintext
