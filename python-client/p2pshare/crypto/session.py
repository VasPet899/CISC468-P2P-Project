"""AES-256-GCM session encryption/decryption with sequence number tracking.

Wire format for encrypted payloads:
    nonce (12 bytes) || ciphertext || tag (16 bytes)

GCM provides both confidentiality and integrity.
"""

import secrets
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from p2pshare.errors import IntegrityError, ProtocolError


NONCE_SIZE = 12
TAG_SIZE = 16
MAX_PAYLOAD_SIZE = 64 * 1024 * 1024  # 64 MB


class SessionCipher:
    """Encrypts/decrypts messages for an established session.

    Tracks send and receive sequence numbers for replay protection.
    """

    def __init__(self, session_key: bytes):
        if len(session_key) != 32:
            raise ValueError("Session key must be 32 bytes")
        self._gcm = AESGCM(session_key)
        self._send_seq = 0
        self._recv_seq = 0

    @property
    def send_seq(self) -> int:
        return self._send_seq

    @property
    def recv_seq(self) -> int:
        return self._recv_seq

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext. Returns nonce || ciphertext || tag."""
        nonce = secrets.token_bytes(NONCE_SIZE)
        ct = self._gcm.encrypt(nonce, plaintext, None)
        self._send_seq += 1
        return nonce + ct

    def decrypt(self, payload: bytes) -> bytes:
        """Decrypt a payload of nonce || ciphertext || tag.

        Raises IntegrityError if the GCM tag verification fails.
        """
        if len(payload) < NONCE_SIZE + TAG_SIZE:
            raise ProtocolError("Encrypted payload too short")
        nonce = payload[:NONCE_SIZE]
        ct = payload[NONCE_SIZE:]
        try:
            plaintext = self._gcm.decrypt(nonce, ct, None)
        except Exception:
            raise IntegrityError(
                "Message integrity check failed — possible tampering or data corruption."
            )
        self._recv_seq += 1
        return plaintext


def encrypt_raw(key: bytes, plaintext: bytes) -> bytes:
    """One-shot AES-256-GCM encryption. Returns nonce || ciphertext || tag."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_raw(key: bytes, payload: bytes) -> bytes:
    """One-shot AES-256-GCM decryption of nonce || ciphertext || tag."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(payload) < NONCE_SIZE + TAG_SIZE:
        raise IntegrityError("Encrypted payload too short")
    nonce = payload[:NONCE_SIZE]
    ct = payload[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        raise IntegrityError(
            "Message integrity check failed — possible tampering or data corruption."
        )
