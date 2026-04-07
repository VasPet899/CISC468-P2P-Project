"""X25519 ephemeral key exchange and HKDF session key derivation.

Implements the 4-step handshake protocol:
  1. HELLO        (plaintext, initiator → responder)
  2. HELLO_ACK    (plaintext, responder → initiator)
  3. AUTH          (encrypted, initiator → responder)
  4. AUTH_ACK      (encrypted, responder → initiator)

Session key derivation:
  shared_secret = X25519(my_ephemeral_sk, peer_ephemeral_pk)
  hkdf_salt     = SHA256(nonce_initiator || nonce_responder)
  session_key   = HKDF-SHA256(ikm=shared_secret, salt=hkdf_salt,
                              info="p2pshare-session-v1", len=32)
"""

import secrets
import hashlib
import json
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

from p2pshare.crypto.keys import (
    public_key_to_bytes,
    b64url_encode,
    b64url_decode,
    peer_id_from_public_key,
)
from p2pshare.crypto.signing import canonical_json, sign, verify
from p2pshare.crypto.session import SessionCipher
from p2pshare.errors import HandshakeError, AuthenticationError


SESSION_KEY_INFO = b"p2pshare-session-v1"
AUTH_CONTEXT = "CISC468-AUTH-v1"
NONCE_SIZE = 32


def generate_ephemeral_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate an ephemeral X25519 keypair for one session."""
    sk = X25519PrivateKey.generate()
    return sk, sk.public_key()


def x25519_public_key_to_bytes(pk: X25519PublicKey) -> bytes:
    """Serialize X25519 public key to 32 raw bytes."""
    return pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def x25519_public_key_from_bytes(data: bytes) -> X25519PublicKey:
    """Deserialize 32 raw bytes into an X25519 public key."""
    return X25519PublicKey.from_public_bytes(data)


def derive_session_key(
    shared_secret: bytes, nonce_initiator: bytes, nonce_responder: bytes
) -> bytes:
    """Derive 32-byte session key via HKDF-SHA256.

    salt = SHA256(nonce_initiator || nonce_responder)
    """
    salt = hashlib.sha256(nonce_initiator + nonce_responder).digest()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=SESSION_KEY_INFO,
    )
    return hkdf.derive(shared_secret)


def compute_shared_secret(my_sk: X25519PrivateKey, peer_pk: X25519PublicKey) -> bytes:
    """Perform X25519 Diffie-Hellman key exchange. Returns 32-byte shared secret."""
    shared = my_sk.exchange(peer_pk)
    if shared == b"\x00" * 32:
        raise HandshakeError("Key exchange failed — invalid peer public key.")
    return shared


def build_auth_transcript(
    signer_id_pk: bytes,
    verifier_id_pk: bytes,
    signer_eph_pk: bytes,
    verifier_eph_pk: bytes,
    signer_nonce: bytes,
    verifier_nonce: bytes,
) -> bytes:
    """Build the canonical JSON bytes for the AUTH signature.

    The transcript is a canonical JSON object with sorted keys.
    """
    transcript = {
        "context": AUTH_CONTEXT,
        "eph_pk_signer": b64url_encode(signer_eph_pk),
        "eph_pk_verifier": b64url_encode(verifier_eph_pk),
        "id_pk_signer": b64url_encode(signer_id_pk),
        "id_pk_verifier": b64url_encode(verifier_id_pk),
        "nonce_signer": b64url_encode(signer_nonce),
        "nonce_verifier": b64url_encode(verifier_nonce),
    }
    return canonical_json(transcript)


def build_hello(
    ephemeral_pk: X25519PublicKey, identity_pk: Ed25519PublicKey
) -> tuple[dict, bytes]:
    """Build a HELLO message. Returns (message_dict, nonce_bytes)."""
    nonce = secrets.token_bytes(NONCE_SIZE)
    msg = {
        "type": "HELLO",
        "version": "1",
        "ephemeral_pk": b64url_encode(x25519_public_key_to_bytes(ephemeral_pk)),
        "peer_id": peer_id_from_public_key(identity_pk),
        "timestamp": int(time.time() * 1000),
        "nonce": b64url_encode(nonce),
    }
    return msg, nonce


def build_hello_ack(
    ephemeral_pk: X25519PublicKey,
    identity_pk: Ed25519PublicKey,
    hello_nonce_b64: str,
) -> tuple[dict, bytes]:
    """Build a HELLO_ACK message. Returns (message_dict, nonce_bytes)."""
    nonce = secrets.token_bytes(NONCE_SIZE)
    msg = {
        "type": "HELLO_ACK",
        "version": "1",
        "ephemeral_pk": b64url_encode(x25519_public_key_to_bytes(ephemeral_pk)),
        "peer_id": peer_id_from_public_key(identity_pk),
        "timestamp": int(time.time() * 1000),
        "nonce": b64url_encode(nonce),
        "hello_nonce": hello_nonce_b64,
    }
    return msg, nonce


def build_auth(
    identity_sk: Ed25519PrivateKey,
    identity_pk: Ed25519PublicKey,
    peer_identity_pk: Ed25519PublicKey,
    my_eph_pk: X25519PublicKey,
    peer_eph_pk: X25519PublicKey,
    my_nonce: bytes,
    peer_nonce: bytes,
    seq: int,
) -> dict:
    """Build an AUTH message with Ed25519 signature over the transcript."""
    my_id_bytes = public_key_to_bytes(identity_pk)
    peer_id_bytes = public_key_to_bytes(peer_identity_pk)
    my_eph_bytes = x25519_public_key_to_bytes(my_eph_pk)
    peer_eph_bytes = x25519_public_key_to_bytes(peer_eph_pk)

    transcript = build_auth_transcript(
        signer_id_pk=my_id_bytes,
        verifier_id_pk=peer_id_bytes,
        signer_eph_pk=my_eph_bytes,
        verifier_eph_pk=peer_eph_bytes,
        signer_nonce=my_nonce,
        verifier_nonce=peer_nonce,
    )
    sig = sign(identity_sk, transcript)

    return {
        "type": "AUTH",
        "version": "1",
        "seq": seq,
        "timestamp": int(time.time() * 1000),
        "peer_id": b64url_encode(my_id_bytes),
        "signature": b64url_encode(sig),
    }


def verify_auth(
    msg: dict,
    peer_identity_pk: Ed25519PublicKey,
    my_identity_pk: Ed25519PublicKey,
    peer_eph_pk: X25519PublicKey,
    my_eph_pk: X25519PublicKey,
    peer_nonce: bytes,
    my_nonce: bytes,
) -> None:
    """Verify an AUTH or AUTH_ACK message signature.

    Raises AuthenticationError if the signature is invalid.
    """
    peer_id_bytes = public_key_to_bytes(peer_identity_pk)
    my_id_bytes = public_key_to_bytes(my_identity_pk)
    peer_eph_bytes = x25519_public_key_to_bytes(peer_eph_pk)
    my_eph_bytes = x25519_public_key_to_bytes(my_eph_pk)

    transcript = build_auth_transcript(
        signer_id_pk=peer_id_bytes,
        verifier_id_pk=my_id_bytes,
        signer_eph_pk=peer_eph_bytes,
        verifier_eph_pk=my_eph_bytes,
        signer_nonce=peer_nonce,
        verifier_nonce=my_nonce,
    )

    sig = b64url_decode(msg["signature"])
    try:
        verify(peer_identity_pk, transcript, sig)
    except Exception:
        raise AuthenticationError(
            "Peer identity verification failed. The peer may be impersonating someone."
        )


class HandshakeInitiator:
    """Drives the initiator side of the 4-step handshake."""

    def __init__(self, identity_sk: Ed25519PrivateKey, identity_pk: Ed25519PublicKey):
        self.identity_sk = identity_sk
        self.identity_pk = identity_pk
        self.eph_sk, self.eph_pk = generate_ephemeral_keypair()
        self.my_nonce: bytes = b""
        self.peer_nonce: bytes = b""
        self.peer_eph_pk: X25519PublicKey | None = None
        self.peer_identity_pk: Ed25519PublicKey | None = None

    def create_hello(self) -> dict:
        """Step 1: create HELLO message."""
        msg, self.my_nonce = build_hello(self.eph_pk, self.identity_pk)
        return msg

    def process_hello_ack(self, msg: dict) -> None:
        """Step 2: process received HELLO_ACK."""
        if msg.get("type") != "HELLO_ACK":
            raise HandshakeError("Expected HELLO_ACK")
        if msg.get("hello_nonce") != b64url_encode(self.my_nonce):
            raise HandshakeError("HELLO_ACK nonce mismatch — possible replay")
        self.peer_nonce = b64url_decode(msg["nonce"])
        self.peer_eph_pk = x25519_public_key_from_bytes(
            b64url_decode(msg["ephemeral_pk"])
        )
        from p2pshare.crypto.keys import bytes_to_public_key
        self.peer_identity_pk = bytes_to_public_key(b64url_decode(msg["peer_id"]))

    def derive_session(self) -> bytes:
        """Derive the session key after HELLO_ACK is processed."""
        shared = compute_shared_secret(self.eph_sk, self.peer_eph_pk)
        return derive_session_key(shared, self.my_nonce, self.peer_nonce)

    def create_auth(self, session_key: bytes) -> tuple[dict, SessionCipher]:
        """Step 3: create encrypted AUTH message. Returns (auth_dict, cipher)."""
        cipher = SessionCipher(session_key)
        auth = build_auth(
            self.identity_sk,
            self.identity_pk,
            self.peer_identity_pk,
            self.eph_pk,
            self.peer_eph_pk,
            self.my_nonce,
            self.peer_nonce,
            seq=1,
        )
        return auth, cipher

    def verify_auth_ack(self, msg: dict) -> None:
        """Step 4: verify the received AUTH_ACK."""
        verify_auth(
            msg,
            self.peer_identity_pk,
            self.identity_pk,
            self.peer_eph_pk,
            self.eph_pk,
            self.peer_nonce,
            self.my_nonce,
        )


class HandshakeResponder:
    """Drives the responder side of the 4-step handshake."""

    def __init__(self, identity_sk: Ed25519PrivateKey, identity_pk: Ed25519PublicKey):
        self.identity_sk = identity_sk
        self.identity_pk = identity_pk
        self.eph_sk, self.eph_pk = generate_ephemeral_keypair()
        self.my_nonce: bytes = b""
        self.peer_nonce: bytes = b""
        self.peer_eph_pk: X25519PublicKey | None = None
        self.peer_identity_pk: Ed25519PublicKey | None = None

    def process_hello(self, msg: dict) -> None:
        """Step 1: process received HELLO."""
        if msg.get("type") != "HELLO":
            raise HandshakeError("Expected HELLO")
        self.peer_nonce = b64url_decode(msg["nonce"])
        self.peer_eph_pk = x25519_public_key_from_bytes(
            b64url_decode(msg["ephemeral_pk"])
        )
        from p2pshare.crypto.keys import bytes_to_public_key
        self.peer_identity_pk = bytes_to_public_key(b64url_decode(msg["peer_id"]))

    def create_hello_ack(self) -> dict:
        """Step 2: create HELLO_ACK message."""
        msg, self.my_nonce = build_hello_ack(
            self.eph_pk,
            self.identity_pk,
            b64url_encode(self.peer_nonce),
        )
        return msg

    def derive_session(self) -> bytes:
        """Derive the session key after HELLO is processed."""
        shared = compute_shared_secret(self.eph_sk, self.peer_eph_pk)
        # Initiator nonce is the peer's nonce (they sent HELLO first)
        return derive_session_key(shared, self.peer_nonce, self.my_nonce)

    def verify_auth(self, msg: dict) -> None:
        """Step 3: verify the received AUTH."""
        verify_auth(
            msg,
            self.peer_identity_pk,
            self.identity_pk,
            self.peer_eph_pk,
            self.eph_pk,
            self.peer_nonce,
            self.my_nonce,
        )

    def create_auth_ack(self, session_key: bytes) -> tuple[dict, SessionCipher]:
        """Step 4: create encrypted AUTH_ACK. Returns (auth_ack_dict, cipher)."""
        cipher = SessionCipher(session_key)
        auth_ack = build_auth(
            self.identity_sk,
            self.identity_pk,
            self.peer_identity_pk,
            self.eph_pk,
            self.peer_eph_pk,
            self.my_nonce,
            self.peer_nonce,
            seq=2,
        )
        auth_ack["type"] = "AUTH_ACK"
        return auth_ack, cipher
