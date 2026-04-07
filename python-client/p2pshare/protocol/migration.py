"""Key migration protocol — create, send, receive, apply.

Migration requires dual signatures:
- old_signature: Ed25519_Sign(old_sk, migration_canonical)
- new_signature: Ed25519_Sign(new_sk, migration_canonical)
"""

import time

from p2pshare.crypto.keys import (
    generate_identity_keypair,
    public_key_to_bytes,
    bytes_to_public_key,
    b64url_encode,
    b64url_decode,
    peer_id_from_public_key,
)
from p2pshare.crypto.signing import canonical_json, sign, verify
from p2pshare.errors import MigrationError
from p2pshare.protocol.messages import key_migration

# Default expiry: 30 days
MIGRATION_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000


def create_migration(old_sk, old_pk, new_sk, new_pk, reason: str = "scheduled_rotation") -> dict:
    """Create a KEY_MIGRATION announcement signed by both old and new keys.

    Returns the full migration message dict.
    """
    now = int(time.time() * 1000)
    old_peer_id = peer_id_from_public_key(old_pk)
    new_peer_id = peer_id_from_public_key(new_pk)

    canonical_fields = {
        "effective_timestamp": now,
        "expiry_timestamp": now + MIGRATION_EXPIRY_MS,
        "new_peer_id": new_peer_id,
        "old_peer_id": old_peer_id,
        "reason": reason,
    }
    canonical_bytes = canonical_json(canonical_fields)

    old_sig = sign(old_sk, canonical_bytes)
    new_sig = sign(new_sk, canonical_bytes)

    return key_migration(
        seq=0,
        old_peer_id=old_peer_id,
        new_peer_id=new_peer_id,
        effective_ts=now,
        expiry_ts=now + MIGRATION_EXPIRY_MS,
        reason=reason,
        old_signature=b64url_encode(old_sig),
        new_signature=b64url_encode(new_sig),
    )


def verify_migration(msg: dict, known_old_pk_bytes: bytes) -> bytes:
    """Verify a KEY_MIGRATION announcement.

    Args:
        msg: The migration message dict.
        known_old_pk_bytes: The 32-byte public key we currently have for this contact.

    Returns:
        The new public key bytes (32 bytes) if valid.

    Raises:
        MigrationError if any check fails.
    """
    now = int(time.time() * 1000)

    # Check timestamps
    effective = msg.get("effective_timestamp", 0)
    expiry = msg.get("expiry_timestamp", 0)
    if effective > now + 5000:  # 5 second grace for clock skew
        raise MigrationError("Key migration announcement not yet effective.")
    if expiry <= now:
        raise MigrationError("Key migration announcement has expired.")

    # Check reason is known
    reason = msg.get("reason", "")
    if reason not in ("scheduled_rotation", "compromise", "other"):
        raise MigrationError(f"Unknown migration reason: {reason}")

    # Build canonical bytes
    canonical_fields = {
        "effective_timestamp": effective,
        "expiry_timestamp": expiry,
        "new_peer_id": msg["new_peer_id"],
        "old_peer_id": msg["old_peer_id"],
        "reason": reason,
    }
    canonical_bytes = canonical_json(canonical_fields)

    # Verify old signature
    old_pk = bytes_to_public_key(known_old_pk_bytes)
    old_sig = b64url_decode(msg["old_signature"])
    try:
        verify(old_pk, canonical_bytes, old_sig)
    except Exception:
        raise MigrationError("Key migration announcement is invalid — old signature check failed.")

    # Verify new signature
    new_pk_bytes = b64url_decode(msg["new_peer_id"])
    new_pk = bytes_to_public_key(new_pk_bytes)
    new_sig = b64url_decode(msg["new_signature"])
    try:
        verify(new_pk, canonical_bytes, new_sig)
    except Exception:
        raise MigrationError("Key migration announcement is invalid — new signature check failed.")

    return new_pk_bytes
