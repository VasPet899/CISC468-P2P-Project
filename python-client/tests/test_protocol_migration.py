"""Tests for key migration creation and verification."""

import time
import pytest

from p2pshare.crypto.keys import (
    generate_identity_keypair,
    public_key_to_bytes,
    b64url_encode,
    b64url_decode,
)
from p2pshare.protocol.migration import (
    create_migration,
    verify_migration,
    MIGRATION_EXPIRY_MS,
)
from p2pshare.errors import MigrationError


def test_create_migration():
    old_sk, old_pk = generate_identity_keypair()
    new_sk, new_pk = generate_identity_keypair()
    msg = create_migration(old_sk, old_pk, new_sk, new_pk, "scheduled_rotation")
    assert msg["type"] == "KEY_MIGRATION"
    assert "old_signature" in msg
    assert "new_signature" in msg
    assert msg["reason"] == "scheduled_rotation"


def test_verify_migration_valid():
    old_sk, old_pk = generate_identity_keypair()
    new_sk, new_pk = generate_identity_keypair()
    msg = create_migration(old_sk, old_pk, new_sk, new_pk)

    old_pk_bytes = public_key_to_bytes(old_pk)
    new_pk_bytes = verify_migration(msg, old_pk_bytes)
    assert new_pk_bytes == public_key_to_bytes(new_pk)


def test_verify_migration_wrong_old_key():
    old_sk, old_pk = generate_identity_keypair()
    new_sk, new_pk = generate_identity_keypair()
    _, wrong_pk = generate_identity_keypair()

    msg = create_migration(old_sk, old_pk, new_sk, new_pk)
    with pytest.raises(MigrationError, match="old signature"):
        verify_migration(msg, public_key_to_bytes(wrong_pk))


def test_verify_migration_tampered_new_peer_id():
    old_sk, old_pk = generate_identity_keypair()
    new_sk, new_pk = generate_identity_keypair()
    msg = create_migration(old_sk, old_pk, new_sk, new_pk)

    # Replace new_peer_id with a different key
    _, fake_pk = generate_identity_keypair()
    msg["new_peer_id"] = b64url_encode(public_key_to_bytes(fake_pk))

    old_pk_bytes = public_key_to_bytes(old_pk)
    with pytest.raises(MigrationError):
        verify_migration(msg, old_pk_bytes)


def test_verify_migration_expired():
    old_sk, old_pk = generate_identity_keypair()
    new_sk, new_pk = generate_identity_keypair()
    msg = create_migration(old_sk, old_pk, new_sk, new_pk)

    # Force expiry to the past
    msg["expiry_timestamp"] = int(time.time() * 1000) - 10000

    old_pk_bytes = public_key_to_bytes(old_pk)
    with pytest.raises(MigrationError, match="expired"):
        verify_migration(msg, old_pk_bytes)


def test_verify_migration_unknown_reason():
    old_sk, old_pk = generate_identity_keypair()
    new_sk, new_pk = generate_identity_keypair()
    msg = create_migration(old_sk, old_pk, new_sk, new_pk, "scheduled_rotation")

    msg["reason"] = "unknown_reason"

    old_pk_bytes = public_key_to_bytes(old_pk)
    with pytest.raises(MigrationError, match="Unknown migration reason"):
        verify_migration(msg, old_pk_bytes)
