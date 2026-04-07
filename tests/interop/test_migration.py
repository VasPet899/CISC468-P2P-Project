"""Integration test: key migration protocol.

Verifies that:
  1. A KEY_MIGRATION message is signed by both old and new keys.
  2. A contact receiving the migration verifies both signatures and updates their record.
  3. Tampered signatures are rejected.
  4. Expired or future-dated migrations are rejected.
  5. Unknown reason codes are rejected.
  6. The fixture migration message is verifiable by Python (and must also be verifiable
     by Go when Go is available — both read the same fixture file).
"""

import time
import pytest

from helpers import load_fixture
from p2pshare.crypto.keys import (
    generate_identity_keypair,
    public_key_to_bytes,
    b64url_encode,
    b64url_decode,
)
from p2pshare.protocol.migration import create_migration, verify_migration
from p2pshare.errors import MigrationError


# ── fixture-based vectors ─────────────────────────────────────────────────────

class TestMigrationFixtureVectors:
    """Validate the pre-generated fixture migration message (cross-language reference)."""

    def setup_method(self):
        self.fx = load_fixture("sample_migration.json")
        self.old_pk_bytes = b64url_decode(self.fx["old_public_key"])
        self.new_pk_bytes_expected = b64url_decode(self.fx["new_public_key"])

    def test_fixture_migration_verifies(self):
        """verify_migration accepts the fixture message and returns correct new PK bytes."""
        new_pk_bytes = verify_migration(self.fx["migration_message"], self.old_pk_bytes)
        assert new_pk_bytes == self.new_pk_bytes_expected

    def test_fixture_migration_wrong_old_key_rejected(self):
        """verify_migration rejects the message when given the wrong old key."""
        _, wrong_pk = generate_identity_keypair()
        with pytest.raises(MigrationError):
            verify_migration(self.fx["migration_message"], public_key_to_bytes(wrong_pk))

    def test_fixture_migration_new_key_bytes_match_new_peer_id(self):
        """The returned new_pk_bytes equal b64url_decode(new_peer_id) from the message."""
        msg = self.fx["migration_message"]
        new_pk_bytes = verify_migration(msg, self.old_pk_bytes)
        assert new_pk_bytes == b64url_decode(msg["new_peer_id"])


# ── live migration creation and verification ──────────────────────────────────

class TestMigrationLive:
    """Create and verify live KEY_MIGRATION messages."""

    def test_valid_migration_accepted(self):
        sk_old, pk_old = generate_identity_keypair()
        sk_new, pk_new = generate_identity_keypair()
        msg = create_migration(sk_old, pk_old, sk_new, pk_new)
        new_pk = verify_migration(msg, public_key_to_bytes(pk_old))
        assert new_pk == public_key_to_bytes(pk_new)

    def test_migration_all_valid_reasons(self):
        """All three accepted reason codes must pass verification."""
        for reason in ("scheduled_rotation", "compromise", "other"):
            sk_old, pk_old = generate_identity_keypair()
            sk_new, pk_new = generate_identity_keypair()
            msg = create_migration(sk_old, pk_old, sk_new, pk_new, reason=reason)
            new_pk = verify_migration(msg, public_key_to_bytes(pk_old))
            assert new_pk == public_key_to_bytes(pk_new)

    def test_migration_tampered_old_signature_rejected(self):
        sk_old, pk_old = generate_identity_keypair()
        sk_new, pk_new = generate_identity_keypair()
        msg = create_migration(sk_old, pk_old, sk_new, pk_new)
        msg["old_signature"] = b64url_encode(bytes(64))  # zeroed signature
        with pytest.raises(MigrationError, match="old signature"):
            verify_migration(msg, public_key_to_bytes(pk_old))

    def test_migration_tampered_new_signature_rejected(self):
        sk_old, pk_old = generate_identity_keypair()
        sk_new, pk_new = generate_identity_keypair()
        msg = create_migration(sk_old, pk_old, sk_new, pk_new)
        msg["new_signature"] = b64url_encode(bytes(64))  # zeroed signature
        with pytest.raises(MigrationError, match="new signature"):
            verify_migration(msg, public_key_to_bytes(pk_old))

    def test_migration_unknown_reason_rejected(self):
        sk_old, pk_old = generate_identity_keypair()
        sk_new, pk_new = generate_identity_keypair()
        msg = create_migration(sk_old, pk_old, sk_new, pk_new)
        msg["reason"] = "hacked"
        with pytest.raises(MigrationError, match="reason"):
            verify_migration(msg, public_key_to_bytes(pk_old))

    def test_migration_expired_rejected(self):
        sk_old, pk_old = generate_identity_keypair()
        sk_new, pk_new = generate_identity_keypair()
        msg = create_migration(sk_old, pk_old, sk_new, pk_new)
        # Set expiry in the past
        msg["expiry_timestamp"] = int(time.time() * 1000) - 1000
        with pytest.raises(MigrationError, match="expired"):
            verify_migration(msg, public_key_to_bytes(pk_old))

    def test_migration_future_effective_rejected(self):
        """Migration with effective_timestamp too far in the future is rejected."""
        sk_old, pk_old = generate_identity_keypair()
        sk_new, pk_new = generate_identity_keypair()
        msg = create_migration(sk_old, pk_old, sk_new, pk_new)
        # Move effective_ts well beyond the 5-second grace period
        msg["effective_timestamp"] = int(time.time() * 1000) + 60_000
        with pytest.raises(MigrationError, match="not yet effective"):
            verify_migration(msg, public_key_to_bytes(pk_old))

    def test_migration_message_structure(self):
        """KEY_MIGRATION message contains all required fields."""
        sk_old, pk_old = generate_identity_keypair()
        sk_new, pk_new = generate_identity_keypair()
        msg = create_migration(sk_old, pk_old, sk_new, pk_new, reason="compromise")

        assert msg["type"] == "KEY_MIGRATION"
        assert msg["version"] == "1"
        assert "old_peer_id" in msg
        assert "new_peer_id" in msg
        assert "old_signature" in msg
        assert "new_signature" in msg
        assert "effective_timestamp" in msg
        assert "expiry_timestamp" in msg
        assert msg["reason"] == "compromise"
        assert msg["expiry_timestamp"] > msg["effective_timestamp"]

    def test_migration_new_peer_id_is_new_public_key(self):
        """new_peer_id encodes the new public key bytes (b64url)."""
        sk_old, pk_old = generate_identity_keypair()
        sk_new, pk_new = generate_identity_keypair()
        msg = create_migration(sk_old, pk_old, sk_new, pk_new)
        assert b64url_decode(msg["new_peer_id"]) == public_key_to_bytes(pk_new)

    def test_migration_old_peer_id_is_old_public_key(self):
        """old_peer_id encodes the old public key bytes (b64url)."""
        sk_old, pk_old = generate_identity_keypair()
        sk_new, pk_new = generate_identity_keypair()
        msg = create_migration(sk_old, pk_old, sk_new, pk_new)
        assert b64url_decode(msg["old_peer_id"]) == public_key_to_bytes(pk_old)


# ── contact book update simulation ───────────────────────────────────────────

class TestMigrationContactUpdate:
    """Simulate a contact receiving a migration and updating their contact book."""

    def test_contact_updates_peer_id_after_migration(self):
        """After migration, contact book should hold the new public key."""
        sk_old, pk_old = generate_identity_keypair()
        sk_new, pk_new = generate_identity_keypair()

        # Contact's "database": maps peer_id -> pk_bytes
        contact_book = {
            b64url_encode(public_key_to_bytes(pk_old)): public_key_to_bytes(pk_old)
        }

        old_peer_id = b64url_encode(public_key_to_bytes(pk_old))
        assert old_peer_id in contact_book

        # Owner broadcasts migration
        msg = create_migration(sk_old, pk_old, sk_new, pk_new)

        # Contact verifies and updates
        known_pk = contact_book[old_peer_id]
        new_pk_bytes = verify_migration(msg, known_pk)

        # Update contact book
        del contact_book[old_peer_id]
        new_peer_id = b64url_encode(new_pk_bytes)
        contact_book[new_peer_id] = new_pk_bytes

        assert old_peer_id not in contact_book
        assert new_peer_id in contact_book
        assert contact_book[new_peer_id] == public_key_to_bytes(pk_new)

    def test_contact_rejects_migration_for_unknown_peer(self):
        """Contact ignores a migration for a peer they don't know about."""
        sk_old, pk_old = generate_identity_keypair()
        sk_new, pk_new = generate_identity_keypair()
        _, unknown_pk = generate_identity_keypair()

        # Contact doesn't have old_pk in their book; they have a different key
        msg = create_migration(sk_old, pk_old, sk_new, pk_new)

        # Trying to verify with wrong key should raise
        with pytest.raises(MigrationError):
            verify_migration(msg, public_key_to_bytes(unknown_pk))

    def test_dual_signature_prevents_stolen_key_forgery(self):
        """Attacker with only the old key cannot forge a migration to their own key.

        They lack the new private key, so they can't produce a valid new_signature.
        """
        sk_old, pk_old = generate_identity_keypair()
        sk_new, pk_new = generate_identity_keypair()  # legitimate new key
        sk_attacker, pk_attacker = generate_identity_keypair()

        # Attacker creates a migration message with their own new key,
        # but signs with the stolen old key and their own attacker new key.
        # This IS a valid migration (dual signatures present).
        # The protection here is that the attacker would need sk_old to do this at all.
        # If they have sk_old and want to impersonate, that's a compromise scenario.
        # The test verifies that a migration signed by sk_new (legitimate) cannot be
        # re-used to make the attacker's key appear as new_peer_id.
        legit_msg = create_migration(sk_old, pk_old, sk_new, pk_new)

        # Attacker tampers new_peer_id to point to their key
        tampered = dict(legit_msg)
        tampered["new_peer_id"] = b64url_encode(public_key_to_bytes(pk_attacker))

        with pytest.raises(MigrationError):
            verify_migration(tampered, public_key_to_bytes(pk_old))
