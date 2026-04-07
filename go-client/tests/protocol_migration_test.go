package tests

import (
	"testing"
	"time"

	"github.com/cisc468/p2p-project/internal/crypto"
	"github.com/cisc468/p2p-project/internal/protocol"
)

func TestCreateMigration(t *testing.T) {
	oldSK, oldPK, _ := crypto.GenerateIdentityKeypair()
	newSK, newPK, _ := crypto.GenerateIdentityKeypair()

	msg, err := protocol.CreateMigration(oldSK, oldPK, newSK, newPK, "scheduled_rotation")
	if err != nil {
		t.Fatalf("CreateMigration: %v", err)
	}
	if msg["type"] != "KEY_MIGRATION" {
		t.Errorf("type = %v, want KEY_MIGRATION", msg["type"])
	}
	if _, ok := msg["old_signature"]; !ok {
		t.Error("missing old_signature")
	}
	if _, ok := msg["new_signature"]; !ok {
		t.Error("missing new_signature")
	}
}

func TestVerifyMigrationValid(t *testing.T) {
	oldSK, oldPK, _ := crypto.GenerateIdentityKeypair()
	newSK, newPK, _ := crypto.GenerateIdentityKeypair()

	msg, _ := protocol.CreateMigration(oldSK, oldPK, newSK, newPK, "scheduled_rotation")
	oldPKBytes := crypto.PublicKeyToBytes(oldPK)

	newPKBytes, err := protocol.VerifyMigration(msg, oldPKBytes)
	if err != nil {
		t.Fatalf("VerifyMigration: %v", err)
	}
	if string(newPKBytes) != string(crypto.PublicKeyToBytes(newPK)) {
		t.Error("returned new PK bytes mismatch")
	}
}

func TestVerifyMigrationWrongOldKey(t *testing.T) {
	oldSK, oldPK, _ := crypto.GenerateIdentityKeypair()
	newSK, newPK, _ := crypto.GenerateIdentityKeypair()
	_, wrongPK, _ := crypto.GenerateIdentityKeypair()

	msg, _ := protocol.CreateMigration(oldSK, oldPK, newSK, newPK, "scheduled_rotation")
	if _, err := protocol.VerifyMigration(msg, crypto.PublicKeyToBytes(wrongPK)); err == nil {
		t.Error("expected error for wrong old key")
	}
}

func TestVerifyMigrationTamperedNewPeerID(t *testing.T) {
	oldSK, oldPK, _ := crypto.GenerateIdentityKeypair()
	newSK, newPK, _ := crypto.GenerateIdentityKeypair()
	_, fakePK, _ := crypto.GenerateIdentityKeypair()

	msg, _ := protocol.CreateMigration(oldSK, oldPK, newSK, newPK, "scheduled_rotation")
	msg["new_peer_id"] = crypto.B64URLEncode(crypto.PublicKeyToBytes(fakePK))

	if _, err := protocol.VerifyMigration(msg, crypto.PublicKeyToBytes(oldPK)); err == nil {
		t.Error("expected error for tampered new_peer_id")
	}
}

func TestVerifyMigrationExpired(t *testing.T) {
	oldSK, oldPK, _ := crypto.GenerateIdentityKeypair()
	newSK, newPK, _ := crypto.GenerateIdentityKeypair()

	msg, _ := protocol.CreateMigration(oldSK, oldPK, newSK, newPK, "scheduled_rotation")
	msg["expiry_timestamp"] = float64(time.Now().UnixMilli() - 10000)

	if _, err := protocol.VerifyMigration(msg, crypto.PublicKeyToBytes(oldPK)); err == nil {
		t.Error("expected error for expired migration")
	}
}

func TestVerifyMigrationUnknownReason(t *testing.T) {
	oldSK, oldPK, _ := crypto.GenerateIdentityKeypair()
	newSK, newPK, _ := crypto.GenerateIdentityKeypair()

	msg, _ := protocol.CreateMigration(oldSK, oldPK, newSK, newPK, "scheduled_rotation")
	msg["reason"] = "unknown_reason"

	if _, err := protocol.VerifyMigration(msg, crypto.PublicKeyToBytes(oldPK)); err == nil {
		t.Error("expected error for unknown reason")
	}
}
