package protocol

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/cisc468/p2p-project/internal/crypto"
)

const migrationExpiryMS = 30 * 24 * 60 * 60 * 1000 // 30 days

// CreateMigration creates a KEY_MIGRATION announcement signed by both old and new keys.
func CreateMigration(oldSK ed25519.PrivateKey, oldPK ed25519.PublicKey,
	newSK ed25519.PrivateKey, newPK ed25519.PublicKey, reason string) (map[string]interface{}, error) {

	now := time.Now().UnixMilli()
	oldPeerID := crypto.PeerIDFromPublicKey(oldPK)
	newPeerID := crypto.PeerIDFromPublicKey(newPK)

	canonicalFields := map[string]interface{}{
		"effective_timestamp": float64(now),
		"expiry_timestamp":   float64(now + migrationExpiryMS),
		"new_peer_id":        newPeerID,
		"old_peer_id":        oldPeerID,
		"reason":             reason,
	}
	canonicalBytes, err := crypto.CanonicalJSON(canonicalFields)
	if err != nil {
		return nil, err
	}

	oldSig := crypto.Sign(oldSK, canonicalBytes)
	newSig := crypto.Sign(newSK, canonicalBytes)

	return KeyMigration(
		0, oldPeerID, newPeerID,
		now, now+migrationExpiryMS,
		reason,
		crypto.B64URLEncode(oldSig),
		crypto.B64URLEncode(newSig),
	), nil
}

// VerifyMigration verifies a KEY_MIGRATION announcement.
// Returns the new public key bytes if valid.
func VerifyMigration(msg map[string]interface{}, knownOldPKBytes []byte) ([]byte, error) {
	now := time.Now().UnixMilli()

	effectiveF, _ := msg["effective_timestamp"].(float64)
	expiryF, _ := msg["expiry_timestamp"].(float64)
	effective := int64(effectiveF)
	expiry := int64(expiryF)

	if effective > now+5000 {
		return nil, errors.New("key migration announcement not yet effective")
	}
	if expiry <= now {
		return nil, errors.New("key migration announcement has expired")
	}

	reason, _ := msg["reason"].(string)
	if reason != "scheduled_rotation" && reason != "compromise" && reason != "other" {
		return nil, fmt.Errorf("unknown migration reason: %s", reason)
	}

	oldPeerID, _ := msg["old_peer_id"].(string)
	newPeerID, _ := msg["new_peer_id"].(string)

	canonicalFields := map[string]interface{}{
		"effective_timestamp": float64(effective),
		"expiry_timestamp":   float64(expiry),
		"new_peer_id":        newPeerID,
		"old_peer_id":        oldPeerID,
		"reason":             reason,
	}
	canonicalBytes, err := crypto.CanonicalJSON(canonicalFields)
	if err != nil {
		return nil, err
	}

	// Verify old signature
	oldPK, err := crypto.BytesToPublicKey(knownOldPKBytes)
	if err != nil {
		return nil, err
	}
	oldSigStr, _ := msg["old_signature"].(string)
	oldSig, err := crypto.B64URLDecode(oldSigStr)
	if err != nil {
		return nil, err
	}
	if err := crypto.Verify(oldPK, canonicalBytes, oldSig); err != nil {
		return nil, errors.New("key migration announcement is invalid — old signature check failed")
	}

	// Verify new signature
	newPKBytes, err := crypto.B64URLDecode(newPeerID)
	if err != nil {
		return nil, err
	}
	newPK, err := crypto.BytesToPublicKey(newPKBytes)
	if err != nil {
		return nil, err
	}
	newSigStr, _ := msg["new_signature"].(string)
	newSig, err := crypto.B64URLDecode(newSigStr)
	if err != nil {
		return nil, err
	}
	if err := crypto.Verify(newPK, canonicalBytes, newSig); err != nil {
		return nil, errors.New("key migration announcement is invalid — new signature check failed")
	}

	return newPKBytes, nil
}
