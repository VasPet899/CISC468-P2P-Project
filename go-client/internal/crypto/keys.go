// Package crypto provides Ed25519 identity key management, X25519 ECDH,
// AES-256-GCM session encryption, and Argon2id vault key derivation.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// GenerateIdentityKeypair creates a new Ed25519 identity keypair.
// Returns (seed [32]byte, publicKey [32]byte).
func GenerateIdentityKeypair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("keygen failed: %w", err)
	}
	return priv, pub, nil
}

// PrivateKeyToSeed extracts the 32-byte seed from an Ed25519 private key.
func PrivateKeyToSeed(sk ed25519.PrivateKey) []byte {
	return sk.Seed()
}

// SeedToPrivateKey reconstructs an Ed25519 private key from a 32-byte seed.
func SeedToPrivateKey(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("Ed25519 seed must be exactly 32 bytes")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PublicKeyToBytes returns the raw 32-byte representation of an Ed25519 public key.
func PublicKeyToBytes(pk ed25519.PublicKey) []byte {
	return []byte(pk)
}

// BytesToPublicKey interprets 32 raw bytes as an Ed25519 public key.
func BytesToPublicKey(data []byte) (ed25519.PublicKey, error) {
	if len(data) != ed25519.PublicKeySize {
		return nil, errors.New("Ed25519 public key must be exactly 32 bytes")
	}
	return ed25519.PublicKey(data), nil
}

// B64URLEncode encodes bytes as URL-safe base64 without padding
// (matches Python's urlsafe_b64encode().rstrip('=')).
func B64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// B64URLDecode decodes URL-safe base64 without padding.
func B64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// PeerIDFromPublicKey computes the peer ID: base64url of the raw 32-byte public key.
func PeerIDFromPublicKey(pk ed25519.PublicKey) string {
	return B64URLEncode(PublicKeyToBytes(pk))
}

// Fingerprint computes a human-readable fingerprint: first 8 hex chars of SHA-256(pubkey).
func Fingerprint(pk ed25519.PublicKey) string {
	h := sha256.Sum256(PublicKeyToBytes(pk))
	return fmt.Sprintf("%x", h[:4])
}
