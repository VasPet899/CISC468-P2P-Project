package tests

import (
	"bytes"
	"strings"
	"testing"

	"crypto/ed25519"

	"github.com/cisc468/p2p-project/internal/crypto"
)

func TestGenerateIdentityKeypair(t *testing.T) {
	sk, pk, err := crypto.GenerateIdentityKeypair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeypair: %v", err)
	}
	if len(crypto.PrivateKeyToSeed(sk)) != 32 {
		t.Error("seed must be 32 bytes")
	}
	if len(crypto.PublicKeyToBytes(pk)) != 32 {
		t.Error("public key must be 32 bytes")
	}
}

func TestSeedRoundtrip(t *testing.T) {
	sk, pk, _ := crypto.GenerateIdentityKeypair()
	seed := crypto.PrivateKeyToSeed(sk)
	sk2, err := crypto.SeedToPrivateKey(seed)
	if err != nil {
		t.Fatalf("SeedToPrivateKey: %v", err)
	}
	if !bytes.Equal(crypto.PrivateKeyToSeed(sk2), seed) {
		t.Error("seed roundtrip: seeds differ")
	}
	if !bytes.Equal(crypto.PublicKeyToBytes(ed25519.PublicKey(sk2.Public().(ed25519.PublicKey))), crypto.PublicKeyToBytes(pk)) {
		t.Error("seed roundtrip: public keys differ")
	}
}

func TestPublicKeyRoundtrip(t *testing.T) {
	_, pk, _ := crypto.GenerateIdentityKeypair()
	pkBytes := crypto.PublicKeyToBytes(pk)
	pk2, err := crypto.BytesToPublicKey(pkBytes)
	if err != nil {
		t.Fatalf("BytesToPublicKey: %v", err)
	}
	if !bytes.Equal(crypto.PublicKeyToBytes(pk2), pkBytes) {
		t.Error("public key roundtrip failed")
	}
}

func TestInvalidSeedLength(t *testing.T) {
	_, err := crypto.SeedToPrivateKey(make([]byte, 16))
	if err == nil {
		t.Error("expected error for 16-byte seed")
	}
}

func TestInvalidPubkeyLength(t *testing.T) {
	_, err := crypto.BytesToPublicKey(make([]byte, 16))
	if err == nil {
		t.Error("expected error for 16-byte pubkey")
	}
}

func TestB64URLRoundtrip(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}
	encoded := crypto.B64URLEncode(data)
	if strings.Contains(encoded, "=") {
		t.Error("base64url must not have padding")
	}
	if strings.ContainsAny(encoded, "+/") {
		t.Error("base64url must be url-safe")
	}
	decoded, err := crypto.B64URLDecode(encoded)
	if err != nil {
		t.Fatalf("B64URLDecode: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Error("base64url roundtrip mismatch")
	}
}

func TestPeerID(t *testing.T) {
	_, pk, _ := crypto.GenerateIdentityKeypair()
	pid := crypto.PeerIDFromPublicKey(pk)
	if len(pid) != 43 {
		t.Errorf("peer ID length = %d, want 43 (base64url of 32 bytes)", len(pid))
	}
	decoded, _ := crypto.B64URLDecode(pid)
	if !bytes.Equal(decoded, crypto.PublicKeyToBytes(pk)) {
		t.Error("peer ID does not decode back to pubkey bytes")
	}
}

func TestFingerprint(t *testing.T) {
	_, pk, _ := crypto.GenerateIdentityKeypair()
	fp := crypto.Fingerprint(pk)
	if len(fp) != 8 {
		t.Errorf("fingerprint length = %d, want 8", len(fp))
	}
}
