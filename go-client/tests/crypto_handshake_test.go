package tests

import (
	"bytes"
	"testing"

	"github.com/cisc468/p2p-project/internal/crypto"
)

func TestFullHandshake(t *testing.T) {
	skI, pkI, _ := crypto.GenerateIdentityKeypair()
	skR, pkR, _ := crypto.GenerateIdentityKeypair()

	initiator, err := crypto.NewHandshakeInitiator(skI, pkI)
	if err != nil {
		t.Fatalf("NewHandshakeInitiator: %v", err)
	}
	responder, err := crypto.NewHandshakeResponder(skR, pkR)
	if err != nil {
		t.Fatalf("NewHandshakeResponder: %v", err)
	}

	// Step 1: HELLO
	hello, err := initiator.CreateHello()
	if err != nil {
		t.Fatalf("CreateHello: %v", err)
	}
	if hello["type"] != "HELLO" {
		t.Errorf("type = %v, want HELLO", hello["type"])
	}

	// Process HELLO
	if err := responder.ProcessHello(hello); err != nil {
		t.Fatalf("ProcessHello: %v", err)
	}

	// Step 2: HELLO_ACK
	helloAck, err := responder.CreateHelloAck()
	if err != nil {
		t.Fatalf("CreateHelloAck: %v", err)
	}
	if helloAck["type"] != "HELLO_ACK" {
		t.Errorf("type = %v, want HELLO_ACK", helloAck["type"])
	}
	if helloAck["hello_nonce"] != hello["nonce"] {
		t.Error("hello_nonce mismatch in HELLO_ACK")
	}

	// Process HELLO_ACK
	if err := initiator.ProcessHelloAck(helloAck); err != nil {
		t.Fatalf("ProcessHelloAck: %v", err)
	}

	// Derive session keys — must match
	sessionKeyI, err := initiator.DeriveSession()
	if err != nil {
		t.Fatalf("initiator DeriveSession: %v", err)
	}
	sessionKeyR, err := responder.DeriveSession()
	if err != nil {
		t.Fatalf("responder DeriveSession: %v", err)
	}
	if !bytes.Equal(sessionKeyI, sessionKeyR) {
		t.Error("session keys differ between initiator and responder")
	}
	if len(sessionKeyI) != 32 {
		t.Errorf("session key length = %d, want 32", len(sessionKeyI))
	}

	// Step 3: AUTH
	auth, _, err := initiator.CreateAuth(sessionKeyI)
	if err != nil {
		t.Fatalf("CreateAuth: %v", err)
	}
	if err := responder.VerifyAuth(auth); err != nil {
		t.Fatalf("VerifyAuth: %v", err)
	}

	// Step 4: AUTH_ACK
	authAck, _, err := responder.CreateAuthAck(sessionKeyR)
	if err != nil {
		t.Fatalf("CreateAuthAck: %v", err)
	}
	if authAck["type"] != "AUTH_ACK" {
		t.Errorf("type = %v, want AUTH_ACK", authAck["type"])
	}
	if err := initiator.VerifyAuthAck(authAck); err != nil {
		t.Fatalf("VerifyAuthAck: %v", err)
	}
}

func TestHandshakeDifferentSessionKeys(t *testing.T) {
	skI, pkI, _ := crypto.GenerateIdentityKeypair()
	skR, pkR, _ := crypto.GenerateIdentityKeypair()

	var keys [][]byte
	for i := 0; i < 3; i++ {
		init, _ := crypto.NewHandshakeInitiator(skI, pkI)
		resp, _ := crypto.NewHandshakeResponder(skR, pkR)

		hello, _ := init.CreateHello()
		resp.ProcessHello(hello)
		helloAck, _ := resp.CreateHelloAck()
		init.ProcessHelloAck(helloAck)
		k, _ := init.DeriveSession()
		keys = append(keys, k)
	}

	if bytes.Equal(keys[0], keys[1]) || bytes.Equal(keys[1], keys[2]) {
		t.Error("PFS violated: multiple handshakes produced same session key")
	}
}

func TestHandshakeWrongHelloNonce(t *testing.T) {
	skI, pkI, _ := crypto.GenerateIdentityKeypair()
	skR, pkR, _ := crypto.GenerateIdentityKeypair()

	init, _ := crypto.NewHandshakeInitiator(skI, pkI)
	resp, _ := crypto.NewHandshakeResponder(skR, pkR)

	hello, _ := init.CreateHello()
	resp.ProcessHello(hello)
	helloAck, _ := resp.CreateHelloAck()

	// Tamper with hello_nonce
	helloAck["hello_nonce"] = crypto.B64URLEncode(make([]byte, 32))

	if err := init.ProcessHelloAck(helloAck); err == nil {
		t.Error("expected error for mismatched hello_nonce")
	}
}

func TestHandshakeAuthWrongSignature(t *testing.T) {
	skI, pkI, _ := crypto.GenerateIdentityKeypair()
	skR, pkR, _ := crypto.GenerateIdentityKeypair()

	init, _ := crypto.NewHandshakeInitiator(skI, pkI)
	resp, _ := crypto.NewHandshakeResponder(skR, pkR)

	hello, _ := init.CreateHello()
	resp.ProcessHello(hello)
	helloAck, _ := resp.CreateHelloAck()
	init.ProcessHelloAck(helloAck)

	sessionKey, _ := init.DeriveSession()
	auth, _, _ := init.CreateAuth(sessionKey)
	auth["signature"] = crypto.B64URLEncode(make([]byte, 64)) // bad sig

	if err := resp.VerifyAuth(auth); err == nil {
		t.Error("expected error for invalid AUTH signature")
	}
}

func TestEphemeralKeyExchange(t *testing.T) {
	ephA, err := crypto.GenerateEphemeralKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ephB, err := crypto.GenerateEphemeralKeypair()
	if err != nil {
		t.Fatal(err)
	}

	sharedA, err := crypto.ComputeSharedSecret(ephA.PrivateKey, ephB.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sharedB, err := crypto.ComputeSharedSecret(ephB.PrivateKey, ephA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sharedA, sharedB) {
		t.Error("X25519 shared secrets differ between sides")
	}
	if len(sharedA) != 32 {
		t.Errorf("shared secret length = %d, want 32", len(sharedA))
	}
}

func TestSessionKeyDerivationDeterministic(t *testing.T) {
	shared := bytes.Repeat([]byte{0xab}, 32)
	nonceI := bytes.Repeat([]byte{0x01}, 32)
	nonceR := bytes.Repeat([]byte{0x02}, 32)

	k1, _ := crypto.DeriveSessionKey(shared, nonceI, nonceR)
	k2, _ := crypto.DeriveSessionKey(shared, nonceI, nonceR)
	if !bytes.Equal(k1, k2) {
		t.Error("session key derivation not deterministic")
	}
}

func TestSessionKeyDerivationDifferentNonces(t *testing.T) {
	shared := bytes.Repeat([]byte{0xab}, 32)
	k1, _ := crypto.DeriveSessionKey(shared, bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x02}, 32))
	k2, _ := crypto.DeriveSessionKey(shared, bytes.Repeat([]byte{0x03}, 32), bytes.Repeat([]byte{0x04}, 32))
	if bytes.Equal(k1, k2) {
		t.Error("different nonces should produce different session keys")
	}
}
