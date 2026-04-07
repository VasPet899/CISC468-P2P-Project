package tests

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cisc468/p2p-project/internal/crypto"
)

func TestSessionCipherRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	send, _ := crypto.NewSessionCipher(key)
	recv, _ := crypto.NewSessionCipher(key)

	plaintext := []byte("Hello, encrypted world!")
	encrypted, err := send.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(encrypted) != crypto.NonceSize+len(plaintext)+crypto.TagSize {
		t.Errorf("encrypted length wrong: got %d", len(encrypted))
	}
	decrypted, err := recv.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("plaintext mismatch after decrypt")
	}
}

func TestSessionCipherSeqTracking(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	c, _ := crypto.NewSessionCipher(key)

	if c.SendSeq != 0 {
		t.Error("initial SendSeq should be 0")
	}
	c.Encrypt([]byte("msg1"))
	if c.SendSeq != 1 {
		t.Errorf("SendSeq = %d, want 1", c.SendSeq)
	}
	c.Encrypt([]byte("msg2"))
	if c.SendSeq != 2 {
		t.Errorf("SendSeq = %d, want 2", c.SendSeq)
	}
}

func TestSessionCipherWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	send, _ := crypto.NewSessionCipher(key1)
	recv, _ := crypto.NewSessionCipher(key2)

	enc, _ := send.Encrypt([]byte("secret"))
	_, err := recv.Decrypt(enc)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}

func TestSessionCipherTampered(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	send, _ := crypto.NewSessionCipher(key)
	recv, _ := crypto.NewSessionCipher(key)

	enc, _ := send.Encrypt([]byte("important data"))
	enc[len(enc)-1] ^= 0xFF // flip last byte (in tag)
	_, err := recv.Decrypt(enc)
	if err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

func TestSessionCipherTooShort(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	c, _ := crypto.NewSessionCipher(key)
	_, err := c.Decrypt(make([]byte, 10))
	if err == nil {
		t.Error("expected error for too-short payload")
	}
}

func TestEncryptRawRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("raw encryption test")
	enc, err := crypto.EncryptRaw(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptRaw: %v", err)
	}
	dec, err := crypto.DecryptRaw(key, enc)
	if err != nil {
		t.Fatalf("DecryptRaw: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Error("plaintext mismatch")
	}
}

func TestEncryptRawWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)
	enc, _ := crypto.EncryptRaw(key1, []byte("data"))
	_, err := crypto.DecryptRaw(key2, enc)
	if err == nil {
		t.Error("expected error for wrong key")
	}
}

func TestEncryptRawInvalidKeyLength(t *testing.T) {
	_, err := crypto.EncryptRaw([]byte("short"), []byte("data"))
	if err == nil {
		t.Error("expected error for short key")
	}
}

func TestEncryptRawEmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	enc, _ := crypto.EncryptRaw(key, []byte{})
	dec, err := crypto.DecryptRaw(key, enc)
	if err != nil {
		t.Fatalf("DecryptRaw: %v", err)
	}
	if len(dec) != 0 {
		t.Error("expected empty decrypted output")
	}
}
