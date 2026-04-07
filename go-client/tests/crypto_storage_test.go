package tests

import (
	"bytes"
	"testing"

	"github.com/cisc468/p2p-project/internal/crypto"
)

func TestDeriveVaultKeyDeterministic(t *testing.T) {
	salt := make([]byte, 16)
	k1 := crypto.DeriveVaultKey("password123", salt)
	k2 := crypto.DeriveVaultKey("password123", salt)
	if !bytes.Equal(k1, k2) {
		t.Error("vault key derivation not deterministic")
	}
	if len(k1) != 32 {
		t.Errorf("vault key length = %d, want 32", len(k1))
	}
}

func TestDeriveVaultKeyDifferentPasswords(t *testing.T) {
	salt := make([]byte, 16)
	k1 := crypto.DeriveVaultKey("password1", salt)
	k2 := crypto.DeriveVaultKey("password2", salt)
	if bytes.Equal(k1, k2) {
		t.Error("different passwords produced same key")
	}
}

func TestDeriveVaultKeyDifferentSalts(t *testing.T) {
	k1 := crypto.DeriveVaultKey("password", make([]byte, 16))
	salt2 := bytes.Repeat([]byte{0x01}, 16)
	k2 := crypto.DeriveVaultKey("password", salt2)
	if bytes.Equal(k1, k2) {
		t.Error("different salts produced same key")
	}
}

func TestGenerateSalt(t *testing.T) {
	s1, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	s2, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	if len(s1) != crypto.Argon2SaltLen {
		t.Errorf("salt length = %d, want %d", len(s1), crypto.Argon2SaltLen)
	}
	if bytes.Equal(s1, s2) {
		t.Error("two generated salts should differ")
	}
}

func TestVaultEncryptDecrypt(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	key := crypto.DeriveVaultKey("test", salt)
	plaintext := []byte(`{"identity":"test_data"}`)
	enc, err := crypto.EncryptVault(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptVault: %v", err)
	}
	dec, err := crypto.DecryptVault(key, enc)
	if err != nil {
		t.Fatalf("DecryptVault: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Error("vault decrypt mismatch")
	}
}

func TestVaultDecryptWrongKey(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	key1 := crypto.DeriveVaultKey("correct", salt)
	key2 := crypto.DeriveVaultKey("wrong", salt)
	enc, _ := crypto.EncryptVault(key1, []byte("secret"))
	_, err := crypto.DecryptVault(key2, enc)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}
