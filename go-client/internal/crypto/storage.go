package crypto

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters — must match Python implementation exactly.
const (
	Argon2Time        = 3
	Argon2Memory      = 65536 // 64 MB
	Argon2Parallelism = 4
	Argon2KeyLen      = 32
	Argon2SaltLen     = 16
)

// DeriveVaultKey derives a 32-byte vault key from a password using Argon2id.
func DeriveVaultKey(password string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Parallelism,
		Argon2KeyLen,
	)
}

// GenerateSalt generates a random 16-byte salt for Argon2id.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, Argon2SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// EncryptVault encrypts vault plaintext with AES-256-GCM.
func EncryptVault(vaultKey, plaintext []byte) ([]byte, error) {
	return EncryptRaw(vaultKey, plaintext)
}

// DecryptVault decrypts vault payload.
func DecryptVault(vaultKey, payload []byte) ([]byte, error) {
	return DecryptRaw(vaultKey, payload)
}
