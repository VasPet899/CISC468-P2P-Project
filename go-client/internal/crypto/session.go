package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	NonceSize      = 12
	TagSize        = 16
	MaxPayloadSize = 64 * 1024 * 1024 // 64 MB
)

// SessionCipher handles AES-256-GCM encryption/decryption for an established session.
type SessionCipher struct {
	gcm     cipher.AEAD
	SendSeq int
	RecvSeq int
}

// NewSessionCipher creates a new session cipher from a 32-byte session key.
func NewSessionCipher(sessionKey []byte) (*SessionCipher, error) {
	if len(sessionKey) != 32 {
		return nil, errors.New("session key must be 32 bytes")
	}
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	return &SessionCipher{gcm: gcm}, nil
}

// Encrypt encrypts plaintext. Returns nonce (12B) || ciphertext || tag (16B).
func (sc *SessionCipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation: %w", err)
	}
	ct := sc.gcm.Seal(nil, nonce, plaintext, nil)
	sc.SendSeq++
	out := make([]byte, 0, NonceSize+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Decrypt decrypts a payload of nonce (12B) || ciphertext || tag (16B).
func (sc *SessionCipher) Decrypt(payload []byte) ([]byte, error) {
	if len(payload) < NonceSize+TagSize {
		return nil, errors.New("encrypted payload too short")
	}
	nonce := payload[:NonceSize]
	ct := payload[NonceSize:]
	plaintext, err := sc.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("message integrity check failed — possible tampering or data corruption")
	}
	sc.RecvSeq++
	return plaintext, nil
}

// EncryptRaw performs one-shot AES-256-GCM encryption. Returns nonce || ct || tag.
func EncryptRaw(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, NonceSize+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// DecryptRaw performs one-shot AES-256-GCM decryption of nonce || ct || tag.
func DecryptRaw(key, payload []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}
	if len(payload) < NonceSize+TagSize {
		return nil, errors.New("encrypted payload too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := payload[:NonceSize]
	ct := payload[NonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("message integrity check failed — possible tampering or data corruption")
	}
	return plaintext, nil
}
