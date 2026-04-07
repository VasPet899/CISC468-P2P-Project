package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	SessionKeyInfo = "p2pshare-session-v1"
	AuthContext    = "CISC468-AUTH-v1"
	HandshakeNonceSize = 32
)

// EphemeralKeypair holds an X25519 ephemeral key pair.
type EphemeralKeypair struct {
	PrivateKey []byte // 32 bytes
	PublicKey  []byte // 32 bytes
}

// GenerateEphemeralKeypair generates an X25519 ephemeral keypair.
func GenerateEphemeralKeypair() (*EphemeralKeypair, error) {
	var sk [32]byte
	if _, err := io.ReadFull(rand.Reader, sk[:]); err != nil {
		return nil, fmt.Errorf("ephemeral keygen: %w", err)
	}
	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("X25519 basepoint mul: %w", err)
	}
	return &EphemeralKeypair{PrivateKey: sk[:], PublicKey: pk}, nil
}

// ComputeSharedSecret performs X25519 Diffie-Hellman.
func ComputeSharedSecret(myPriv, peerPub []byte) ([]byte, error) {
	shared, err := curve25519.X25519(myPriv, peerPub)
	if err != nil {
		return nil, fmt.Errorf("X25519: %w", err)
	}
	// Check for all-zero output (low-order point)
	allZero := true
	for _, b := range shared {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, errors.New("key exchange failed — invalid peer public key")
	}
	return shared, nil
}

// DeriveSessionKey derives a 32-byte session key via HKDF-SHA256.
// salt = SHA256(nonceInitiator || nonceResponder)
func DeriveSessionKey(sharedSecret, nonceInitiator, nonceResponder []byte) ([]byte, error) {
	saltInput := append(append([]byte{}, nonceInitiator...), nonceResponder...)
	saltHash := sha256.Sum256(saltInput)

	hkdfReader := hkdf.New(sha256.New, sharedSecret, saltHash[:], []byte(SessionKeyInfo))
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, sessionKey); err != nil {
		return nil, fmt.Errorf("HKDF derive: %w", err)
	}
	return sessionKey, nil
}

// BuildAuthTranscript builds the canonical JSON bytes for the AUTH signature.
func BuildAuthTranscript(signerIDPK, verifierIDPK, signerEphPK, verifierEphPK, signerNonce, verifierNonce []byte) ([]byte, error) {
	transcript := map[string]interface{}{
		"context":          AuthContext,
		"eph_pk_signer":    B64URLEncode(signerEphPK),
		"eph_pk_verifier":  B64URLEncode(verifierEphPK),
		"id_pk_signer":     B64URLEncode(signerIDPK),
		"id_pk_verifier":   B64URLEncode(verifierIDPK),
		"nonce_signer":     B64URLEncode(signerNonce),
		"nonce_verifier":   B64URLEncode(verifierNonce),
	}
	return CanonicalJSON(transcript)
}

// GenerateNonce generates a random 32-byte nonce for the handshake.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, HandshakeNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// BuildHello creates a HELLO message dict and returns it along with the nonce.
func BuildHello(ephPK []byte, identityPK ed25519.PublicKey) (map[string]interface{}, []byte, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, nil, err
	}
	msg := map[string]interface{}{
		"type":         "HELLO",
		"version":      "1",
		"ephemeral_pk": B64URLEncode(ephPK),
		"peer_id":      PeerIDFromPublicKey(identityPK),
		"timestamp":    float64(time.Now().UnixMilli()),
		"nonce":        B64URLEncode(nonce),
	}
	return msg, nonce, nil
}

// BuildHelloAck creates a HELLO_ACK message.
func BuildHelloAck(ephPK []byte, identityPK ed25519.PublicKey, helloNonceB64 string) (map[string]interface{}, []byte, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, nil, err
	}
	msg := map[string]interface{}{
		"type":         "HELLO_ACK",
		"version":      "1",
		"ephemeral_pk": B64URLEncode(ephPK),
		"peer_id":      PeerIDFromPublicKey(identityPK),
		"timestamp":    float64(time.Now().UnixMilli()),
		"nonce":        B64URLEncode(nonce),
		"hello_nonce":  helloNonceB64,
	}
	return msg, nonce, nil
}

// BuildAuth creates an AUTH message with Ed25519 signature over the transcript.
func BuildAuth(identitySK ed25519.PrivateKey, identityPK, peerIdentityPK ed25519.PublicKey,
	myEphPK, peerEphPK []byte, myNonce, peerNonce []byte, seq int) (map[string]interface{}, error) {

	transcript, err := BuildAuthTranscript(
		PublicKeyToBytes(identityPK),
		PublicKeyToBytes(peerIdentityPK),
		myEphPK, peerEphPK,
		myNonce, peerNonce,
	)
	if err != nil {
		return nil, err
	}
	sig := Sign(identitySK, transcript)

	msg := map[string]interface{}{
		"type":      "AUTH",
		"version":   "1",
		"seq":       float64(seq),
		"timestamp": float64(time.Now().UnixMilli()),
		"peer_id":   PeerIDFromPublicKey(identityPK),
		"signature": B64URLEncode(sig),
	}
	return msg, nil
}

// VerifyAuth verifies an AUTH or AUTH_ACK message signature.
func VerifyAuth(msg map[string]interface{}, peerIdentityPK, myIdentityPK ed25519.PublicKey,
	peerEphPK, myEphPK []byte, peerNonce, myNonce []byte) error {

	transcript, err := BuildAuthTranscript(
		PublicKeyToBytes(peerIdentityPK),
		PublicKeyToBytes(myIdentityPK),
		peerEphPK, myEphPK,
		peerNonce, myNonce,
	)
	if err != nil {
		return err
	}

	sigStr, ok := msg["signature"].(string)
	if !ok {
		return errors.New("missing signature field")
	}
	sig, err := B64URLDecode(sigStr)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if err := Verify(peerIdentityPK, transcript, sig); err != nil {
		return errors.New("peer identity verification failed — the peer may be impersonating someone")
	}
	return nil
}

// HandshakeInitiator drives the initiator side of the 4-step handshake.
type HandshakeInitiator struct {
	IdentitySK     ed25519.PrivateKey
	IdentityPK     ed25519.PublicKey
	Eph            *EphemeralKeypair
	MyNonce        []byte
	PeerNonce      []byte
	PeerEphPK      []byte
	PeerIdentityPK ed25519.PublicKey
}

// NewHandshakeInitiator creates a new initiator.
func NewHandshakeInitiator(sk ed25519.PrivateKey, pk ed25519.PublicKey) (*HandshakeInitiator, error) {
	eph, err := GenerateEphemeralKeypair()
	if err != nil {
		return nil, err
	}
	return &HandshakeInitiator{IdentitySK: sk, IdentityPK: pk, Eph: eph}, nil
}

func (h *HandshakeInitiator) CreateHello() (map[string]interface{}, error) {
	msg, nonce, err := BuildHello(h.Eph.PublicKey, h.IdentityPK)
	if err != nil {
		return nil, err
	}
	h.MyNonce = nonce
	return msg, nil
}

func (h *HandshakeInitiator) ProcessHelloAck(msg map[string]interface{}) error {
	if msg["type"] != "HELLO_ACK" {
		return errors.New("expected HELLO_ACK")
	}
	if msg["hello_nonce"] != B64URLEncode(h.MyNonce) {
		return errors.New("HELLO_ACK nonce mismatch — possible replay")
	}
	nonceStr, _ := msg["nonce"].(string)
	peerNonce, err := B64URLDecode(nonceStr)
	if err != nil {
		return err
	}
	h.PeerNonce = peerNonce

	ephStr, _ := msg["ephemeral_pk"].(string)
	h.PeerEphPK, err = B64URLDecode(ephStr)
	if err != nil {
		return err
	}

	peerIDStr, _ := msg["peer_id"].(string)
	peerIDBytes, err := B64URLDecode(peerIDStr)
	if err != nil {
		return err
	}
	h.PeerIdentityPK, err = BytesToPublicKey(peerIDBytes)
	return err
}

func (h *HandshakeInitiator) DeriveSession() ([]byte, error) {
	shared, err := ComputeSharedSecret(h.Eph.PrivateKey, h.PeerEphPK)
	if err != nil {
		return nil, err
	}
	return DeriveSessionKey(shared, h.MyNonce, h.PeerNonce)
}

func (h *HandshakeInitiator) CreateAuth(sessionKey []byte) (map[string]interface{}, *SessionCipher, error) {
	cipher, err := NewSessionCipher(sessionKey)
	if err != nil {
		return nil, nil, err
	}
	auth, err := BuildAuth(h.IdentitySK, h.IdentityPK, h.PeerIdentityPK,
		h.Eph.PublicKey, h.PeerEphPK, h.MyNonce, h.PeerNonce, 1)
	if err != nil {
		return nil, nil, err
	}
	return auth, cipher, nil
}

func (h *HandshakeInitiator) VerifyAuthAck(msg map[string]interface{}) error {
	return VerifyAuth(msg, h.PeerIdentityPK, h.IdentityPK,
		h.PeerEphPK, h.Eph.PublicKey, h.PeerNonce, h.MyNonce)
}

// HandshakeResponder drives the responder side.
type HandshakeResponder struct {
	IdentitySK     ed25519.PrivateKey
	IdentityPK     ed25519.PublicKey
	Eph            *EphemeralKeypair
	MyNonce        []byte
	PeerNonce      []byte
	PeerEphPK      []byte
	PeerIdentityPK ed25519.PublicKey
}

func NewHandshakeResponder(sk ed25519.PrivateKey, pk ed25519.PublicKey) (*HandshakeResponder, error) {
	eph, err := GenerateEphemeralKeypair()
	if err != nil {
		return nil, err
	}
	return &HandshakeResponder{IdentitySK: sk, IdentityPK: pk, Eph: eph}, nil
}

func (h *HandshakeResponder) ProcessHello(msg map[string]interface{}) error {
	if msg["type"] != "HELLO" {
		return errors.New("expected HELLO")
	}
	nonceStr, _ := msg["nonce"].(string)
	var err error
	h.PeerNonce, err = B64URLDecode(nonceStr)
	if err != nil {
		return err
	}
	ephStr, _ := msg["ephemeral_pk"].(string)
	h.PeerEphPK, err = B64URLDecode(ephStr)
	if err != nil {
		return err
	}
	peerIDStr, _ := msg["peer_id"].(string)
	peerIDBytes, err := B64URLDecode(peerIDStr)
	if err != nil {
		return err
	}
	h.PeerIdentityPK, err = BytesToPublicKey(peerIDBytes)
	return err
}

func (h *HandshakeResponder) CreateHelloAck() (map[string]interface{}, error) {
	msg, nonce, err := BuildHelloAck(h.Eph.PublicKey, h.IdentityPK, B64URLEncode(h.PeerNonce))
	if err != nil {
		return nil, err
	}
	h.MyNonce = nonce
	return msg, nil
}

func (h *HandshakeResponder) DeriveSession() ([]byte, error) {
	shared, err := ComputeSharedSecret(h.Eph.PrivateKey, h.PeerEphPK)
	if err != nil {
		return nil, err
	}
	// Initiator nonce = peer nonce, responder nonce = my nonce
	return DeriveSessionKey(shared, h.PeerNonce, h.MyNonce)
}

func (h *HandshakeResponder) VerifyAuth(msg map[string]interface{}) error {
	return VerifyAuth(msg, h.PeerIdentityPK, h.IdentityPK,
		h.PeerEphPK, h.Eph.PublicKey, h.PeerNonce, h.MyNonce)
}

func (h *HandshakeResponder) CreateAuthAck(sessionKey []byte) (map[string]interface{}, *SessionCipher, error) {
	cipher, err := NewSessionCipher(sessionKey)
	if err != nil {
		return nil, nil, err
	}
	authAck, err := BuildAuth(h.IdentitySK, h.IdentityPK, h.PeerIdentityPK,
		h.Eph.PublicKey, h.PeerEphPK, h.MyNonce, h.PeerNonce, 2)
	if err != nil {
		return nil, nil, err
	}
	authAck["type"] = "AUTH_ACK"
	return authAck, cipher, nil
}
