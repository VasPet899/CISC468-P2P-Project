// Package storage provides encrypted vault and file store management.
package storage

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cisc468/p2p-project/internal/crypto"
)

// Vault is the in-memory representation of the decrypted vault.
type Vault struct {
	DataDir    string
	VaultPath  string
	VaultKey   []byte
	IdentitySK ed25519.PrivateKey
	IdentityPK ed25519.PublicKey
	Contacts   []Contact
	Settings   Settings
	CreatedAt  int64
}

// Contact represents a known peer in the contact book.
type Contact struct {
	PeerID           string   `json:"peer_id"`
	Alias            string   `json:"alias"`
	PublicKey        string   `json:"public_key"` // base64url of raw 32-byte Ed25519 pubkey
	AddedAt          int64    `json:"added_at"`
	LastSeen         int64    `json:"last_seen"`
	MigrationHistory []string `json:"migration_history"`
}

// Settings holds user preferences.
type Settings struct {
	DisplayName              string `json:"display_name"`
	RequireConsentForTransfer bool   `json:"require_consent_for_transfer"`
}

// vaultPlaintext is the JSON structure inside the encrypted vault.
type vaultPlaintext struct {
	Identity struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
		CreatedAt  int64  `json:"created_at"`
	} `json:"identity"`
	Contacts []Contact `json:"contacts"`
	Settings Settings  `json:"settings"`
}

// vaultOuter is the on-disk vault.json structure.
type vaultOuter struct {
	VaultVersion int `json:"vault_version"`
	KDF          string `json:"kdf"`
	KDFParams    struct {
		Time        int    `json:"time"`
		Memory      int    `json:"memory"`
		Parallelism int    `json:"parallelism"`
		Salt        string `json:"salt"`
		KeyLen      int    `json:"keylen"`
	} `json:"kdf_params"`
	Ciphertext string `json:"ciphertext"`
}

// NewVault creates a new Vault handle for the given data directory.
func NewVault(dataDir string) *Vault {
	return &Vault{
		DataDir:   dataDir,
		VaultPath: filepath.Join(dataDir, "vault.json"),
	}
}

// PeerID returns the base64url peer ID of this vault's identity.
func (v *Vault) PeerID() string {
	return crypto.PeerIDFromPublicKey(v.IdentityPK)
}

// Exists checks if vault.json exists on disk.
func (v *Vault) Exists() bool {
	_, err := os.Stat(v.VaultPath)
	return err == nil
}

// Create initializes a new vault with a fresh identity keypair.
func (v *Vault) Create(password, displayName string) error {
	os.MkdirAll(filepath.Join(v.DataDir, "files"), 0700)
	os.MkdirAll(filepath.Join(v.DataDir, "migrations"), 0700)

	sk, pk, err := crypto.GenerateIdentityKeypair()
	if err != nil {
		return err
	}
	v.IdentitySK = sk
	v.IdentityPK = pk
	v.CreatedAt = time.Now().UnixMilli()
	v.Contacts = []Contact{}
	v.Settings = Settings{
		DisplayName:              displayName,
		RequireConsentForTransfer: true,
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}
	v.VaultKey = crypto.DeriveVaultKey(password, salt)
	return v.save(salt)
}

// Open decrypts and loads an existing vault.
func (v *Vault) Open(password string) error {
	if !v.Exists() {
		return errors.New("vault file not found — run 'init' first")
	}

	data, err := os.ReadFile(v.VaultPath)
	if err != nil {
		return err
	}
	var outer vaultOuter
	if err := json.Unmarshal(data, &outer); err != nil {
		return fmt.Errorf("parse vault: %w", err)
	}

	salt, err := crypto.B64URLDecode(outer.KDFParams.Salt)
	if err != nil {
		return err
	}
	v.VaultKey = crypto.DeriveVaultKey(password, salt)

	ciphertext, err := crypto.B64URLDecode(outer.Ciphertext)
	if err != nil {
		return err
	}
	plaintext, err := crypto.DecryptVault(v.VaultKey, ciphertext)
	if err != nil {
		return errors.New("incorrect password or corrupted vault file")
	}

	var vp vaultPlaintext
	if err := json.Unmarshal(plaintext, &vp); err != nil {
		return fmt.Errorf("parse vault plaintext: %w", err)
	}

	seed, err := crypto.B64URLDecode(vp.Identity.PrivateKey)
	if err != nil {
		return err
	}
	v.IdentitySK, err = crypto.SeedToPrivateKey(seed)
	if err != nil {
		return err
	}

	pkBytes, err := crypto.B64URLDecode(vp.Identity.PublicKey)
	if err != nil {
		return err
	}
	v.IdentityPK, err = crypto.BytesToPublicKey(pkBytes)
	if err != nil {
		return err
	}

	v.CreatedAt = vp.Identity.CreatedAt
	v.Contacts = vp.Contacts
	v.Settings = vp.Settings
	return nil
}

// Save re-encrypts and saves the vault.
func (v *Vault) Save() error {
	if v.VaultKey == nil {
		return errors.New("vault not open")
	}
	data, err := os.ReadFile(v.VaultPath)
	if err != nil {
		return err
	}
	var outer vaultOuter
	if err := json.Unmarshal(data, &outer); err != nil {
		return err
	}
	salt, err := crypto.B64URLDecode(outer.KDFParams.Salt)
	if err != nil {
		return err
	}
	return v.save(salt)
}

func (v *Vault) save(salt []byte) error {
	vp := vaultPlaintext{
		Contacts: v.Contacts,
		Settings: v.Settings,
	}
	vp.Identity.PrivateKey = crypto.B64URLEncode(crypto.PrivateKeyToSeed(v.IdentitySK))
	vp.Identity.PublicKey = crypto.B64URLEncode(crypto.PublicKeyToBytes(v.IdentityPK))
	vp.Identity.CreatedAt = v.CreatedAt

	plaintext, err := json.Marshal(vp)
	if err != nil {
		return err
	}
	encrypted, err := crypto.EncryptVault(v.VaultKey, plaintext)
	if err != nil {
		return err
	}

	outer := vaultOuter{
		VaultVersion: 1,
		KDF:          "argon2id",
		Ciphertext:   crypto.B64URLEncode(encrypted),
	}
	outer.KDFParams.Time = crypto.Argon2Time
	outer.KDFParams.Memory = crypto.Argon2Memory
	outer.KDFParams.Parallelism = crypto.Argon2Parallelism
	outer.KDFParams.Salt = crypto.B64URLEncode(salt)
	outer.KDFParams.KeyLen = crypto.Argon2KeyLen

	data, err := json.MarshalIndent(outer, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(v.VaultPath, data, 0600)
}

// AddContact adds or updates a contact.
func (v *Vault) AddContact(peerID string, publicKeyBytes []byte, alias string) {
	now := time.Now().UnixMilli()
	for i, c := range v.Contacts {
		if c.PeerID == peerID {
			v.Contacts[i].LastSeen = now
			return
		}
	}
	if alias == "" {
		alias = peerID[:8]
	}
	v.Contacts = append(v.Contacts, Contact{
		PeerID:           peerID,
		Alias:            alias,
		PublicKey:         crypto.B64URLEncode(publicKeyBytes),
		AddedAt:          now,
		LastSeen:         now,
		MigrationHistory: []string{},
	})
}

// GetContact looks up a contact by peer_id.
func (v *Vault) GetContact(peerID string) *Contact {
	for i, c := range v.Contacts {
		if c.PeerID == peerID {
			return &v.Contacts[i]
		}
	}
	return nil
}

// UpdateContactKey updates a contact's key after migration.
func (v *Vault) UpdateContactKey(oldPeerID, newPeerID string, newPublicKeyBytes []byte) bool {
	for i, c := range v.Contacts {
		if c.PeerID == oldPeerID {
			v.Contacts[i].MigrationHistory = append(v.Contacts[i].MigrationHistory, oldPeerID)
			v.Contacts[i].PeerID = newPeerID
			v.Contacts[i].PublicKey = crypto.B64URLEncode(newPublicKeyBytes)
			v.Contacts[i].LastSeen = time.Now().UnixMilli()
			return true
		}
	}
	return false
}

// GetDisplayName returns the configured display name.
func (v *Vault) GetDisplayName() string {
	if v.Settings.DisplayName == "" {
		return "peer"
	}
	return v.Settings.DisplayName
}

// ChangePassword re-encrypts the vault with a new password.
func (v *Vault) ChangePassword(newPassword string) error {
	if v.VaultKey == nil {
		return errors.New("vault not open")
	}
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}
	v.VaultKey = crypto.DeriveVaultKey(newPassword, salt)
	return v.save(salt)
}
