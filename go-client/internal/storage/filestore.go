package storage

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/cisc468/p2p-project/internal/crypto"
)

const fileKeyInfo = "p2pshare-file-v1"

// DeriveFileKey derives a per-file AES-256-GCM key from the vault key and file_id.
func DeriveFileKey(vaultKey []byte, fileID string) ([]byte, error) {
	fileIDBytes, err := crypto.B64URLDecode(fileID)
	if err != nil {
		return nil, err
	}
	hkdfReader := hkdf.New(sha256.New, vaultKey, fileIDBytes, []byte(fileKeyInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// ComputeFileID computes file_id = base64url(SHA256(ownerID || utf8(filename) || timestamp_bytes)).
func ComputeFileID(ownerIDBytes []byte, filename string, uploadTimestamp int64) string {
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(uploadTimestamp))
	h := sha256.New()
	h.Write(ownerIDBytes)
	h.Write([]byte(filename))
	h.Write(tsBytes)
	return crypto.B64URLEncode(h.Sum(nil))
}

// ComputeFileHash computes base64url(SHA256(data)).
func ComputeFileHash(data []byte) string {
	h := sha256.Sum256(data)
	return crypto.B64URLEncode(h[:])
}

// Manifest represents a signed file manifest entry.
type Manifest struct {
	FileID          string `json:"file_id"`
	Filename        string `json:"filename"`
	SizeBytes       int64  `json:"size_bytes"`
	SHA256          string `json:"sha256"`
	OwnerID         string `json:"owner_id"`
	UploadTimestamp int64  `json:"upload_timestamp"`
	Description     string `json:"description"`
	Version         int    `json:"version"`
	OwnerSignature  string `json:"owner_signature,omitempty"`
}

// ManifestWithoutSig returns the manifest fields as a map without owner_signature for signing.
func ManifestWithoutSig(m *Manifest) map[string]interface{} {
	return map[string]interface{}{
		"file_id":          m.FileID,
		"filename":         m.Filename,
		"size_bytes":       float64(m.SizeBytes),
		"sha256":           m.SHA256,
		"owner_id":         m.OwnerID,
		"upload_timestamp": float64(m.UploadTimestamp),
		"description":      m.Description,
		"version":          float64(m.Version),
	}
}

// CreateManifest creates a signed manifest for a file.
func CreateManifest(identitySK ed25519.PrivateKey, identityPK ed25519.PublicKey,
	filename string, fileData []byte, description string) (*Manifest, error) {

	ownerIDBytes := crypto.PublicKeyToBytes(identityPK)
	uploadTS := time.Now().UnixMilli()
	fileID := ComputeFileID(ownerIDBytes, filename, uploadTS)
	fileHash := ComputeFileHash(fileData)

	m := &Manifest{
		FileID:          fileID,
		Filename:        filename,
		SizeBytes:       int64(len(fileData)),
		SHA256:          fileHash,
		OwnerID:         crypto.PeerIDFromPublicKey(identityPK),
		UploadTimestamp: uploadTS,
		Description:     description,
		Version:         1,
	}

	sigData, err := crypto.CanonicalJSON(ManifestWithoutSig(m))
	if err != nil {
		return nil, err
	}
	sig := crypto.Sign(identitySK, sigData)
	m.OwnerSignature = crypto.B64URLEncode(sig)
	return m, nil
}

// VerifyManifest verifies the owner_signature on a manifest entry.
func VerifyManifest(m *Manifest, ownerPK ed25519.PublicKey) error {
	sig, err := crypto.B64URLDecode(m.OwnerSignature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	sigData, err := crypto.CanonicalJSON(ManifestWithoutSig(m))
	if err != nil {
		return err
	}
	return crypto.Verify(ownerPK, sigData, sig)
}

// VerifyFileIntegrity checks that file data matches the expected hash.
func VerifyFileIntegrity(fileData []byte, expectedHashB64 string) error {
	actual := ComputeFileHash(fileData)
	if actual != expectedHashB64 {
		return errors.New("downloaded file is corrupted or was tampered with — file discarded")
	}
	return nil
}

// FileStore manages encrypted file storage on disk.
type FileStore struct {
	FilesDir string
	VaultKey []byte
}

// NewFileStore creates a new FileStore.
func NewFileStore(dataDir string, vaultKey []byte) *FileStore {
	dir := filepath.Join(dataDir, "files")
	os.MkdirAll(dir, 0700)
	return &FileStore{FilesDir: dir, VaultKey: vaultKey}
}

// StoreFile encrypts and stores a file and its manifest.
func (fs *FileStore) StoreFile(fileID string, fileData []byte, manifest *Manifest) error {
	fileKey, err := DeriveFileKey(fs.VaultKey, fileID)
	if err != nil {
		return err
	}
	encrypted, err := crypto.EncryptRaw(fileKey, fileData)
	if err != nil {
		return err
	}

	encPath := filepath.Join(fs.FilesDir, fileID+".enc")
	if err := os.WriteFile(encPath, encrypted, 0600); err != nil {
		return err
	}

	metaData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	metaPath := filepath.Join(fs.FilesDir, fileID+".meta")
	return os.WriteFile(metaPath, metaData, 0644)
}

// LoadFile decrypts and returns a stored file.
func (fs *FileStore) LoadFile(fileID string) ([]byte, error) {
	encPath := filepath.Join(fs.FilesDir, fileID+".enc")
	encrypted, err := os.ReadFile(encPath)
	if err != nil {
		return nil, fmt.Errorf("file %s not found in store", fileID)
	}
	fileKey, err := DeriveFileKey(fs.VaultKey, fileID)
	if err != nil {
		return nil, err
	}
	return crypto.DecryptRaw(fileKey, encrypted)
}

// LoadManifest loads a file's manifest entry.
func (fs *FileStore) LoadManifest(fileID string) (*Manifest, error) {
	metaPath := filepath.Join(fs.FilesDir, fileID+".meta")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("manifest %s not found", fileID)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ListManifests lists all stored file manifests.
func (fs *FileStore) ListManifests() ([]*Manifest, error) {
	entries, err := os.ReadDir(fs.FilesDir)
	if err != nil {
		return nil, err
	}
	var manifests []*Manifest
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".meta") {
			data, err := os.ReadFile(filepath.Join(fs.FilesDir, e.Name()))
			if err != nil {
				continue
			}
			var m Manifest
			if err := json.Unmarshal(data, &m); err != nil {
				continue
			}
			manifests = append(manifests, &m)
		}
	}
	return manifests, nil
}

// HasFile checks if a file is stored locally.
func (fs *FileStore) HasFile(fileID string) bool {
	_, err := os.Stat(filepath.Join(fs.FilesDir, fileID+".enc"))
	return err == nil
}

// StoreOwnFile reads a file from disk, creates a signed manifest, encrypts and stores it.
func (fs *FileStore) StoreOwnFile(identitySK ed25519.PrivateKey, identityPK ed25519.PublicKey,
	filePath, description string) (*Manifest, error) {

	filename := filepath.Base(filePath)
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	manifest, err := CreateManifest(identitySK, identityPK, filename, fileData, description)
	if err != nil {
		return nil, err
	}
	return manifest, fs.StoreFile(manifest.FileID, fileData, manifest)
}
