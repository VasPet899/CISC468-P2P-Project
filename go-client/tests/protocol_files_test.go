package tests

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cisc468/p2p-project/internal/crypto"
	"github.com/cisc468/p2p-project/internal/protocol"
	"github.com/cisc468/p2p-project/internal/storage"
)

func TestCreateManifest(t *testing.T) {
	sk, pk, _ := crypto.GenerateIdentityKeypair()
	fileData := []byte("Hello, test file content!")
	m, err := storage.CreateManifest(sk, pk, "test.txt", fileData, "A test")
	if err != nil {
		t.Fatalf("CreateManifest: %v", err)
	}
	if m.Filename != "test.txt" {
		t.Errorf("filename = %s, want test.txt", m.Filename)
	}
	if m.SizeBytes != int64(len(fileData)) {
		t.Errorf("size = %d, want %d", m.SizeBytes, len(fileData))
	}
	if m.OwnerSignature == "" {
		t.Error("owner_signature should not be empty")
	}
}

func TestVerifyManifest(t *testing.T) {
	sk, pk, _ := crypto.GenerateIdentityKeypair()
	m, _ := storage.CreateManifest(sk, pk, "test.txt", []byte("data"), "")
	if err := storage.VerifyManifest(m, pk); err != nil {
		t.Errorf("VerifyManifest failed: %v", err)
	}
}

func TestVerifyManifestTampered(t *testing.T) {
	sk, pk, _ := crypto.GenerateIdentityKeypair()
	m, _ := storage.CreateManifest(sk, pk, "test.txt", []byte("data"), "")
	m.Filename = "tampered.txt"
	if err := storage.VerifyManifest(m, pk); err == nil {
		t.Error("expected error for tampered manifest")
	}
}

func TestVerifyManifestWrongKey(t *testing.T) {
	sk, pk, _ := crypto.GenerateIdentityKeypair()
	_, otherPK, _ := crypto.GenerateIdentityKeypair()
	m, _ := storage.CreateManifest(sk, pk, "test.txt", []byte("data"), "")
	if err := storage.VerifyManifest(m, otherPK); err == nil {
		t.Error("expected error for wrong key")
	}
}

func TestVerifyFileIntegrity(t *testing.T) {
	data := []byte("file content")
	hash := storage.ComputeFileHash(data)
	if err := storage.VerifyFileIntegrity(data, hash); err != nil {
		t.Errorf("VerifyFileIntegrity: %v", err)
	}
}

func TestVerifyFileIntegrityTampered(t *testing.T) {
	data := []byte("file content")
	hash := storage.ComputeFileHash(data)
	if err := storage.VerifyFileIntegrity(append(data, 0x00), hash); err == nil {
		t.Error("expected error for tampered file")
	}
}

func TestFileStoreRoundtrip(t *testing.T) {
	dir := tempDir(t)
	sk, pk, _ := crypto.GenerateIdentityKeypair()
	vaultKey := make([]byte, 32)
	rand.Read(vaultKey)
	fs := storage.NewFileStore(dir, vaultKey)

	fileData := []byte("test file data for storage")
	m, _ := storage.CreateManifest(sk, pk, "doc.pdf", fileData, "")
	if err := fs.StoreFile(m.FileID, fileData, m); err != nil {
		t.Fatalf("StoreFile: %v", err)
	}
	if !fs.HasFile(m.FileID) {
		t.Error("file should exist after store")
	}
	loaded, err := fs.LoadFile(m.FileID)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if !bytes.Equal(loaded, fileData) {
		t.Error("loaded file data mismatch")
	}
}

func TestFileStoreList(t *testing.T) {
	dir := tempDir(t)
	sk, pk, _ := crypto.GenerateIdentityKeypair()
	vaultKey := make([]byte, 32)
	rand.Read(vaultKey)
	fs := storage.NewFileStore(dir, vaultKey)

	m1, _ := storage.CreateManifest(sk, pk, "a.txt", []byte("a"), "")
	m2, _ := storage.CreateManifest(sk, pk, "b.txt", []byte("b"), "")
	fs.StoreFile(m1.FileID, []byte("a"), m1)
	fs.StoreFile(m2.FileID, []byte("b"), m2)

	manifests, err := fs.ListManifests()
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != 2 {
		t.Errorf("manifest count = %d, want 2", len(manifests))
	}
}

func TestBuildAndReassembleChunks(t *testing.T) {
	dir := tempDir(t)
	sk, pk, _ := crypto.GenerateIdentityKeypair()
	vaultKey := make([]byte, 32)
	rand.Read(vaultKey)
	fs := storage.NewFileStore(dir, vaultKey)

	fileData := []byte("chunk test data that should survive chunking and reassembly")
	m, _ := storage.CreateManifest(sk, pk, "test.bin", fileData, "")
	fs.StoreFile(m.FileID, fileData, m)

	chunkMsgs, err := protocol.BuildFileChunks(fs, m.FileID, 0)
	if err != nil {
		t.Fatalf("BuildFileChunks: %v", err)
	}
	// Last msg is TRANSFER_COMPLETE
	last := chunkMsgs[len(chunkMsgs)-1]
	if last["type"] != "TRANSFER_COMPLETE" {
		t.Errorf("last msg type = %v, want TRANSFER_COMPLETE", last["type"])
	}

	var chunks []map[string]interface{}
	for _, msg := range chunkMsgs {
		if msg["type"] == "TRANSFER_CHUNK" {
			chunks = append(chunks, msg)
		}
	}
	reassembled, err := protocol.ReassembleFile(chunks)
	if err != nil {
		t.Fatalf("ReassembleFile: %v", err)
	}
	if !bytes.Equal(reassembled, fileData) {
		t.Error("reassembled data mismatch")
	}
}

func TestVerifyReceivedFile(t *testing.T) {
	sk, pk, _ := crypto.GenerateIdentityKeypair()
	fileData := []byte("verify me")
	m, _ := storage.CreateManifest(sk, pk, "test.txt", fileData, "")
	pkBytes := crypto.PublicKeyToBytes(pk)
	if err := protocol.VerifyReceivedFile(fileData, m, pkBytes); err != nil {
		t.Errorf("VerifyReceivedFile: %v", err)
	}
}

func TestVerifyReceivedFileTampered(t *testing.T) {
	sk, pk, _ := crypto.GenerateIdentityKeypair()
	fileData := []byte("verify me")
	m, _ := storage.CreateManifest(sk, pk, "test.txt", fileData, "")
	pkBytes := crypto.PublicKeyToBytes(pk)
	if err := protocol.VerifyReceivedFile(append(fileData, 0x00), m, pkBytes); err == nil {
		t.Error("expected error for tampered file")
	}
}
