package tests

import (
	"bytes"
	"os"
	"testing"

	"github.com/cisc468/p2p-project/internal/crypto"
	"github.com/cisc468/p2p-project/internal/storage"
)

func tempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "p2pshare-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestVaultCreateAndOpen(t *testing.T) {
	dir := tempDir(t)
	v := storage.NewVault(dir)
	if err := v.Create("secret", "Alice"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !v.Exists() {
		t.Error("vault should exist after Create")
	}
	pid := v.PeerID()
	if len(pid) == 0 {
		t.Error("peer ID should not be empty")
	}

	v2 := storage.NewVault(dir)
	if err := v2.Open("secret"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if v2.PeerID() != pid {
		t.Errorf("peer ID mismatch after reopen: %s != %s", v2.PeerID(), pid)
	}
	if v2.GetDisplayName() != "Alice" {
		t.Errorf("display name = %s, want Alice", v2.GetDisplayName())
	}
}

func TestVaultWrongPassword(t *testing.T) {
	dir := tempDir(t)
	v := storage.NewVault(dir)
	v.Create("correct", "Bob")
	v2 := storage.NewVault(dir)
	if err := v2.Open("wrong"); err == nil {
		t.Error("expected error for wrong password")
	}
}

func TestVaultNotExists(t *testing.T) {
	dir := tempDir(t)
	v := storage.NewVault(dir)
	if err := v.Open("any"); err == nil {
		t.Error("expected error when vault does not exist")
	}
}

func TestVaultAddContact(t *testing.T) {
	dir := tempDir(t)
	v := storage.NewVault(dir)
	v.Create("pw", "Peer")

	pkBytes := make([]byte, 32)
	for i := range pkBytes {
		pkBytes[i] = byte(i)
	}
	peerID := crypto.B64URLEncode(pkBytes)
	v.AddContact(peerID, pkBytes, "Alice")
	v.Save()

	v2 := storage.NewVault(dir)
	v2.Open("pw")
	c := v2.GetContact(peerID)
	if c == nil {
		t.Fatal("contact not found after reopen")
	}
	if c.Alias != "Alice" {
		t.Errorf("alias = %s, want Alice", c.Alias)
	}
}

func TestVaultUpdateContactKey(t *testing.T) {
	dir := tempDir(t)
	v := storage.NewVault(dir)
	v.Create("pw", "Peer")

	oldPK := make([]byte, 32)
	newPK := make([]byte, 32)
	for i := range newPK {
		newPK[i] = byte(i + 1)
	}
	oldID := crypto.B64URLEncode(oldPK)
	newID := crypto.B64URLEncode(newPK)
	v.AddContact(oldID, oldPK, "Bob")

	if !v.UpdateContactKey(oldID, newID, newPK) {
		t.Error("UpdateContactKey returned false")
	}
	if v.GetContact(oldID) != nil {
		t.Error("old contact should not exist after migration")
	}
	if v.GetContact(newID) == nil {
		t.Error("new contact should exist after migration")
	}
}

func TestVaultChangePassword(t *testing.T) {
	dir := tempDir(t)
	v := storage.NewVault(dir)
	v.Create("old_pw", "Charlie")
	pid := v.PeerID()
	if err := v.ChangePassword("new_pw"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// Old password fails
	v2 := storage.NewVault(dir)
	if err := v2.Open("old_pw"); err == nil {
		t.Error("old password should no longer work")
	}

	// New password works
	v3 := storage.NewVault(dir)
	if err := v3.Open("new_pw"); err != nil {
		t.Fatalf("Open with new_pw: %v", err)
	}
	if v3.PeerID() != pid {
		t.Error("peer ID changed after password change")
	}
}

func TestVaultDirsCreated(t *testing.T) {
	dir := tempDir(t)
	v := storage.NewVault(dir)
	v.Create("pw", "Test")

	for _, sub := range []string{"files", "migrations"} {
		info, err := os.Stat(dir + "/" + sub)
		if err != nil || !info.IsDir() {
			t.Errorf("directory %s not created", sub)
		}
	}
	_ = bytes.Equal // suppress unused import
}
