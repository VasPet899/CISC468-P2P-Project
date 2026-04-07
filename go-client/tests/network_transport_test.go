package tests

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"

	"github.com/cisc468/p2p-project/internal/crypto"
	"github.com/cisc468/p2p-project/internal/network"
)

// makeConnPair returns a connected client/server socket pair.
func makeConnPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ln.Close()
		done <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-done
	t.Cleanup(func() { client.Close(); server.Close() })
	return
}

func TestFrameRoundtrip(t *testing.T) {
	c, s := makeConnPair(t)
	payload := []byte("hello frame")
	if err := network.SendFrame(c, payload); err != nil {
		t.Fatal(err)
	}
	received, err := network.RecvFrame(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Error("frame payload mismatch")
	}
}

func TestFrameEmpty(t *testing.T) {
	c, s := makeConnPair(t)
	network.SendFrame(c, []byte{})
	received, err := network.RecvFrame(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(received) != 0 {
		t.Error("expected empty frame")
	}
}

func TestFrameLarge(t *testing.T) {
	c, s := makeConnPair(t)
	payload := make([]byte, 256*1024)
	rand.Read(payload)
	network.SendFrame(c, payload)
	received, err := network.RecvFrame(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Error("large frame payload mismatch")
	}
}

func TestJSONRoundtrip(t *testing.T) {
	c, s := makeConnPair(t)
	obj := map[string]interface{}{"type": "TEST", "value": 42.0}
	network.SendJSON(c, obj)
	received, err := network.RecvJSON(s)
	if err != nil {
		t.Fatal(err)
	}
	if received["type"] != "TEST" || received["value"] != 42.0 {
		t.Error("JSON roundtrip mismatch")
	}
}

func TestEncryptedRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	ciphSend, _ := crypto.NewSessionCipher(key)
	ciphRecv, _ := crypto.NewSessionCipher(key)

	c, s := makeConnPair(t)
	obj := map[string]interface{}{"type": "AUTH", "seq": 1.0, "secret": "data"}
	network.SendEncrypted(c, ciphSend, obj)
	received, err := network.RecvEncrypted(s, ciphRecv)
	if err != nil {
		t.Fatal(err)
	}
	if received["secret"] != "data" {
		t.Error("encrypted JSON roundtrip mismatch")
	}
}

func TestEncryptedWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)
	ciphSend, _ := crypto.NewSessionCipher(key1)
	ciphRecv, _ := crypto.NewSessionCipher(key2)

	c, s := makeConnPair(t)
	network.SendEncrypted(c, ciphSend, map[string]interface{}{"msg": "secret"})
	_, err := network.RecvEncrypted(s, ciphRecv)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}

func TestMultipleFrames(t *testing.T) {
	c, s := makeConnPair(t)
	messages := [][]byte{[]byte("first"), []byte("second"), []byte("third")}
	for _, m := range messages {
		network.SendFrame(c, m)
	}
	for _, expected := range messages {
		received, err := network.RecvFrame(s)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(received, expected) {
			t.Errorf("frame mismatch: got %s, want %s", received, expected)
		}
	}
}

func TestRecvFrameConnectionClosed(t *testing.T) {
	c, s := makeConnPair(t)
	c.Close()
	_, err := network.RecvFrame(s)
	if err == nil {
		t.Error("expected error when connection is closed")
	}
}
