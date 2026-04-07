// Package network provides TCP transport with length-prefixed framing
// and mDNS peer discovery.
package network

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"

	"github.com/cisc468/p2p-project/internal/crypto"
)

const (
	HeaderSize     = 4
	MaxPayloadSize = 64 * 1024 * 1024 // 64 MB
)

// SendFrame sends a length-prefixed frame over a TCP connection.
func SendFrame(conn net.Conn, payload []byte) error {
	if len(payload) > MaxPayloadSize {
		return fmt.Errorf("payload too large: %d > %d", len(payload), MaxPayloadSize)
	}
	header := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if _, err := conn.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// RecvFrame receives a length-prefixed frame from a TCP connection.
func RecvFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	length := binary.BigEndian.Uint32(header)
	if length > MaxPayloadSize {
		return nil, fmt.Errorf("frame too large: %d > %d", length, MaxPayloadSize)
	}
	if length == 0 {
		return []byte{}, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	return payload, nil
}

// SendJSON sends a JSON object as a plaintext frame (used during handshake).
func SendJSON(conn net.Conn, obj map[string]interface{}) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	return SendFrame(conn, data)
}

// RecvJSON receives a JSON object from a plaintext frame.
func RecvJSON(conn net.Conn) (map[string]interface{}, error) {
	data, err := RecvFrame(conn)
	if err != nil {
		return nil, err
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("unmarshal JSON: %w", err)
	}
	return obj, nil
}

// SendEncrypted encrypts a JSON object and sends it as a length-prefixed frame.
func SendEncrypted(conn net.Conn, cipher *crypto.SessionCipher, obj map[string]interface{}) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	encrypted, err := cipher.Encrypt(data)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return SendFrame(conn, encrypted)
}

// RecvEncrypted receives and decrypts a JSON object from an encrypted frame.
func RecvEncrypted(conn net.Conn, cipher *crypto.SessionCipher) (map[string]interface{}, error) {
	data, err := RecvFrame(conn)
	if err != nil {
		return nil, err
	}
	plaintext, err := cipher.Decrypt(data)
	if err != nil {
		return nil, err
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(plaintext, &obj); err != nil {
		return nil, fmt.Errorf("unmarshal decrypted JSON: %w", err)
	}
	return obj, nil
}
