package network

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cisc468/p2p-project/internal/crypto"
	"github.com/cisc468/p2p-project/internal/protocol"
	"github.com/cisc468/p2p-project/internal/storage"
)

// ConsentFunc is a callback that prompts the user for consent. Returns true if accepted.
type ConsentFunc func(prompt string) bool

// PeerConnection represents a single authenticated, encrypted peer connection.
type PeerConnection struct {
	Conn      net.Conn
	Vault     *storage.Vault
	FileStore *storage.FileStore
	Cipher    *crypto.SessionCipher
	PeerID    string
	PeerPK    []byte // raw 32-byte Ed25519 public key
	Seq       int
	Consent   ConsentFunc
}

// NewPeerConnection creates a new peer connection wrapper.
func NewPeerConnection(conn net.Conn, vault *storage.Vault, fs *storage.FileStore, consent ConsentFunc) *PeerConnection {
	if consent == nil {
		consent = DefaultConsent
	}
	return &PeerConnection{
		Conn:      conn,
		Vault:     vault,
		FileStore: fs,
		Consent:   consent,
	}
}

func (pc *PeerConnection) nextSeq() int {
	pc.Seq++
	return pc.Seq
}

// ConnectAsInitiator performs the 4-step handshake as the initiator.
func (pc *PeerConnection) ConnectAsInitiator() error {
	hs, err := crypto.NewHandshakeInitiator(pc.Vault.IdentitySK, pc.Vault.IdentityPK)
	if err != nil {
		return err
	}

	// Step 1: send HELLO
	hello, err := hs.CreateHello()
	if err != nil {
		return err
	}
	if err := SendJSON(pc.Conn, hello); err != nil {
		return err
	}

	// Step 2: receive HELLO_ACK
	helloAck, err := RecvJSON(pc.Conn)
	if err != nil {
		return err
	}
	if err := hs.ProcessHelloAck(helloAck); err != nil {
		return err
	}

	// Derive session key
	sessionKey, err := hs.DeriveSession()
	if err != nil {
		return err
	}

	// Step 3: send AUTH
	auth, cipher, err := hs.CreateAuth(sessionKey)
	if err != nil {
		return err
	}
	pc.Cipher = cipher
	if err := SendEncrypted(pc.Conn, pc.Cipher, auth); err != nil {
		return err
	}

	// Step 4: receive AUTH_ACK
	authAck, err := RecvEncrypted(pc.Conn, pc.Cipher)
	if err != nil {
		return err
	}
	if err := hs.VerifyAuthAck(authAck); err != nil {
		return err
	}

	pc.PeerID = crypto.PeerIDFromPublicKey(hs.PeerIdentityPK)
	pc.PeerPK = crypto.PublicKeyToBytes(hs.PeerIdentityPK)
	pc.handleNewPeer()
	return nil
}

// AcceptAsResponder performs the 4-step handshake as the responder.
func (pc *PeerConnection) AcceptAsResponder() error {
	hs, err := crypto.NewHandshakeResponder(pc.Vault.IdentitySK, pc.Vault.IdentityPK)
	if err != nil {
		return err
	}

	// Step 1: receive HELLO
	hello, err := RecvJSON(pc.Conn)
	if err != nil {
		return err
	}
	if err := hs.ProcessHello(hello); err != nil {
		return err
	}

	// Step 2: send HELLO_ACK
	helloAck, err := hs.CreateHelloAck()
	if err != nil {
		return err
	}
	if err := SendJSON(pc.Conn, helloAck); err != nil {
		return err
	}

	// Derive session key
	sessionKey, err := hs.DeriveSession()
	if err != nil {
		return err
	}

	// Step 3: receive AUTH (need a temporary cipher for the first encrypted message)
	tmpCipher, err := crypto.NewSessionCipher(sessionKey)
	if err != nil {
		return err
	}
	authMsg, err := RecvEncrypted(pc.Conn, tmpCipher)
	if err != nil {
		return err
	}
	if err := hs.VerifyAuth(authMsg); err != nil {
		return err
	}

	// Step 4: send AUTH_ACK
	authAck, cipher, err := hs.CreateAuthAck(sessionKey)
	if err != nil {
		return err
	}
	pc.Cipher = cipher
	if err := SendEncrypted(pc.Conn, pc.Cipher, authAck); err != nil {
		return err
	}

	pc.PeerID = crypto.PeerIDFromPublicKey(hs.PeerIdentityPK)
	pc.PeerPK = crypto.PublicKeyToBytes(hs.PeerIdentityPK)
	pc.handleNewPeer()
	return nil
}

func (pc *PeerConnection) handleNewPeer() {
	contact := pc.Vault.GetContact(pc.PeerID)
	if contact == nil {
		pc.Vault.AddContact(pc.PeerID, pc.PeerPK, "")
		_ = pc.Vault.Save()
		peerPK, _ := crypto.BytesToPublicKey(pc.PeerPK)
		fp := crypto.Fingerprint(peerPK)
		fmt.Printf("[+] New peer added to contacts: %s... (fingerprint: %s)\n", pc.PeerID[:8], fp)
	}
}

// SendMsg sends an encrypted message.
func (pc *PeerConnection) SendMsg(msg map[string]interface{}) error {
	return SendEncrypted(pc.Conn, pc.Cipher, msg)
}

// RecvMsg receives and decrypts a message.
func (pc *PeerConnection) RecvMsg() (map[string]interface{}, error) {
	return RecvEncrypted(pc.Conn, pc.Cipher)
}

// RequestFileList requests the peer's file list.
func (pc *PeerConnection) RequestFileList() ([]map[string]interface{}, error) {
	req := protocol.ListRequest(pc.nextSeq(), nil)
	if err := pc.SendMsg(req); err != nil {
		return nil, err
	}
	resp, err := pc.RecvMsg()
	if err != nil {
		return nil, err
	}
	if resp["type"] == "ERROR" {
		return nil, fmt.Errorf("peer error: %v", resp["message"])
	}
	filesRaw, _ := resp["files"].([]interface{})
	var files []map[string]interface{}
	for _, f := range filesRaw {
		if fm, ok := f.(map[string]interface{}); ok {
			files = append(files, fm)
		}
	}
	return files, nil
}

// RequestFile requests a file from the peer (pull/download flow).
func (pc *PeerConnection) RequestFile(fileID string) ([]byte, error) {
	req := protocol.TransferRequest(pc.nextSeq(), fileID, pc.Vault.PeerID(), nil)
	if err := pc.SendMsg(req); err != nil {
		return nil, err
	}

	resp, err := pc.RecvMsg()
	if err != nil {
		return nil, err
	}
	if resp["type"] == "TRANSFER_RESPONSE" {
		accepted, _ := resp["accepted"].(bool)
		if !accepted {
			reason, _ := resp["reason"].(string)
			return nil, fmt.Errorf("transfer declined by peer: %s", reason)
		}
	} else if resp["type"] == "ERROR" {
		return nil, fmt.Errorf("peer error: %v", resp["message"])
	}

	// Receive chunks
	var chunks []map[string]interface{}
	for {
		msg, err := pc.RecvMsg()
		if err != nil {
			return nil, err
		}
		msgType, _ := msg["type"].(string)
		if msgType == "TRANSFER_CHUNK" {
			chunks = append(chunks, msg)
		} else if msgType == "TRANSFER_COMPLETE" {
			break
		} else if msgType == "ERROR" {
			return nil, fmt.Errorf("error during transfer: %v", msg["message"])
		}
	}

	return protocol.ReassembleFile(chunks)
}

// SendFile sends a file to the peer after consent is granted.
func (pc *PeerConnection) SendFile(fileID string) error {
	chunkMsgs, err := protocol.BuildFileChunks(pc.FileStore, fileID, pc.Seq)
	if err != nil {
		return err
	}
	for _, msg := range chunkMsgs {
		if err := pc.SendMsg(msg); err != nil {
			return err
		}
		if s, ok := msg["seq"].(float64); ok {
			pc.Seq = int(s)
		}
	}
	return nil
}

// HandleIncoming is the main loop for handling incoming messages.
func (pc *PeerConnection) HandleIncoming() {
	for {
		msg, err := pc.RecvMsg()
		if err != nil {
			return // Connection closed
		}
		msgType, _ := msg["type"].(string)

		switch msgType {
		case "LIST_REQUEST":
			resp, err := protocol.HandleListRequest(msg, pc.FileStore, &pc.Seq)
			if err != nil {
				pc.SendMsg(protocol.ErrorMsg(pc.nextSeq(), protocol.ProtocolErrorCode, err.Error()))
				continue
			}
			pc.SendMsg(resp)

		case "TRANSFER_REQUEST":
			pc.handleTransferRequest(msg)

		case "KEY_MIGRATION":
			pc.handleMigration(msg)

		case "ERROR":
			code, _ := msg["code"].(string)
			message, _ := msg["message"].(string)
			fmt.Printf("[!] Peer error: [%s] %s\n", code, message)

		default:
			fmt.Printf("[?] Unknown message type: %s\n", msgType)
		}
	}
}

func (pc *PeerConnection) handleTransferRequest(msg map[string]interface{}) {
	fileID, _ := msg["file_id"].(string)
	requesterID, _ := msg["requester_id"].(string)

	// Resolve file_id prefix to full file_id
	if !pc.FileStore.HasFile(fileID) {
		if manifests, err := pc.FileStore.ListManifests(); err == nil {
			for _, m := range manifests {
				if strings.HasPrefix(m.FileID, fileID) {
					fileID = m.FileID
					break
				}
			}
		}
	}

	short := requesterID
	if len(short) > 8 {
		short = short[:8]
	}

	if pc.FileStore.HasFile(fileID) {
		// Pull flow: requester wants to download this file from us
		manifest, err := pc.FileStore.LoadManifest(fileID)
		if err != nil {
			pc.SendMsg(protocol.ErrorMsg(pc.nextSeq(), protocol.FileNotFound, err.Error()))
			return
		}
		prompt := fmt.Sprintf("Peer %s... is requesting '%s'. Send it? [y/n]: ", short, manifest.Filename)
		if pc.Consent(prompt) {
			pc.SendMsg(protocol.TransferResponse(pc.nextSeq(), fileID, true, ""))
			pc.SendFile(fileID)
		} else {
			pc.SendMsg(protocol.TransferResponse(pc.nextSeq(), fileID, false, "User declined"))
		}
	} else if incomingManifest, ok := msg["manifest"].(map[string]interface{}); ok {
		// Push flow: sender wants to push a file to us
		filename, _ := incomingManifest["filename"].(string)
		sizeF, _ := incomingManifest["size_bytes"].(float64)
		if filename == "" {
			filename = fileID
			if len(filename) > 8 {
				filename = filename[:8]
			}
		}
		prompt := fmt.Sprintf("Peer %s... wants to send you '%s' (%.0f bytes). Accept? [y/n]: ", short, filename, sizeF)
		if pc.Consent(prompt) {
			pc.SendMsg(protocol.TransferResponse(pc.nextSeq(), fileID, true, ""))
			pc.receiveFile(fileID, incomingManifest)
		} else {
			pc.SendMsg(protocol.TransferResponse(pc.nextSeq(), fileID, false, "User declined"))
		}
	} else {
		pc.SendMsg(protocol.ErrorMsg(pc.nextSeq(), protocol.FileNotFound,
			fmt.Sprintf("File '%s...' is not available.", fileID[:8])))
	}
}

func (pc *PeerConnection) receiveFile(fileID string, manifestRaw map[string]interface{}) {
	var chunks []map[string]interface{}
loop:
	for {
		msg, err := pc.RecvMsg()
		if err != nil {
			return
		}
		msgType, _ := msg["type"].(string)
		switch msgType {
		case "TRANSFER_CHUNK":
			chunks = append(chunks, msg)
		case "TRANSFER_COMPLETE":
			break loop
		case "ERROR":
			fmt.Printf("[!] Error during receive: %v\n", msg["message"])
			return
		}
	}

	if len(chunks) == 0 {
		return
	}

	fileData, err := protocol.ReassembleFile(chunks)
	if err != nil {
		fmt.Printf("[!] Failed to reassemble file: %v\n", err)
		return
	}

	data, _ := json.Marshal(manifestRaw)
	var manifest storage.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		fmt.Printf("[!] Invalid manifest: %v\n", err)
		return
	}

	ownerID := manifest.OwnerID
	contact := pc.Vault.GetContact(ownerID)
	if contact != nil {
		ownerPKBytes, _ := crypto.B64URLDecode(contact.PublicKey)
		if err := protocol.VerifyReceivedFile(fileData, &manifest, ownerPKBytes); err != nil {
			fmt.Printf("[!] %v\n", err)
			return
		}
		fmt.Println("[+] File integrity and owner signature verified.")
	} else {
		ownerShort := ownerID
		if len(ownerShort) > 8 {
			ownerShort = ownerShort[:8]
		}
		fmt.Printf("[!] Warning: Cannot verify owner — %s... not in contacts.\n", ownerShort)
	}

	if err := pc.FileStore.StoreFile(fileID, fileData, &manifest); err != nil {
		fmt.Printf("[!] Failed to store file: %v\n", err)
		return
	}
	fmt.Printf("[+] Received file '%s' saved.\n", manifest.Filename)
}

func (pc *PeerConnection) handleMigration(msg map[string]interface{}) {
	oldPeerID, _ := msg["old_peer_id"].(string)
	contact := pc.Vault.GetContact(oldPeerID)
	if contact == nil {
		pc.SendMsg(protocol.MigrationAck(pc.nextSeq(), false, "Unknown peer"))
		return
	}

	oldPKBytes, err := crypto.B64URLDecode(contact.PublicKey)
	if err != nil {
		pc.SendMsg(protocol.MigrationAck(pc.nextSeq(), false, "Invalid stored key"))
		return
	}

	newPKBytes, err := protocol.VerifyMigration(msg, oldPKBytes)
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		pc.SendMsg(protocol.MigrationAck(pc.nextSeq(), false, err.Error()))
		return
	}

	newPeerID, _ := msg["new_peer_id"].(string)
	pc.Vault.UpdateContactKey(oldPeerID, newPeerID, newPKBytes)
	pc.Vault.Save()
	fmt.Printf("[+] Key migration accepted for peer %s... → %s...\n", oldPeerID[:8], newPeerID[:8])
	pc.SendMsg(protocol.MigrationAck(pc.nextSeq(), true, ""))
}

// DefaultConsent prompts the user via stdin.
func DefaultConsent(prompt string) bool {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes"
}

// Close closes the connection.
func (pc *PeerConnection) Close() {
	pc.Conn.Close()
}
