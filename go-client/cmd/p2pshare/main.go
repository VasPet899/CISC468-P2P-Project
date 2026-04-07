// CLI entry point for the Go P2P file sharing client.
//
// Usage:
//
//	go run ./cmd/p2pshare init --data-dir DIR --name NAME
//	go run ./cmd/p2pshare start --data-dir DIR --port PORT --name NAME
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cisc468/p2p-project/internal/crypto"
	"github.com/cisc468/p2p-project/internal/network"
	"github.com/cisc468/p2p-project/internal/protocol"
	"github.com/cisc468/p2p-project/internal/storage"
)

const defaultPort = 47890

type consentRequest struct {
	prompt string
	reply  chan bool
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "init":
		cmdInit(os.Args[2:])
	case "start":
		cmdStart(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: p2pshare <command> [flags]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  init    Create a new vault")
	fmt.Println("  start   Start the peer")
}

func getDataDir(fs *flag.FlagSet, flagVal string) string {
	if env := os.Getenv("P2PSHARE_DATA_DIR"); env != "" {
		return env
	}
	return flagVal
}

func getPort(flagVal int) int {
	if env := os.Getenv("P2PSHARE_PORT"); env != "" {
		if p, err := strconv.Atoi(env); err == nil {
			return p
		}
	}
	return flagVal
}

func getPassword(testMode bool) string {
	if testMode {
		if pw := os.Getenv("P2PSHARE_PASSWORD"); pw != "" {
			return pw
		}
	}
	fmt.Print("Vault password: ")
	// Read password (no echo on Unix; on Windows this is a best-effort)
	reader := bufio.NewReader(os.Stdin)
	pw, _ := reader.ReadString('\n')
	return strings.TrimSpace(pw)
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "Data directory")
	name := fs.String("name", "peer", "Display name")
	testMode := fs.Bool("test-mode", false, "Enable test mode")
	fs.Parse(args)

	dir := getDataDir(fs, *dataDir)
	vault := storage.NewVault(dir)
	if vault.Exists() {
		fmt.Println("[!] Vault already exists. Delete it first to re-initialize.")
		return
	}

	password := getPassword(*testMode)
	if err := vault.Create(password, *name); err != nil {
		fmt.Printf("[!] Error creating vault: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Vault created at %s\n", dir)
	fmt.Printf("[+] Peer ID: %s\n", vault.PeerID())
	fmt.Printf("[+] Fingerprint: %s\n", crypto.Fingerprint(vault.IdentityPK))
}

func cmdStart(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "Data directory")
	port := fs.Int("port", defaultPort, "TCP port")
	name := fs.String("name", "", "Display name override")
	testMode := fs.Bool("test-mode", false, "Enable test mode")
	fs.Parse(args)

	dir := getDataDir(fs, *dataDir)
	listenPort := getPort(*port)

	vault := storage.NewVault(dir)
	password := getPassword(*testMode)
	if err := vault.Open(password); err != nil {
		fmt.Printf("[!] %v\n", err)
		os.Exit(1)
	}

	if *name != "" {
		vault.Settings.DisplayName = *name
	}

	fileStore := storage.NewFileStore(dir, vault.VaultKey)

	fmt.Printf("[+] Identity: %s... (fingerprint: %s)\n", vault.PeerID()[:16], crypto.Fingerprint(vault.IdentityPK))
	fmt.Printf("[+] Display name: %s\n", vault.GetDisplayName())

	// Start mDNS
	discovery := network.NewPeerDiscovery(vault.GetDisplayName(), vault.PeerID(), listenPort)
	if err := discovery.Start(); err != nil {
		fmt.Printf("[!] mDNS error: %v\n", err)
		os.Exit(1)
	}
	defer discovery.Stop()
	fmt.Printf("[+] mDNS registered on port %d\n", listenPort)

	// Start TCP listener
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", listenPort))
	if err != nil {
		fmt.Printf("[!] Listen error: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("[+] Listening on port %d\n", listenPort)

	var connections []*network.PeerConnection
	var connMu sync.Mutex

	// Queue-based consent: background goroutines send a request and block on the reply channel.
	// Only the main goroutine reads stdin.
	consentCh := make(chan consentRequest)

	sharedConsent := func(prompt string) bool {
		reply := make(chan bool, 1)
		consentCh <- consentRequest{prompt: prompt, reply: reply}
		return <-reply
	}

	scanner := bufio.NewScanner(os.Stdin)

	// Accept loop
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			fmt.Printf("\n[+] Incoming connection from %s\n", conn.RemoteAddr())
			go func(c net.Conn) {
				pc := network.NewPeerConnection(c, vault, fileStore, sharedConsent)
				if err := pc.AcceptAsResponder(); err != nil {
					fmt.Printf("[!] Handshake failed: %v\n", err)
					c.Close()
					return
				}
				fmt.Printf("[+] Authenticated peer: %s...\n", pc.PeerID[:16])
				connMu.Lock()
				connections = append(connections, pc)
				connMu.Unlock()
				pc.HandleIncoming()
			}(conn)
		}
	}()

	// Interactive command loop
	fmt.Println()
	fmt.Println("Commands: list-peers, list-files [peer_id], send <peer_id> <file_id|filename|filepath>,")
	fmt.Println("          request <peer_id> <file_id> [file_id ...], add-file <filepath>, migrate-key, quit")
	fmt.Println()

	// Read stdin lines in a separate goroutine and send them to a channel,
	// so the main loop can select between user commands and consent requests.
	lineCh := make(chan string)
	go func() {
		for scanner.Scan() {
			lineCh <- scanner.Text()
		}
		close(lineCh)
	}()

	fmt.Print("> ")
	for {
		var line string
		var ok bool

		// Wait for either a consent request or a stdin line
		select {
		case req := <-consentCh:
			// Background thread needs consent — prompt and read answer
			fmt.Print(req.prompt)
			answer, lineOk := <-lineCh
			if !lineOk {
				req.reply <- false
				goto cleanup
			}
			answer = strings.TrimSpace(strings.ToLower(answer))
			req.reply <- (answer == "y" || answer == "yes")
			fmt.Print("> ")
			continue
		case line, ok = <-lineCh:
			if !ok {
				goto cleanup
			}
		}

		line = strings.TrimSpace(line)
		if line == "" {
			fmt.Print("> ")
			continue
		}

		parts := strings.SplitN(line, " ", 3)
		cmd := strings.ToLower(parts[0])

		switch cmd {
		case "quit", "exit":
			goto cleanup

		case "list-peers":
			peers := discovery.GetPeers()
			if len(peers) == 0 {
				fmt.Println("  No peers discovered.")
			}
			for _, p := range peers {
				fmt.Printf("  %s... (%s) at %s:%d\n", p.PeerID[:16], p.Name, p.Host, p.Port)
			}

		case "list-files":
			if len(parts) < 2 {
				// List own files
				manifests, _ := fileStore.ListManifests()
				if len(manifests) == 0 {
					fmt.Println("  No files in local store.")
				}
				for _, m := range manifests {
					fid := m.FileID
					if len(fid) > 12 {
						fid = fid[:12]
					}
					fmt.Printf("  [%s...] %s (%d bytes)\n", fid, m.Filename, m.SizeBytes)
				}
				continue
			}
			peerIDPrefix := parts[1]
			pc := connectToPeer(peerIDPrefix, discovery, vault, fileStore)
			if pc == nil {
				continue
			}
			files, err := pc.RequestFileList()
			if err != nil {
				fmt.Printf("  [!] Error: %v\n", err)
			} else if len(files) == 0 {
				fmt.Println("  No files available from peer.")
			} else {
				for _, f := range files {
					fid, _ := f["file_id"].(string)
					fname, _ := f["filename"].(string)
					sizeF, _ := f["size_bytes"].(float64)
					ownerID, _ := f["owner_id"].(string)
					if len(fid) > 12 {
						fid = fid[:12]
					}
					if len(ownerID) > 8 {
						ownerID = ownerID[:8]
					}
					fmt.Printf("  [%s...] %s (%.0f bytes) owner=%s...\n", fid, fname, sizeF, ownerID)
				}
			}
			pc.Close()

		case "request":
			if len(parts) < 3 {
				fmt.Println("  Usage: request <peer_id> <file_id> [file_id ...]")
				continue
			}
			peerIDPrefix := parts[1]
			fileIDs := strings.Fields(parts[2])

			pc := connectToPeer(peerIDPrefix, discovery, vault, fileStore)
			if pc == nil {
				continue
			}
			// Fetch file list once for manifest lookups
			peerFiles, _ := pc.RequestFileList()

			for _, fileID := range fileIDs {
				fileData, err := pc.RequestFile(fileID)
				if err != nil {
					fmt.Printf("  [!] %v\n", err)
					continue
				}
				// Find manifest by prefix match
				var manifest *storage.Manifest
				for _, f := range peerFiles {
					if fid, _ := f["file_id"].(string); fid == fileID || strings.HasPrefix(fid, fileID) {
						data, _ := json.Marshal(f)
						var m storage.Manifest
						json.Unmarshal(data, &m)
						manifest = &m
						break
					}
				}
				if manifest != nil {
					ownerID := manifest.OwnerID
					contact := vault.GetContact(ownerID)
					if contact != nil {
						ownerPKBytes, _ := crypto.B64URLDecode(contact.PublicKey)
						if err := protocol.VerifyReceivedFile(fileData, manifest, ownerPKBytes); err != nil {
							fmt.Printf("  [!] %v\n", err)
							continue
						}
						fmt.Println("  [+] File integrity and owner signature verified.")
					} else {
						short := ownerID
						if len(short) > 8 {
							short = short[:8]
						}
						fmt.Printf("  [!] Warning: Cannot verify owner signature — owner %s... not in contacts.\n", short)
					}
					fileStore.StoreFile(manifest.FileID, fileData, manifest)
					fmt.Printf("  [+] File '%s' saved.\n", manifest.Filename)
				} else {
					short := fileID
					if len(short) > 8 {
						short = short[:8]
					}
					fmt.Printf("  [!] Could not find manifest for file %s...\n", short)
				}
			}
			pc.Close()

		case "send":
			if len(parts) < 3 {
				fmt.Println("  Usage: send <peer_id> <file_id|filename|filepath>")
				continue
			}
			peerIDPrefix := parts[1]
			fileArg := parts[2]

			// Resolve file: filesystem path first, then local store lookup by id/name
			var manifest *storage.Manifest
			if _, err := os.Stat(fileArg); err == nil {
				m, err := fileStore.StoreOwnFile(vault.IdentitySK, vault.IdentityPK, fileArg, "")
				if err != nil {
					fmt.Printf("  [!] Error indexing file: %v\n", err)
					continue
				}
				manifest = m
				fid := manifest.FileID
				if len(fid) > 12 {
					fid = fid[:12]
				}
				fmt.Printf("  [+] File indexed: %s...\n", fid)
			} else {
				allManifests, _ := fileStore.ListManifests()
				for _, m := range allManifests {
					if strings.HasPrefix(m.FileID, fileArg) || m.Filename == fileArg {
						manifest = m
						break
					}
				}
				if manifest == nil {
					fmt.Printf("  [!] File not found: %s\n", fileArg)
					continue
				}
			}

			// Build manifest map to include in TRANSFER_REQUEST (push signal)
			manifestData, _ := json.Marshal(manifest)
			var manifestMap map[string]interface{}
			json.Unmarshal(manifestData, &manifestMap)

			pc := connectToPeer(peerIDPrefix, discovery, vault, fileStore)
			if pc == nil {
				continue
			}
			req := protocol.TransferRequest(pc.Seq+1, manifest.FileID, vault.PeerID(), manifestMap)
			pc.Seq++
			if err := pc.SendMsg(req); err != nil {
				fmt.Printf("  [!] Send error: %v\n", err)
				pc.Close()
				continue
			}
			resp, err := pc.RecvMsg()
			if err != nil {
				fmt.Printf("  [!] Receive error: %v\n", err)
				pc.Close()
				continue
			}
			if resp["type"] == "TRANSFER_RESPONSE" {
				accepted, _ := resp["accepted"].(bool)
				if accepted {
					if err := pc.SendFile(manifest.FileID); err != nil {
						fmt.Printf("  [!] Transfer error: %v\n", err)
					} else {
						fmt.Println("  [+] File sent successfully.")
					}
				} else {
					reason, _ := resp["reason"].(string)
					if reason == "" {
						reason, _ = resp["message"].(string)
					}
					fmt.Printf("  [!] Transfer declined: %s\n", reason)
				}
			}
			pc.Close()

		case "add-file":
			if len(parts) < 2 {
				fmt.Println("  Usage: add-file <filepath>")
				continue
			}
			filePath := parts[1]
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				fmt.Printf("  [!] File not found: %s\n", filePath)
				continue
			}
			manifest, err := fileStore.StoreOwnFile(vault.IdentitySK, vault.IdentityPK, filePath, "")
			if err != nil {
				fmt.Printf("  [!] Error: %v\n", err)
				continue
			}
			fid := manifest.FileID
			if len(fid) > 12 {
				fid = fid[:12]
			}
			fmt.Printf("  [+] File added: [%s...] %s\n", fid, manifest.Filename)

		case "migrate-key":
			doMigrateKey(vault, fileStore, discovery)

		default:
			fmt.Printf("  Unknown command: %s\n", cmd)
		}
		fmt.Print("> ")
	}

cleanup:
	fmt.Println("[+] Shutting down...")
	connMu.Lock()
	for _, pc := range connections {
		pc.Close()
	}
	connMu.Unlock()
}

func connectToPeer(peerIDPrefix string, discovery *network.PeerDiscovery,
	vault *storage.Vault, fileStore *storage.FileStore) *network.PeerConnection {

	peers := discovery.GetPeers()
	var matched []*network.DiscoveredPeer
	for _, p := range peers {
		if strings.HasPrefix(p.PeerID, peerIDPrefix) {
			matched = append(matched, p)
		}
	}
	if len(matched) == 0 {
		fmt.Printf("  [!] No peer found matching '%s'\n", peerIDPrefix)
		return nil
	}
	if len(matched) > 1 {
		fmt.Println("  [!] Ambiguous peer ID prefix. Matches:")
		for _, p := range matched {
			fmt.Printf("    %s...\n", p.PeerID[:16])
		}
		return nil
	}

	peer := matched[0]
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", peer.Host, peer.Port), 10*time.Second)
	if err != nil {
		fmt.Printf("  [!] Could not connect to %s: %v\n", peer.Name, err)
		return nil
	}
	pc := network.NewPeerConnection(conn, vault, fileStore, nil)
	if err := pc.ConnectAsInitiator(); err != nil {
		fmt.Printf("  [!] Handshake failed: %v\n", err)
		conn.Close()
		return nil
	}
	fmt.Printf("  [+] Connected to %s (%s...)\n", peer.Name, peer.PeerID[:16])
	return pc
}

func doMigrateKey(vault *storage.Vault, fileStore *storage.FileStore, discovery *network.PeerDiscovery) {
	fmt.Println("[*] Generating new identity keypair...")
	newSK, newPK, err := crypto.GenerateIdentityKeypair()
	if err != nil {
		fmt.Printf("[!] Keygen error: %v\n", err)
		return
	}

	migrationMsg, err := protocol.CreateMigration(
		vault.IdentitySK, vault.IdentityPK,
		newSK, newPK,
		"scheduled_rotation",
	)
	if err != nil {
		fmt.Printf("[!] Migration creation error: %v\n", err)
		return
	}

	notified := 0
	for _, contact := range vault.Contacts {
		peer := discovery.GetPeer(contact.PeerID)
		if peer == nil {
			fmt.Printf("  [-] %s (%s...) is offline — will notify later.\n", contact.Alias, contact.PeerID[:8])
			continue
		}
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", peer.Host, peer.Port), 10*time.Second)
		if err != nil {
			fmt.Printf("  [!] Failed to connect to %s: %v\n", contact.Alias, err)
			continue
		}
		pc := network.NewPeerConnection(conn, vault, fileStore, nil)
		if err := pc.ConnectAsInitiator(); err != nil {
			fmt.Printf("  [!] Handshake failed with %s: %v\n", contact.Alias, err)
			conn.Close()
			continue
		}
		if err := pc.SendMsg(migrationMsg); err != nil {
			fmt.Printf("  [!] Send error for %s: %v\n", contact.Alias, err)
			pc.Close()
			continue
		}
		ack, err := pc.RecvMsg()
		if err != nil {
			fmt.Printf("  [!] No ack from %s: %v\n", contact.Alias, err)
			pc.Close()
			continue
		}
		accepted, _ := ack["accepted"].(bool)
		if accepted {
			fmt.Printf("  [+] %s accepted key migration.\n", contact.Alias)
			notified++
		} else {
			reason, _ := ack["reason"].(string)
			fmt.Printf("  [!] %s rejected: %s\n", contact.Alias, reason)
		}
		pc.Close()
	}

	// Save old peer ID before updating vault
	oldPeerID := vault.PeerID()

	// Update vault
	vault.IdentitySK = newSK
	vault.IdentityPK = newPK
	vault.Save()

	// Re-sign owned file manifests with new key
	manifests, _ := fileStore.ListManifests()
	resigned := 0
	for _, m := range manifests {
		if m.OwnerID == oldPeerID {
			m.OwnerID = vault.PeerID()
			m.OwnerSignature = ""
			sigData, err := crypto.CanonicalJSON(storage.ManifestWithoutSig(m))
			if err != nil {
				fmt.Printf("  [!] Failed to re-sign %s: %v\n", m.FileID[:8], err)
				continue
			}
			sig := crypto.Sign(newSK, sigData)
			m.OwnerSignature = crypto.B64URLEncode(sig)
			metaData, _ := json.MarshalIndent(m, "", "  ")
			metaPath := filepath.Join(fileStore.FilesDir, m.FileID+".meta")
			os.WriteFile(metaPath, metaData, 0644)
			resigned++
		}
	}
	if resigned > 0 {
		fmt.Printf("[+] Re-signed %d file manifest(s) with new key.\n", resigned)
	}

	fmt.Printf("[+] Key migration complete. Notified %d/%d contacts.\n", notified, len(vault.Contacts))
	fmt.Printf("[+] New peer ID: %s\n", vault.PeerID())
	fmt.Printf("[+] New fingerprint: %s\n", crypto.Fingerprint(vault.IdentityPK))
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".p2pshare"
	}
	return filepath.Join(home, ".p2pshare")
}

// Unused import guard — syscall used for potential future password reading without echo.
var _ = syscall.Stdin
