# CISC468 P2P Secure File Sharing

A peer-to-peer secure file sharing application with two interoperating clients — one in **Python**, one in **Go** — that communicate over a local network using mutual authentication, end-to-end encryption, and signed file manifests.

---

## Prerequisites

| Tool | Minimum version |
|---|---|
| Python | 3.10 |
| Go | 1.22 |
| pip | any recent |

---

## Setup

### Python client

```bash
cd python-client
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .
```

### Go client

```bash
cd go-client
go mod download
go build ./cmd/p2pshare/
```

The binary is written to `go-client/p2pshare` (or `p2pshare.exe` on Windows). You can also skip the build step and use `go run ./cmd/p2pshare/` in every command below.

---

## Running two peers locally

Each peer needs its own data directory and port. Open two terminals.

**Terminal 1 — Alice (Python):**
```bash
cd python-client
python -m p2pshare init --data-dir /tmp/alice --name Alice
python -m p2pshare start --data-dir /tmp/alice --port 47890
```

**Terminal 2 — Bob (Go):**
```bash
cd go-client
./p2pshare init --data-dir /tmp/bob --name Bob
./p2pshare start --data-dir /tmp/bob --port 47891
```

Both peers will print their peer ID and fingerprint on startup and then show an interactive prompt (`>`).

> **Windows paths:** replace `/tmp/alice` and `/tmp/bob` with Windows paths such as `C:\tmp\alice` and `C:\tmp\bob`.

> **Three peers:** start a third terminal with a different `--data-dir` and `--port` (e.g. `47892`) for relay and multi-peer tests.

---

## CLI reference

All commands are entered at the `>` prompt after running `start`.

| Command | Description |
|---|---|
| `list-peers` | Show all peers discovered on the local network |
| `list-files` | List files in your own local store |
| `list-files <peer_id>` | List files available from a specific peer |
| `add-file <filepath>` | Index and encrypt a local file into your store |
| `send <peer_id> <file_id\|filename\|filepath>` | Push a file to a peer (peer must consent) |
| `request <peer_id> <file_id> [file_id ...]` | Pull one or more files from a peer (peer must consent) |
| `migrate-key` | Rotate your identity keypair and notify online contacts |
| `quit` | Shut down |

`<peer_id>` accepts a prefix — you only need to type enough characters to uniquely identify the peer.

---

## Testing each requirement

### Requirement 1 — Peer discovery

Start both peers. On either peer:
```
> list-peers
```
Expected output: the other peer listed with its display name, peer ID prefix, and address.

---

### Requirement 2 — Mutual authentication

Connect any two peers. The first time they connect (via any command that establishes a connection), each terminal prints:
```
[+] New peer added to contacts: <peer_id_prefix>... (fingerprint: <hex>)
```
Both sides print this, confirming mutual authentication via Ed25519 and TOFU contact registration. Subsequent connections print only the authenticated peer ID without re-adding.

---

### Requirement 3 — File transfer with consent

**Push (sender initiates):**

On Alice:
```
> add-file /path/to/file.txt
> list-peers
> send <bob_peer_id> file.txt
```
Bob's terminal shows:
```
Peer <alice_id>... wants to send you 'file.txt' (N bytes). Accept? [y/n]:
```
Type `y`. Alice confirms:
```
[+] File sent successfully.
```

**Pull (requester initiates):**

On Alice:
```
> list-files <bob_peer_id>
```
Bob's terminal shows a consent prompt. Type `y`. Alice receives the file list.

Then:
```
> request <bob_peer_id> <file_id>
```
Bob's terminal shows a consent prompt to send. Type `y`. Alice receives the file and prints:
```
[+] File integrity and owner signature verified.
[+] File '<filename>' saved.
```

---

### Requirement 4 — File listing

On either peer:
```
> list-files
```
Lists files in the local store (no connection needed).

```
> list-files <peer_id>
```
Connects to the peer, retrieves their signed manifest list, and displays file ID, filename, size, and owner. Bob must consent at his prompt.

---

### Requirement 5 — Offline relay

1. Start Alice (port 47890), Bob (port 47891), and Charlie (port 47892).
2. Have Charlie connect to Alice at least once so Alice is in Charlie's contact book:
   ```
   Charlie> list-files <alice_peer_id>
   ```
3. Have Bob download Alice's file:
   ```
   Bob> request <alice_peer_id> <file_id>
   ```
4. Stop Alice (`Ctrl+C`).
5. On Charlie, list Bob's files — Alice's file appears with Alice as owner:
   ```
   Charlie> list-files <bob_peer_id>
   ```
6. Request the file from Bob (the relay):
   ```
   Charlie> request <bob_peer_id> <file_id>
   ```
   Charlie's terminal prints:
   ```
   [+] File integrity and owner signature verified.
   [+] File '<filename>' saved.
   ```
   This confirms Charlie verified Alice's original `owner_signature` using Alice's key from the contact book — even though Alice is offline and Bob served the file.

---

### Requirement 6 — Key migration

On Alice:
```
> migrate-key
```
Alice generates a new keypair, sends `KEY_MIGRATION` to all online contacts, re-signs all owned file manifests, and updates her vault. Each online contact prints:
```
[+] Key migration accepted for peer <old_id>... → <new_id>...
```
Alice prints her new peer ID and fingerprint. On the next `list-peers`, Alice appears under her new peer ID.

---

### Requirement 7 — Confidentiality and integrity

All traffic between peers is encrypted with AES-256-GCM over the session key (derived from ephemeral X25519 ECDH). Files are stored encrypted at rest with a per-file key derived from the vault key.

To observe integrity protection: request a file, then manually corrupt a byte in the `.enc` file in the data directory and request again — the client will refuse to save the corrupted file and print an integrity error.

---

### Requirement 8 — Perfect forward secrecy

Each TCP connection generates fresh ephemeral X25519 keys. Verified by the unit tests (`test_handshake_each_produces_unique_session_key` / `TestHandshakeDifferentSessionKeys`), which confirm that two connections between the same peers produce different session keys.

---

### Requirement 9 — Secure local storage

The vault (identity key + contacts) is encrypted with AES-256-GCM using a key derived from your password via Argon2id. Test wrong-password rejection:

```bash
# Python
python -m p2pshare start --data-dir /tmp/alice
# enter a wrong password at the prompt → prints error and exits

# Go
./p2pshare start --data-dir /tmp/bob
# enter a wrong password at the prompt → prints error and exits
```

---

### Requirement 10 — Error handling

| Scenario | How to trigger | Expected message |
|---|---|---|
| Wrong vault password | Enter wrong password at `start` | `Incorrect password or corrupted vault file` |
| File not found on peer | `request` a file ID that doesn't exist | `File '...' is not available` |
| Transfer declined | Peer types `n` at consent prompt | `Transfer declined: User declined` |
| Unknown peer connecting | First connection from a new peer | `[+] New peer added to contacts: ... (fingerprint: ...)` |
| Peer offline | `send` or `request` to a peer not in `list-peers` | `No peer found matching '...'` |

---

## Running the tests

### Python unit tests

```bash
cd python-client
python -m pytest tests/ -v
```
83 tests covering crypto primitives, protocol messages, file transfer, migration, vault, and transport.

### Go unit tests

```bash
cd go-client
go test ./tests/... -v
```
68 tests covering the same modules from the Go side.

### Cross-language interop tests

Tests that the Python and Go implementations produce byte-identical output for all cryptographic operations, and that the full protocol works end-to-end within Python.

```bash
# Use the same venv as the Python client (deps already installed)
cd tests/interop
python -m pytest -v
```
48 tests covering Ed25519 / canonical JSON vectors, HKDF, Argon2id, AES-GCM, handshake, file transfer, offline relay, and key migration — all validated against shared fixture files that Go also reads.
