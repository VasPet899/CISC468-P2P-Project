"""CLI entry point for the Python P2P file sharing client.

Usage:
    python -m p2pshare init --data-dir DIR --name NAME
    python -m p2pshare start --data-dir DIR --port PORT --name NAME
"""

import argparse
import getpass
import os
import queue
import socket
import sys
import threading
import json
import time

from p2pshare.storage.vault import Vault
from p2pshare.storage.file_store import FileStore
from p2pshare.network.discovery import PeerDiscovery
from p2pshare.network.peer import PeerConnection
from p2pshare.protocol import messages
from p2pshare.protocol.files import verify_received_file
from p2pshare.protocol.migration import create_migration
from p2pshare.crypto.keys import (
    generate_identity_keypair,
    public_key_to_bytes,
    b64url_decode,
    b64url_encode,
    peer_id_from_public_key,
    fingerprint,
)
from p2pshare.crypto.signing import canonical_json, sign
from p2pshare.errors import P2PShareError


DEFAULT_PORT = 47890
DEFAULT_DATA_DIR = os.path.expanduser("~/.p2pshare")


def get_data_dir(args) -> str:
    return os.environ.get("P2PSHARE_DATA_DIR", args.data_dir)


def get_port(args) -> int:
    env_port = os.environ.get("P2PSHARE_PORT")
    if env_port:
        return int(env_port)
    return args.port


def get_password(args) -> str:
    if getattr(args, "test_mode", False):
        env_pw = os.environ.get("P2PSHARE_PASSWORD")
        if env_pw:
            return env_pw
    return getpass.getpass("Vault password: ")


def cmd_init(args):
    """Initialize a new vault."""
    data_dir = get_data_dir(args)
    vault = Vault(data_dir)
    if vault.exists():
        print("[!] Vault already exists. Delete it first to re-initialize.")
        return

    password = get_password(args)
    name = args.name or "peer"
    vault.create(password, name)
    print(f"[+] Vault created at {data_dir}")
    print(f"[+] Peer ID: {vault.peer_id}")
    print(f"[+] Fingerprint: {fingerprint(vault.identity_pk)}")


def cmd_start(args):
    """Start the peer — listen for connections and accept interactive commands."""
    data_dir = get_data_dir(args)
    port = get_port(args)
    vault = Vault(data_dir)
    password = get_password(args)
    vault.open(password)

    file_store = FileStore(data_dir, vault.vault_key)

    print(f"[+] Identity: {vault.peer_id[:16]}... (fingerprint: {fingerprint(vault.identity_pk)})")
    print(f"[+] Display name: {vault.get_display_name()}")

    # Start mDNS discovery
    discovery = PeerDiscovery(vault.get_display_name(), vault.peer_id, port)
    discovery.start()
    print(f"[+] mDNS registered on port {port}")

    # Start TCP listener
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", port))
    server_sock.listen(5)
    print(f"[+] Listening on port {port}")

    # Queue-based consent: background threads post (prompt, event, result_list) tuples
    # and the main loop is the only thread that reads stdin.
    consent_queue = queue.Queue()

    def shared_consent(prompt: str) -> bool:
        """Consent callback used by background threads — never reads stdin directly."""
        event = threading.Event()
        result = [False]
        consent_queue.put((prompt, event, result))
        event.wait()  # block until main loop answers
        return result[0]

    # Accept connections in background
    connections: list[PeerConnection] = []

    def accept_loop():
        while True:
            try:
                client_sock, addr = server_sock.accept()
                print(f"\n[+] Incoming connection from {addr}")
                pc = PeerConnection(client_sock, vault, file_store, consent_callback=shared_consent)
                try:
                    pc.accept_as_responder()
                    print(f"[+] Authenticated peer: {pc.peer_id[:16]}...")
                    connections.append(pc)
                    t = threading.Thread(target=pc.handle_incoming, daemon=True)
                    t.start()
                except P2PShareError as e:
                    print(f"[!] Handshake failed: {e}")
                    client_sock.close()
            except OSError:
                break

    accept_thread = threading.Thread(target=accept_loop, daemon=True)
    accept_thread.start()

    # Interactive command loop
    print("\nCommands: list-peers, list-files [peer_id], send <peer_id> <file_id|filename|filepath>,")
    print("          request <peer_id> <file_id> [file_id ...], add-file <filepath>, migrate-key, quit\n")

    # Read stdin in a dedicated thread so the main loop can multiplex
    # between user commands and consent prompts without deadlocking.
    line_queue: queue.Queue[str | None] = queue.Queue()

    def stdin_reader():
        try:
            for raw in sys.stdin:
                line_queue.put(raw)
        except Exception:
            pass
        line_queue.put(None)  # EOF sentinel

    threading.Thread(target=stdin_reader, daemon=True).start()

    print("> ", end="", flush=True)
    try:
        while True:
            # Check for pending consent requests first
            try:
                prompt, event, result = consent_queue.get_nowait()
                print(prompt, end="", flush=True)
                raw = line_queue.get()
                if raw is None:
                    result[0] = False
                    event.set()
                    break
                answer = raw.strip().lower()
                result[0] = answer in ("y", "yes")
                event.set()
                print("> ", end="", flush=True)
                continue
            except queue.Empty:
                pass

            # Wait briefly for a stdin line, then loop back to check consent queue
            try:
                raw = line_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if raw is None:
                break
            line = raw.strip()
            if not line:
                print("> ", end="", flush=True)
                continue

            parts = line.split(maxsplit=2)
            cmd = parts[0].lower()

            if cmd == "quit" or cmd == "exit":
                break

            elif cmd == "list-peers":
                peers = discovery.get_peers()
                if not peers:
                    print("  No peers discovered.")
                for p in peers:
                    print(f"  {p.peer_id[:16]}... ({p.name}) at {p.host}:{p.port}")

            elif cmd == "list-files":
                if len(parts) < 2:
                    # List own files
                    manifests = file_store.list_manifests()
                    if not manifests:
                        print("  No files in local store.")
                    for m in manifests:
                        print(f"  [{m['file_id'][:12]}...] {m['filename']} ({m['size_bytes']} bytes)")
                    continue

                peer_id_prefix = parts[1]
                pc = _connect_to_peer(peer_id_prefix, discovery, vault, file_store)
                if pc is None:
                    continue
                try:
                    files = pc.request_file_list()
                    if not files:
                        print("  No files available from peer.")
                    for f in files:
                        print(f"  [{f['file_id'][:12]}...] {f['filename']} ({f.get('size_bytes', '?')} bytes) owner={f.get('owner_id', '?')[:8]}...")
                finally:
                    pc.close()

            elif cmd == "request":
                if len(parts) < 3:
                    print("  Usage: request <peer_id> <file_id> [file_id ...]")
                    continue
                peer_id_prefix = parts[1]
                file_ids = parts[2].split()

                pc = _connect_to_peer(peer_id_prefix, discovery, vault, file_store)
                if pc is None:
                    continue
                try:
                    # Fetch file list once for manifest lookups
                    peer_files = pc.request_file_list()

                    for file_id in file_ids:
                        file_data = pc.request_file(file_id)
                        if file_data is None:
                            continue

                        # Find manifest by prefix match
                        manifest = None
                        for f in peer_files:
                            fid = f.get("file_id", "")
                            if fid == file_id or fid.startswith(file_id):
                                manifest = f
                                break

                        if manifest:
                            owner_id = manifest.get("owner_id", "")
                            contact = vault.get_contact(owner_id)
                            if contact:
                                owner_pk_bytes = b64url_decode(contact["public_key"])
                                try:
                                    verify_received_file(file_data, manifest, owner_pk_bytes)
                                    print(f"  [+] File integrity and owner signature verified.")
                                except P2PShareError as e:
                                    print(f"  [!] {e}")
                                    continue
                            else:
                                print(f"  [!] Warning: Cannot verify owner signature — owner {owner_id[:8]}... not in contacts.")

                            file_store.store_file(manifest.get("file_id", file_id), file_data, manifest)
                            print(f"  [+] File '{manifest.get('filename', file_id[:8])}' saved.")
                        else:
                            print(f"  [!] Could not find manifest for file {file_id[:8]}...")
                finally:
                    pc.close()

            elif cmd == "send":
                if len(parts) < 3:
                    print("  Usage: send <peer_id> <file_id|filename|filepath>")
                    continue
                peer_id_prefix = parts[1]
                file_arg = parts[2]

                # Resolve file: filesystem path first, then local store lookup by id/name
                manifest = None
                if os.path.exists(file_arg):
                    manifest = file_store.store_own_file(vault.identity_sk, vault.identity_pk, file_arg)
                    print(f"  [+] File indexed: {manifest['file_id'][:12]}...")
                else:
                    for m in file_store.list_manifests():
                        if m["file_id"].startswith(file_arg) or m["filename"] == file_arg:
                            manifest = m
                            break
                    if manifest is None:
                        print(f"  [!] File not found: {file_arg}")
                        continue

                file_id = manifest["file_id"]

                pc = _connect_to_peer(peer_id_prefix, discovery, vault, file_store)
                if pc is None:
                    continue
                try:
                    # Send transfer request with manifest so receiver knows it's a push
                    req = messages.transfer_request(pc._next_seq(), file_id, vault.peer_id, manifest)
                    pc.send_msg(req)
                    resp = pc.recv_msg()
                    if resp.get("type") == "TRANSFER_RESPONSE" and resp.get("accepted"):
                        pc.send_file(file_id)
                        print(f"  [+] File sent successfully.")
                    else:
                        reason = resp.get("reason", resp.get("message", "Unknown"))
                        print(f"  [!] Transfer declined: {reason}")
                finally:
                    pc.close()

            elif cmd == "add-file":
                if len(parts) < 2:
                    print("  Usage: add-file <filepath>")
                    continue
                filepath = parts[1]
                if not os.path.exists(filepath):
                    print(f"  [!] File not found: {filepath}")
                    continue
                manifest = file_store.store_own_file(vault.identity_sk, vault.identity_pk, filepath)
                print(f"  [+] File added: [{manifest['file_id'][:12]}...] {manifest['filename']}")

            elif cmd == "migrate-key":
                _do_migrate_key(vault, file_store, discovery)

            else:
                print(f"  Unknown command: {cmd}")

            print("> ", end="", flush=True)

    except KeyboardInterrupt:
        print("\n[+] Shutting down...")

    # Cleanup
    for pc in connections:
        pc.close()
    discovery.stop()
    server_sock.close()


def _connect_to_peer(peer_id_prefix: str, discovery: PeerDiscovery,
                     vault: Vault, file_store: FileStore) -> PeerConnection | None:
    """Find a peer by ID prefix and establish an authenticated connection."""
    peers = discovery.get_peers()
    matched = [p for p in peers if p.peer_id.startswith(peer_id_prefix)]
    if not matched:
        print(f"  [!] No peer found matching '{peer_id_prefix}'")
        return None
    if len(matched) > 1:
        print(f"  [!] Ambiguous peer ID prefix. Matches:")
        for p in matched:
            print(f"    {p.peer_id[:16]}...")
        return None

    peer = matched[0]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    pc = PeerConnection(sock, vault, file_store)
    try:
        pc.connect_as_initiator(peer.host, peer.port)
        sock.settimeout(None)  # Switch to blocking after handshake (consent may take time)
        print(f"  [+] Connected to {peer.name} ({peer.peer_id[:16]}...)")
        return pc
    except Exception as e:
        print(f"  [!] Could not connect to {peer.name}: {e}")
        sock.close()
        return None


def _do_migrate_key(vault: Vault, file_store: FileStore, discovery: PeerDiscovery):
    """Perform key migration: generate new keypair, notify contacts."""
    print("[*] Generating new identity keypair...")
    new_sk, new_pk = generate_identity_keypair()
    migration_msg = create_migration(
        vault.identity_sk, vault.identity_pk,
        new_sk, new_pk,
        reason="scheduled_rotation",
    )

    # Notify online contacts
    notified = 0
    for contact in vault.contacts:
        peer = discovery.get_peer(contact["peer_id"])
        if peer is None:
            print(f"  [-] {contact['alias']} ({contact['peer_id'][:8]}...) is offline — will notify later.")
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        pc = PeerConnection(sock, vault, file_store)
        try:
            pc.connect_as_initiator(peer.host, peer.port)
            pc.send_msg(migration_msg)
            ack = pc.recv_msg()
            if ack.get("accepted"):
                print(f"  [+] {contact['alias']} accepted key migration.")
                notified += 1
            else:
                print(f"  [!] {contact['alias']} rejected: {ack.get('reason', '?')}")
        except Exception as e:
            print(f"  [!] Failed to notify {contact['alias']}: {e}")
        finally:
            pc.close()

    # Save old peer_id before updating vault
    old_peer_id = vault.peer_id
    new_peer_id = peer_id_from_public_key(new_pk)

    # Update vault with new key
    vault.identity_sk = new_sk
    vault.identity_pk = new_pk
    vault.save()

    # Re-sign owned file manifests with new key
    manifests = file_store.list_manifests()
    resigned = 0
    for m in manifests:
        if m.get("owner_id") == old_peer_id:
            m["owner_id"] = new_peer_id
            m.pop("owner_signature", None)
            sig = sign(new_sk, canonical_json(m))
            m["owner_signature"] = b64url_encode(sig)
            meta_path = os.path.join(file_store.files_dir, f"{m['file_id']}.meta")
            with open(meta_path, "w") as f:
                json.dump(m, f, indent=2)
            resigned += 1
    if resigned:
        print(f"[+] Re-signed {resigned} file manifest(s) with new key.")

    print(f"[+] Key migration complete. Notified {notified}/{len(vault.contacts)} contacts.")
    print(f"[+] New peer ID: {vault.peer_id}")
    print(f"[+] New fingerprint: {fingerprint(vault.identity_pk)}")


def main():
    parser = argparse.ArgumentParser(prog="p2pshare", description="P2P Secure File Sharing")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR, help="Data directory")
    parser.add_argument("--test-mode", action="store_true", help="Enable test mode (reads P2PSHARE_PASSWORD)")
    subparsers = parser.add_subparsers(dest="command")

    # init
    init_parser = subparsers.add_parser("init", help="Create a new vault")
    init_parser.add_argument("--name", default="peer", help="Display name")

    # start
    start_parser = subparsers.add_parser("start", help="Start the peer")
    start_parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="TCP port")
    start_parser.add_argument("--name", default=None, help="Display name override")

    args = parser.parse_args()
    if args.command == "init":
        cmd_init(args)
    elif args.command == "start":
        cmd_start(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
