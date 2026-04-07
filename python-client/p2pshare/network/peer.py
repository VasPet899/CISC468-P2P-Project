"""Peer connection state machine.

Manages the lifecycle of a single peer-to-peer TCP connection:
  1. TCP connect
  2. Handshake (HELLO/HELLO_ACK/AUTH/AUTH_ACK)
  3. Encrypted message exchange
  4. Graceful close
"""

import socket
import json
import math
import threading

from p2pshare.crypto.keys import (
    b64url_encode,
    b64url_decode,
    bytes_to_public_key,
    public_key_to_bytes,
    peer_id_from_public_key,
    fingerprint,
)
from p2pshare.crypto.handshake import HandshakeInitiator, HandshakeResponder
from p2pshare.crypto.session import SessionCipher
from p2pshare.network.transport import (
    send_json,
    recv_json,
    send_encrypted,
    recv_encrypted,
)
from p2pshare.protocol import messages
from p2pshare.protocol.files import (
    handle_list_request,
    build_file_chunks,
    reassemble_file,
    verify_received_file,
)
from p2pshare.protocol.migration import verify_migration
from p2pshare.storage.vault import Vault
from p2pshare.storage.file_store import FileStore
from p2pshare.errors import (
    HandshakeError,
    AuthenticationError,
    IntegrityError,
    ConsentDeniedError,
    P2PShareError,
)


class PeerConnection:
    """A single authenticated, encrypted peer connection."""

    def __init__(self, sock: socket.socket, vault: Vault, file_store: FileStore,
                 consent_callback=None):
        self.sock = sock
        self.vault = vault
        self.file_store = file_store
        self.cipher: SessionCipher | None = None
        self.peer_id: str = ""
        self.peer_pk = None
        self.seq = 0
        self._consent_callback = consent_callback or self._default_consent

    def _next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def connect_as_initiator(self, host: str, port: int) -> None:
        """Initiate a connection and perform the handshake."""
        self.sock.connect((host, port))
        hs = HandshakeInitiator(self.vault.identity_sk, self.vault.identity_pk)

        # Step 1: send HELLO
        hello = hs.create_hello()
        send_json(self.sock, hello)

        # Step 2: receive HELLO_ACK
        hello_ack = recv_json(self.sock)
        hs.process_hello_ack(hello_ack)

        # Derive session key
        session_key = hs.derive_session()

        # Step 3: send AUTH
        auth, self.cipher = hs.create_auth(session_key)
        send_encrypted(self.sock, self.cipher, auth)

        # Step 4: receive AUTH_ACK
        auth_ack = recv_encrypted(self.sock, self.cipher)
        hs.verify_auth_ack(auth_ack)

        self.peer_id = b64url_encode(public_key_to_bytes(hs.peer_identity_pk))
        self.peer_pk = hs.peer_identity_pk
        self._handle_new_peer()

    def accept_as_responder(self) -> None:
        """Accept an incoming connection and perform the handshake."""
        hs = HandshakeResponder(self.vault.identity_sk, self.vault.identity_pk)

        # Step 1: receive HELLO
        hello = recv_json(self.sock)
        hs.process_hello(hello)

        # Step 2: send HELLO_ACK
        hello_ack = hs.create_hello_ack()
        send_json(self.sock, hello_ack)

        # Derive session key
        session_key = hs.derive_session()

        # Step 3: receive AUTH
        auth = recv_encrypted(self.sock, SessionCipher(session_key))
        hs.verify_auth(auth)

        # Step 4: send AUTH_ACK
        auth_ack, self.cipher = hs.create_auth_ack(session_key)
        send_encrypted(self.sock, self.cipher, auth_ack)

        self.peer_id = b64url_encode(public_key_to_bytes(hs.peer_identity_pk))
        self.peer_pk = hs.peer_identity_pk
        self._handle_new_peer()

    def _handle_new_peer(self) -> None:
        """Handle a newly authenticated peer (TOFU contact add)."""
        contact = self.vault.get_contact(self.peer_id)
        if contact is None:
            pk_bytes = public_key_to_bytes(self.peer_pk)
            self.vault.add_contact(self.peer_id, pk_bytes)
            self.vault.save()
            fp = fingerprint(self.peer_pk)
            print(f"[+] New peer added to contacts: {self.peer_id[:8]}... (fingerprint: {fp})")

    def send_msg(self, msg: dict) -> None:
        """Send an encrypted message."""
        send_encrypted(self.sock, self.cipher, msg)

    def recv_msg(self) -> dict:
        """Receive and decrypt a message."""
        return recv_encrypted(self.sock, self.cipher)

    def request_file_list(self) -> list[dict]:
        """Request and return the peer's file list."""
        req = messages.list_request(self._next_seq())
        self.send_msg(req)
        resp = self.recv_msg()
        if resp.get("type") == "ERROR":
            print(f"[!] Error: {resp.get('message', 'Unknown error')}")
            return []
        return resp.get("files", [])

    def request_file(self, file_id: str) -> bytes | None:
        """Request a file from the peer. Returns file data or None if declined."""
        req = messages.transfer_request(self._next_seq(), file_id, self.vault.peer_id)
        self.send_msg(req)

        resp = self.recv_msg()
        if resp.get("type") == "TRANSFER_RESPONSE":
            if not resp.get("accepted"):
                print(f"[!] Transfer declined by peer: {resp.get('reason', '')}")
                return None
        elif resp.get("type") == "ERROR":
            print(f"[!] Error: {resp.get('message', 'Unknown error')}")
            return None

        # Receive chunks
        chunks = []
        while True:
            msg = self.recv_msg()
            if msg.get("type") == "TRANSFER_CHUNK":
                chunks.append(msg)
            elif msg.get("type") == "TRANSFER_COMPLETE":
                break
            elif msg.get("type") == "ERROR":
                print(f"[!] Error during transfer: {msg.get('message')}")
                return None

        return reassemble_file(chunks)

    def send_file(self, file_id: str) -> None:
        """Send a file to the peer (called after consent is granted)."""
        chunk_msgs = build_file_chunks(self.file_store, file_id, self.seq)
        for msg in chunk_msgs:
            self.send_msg(msg)
            self.seq = msg["seq"]

    def handle_incoming(self) -> None:
        """Main loop for handling incoming messages from a connected peer."""
        seq_counter = [self.seq]
        try:
            while True:
                msg = self.recv_msg()
                msg_type = msg.get("type")

                if msg_type == "LIST_REQUEST":
                    resp = handle_list_request(msg, self.file_store, seq_counter)
                    self.send_msg(resp)

                elif msg_type == "TRANSFER_REQUEST":
                    file_id = msg.get("file_id", "")
                    requester = msg.get("requester_id", "")[:8]
                    incoming_manifest = msg.get("manifest")

                    # Resolve file_id prefix to full file_id
                    if not self.file_store.has_file(file_id):
                        for m in self.file_store.list_manifests():
                            if m["file_id"].startswith(file_id):
                                file_id = m["file_id"]
                                break

                    if self.file_store.has_file(file_id):
                        # Pull flow: requester wants to download this file from us
                        manifest = self.file_store.load_manifest(file_id)
                        filename = manifest.get("filename", file_id[:8])
                        accepted = self._consent_callback(
                            f"Peer {requester}... is requesting '{filename}'. Send it? [y/n]: "
                        )
                        seq_counter[0] += 1
                        if accepted:
                            self.send_msg(messages.transfer_response(seq_counter[0], file_id, True))
                            self.seq = seq_counter[0]
                            self.send_file(file_id)
                        else:
                            self.send_msg(messages.transfer_response(seq_counter[0], file_id, False, "User declined"))

                    elif incoming_manifest is not None:
                        # Push flow: sender wants to push a file to us
                        filename = incoming_manifest.get("filename", file_id[:8])
                        size_bytes = incoming_manifest.get("size_bytes", 0)
                        accepted = self._consent_callback(
                            f"Peer {requester}... wants to send you '{filename}' ({size_bytes} bytes). Accept? [y/n]: "
                        )
                        seq_counter[0] += 1
                        if not accepted:
                            self.send_msg(messages.transfer_response(seq_counter[0], file_id, False, "User declined"))
                        else:
                            self.send_msg(messages.transfer_response(seq_counter[0], file_id, True))
                            self.seq = seq_counter[0]
                            # Receive chunks from sender
                            chunks = []
                            complete_msg = None
                            while True:
                                chunk_msg = self.recv_msg()
                                if chunk_msg.get("type") == "TRANSFER_CHUNK":
                                    chunks.append(chunk_msg)
                                elif chunk_msg.get("type") == "TRANSFER_COMPLETE":
                                    complete_msg = chunk_msg
                                    break
                                elif chunk_msg.get("type") == "ERROR":
                                    print(f"[!] Error during receive: {chunk_msg.get('message')}")
                                    break
                            if complete_msg is not None and chunks:
                                file_data = reassemble_file(chunks)
                                owner_id = incoming_manifest.get("owner_id", "")
                                contact = self.vault.get_contact(owner_id)
                                if contact:
                                    owner_pk_bytes = b64url_decode(contact["public_key"])
                                    try:
                                        verify_received_file(file_data, incoming_manifest, owner_pk_bytes)
                                        print(f"[+] File integrity and owner signature verified.")
                                    except Exception as e:
                                        print(f"[!] {e}")
                                        continue
                                else:
                                    print(f"[!] Warning: Cannot verify owner — {owner_id[:8]}... not in contacts.")
                                self.file_store.store_file(file_id, file_data, incoming_manifest)
                                print(f"[+] Received file '{filename}' saved.")

                    else:
                        self.send_msg(messages.error_msg(
                            self._next_seq(), messages.FILE_NOT_FOUND,
                            f"File '{file_id[:8]}...' is not available."))

                elif msg_type == "KEY_MIGRATION":
                    self._handle_migration(msg, seq_counter)

                elif msg_type == "ERROR":
                    print(f"[!] Peer error: [{msg.get('code')}] {msg.get('message')}")

                else:
                    print(f"[?] Unknown message type: {msg_type}")

        except P2PShareError as e:
            print(f"[!] Connection error: {e}")
        except Exception:
            pass  # Connection closed

    def _handle_migration(self, msg: dict, seq_counter: list) -> None:
        """Process a KEY_MIGRATION announcement."""
        old_peer_id = msg.get("old_peer_id", "")
        contact = self.vault.get_contact(old_peer_id)
        if contact is None:
            seq_counter[0] += 1
            self.send_msg(messages.migration_ack(seq_counter[0], False, "Unknown peer"))
            return

        old_pk_bytes = b64url_decode(contact["public_key"])
        try:
            new_pk_bytes = verify_migration(msg, old_pk_bytes)
        except Exception as e:
            print(f"[!] {e}")
            seq_counter[0] += 1
            self.send_msg(messages.migration_ack(seq_counter[0], False, str(e)))
            return

        new_peer_id = msg.get("new_peer_id", "")
        self.vault.update_contact_key(old_peer_id, new_peer_id, new_pk_bytes)
        self.vault.save()
        print(f"[+] Key migration accepted for peer {old_peer_id[:8]}... → {new_peer_id[:8]}...")
        seq_counter[0] += 1
        self.send_msg(messages.migration_ack(seq_counter[0], True))

    @staticmethod
    def _default_consent(prompt: str) -> bool:
        """Default consent callback: blocking stdin prompt."""
        try:
            answer = input(prompt).strip().lower()
            return answer in ("y", "yes")
        except EOFError:
            return False

    def close(self) -> None:
        """Close the connection."""
        try:
            self.sock.close()
        except Exception:
            pass
