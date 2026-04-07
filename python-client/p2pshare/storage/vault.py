"""Encrypted vault for identity key, contacts, and settings.

The vault is stored as vault.json in the data directory.
It is encrypted with AES-256-GCM using a key derived from the user's password via Argon2id.
"""

import json
import os
import time

from p2pshare.crypto.keys import (
    generate_identity_keypair,
    private_key_to_seed,
    seed_to_private_key,
    public_key_to_bytes,
    bytes_to_public_key,
    b64url_encode,
    b64url_decode,
    peer_id_from_public_key,
)
from p2pshare.crypto.storage import (
    derive_vault_key,
    generate_salt,
    encrypt_vault,
    decrypt_vault,
    ARGON2_TIME,
    ARGON2_MEMORY,
    ARGON2_PARALLELISM,
    ARGON2_KEYLEN,
)
from p2pshare.errors import VaultError


class Vault:
    """In-memory representation of the decrypted vault."""

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.vault_path = os.path.join(data_dir, "vault.json")
        self.vault_key: bytes | None = None
        self.identity_sk = None
        self.identity_pk = None
        self.contacts: list[dict] = []
        self.settings: dict = {}
        self._created_at: int = 0

    @property
    def peer_id(self) -> str:
        return peer_id_from_public_key(self.identity_pk)

    def exists(self) -> bool:
        return os.path.exists(self.vault_path)

    def create(self, password: str, display_name: str = "peer") -> None:
        """Create a new vault with a fresh identity keypair."""
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(os.path.join(self.data_dir, "files"), exist_ok=True)
        os.makedirs(os.path.join(self.data_dir, "migrations"), exist_ok=True)

        self.identity_sk, self.identity_pk = generate_identity_keypair()
        self._created_at = int(time.time() * 1000)
        self.contacts = []
        self.settings = {
            "display_name": display_name,
            "require_consent_for_transfer": True,
        }

        salt = generate_salt()
        self.vault_key = derive_vault_key(password, salt)
        self._save(salt)

    def open(self, password: str) -> None:
        """Decrypt and load an existing vault."""
        if not self.exists():
            raise VaultError("Vault file not found. Run 'init' first.")

        with open(self.vault_path, "r") as f:
            outer = json.load(f)

        salt = b64url_decode(outer["kdf_params"]["salt"])
        self.vault_key = derive_vault_key(password, salt)

        payload = b64url_decode(outer["ciphertext"])
        try:
            plaintext = decrypt_vault(self.vault_key, payload)
        except Exception:
            raise VaultError("Incorrect password or corrupted vault file.")

        data = json.loads(plaintext.decode("utf-8"))
        self.identity_sk = seed_to_private_key(b64url_decode(data["identity"]["private_key"]))
        self.identity_pk = bytes_to_public_key(b64url_decode(data["identity"]["public_key"]))
        self._created_at = data["identity"]["created_at"]
        self.contacts = data.get("contacts", [])
        self.settings = data.get("settings", {})

    def save(self) -> None:
        """Re-encrypt and save the vault with the current vault key."""
        if self.vault_key is None:
            raise VaultError("Vault not open")
        # Read existing salt
        with open(self.vault_path, "r") as f:
            outer = json.load(f)
        salt = b64url_decode(outer["kdf_params"]["salt"])
        self._save(salt)

    def _save(self, salt: bytes) -> None:
        """Encrypt and write vault.json."""
        plaintext_data = {
            "identity": {
                "private_key": b64url_encode(private_key_to_seed(self.identity_sk)),
                "public_key": b64url_encode(public_key_to_bytes(self.identity_pk)),
                "created_at": self._created_at,
            },
            "contacts": self.contacts,
            "settings": self.settings,
        }
        plaintext = json.dumps(plaintext_data, separators=(",", ":")).encode("utf-8")
        encrypted = encrypt_vault(self.vault_key, plaintext)

        outer = {
            "vault_version": 1,
            "kdf": "argon2id",
            "kdf_params": {
                "time": ARGON2_TIME,
                "memory": ARGON2_MEMORY,
                "parallelism": ARGON2_PARALLELISM,
                "salt": b64url_encode(salt),
                "keylen": ARGON2_KEYLEN,
            },
            "ciphertext": b64url_encode(encrypted),
        }

        with open(self.vault_path, "w") as f:
            json.dump(outer, f, indent=2)

    def add_contact(self, peer_id: str, public_key_bytes: bytes, alias: str = "") -> None:
        """Add a new contact to the vault."""
        for c in self.contacts:
            if c["peer_id"] == peer_id:
                c["last_seen"] = int(time.time() * 1000)
                return
        self.contacts.append({
            "peer_id": peer_id,
            "alias": alias or peer_id[:8],
            "public_key": b64url_encode(public_key_bytes),
            "added_at": int(time.time() * 1000),
            "last_seen": int(time.time() * 1000),
            "migration_history": [],
        })

    def get_contact(self, peer_id: str) -> dict | None:
        """Look up a contact by peer_id."""
        for c in self.contacts:
            if c["peer_id"] == peer_id:
                return c
        return None

    def update_contact_key(self, old_peer_id: str, new_peer_id: str, new_public_key_bytes: bytes) -> bool:
        """Update a contact's key after key migration. Returns True if found and updated."""
        for c in self.contacts:
            if c["peer_id"] == old_peer_id:
                c["migration_history"].append(old_peer_id)
                c["peer_id"] = new_peer_id
                c["public_key"] = b64url_encode(new_public_key_bytes)
                c["last_seen"] = int(time.time() * 1000)
                return True
        return False

    def get_display_name(self) -> str:
        return self.settings.get("display_name", "peer")

    def change_password(self, new_password: str) -> None:
        """Re-encrypt the vault with a new password."""
        if self.vault_key is None:
            raise VaultError("Vault not open")
        salt = generate_salt()
        self.vault_key = derive_vault_key(new_password, salt)
        self._save(salt)
