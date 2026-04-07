"""Tests for encrypted vault create/open/save/contacts."""

import os
import tempfile
import pytest

from p2pshare.storage.vault import Vault
from p2pshare.errors import VaultError


@pytest.fixture
def tmp_vault():
    with tempfile.TemporaryDirectory() as d:
        yield d


def test_vault_create_and_open(tmp_vault):
    v = Vault(tmp_vault)
    v.create("secret", "Alice")
    assert v.exists()
    assert v.peer_id  # non-empty base64url string
    assert v.get_display_name() == "Alice"

    # Re-open
    v2 = Vault(tmp_vault)
    v2.open("secret")
    assert v2.peer_id == v.peer_id
    assert v2.get_display_name() == "Alice"


def test_vault_wrong_password(tmp_vault):
    v = Vault(tmp_vault)
    v.create("correct", "Bob")
    v2 = Vault(tmp_vault)
    with pytest.raises(VaultError, match="Incorrect password"):
        v2.open("wrong")


def test_vault_not_exists(tmp_vault):
    v = Vault(tmp_vault)
    with pytest.raises(VaultError):
        v.open("any")


def test_vault_add_contact(tmp_vault):
    v = Vault(tmp_vault)
    v.create("pw", "Peer")
    pk_bytes = bytes(range(32))
    import base64
    peer_id = base64.urlsafe_b64encode(pk_bytes).rstrip(b"=").decode()
    v.add_contact(peer_id, pk_bytes, "Alice")
    v.save()

    v2 = Vault(tmp_vault)
    v2.open("pw")
    c = v2.get_contact(peer_id)
    assert c is not None
    assert c["alias"] == "Alice"


def test_vault_update_contact_key(tmp_vault):
    v = Vault(tmp_vault)
    v.create("pw", "Peer")
    old_pk = bytes(range(32))
    new_pk = bytes(range(1, 33))
    import base64
    old_id = base64.urlsafe_b64encode(old_pk).rstrip(b"=").decode()
    new_id = base64.urlsafe_b64encode(new_pk).rstrip(b"=").decode()
    v.add_contact(old_id, old_pk, "Bob")
    result = v.update_contact_key(old_id, new_id, new_pk)
    assert result is True
    assert v.get_contact(old_id) is None
    assert v.get_contact(new_id) is not None


def test_vault_change_password(tmp_vault):
    v = Vault(tmp_vault)
    v.create("old_pw", "Charlie")
    peer_id = v.peer_id
    v.change_password("new_pw")

    v2 = Vault(tmp_vault)
    with pytest.raises(VaultError):
        v2.open("old_pw")

    v3 = Vault(tmp_vault)
    v3.open("new_pw")
    assert v3.peer_id == peer_id


def test_vault_dirs_created(tmp_vault):
    v = Vault(tmp_vault)
    v.create("pw", "Test")
    assert os.path.isdir(os.path.join(tmp_vault, "files"))
    assert os.path.isdir(os.path.join(tmp_vault, "migrations"))
