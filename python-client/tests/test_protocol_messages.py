"""Tests for protocol message construction."""

from p2pshare.protocol.messages import (
    list_request,
    list_response,
    transfer_request,
    transfer_response,
    transfer_chunk,
    transfer_complete,
    key_migration,
    migration_ack,
    error_msg,
)


def test_list_request_format():
    msg = list_request(1)
    assert msg["type"] == "LIST_REQUEST"
    assert msg["version"] == "1"
    assert msg["seq"] == 1
    assert "timestamp" in msg
    assert msg["filter"]["owner_id"] is None


def test_list_response_format():
    files = [{"file_id": "abc", "filename": "test.txt"}]
    msg = list_response(2, files)
    assert msg["type"] == "LIST_RESPONSE"
    assert len(msg["files"]) == 1


def test_transfer_request_format():
    msg = transfer_request(3, "file123", "peer456")
    assert msg["type"] == "TRANSFER_REQUEST"
    assert msg["file_id"] == "file123"
    assert msg["requester_id"] == "peer456"


def test_transfer_response_accepted():
    msg = transfer_response(4, "file123", True)
    assert msg["accepted"] is True


def test_transfer_response_declined():
    msg = transfer_response(5, "file123", False, "User declined")
    assert msg["accepted"] is False
    assert msg["reason"] == "User declined"


def test_transfer_chunk_format():
    msg = transfer_chunk(6, "file123", 0, 3, b"\x00\x01\x02")
    assert msg["type"] == "TRANSFER_CHUNK"
    assert msg["chunk_index"] == 0
    assert msg["total_chunks"] == 3
    assert "chunk_data" in msg


def test_transfer_complete_format():
    msg = transfer_complete(7, "file123", "abc123hash")
    assert msg["type"] == "TRANSFER_COMPLETE"
    assert msg["sha256"] == "abc123hash"


def test_error_msg_format():
    msg = error_msg(8, "AUTH_FAILED", "Bad signature")
    assert msg["type"] == "ERROR"
    assert msg["code"] == "AUTH_FAILED"
    assert msg["message"] == "Bad signature"


def test_key_migration_format():
    msg = key_migration(9, "old_id", "new_id", 1000, 2000, "compromise", "old_sig", "new_sig")
    assert msg["type"] == "KEY_MIGRATION"
    assert msg["old_peer_id"] == "old_id"
    assert msg["new_peer_id"] == "new_id"
    assert msg["reason"] == "compromise"


def test_migration_ack_format():
    msg = migration_ack(10, True)
    assert msg["accepted"] is True
