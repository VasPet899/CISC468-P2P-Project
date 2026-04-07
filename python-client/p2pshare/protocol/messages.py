"""Protocol message types and construction helpers.

All message types share a common envelope:
  { "type": ..., "version": "1", "seq": N, "timestamp": ms }
"""

import time
import base64

PROTOCOL_VERSION = "1"
CHUNK_SIZE = 64 * 1024  # 64 KB


def _envelope(msg_type: str, seq: int, **kwargs) -> dict:
    msg = {
        "type": msg_type,
        "version": PROTOCOL_VERSION,
        "seq": seq,
        "timestamp": int(time.time() * 1000),
    }
    msg.update(kwargs)
    return msg


def list_request(seq: int, owner_id: str | None = None) -> dict:
    return _envelope("LIST_REQUEST", seq, filter={"owner_id": owner_id})


def list_response(seq: int, files: list[dict]) -> dict:
    return _envelope("LIST_RESPONSE", seq, files=files)


def transfer_request(seq: int, file_id: str, requester_id: str, manifest: dict | None = None) -> dict:
    extra: dict = {"file_id": file_id, "requester_id": requester_id}
    if manifest is not None:
        extra["manifest"] = manifest
    return _envelope("TRANSFER_REQUEST", seq, **extra)


def transfer_response(seq: int, file_id: str, accepted: bool, reason: str = "") -> dict:
    return _envelope("TRANSFER_RESPONSE", seq, file_id=file_id, accepted=accepted, reason=reason)


def transfer_chunk(seq: int, file_id: str, chunk_index: int, total_chunks: int, chunk_data: bytes) -> dict:
    from p2pshare.crypto.keys import b64url_encode
    return _envelope(
        "TRANSFER_CHUNK", seq,
        file_id=file_id,
        chunk_index=chunk_index,
        total_chunks=total_chunks,
        chunk_data=b64url_encode(chunk_data),
    )


def transfer_complete(seq: int, file_id: str, sha256_hash: str) -> dict:
    return _envelope("TRANSFER_COMPLETE", seq, file_id=file_id, sha256=sha256_hash)


def key_migration(seq: int, old_peer_id: str, new_peer_id: str,
                  effective_ts: int, expiry_ts: int, reason: str,
                  old_signature: str, new_signature: str) -> dict:
    return _envelope(
        "KEY_MIGRATION", seq,
        old_peer_id=old_peer_id,
        new_peer_id=new_peer_id,
        effective_timestamp=effective_ts,
        expiry_timestamp=expiry_ts,
        reason=reason,
        old_signature=old_signature,
        new_signature=new_signature,
    )


def migration_ack(seq: int, accepted: bool, reason: str = "") -> dict:
    return _envelope("MIGRATION_ACK", seq, accepted=accepted, reason=reason)


def error_msg(seq: int, code: str, message: str) -> dict:
    return _envelope("ERROR", seq, code=code, message=message)


# Error codes
AUTH_FAILED = "AUTH_FAILED"
UNKNOWN_PEER = "UNKNOWN_PEER"
FILE_NOT_FOUND = "FILE_NOT_FOUND"
CONSENT_DENIED = "CONSENT_DENIED"
INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
MIGRATION_INVALID = "MIGRATION_INVALID"
PROTOCOL_ERROR = "PROTOCOL_ERROR"
VERSION_MISMATCH = "VERSION_MISMATCH"
