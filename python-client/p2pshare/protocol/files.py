"""File listing and transfer protocol logic."""

import math

from p2pshare.crypto.keys import b64url_encode, b64url_decode, bytes_to_public_key
from p2pshare.storage.file_store import (
    FileStore,
    verify_manifest,
    verify_file_integrity,
)
from p2pshare.protocol.messages import (
    list_response,
    transfer_response,
    transfer_chunk,
    transfer_complete,
    CHUNK_SIZE,
)
from p2pshare.errors import IntegrityError


def handle_list_request(msg: dict, file_store: FileStore, seq_counter: list) -> dict:
    """Handle a LIST_REQUEST — returns a LIST_RESPONSE with all manifests."""
    manifests = file_store.list_manifests()
    seq_counter[0] += 1
    return list_response(seq_counter[0], manifests)


def build_file_chunks(file_store: FileStore, file_id: str, seq_start: int) -> list[dict]:
    """Build TRANSFER_CHUNK and TRANSFER_COMPLETE messages for a file."""
    file_data = file_store.load_file(file_id)
    manifest = file_store.load_manifest(file_id)

    total_chunks = max(1, math.ceil(len(file_data) / CHUNK_SIZE))
    msgs = []
    seq = seq_start

    for i in range(total_chunks):
        start = i * CHUNK_SIZE
        end = min(start + CHUNK_SIZE, len(file_data))
        chunk = file_data[start:end]
        seq += 1
        msgs.append(transfer_chunk(seq, file_id, i, total_chunks, chunk))

    seq += 1
    msgs.append(transfer_complete(seq, file_id, manifest["sha256"]))
    return msgs


def reassemble_file(chunks: list[dict]) -> bytes:
    """Reassemble file data from TRANSFER_CHUNK messages (already ordered by chunk_index)."""
    chunks_sorted = sorted(chunks, key=lambda c: c["chunk_index"])
    parts = []
    for c in chunks_sorted:
        parts.append(b64url_decode(c["chunk_data"]))
    return b"".join(parts)


def verify_received_file(file_data: bytes, manifest: dict, owner_pk_bytes: bytes) -> None:
    """Verify a received file's integrity and owner signature.

    Raises IntegrityError if either check fails.
    """
    # Verify file hash
    verify_file_integrity(file_data, manifest["sha256"])

    # Verify owner signature
    owner_pk = bytes_to_public_key(owner_pk_bytes)
    verify_manifest(manifest, owner_pk)
