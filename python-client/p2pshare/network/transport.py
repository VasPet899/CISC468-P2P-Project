"""TCP transport with 4-byte big-endian length-prefixed framing.

Wire format:
    [uint32 big-endian: payload_length][payload_bytes]

Maximum payload size: 64 MB.
"""

import struct
import socket
import json

from p2pshare.errors import ProtocolError
from p2pshare.crypto.session import SessionCipher, MAX_PAYLOAD_SIZE


HEADER_SIZE = 4
HEADER_FORMAT = "!I"  # big-endian unsigned 32-bit int


def send_frame(sock: socket.socket, payload: bytes) -> None:
    """Send a length-prefixed frame over a TCP socket."""
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ProtocolError(f"Payload too large: {len(payload)} > {MAX_PAYLOAD_SIZE}")
    header = struct.pack(HEADER_FORMAT, len(payload))
    sock.sendall(header + payload)


def recv_frame(sock: socket.socket) -> bytes:
    """Receive a length-prefixed frame from a TCP socket.

    Raises ProtocolError if the frame is too large or the connection closes.
    """
    header = _recv_exact(sock, HEADER_SIZE)
    if not header:
        raise ProtocolError("Connection closed")
    length = struct.unpack(HEADER_FORMAT, header)[0]
    if length > MAX_PAYLOAD_SIZE:
        raise ProtocolError(f"Frame too large: {length} > {MAX_PAYLOAD_SIZE}")
    if length == 0:
        return b""
    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a socket."""
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ProtocolError("Connection closed unexpectedly")
        data.extend(chunk)
    return bytes(data)


def send_json(sock: socket.socket, obj: dict) -> None:
    """Send a JSON object as a plaintext frame (used during handshake)."""
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    send_frame(sock, payload)


def recv_json(sock: socket.socket) -> dict:
    """Receive a JSON object from a plaintext frame (used during handshake)."""
    payload = recv_frame(sock)
    try:
        return json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ProtocolError(f"Invalid JSON frame: {e}")


def send_encrypted(sock: socket.socket, cipher: SessionCipher, obj: dict) -> None:
    """Encrypt a JSON object and send as a length-prefixed frame."""
    plaintext = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    encrypted = cipher.encrypt(plaintext)
    send_frame(sock, encrypted)


def recv_encrypted(sock: socket.socket, cipher: SessionCipher) -> dict:
    """Receive and decrypt a JSON object from an encrypted frame."""
    payload = recv_frame(sock)
    plaintext = cipher.decrypt(payload)
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ProtocolError(f"Invalid decrypted JSON: {e}")
