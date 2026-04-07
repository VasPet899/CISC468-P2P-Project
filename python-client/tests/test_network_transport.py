"""Tests for TCP length-prefixed framing."""

import socket
import threading
import os
import pytest

from p2pshare.network.transport import (
    send_frame,
    recv_frame,
    send_json,
    recv_json,
    send_encrypted,
    recv_encrypted,
)
from p2pshare.crypto.session import SessionCipher
from p2pshare.errors import ProtocolError


def make_socket_pair():
    """Create a connected pair of sockets for testing."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    conn, _ = server.accept()
    server.close()
    return client, conn


def test_frame_roundtrip():
    c, s = make_socket_pair()
    try:
        payload = b"hello frame"
        send_frame(c, payload)
        received = recv_frame(s)
        assert received == payload
    finally:
        c.close(); s.close()


def test_frame_empty():
    c, s = make_socket_pair()
    try:
        send_frame(c, b"")
        received = recv_frame(s)
        assert received == b""
    finally:
        c.close(); s.close()


def test_frame_large():
    c, s = make_socket_pair()
    try:
        payload = os.urandom(256 * 1024)  # 256 KB
        send_frame(c, payload)
        received = recv_frame(s)
        assert received == payload
    finally:
        c.close(); s.close()


def test_json_roundtrip():
    c, s = make_socket_pair()
    try:
        obj = {"type": "TEST", "value": 42, "nested": {"a": 1}}
        send_json(c, obj)
        received = recv_json(s)
        assert received == obj
    finally:
        c.close(); s.close()


def test_encrypted_roundtrip():
    key = os.urandom(32)
    cipher_send = SessionCipher(key)
    cipher_recv = SessionCipher(key)

    c, s = make_socket_pair()
    try:
        obj = {"type": "AUTH", "seq": 1, "secret": "data"}
        send_encrypted(c, cipher_send, obj)
        received = recv_encrypted(s, cipher_recv)
        assert received == obj
    finally:
        c.close(); s.close()


def test_encrypted_wrong_key():
    from p2pshare.errors import IntegrityError
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    cipher_send = SessionCipher(key1)
    cipher_recv = SessionCipher(key2)

    c, s = make_socket_pair()
    try:
        send_encrypted(c, cipher_send, {"msg": "secret"})
        with pytest.raises(IntegrityError):
            recv_encrypted(s, cipher_recv)
    finally:
        c.close(); s.close()


def test_multiple_frames_in_sequence():
    c, s = make_socket_pair()
    try:
        messages = [b"first", b"second", b"third"]
        for m in messages:
            send_frame(c, m)
        for expected in messages:
            assert recv_frame(s) == expected
    finally:
        c.close(); s.close()


def test_recv_frame_connection_closed():
    c, s = make_socket_pair()
    c.close()
    with pytest.raises(ProtocolError):
        recv_frame(s)
    s.close()
