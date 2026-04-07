"""Message dispatch — routes decrypted messages to the appropriate handler."""

import math

from p2pshare.errors import ProtocolError
from p2pshare.protocol import messages


class MessageHandler:
    """Routes incoming messages to registered callbacks.

    Validates the message envelope (type, version, seq) before dispatching.
    """

    def __init__(self):
        self._handlers: dict[str, callable] = {}
        self._expected_seq = 1

    def register(self, msg_type: str, handler: callable) -> None:
        self._handlers[msg_type] = handler

    def handle(self, msg: dict) -> dict | None:
        """Process an incoming decrypted message. Returns a response dict or None."""
        # Validate envelope
        msg_type = msg.get("type")
        if not msg_type:
            raise ProtocolError("Message missing 'type' field")

        version = msg.get("version")
        if version != messages.PROTOCOL_VERSION:
            return messages.error_msg(0, messages.VERSION_MISMATCH,
                                      f"Unsupported protocol version: {version}")

        handler = self._handlers.get(msg_type)
        if handler is None:
            raise ProtocolError(f"Unknown message type: {msg_type}")

        return handler(msg)
