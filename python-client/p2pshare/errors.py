"""Custom exception hierarchy for p2pshare."""


class P2PShareError(Exception):
    """Base exception for all p2pshare errors."""


class AuthenticationError(P2PShareError):
    """Peer identity verification failed."""


class IntegrityError(P2PShareError):
    """Message or file integrity check failed."""


class HandshakeError(P2PShareError):
    """Session handshake failed."""


class VaultError(P2PShareError):
    """Vault decryption or corruption error."""


class ProtocolError(P2PShareError):
    """Wire protocol violation."""


class ConsentDeniedError(P2PShareError):
    """Transfer was declined by the peer."""


class MigrationError(P2PShareError):
    """Key migration announcement is invalid."""


class PeerOfflineError(P2PShareError):
    """Could not connect to peer."""


class FileNotFoundError(P2PShareError):
    """Requested file is not available."""
