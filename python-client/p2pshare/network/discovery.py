"""mDNS/DNS-SD peer discovery using zeroconf.

Service type: _p2pshare._tcp.local.
TXT records: peer_id=<base64url>, port=<tcp_port>
"""

import socket
import threading
import time

from zeroconf import Zeroconf, ServiceBrowser, ServiceInfo, ServiceStateChange


SERVICE_TYPE = "_p2pshare._tcp.local."


class DiscoveredPeer:
    """A peer discovered via mDNS."""

    def __init__(self, name: str, peer_id: str, host: str, port: int):
        self.name = name
        self.peer_id = peer_id
        self.host = host
        self.port = port
        self.last_seen = time.time()

    def __repr__(self):
        return f"DiscoveredPeer({self.name}, {self.host}:{self.port}, id={self.peer_id[:8]}...)"


class PeerDiscovery:
    """Manages mDNS service registration and browsing for peer discovery."""

    def __init__(self, display_name: str, peer_id: str, port: int):
        self.display_name = display_name
        self.peer_id = peer_id
        self.port = port
        self.peers: dict[str, DiscoveredPeer] = {}  # keyed by peer_id
        self._lock = threading.Lock()
        self._zeroconf: Zeroconf | None = None
        self._browser: ServiceBrowser | None = None
        self._service_info: ServiceInfo | None = None

    def start(self) -> None:
        """Start mDNS registration and browsing."""
        self._zeroconf = Zeroconf()

        # Register our service
        hostname = socket.gethostname()
        local_ip = self._get_local_ip()

        self._service_info = ServiceInfo(
            SERVICE_TYPE,
            f"{self.display_name}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={
                "peer_id": self.peer_id.encode("utf-8"),
            },
            server=f"{hostname}.local.",
        )
        self._zeroconf.register_service(self._service_info)

        # Browse for peers
        self._browser = ServiceBrowser(
            self._zeroconf, SERVICE_TYPE, handlers=[self._on_service_state_change]
        )

    def stop(self) -> None:
        """Stop mDNS registration and browsing."""
        if self._zeroconf:
            if self._service_info:
                self._zeroconf.unregister_service(self._service_info)
            self._zeroconf.close()
            self._zeroconf = None

    def get_peers(self) -> list[DiscoveredPeer]:
        """Return a list of currently discovered peers (excluding self)."""
        with self._lock:
            return [p for p in self.peers.values() if p.peer_id != self.peer_id]

    def get_peer(self, peer_id: str) -> DiscoveredPeer | None:
        """Look up a discovered peer by peer_id."""
        with self._lock:
            return self.peers.get(peer_id)

    def _on_service_state_change(
        self, zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
    ) -> None:
        if state_change == ServiceStateChange.Added:
            info = zeroconf.get_service_info(service_type, name)
            if info:
                self._add_peer(info)
        elif state_change == ServiceStateChange.Removed:
            self._remove_peer(name)

    def _add_peer(self, info: ServiceInfo) -> None:
        props = info.properties or {}
        peer_id_bytes = props.get(b"peer_id", b"")
        if isinstance(peer_id_bytes, bytes):
            peer_id = peer_id_bytes.decode("utf-8")
        else:
            peer_id = str(peer_id_bytes)

        if not peer_id:
            return

        addresses = info.parsed_addresses()
        if not addresses:
            return
        host = addresses[0]

        peer = DiscoveredPeer(
            name=info.name,
            peer_id=peer_id,
            host=host,
            port=info.port,
        )
        with self._lock:
            self.peers[peer_id] = peer

    def _remove_peer(self, name: str) -> None:
        with self._lock:
            to_remove = [pid for pid, p in self.peers.items() if p.name == name]
            for pid in to_remove:
                del self.peers[pid]

    def _get_local_ip(self) -> str:
        """Get the local IP address (not 127.0.0.1) for mDNS advertisement."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
