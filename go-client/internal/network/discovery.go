package network

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time" // used by DiscoveredPeer.LastSeen

	"github.com/grandcat/zeroconf"
)

const serviceType = "_p2pshare._tcp"
const domain = "local."

// DiscoveredPeer is a peer found via mDNS.
type DiscoveredPeer struct {
	Name     string
	PeerID   string
	Host     string
	Port     int
	LastSeen time.Time
}

// PeerDiscovery manages mDNS service registration and browsing.
type PeerDiscovery struct {
	DisplayName string
	PeerID      string
	Port        int

	mu     sync.Mutex
	peers  map[string]*DiscoveredPeer // keyed by peer_id
	server *zeroconf.Server
	cancel context.CancelFunc
}

// NewPeerDiscovery creates a new PeerDiscovery instance.
func NewPeerDiscovery(displayName, peerID string, port int) *PeerDiscovery {
	return &PeerDiscovery{
		DisplayName: displayName,
		PeerID:      peerID,
		Port:        port,
		peers:       make(map[string]*DiscoveredPeer),
	}
}

// Start begins mDNS registration and browsing.
func (pd *PeerDiscovery) Start() error {
	// Register our service
	var err error
	pd.server, err = zeroconf.Register(
		pd.DisplayName,  // instance name
		serviceType,     // service type
		domain,          // domain
		pd.Port,         // port
		[]string{fmt.Sprintf("peer_id=%s", pd.PeerID)}, // TXT records
		nil,             // interfaces (nil = all)
	)
	if err != nil {
		return fmt.Errorf("mDNS register: %w", err)
	}

	// Browse for peers
	ctx, cancel := context.WithCancel(context.Background())
	pd.cancel = cancel
	go pd.browse(ctx)

	return nil
}

// Stop stops mDNS registration and browsing.
func (pd *PeerDiscovery) Stop() {
	if pd.cancel != nil {
		pd.cancel()
	}
	if pd.server != nil {
		pd.server.Shutdown()
	}
}

// GetPeers returns all discovered peers (excluding self).
func (pd *PeerDiscovery) GetPeers() []*DiscoveredPeer {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	var result []*DiscoveredPeer
	for _, p := range pd.peers {
		if p.PeerID != pd.PeerID {
			result = append(result, p)
		}
	}
	return result
}

// GetPeer looks up a discovered peer by peer_id.
func (pd *PeerDiscovery) GetPeer(peerID string) *DiscoveredPeer {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	return pd.peers[peerID]
}

func (pd *PeerDiscovery) browse(ctx context.Context) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Printf("mDNS resolver error: %v", err)
		return
	}

	entries := make(chan *zeroconf.ServiceEntry)
	go func() {
		for entry := range entries {
			pd.addPeer(entry)
		}
	}()

	// A single Browse runs until ctx is cancelled by Stop().
	// Do NOT restart Browse on the same entries channel — zeroconf closes it
	// on context cancellation and a second Browse would panic (close of closed channel).
	if err := resolver.Browse(ctx, serviceType, domain, entries); err != nil {
		log.Printf("mDNS browse error: %v", err)
	}
}

func (pd *PeerDiscovery) addPeer(entry *zeroconf.ServiceEntry) {
	var peerID string
	for _, txt := range entry.Text {
		if len(txt) > 8 && txt[:8] == "peer_id=" {
			peerID = txt[8:]
		}
	}
	if peerID == "" {
		return
	}

	host := ""
	if len(entry.AddrIPv4) > 0 {
		host = entry.AddrIPv4[0].String()
	} else if len(entry.AddrIPv6) > 0 {
		host = entry.AddrIPv6[0].String()
	}
	if host == "" {
		return
	}

	pd.mu.Lock()
	defer pd.mu.Unlock()
	pd.peers[peerID] = &DiscoveredPeer{
		Name:     entry.Instance,
		PeerID:   peerID,
		Host:     host,
		Port:     entry.Port,
		LastSeen: time.Now(),
	}
}

// GetLocalIP returns the machine's non-loopback IP address.
func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}
