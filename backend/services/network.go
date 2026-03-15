package services

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
)

// WireGuardPeer represents a WireGuard peer configuration.
type WireGuardPeer struct {
	PublicKey           string `json:"public_key"`
	Endpoint            string `json:"endpoint,omitempty"`
	AllowedIPs          string `json:"allowed_ips"`
	LatestHandshake     string `json:"latest_handshake,omitempty"`
	TransferRx          string `json:"transfer_rx,omitempty"`
	TransferTx          string `json:"transfer_tx,omitempty"`
}

// WireGuardStatus represents the WireGuard interface status.
type WireGuardStatus struct {
	Interface  string          `json:"interface"`
	PublicKey  string          `json:"public_key"`
	ListenPort string          `json:"listen_port"`
	Peers      []WireGuardPeer `json:"peers"`
}

// TailscalePeer represents a Tailscale network peer.
type TailscalePeer struct {
	ID          string   `json:"id"`
	Hostname    string   `json:"hostname"`
	DNSName     string   `json:"dns_name"`
	TailscaleIP string   `json:"tailscale_ip"`
	OS          string   `json:"os"`
	Online      bool     `json:"online"`
	ExitNode    bool     `json:"exit_node"`
	Tags        []string `json:"tags,omitempty"`
}

// TailscaleStatus represents the Tailscale network status.
type TailscaleStatus struct {
	BackendState string          `json:"backend_state"` // "Running", "Stopped", etc.
	Self         *TailscalePeer  `json:"self,omitempty"`
	Peers        []TailscalePeer `json:"peers"`
	MagicDNS     bool            `json:"magic_dns"`
}

// WireGuardKeyPair represents a generated WireGuard key pair.
type WireGuardKeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// NetworkStatus combines WireGuard and Tailscale status.
type NetworkStatus struct {
	WireGuard     *WireGuardStatus  `json:"wireguard,omitempty"`
	Tailscale     *TailscaleStatus  `json:"tailscale,omitempty"`
	WireGuardAvailable bool          `json:"wireguard_available"`
	TailscaleAvailable bool          `json:"tailscale_available"`
	Platform            string       `json:"platform"`
}

// GetNetworkStatus returns combined VPN status.
func GetNetworkStatus() NetworkStatus {
	status := NetworkStatus{
		Platform: runtime.GOOS,
	}

	if runtime.GOOS != "linux" {
		return status
	}

	// Check WireGuard
	if _, err := exec.LookPath("wg"); err == nil {
		status.WireGuardAvailable = true
		wgStatus, err := getWireGuardStatus()
		if err == nil {
			status.WireGuard = wgStatus
		}
	}

	// Check Tailscale
	if _, err := exec.LookPath("tailscale"); err == nil {
		status.TailscaleAvailable = true
		tsStatus, err := getTailscaleStatus()
		if err == nil {
			status.Tailscale = tsStatus
		}
	}

	return status
}

// --- WireGuard ---

// getWireGuardStatus parses `wg show` output.
func getWireGuardStatus() (*WireGuardStatus, error) {
	out, err := exec.Command("wg", "show", "all", "dump").Output()
	if err != nil {
		return nil, fmt.Errorf("wg show failed: %w", err)
	}

	status := &WireGuardStatus{}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}

		if status.Interface == "" {
			// First line is the interface
			status.Interface = fields[0]
			status.PublicKey = fields[1]
			status.ListenPort = fields[2]
		} else {
			// Subsequent lines are peers
			peer := WireGuardPeer{
				PublicKey: fields[0],
			}
			if len(fields) > 1 {
				peer.Endpoint = fields[2]
			}
			if len(fields) > 2 {
				peer.AllowedIPs = fields[3]
			}
			if len(fields) > 4 {
				peer.LatestHandshake = fields[4]
			}
			if len(fields) > 5 {
				peer.TransferRx = fields[5]
			}
			if len(fields) > 6 {
				peer.TransferTx = fields[6]
			}
			status.Peers = append(status.Peers, peer)
		}
	}

	return status, nil
}

// GetWireGuardPeers returns the list of WireGuard peers.
func GetWireGuardPeers() ([]WireGuardPeer, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("WireGuard management requires Linux")
	}

	status, err := getWireGuardStatus()
	if err != nil {
		return nil, err
	}

	return status.Peers, nil
}

// AddWireGuardPeer adds a new peer to the WireGuard interface.
func AddWireGuardPeer(publicKey, allowedIPs, endpoint string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("WireGuard management requires Linux")
	}

	args := []string{"set", "wg0", "peer", publicKey, "allowed-ips", allowedIPs}
	if endpoint != "" {
		args = append(args, "endpoint", endpoint)
	}

	cmd := exec.Command("wg", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg set failed: %s: %w", string(output), err)
	}

	log.Printf("WireGuard: added peer %s with allowed-ips %s", publicKey[:16]+"...", allowedIPs)
	return nil
}

// RemoveWireGuardPeer removes a peer from the WireGuard interface.
func RemoveWireGuardPeer(publicKey string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("WireGuard management requires Linux")
	}

	cmd := exec.Command("wg", "set", "wg0", "peer", publicKey, "remove")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg remove peer failed: %s: %w", string(output), err)
	}

	log.Printf("WireGuard: removed peer %s", publicKey[:16]+"...")
	return nil
}

// GenerateWireGuardKeyPair generates a new WireGuard key pair.
func GenerateWireGuardKeyPair() (*WireGuardKeyPair, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("WireGuard key generation requires Linux")
	}

	// Generate private key
	privOut, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return nil, fmt.Errorf("wg genkey failed: %w", err)
	}
	privateKey := strings.TrimSpace(string(privOut))

	// Derive public key
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	pubOut, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("wg pubkey failed: %w", err)
	}
	publicKey := strings.TrimSpace(string(pubOut))

	return &WireGuardKeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// --- Tailscale ---

// getTailscaleStatus parses `tailscale status --json`.
func getTailscaleStatus() (*TailscaleStatus, error) {
	out, err := exec.Command("tailscale", "status", "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("tailscale status failed: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse tailscale status: %w", err)
	}

	status := &TailscaleStatus{}

	if state, ok := raw["BackendState"].(string); ok {
		status.BackendState = state
	}

	if magicDNS, ok := raw["MagicDNSSuffix"].(string); ok {
		status.MagicDNS = magicDNS != ""
	}

	// Parse self
	if selfData, ok := raw["Self"].(map[string]interface{}); ok {
		status.Self = parseTailscalePeer(selfData)
	}

	// Parse peers
	if peersMap, ok := raw["Peer"].(map[string]interface{}); ok {
		for _, peerData := range peersMap {
			if peerMap, ok := peerData.(map[string]interface{}); ok {
				peer := parseTailscalePeer(peerMap)
				if peer != nil {
					status.Peers = append(status.Peers, *peer)
				}
			}
		}
	}

	return status, nil
}

func parseTailscalePeer(data map[string]interface{}) *TailscalePeer {
	peer := &TailscalePeer{}

	if id, ok := data["ID"].(string); ok {
		peer.ID = id
	}
	if host, ok := data["HostName"].(string); ok {
		peer.Hostname = host
	}
	if dns, ok := data["DNSName"].(string); ok {
		peer.DNSName = dns
	}
	if os, ok := data["OS"].(string); ok {
		peer.OS = os
	}
	if online, ok := data["Online"].(bool); ok {
		peer.Online = online
	}
	if exitNode, ok := data["ExitNode"].(bool); ok {
		peer.ExitNode = exitNode
	}

	// Extract Tailscale IP from TailscaleIPs array
	if ips, ok := data["TailscaleIPs"].([]interface{}); ok && len(ips) > 0 {
		if ip, ok := ips[0].(string); ok {
			peer.TailscaleIP = ip
		}
	}

	return peer
}

// GetTailscalePeers returns the list of Tailscale peers.
func GetTailscalePeers() ([]TailscalePeer, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("Tailscale management requires Linux")
	}

	status, err := getTailscaleStatus()
	if err != nil {
		return nil, err
	}

	return status.Peers, nil
}

// AdvertiseTailscaleRoutes configures subnet routes on the Tailscale node.
func AdvertiseTailscaleRoutes(routes []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("Tailscale management requires Linux")
	}

	if len(routes) == 0 {
		return fmt.Errorf("no routes specified")
	}

	routeStr := strings.Join(routes, ",")
	cmd := exec.Command("tailscale", "set", "--advertise-routes="+routeStr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tailscale set routes failed: %s: %w", string(output), err)
	}

	log.Printf("Tailscale: advertising routes: %s", routeStr)
	return nil
}
