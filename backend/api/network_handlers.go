package api

import (
	"net/http"

	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// GetNetworkStatus returns the combined WireGuard + Tailscale status.
func GetNetworkStatus(c *gin.Context) {
	status := services.GetNetworkStatus()
	c.JSON(http.StatusOK, status)
}

// GetWireGuardPeers returns the list of WireGuard peers.
func GetWireGuardPeers(c *gin.Context) {
	peers, err := services.GetWireGuardPeers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if peers == nil {
		peers = []services.WireGuardPeer{}
	}

	c.JSON(http.StatusOK, gin.H{"peers": peers})
}

// AddWireGuardPeer adds a new peer to the WireGuard interface.
func AddWireGuardPeer(c *gin.Context) {
	var req struct {
		PublicKey  string `json:"public_key" binding:"required"`
		AllowedIPs string `json:"allowed_ips" binding:"required"`
		Endpoint   string `json:"endpoint"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := services.AddWireGuardPeer(req.PublicKey, req.AllowedIPs, req.Endpoint); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Peer added successfully"})
}

// RemoveWireGuardPeer removes a peer from the WireGuard interface.
func RemoveWireGuardPeer(c *gin.Context) {
	publicKey := c.Param("key")
	if publicKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Public key is required"})
		return
	}

	if err := services.RemoveWireGuardPeer(publicKey); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Peer removed successfully"})
}

// GenerateWireGuardKeys generates a new WireGuard key pair.
func GenerateWireGuardKeys(c *gin.Context) {
	keyPair, err := services.GenerateWireGuardKeyPair()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, keyPair)
}

// GetTailscaleStatus returns the Tailscale network status.
func GetTailscaleStatus(c *gin.Context) {
	status := services.GetNetworkStatus()
	if status.Tailscale == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Tailscale not available on this system"})
		return
	}

	c.JSON(http.StatusOK, status.Tailscale)
}

// GetTailscalePeers returns the list of Tailscale network peers.
func GetTailscalePeers(c *gin.Context) {
	peers, err := services.GetTailscalePeers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if peers == nil {
		peers = []services.TailscalePeer{}
	}

	c.JSON(http.StatusOK, gin.H{"peers": peers})
}

// AdvertiseTailscaleRoutes configures subnet routes on the Tailscale node.
func AdvertiseTailscaleRoutes(c *gin.Context) {
	var req struct {
		Routes []string `json:"routes" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := services.AdvertiseTailscaleRoutes(req.Routes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Routes advertised successfully", "routes": req.Routes})
}
