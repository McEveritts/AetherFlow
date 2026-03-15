package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
)

// OIDCClientInfo represents a registered OIDC client application.
type OIDCClientInfo struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	CreatedAt    string   `json:"created_at"`
}

// GetOIDCClients lists all registered OIDC client applications.
func GetOIDCClients(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, name, redirect_uris, created_at FROM oidc_clients ORDER BY created_at DESC")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query clients"})
		return
	}
	defer rows.Close()

	var clients []OIDCClientInfo
	for rows.Next() {
		var client OIDCClientInfo
		var redirectURIsJSON string
		if err := rows.Scan(&client.ID, &client.Name, &redirectURIsJSON, &client.CreatedAt); err != nil {
			continue
		}
		json.Unmarshal([]byte(redirectURIsJSON), &client.RedirectURIs)
		clients = append(clients, client)
	}

	if clients == nil {
		clients = []OIDCClientInfo{}
	}

	c.JSON(http.StatusOK, gin.H{"clients": clients})
}

// CreateOIDCClient registers a new OIDC client application.
func CreateOIDCClient(c *gin.Context) {
	var req struct {
		Name         string   `json:"name" binding:"required"`
		RedirectURIs []string `json:"redirect_uris" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.RedirectURIs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one redirect_uri is required"})
		return
	}

	// Generate client_id
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	clientID := hex.EncodeToString(idBytes)

	// Generate client_secret
	secretBytes := make([]byte, 32)
	rand.Read(secretBytes)
	clientSecret := hex.EncodeToString(secretBytes)

	// Hash the secret for storage
	secretHash := sha256.Sum256([]byte(clientSecret))
	secretHashHex := hex.EncodeToString(secretHash[:])

	// Serialize redirect URIs as JSON
	redirectURIsJSON, _ := json.Marshal(req.RedirectURIs)

	_, err := db.DB.Exec(
		`INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) VALUES (?, ?, ?, ?)`,
		clientID, secretHashHex, req.Name, string(redirectURIsJSON),
	)
	if err != nil {
		log.Printf("OIDC: failed to create client: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create client"})
		return
	}

	// Return the secret once (it cannot be retrieved later)
	c.JSON(http.StatusCreated, gin.H{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"name":          req.Name,
		"redirect_uris": req.RedirectURIs,
		"message":       "Save the client_secret now — it cannot be retrieved later",
	})
}

// DeleteOIDCClient removes a registered OIDC client and revokes its tokens.
func DeleteOIDCClient(c *gin.Context) {
	clientID := c.Param("id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Client ID is required"})
		return
	}

	// Delete the client
	result, err := db.DB.Exec("DELETE FROM oidc_clients WHERE id = ?", clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete client"})
		return
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Client not found"})
		return
	}

	// Revoke all associated tokens
	db.DB.Exec("UPDATE oidc_refresh_tokens SET revoked = 1 WHERE client_id = ?", clientID)
	db.DB.Exec("DELETE FROM oidc_auth_codes WHERE client_id = ?", clientID)

	c.JSON(http.StatusOK, gin.H{"message": "Client deleted and tokens revoked"})
}
