package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

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
		InternalError(c, "Failed to query clients")
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
		Name                    string   `json:"name" binding:"required"`
		RedirectURIs            []string `json:"redirect_uris" binding:"required"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		Public                  bool     `json:"public"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.RedirectURIs) == 0 {
		BadRequest(c, "name and at least one redirect_uri are required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !isSafeRedirectURI(u) {
			BadRequest(c, "redirect_uris must use valid https URLs or loopback http URLs without credentials or fragments")
			return
		}
	}

	isPublic := req.Public || strings.EqualFold(strings.TrimSpace(req.TokenEndpointAuthMethod), "none")

	// Generate client_id
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		InternalError(c, "Failed to generate client_id")
		return
	}
	clientID := hex.EncodeToString(idBytes)

	clientSecret := ""
	secretHashHex := ""
	if !isPublic {
		secretBytes := make([]byte, 32)
		if _, err := rand.Read(secretBytes); err != nil {
			InternalError(c, "Failed to generate client_secret")
			return
		}
		clientSecret = hex.EncodeToString(secretBytes)
		secretHash := sha256.Sum256([]byte(clientSecret))
		secretHashHex = hex.EncodeToString(secretHash[:])
	}

	// Serialize redirect URIs as JSON
	redirectURIsJSON, _ := json.Marshal(req.RedirectURIs)

	_, err := db.DB.Exec(
		`INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) VALUES (?, ?, ?, ?)`,
		clientID, secretHashHex, req.Name, string(redirectURIsJSON),
	)
	if err != nil {
		slog.Info("OIDC: failed to create client", "error", err)
		InternalError(c, "Failed to create client")
		return
	}

	// Audit: OIDC client creation is security-sensitive
	actorID, _ := c.Get("user_id")
	actorName, _ := c.Get("username")
	aid, _ := actorID.(int)
	aname, _ := actorName.(string)
	db.RecordAudit(aid, aname, "oidc_client_create", "oidc_client", clientID, "name="+req.Name, c.ClientIP(), c.Request.UserAgent())

	resp := gin.H{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"name":          req.Name,
		"redirect_uris": req.RedirectURIs,
		"message":       "Save the client_secret now — it cannot be retrieved later",
	}
	if isPublic {
		resp["token_endpoint_auth_method"] = "none"
		resp["message"] = "Public PKCE client created (no client_secret)"
	}
	c.JSON(http.StatusCreated, resp)
}

// DeleteOIDCClient removes a registered OIDC client and revokes its tokens.
func DeleteOIDCClient(c *gin.Context) {
	clientID := c.Param("id")
	if clientID == "" {
		BadRequest(c, "Client ID is required")
		return
	}

	// Delete the client
	result, err := db.DB.Exec("DELETE FROM oidc_clients WHERE id = ?", clientID)
	if err != nil {
		InternalError(c, "Failed to delete client")
		return
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		NotFoundError(c, "Client not found")
		return
	}

	// Revoke all associated tokens
	db.DB.Exec("UPDATE oidc_refresh_tokens SET revoked = 1 WHERE client_id = ?", clientID)
	db.DB.Exec("DELETE FROM oidc_auth_codes WHERE client_id = ?", clientID)

	// Audit: OIDC client deletion
	actorID, _ := c.Get("user_id")
	actorName, _ := c.Get("username")
	aid, _ := actorID.(int)
	aname, _ := actorName.(string)
	db.RecordAudit(aid, aname, "oidc_client_delete", "oidc_client", clientID, "", c.ClientIP(), c.Request.UserAgent())

	c.JSON(http.StatusOK, gin.H{"message": "Client deleted and tokens revoked"})
}
