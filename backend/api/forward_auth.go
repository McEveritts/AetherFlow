package api

import (
	"database/sql"
	"net/http"
	"aetherflow/db"
	"github.com/gin-gonic/gin"
)

// VerifyProxyAuth handles Caddy's forward_auth directive.
// If valid session cookie is present, returns 200 OK and injects X-Aetherflow-User.
// Otherwise, returns 401 Unauthorized forcing Caddy to redirect to login.
func VerifyProxyAuth(c *gin.Context) {
	// Re-use internal secure session parsing logic
	_, claims, err := resolveSessionToken(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized session"})
		return
	}

	userIdFloat, ok := claims["user_id"].(float64)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid session token claims"})
		return
	}

	userId := int(userIdFloat)

	// Fetch username to pass natively to upstream apps (Jellyseerr etc)
	var username string
	err = db.DB.QueryRow("SELECT username FROM users WHERE id = ?", userId).Scan(&username)
	if err != nil {
		if err == sql.ErrNoRows {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User no longer exists"})
			return
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal validation error"})
		return
	}

	// Session is valid. Inject identity headers into the Response.
	// Caddy's `copy_response_headers` logic will pull these and push to upstream apps.
	c.Header("X-Aetherflow-User", username)
	c.Header("Remote-User", username) // Included for older app compatibility

	c.Status(http.StatusOK)
}
