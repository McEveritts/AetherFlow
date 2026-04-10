package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

// issueCSRFToken generates a cryptographically random CSRF token, sets it as a
// SameSite=Strict cookie (readable by JavaScript), and returns it in the JSON body.
// The frontend must send this token in the X-CSRF-Token header on mutating requests.
func issueCSRFToken(c *gin.Context) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		InternalError(c, "Failed to generate CSRF token")
		return
	}
	token := hex.EncodeToString(tokenBytes)

	c.SetSameSite(http.SameSiteStrictMode)
	// HttpOnly=false so JavaScript can read the cookie value for the X-CSRF-Token header
	c.SetCookie("csrf_token", token, 3600, "/", "", secureCookie(), false)

	c.JSON(http.StatusOK, gin.H{"csrf_token": token})
}
