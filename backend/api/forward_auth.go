package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// VerifyProxyAuth handles reverse-proxy forward-auth verification (Apache2 / Subdomain Gateway).
// If a valid active human session is present, returns 200 OK and injects X-Aetherflow-User.
// Otherwise, returns 401 Unauthorized (or 403 Forbidden if suspended).
func VerifyProxyAuth(c *gin.Context) {
	_, _, subj, err := resolveSessionTokenWithSubject(c)
	if err != nil {
		if errors.Is(err, errSubjectSuspended) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Account is not active"})
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized session"})
		return
	}

	c.Header("X-Aetherflow-User", subj.username)
	c.Header("Remote-User", subj.username)
	c.Status(http.StatusOK)
}
