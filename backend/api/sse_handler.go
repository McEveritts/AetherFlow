package api

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

var sseSecretRedactRe = regexp.MustCompile(`(?i)(bearer\s+[A-Za-z0-9._~+/-]+=*|(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S+)`)

func sanitizeSSEPayload(msg string) string {
	clean := strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(msg)
	return sseSecretRedactRe.ReplaceAllString(clean, "[REDACTED]")
}

// HandleDeployStream upgrades a standard request to a Server-Sent Events stream
// tracking the live lifecycle logs of an AetherFlow Blueprint execution or Blue/Green swap.
func HandleDeployStream(c *gin.Context) {
	appName := c.Query("appName")
	if appName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "appName query parameter is required"})
		return
	}

	// Check session authorization if context carries authenticated subject metadata.
	var userID int
	if rawUID, exists := c.Get("user_id"); exists {
		if uid, ok := rawUID.(int); ok {
			userID = uid
		}
	}
	sessionJTI := c.GetString("session_jti")
	var sessionVer int64
	if rawVer, hasVer := c.Get("session_ver"); hasVer {
		switch v := rawVer.(type) {
		case int64:
			sessionVer = v
		case int:
			sessionVer = int64(v)
		}
	}
	if userID > 0 && !isLogWSAuthorized(userID, sessionJTI, sessionVer) {
		RespondError(c, http.StatusForbidden, ErrCodeForbidden, "Admin access required")
		return
	}

	// Retrieve the active stream BEFORE setting text/event-stream headers so 404 remains JSON.
	streamChan := services.StreamHub.GetStream(appName)
	if streamChan == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No active deployment found for this application."})
		return
	}

	// Upgrade the HTTP sequence to text/event-stream
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	// Allow bypassing buffer for instant feedback
	c.Writer.Header().Set("X-Accel-Buffering", "no")

	notify := c.Request.Context().Done()
	authTicker := time.NewTicker(5 * time.Second)
	defer authTicker.Stop()

	// Spin event loop bridging Go channels to chunked HTTP chunks with periodic revocation checks
	for {
		select {
		case <-notify:
			return

		case <-authTicker.C:
			if userID > 0 && !isLogWSAuthorized(userID, sessionJTI, sessionVer) {
				return
			}

		case msg, ok := <-streamChan:
			if !ok {
				return
			}
			if userID > 0 && !isLogWSAuthorized(userID, sessionJTI, sessionVer) {
				return
			}
			fmt.Fprintf(c.Writer, "data: %s\n\n", sanitizeSSEPayload(msg))
			c.Writer.Flush()
		}
	}
}
