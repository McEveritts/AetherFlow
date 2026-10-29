package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"aetherflow/db"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

func init() {
	services.KeyDecryptor = DecryptKey
}

// GetStreamingDashboard returns real-time active streams, server statuses, bandwidth usage, and play statistics.
func GetStreamingDashboard(c *gin.Context) {
	windowStr := c.DefaultQuery("window", "30")
	windowDays, err := strconv.Atoi(windowStr)
	if err != nil || windowDays < 0 {
		windowDays = 30
	}
	playMethod := strings.TrimSpace(c.DefaultQuery("playMethod", "all"))
	mediaType := strings.TrimSpace(c.DefaultQuery("mediaType", "all"))

	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()

	payload := services.BuildStreamingDashboard(ctx, windowDays, playMethod, mediaType)
	if role, _ := c.Get("user_role"); role != "admin" {
		for i := range payload.Servers {
			payload.Servers[i].APIKeyMasked = ""
		}
		for i := range payload.ActiveSessions {
			payload.ActiveSessions[i].IPAddress = ""
		}
		for i := range payload.Analytics.RecentHistory {
			payload.Analytics.RecentHistory[i].IPAddress = ""
		}
	}
	c.JSON(http.StatusOK, payload)
}

// GetStreamingArtwork proxies cover art from Jellyfin without exposing credentials to the client.
func GetStreamingArtwork(c *gin.Context) {
	itemID := strings.TrimSpace(c.Param("itemId"))
	if itemID == "" || len(itemID) > 128 || strings.Contains(itemID, "..") || strings.ContainsAny(itemID, "/\\") {
		BadRequest(c, "valid itemId is required")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
	defer cancel()

	data, contentType, err := services.FetchJellyfinArtwork(ctx, itemID)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}

	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	switch mediaType {
	case "image/jpeg", "image/jpg", "image/png", "image/webp", "image/gif", "image/avif":
	default:
		mediaType = "image/jpeg"
	}

	c.Header("Cache-Control", "private, max-age=3600")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Security-Policy", "default-src 'none'; img-src 'self'; sandbox")
	c.Data(http.StatusOK, mediaType, data)
}

// UpdateStreamingServer saves or updates a media server configuration (Jellyfin first; Plex/Emby reserved).
func UpdateStreamingServer(c *gin.Context) {
	provider := strings.ToLower(strings.TrimSpace(c.Param("provider")))
	if provider == "" {
		provider = "jellyfin"
	}
	if provider != "jellyfin" {
		RespondError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Only Jellyfin connection is enabled in this release; Plex and Emby support will arrive in a future update.")
		return
	}

	var req struct {
		Name    string `json:"name"`
		URL     string `json:"url" binding:"required"`
		APIKey  string `json:"apiKey"`
		Enabled *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	cleanURL, err := services.ValidateServerURL(req.URL)
	if err != nil {
		BadRequest(c, err.Error())
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	_, prevURL, prevKey, _ := services.GetStoredJellyfinConfig()
	urlChanged := !strings.EqualFold(cleanURL, strings.TrimRight(strings.TrimSpace(prevURL), "/"))

	rawKey := strings.TrimSpace(req.APIKey)
	keepExisting := strings.HasPrefix(rawKey, "****") || rawKey == ""
	if keepExisting && urlChanged && prevKey != "" {
		if strings.HasPrefix(rawKey, "****") {
			BadRequest(c, "A new API key is required when changing the Jellyfin server URL")
			return
		}
		keepExisting = false
	}

	storedKey := ""
	if !keepExisting && rawKey != "" {
		enc, encErr := EncryptKey(rawKey)
		if encErr != nil {
			InternalError(c, "Failed to encrypt streaming server API key")
			return
		}
		storedKey = enc
	}

	if err := services.SaveStreamingServerConfig(provider, req.Name, cleanURL, storedKey, keepExisting, enabled); err != nil {
		InternalError(c, "Failed to save streaming server configuration: "+err.Error())
		return
	}

	// Test connection and optionally trigger background history sync
	_, resolvedURL, resolvedKey, _ := services.GetStoredJellyfinConfig()
	ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
	defer cancel()

	status, _ := services.TestJellyfinConnection(ctx, resolvedURL, resolvedKey)
	if status != nil && status.Status == "connected" {
		go func() {
			syncCtx, syncCancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer syncCancel()
			_, _ = services.SyncJellyfinWatchHistory(syncCtx)
		}()
	}

	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")
	uid, _ := userID.(int)
	uname, _ := username.(string)
	db.RecordAudit(uid, uname, "streaming_server_update", "streaming_server", provider, cleanURL, c.ClientIP(), c.Request.UserAgent())

	c.JSON(http.StatusOK, gin.H{
		"message": "Jellyfin server configuration saved",
		"server":  status,
	})
}

// TestStreamingServer tests reachability and API key authentication against a Jellyfin server.
func TestStreamingServer(c *gin.Context) {
	var req struct {
		Provider string `json:"provider"`
		URL      string `json:"url"`
		APIKey   string `json:"apiKey"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	_, storedURL, storedKey, _ := services.GetStoredJellyfinConfig()
	targetURL := strings.TrimSpace(req.URL)
	if targetURL == "" {
		targetURL = storedURL
	}
	cleanTargetURL, urlErr := services.ValidateServerURL(targetURL)
	if urlErr != nil {
		BadRequest(c, urlErr.Error())
		return
	}
	targetKey := strings.TrimSpace(req.APIKey)
	if targetKey == "" || strings.HasPrefix(targetKey, "****") {
		if strings.EqualFold(cleanTargetURL, strings.TrimRight(strings.TrimSpace(storedURL), "/")) {
			targetKey = storedKey
		} else {
			targetKey = ""
		}
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
	defer cancel()

	status, err := services.TestJellyfinConnection(ctx, cleanTargetURL, targetKey)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"ok":      false,
			"message": err.Error(),
			"server":  status,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":      status.Status == "connected",
		"message": "Connected to " + status.Name + " (v" + status.Version + ")",
		"server":  status,
	})
}

// SyncStreamingServerHistory imports played items and watch statistics from Jellyfin.
func SyncStreamingServerHistory(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()

	imported, err := services.SyncJellyfinWatchHistory(ctx)
	if err != nil {
		BadRequest(c, "History sync failed: "+err.Error())
		return
	}

	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")
	uid, _ := userID.(int)
	uname, _ := username.(string)
	db.RecordAudit(uid, uname, "streaming_history_sync", "streaming_server", "jellyfin", strconv.Itoa(imported), c.ClientIP(), c.Request.UserAgent())

	c.JSON(http.StatusOK, gin.H{
		"message":  "Jellyfin watch history synchronized",
		"imported": imported,
	})
}

// ControlStreamingSession executes remote playback commands (pause, resume, stop, message) on a session.
func ControlStreamingSession(c *gin.Context) {
	sessionID := strings.TrimSpace(c.Param("sessionId"))
	if sessionID == "" || len(sessionID) > 128 {
		BadRequest(c, "valid sessionId is required")
		return
	}

	var req struct {
		Command string `json:"command" binding:"required"`
		Header  string `json:"header"`
		Message string `json:"message"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	cmd := strings.ToLower(strings.TrimSpace(req.Command))
	if cmd != "pause" && cmd != "resume" && cmd != "stop" && cmd != "message" {
		BadRequest(c, "command must be one of: pause, resume, stop, message")
		return
	}
	header := strings.TrimSpace(req.Header)
	message := strings.TrimSpace(req.Message)
	if len(header) > 120 || len(message) > 1000 {
		BadRequest(c, "header (max 120 chars) or message (max 1000 chars) exceeds maximum length")
		return
	}
	if cmd == "message" && message == "" {
		BadRequest(c, "message text is required when command is message")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
	defer cancel()

	if err := services.SendJellyfinSessionCommand(ctx, sessionID, cmd, header, message); err != nil {
		InternalError(c, "Session control command failed: "+err.Error())
		return
	}

	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")
	uid, _ := userID.(int)
	uname, _ := username.(string)
	db.RecordAudit(uid, uname, "streaming_session_"+cmd, "streaming_session", sessionID, message, c.ClientIP(), c.Request.UserAgent())

	c.JSON(http.StatusOK, gin.H{
		"message":   "Command sent to session",
		"sessionId": sessionID,
		"command":   cmd,
	})
}

// HandleStreamingDemo seeds or clears demo streaming telemetry so admins can preview the dashboard.
func HandleStreamingDemo(c *gin.Context) {
	var req struct {
		Action string `json:"action"` // "seed" or "clear"
	}
	_ = c.ShouldBindJSON(&req)

	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")
	uid, _ := userID.(int)
	uname, _ := username.(string)

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "clear" {
		if err := services.ClearStreamingDemoData(); err != nil {
			InternalError(c, "Failed to clear demo data: "+err.Error())
			return
		}
		db.RecordAudit(uid, uname, "streaming_demo_clear", "streaming_demo", "jellyfin", "clear", c.ClientIP(), c.Request.UserAgent())
		c.JSON(http.StatusOK, gin.H{"message": "Demo telemetry cleared", "demoMode": false})
		return
	}

	if err := services.SeedStreamingDemoData(); err != nil {
		InternalError(c, "Failed to seed demo data: "+err.Error())
		return
	}
	db.RecordAudit(uid, uname, "streaming_demo_seed", "streaming_demo", "jellyfin", "seed", c.ClientIP(), c.Request.UserAgent())
	c.JSON(http.StatusOK, gin.H{"message": "Demo streaming telemetry loaded", "demoMode": true})
}
