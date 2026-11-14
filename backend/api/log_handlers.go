package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"aetherflow/db"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// GetLogs queries the log aggregator with filters.
func GetLogs(c *gin.Context) {
	if services.Logs == nil {
		RespondError(c, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Log aggregator not initialized")
		return
	}

	filter := services.LogFilter{
		Source:   c.Query("source"),
		Unit:     c.Query("unit"),
		Priority: c.Query("priority"),
		Keyword:  c.Query("keyword"),
	}

	if limit, err := strconv.Atoi(c.Query("limit")); err == nil {
		filter.Limit = limit
	}
	if offset, err := strconv.Atoi(c.Query("offset")); err == nil {
		filter.Offset = offset
	}
	if since := c.Query("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			filter.Since = t
		}
	}
	if until := c.Query("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			filter.Until = t
		}
	}

	entries := services.Logs.Query(filter)
	if entries == nil {
		entries = []services.LogEntry{}
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":  entries,
		"count": len(entries),
	})
}

// GetLogSources returns available log sources.
func GetLogSources(c *gin.Context) {
	if services.Logs == nil {
		RespondError(c, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Log aggregator not initialized")
		return
	}

	sources := services.Logs.GetSources()
	if sources == nil {
		sources = []string{}
	}

	c.JSON(http.StatusOK, gin.H{"sources": sources})
}

// BookmarkLog saves a log entry bookmark for the current user.
func BookmarkLog(c *gin.Context) {
	rawUserID, exists := c.Get("user_id")
	if !exists {
		Unauthorized(c, "Unauthorized")
		return
	}
	userID, ok := rawUserID.(int)
	if !ok {
		Unauthorized(c, "Unauthorized")
		return
	}

	var req struct {
		LogSource string `json:"log_source" binding:"required"`
		LogLine   string `json:"log_line" binding:"required"`
		Timestamp string `json:"timestamp" binding:"required"`
		Note      string `json:"note"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	_, err := db.DB.Exec(
		"INSERT INTO log_bookmarks (user_id, log_source, log_line, timestamp, note) VALUES (?, ?, ?, ?, ?)",
		userID, req.LogSource, req.LogLine, req.Timestamp, req.Note,
	)
	if err != nil {
		InternalError(c, "Failed to bookmark log")
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Log bookmarked"})
}

// isLogWSAuthorized re-validates session JTI revocation, credential epoch, and admin role.
func isLogWSAuthorized(userID int, sessionJTI string, sessionVer int64) bool {
	if userID <= 0 {
		return false
	}
	if sessionJTI != "" && isTokenRevokedBeyondGraceForUser(sessionJTI, userID) {
		return false
	}
	if db.DB != nil {
		subj, err := loadActiveHumanSubject(db.DB, userID)
		if err != nil || sessionVer < subj.sessionsRevokedAfter || subj.role != "admin" {
			return false
		}
	}
	return true
}

// HandleLogWebSocket provides real-time log streaming over WebSocket.
func HandleLogWebSocket(c *gin.Context) {
	if services.Logs == nil {
		RespondError(c, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Log aggregator not initialized")
		return
	}

	rawUserID, exists := c.Get("user_id")
	if !exists {
		Unauthorized(c, "WebSocket requires authentication")
		return
	}
	userID, ok := rawUserID.(int)
	if !ok || userID <= 0 {
		Unauthorized(c, "WebSocket requires authentication")
		return
	}
	sessionJTI := c.GetString("session_jti")
	var sessionVer int64
	if rawVer, hasVer := c.Get("session_ver"); hasVer {
		if v, vOK := rawVer.(int64); vOK {
			sessionVer = v
		}
	}
	if !isLogWSAuthorized(userID, sessionJTI, sessionVer) {
		RespondError(c, http.StatusForbidden, ErrCodeForbidden, "Admin access required")
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		slog.Error("log WebSocket upgrade error", "error", err)
		return
	}
	defer conn.Close()

	// Subscribe to log stream
	logCh := services.Logs.Subscribe()
	defer services.Logs.Unsubscribe(logCh)

	// Read filter preferences from client asynchronously while monitoring disconnects
	filterCh := make(chan services.LogFilter, 4)
	closedCh := make(chan struct{})
	go func() {
		defer close(closedCh)
		for {
			_, msg, readErr := conn.ReadMessage()
			if readErr != nil {
				return
			}
			var nextFilter services.LogFilter
			if json.Unmarshal(msg, &nextFilter) == nil {
				select {
				case filterCh <- nextFilter:
				default:
				}
			}
		}
	}()

	var filter services.LogFilter
	authTicker := time.NewTicker(5 * time.Second)
	defer authTicker.Stop()

	for {
		select {
		case <-closedCh:
			return
		case nextFilter := <-filterCh:
			filter = nextFilter
		case <-authTicker.C:
			if !isLogWSAuthorized(userID, sessionJTI, sessionVer) {
				_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "session revoked"), time.Now().Add(writeWait))
				return
			}
		case entry, chOpen := <-logCh:
			if !chOpen {
				return
			}
			if !isLogWSAuthorized(userID, sessionJTI, sessionVer) {
				_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "session revoked"), time.Now().Add(writeWait))
				return
			}
			if filter.Source != "" && entry.Source != filter.Source {
				continue
			}
			if filter.Unit != "" && !services.MatchesUnitFilter(entry.Unit, filter.Unit) {
				continue
			}
			if filter.Priority != "" && entry.Priority != filter.Priority {
				continue
			}

			entry.Message = services.RedactLogSecrets(entry.Message)
			payload := map[string]interface{}{
				"type": "LOG_ENTRY",
				"data": entry,
			}

			message, mErr := json.Marshal(payload)
			if mErr != nil {
				continue
			}

			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		}
	}
}

// GetBookmarks retrieves log bookmarks for the current user.
func GetBookmarks(c *gin.Context) {
	rawUserID, exists := c.Get("user_id")
	if !exists {
		Unauthorized(c, "Unauthorized")
		return
	}
	userId, ok := rawUserID.(int)
	if !ok {
		Unauthorized(c, "Unauthorized")
		return
	}

	rows, err := db.DB.Query(
		"SELECT id, log_source, log_line, timestamp, note, created_at FROM log_bookmarks WHERE user_id = ? ORDER BY created_at DESC",
		userId,
	)
	if err != nil {
		InternalError(c, "Failed to fetch bookmarks")
		return
	}
	defer rows.Close()

	var bookmarks []map[string]interface{}
	for rows.Next() {
		var id int
		var logSource, logLine, timestamp, note, createdAt string
		if err := rows.Scan(&id, &logSource, &logLine, &timestamp, &note, &createdAt); err == nil {
			bookmarks = append(bookmarks, map[string]interface{}{
				"id":         id,
				"log_source": logSource,
				"log_line":   logLine,
				"timestamp":  timestamp,
				"note":       note,
				"created_at": createdAt,
			})
		}
	}

	if bookmarks == nil {
		bookmarks = make([]map[string]interface{}, 0)
	}

	c.JSON(http.StatusOK, gin.H{"bookmarks": bookmarks})
}
