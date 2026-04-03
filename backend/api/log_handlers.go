package api

import (
	"encoding/json"
	"log"
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
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Log aggregator not initialized"})
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
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Log aggregator not initialized"})
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userID, ok := rawUserID.(int)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		LogSource string `json:"log_source" binding:"required"`
		LogLine   string `json:"log_line" binding:"required"`
		Timestamp string `json:"timestamp" binding:"required"`
		Note      string `json:"note"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := db.DB.Exec(
		"INSERT INTO log_bookmarks (user_id, log_source, log_line, timestamp, note) VALUES (?, ?, ?, ?, ?)",
		userID, req.LogSource, req.LogLine, req.Timestamp, req.Note,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to bookmark log"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Log bookmarked"})
}

// HandleLogWebSocket provides real-time log streaming over WebSocket.
func HandleLogWebSocket(c *gin.Context) {
	if services.Logs == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Log aggregator not initialized"})
		return
	}

	if _, exists := c.Get("user_id"); !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "WebSocket requires authentication"})
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("Log WebSocket upgrade error:", err)
		return
	}
	defer conn.Close()

	// Subscribe to log stream
	logCh := services.Logs.Subscribe()
	defer services.Logs.Unsubscribe(logCh)

	// Read filter preferences from client (optional first message)
	var filter services.LogFilter
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err == nil {
		json.Unmarshal(msg, &filter)
	}
	conn.SetReadDeadline(time.Time{}) // Reset deadline

	// Stream logs to client
	for entry := range logCh {
		// Apply client-side filter
		if filter.Source != "" && entry.Source != filter.Source {
			continue
		}
		if filter.Unit != "" && entry.Unit != filter.Unit {
			continue
		}
		if filter.Priority != "" && entry.Priority != filter.Priority {
			continue
		}

		payload := map[string]interface{}{
			"type": "LOG_ENTRY",
			"data": entry,
		}

		message, err := json.Marshal(payload)
		if err != nil {
			continue
		}

		conn.SetWriteDeadline(time.Now().Add(writeWait))
		if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
			return
		}
	}
}

// GetBookmarks retrieves log bookmarks for the current user.
func GetBookmarks(c *gin.Context) {
	rawUserID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userId, ok := rawUserID.(int)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	rows, err := db.DB.Query(
		"SELECT id, log_source, log_line, timestamp, note, created_at FROM log_bookmarks WHERE user_id = ? ORDER BY created_at DESC",
		userId,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch bookmarks"})
		return
	}
	defer rows.Close()

	var bookmarks []map[string]interface{}
	for rows.Next() {
		var id int
		var logSource, logLine, timestamp, note, createdAt string
		if err := rows.Scan(&id, &logSource, &logLine, &timestamp, &note, &createdAt); err == nil {
			bookmarks = append(bookmarks, map[string]interface{}{
				"id": id,
				"log_source": logSource,
				"log_line": logLine,
				"timestamp": timestamp,
				"note": note,
				"created_at": createdAt,
			})
		}
	}

	if bookmarks == nil {
		bookmarks = make([]map[string]interface{}, 0)
	}

	c.JSON(http.StatusOK, gin.H{"bookmarks": bookmarks})
}
