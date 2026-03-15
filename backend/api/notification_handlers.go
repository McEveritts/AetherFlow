package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"aetherflow/db"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// --- Notification Endpoints ---

// GetNotifications returns notification history for the current user.
func GetNotifications(c *gin.Context) {
	limit := 50
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 && l <= 200 {
		limit = l
	}

	offset := 0
	if o, err := strconv.Atoi(c.Query("offset")); err == nil && o >= 0 {
		offset = o
	}

	rows, err := db.DB.Query(
		"SELECT id, user_id, level, title, message, read, created_at FROM notifications ORDER BY created_at DESC LIMIT ? OFFSET ?",
		limit, offset,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query notifications"})
		return
	}
	defer rows.Close()

	var notifications []services.Notification
	for rows.Next() {
		var n services.Notification
		if err := rows.Scan(&n.ID, &n.UserID, &n.Level, &n.Title, &n.Message, &n.Read, &n.CreatedAt); err != nil {
			continue
		}
		notifications = append(notifications, n)
	}

	if notifications == nil {
		notifications = []services.Notification{}
	}

	// Get unread count
	var unreadCount int
	db.DB.QueryRow("SELECT COUNT(*) FROM notifications WHERE read = 0").Scan(&unreadCount)

	c.JSON(http.StatusOK, gin.H{
		"notifications": notifications,
		"unread_count":  unreadCount,
	})
}

// MarkNotificationRead marks a specific notification as read.
func MarkNotificationRead(c *gin.Context) {
	id := c.Param("id")
	_, err := db.DB.Exec("UPDATE notifications SET read = 1 WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update notification"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Notification marked as read"})
}

// DismissAllNotifications marks all notifications as read.
func DismissAllNotifications(c *gin.Context) {
	_, err := db.DB.Exec("UPDATE notifications SET read = 1 WHERE read = 0")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to dismiss notifications"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "All notifications dismissed"})
}

// --- Notification Rules ---

// GetNotificationRules returns all configured alert rules.
func GetNotificationRules(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, name, condition_type, condition_value, level, enabled, created_at FROM notification_rules ORDER BY created_at DESC")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query rules"})
		return
	}
	defer rows.Close()

	var rules []services.NotificationRule
	for rows.Next() {
		var r services.NotificationRule
		if err := rows.Scan(&r.ID, &r.Name, &r.ConditionType, &r.ConditionValue, &r.Level, &r.Enabled, &r.CreatedAt); err != nil {
			continue
		}
		rules = append(rules, r)
	}

	if rules == nil {
		rules = []services.NotificationRule{}
	}

	c.JSON(http.StatusOK, gin.H{"rules": rules})
}

// CreateNotificationRule creates a new alert rule.
func CreateNotificationRule(c *gin.Context) {
	var req struct {
		Name           string `json:"name" binding:"required"`
		ConditionType  string `json:"condition_type" binding:"required"`
		ConditionValue string `json:"condition_value" binding:"required"`
		Level          string `json:"level"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate condition type
	validTypes := map[string]bool{"disk_usage": true, "cpu_usage": true, "memory_usage": true, "service_down": true}
	if !validTypes[req.ConditionType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid condition_type. Allowed: disk_usage, cpu_usage, memory_usage, service_down"})
		return
	}

	if req.Level == "" {
		req.Level = "warning"
	}

	result, err := db.DB.Exec(
		"INSERT INTO notification_rules (name, condition_type, condition_value, level) VALUES (?, ?, ?, ?)",
		req.Name, req.ConditionType, req.ConditionValue, req.Level,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rule"})
		return
	}

	id, _ := result.LastInsertId()

	// Reload rules in the notification engine
	if services.Notifier != nil {
		services.Notifier.ReloadRules()
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Rule created", "id": id})
}

// UpdateNotificationRule updates an existing alert rule.
func UpdateNotificationRule(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Name           string `json:"name"`
		ConditionType  string `json:"condition_type"`
		ConditionValue string `json:"condition_value"`
		Level          string `json:"level"`
		Enabled        *bool  `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build dynamic UPDATE
	updates := []string{}
	args := []interface{}{}

	if req.Name != "" {
		updates = append(updates, "name = ?")
		args = append(args, req.Name)
	}
	if req.ConditionType != "" {
		updates = append(updates, "condition_type = ?")
		args = append(args, req.ConditionType)
	}
	if req.ConditionValue != "" {
		updates = append(updates, "condition_value = ?")
		args = append(args, req.ConditionValue)
	}
	if req.Level != "" {
		updates = append(updates, "level = ?")
		args = append(args, req.Level)
	}
	if req.Enabled != nil {
		updates = append(updates, "enabled = ?")
		args = append(args, *req.Enabled)
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	query := "UPDATE notification_rules SET "
	for i, u := range updates {
		if i > 0 {
			query += ", "
		}
		query += u
	}
	query += " WHERE id = ?"
	args = append(args, id)

	_, err := db.DB.Exec(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	if services.Notifier != nil {
		services.Notifier.ReloadRules()
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule updated"})
}

// DeleteNotificationRule deletes an alert rule.
func DeleteNotificationRule(c *gin.Context) {
	id := c.Param("id")
	_, err := db.DB.Exec("DELETE FROM notification_rules WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	if services.Notifier != nil {
		services.Notifier.ReloadRules()
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule deleted"})
}

// --- Notification Channels ---

// GetNotificationChannels returns all configured webhook channels.
func GetNotificationChannels(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, name, type, config, enabled, created_at FROM notification_channels ORDER BY created_at DESC")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query channels"})
		return
	}
	defer rows.Close()

	var channels []services.NotificationChannel
	for rows.Next() {
		var ch services.NotificationChannel
		if err := rows.Scan(&ch.ID, &ch.Name, &ch.Type, &ch.Config, &ch.Enabled, &ch.CreatedAt); err != nil {
			continue
		}
		channels = append(channels, ch)
	}

	if channels == nil {
		channels = []services.NotificationChannel{}
	}

	c.JSON(http.StatusOK, gin.H{"channels": channels})
}

// CreateNotificationChannel adds a new webhook channel.
func CreateNotificationChannel(c *gin.Context) {
	var req struct {
		Name    string          `json:"name" binding:"required"`
		Type    string          `json:"type" binding:"required"`
		Config  json.RawMessage `json:"config" binding:"required"`
		Enabled bool            `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate type
	validTypes := map[string]bool{"discord": true, "telegram": true, "slack": true, "custom": true}
	if !validTypes[req.Type] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid channel type. Allowed: discord, telegram, slack, custom"})
		return
	}

	result, err := db.DB.Exec(
		"INSERT INTO notification_channels (name, type, config, enabled) VALUES (?, ?, ?, ?)",
		req.Name, req.Type, string(req.Config), true,
	)
	if err != nil {
		log.Printf("Failed to create notification channel: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create channel"})
		return
	}

	id, _ := result.LastInsertId()

	if services.Notifier != nil {
		services.Notifier.ReloadRules()
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Channel created", "id": id})
}

// TestNotificationChannel sends a test notification to a specific channel.
func TestNotificationChannel(c *gin.Context) {
	id := c.Param("id")

	var ch services.NotificationChannel
	err := db.DB.QueryRow("SELECT id, name, type, config, enabled, created_at FROM notification_channels WHERE id = ?", id).
		Scan(&ch.ID, &ch.Name, &ch.Type, &ch.Config, &ch.Enabled, &ch.CreatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Channel not found"})
		return
	}

	if services.Notifier != nil {
		services.Notifier.TestChannel(ch)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Test notification sent to " + ch.Name})
}

// DeleteNotificationChannel removes a webhook channel.
func DeleteNotificationChannel(c *gin.Context) {
	id := c.Param("id")
	_, err := db.DB.Exec("DELETE FROM notification_channels WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete channel"})
		return
	}

	if services.Notifier != nil {
		services.Notifier.ReloadRules()
	}

	c.JSON(http.StatusOK, gin.H{"message": "Channel deleted"})
}
