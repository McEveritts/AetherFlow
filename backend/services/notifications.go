package services

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"aetherflow/db"
	"aetherflow/logging"
)

// notifLog is the domain-scoped structured logger for the notification engine.
var notifLog *slog.Logger

// NotificationType represents the severity level of a notification.
type NotificationType string

const (
	NotifyInfo     NotificationType = "info"
	NotifyWarning  NotificationType = "warning"
	NotifyCritical NotificationType = "critical"
	NotifySuccess  NotificationType = "success"
)

// Notification represents a system notification.
type Notification struct {
	ID        int              `json:"id"`
	UserID    *int             `json:"user_id,omitempty"` // nil = broadcast to all
	Level     NotificationType `json:"level"`
	Title     string           `json:"title"`
	Message   string           `json:"message"`
	Read      bool             `json:"read"`
	CreatedAt string           `json:"created_at"`
}

// NotificationRule defines an automated alert condition.
type NotificationRule struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	ConditionType  string `json:"condition_type"`  // "disk_usage", "service_down", "cpu_usage", "memory_usage"
	ConditionValue string `json:"condition_value"` // threshold value (e.g., "90" for 90%)
	Level          string `json:"level"`
	Enabled        bool   `json:"enabled"`
	CreatedAt      string `json:"created_at"`
}

// NotificationChannel represents a webhook delivery channel.
type NotificationChannel struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`   // "discord", "telegram", "slack", "custom"
	Config    string `json:"config"` // JSON config (url, token, chat_id, etc.)
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
}

// NotificationEngine manages rules, evaluation, and dispatch.
type NotificationEngine struct {
	mu             sync.RWMutex
	evalMu         sync.Mutex   // Dedicated lock for the background evaluation loop
	rules          []NotificationRule
	channels       []NotificationChannel
	dispatchFn     func(Notification) // callback to broadcast via WebSocket
	lastEvaluation map[string]time.Time // tracks cooldown per rule to avoid spam
}

// Global notification engine instance.
var Notifier *NotificationEngine

// InitNotificationEngine creates and starts the notification engine.
func InitNotificationEngine(dispatchFn func(Notification)) {
	notifLog = logging.ForDomain("notifications", "engine")
	Notifier = &NotificationEngine{
		dispatchFn:     dispatchFn,
		lastEvaluation: make(map[string]time.Time),
	}
	Notifier.loadRules()
	Notifier.loadChannels()

	// Start rule evaluator goroutine
	go Notifier.evaluationLoop()

	notifLog.Info("notification engine initialized")
}

// loadRules loads notification rules from the database.
func (ne *NotificationEngine) loadRules() {
	rows, err := db.DB.Query("SELECT id, name, condition_type, condition_value, level, enabled, created_at FROM notification_rules WHERE enabled = 1")
	if err != nil {
		notifLog.Error("failed to load rules", "error", err)
		return
	}
	defer rows.Close()

	ne.mu.Lock()
	defer ne.mu.Unlock()
	ne.rules = nil

	for rows.Next() {
		var rule NotificationRule
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.ConditionType, &rule.ConditionValue, &rule.Level, &rule.Enabled, &rule.CreatedAt); err != nil {
			continue
		}
		ne.rules = append(ne.rules, rule)
	}

	notifLog.Info("loaded active rules", "count", len(ne.rules))
}

// loadChannels loads notification channels from the database.
func (ne *NotificationEngine) loadChannels() {
	rows, err := db.DB.Query("SELECT id, name, type, config, enabled, created_at FROM notification_channels WHERE enabled = 1")
	if err != nil {
		notifLog.Error("failed to load channels", "error", err)
		return
	}
	defer rows.Close()

	ne.mu.Lock()
	defer ne.mu.Unlock()
	ne.channels = nil

	for rows.Next() {
		var ch NotificationChannel
		if err := rows.Scan(&ch.ID, &ch.Name, &ch.Type, &ch.Config, &ch.Enabled, &ch.CreatedAt); err != nil {
			continue
		}
		ne.channels = append(ne.channels, ch)
	}
}

// ReloadRules refreshes the rules and channels from the database.
func (ne *NotificationEngine) ReloadRules() {
	ne.loadRules()
	ne.loadChannels()
}

// Dispatch sends a notification via WebSocket and all configured webhook channels.
func (ne *NotificationEngine) Dispatch(n Notification) {
	// Persist to database
	result, err := db.DB.Exec(
		"INSERT INTO notifications (user_id, level, title, message) VALUES (?, ?, ?, ?)",
		n.UserID, string(n.Level), n.Title, n.Message,
	)
	if err != nil {
		notifLog.Error("failed to persist notification", "error", err)
	} else {
		id, _ := result.LastInsertId()
		n.ID = int(id)
	}

	// Broadcast via WebSocket
	if ne.dispatchFn != nil {
		ne.dispatchFn(n)
	}

	// Send via webhook channels
	ne.mu.RLock()
	channels := make([]NotificationChannel, len(ne.channels))
	copy(channels, ne.channels)
	ne.mu.RUnlock()

	for _, ch := range channels {
		go ne.sendToChannel(ch, n)
	}
}

// sendToChannel dispatches a notification to a specific webhook channel
// and records the delivery result in notification_delivery_log (Phase 13).
func (ne *NotificationEngine) sendToChannel(ch NotificationChannel, n Notification) {
	var config map[string]string
	if err := json.Unmarshal([]byte(ch.Config), &config); err != nil {
		notifLog.Error("invalid channel config", "channel", ch.Name, "error", err)
		recordDelivery(ch.ID, ch.Type, n.ID, "failed", 0, "invalid channel config: "+err.Error())
		return
	}

	var attempts int
	var deliveryErr error

	switch ch.Type {
	case "discord":
		attempts, deliveryErr = sendWebhookWithRetry(config["url"], buildDiscordPayload(n))
	case "telegram":
		if config["bot_token"] == "" || config["chat_id"] == "" {
			recordDelivery(ch.ID, ch.Type, n.ID, "failed", 0, "missing bot_token or chat_id")
			return
		}
		url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", config["bot_token"])
		attempts, deliveryErr = sendWebhookWithRetry(url, buildTelegramPayload(config["chat_id"], n))
	case "slack":
		attempts, deliveryErr = sendWebhookWithRetry(config["url"], buildSlackPayload(n))
	case "custom":
		attempts, deliveryErr = sendWebhookWithRetry(config["url"], buildCustomPayload(n))
	default:
		notifLog.Warn("unknown channel type", "channel", ch.Name, "type", ch.Type)
		recordDelivery(ch.ID, ch.Type, n.ID, "failed", 0, "unknown channel type: "+ch.Type)
		return
	}

	if deliveryErr != nil {
		recordDelivery(ch.ID, ch.Type, n.ID, "failed", attempts, deliveryErr.Error())
	} else {
		recordDelivery(ch.ID, ch.Type, n.ID, "delivered", attempts, "")
	}
}

// recordDelivery logs a webhook delivery attempt to the audit table (Phase 13).
func recordDelivery(channelID int, channelType string, notificationID int, status string, attempts int, lastError string) {
	completedAt := ""
	if status == "delivered" || status == "failed" {
		completedAt = time.Now().Format(time.RFC3339)
	}
	_, err := db.DB.Exec(
		`INSERT INTO notification_delivery_log (channel_id, channel_type, notification_id, status, attempts, last_error, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		channelID, channelType, notificationID, status, attempts, lastError, completedAt,
	)
	if err != nil {
		notifLog.Error("failed to record delivery log", "error", err)
	}
}

// evaluationLoop periodically checks rules against the current system state.
func (ne *NotificationEngine) evaluationLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	ctx := SubsystemContext()
	for {
		select {
		case <-ctx.Done():
			notifLog.Info("shutdown signal received, stopping")
			return
		case <-ticker.C:
			ne.evaluateRules()
		}
	}
}

// evaluateRules checks all active rules against the current system metrics.
func (ne *NotificationEngine) evaluateRules() {
	// Acquire the dedicated evaluation lock to prevent concurrent map access panics
	ne.evalMu.Lock()
	defer ne.evalMu.Unlock()

	metrics := GetSystemMetricsCore()

	ne.mu.RLock()
	rules := make([]NotificationRule, len(ne.rules))
	copy(rules, ne.rules)
	ne.mu.RUnlock()

	for _, rule := range rules {
		// Cooldown: don't fire the same rule more than once per 5 minutes
		ruleKey := strconv.Itoa(rule.ID)
		if lastFired, ok := ne.lastEvaluation[ruleKey]; ok {
			if time.Since(lastFired) < 5*time.Minute {
				continue
			}
		}

		triggered := false
		var message string

		switch rule.ConditionType {
		case "disk_usage":
			threshold, _ := strconv.ParseFloat(rule.ConditionValue, 64)
			if len(metrics.Disks) > 0 {
				for _, disk := range metrics.Disks {
					if disk.UsedPct >= threshold {
						triggered = true
						message = "Disk " + disk.MountPoint + " is at " + strconv.FormatFloat(disk.UsedPct, 'f', 1, 64) + "% usage"
						break
					}
				}
			}

		case "cpu_usage":
			threshold, _ := strconv.ParseFloat(rule.ConditionValue, 64)
			if metrics.CPUUsage >= threshold {
				triggered = true
				message = "CPU usage is at " + strconv.FormatFloat(metrics.CPUUsage, 'f', 1, 64) + "%"
			}

		case "memory_usage":
			threshold, _ := strconv.ParseFloat(rule.ConditionValue, 64)
			if total, ok := metrics.Memory["total"]; ok && total > 0 {
				used := metrics.Memory["used"]
				pct := (used / total) * 100
				if pct >= threshold {
					triggered = true
					message = "Memory usage is at " + strconv.FormatFloat(pct, 'f', 1, 64) + "%"
				}
			}
		}

		if triggered {
			ne.lastEvaluation[ruleKey] = time.Now()
			ne.Dispatch(Notification{
				Level:   NotificationType(rule.Level),
				Title:   rule.Name,
				Message: message,
			})
		}
	}
}

// TestChannel sends a test notification to a specific channel.
func (ne *NotificationEngine) TestChannel(channel NotificationChannel) error {
	testNotification := Notification{
		Level:   NotifyInfo,
		Title:   "AetherFlow Test Notification",
		Message: "This is a test notification from AetherFlow at " + time.Now().Format(time.RFC3339),
	}
	ne.sendToChannel(channel, testNotification)
	return nil
}
