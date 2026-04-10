package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

const webhookTimeout = 5 * time.Second
const maxRetries = 3

// SendDiscordWebhook sends a notification as a Discord embed.
func SendDiscordWebhook(webhookURL string, n Notification) {
	if webhookURL == "" {
		return
	}
	sendWebhookWithRetry(webhookURL, buildDiscordPayload(n))
}

func buildDiscordPayload(n Notification) map[string]interface{} {
	color := 0x3498db // blue (info)
	switch n.Level {
	case NotifyWarning:
		color = 0xf39c12 // yellow
	case NotifyCritical:
		color = 0xe74c3c // red
	case NotifySuccess:
		color = 0x2ecc71 // green
	}
	return map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("🔔 %s", n.Title),
				"description": n.Message,
				"color":       color,
				"footer": map[string]string{
					"text": "AetherFlow Notification Engine",
				},
				"timestamp": time.Now().Format(time.RFC3339),
			},
		},
	}
}

// SendTelegramWebhook sends a notification via the Telegram Bot API.
func SendTelegramWebhook(botToken, chatID string, n Notification) {
	if botToken == "" || chatID == "" {
		return
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	sendWebhookWithRetry(url, buildTelegramPayload(chatID, n))
}

func buildTelegramPayload(chatID string, n Notification) map[string]interface{} {
	emoji := "ℹ️"
	switch n.Level {
	case NotifyWarning:
		emoji = "⚠️"
	case NotifyCritical:
		emoji = "🚨"
	case NotifySuccess:
		emoji = "✅"
	}
	return map[string]interface{}{
		"chat_id":    chatID,
		"text":       fmt.Sprintf("%s *%s*\n%s", emoji, escapeMarkdown(n.Title), escapeMarkdown(n.Message)),
		"parse_mode": "Markdown",
	}
}

// SendSlackWebhook sends a notification as a Slack Block Kit message.
func SendSlackWebhook(webhookURL string, n Notification) {
	if webhookURL == "" {
		return
	}
	sendWebhookWithRetry(webhookURL, buildSlackPayload(n))
}

func buildSlackPayload(n Notification) map[string]interface{} {
	emoji := ":information_source:"
	switch n.Level {
	case NotifyWarning:
		emoji = ":warning:"
	case NotifyCritical:
		emoji = ":rotating_light:"
	case NotifySuccess:
		emoji = ":white_check_mark:"
	}
	return map[string]interface{}{
		"blocks": []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": fmt.Sprintf("%s *%s*\n%s", emoji, n.Title, n.Message),
				},
			},
			{
				"type": "context",
				"elements": []map[string]string{
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("_AetherFlow • %s_", time.Now().Format("Jan 2 15:04")),
					},
				},
			},
		},
	}
}

// SendCustomWebhook sends a raw JSON POST to a custom URL.
func SendCustomWebhook(webhookURL string, n Notification) {
	if webhookURL == "" {
		return
	}
	sendWebhookWithRetry(webhookURL, buildCustomPayload(n))
}

func buildCustomPayload(n Notification) map[string]interface{} {
	return map[string]interface{}{
		"level":     string(n.Level),
		"title":     n.Title,
		"message":   n.Message,
		"timestamp": time.Now().Format(time.RFC3339),
		"source":    "aetherflow",
	}
}

// sendWebhookWithRetry sends a JSON POST with exponential backoff retry.
// Returns the number of attempts made and any final error.
func sendWebhookWithRetry(url string, payload interface{}) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Webhook: failed to marshal payload: %v", err)
		return 0, fmt.Errorf("marshal error: %w", err)
	}

	client := &http.Client{Timeout: webhookTimeout}
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 1s, 2s, 4s
			time.Sleep(time.Duration(1<<uint(attempt-1)) * time.Second)
		}

		resp, err := client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("Webhook: attempt %d failed for %s: %v", attempt+1, truncateURL(url), err)
			lastErr = err
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return attempt + 1, nil // Success
		}

		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		log.Printf("Webhook: attempt %d returned %d for %s", attempt+1, resp.StatusCode, truncateURL(url))
	}

	log.Printf("Webhook: all %d attempts failed for %s", maxRetries, truncateURL(url))
	return maxRetries, lastErr
}

// truncateURL returns a safe version of the URL for logging (hides secrets).
func truncateURL(url string) string {
	if len(url) > 50 {
		return url[:50] + "..."
	}
	return url
}

// escapeMarkdown escapes special Markdown characters for Telegram.
func escapeMarkdown(s string) string {
	replacer := bytes.NewBuffer(nil)
	for _, c := range s {
		switch c {
		case '_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!':
			replacer.WriteRune('\\')
		}
		replacer.WriteRune(c)
	}
	return replacer.String()
}
