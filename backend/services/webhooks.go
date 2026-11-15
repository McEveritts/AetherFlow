package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

const webhookTimeout = 5 * time.Second
const maxRetries = 3

var telegramBotTokenRe = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]{8,}$`)

// allowLoopbackWebhookTargetsForTest is strictly false in production and only
// toggled inside package-internal unit tests that exercise retry backoff against httptest.Server.
var allowLoopbackWebhookTargetsForTest atomic.Bool

// IsPublicWebhookAddr returns true only for globally routable public unicast IPv4/IPv6 addresses.
func IsPublicWebhookAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	u := addr.Unmap()
	if u.IsUnspecified() ||
		u.IsLoopback() ||
		u.IsPrivate() ||
		u.IsLinkLocalUnicast() ||
		u.IsLinkLocalMulticast() ||
		u.IsMulticast() {
		return false
	}
	if u.Is4() {
		b := u.As4()
		// 0.0.0.0/8
		if b[0] == 0 {
			return false
		}
		// 100.64.0.0/10 (Carrier-Grade NAT)
		if b[0] == 100 && (b[1]&0xC0) == 64 {
			return false
		}
		// 168.63.129.16 (Azure WireServer / IMDS)
		if b == [4]byte{168, 63, 129, 16} {
			return false
		}
		// 192.0.0.0/24, 192.0.2.0/24 (IETF / TEST-NET-1), and 192.88.99.0/24 (6to4 relay anycast)
		if b[0] == 192 && ((b[1] == 0 && (b[2] == 0 || b[2] == 2)) || (b[1] == 88 && b[2] == 99)) {
			return false
		}
		// 198.18.0.0/15 (Benchmarking)
		if b[0] == 198 && (b[1] == 18 || b[1] == 19) {
			return false
		}
		// 198.51.100.0/24 (TEST-NET-2)
		if b[0] == 198 && b[1] == 51 && b[2] == 100 {
			return false
		}
		// 203.0.113.0/24 (TEST-NET-3)
		if b[0] == 203 && b[1] == 0 && b[2] == 113 {
			return false
		}
		// 224.0.0.0/4 multicast + 240.0.0.0/4 reserved + 255.255.255.255 broadcast
		if b[0] >= 224 {
			return false
		}
		return true
	}

	b := u.As16()
	// Allow only Global Unicast 2000::/3 (rejects NAT64 64:ff9b::/96 & 64:ff9b:1::/48,
	// discard 100::/64, ULA fc00::/7, link-local fe80::/10, multicast ff00::/8, ::/128, ::1/128).
	if (b[0] & 0xe0) != 0x20 {
		return false
	}
	// 2001::/23 IETF protocol assignments (Teredo 2001::/32, benchmarking 2001:2::/48, ORCHID)
	if b[0] == 0x20 && b[1] == 0x01 && b[2] < 0x02 {
		return false
	}
	// 2001:db8::/32 documentation
	if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8 {
		return false
	}
	// 2002::/16 6to4
	if b[0] == 0x20 && b[1] == 0x02 {
		return false
	}
	// 3fff::/20 RFC 9637 documentation
	if b[0] == 0x3f && b[1] == 0xff && (b[2]&0xf0) == 0x00 {
		return false
	}
	return true
}

func isAllowedWebhookAddr(addr netip.Addr) bool {
	if allowLoopbackWebhookTargetsForTest.Load() && addr.IsValid() && addr.Unmap().IsLoopback() {
		return true
	}
	return IsPublicWebhookAddr(addr)
}

// ValidatePublicWebhookURL validates that rawURL is an http(s) URL without embedded credentials
// and resolves exclusively to public routable IP addresses.
func ValidatePublicWebhookURL(rawURL string) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", fmt.Errorf("webhook URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid webhook URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("webhook URL must start with http:// or https://")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("webhook URL must include a host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("webhook URL must not include embedded credentials")
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" ||
		host == "localhost" ||
		strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") ||
		host == "metadata.google.internal" ||
		host == "metadata.goog" ||
		host == "instance-data" {
		if !(allowLoopbackWebhookTargetsForTest.Load() && host == "localhost") {
			return "", fmt.Errorf("webhook URL host %q is not permitted", host)
		}
	}

	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		if !isAllowedWebhookAddr(ip) {
			return "", fmt.Errorf("webhook URL address %q is not permitted (non-public IP)", host)
		}
		return trimmed, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if lookupErr != nil || len(addrs) == 0 {
		return "", fmt.Errorf("webhook URL host %q could not be resolved", host)
	}
	for _, addr := range addrs {
		if !isAllowedWebhookAddr(addr) {
			return "", fmt.Errorf("webhook URL host %q resolves to a non-public IP address", host)
		}
	}
	return trimmed, nil
}

// ValidateNotificationChannelConfig validates channel configuration payloads before persistence.
func ValidateNotificationChannelConfig(chType string, rawConfig []byte) error {
	var cfg map[string]interface{}
	if err := json.Unmarshal(rawConfig, &cfg); err != nil || cfg == nil {
		return fmt.Errorf("config must be a valid JSON object")
	}
	strField := func(keys ...string) string {
		for _, k := range keys {
			if raw, ok := cfg[k]; ok {
				if s, okStr := raw.(string); okStr && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
		return ""
	}

	switch chType {
	case "discord", "slack", "custom", "webhook":
		u := strField("url", "webhook_url")
		if _, err := ValidatePublicWebhookURL(u); err != nil {
			return err
		}
	case "gotify":
		u := strField("url", "server_url")
		if _, err := ValidatePublicWebhookURL(u); err != nil {
			return err
		}
		if strField("token", "app_token") == "" {
			return fmt.Errorf("gotify channel requires token")
		}
	case "telegram":
		botToken := strField("bot_token")
		chatID := strField("chat_id")
		if botToken == "" || chatID == "" {
			return fmt.Errorf("telegram channel requires bot_token and chat_id")
		}
		if !telegramBotTokenRe.MatchString(botToken) {
			return fmt.Errorf("invalid telegram bot_token format")
		}
	case "email":
		u := strField("url", "webhook_url")
		if u == "" {
			return fmt.Errorf("email channel requires a configured HTTP relay url")
		}
		if _, err := ValidatePublicWebhookURL(u); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported channel type: %s", chType)
	}
	return nil
}

func newPinnedWebhookHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: webhookTimeout}
	transport := &http.Transport{
		Proxy:               nil,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid webhook dial address: %w", err)
			}
			portNum, err := net.DefaultResolver.LookupPort(ctx, network, port)
			if err != nil || portNum <= 0 || portNum > 65535 {
				return nil, fmt.Errorf("invalid webhook port: %q", port)
			}
			var verified []netip.Addr
			if literal, pErr := netip.ParseAddr(host); pErr == nil {
				if !isAllowedWebhookAddr(literal) {
					return nil, fmt.Errorf("blocked non-public webhook IP %s", literal)
				}
				verified = append(verified, literal.Unmap())
			} else {
				lowerHost := strings.ToLower(strings.TrimSpace(host))
				if lowerHost == "localhost" ||
					strings.HasSuffix(lowerHost, ".localhost") ||
					strings.HasSuffix(lowerHost, ".local") ||
					strings.HasSuffix(lowerHost, ".internal") ||
					lowerHost == "metadata.google.internal" {
					if !(allowLoopbackWebhookTargetsForTest.Load() && lowerHost == "localhost") {
						return nil, fmt.Errorf("blocked internal webhook hostname %q", host)
					}
				}
				resolved, lErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
				if lErr != nil || len(resolved) == 0 {
					return nil, fmt.Errorf("failed to resolve webhook host %q", host)
				}
				for _, ip := range resolved {
					if !isAllowedWebhookAddr(ip) {
						return nil, fmt.Errorf("webhook host %q resolved to non-public IP %s", host, ip)
					}
					verified = append(verified, ip.Unmap())
				}
			}
			var lastDialErr error
			for _, ip := range verified {
				target := netip.AddrPortFrom(ip, uint16(portNum)).String()
				conn, dErr := dialer.DialContext(ctx, network, target)
				if dErr == nil {
					return conn, nil
				}
				lastDialErr = dErr
			}
			if lastDialErr != nil {
				return nil, lastDialErr
			}
			return nil, fmt.Errorf("no routable public IP for %q", host)
		},
	}
	return &http.Client{
		Timeout:   webhookTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

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
	if botToken == "" || chatID == "" || !telegramBotTokenRe.MatchString(botToken) {
		return
	}
	targetURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	_, _ = sendWebhookWithRetry(targetURL, buildTelegramPayload(chatID, n))
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
	_, _ = sendWebhookWithRetry(webhookURL, buildCustomPayload(n))
}

func sendGotifyWebhook(baseURL, appToken string, n Notification) (int, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/message"
	cleanURL, valErr := ValidatePublicWebhookURL(endpoint)
	if valErr != nil {
		return 0, valErr
	}
	cleanToken := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r < 0x20 {
			return -1
		}
		return r
	}, appToken)
	body, err := json.Marshal(map[string]interface{}{
		"title":    n.Title,
		"message":  n.Message,
		"priority": 5,
	})
	if err != nil {
		return 0, err
	}
	client := newPinnedWebhookHTTPClient()
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<uint(attempt-1)) * time.Second)
		}
		req, reqErr := http.NewRequest(http.MethodPost, cleanURL, bytes.NewReader(body))
		if reqErr != nil {
			return attempt, reqErr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Gotify-Key", cleanToken)
		resp, doErr := client.Do(req) // #nosec G704 -- URL validated by ValidatePublicWebhookURL + connect-time IP-pinning DialContext
		if doErr != nil {
			lastErr = doErr
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return attempt + 1, nil
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return attempt + 1, fmt.Errorf("gotify redirect HTTP %d blocked", resp.StatusCode)
		}
		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return maxRetries, lastErr
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

// sendWebhookWithRetry sends a JSON POST with exponential backoff retry,
// connect-time public-IP pinning, no proxy inheritance, and no redirect following.
// Returns the number of attempts made and any final error.
func sendWebhookWithRetry(rawURL string, payload interface{}) (int, error) {
	cleanURL, valErr := ValidatePublicWebhookURL(rawURL)
	if valErr != nil {
		slog.Warn("webhook target blocked by SSRF policy", "url", truncateURL(rawURL), "error", valErr)
		return 0, valErr
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Info("Webhook: failed to marshal payload", "error", err)
		return 0, fmt.Errorf("marshal error: %w", err)
	}

	client := newPinnedWebhookHTTPClient()
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 1s, 2s, 4s
			time.Sleep(time.Duration(1<<uint(attempt-1)) * time.Second)
		}

		req, reqErr := http.NewRequest(http.MethodPost, cleanURL, bytes.NewReader(body))
		if reqErr != nil {
			return attempt, reqErr
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req) // #nosec G704 -- URL validated by ValidatePublicWebhookURL + connect-time IP-pinning DialContext
		if err != nil {
			slog.Warn("webhook attempt failed", "attempt", attempt+1, "url", truncateURL(cleanURL), "error", err)
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return attempt + 1, nil // Success
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return attempt + 1, fmt.Errorf("webhook redirect HTTP %d blocked", resp.StatusCode)
		}

		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		slog.Warn("webhook attempt returned non-2xx", "attempt", attempt+1, "status", resp.StatusCode, "url", truncateURL(cleanURL))
	}

	slog.Error("webhook: all attempts failed", "max_retries", maxRetries, "url", truncateURL(cleanURL))
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
