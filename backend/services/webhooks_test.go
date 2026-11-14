package services

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestSendWebhookWithRetry_Success verifies that a webhook is delivered
// on the first attempt against a healthy endpoint.
func TestSendWebhookWithRetry_Success(t *testing.T) {
	allowLoopbackWebhookTargetsForTest.Store(true)
	defer allowLoopbackWebhookTargetsForTest.Store(false)

	var received []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		received = body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	payload := map[string]string{"test": "data"}
	attempts, err := sendWebhookWithRetry(server.URL, payload)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if attempts != 1 {
		t.Errorf("Expected 1 attempt, got %d", attempts)
	}

	mu.Lock()
	defer mu.Unlock()
	if received == nil {
		t.Fatal("Server did not receive request")
	}

	var result map[string]string
	if err := json.Unmarshal(received, &result); err != nil {
		t.Fatalf("Invalid JSON received: %v", err)
	}
	if result["test"] != "data" {
		t.Errorf("Expected test=data, got %q", result["test"])
	}
}

// TestSendWebhookWithRetry_RetryOnServerError verifies exponential backoff retry
// when the server returns 500 errors, eventually failing after maxRetries.
func TestSendWebhookWithRetry_RetryOnServerError(t *testing.T) {
	allowLoopbackWebhookTargetsForTest.Store(true)
	defer allowLoopbackWebhookTargetsForTest.Store(false)

	var hitCount int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hitCount++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	attempts, err := sendWebhookWithRetry(server.URL, map[string]string{"test": "retry"})

	if err == nil {
		t.Fatal("Expected error after all retries exhausted")
	}
	if attempts != maxRetries {
		t.Errorf("Expected %d attempts, got %d", maxRetries, attempts)
	}

	mu.Lock()
	defer mu.Unlock()
	if hitCount != maxRetries {
		t.Errorf("Expected %d server hits, got %d", maxRetries, hitCount)
	}
}

// TestSendWebhookWithRetry_RetryThenSucceed verifies that the retry mechanism
// succeeds after transient failures.
func TestSendWebhookWithRetry_RetryThenSucceed(t *testing.T) {
	allowLoopbackWebhookTargetsForTest.Store(true)
	defer allowLoopbackWebhookTargetsForTest.Store(false)

	var hitCount int
	var mu sync.Mutex

	// Fail on first attempt, succeed on second
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hitCount++
		current := hitCount
		mu.Unlock()

		if current == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	attempts, err := sendWebhookWithRetry(server.URL, map[string]string{"test": "retry-succeed"})

	if err != nil {
		t.Fatalf("Expected success on retry, got: %v", err)
	}
	if attempts != 2 {
		t.Errorf("Expected 2 attempts (1 fail + 1 success), got %d", attempts)
	}
}

// TestBuildDiscordPayload verifies Discord embed formatting.
func TestBuildDiscordPayload(t *testing.T) {
	n := Notification{
		Level:   NotifyCritical,
		Title:   "Disk Full",
		Message: "Root partition at 95%",
	}

	payload := buildDiscordPayload(n)
	embeds, ok := payload["embeds"].([]map[string]interface{})
	if !ok || len(embeds) == 0 {
		t.Fatal("Expected embeds array")
	}

	embed := embeds[0]
	if embed["color"] != 0xe74c3c {
		t.Errorf("Expected critical red color, got %v", embed["color"])
	}
	if desc, ok := embed["description"].(string); !ok || desc != "Root partition at 95%" {
		t.Errorf("Unexpected description: %v", embed["description"])
	}
}

// TestBuildSlackPayload verifies Slack Block Kit formatting.
func TestBuildSlackPayload(t *testing.T) {
	n := Notification{
		Level:   NotifySuccess,
		Title:   "Backup Complete",
		Message: "Daily backup finished successfully",
	}

	payload := buildSlackPayload(n)
	blocks, ok := payload["blocks"].([]map[string]interface{})
	if !ok || len(blocks) < 1 {
		t.Fatal("Expected blocks array")
	}

	section := blocks[0]
	if section["type"] != "section" {
		t.Errorf("Expected section type, got %v", section["type"])
	}
}

// TestBuildCustomPayload verifies custom webhook JSON shape.
func TestBuildCustomPayload(t *testing.T) {
	n := Notification{
		Level:   NotifyWarning,
		Title:   "High CPU",
		Message: "CPU at 90%",
	}

	payload := buildCustomPayload(n)
	if payload["source"] != "aetherflow" {
		t.Errorf("Expected source=aetherflow, got %v", payload["source"])
	}
	if payload["level"] != "warning" {
		t.Errorf("Expected level=warning, got %v", payload["level"])
	}
}

func TestValidatePublicWebhookURL_BlocksSSRF(t *testing.T) {
	blocked := []string{
		"http://127.0.0.1:8080/hook",
		"http://localhost:8080/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::ffff:169.254.169.254]/latest/meta-data/",
		"http://168.63.129.16/metadata",
		"http://10.0.0.5/hook",
		"http://192.168.1.10/hook",
		"http://100.64.0.10/hook",
		"http://[fd00:ec2::254]/latest",
		"https://user:pass@8.8.8.8/hook",
		"file:///etc/passwd",
	}
	for _, u := range blocked {
		if _, err := ValidatePublicWebhookURL(u); err == nil {
			t.Errorf("expected ValidatePublicWebhookURL(%q) to fail, but succeeded", u)
		}
	}
	if _, err := ValidatePublicWebhookURL("https://8.8.8.8/webhook"); err != nil {
		t.Fatalf("expected public IP webhook URL to succeed, got: %v", err)
	}
}

func TestSendWebhookWithRetry_BlocksRedirects(t *testing.T) {
	allowLoopbackWebhookTargetsForTest.Store(true)
	defer allowLoopbackWebhookTargetsForTest.Store(false)

	var redirectedHit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	attempts, err := sendWebhookWithRetry(redirector.URL, map[string]string{"hello": "world"})
	if err == nil {
		t.Fatal("expected 302 redirect from webhook endpoint to be rejected")
	}
	if attempts != 1 {
		t.Errorf("expected redirect rejection without retry amplification, got %d attempts", attempts)
	}
	if redirectedHit {
		t.Fatal("webhook client must never follow 3xx redirects")
	}
}

func TestValidateServerURL_BlocksIPv4MappedMetadata(t *testing.T) {
	blocked := []string{
		"http://169.254.169.254:80",
		"http://[::ffff:169.254.169.254]:80",
		"http://[::ffff:0.0.0.0]:8096",
		"http://168.63.129.16:80",
		"http://[fd00:ec2::254]:80",
		"http://metadata.google.internal:80",
	}
	for _, u := range blocked {
		if _, err := ValidateServerURL(u); err == nil {
			t.Errorf("expected ValidateServerURL(%q) to reject metadata/unspecified target", u)
		}
	}
	for _, allowed := range []string{"http://127.0.0.1:8096", "http://192.168.1.20:8096"} {
		if _, err := ValidateServerURL(allowed); err != nil {
			t.Errorf("expected ValidateServerURL(%q) to allow LAN/loopback Jellyfin, got: %v", allowed, err)
		}
	}
}
