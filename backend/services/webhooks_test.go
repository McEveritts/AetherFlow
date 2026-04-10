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
