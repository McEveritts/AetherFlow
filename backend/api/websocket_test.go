package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// ── Phase 29: WebSocket Domain — Ticket Lifecycle Tests ─────────────────
//
// These tests verify the WebSocket ticket authentication pipeline:
// issuance, single-use consumption, missing ticket rejection,
// IP-binding verification, and the Hub registration machinery.

// --- Ticket Issuance ---

func TestIssueWSTicket_ReturnsTicket(t *testing.T) {
	r := gin.New()
	r.GET("/ws/ticket", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Next()
	}, IssueWSTicket)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ws/ticket", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
	ticket := body["ticket"]
	if ticket == "" {
		t.Error("Expected non-empty ticket")
	}
	if len(ticket) != 32 { // 16 bytes hex-encoded = 32 chars
		t.Errorf("Expected 32-char hex ticket, got %d chars: %q", len(ticket), ticket)
	}
}

func TestIssueWSTicket_Unauthorized(t *testing.T) {
	r := gin.New()
	// No user_id set in context
	r.GET("/ws/ticket", IssueWSTicket)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ws/ticket", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 without user_id, got %d", w.Code)
	}
}

func TestIssueWSTicket_UniquePerRequest(t *testing.T) {
	r := gin.New()
	r.GET("/ws/ticket", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Next()
	}, IssueWSTicket)

	tickets := make(map[string]bool)
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/ws/ticket", nil)
		r.ServeHTTP(w, req)

		var body map[string]string
		json.Unmarshal(w.Body.Bytes(), &body)
		ticket := body["ticket"]
		if tickets[ticket] {
			t.Errorf("Duplicate ticket issued: %s", ticket)
		}
		tickets[ticket] = true
	}
}

// --- HandleWebSocket Rejection Tests ---

func TestHandleWebSocket_MissingTicket(t *testing.T) {
	r := gin.New()
	r.GET("/ws", HandleWebSocket)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ws", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for missing ticket, got %d", w.Code)
	}

	var body APIError
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
	if body.Code != "WS_MISSING_TICKET" {
		t.Errorf("Expected code=WS_MISSING_TICKET, got %q", body.Code)
	}
}

func TestHandleWebSocket_InvalidTicket(t *testing.T) {
	r := gin.New()
	r.GET("/ws", HandleWebSocket)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ws?ticket=nonexistent-ticket", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for invalid ticket, got %d", w.Code)
	}

	var body APIError
	json.Unmarshal(w.Body.Bytes(), &body)
	if body.Code != "WS_INVALID_TICKET" {
		t.Errorf("Expected code=WS_INVALID_TICKET, got %q", body.Code)
	}
}

func TestHandleWebSocket_SingleUse(t *testing.T) {
	// Issue a real ticket
	r := gin.New()
	r.GET("/ws/ticket", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Next()
	}, IssueWSTicket)
	r.GET("/ws", HandleWebSocket)

	// Get a ticket
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("GET", "/ws/ticket", nil)
	r.ServeHTTP(w1, req1)
	var body map[string]string
	json.Unmarshal(w1.Body.Bytes(), &body)
	ticket := body["ticket"]

	// First use — consumes the ticket (will fail upgrade but that's OK)
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/ws?ticket="+ticket, nil)
	r.ServeHTTP(w2, req2)
	// The upgrade will fail (no actual websocket handshake), but ticket is consumed

	// Second use — should be rejected as consumed
	w3 := httptest.NewRecorder()
	req3, _ := http.NewRequest("GET", "/ws?ticket="+ticket, nil)
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for reused ticket, got %d", w3.Code)
	}

	var errBody APIError
	json.Unmarshal(w3.Body.Bytes(), &errBody)
	if errBody.Code != "WS_INVALID_TICKET" {
		t.Errorf("Expected WS_INVALID_TICKET for reused ticket, got %q", errBody.Code)
	}
}

func TestHandleWebSocket_IPMismatch(t *testing.T) {
	// Directly inject a ticket with a specific IP
	ticket := "test-ip-mismatch-ticket"
	wsTicketsMu.Lock()
	wsTickets[ticket] = wsTicketEntry{
		UserID:   1,
		ClientIP: "192.168.1.100", // Issued to this IP
	}
	wsTicketsMu.Unlock()

	r := gin.New()
	r.GET("/ws", HandleWebSocket)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ws?ticket="+ticket, nil)
	// httptest uses empty RemoteAddr which maps to different IP
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 for IP mismatch, got %d", w.Code)
	}

	var body APIError
	json.Unmarshal(w.Body.Bytes(), &body)
	if body.Code != "WS_IP_MISMATCH" {
		t.Errorf("Expected WS_IP_MISMATCH, got %q", body.Code)
	}
}

// --- Hub Tests ---

func TestHub_RegisterAndUnregister(t *testing.T) {
	hub := newHub()
	go hub.run()

	// Give the hub goroutine time to start
	time.Sleep(10 * time.Millisecond)

	client := &Client{
		hub:  hub,
		send: make(chan []byte, 256),
	}

	// Register
	hub.register <- client
	time.Sleep(10 * time.Millisecond)

	hub.mu.Lock()
	count := len(hub.clients)
	hub.mu.Unlock()

	if count != 1 {
		t.Errorf("Expected 1 client after register, got %d", count)
	}

	// Unregister
	hub.unregister <- client
	time.Sleep(10 * time.Millisecond)

	hub.mu.Lock()
	count = len(hub.clients)
	hub.mu.Unlock()

	if count != 0 {
		t.Errorf("Expected 0 clients after unregister, got %d", count)
	}
}

func TestHub_BroadcastToClients(t *testing.T) {
	hub := newHub()
	go hub.run()
	time.Sleep(10 * time.Millisecond)

	client1 := &Client{hub: hub, send: make(chan []byte, 256)}
	client2 := &Client{hub: hub, send: make(chan []byte, 256)}

	hub.register <- client1
	hub.register <- client2
	time.Sleep(10 * time.Millisecond)

	// Broadcast a message
	msg := []byte(`{"type":"test","data":"hello"}`)
	hub.broadcast <- msg
	time.Sleep(10 * time.Millisecond)

	// Both clients should have received it
	select {
	case received := <-client1.send:
		if string(received) != string(msg) {
			t.Errorf("Client1 received wrong message: %s", received)
		}
	default:
		t.Error("Client1 did not receive broadcast")
	}

	select {
	case received := <-client2.send:
		if string(received) != string(msg) {
			t.Errorf("Client2 received wrong message: %s", received)
		}
	default:
		t.Error("Client2 did not receive broadcast")
	}
}

// --- WebSocket Constants ---

func TestWebSocketTimingConstants(t *testing.T) {
	// Verify invariant: pingPeriod < pongWait
	if pingPeriod >= pongWait {
		t.Errorf("pingPeriod (%v) must be less than pongWait (%v)", pingPeriod, pongWait)
	}
	if writeWait <= 0 {
		t.Error("writeWait must be positive")
	}
}

// --- Health Probes ---

func TestHealthLive_AlwaysOK(t *testing.T) {
	r := gin.New()
	r.GET("/health/live", HealthLive)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health/live", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 from liveness probe, got %d", w.Code)
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "alive" {
		t.Errorf("Expected status=alive, got %q", body["status"])
	}
}
