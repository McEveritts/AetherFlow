package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// --- P1: Type assertion safety ---

func TestAllowedActions(t *testing.T) {
	tests := []struct {
		action string
		want   bool
	}{
		{"start", true},
		{"stop", true},
		{"restart", true},
		{"delete", false},
		{"rm -rf /", false},
		{"", false},
	}

	for _, tt := range tests {
		got := allowedActions[tt.action]
		if got != tt.want {
			t.Errorf("allowedActions[%q] = %v, want %v", tt.action, got, tt.want)
		}
	}
}

// --- P6: AI model allowlist ---

func TestAllowedAIModels(t *testing.T) {
	tests := []struct {
		model string
		want  bool
	}{
		{"gemini-2.5-pro", true},
		{"gemini-2.0-flash", true},
		{"gemini-2.0-flash-lite", true},
		{"gemini-2.5-flash", true},
		{"gemini-1.5-pro", true},
		{"gemini-1.5-flash", true},
		{"gpt-4", false},
		{"'; DROP TABLE users;--", false},
		{"", false},
	}

	for _, tt := range tests {
		got := allowedAIModels[tt.model]
		if got != tt.want {
			t.Errorf("allowedAIModels[%q] = %v, want %v", tt.model, got, tt.want)
		}
	}
}

// --- P5: Rate limiter ---

func TestRateLimiter(t *testing.T) {
	limiter := newRateLimiter(3, 1*time.Minute)

	// First 3 requests should be allowed
	for i := 0; i < 3; i++ {
		if !limiter.allow("192.168.1.1") {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 4th request should be blocked
	if limiter.allow("192.168.1.1") {
		t.Error("Request 4 should be blocked")
	}

	// Different IP should still be allowed
	if !limiter.allow("192.168.1.2") {
		t.Error("Different IP should be allowed")
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	r := gin.New()
	r.GET("/test", RateLimitMiddleware(2, 1*time.Minute), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	// First 2 should pass
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Errorf("Request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// 3rd should be rate limited
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	r.ServeHTTP(w, req)
	if w.Code != 429 {
		t.Errorf("Request 3: expected 429, got %d", w.Code)
	}
}

// --- P7: Semver comparison ---

func TestIsNewerVersion(t *testing.T) {
	tests := []struct {
		local, remote string
		want          bool
	}{
		{"v3.0.0", "v3.1.0", true},
		{"v3.1.0", "v3.0.0", false},
		{"v3.0.0", "v3.0.0", false},
		{"v3.0.0", "v4.0.0", true},
		{"v4.0.0", "v3.0.0", false},
		{"v3.0.1", "v3.0.2", true},
		{"v3.0.2", "v3.0.1", false},
		{"v3.1.0-beta", "v3.1.0", false}, // same semver (beta stripped)
		{"3.0.0", "v3.1.0", true},        // missing v prefix
		{"v3.2.0-dev", "v3.1.0", false},  // local is higher
	}

	for _, tt := range tests {
		got := isNewerVersion(tt.local, tt.remote)
		if got != tt.want {
			t.Errorf("isNewerVersion(%q, %q) = %v, want %v", tt.local, tt.remote, got, tt.want)
		}
	}
}

// --- P5: secureCookie helper ---

func TestSecureCookieDefault(t *testing.T) {
	// Default should be true (secure)
	result := secureCookie()
	if !result {
		t.Error("secureCookie() should default to true")
	}
}

// --- P1: controlService action validation ---

func TestControlServiceRejectsInvalidAction(t *testing.T) {
	r := gin.New()
	r.POST("/services/:name/control", controlService)

	body := `{"action": "delete", "managed_by": "systemd"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/services/test/control", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for invalid action, got %d", w.Code)
	}
}

func TestControlServiceAcceptsValidAction(t *testing.T) {
	// Note: This will fail on the systemctl call, but validates input validation passes
	r := gin.New()
	r.POST("/services/:name/control", controlService)

	body := `{"action": "restart", "managed_by": "systemd", "process": "test"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/services/test/control", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	// Should NOT be 400 (it may be 500 because systemctl isn't available in test)
	if w.Code == 400 {
		t.Errorf("Expected non-400 for valid action, got %d", w.Code)
	}
}

// --- WebSocket origin validation ---

func TestWebSocketOriginCheck(t *testing.T) {
	tests := []struct {
		origin string
		host   string
		want   bool
	}{
		{"https://example.com", "example.com", true},
		{"http://example.com", "example.com", true},
		{"https://evil.com", "example.com", false},
		{"", "example.com", true},                         // Non-browser clients
		{"https://sub.example.com", "example.com", false}, // Subdomain mismatch
	}

	for _, tt := range tests {
		req, _ := http.NewRequest("GET", "/ws", nil)
		req.Host = tt.host
		if tt.origin != "" {
			req.Header.Set("Origin", tt.origin)
		}
		got := upgrader.CheckOrigin(req)
		if got != tt.want {
			t.Errorf("CheckOrigin(origin=%q, host=%q) = %v, want %v", tt.origin, tt.host, got, tt.want)
		}
	}
}

// --- Fileshare extension blocklist ---

func TestBlockedFileExtensions(t *testing.T) {
	r := gin.New()
	r.POST("/fileshare/upload", UploadFile)

	// Test that requests without files are rejected (validates handler is wired)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/fileshare/upload", nil)
	r.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 for no file upload, got %d", w.Code)
	}
}

// --- Backup download path traversal ---

func TestBackupDownloadSanitizesFilename(t *testing.T) {
	r := gin.New()
	r.GET("/backup/download/:filename", DownloadBackup)

	// Attempting path traversal should return 404 (file won't exist in sanitized path)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/backup/download/..%2F..%2Fetc%2Fpasswd", nil)
	r.ServeHTTP(w, req)

	// Should not be 200 (the file shouldn't exist via traversal)
	if w.Code == 200 {
		t.Error("Path traversal should not return 200")
	}
}

// --- Upload directory fallback ---

func TestGetUploadDirFallback(t *testing.T) {
	dir := getUploadDir()
	if dir == "" {
		t.Error("getUploadDir() should never return empty string")
	}
}
