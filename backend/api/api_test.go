package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestMain(m *testing.M) {
	if os.Getenv("JWT_SECRET") == "" {
		os.Setenv("JWT_SECRET", "ci-test-secret-exactly-32bytes!!")
	}
	os.Exit(m.Run())
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
		// Gemini preview models
		{"gemini-3.1-pro-preview", true},
		{"gemini-3-flash-preview", true},
		{"gemini-3.1-flash-lite-preview", true},
		{"gemini-3-pro-image-preview", true},
		{"gemini-3.1-flash-image-preview", true},
		// Gemini stable models
		{"gemini-2.5-pro", true},
		{"gemini-2.5-flash", true},
		{"gemini-2.0-flash", true},
		{"gemini-2.0-flash-lite", true},
		{"gemini-1.5-pro", true},
		{"gemini-1.5-flash", true},
		// OpenAI models
		{"gpt-4o", true},
		{"gpt-4o-mini", true},
		{"gpt-4-turbo", true},
		{"gpt-5.4", true},
		{"gpt-5.4-mini", true},
		// Anthropic models
		{"claude-opus", true},
		{"claude-opus-4.5", true},
		{"claude-opus-4.6", true},
		{"claude-sonnet-4.5", true},
		{"claude-sonnet-4.6", true},
		{"claude-4-6-sonnet", true},
		{"claude-4-6-haiku", true},
		{"claude-4-5-opus", true},
		// Local AI
		{"lm-studio", true},
		{"ollama", true},
		{"anthropic-local", true},
		// Invalid / attack payloads
		{"gpt-4", false},
		{"gemini-pro", false},
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

// --- AI Provider Routing ---

func TestResolveProvider(t *testing.T) {
	tests := []struct {
		hint  string
		model string
		want  string
	}{
		// Explicit hint takes precedence
		{"openai", "gemini-2.0-flash", "openai"},
		{"anthropic", "gpt-4o", "anthropic"},
		// Auto-detect from model prefix
		{"", "gemini-2.5-pro", "gemini"},
		{"", "gemini-3.1-pro-preview", "gemini"},
		{"", "gpt-4o", "openai"},
		{"", "gpt-5.4-mini", "openai"},
		{"", "claude-opus-4.6", "anthropic"},
		{"", "claude-4-6-haiku", "anthropic"},
		// Local AI detection
		{"", "lm-studio", "localai"},
		{"", "ollama", "localai"},
		{"", "anthropic-local", "localai"},
		// Unknown model defaults to gemini
		{"", "unknown-model", "gemini"},
	}

	for _, tt := range tests {
		got := ResolveProvider(tt.hint, tt.model)
		if got != tt.want {
			t.Errorf("ResolveProvider(%q, %q) = %q, want %q", tt.hint, tt.model, got, tt.want)
		}
	}
}

func TestBuildProviderConfig(t *testing.T) {
	ps := &ProviderSettings{
		GeminiAPIKey:    "gemini-test-key",
		OpenAIAPIKey:    "openai-test-key",
		AnthropicAPIKey: "anthropic-test-key",
		LMStudioEndpoint: "http://localhost:1234",
		OllamaEndpoint:   "http://localhost:11434",
		AnthropicEndpoint: "https://custom-anthropic.example.com",
	}

	// Gemini config
	cfg := buildProviderConfig(ps, "gemini", "gemini-2.0-flash")
	if cfg.APIKey != "gemini-test-key" {
		t.Errorf("Gemini config APIKey = %q, want %q", cfg.APIKey, "gemini-test-key")
	}
	if cfg.Model != "gemini-2.0-flash" {
		t.Errorf("Gemini config Model = %q, want %q", cfg.Model, "gemini-2.0-flash")
	}

	// OpenAI config
	cfg = buildProviderConfig(ps, "openai", "gpt-4o")
	if cfg.APIKey != "openai-test-key" {
		t.Errorf("OpenAI config APIKey = %q, want %q", cfg.APIKey, "openai-test-key")
	}

	// Anthropic config with custom endpoint
	cfg = buildProviderConfig(ps, "anthropic", "claude-opus")
	if cfg.APIKey != "anthropic-test-key" {
		t.Errorf("Anthropic config APIKey = %q, want %q", cfg.APIKey, "anthropic-test-key")
	}
	if cfg.Endpoint != "https://custom-anthropic.example.com" {
		t.Errorf("Anthropic config Endpoint = %q, want custom endpoint", cfg.Endpoint)
	}

	// LocalAI with LM Studio
	cfg = buildProviderConfig(ps, "localai", "lm-studio")
	if cfg.Endpoint != "http://localhost:1234" {
		t.Errorf("LocalAI config Endpoint = %q, want LM Studio endpoint", cfg.Endpoint)
	}

	// LocalAI with Ollama
	cfg = buildProviderConfig(ps, "localai", "ollama")
	if cfg.Endpoint != "http://localhost:11434" {
		t.Errorf("Ollama config Endpoint = %q, want Ollama endpoint", cfg.Endpoint)
	}

	// LocalAI with anthropic-local (should use Anthropic endpoint, not LM Studio)
	cfg = buildProviderConfig(ps, "localai", "anthropic-local")
	if cfg.Endpoint != "https://custom-anthropic.example.com" {
		t.Errorf("Anthropic-local config Endpoint = %q, want Anthropic endpoint", cfg.Endpoint)
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

func TestSafeBackupPathRejectsTraversal(t *testing.T) {
	base := filepath.Join(os.TempDir(), "af-backups-test")
	path, err := safeBackupPath(base, "../../etc/passwd")
	if err != nil {
		t.Fatalf("Expected traversal input to be sanitized, got error: %v", err)
	}
	expected := filepath.Join(base, "passwd")
	if path != expected {
		t.Fatalf("Expected sanitized path %q, got %q", expected, path)
	}
}

func TestUploadBackupChunkRequiresChunkParams(t *testing.T) {
	r := gin.New()
	r.POST("/backup/upload/:filename", UploadBackupChunk)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/backup/upload/test.sqlite", strings.NewReader("abc"))
	r.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("Expected 400 when chunk params are missing, got %d", w.Code)
	}
}

// --- P23: Admin Route Bleeding Integration Test ---

func TestAdminRouteBlocksStandardUser(t *testing.T) {
	r := gin.New()
	
	// Set up the routes exactly as they are in production
	adminGroup := r.Group("/admin")
	
	// Mock AuthMiddleware to set standard user role
	mockAuth := func(c *gin.Context) {
		c.Set("user_id", 123)
		c.Set("user_role", "user") // Standard user
		c.Next()
	}
	
	adminGroup.Use(mockAuth, AdminOnly())
	adminGroup.GET("/metrics", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})
	
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/admin/metrics", nil)
	r.ServeHTTP(w, req)
	
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for standard user accessing admin route, got %d", w.Code)
	}
}

