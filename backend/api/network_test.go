package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// ── Phase 29: Network Domain — Handler Validation Tests ─────────────────
//
// These tests verify network handler input validation at the API layer.
// They don't require actual WireGuard/Tailscale binaries since they test
// the Gin handler logic (binding, empty checks) before reaching services.

func TestAddWireGuardPeer_MissingPublicKey(t *testing.T) {
	r := gin.New()
	r.POST("/wg/peers", AddWireGuardPeer)

	body := `{"allowed_ips": "10.0.0.2/32"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/wg/peers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing public_key, got %d", w.Code)
	}
}

func TestAddWireGuardPeer_MissingAllowedIPs(t *testing.T) {
	r := gin.New()
	r.POST("/wg/peers", AddWireGuardPeer)

	body := `{"public_key": "abc123"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/wg/peers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing allowed_ips, got %d", w.Code)
	}
}

func TestAddWireGuardPeer_InvalidJSON(t *testing.T) {
	r := gin.New()
	r.POST("/wg/peers", AddWireGuardPeer)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/wg/peers", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestRemoveWireGuardPeer_MissingKey(t *testing.T) {
	r := gin.New()
	r.DELETE("/wg/peers/:key", RemoveWireGuardPeer)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/wg/peers/", nil)
	r.ServeHTTP(w, req)

	// Route won't match with empty key — Gin returns 404 for missing path param
	if w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest {
		t.Errorf("Expected 404 or 400 for empty key, got %d", w.Code)
	}
}

func TestAdvertiseTailscaleRoutes_MissingRoutes(t *testing.T) {
	r := gin.New()
	r.POST("/ts/routes", AdvertiseTailscaleRoutes)

	body := `{}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/ts/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing routes, got %d", w.Code)
	}
}

func TestAdvertiseTailscaleRoutes_EmptyArray(t *testing.T) {
	r := gin.New()
	r.POST("/ts/routes", AdvertiseTailscaleRoutes)

	body := `{"routes": []}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/ts/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	// Gin's binding:"required" accepts empty arrays — they pass validation
	// but the service call may fail (500) on systems without Tailscale.
	// The key contract: it should NOT return 200/201 success.
	if w.Code == http.StatusOK || w.Code == http.StatusCreated {
		t.Errorf("Empty routes should not succeed, got %d", w.Code)
	}
}

func TestAdvertiseTailscaleRoutes_InvalidJSON(t *testing.T) {
	r := gin.New()
	r.POST("/ts/routes", AdvertiseTailscaleRoutes)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/ts/routes", strings.NewReader("garbage"))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid JSON, got %d", w.Code)
	}
}

// --- Security Headers Tests ---

func TestSecurityHeaders_Applied(t *testing.T) {
	r := gin.New()
	r.Use(SecurityHeadersMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
		"X-XSS-Protection":      "1; mode=block",
		"Referrer-Policy":       "strict-origin-when-cross-origin",
	}

	for name, expected := range headers {
		got := w.Header().Get(name)
		if got != expected {
			t.Errorf("Header %s: expected %q, got %q", name, expected, got)
		}
	}
}

func TestSecurityHeaders_HSTS(t *testing.T) {
	r := gin.New()
	r.Use(SecurityHeadersMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	hsts := w.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("Expected Strict-Transport-Security header to be set")
	}
}

// --- Rate Limiter Tests (via existing middleware) ---

func TestRateLimiter_CreateAndCheck(t *testing.T) {
	rl := newRateLimiter(3, time.Second) // 3 requests per second

	// First 3 should pass
	for i := 0; i < 3; i++ {
		if !rl.allow("test-ip") {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 4th should be rate limited
	if rl.allow("test-ip") {
		t.Error("4th request should be rate limited")
	}
}

func TestRateLimiter_IndependentIPs(t *testing.T) {
	rl := newRateLimiter(1, time.Second)
	rl.allow("ip-1") // consume ip-1's budget

	// ip-2 should still be allowed
	if !rl.allow("ip-2") {
		t.Error("Different IP should have independent rate limit")
	}
}

// --- API Version via Header ---

func TestAPIVersionHeader_Accepted(t *testing.T) {
	r := gin.New()
	r.Use(APIVersionMiddleware("v1"))
	r.GET("/test", func(c *gin.Context) {
		version := c.GetString("api_version")
		c.JSON(200, gin.H{"version": version})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Version", "v1")
	r.ServeHTTP(w, req)

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["version"] != "v1" {
		t.Errorf("Expected version=v1, got %q", body["version"])
	}
}

func TestAPIVersionHeader_NormalizedFromNumber(t *testing.T) {
	r := gin.New()
	r.Use(APIVersionMiddleware("v1"))
	r.GET("/test", func(c *gin.Context) {
		version := c.GetString("api_version")
		c.JSON(200, gin.H{"version": version})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Version", "1")
	r.ServeHTTP(w, req)

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["version"] != "v1" {
		t.Errorf("Expected version=v1 from '1', got %q", body["version"])
	}
}
