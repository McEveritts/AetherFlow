package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// ── Phase 29: Identity Domain — Error Contract Tests ────────────────────
//
// These tests verify that all trust-critical error paths emit the
// standardized APIError JSON shape with a machine-readable `code` field.

func init() {
	gin.SetMode(gin.TestMode)
}

// --- RespondError Integration Tests ---

func TestRespondError_JSONShape(t *testing.T) {
	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "Token expired")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401, got %d", w.Code)
	}

	var body APIError
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to unmarshal error response: %v. Body: %s", err, w.Body.String())
	}
	if body.Code != "UNAUTHORIZED" {
		t.Errorf("Expected code=UNAUTHORIZED, got %q", body.Code)
	}
	if body.Message != "Token expired" {
		t.Errorf("Expected message='Token expired', got %q", body.Message)
	}
	if body.Details != nil {
		t.Error("Expected nil details for basic RespondError")
	}
}

func TestRespondErrorWithDetails_JSONShape(t *testing.T) {
	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		RespondErrorWithDetails(c, http.StatusBadRequest, ErrCodeValidation,
			"Invalid input",
			map[string]string{"field": "email", "reason": "required"},
		)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d", w.Code)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	if raw["code"] != "VALIDATION_ERROR" {
		t.Errorf("Expected code=VALIDATION_ERROR, got %v", raw["code"])
	}
	details, ok := raw["details"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected details to be a map, got %T", raw["details"])
	}
	if details["field"] != "email" {
		t.Errorf("Expected details.field=email, got %v", details["field"])
	}
}

// --- Error Code Constants Tests ---

func TestErrorCodeConstants_NonEmpty(t *testing.T) {
	codes := []string{
		ErrCodeInternal,
		ErrCodeBadRequest,
		ErrCodeUnauthorized,
		ErrCodeForbidden,
		ErrCodeNotFound,
		ErrCodeConflict,
		ErrCodeRateLimit,
		ErrCodeValidation,
		ErrCodeQuotaExceeded,
		ErrCodeAIUnavailable,
		ErrCodeSessionExpired,
		ErrCodeSessionHijacked,
	}
	for _, code := range codes {
		if code == "" {
			t.Error("Found empty error code constant")
		}
	}
	if len(codes) < 10 {
		t.Errorf("Expected at least 10 error code constants, got %d", len(codes))
	}
}

// --- RecoveryMiddleware Tests ---

func TestRecoveryMiddleware_CatchesPanic(t *testing.T) {
	r := gin.New()
	r.Use(RecoveryMiddleware())
	r.GET("/panic", func(c *gin.Context) {
		panic("test panic: something went wrong")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/panic", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500 from panic recovery, got %d", w.Code)
	}

	var body APIError
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to unmarshal recovery response: %v", err)
	}
	if body.Code != ErrCodeInternal {
		t.Errorf("Expected code=%s, got %q", ErrCodeInternal, body.Code)
	}
}

func TestRecoveryMiddleware_PassesThrough(t *testing.T) {
	r := gin.New()
	r.Use(RecoveryMiddleware())
	r.GET("/ok", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ok", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for non-panic handler, got %d", w.Code)
	}
}

// --- RequestIDMiddleware Tests ---

func TestRequestIDMiddleware_GeneratesID(t *testing.T) {
	r := gin.New()
	r.Use(RequestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"request_id": c.GetString("request_id")})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	rid := w.Header().Get("X-Request-ID")
	if rid == "" {
		t.Error("Expected X-Request-ID header to be set")
	}
}

func TestRequestIDMiddleware_PreservesExisting(t *testing.T) {
	r := gin.New()
	r.Use(RequestIDMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"request_id": c.GetString("request_id")})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "custom-trace-123")
	r.ServeHTTP(w, req)

	rid := w.Header().Get("X-Request-ID")
	if rid != "custom-trace-123" {
		t.Errorf("Expected request ID to be preserved, got %q", rid)
	}
}

// --- Auth Middleware Error Code Verification ---

func TestAuthMiddleware_EmitsErrorCode(t *testing.T) {
	r := gin.New()
	r.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	r.ServeHTTP(w, req)

	var body APIError
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to unmarshal auth error: %v", err)
	}
	// Must emit a machine-readable code, not just a plain error string
	if body.Code == "" {
		t.Error("Auth middleware must emit a non-empty error code")
	}
	if body.Message == "" {
		t.Error("Auth middleware must emit a non-empty error message")
	}
}

func TestAdminOnly_EmitsErrorCode(t *testing.T) {
	r := gin.New()
	r.GET("/admin", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("user_role", "user") // Not admin
		c.Next()
	}, AdminOnly(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/admin", nil)
	r.ServeHTTP(w, req)

	var body APIError
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to unmarshal admin error: %v", err)
	}
	if body.Code != ErrCodeForbidden {
		t.Errorf("Expected code=%s, got %q", ErrCodeForbidden, body.Code)
	}
}

// --- Content-Type Validation ---

func TestRespondError_ContentType(t *testing.T) {
	r := gin.New()
	r.GET("/error", func(c *gin.Context) {
		RespondError(c, http.StatusNotFound, ErrCodeNotFound, "Resource not found")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/error", nil)
	r.ServeHTTP(w, req)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json; charset=utf-8" {
		t.Errorf("Expected Content-Type application/json, got %q", ct)
	}
}
