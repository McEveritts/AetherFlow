package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNormalizeAPIVersion(t *testing.T) {
	cases := map[string]string{
		"v1":       "v1",
		"1":        "v1",
		" version=1 ": "v1",
		"VERSION=V1": "v1",
		"":         "",
	}

	for input, want := range cases {
		if got := normalizeAPIVersion(input); got != want {
			t.Fatalf("normalizeAPIVersion(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAPIVersionFromAcceptHeader(t *testing.T) {
	header := "application/json, application/vnd.aetherflow.v1+json"
	if got := apiVersionFromAcceptHeader(header); got != "v1" {
		t.Fatalf("apiVersionFromAcceptHeader() = %q, want v1", got)
	}
}

func TestAPIVersionMiddlewareRejectsUnsupportedVersion(t *testing.T) {
	r := gin.New()
	r.Use(APIVersionMiddleware(defaultAPIVersion))
	r.GET("/api/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-API-Version", "v9")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestLegacyVersionHeadersExposeMigrationHints(t *testing.T) {
	r := gin.New()
	r.Use(APIVersionMiddleware(defaultAPIVersion))
	r.GET("/api/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"version": GetAPIVersion(c)})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("X-API-Version"); got != "v1" {
		t.Fatalf("X-API-Version = %q, want v1", got)
	}
	if got := w.Header().Get("Deprecation"); got != "true" {
		t.Fatalf("Deprecation = %q, want true", got)
	}
	if got := w.Header().Get("Link"); got == "" {
		t.Fatal("expected successor Link header to be set")
	}
}
