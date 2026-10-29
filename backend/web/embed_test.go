package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRegisterSPAHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte("<html>AetherFlow SPA</html>"), 0600); err != nil {
		t.Fatalf("write index.html: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "login.html"), []byte("<html>Login Page</html>"), 0600); err != nil {
		t.Fatalf("write login.html: %v", err)
	}
	nextStaticDir := filepath.Join(tmpDir, "_next", "static", "chunks")
	if err := os.MkdirAll(nextStaticDir, 0750); err != nil {
		t.Fatalf("mkdir _next/static: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nextStaticDir, "app.js"), []byte("console.log('ok')"), 0600); err != nil {
		t.Fatalf("write app.js: %v", err)
	}

	t.Setenv("STATIC_DIR", tmpDir)

	r := gin.New()
	RegisterSPAHandler(r)

	// 1. API route must return 404 JSON, not SPA HTML
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/does-not-exist", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown API route, got %d", w.Code)
	}

	// 2. Next.js static asset should serve with immutable Cache-Control
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/_next/static/chunks/app.js", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for static asset, got %d", w.Code)
	}
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("unexpected Cache-Control header: %q", got)
	}

	// 3. Clean URL (.html resolution)
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/login", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "<html>Login Page</html>" {
		t.Fatalf("expected login.html content, got status=%d body=%q", w.Code, w.Body.String())
	}

	// 4. SPA fallback for dynamic client routes
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/dashboard/immersive", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "<html>AetherFlow SPA</html>" {
		t.Fatalf("expected SPA index.html fallback, got status=%d body=%q", w.Code, w.Body.String())
	}
}
