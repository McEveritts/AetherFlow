package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// --- Phase 23: Route-Level Security Integration Tests ---

func TestAuthRoutes_RejectUnauthenticated(t *testing.T) {
	r := gin.New()

	// Set up auth-gated group with mock handler
	authGroup := r.Group("/auth")
	authGroup.Use(AuthMiddleware())
	{
		authGroup.GET("/settings", func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		authGroup.POST("/ai/chat", func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		authGroup.GET("/notifications", func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
	}

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/auth/settings"},
		{"POST", "/auth/ai/chat"},
		{"GET", "/auth/notifications"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(ep.method, ep.path, nil)
			// Deliberately no Authorization header
			r.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("Expected 401 for unauthenticated %s %s, got %d", ep.method, ep.path, w.Code)
			}
		})
	}
}

func TestAdminRoutes_RejectStandardUser(t *testing.T) {
	r := gin.New()

	// Mock AuthMiddleware that sets standard user
	mockAuth := func(c *gin.Context) {
		c.Set("user_id", 42)
		c.Set("user_role", "user")
		c.Next()
	}

	adminGroup := r.Group("/admin")
	adminGroup.Use(mockAuth, AdminOnly())
	{
		adminGroup.POST("/backup/run", func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		adminGroup.PUT("/settings", func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		adminGroup.GET("/users", func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		adminGroup.DELETE("/users/1", func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
		adminGroup.GET("/logs", func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
	}

	endpoints := []struct {
		method string
		path   string
	}{
		{"POST", "/admin/backup/run"},
		{"PUT", "/admin/settings"},
		{"GET", "/admin/users"},
		{"DELETE", "/admin/users/1"},
		{"GET", "/admin/logs"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			var body *strings.Reader
			if ep.method == "POST" || ep.method == "PUT" {
				body = strings.NewReader(`{}`)
			}
			var req *http.Request
			if body != nil {
				req, _ = http.NewRequest(ep.method, ep.path, body)
				req.Header.Set("Content-Type", "application/json")
			} else {
				req, _ = http.NewRequest(ep.method, ep.path, nil)
			}
			r.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("Expected 403 for standard user %s %s, got %d", ep.method, ep.path, w.Code)
			}
		})
	}
}

func TestAdminRoutes_AllowAdmin(t *testing.T) {
	r := gin.New()

	// Mock AuthMiddleware that sets admin user
	mockAuth := func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("user_role", "admin")
		c.Next()
	}

	adminGroup := r.Group("/admin")
	adminGroup.Use(mockAuth, AdminOnly())
	{
		adminGroup.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		})
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/admin/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for admin user, got %d", w.Code)
	}
}

// --- Phase 23: HTTP Method Tampering ---

func TestHttpMethodTampering(t *testing.T) {
	r := gin.New()

	// Only POST is registered — GET/PUT/DELETE should fail
	r.POST("/submit", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	methods := []string{"GET", "PUT", "DELETE", "PATCH"}
	for _, method := range methods {
		t.Run(method+" to POST-only endpoint", func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(method, "/submit", nil)
			r.ServeHTTP(w, req)

			// Gin returns 404 for unmatched method/path combos (no HandleMethodNotAllowed by default)
			if w.Code == http.StatusOK {
				t.Errorf("Expected non-200 for %s on POST-only endpoint, got %d", method, w.Code)
			}
		})
	}
}

// --- Phase 23: Route Bleeding ---

func TestRouteBleed_PublicCannotAccessAuth(t *testing.T) {
	r := gin.New()

	// Public group — no auth
	publicGroup := r.Group("/public")
	publicGroup.GET("/openapi.yaml", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	// Auth group — requires auth
	authGroup := r.Group("/auth")
	authGroup.Use(AuthMiddleware())
	authGroup.GET("/settings", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	// Public endpoint should work
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/public/openapi.yaml", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Public endpoint should return 200, got %d", w.Code)
	}

	// Auth endpoint without token should be blocked
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/auth/settings", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Auth endpoint without token should return 401, got %d", w.Code)
	}
}

// --- Phase 23: Path Traversal in Download ---

func TestBackupDownload_RejectsPathTraversal(t *testing.T) {
	r := gin.New()
	r.GET("/backup/download/:filename", DownloadBackup)

	attacks := []string{
		"../../../etc/passwd",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"....//....//etc/passwd",
		"%00malicious.sqlite",
		"backup.sqlite/../../../etc/passwd",
	}

	for _, attack := range attacks {
		t.Run(attack, func(t *testing.T) {
			w := httptest.NewRecorder()
			// URL-encode the attack string for the request
			req, _ := http.NewRequest("GET", "/backup/download/"+attack, nil)
			r.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				t.Errorf("Path traversal attack %q should not return 200", attack)
			}
		})
	}
}
