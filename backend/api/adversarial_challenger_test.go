package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"aetherflow/db"
	"aetherflow/models"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// -----------------------------------------------------------------------------
// Test 1: Adversarial Directory Traversal against GET /api/v1/auth/fs
// -----------------------------------------------------------------------------

func TestAdversarial_FSDirectoryTraversal(t *testing.T) {
	tempSandbox := t.TempDir()
	allowedSubdir := filepath.Join(tempSandbox, "allowed_media")
	if err := os.Mkdir(allowedSubdir, 0755); err != nil {
		t.Fatalf("failed to create allowed subdir: %v", err)
	}
	testFile := filepath.Join(allowedSubdir, "video.mp4")
	_ = os.WriteFile(testFile, []byte("fake video content"), 0644)

	// Set allowed roots exclusively to tempSandbox
	t.Setenv("AF_ALLOWED_FS_ROOTS", tempSandbox)

	r := gin.New()
	r.GET("/api/v1/auth/fs", BrowseDirectories)

	cases := []struct {
		name         string
		pathParam    string
		expectedCode int
		desc         string
	}{
		{
			name:         "Relative traverse to /etc/shadow",
			pathParam:    "../../../../etc/shadow",
			expectedCode: 403, // Or 404 if file does not exist on test host
			desc:         "Path traversal escaping sandbox must be blocked",
		},
		{
			name:         "Relative traverse to /etc/passwd",
			pathParam:    "../../../../etc/passwd",
			expectedCode: 403,
			desc:         "Path traversal to system files must be blocked",
		},
		{
			name:         "URL encoded traversal (%2e%2e%2f)",
			pathParam:    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			expectedCode: 403,
			desc:         "URL encoded dot-dot-slash must be decoded and blocked",
		},
		{
			name:         "Double URL encoded traversal (%252e%252e)",
			pathParam:    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
			expectedCode: 404, // Evaluated literally as nonexistent dir
			desc:         "Double URL encoding must not escape sandbox",
		},
		{
			name:         "Null byte injection in path (/mnt%00test)",
			pathParam:    allowedSubdir + "%00test",
			expectedCode: 400,
			desc:         "Null byte in path must be rejected",
		},
		{
			name:         "Null byte with traversal (/allowed/..%00/etc/shadow)",
			pathParam:    allowedSubdir + "/..%00/etc/shadow",
			expectedCode: 400,
			desc:         "Null byte combined with traversal must be rejected",
		},
		{
			name:         "Direct root slash access (/)",
			pathParam:    "/",
			expectedCode: 403,
			desc:         "Root filesystem access must be forbidden when not an allowed root",
		},
		{
			name:         "Empty path parameter",
			pathParam:    "",
			expectedCode: 400,
			desc:         "Empty path parameter must return 400 Bad Request",
		},
		{
			name:         "File path instead of directory",
			pathParam:    testFile,
			expectedCode: 400,
			desc:         "Targeting a file must return 400 Not a directory",
		},
		{
			name:         "Valid sandbox directory",
			pathParam:    allowedSubdir,
			expectedCode: 200,
			desc:         "Valid directory inside sandbox must succeed with 200",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			// Construct request URL
			url := "/api/v1/auth/fs?path=" + tc.pathParam
			req, _ := http.NewRequest(http.MethodGet, url, nil)
			r.ServeHTTP(w, req)

			// 403 (Forbidden) or 404 (Not Found if target doesn't exist on host) both safely prevent escape
			if tc.expectedCode == 403 {
				if w.Code != http.StatusForbidden && w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest {
					t.Fatalf("[%s] expected 403/404/400, got HTTP %d: %s", tc.name, w.Code, w.Body.String())
				}
			} else {
				if w.Code != tc.expectedCode {
					t.Fatalf("[%s] expected HTTP %d, got HTTP %d: %s", tc.name, tc.expectedCode, w.Code, w.Body.String())
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Test 2: Symlink Directory Escape Traversal
// -----------------------------------------------------------------------------

func TestAdversarial_FSSymlinkEscape(t *testing.T) {
	tempSandbox := t.TempDir()
	outsideDir := t.TempDir() // Outside allowed sandbox

	// Create a secret file in outside dir
	secretFile := filepath.Join(outsideDir, "secret.key")
	_ = os.WriteFile(secretFile, []byte("super-secret-private-key"), 0600)

	// Create symlink inside sandbox pointing to outside directory
	symlinkPath := filepath.Join(tempSandbox, "symlink_escape")
	err := os.Symlink(outsideDir, symlinkPath)
	if err != nil {
		t.Skipf("Symlinks not supported on this platform/filesystem: %v", err)
	}

	t.Setenv("AF_ALLOWED_FS_ROOTS", tempSandbox)

	r := gin.New()
	r.GET("/api/v1/auth/fs", BrowseDirectories)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/fs?path="+symlinkPath, nil)
	r.ServeHTTP(w, req)

	// Must be blocked because EvalSymlinks resolves to outsideDir which is outside AF_ALLOWED_FS_ROOTS
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for symlink escape, got HTTP %d: %s", w.Code, w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// Test 3: Password Mutation Edge Cases on PUT /api/v1/auth/profile/password
// -----------------------------------------------------------------------------

func TestAdversarial_PasswordMutationEdgeCases(t *testing.T) {
	setupTestDB(t)

	initialPass := "OriginalPassword123!"
	initialHash, _ := bcrypt.GenerateFromPassword([]byte(initialPass), bcrypt.DefaultCost)

	// User 501: Normal local account
	_, err := db.DB.Exec("INSERT INTO users (id, username, role, password_hash) VALUES (?, ?, ?, ?)", 501, "victim_user", "member", string(initialHash))
	if err != nil {
		t.Fatalf("failed to insert user 501: %v", err)
	}

	// User 502: OAuth-only account (empty password hash)
	_, err = db.DB.Exec("INSERT INTO users (id, username, role, password_hash) VALUES (?, ?, ?, ?)", 502, "oauth_only_user", "member", "")
	if err != nil {
		t.Fatalf("failed to insert user 502: %v", err)
	}

	r := gin.New()
	r.PUT("/api/v1/auth/profile/password", func(c *gin.Context) {
		userIDStr := c.GetHeader("X-Test-User-ID")
		if userIDStr == "501" {
			c.Set("user_id", 501)
		} else if userIDStr == "502" {
			c.Set("user_id", 502)
		} else if userIDStr == "999" {
			c.Set("user_id", 999) // Nonexistent user
		}
		// If no header, unauthenticated
		ChangePassword(c)
	})

	// Case 1: Unauthenticated request (no user context)
	{
		payload := `{"current_password":"OriginalPassword123!","new_password":"NewValidPass123!"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPut, "/api/v1/auth/profile/password", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unauthenticated password mutation, got %d", w.Code)
		}
	}

	// Case 2: Incorrect current password
	{
		payload := `{"current_password":"WrongCurrentPassword!","new_password":"NewValidPass123!"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPut, "/api/v1/auth/profile/password", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-User-ID", "501")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for incorrect current password, got %d", w.Code)
		}
	}

	// Case 3: Short password (< 8 chars)
	{
		shortPasswords := []string{"1234567", "short", "a", ""}
		for _, sp := range shortPasswords {
			payload, _ := json.Marshal(map[string]string{
				"current_password": initialPass,
				"new_password":     sp,
			})
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodPut, "/api/v1/auth/profile/password", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Test-User-ID", "501")
			r.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for short password %q, got %d", sp, w.Code)
			}
		}
	}

	// Case 4: OAuth-only account (empty password_hash)
	{
		payload := `{"current_password":"AnyPassword123","new_password":"NewValidPass123!"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPut, "/api/v1/auth/profile/password", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-User-ID", "502")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for OAuth-only user, got %d", w.Code)
		}
	}

	// Case 5: Non-existent user ID in context
	{
		payload := `{"current_password":"OriginalPassword123!","new_password":"NewValidPass123!"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPut, "/api/v1/auth/profile/password", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-User-ID", "999")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for non-existent user, got %d", w.Code)
		}
	}

	// Case 6: Unicode new password with multibyte Japanese and Emojis
	{
		unicodePasswords := []string{
			"パスワード安全です123!",
			"🔑SecretP@ssword123!🚀",
			"Ñoñó-Çédillë-ü-ß-12345",
		}

		currentPass := initialPass
		for _, up := range unicodePasswords {
			payload, _ := json.Marshal(map[string]string{
				"current_password": currentPass,
				"new_password":     up,
			})
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodPut, "/api/v1/auth/profile/password", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Test-User-ID", "501")
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200 for valid unicode password %q, got %d: %s", up, w.Code, w.Body.String())
			}

			// Verify bcrypt hash matches in database
			var storedHash string
			_ = db.DB.QueryRow("SELECT password_hash FROM users WHERE id = 501").Scan(&storedHash)
			if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(up)); err != nil {
				t.Fatalf("stored hash does not match unicode password %q: %v", up, err)
			}

			// Advance currentPass for next iteration
			currentPass = up
		}
	}
}

// -----------------------------------------------------------------------------
// Test 4: Ingress Config Validation on PUT /api/v1/admin/ingress/apps/:appName
// -----------------------------------------------------------------------------

func TestAdversarial_IngressConfigValidation(t *testing.T) {
	setupTestDB(t)

	r := gin.New()
	r.PUT("/api/v1/admin/ingress/apps/:appName", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "admin")
		UpdateAppIngressConfig(c)
	})

	// 1. Port out of range (> 65535)
	{
		payload := `{"publicDomain":"test.example.com","listenPort":70000,"externalAccessEnabled":true}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPut, "/api/v1/admin/ingress/apps/new_unknown_app", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for port > 65535, got %d: %s", w.Code, w.Body.String())
		}
	}

	// 2. Negative port on unknown app
	{
		payload := `{"publicDomain":"test.example.com","listenPort":-10,"externalAccessEnabled":true}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPut, "/api/v1/admin/ingress/apps/new_unknown_app", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for negative port on unknown app, got %d: %s", w.Code, w.Body.String())
		}
	}

	// 3. Negative port on EXISTING app: does it reject, or silently overwrite with existing port?
	{
		// Seed an existing config
		_ = db.SetAppIngressConfig(models.AppIngressConfig{
			AppName:      "radarr",
			PublicDomain: "radarr.example.com",
			ListenPort:   7878,
		})

		payload := `{"publicDomain":"radarr.example.com","listenPort":-1,"externalAccessEnabled":true}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPut, "/api/v1/admin/ingress/apps/radarr", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		// Must reject negative port with HTTP 400 Bad Request
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for negative port on existing app, got %d: %s", w.Code, w.Body.String())
		}
	}

	// 4. Ingress publicDomain with spaces or command injection
	{
		maliciousDomains := []string{
			"malicious.example.com; rm -rf /",
			"example .com",
			"bad\ndomain.com",
			"http://example.com/path",
		}
		for _, md := range maliciousDomains {
			payload, _ := json.Marshal(map[string]interface{}{
				"publicDomain":          md,
				"listenPort":            8080,
				"externalAccessEnabled": true,
			})
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodPut, "/api/v1/admin/ingress/apps/test_app", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for malicious domain %q, got %d: %s", md, w.Code, w.Body.String())
			}
		}
	}

	// 5. Empty domain when externalAccessEnabled is true must return HTTP 400
	{
		payload := `{"publicDomain":"","listenPort":8080,"externalAccessEnabled":true}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPut, "/api/v1/admin/ingress/apps/test_app", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for empty domain when external access enabled, got %d: %s", w.Code, w.Body.String())
		}
	}
}
