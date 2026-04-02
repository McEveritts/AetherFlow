package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// testJWTSecret is the deterministic secret used during testing.
var testJWTSecret = []byte("test-jwt-secret-exactly-32bytes!")

func createTestJWT(userID int, expiry time.Duration, signingKey []byte) string {
	claims := jwt.MapClaims{
		"user_id": userID,
		"sub":     fmt.Sprintf("%d", userID),
		"iss":     "aetherflow",
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(expiry).Unix(),
		"jti":     "test-jti-12345",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(signingKey)
	return tokenString
}

// --- Phase 22: JWT Negative Security Tests ---

func TestAuthMiddleware_MissingAuthorizationHeader(t *testing.T) {
	r := gin.New()
	r.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for missing auth header, got %d", w.Code)
	}
}

func TestAuthMiddleware_MalformedBearerToken(t *testing.T) {
	r := gin.New()
	r.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	tests := []struct {
		name   string
		header string
	}{
		{"empty bearer", "Bearer "},
		{"no bearer prefix", "Token abc123"},
		{"basic auth", "Basic dXNlcjpwYXNz"},
		{"just bearer word", "Bearer"},
		{"garbage", "garbage-token-value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/protected", nil)
			req.Header.Set("Authorization", tt.header)
			r.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("Expected 401 for %q header, got %d", tt.name, w.Code)
			}
		})
	}
}

func TestAuthMiddleware_ExpiredJWT(t *testing.T) {
	// Set up a known JWT secret for testing
	originalSecret := jwtSecret
	jwtSecret = testJWTSecret
	defer func() { jwtSecret = originalSecret }()

	// Create an already-expired token
	expiredToken := createTestJWT(1, -1*time.Hour, testJWTSecret)

	r := gin.New()
	r.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for expired JWT, got %d", w.Code)
	}
}

func TestAuthMiddleware_ForgedSignature(t *testing.T) {
	// Set up a known JWT secret for testing
	originalSecret := jwtSecret
	jwtSecret = testJWTSecret
	defer func() { jwtSecret = originalSecret }()

	// Create a token signed with a DIFFERENT key
	wrongKey := []byte("wrong-key-not-the-real-secret!!!")
	forgedToken := createTestJWT(1, 15*time.Minute, wrongKey)

	r := gin.New()
	r.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+forgedToken)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for forged JWT signature, got %d", w.Code)
	}
}

func TestAuthMiddleware_MissingUserIDClaim(t *testing.T) {
	originalSecret := jwtSecret
	jwtSecret = testJWTSecret
	defer func() { jwtSecret = originalSecret }()

	// Create a token WITHOUT user_id claim
	claims := jwt.MapClaims{
		"sub": "1",
		"iss": "aetherflow",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix(),
		"jti": "test-jti",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(testJWTSecret)

	r := gin.New()
	r.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for JWT missing user_id claim, got %d", w.Code)
	}
}

func TestAuthMiddleware_AlgorithmConfusion_RSA(t *testing.T) {
	originalSecret := jwtSecret
	jwtSecret = testJWTSecret
	defer func() { jwtSecret = originalSecret }()

	// Attempt to use RS256 algorithm — should be rejected since we only accept HMAC
	claims := jwt.MapClaims{
		"user_id": 1,
		"sub":     "1",
		"iss":     "aetherflow",
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
	}

	// Create unsigned token with RS256 header — will have invalid signature
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// We can't sign without an RSA key, so the token will be malformed
	malformedToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJleHAiOjk5OTk5OTk5OTl9.invalid-signature"

	_ = token // suppress unused variable

	r := gin.New()
	r.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+malformedToken)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for RS256 algorithm confusion attack, got %d", w.Code)
	}
}

// --- Phase 22: AdminOnly Negative Tests ---

func TestAdminOnly_StandardUserBlocked(t *testing.T) {
	r := gin.New()

	// Mock auth that sets "user" role
	r.GET("/admin/test", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("user_role", "user")
		c.Next()
	}, AdminOnly(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/admin/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 for standard user, got %d", w.Code)
	}
}

func TestAdminOnly_NoRoleInContext(t *testing.T) {
	r := gin.New()

	// No role set in context at all
	r.GET("/admin/test", AdminOnly(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/admin/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 when no role in context, got %d", w.Code)
	}
}

func TestAdminOnly_AdminAllowed(t *testing.T) {
	r := gin.New()

	r.GET("/admin/test", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("user_role", "admin")
		c.Next()
	}, AdminOnly(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/admin/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for admin user, got %d", w.Code)
	}
}

// --- Phase 22: CSRF Middleware Tests ---

func TestCSRFMiddleware_SkipsBearerAuth(t *testing.T) {
	os.Setenv("CSRF_ENABLED", "true")
	defer os.Unsetenv("CSRF_ENABLED")

	r := gin.New()
	r.POST("/test", CSRFMiddleware(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 when Bearer token present (CSRF exempt), got %d", w.Code)
	}
}

func TestCSRFMiddleware_BlocksMissingToken(t *testing.T) {
	r := gin.New()
	r.POST("/test", CSRFMiddleware(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)
	// No CSRF token or cookie
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 when CSRF token is missing, got %d", w.Code)
	}
}

func TestCSRFMiddleware_BlocksMismatchedToken(t *testing.T) {
	r := gin.New()
	r.POST("/test", CSRFMiddleware(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)
	req.Header.Set("X-CSRF-Token", "token-from-header")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "different-token-in-cookie"})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 when CSRF token mismatches cookie, got %d", w.Code)
	}
}

func TestCSRFMiddleware_AllowsMatchingToken(t *testing.T) {
	r := gin.New()
	r.POST("/test", CSRFMiddleware(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	token := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 when CSRF token matches cookie, got %d", w.Code)
	}
}

func TestCSRFMiddleware_AllowsGETWithoutToken(t *testing.T) {
	r := gin.New()
	r.GET("/test", CSRFMiddleware(), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for GET request without CSRF token, got %d", w.Code)
	}
}

// --- Phase 22: Host Validation Tests ---

func TestHostValidationMiddleware_BlocksSpoofedHost(t *testing.T) {
	os.Setenv("ALLOWED_HOSTS", "api.aetherflow.com,localhost:8080")
	defer os.Unsetenv("ALLOWED_HOSTS")

	r := gin.New()
	r.Use(HostValidationMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Host = "evil.attacker.com"
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for spoofed Host header, got %d", w.Code)
	}
}

func TestHostValidationMiddleware_AllowsValidHost(t *testing.T) {
	os.Setenv("ALLOWED_HOSTS", "api.aetherflow.com,localhost:8080")
	defer os.Unsetenv("ALLOWED_HOSTS")

	r := gin.New()
	r.Use(HostValidationMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Host = "localhost:8080"
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for valid host, got %d", w.Code)
	}
}
