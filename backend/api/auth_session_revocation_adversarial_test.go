package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
)

// -----------------------------------------------------------------------------
// Adversarial Challenger 2: Session Revocation Stress Tests
// -----------------------------------------------------------------------------

func TestAdversarial_RevokeSession_LifecycleAndEdgeCases(t *testing.T) {
	setupTestDB(t)

	// Seed test users
	_, err := db.DB.Exec("INSERT INTO users (id, username, role, password_hash) VALUES (?, ?, ?, ?)", 201, "challenger_victim", "member", "hash")
	if err != nil {
		t.Fatalf("failed to seed user 201: %v", err)
	}
	_, err = db.DB.Exec("INSERT INTO users (id, username, role, password_hash) VALUES (?, ?, ?, ?)", 202, "challenger_attacker", "member", "hash")
	if err != nil {
		t.Fatalf("failed to seed user 202: %v", err)
	}

	futureExp := time.Now().Add(2 * time.Hour).Format(time.RFC3339)

	// Seed sessions for user 201
	// Session 1: standard 32-char hex JTI
	fullJTI1 := "a1b2c3d4e5f60718293a4b5c6d7e8f90"
	_, err = db.DB.Exec(
		"INSERT INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at, last_active) VALUES (?, ?, ?, ?, ?, ?)",
		fullJTI1, 201, "127.0.0.1", "Mozilla/5.0 Chrome", futureExp, time.Now().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("failed to insert session 1: %v", err)
	}

	// Session 2: belongs to user 202
	fullJTI2 := "f9e8d7c6b5a4031234567890abcdef12"
	_, err = db.DB.Exec(
		"INSERT INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at, last_active) VALUES (?, ?, ?, ?, ?, ?)",
		fullJTI2, 202, "10.0.0.1", "Safari", futureExp, time.Now().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("failed to insert session 2: %v", err)
	}

	r := gin.New()
	r.DELETE("/api/v1/auth/sessions/:jti", func(c *gin.Context) {
		uid := c.GetHeader("X-Test-User-ID")
		if uid == "201" {
			c.Set("user_id", 201)
		} else if uid == "202" {
			c.Set("user_id", 202)
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		RevokeSession(c)
	})

	// Case 1: Standard masked JTI revocation by rightful owner
	{
		maskedJTI := "a1b2c3d4..."
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/"+maskedJTI, nil)
		req.Header.Set("X-Test-User-ID", "201")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for masked JTI revocation, got %d: %s", w.Code, w.Body.String())
		}

		// Verify session was actually deleted from active_sessions
		var count int
		_ = db.DB.QueryRow("SELECT COUNT(*) FROM active_sessions WHERE jti = ?", fullJTI1).Scan(&count)
		if count != 0 {
			t.Fatalf("expected session to be removed from active_sessions, count was %d", count)
		}
	}

	// Case 2: IDOR Attempt — user 201 attempts to revoke user 202's session
	{
		maskedJTI2 := "f9e8d7c6..."
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/"+maskedJTI2, nil)
		req.Header.Set("X-Test-User-ID", "201") // Attacker is user 201
		r.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for IDOR cross-user session revocation attempt, got %d: %s", w.Code, w.Body.String())
		}

		// Verify victim's session is still intact
		var count int
		_ = db.DB.QueryRow("SELECT COUNT(*) FROM active_sessions WHERE jti = ?", fullJTI2).Scan(&count)
		if count != 1 {
			t.Fatalf("victim session was unexpectedly deleted! count was %d", count)
		}
	}

	// Case 3: Short JTI (< 8 characters) must be rejected with 400 Bad Request
	{
		shortJTIs := []string{"abc", "1234567", "short"}
		for _, sj := range shortJTIs {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/"+sj, nil)
			req.Header.Set("X-Test-User-ID", "201")
			r.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for short JTI %q, got %d: %s", sj, w.Code, w.Body.String())
			}
		}
	}

	// Case 4: Non-existent JTI prefix (>= 8 chars) must return 404 Not Found
	{
		fakeJTI := "deadbeef1234..."
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/"+fakeJTI, nil)
		req.Header.Set("X-Test-User-ID", "201")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for non-existent session, got %d: %s", w.Code, w.Body.String())
		}
	}
}

// Case 5: CSRF Middleware enforcement on DELETE /api/v1/auth/sessions/:jti
func TestAdversarial_RevokeSession_CSRFEnforcement(t *testing.T) {
	setupTestDB(t)

	r := gin.New()
	authGroup := r.Group("/api/v1/auth")
	authGroup.Use(CSRFMiddleware())
	authGroup.DELETE("/sessions/:jti", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Session revoked"})
	})

	// Subtest 5.1: Missing X-CSRF-Token and missing cookie -> 403 Forbidden
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/abcdef12...", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for DELETE session without CSRF token, got %d", w.Code)
		}
	}

	// Subtest 5.2: Header present but cookie missing -> 403 Forbidden
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/abcdef12...", nil)
		req.Header.Set("X-CSRF-Token", "valid-looking-token")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for DELETE session with missing cookie, got %d", w.Code)
		}
	}

	// Subtest 5.3: Header and cookie mismatch -> 403 Forbidden
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/abcdef12...", nil)
		req.Header.Set("X-CSRF-Token", "header-token")
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "cookie-token"})
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for mismatched CSRF tokens, got %d", w.Code)
		}
	}

	// Subtest 5.4: Matching header and cookie -> 200 OK
	{
		token := "f7e8d9c0b1a23456789abcdef0123456"
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/abcdef12...", nil)
		req.Header.Set("X-CSRF-Token", token)
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for matching CSRF token, got %d: %s", w.Code, w.Body.String())
		}
	}

	// Subtest 5.5: Bearer token auth bypasses CSRF requirement
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/abcdef12...", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", "fake-jwt-token"))
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for Bearer authenticated request without CSRF, got %d: %s", w.Code, w.Body.String())
		}
	}
}
