package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func setupTestDB(t *testing.T) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_parity.sqlite")
	t.Setenv("DB_PATH", dbPath)
	if db.DB != nil {
		_ = db.DB.Close()
	}
	db.InitDB()
}



func TestRefreshSession_Lifecycle(t *testing.T) {
	setupTestDB(t)

	// Create test user in DB
	_, err := db.DB.Exec("INSERT INTO users (id, username, role, password_hash) VALUES (?, ?, ?, ?)", 101, "refresh_tester", "admin", "mock_hash")
	if err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	r := gin.New()
	r.POST("/refresh", RefreshSession)

	// 1. Missing token -> 401
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/refresh", nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for missing token, got %d", w.Code)
		}
	}

	// 2. Invalid signature -> 401
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/refresh", nil)
		req.Header.Set("Authorization", "Bearer invalid.jwt.token")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for invalid token, got %d", w.Code)
		}
	}

	// 3. Expired beyond grace window (> 2 hours) -> 401
	{
		expiredClaims := jwt.MapClaims{
			"user_id":  float64(101),
			"username": "refresh_tester",
			"role":     "admin",
			"jti":      "expired-jti-1",
			"exp":      time.Now().Add(-3 * time.Hour).Unix(),
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
		signed, _ := tok.SignedString(getJWTSecret())

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/refresh", nil)
		req.Header.Set("Authorization", "Bearer "+signed)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for expired token past grace period, got %d", w.Code)
		}
	}

	// 4. Valid active token -> 200 with rotation
	{
		validClaims := jwt.MapClaims{
			"user_id":  float64(101),
			"username": "refresh_tester",
			"role":     "admin",
			"jti":      "valid-jti-42",
			"exp":      time.Now().Add(5 * time.Minute).Unix(),
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims)
		signed, _ := tok.SignedString(getJWTSecret())

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/refresh", nil)
		req.Header.Set("Authorization", "Bearer "+signed)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for valid token refresh, got %d: %s", w.Code, w.Body.String())
		}

		var res struct {
			Status string `json:"status"`
			Token  string `json:"token"`
			User   struct {
				ID       int    `json:"id"`
				Username string `json:"username"`
				Role     string `json:"role"`
			} `json:"user"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("failed to decode refresh response: %v", err)
		}
		if res.User.ID != 101 || res.User.Username != "refresh_tester" {
			t.Fatalf("unexpected user in response: %+v", res.User)
		}
		if res.Token == "" || res.Token == signed {
			t.Fatalf("expected new rotated token, got: %s", res.Token)
		}

		// Verify old JTI has been revoked
		if !db.IsTokenRevoked("valid-jti-42") {
			t.Fatalf("expected old jti to be revoked after refresh")
		}
	}
}

func TestUserProfile_PasswordAndAvatar(t *testing.T) {
	setupTestDB(t)

	initialHash, _ := bcrypt.GenerateFromPassword([]byte("initialPass123"), bcrypt.DefaultCost)
	_, err := db.DB.Exec("INSERT INTO users (id, username, role, password_hash, avatar_url) VALUES (?, ?, ?, ?, ?)", 202, "profile_user", "user", string(initialHash), "http://example.com/avatar.png")
	if err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	r := gin.New()
	authGroup := r.Group("/profile")
	authGroup.Use(func(c *gin.Context) {
		c.Set("user_id", 202)
		c.Set("username", "profile_user")
		c.Next()
	})
	authGroup.PUT("/password", UpdatePassword)
	authGroup.PUT("/avatar", UpdateAvatar)
	authGroup.DELETE("/avatar", DeleteAvatar)

	// 1. Password update - too short -> 400
	{
		payload := `{"current_password":"initialPass123","new_password":"short"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/profile/password", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for short password, got %d", w.Code)
		}
	}

	// 2. Password update - incorrect current password -> 400
	{
		payload := `{"current_password":"wrongPassword","new_password":"validNewPassword123"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/profile/password", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for incorrect current password, got %d", w.Code)
		}
	}

	// 3. Password update - success -> 200
	{
		payload := `{"current_password":"initialPass123","new_password":"validNewPassword123"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/profile/password", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for successful password change, got %d", w.Code)
		}

		// Verify DB hash was updated
		var updatedHash string
		_ = db.DB.QueryRow("SELECT password_hash FROM users WHERE id = ?", 202).Scan(&updatedHash)
		if err := bcrypt.CompareHashAndPassword([]byte(updatedHash), []byte("validNewPassword123")); err != nil {
			t.Fatalf("password hash was not properly updated in DB")
		}
	}

	// 4. Avatar update - empty -> 400
	{
		payload := `{"avatar":""}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/profile/avatar", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for empty avatar, got %d", w.Code)
		}
	}

	// 5. Avatar update - valid -> 200
	{
		payload := `{"avatar":"https://aetherflow.io/new-avatar.png"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/profile/avatar", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for valid avatar update, got %d", w.Code)
		}

		var updatedAvatar string
		_ = db.DB.QueryRow("SELECT avatar_url FROM users WHERE id = ?", 202).Scan(&updatedAvatar)
		if updatedAvatar != "https://aetherflow.io/new-avatar.png" {
			t.Fatalf("avatar_url not updated in DB: %s", updatedAvatar)
		}
	}

	// 6. Delete avatar -> 200
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/profile/avatar", nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for avatar delete, got %d", w.Code)
		}

		var clearedAvatar string
		_ = db.DB.QueryRow("SELECT avatar_url FROM users WHERE id = ?", 202).Scan(&clearedAvatar)
		if clearedAvatar != "" {
			t.Fatalf("avatar_url was not cleared: %s", clearedAvatar)
		}
	}
}

func TestGetSystemTopology_RealNodes(t *testing.T) {
	setupTestDB(t)

	r := gin.New()
	r.GET("/topology", GetSystemTopology)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/topology", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from topology endpoint, got %d", w.Code)
	}

	var topo TopologyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &topo); err != nil {
		t.Fatalf("failed to decode topology response: %v", err)
	}

	if len(topo.Nodes) == 0 {
		t.Fatalf("expected non-empty nodes list in topology")
	}

	nodeIDs := make(map[string]bool)
	for _, n := range topo.Nodes {
		nodeIDs[n.ID] = true
	}

	if !nodeIDs["AetherFlow API"] {
		t.Errorf("missing 'AetherFlow API' node in topology")
	}
	if !nodeIDs["Runner Daemon"] {
		t.Errorf("missing 'Runner Daemon' node in topology")
	}
	if !nodeIDs["SQLite WAL"] {
		t.Errorf("missing 'SQLite WAL' node in topology")
	}
}


