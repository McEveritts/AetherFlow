package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aetherflow/db"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func TestSecurity_PruneExpiredDataPreservesUsedOIDCAuthCodeTombstone(t *testing.T) {
	setupTestDB(t)

	futureExp := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
	pastExp := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)

	if _, err := db.DB.Exec(
		`INSERT INTO oidc_auth_codes (code, client_id, user_id, redirect_uri, scope, expires_at, used)
		 VALUES (?, 'cid', 1, 'https://app.example/cb', 'openid', ?, 1),
		        (?, 'cid', 1, 'https://app.example/cb', 'openid', ?, 1)`,
		"live-used-tombstone", futureExp,
		"expired-used-code", pastExp,
	); err != nil {
		t.Fatalf("failed to seed oidc_auth_codes: %v", err)
	}

	db.PruneExpiredData()

	var liveCount, expiredCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM oidc_auth_codes WHERE code = 'live-used-tombstone'").Scan(&liveCount); err != nil {
		t.Fatalf("query live tombstone failed: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM oidc_auth_codes WHERE code = 'expired-used-code'").Scan(&expiredCount); err != nil {
		t.Fatalf("query expired code failed: %v", err)
	}
	if liveCount != 1 {
		t.Fatalf("expected unexpired used=1 OIDC auth code tombstone to survive prune, got count=%d", liveCount)
	}
	if expiredCount != 0 {
		t.Fatalf("expected expired OIDC auth code to be pruned, got count=%d", expiredCount)
	}
}

func TestSecurity_SanitizeServicesForViewerRedactsMapStringInterface(t *testing.T) {
	raw := map[string]interface{}{
		"radarr": map[string]interface{}{
			"status":  "online",
			"api_key": "sensitive-service-token",
			"port":    7878,
		},
	}

	viewerView, ok := SanitizeServicesForViewer(raw, false).(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{} from SanitizeServicesForViewer")
	}
	radarrViewer, ok := viewerView["radarr"].(gin.H)
	if !ok {
		t.Fatalf("expected sanitized radarr gin.H entry, got %T", viewerView["radarr"])
	}
	if _, leaked := radarrViewer["api_key"]; leaked {
		t.Fatalf("expected api_key to be stripped for non-admin viewer, got %+v", radarrViewer)
	}
	if radarrViewer["status"] != "online" {
		t.Fatalf("expected status=online preserved, got %+v", radarrViewer["status"])
	}

	adminView, ok := SanitizeServicesForViewer(raw, true).(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{} for admin view")
	}
	radarrAdmin, ok := adminView["radarr"].(map[string]interface{})
	if !ok || radarrAdmin["api_key"] != "sensitive-service-token" {
		t.Fatalf("expected admin view to retain api_key, got %+v", adminView)
	}
}

func TestSecurity_LogoutRevokesExpiredWithinGraceCookieAndBlocksRefresh(t *testing.T) {
	setupTestDB(t)
	gin.SetMode(gin.TestMode)

	res, err := db.DB.Exec(
		"INSERT INTO users (username, password_hash, role, sessions_revoked_after) VALUES ('graceadmin', 'hash', 'admin', 0)",
	)
	if err != nil {
		t.Fatalf("insert user failed: %v", err)
	}
	uid64, _ := res.LastInsertId()
	userID := int(uid64)

	now := time.Now().Unix()
	expJTI := "expired-grace-jti"
	if _, err := db.DB.Exec(
		`INSERT INTO active_sessions (jti, family_id, user_id, ip_address, user_agent, expires_at, last_active)
		 VALUES (?, ?, ?, '127.0.0.1', 'grace-agent', ?, ?)`,
		expJTI, expJTI, userID,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		t.Fatalf("insert active_session failed: %v", err)
	}

	r := gin.New()
	authGroup := r.Group("/api/v1/auth")
	authGroup.Use(AuthMiddleware(), CSRFMiddleware())
	authGroup.POST("/logout", Logout)
	authGroup.POST("/refresh", RefreshSession)
	authGroup.PUT("/profile", UpdateProfile)

	// Mint an access token expired 10 minutes ago (within the 2-hour refresh grace window).
	probeReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	probeReq.RemoteAddr = "127.0.0.1:43210"
	probeReq.Header.Set("User-Agent", "grace-agent")
	probeW := httptest.NewRecorder()
	probeCtx, _ := gin.CreateTestContext(probeW)
	probeCtx.Request = probeReq
	cfp := clientFingerprint(probeCtx)

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   userID,
		"username":  "graceadmin",
		"role":      "admin",
		"jti":       expJTI,
		"cfp":       cfp,
		"iss":       "aetherflow",
		"iat":       now - 2400,
		"auth_time": now - 2400,
		"exp":       now - 600,
		"ver":       0,
	})
	expiredJWT, err := tok.SignedString(getJWTSecret())
	if err != nil {
		t.Fatalf("sign jwt failed: %v", err)
	}

	// 1. Empty/invalid Authorization: Bearer header must NOT bypass CSRF or fall back to valid session cookie.
	validTok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   userID,
		"username":  "graceadmin",
		"role":      "admin",
		"jti":       "live-session-jti",
		"cfp":       cfp,
		"iss":       "aetherflow",
		"iat":       now,
		"auth_time": now,
		"exp":       now + 1800,
		"ver":       0,
	})
	liveJWT, _ := validTok.SignedString(getJWTSecret())
	csrfBypassReq := httptest.NewRequest(http.MethodPut, "/api/v1/auth/profile", nil)
	csrfBypassReq.RemoteAddr = "127.0.0.1:43210"
	csrfBypassReq.Header.Set("User-Agent", "grace-agent")
	csrfBypassReq.Header.Set("Authorization", "Bearer   ")
	csrfBypassReq.AddCookie(&http.Cookie{Name: "aetherflow_session", Value: liveJWT})
	csrfBypassW := httptest.NewRecorder()
	r.ServeHTTP(csrfBypassW, csrfBypassReq)
	if csrfBypassW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when empty Bearer header is supplied alongside cookie, got %d", csrfBypassW.Code)
	}

	// 2. Logout with expired-within-grace cookie + valid CSRF token must succeed (200) and revoke family.
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutReq.RemoteAddr = "127.0.0.1:43210"
	logoutReq.Header.Set("User-Agent", "grace-agent")
	logoutReq.Header.Set("X-CSRF-Token", "csrf-grace")
	logoutReq.AddCookie(&http.Cookie{Name: "aetherflow_session", Value: expiredJWT})
	logoutReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-grace"})
	logoutW := httptest.NewRecorder()
	r.ServeHTTP(logoutW, logoutReq)
	if logoutW.Code != http.StatusOK {
		t.Fatalf("expected 200 on logout within 2h grace window, got %d body=%s", logoutW.Code, logoutW.Body.String())
	}
	if !db.IsTokenRevoked(expJTI) {
		t.Fatalf("expected expired-within-grace JTI %q to be revoked on logout", expJTI)
	}

	// 3. Replaying that expired cookie at /api/v1/auth/refresh must now fail with 401.
	refreshReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	refreshReq.RemoteAddr = "127.0.0.1:43210"
	refreshReq.Header.Set("User-Agent", "grace-agent")
	refreshReq.AddCookie(&http.Cookie{Name: "aetherflow_session", Value: expiredJWT})
	refreshW := httptest.NewRecorder()
	r.ServeHTTP(refreshW, refreshReq)
	if refreshW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when refreshing logged-out session cookie, got %d body=%s", refreshW.Code, refreshW.Body.String())
	}
}

func TestSecurity_PerformSystemBackupWritesManifestAndNAT64SSRFBlocked(t *testing.T) {
	setupTestDB(t)

	bf, err := PerformSystemBackup()
	if err != nil {
		t.Fatalf("PerformSystemBackup failed: %v", err)
	}
	backupDir := getBackupDir()
	manifestPath := filepath.Join(backupDir, bf.Filename+".manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("expected .manifest.json sidecar at %s: %v", manifestPath, err)
	}
	var parsed afHostBackupManifest
	if err := json.Unmarshal(manifestBytes, &parsed); err != nil {
		t.Fatalf("invalid manifest json: %v", err)
	}
	if parsed.Format != "af-host.backup-manifest.v1" || parsed.PrimaryArtifact != bf.Filename {
		t.Fatalf("unexpected manifest metadata: %+v", parsed)
	}
	if _, err := os.Stat(manifestPath + ".sha256"); err != nil {
		t.Fatalf("expected .manifest.json.sha256 sidecar: %v", err)
	}

	for _, unsafeURL := range []string{
		"https://[64:ff9b::a9fe:a9fe]/hook",
		"https://[64:ff9b:1::a9fe:a9fe]/hook",
		"https://[2002:a9fe:a9fe::1]/hook",
		"https://[100::1]/hook",
	} {
		if _, err := services.ValidatePublicWebhookURL(unsafeURL); err == nil {
			t.Fatalf("expected ValidatePublicWebhookURL to reject %s", unsafeURL)
		}
		if _, err := services.ValidateServerURL(unsafeURL); err == nil {
			t.Fatalf("expected ValidateServerURL to reject %s", unsafeURL)
		}
	}
}
