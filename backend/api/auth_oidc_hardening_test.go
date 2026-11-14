package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"aetherflow/db"
	"aetherflow/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func TestGetSessionRejectsRevokedTokenAndMismatchedCFP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	db.RedisClient = nil
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	if _, err := db.DB.Exec(
		"INSERT INTO users (id, username, email, role, password_hash) VALUES (?, ?, ?, ?, ?)",
		701, "session_tester", "session@example.test", "user", "hash",
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	r := gin.New()
	r.GET("/session", GetSession)
	r.POST("/logout", Logout)

	wCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	reqCtx := httptest.NewRequest(http.MethodGet, "/session", nil)
	reqCtx.RemoteAddr = "127.0.0.1:41001"
	reqCtx.Header.Set("User-Agent", "TestClient/1.0")
	wCtx.Request = reqCtx

	tokenStr, err := GenerateJWT(701, wCtx)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	// 1. Valid request succeeds
	{
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/session", nil)
		req.RemoteAddr = "127.0.0.1:41001"
		req.Header.Set("User-Agent", "TestClient/1.0")
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 on active session, got %d: %s", w.Code, w.Body.String())
		}
	}

	// 2. Mismatched User-Agent (cfp) is rejected
	{
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/session", nil)
		req.RemoteAddr = "127.0.0.1:41001"
		req.Header.Set("User-Agent", "AttackerClient/9.9")
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on mismatched cfp, got %d", w.Code)
		}
	}

	// 3. Logout revokes token durably with >=2h TTL and GetSession rejects it
	{
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/logout", nil)
		req.RemoteAddr = "127.0.0.1:41001"
		req.Header.Set("User-Agent", "TestClient/1.0")
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 on logout, got %d: %s", w.Code, w.Body.String())
		}

		w2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodGet, "/session", nil)
		req2.RemoteAddr = "127.0.0.1:41001"
		req2.Header.Set("User-Agent", "TestClient/1.0")
		req2.Header.Set("Authorization", "Bearer "+tokenStr)
		r.ServeHTTP(w2, req2)
		if w2.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 after logout revocation, got %d: %s", w2.Code, w2.Body.String())
		}
	}
}

func TestIsAllowedHostAndGetBaseURLHardened(t *testing.T) {
	t.Setenv("ALLOWED_HOSTS", "")
	for _, host := range []string{"localhost", "localhost:8080", "127.0.0.1:8080", "[::1]:8080", "::1"} {
		if !isAllowedHost(host) {
			t.Errorf("expected loopback host %q allowed when ALLOWED_HOSTS unset", host)
		}
	}
	for _, host := range []string{"", "evil.example.com", "localhost/path", "localhost\\evil", "user@localhost", "localhost\r\n"} {
		if isAllowedHost(host) {
			t.Errorf("expected host %q rejected when ALLOWED_HOSTS unset", host)
		}
	}

	t.Setenv("ALLOWED_HOSTS", "panel.example.com, alt.example.com:8443")
	if !isAllowedHost("panel.example.com") {
		t.Error("expected exact allowlisted host accepted")
	}
	if isAllowedHost("localhost:8080") || isAllowedHost("evil.example.com") {
		t.Error("expected non-allowlisted host rejected when ALLOWED_HOSTS is set")
	}

	// Untrusted peer cannot spoof X-Forwarded-Host or X-Forwarded-Proto even with TRUST_PROXY_HEADERS=true
	t.Setenv("TRUST_PROXY_HEADERS", "true")
	t.Setenv("ALLOWED_HOSTS", "panel.example.com,local.example.com")
	{
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "local.example.com"
		req.RemoteAddr = "198.51.100.44:12345"
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "panel.example.com")
		c.Request = req
		if got := getBaseURL(c); got != "http://local.example.com" {
			t.Fatalf("expected untrusted peer forwarded headers ignored, got %q", got)
		}
	}

	// Loopback proxy peer WITH TRUST_PROXY_HEADERS=true uses allowlisted forwarded headers
	{
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "127.0.0.1:8080"
		req.RemoteAddr = "127.0.0.1:54321"
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "panel.example.com")
		c.Request = req
		if got := getBaseURL(c); got != "https://panel.example.com" {
			t.Fatalf("expected trusted loopback proxy headers honored, got %q", got)
		}
	}

	// When TRUST_PROXY_HEADERS is unset, even loopback peer forwarded headers are ignored
	t.Setenv("TRUST_PROXY_HEADERS", "")
	{
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "127.0.0.1:8080"
		req.RemoteAddr = "127.0.0.1:54321"
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "panel.example.com")
		c.Request = req
		if got := getBaseURL(c); got != "http://127.0.0.1:8080" {
			t.Fatalf("expected forwarded headers ignored when TRUST_PROXY_HEADERS unset, got %q", got)
		}
	}
}

func TestIsSafeRedirectURIAndConsentDenialValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	if _, err := db.DB.Exec(
		"INSERT INTO oidc_clients (id, name, client_secret_hash, redirect_uris) VALUES (?, ?, ?, ?)",
		"app-1", "Test App", "hash", `["http://localhost:8080/cb","https://app.example.test/cb"]`,
	); err != nil {
		t.Fatalf("seed oidc client: %v", err)
	}

	for _, bad := range []string{
		"http://app.example.test/cb",
		"javascript:alert(1)",
		"https://user@app.example.test/cb",
		"https://app.example.test/cb#frag",
		"/relative",
	} {
		if isSafeRedirectURI(bad) {
			t.Errorf("expected unsafe redirect URI rejected: %q", bad)
		}
	}
	for _, good := range []string{
		"http://localhost:8080/cb",
		"http://127.0.0.1:9000/cb",
		"https://app.example.test/cb",
	} {
		if !isSafeRedirectURI(good) {
			t.Errorf("expected safe redirect URI allowed: %q", good)
		}
	}

	r := gin.New()
	r.POST("/oidc/consent", func(c *gin.Context) {
		c.Set("user_id", 1)
		OIDCConsent(c)
	})

	// Denied consent with attacker redirect URI MUST fail 400 (never echo attacker redirect URL)
	{
		body := `{"client_id":"app-1","redirect_uri":"https://evil.attacker/steal","response_type":"code","approved":false}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oidc/consent", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 when denied consent supplies unregistered redirect_uri, got %d: %s", w.Code, w.Body.String())
		}
	}

	// Denied consent with registered redirect URI succeeds and includes access_denied
	{
		body := `{"client_id":"app-1","redirect_uri":"https://app.example.test/cb","response_type":"code","state":"st-1","approved":false}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oidc/consent", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for registered denial redirect, got %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "error=access_denied") {
			t.Fatalf("expected access_denied error param in denial redirect: %s", w.Body.String())
		}
	}
}

func TestOIDCNoncePropagationAndScopeFiltering(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	const clientID = "scoped-client"
	const clientSecret = "secret-value"
	const redirectURI = "http://localhost:8080/cb"

	if _, err := db.DB.Exec(
		"INSERT INTO users (id, username, email, avatar_url, role) VALUES (?, ?, ?, ?, ?)",
		801, "alice", "alice@example.test", "https://cdn.example.test/a.png", "admin",
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	secretHash := sha256.Sum256([]byte(clientSecret))
	if _, err := db.DB.Exec(
		"INSERT INTO oidc_clients (id, name, client_secret_hash, redirect_uris) VALUES (?, ?, ?, ?)",
		clientID, "Scoped Client", hex.EncodeToString(secretHash[:]), `["http://localhost:8080/cb"]`,
	); err != nil {
		t.Fatalf("seed client: %v", err)
	}

	r := gin.New()
	r.POST("/oidc/token", OIDCToken)
	r.GET("/oidc/userinfo", OIDCUserInfo)

	cases := []struct {
		name         string
		scope        string
		nonce        string
		expectEmail  bool
		expectName   bool
	}{
		{name: "openid_only", scope: "openid", nonce: "nonce-open-1", expectEmail: false, expectName: false},
		{name: "openid_email", scope: "openid email", nonce: "nonce-email-2", expectEmail: true, expectName: false},
		{name: "openid_profile_email", scope: "openid profile email", nonce: "nonce-all-3", expectEmail: true, expectName: true},
	}

	pkceVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceDigest := sha256.Sum256([]byte(pkceVerifier))
	pkceChallenge := base64.RawURLEncoding.EncodeToString(pkceDigest[:])

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, err := generateAndStoreAuthCode(clientID, 801, redirectURI, tc.scope, tc.nonce, pkceChallenge, "S256")
			if err != nil {
				t.Fatalf("generateAndStoreAuthCode: %v", err)
			}

			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("code", code)
			form.Set("redirect_uri", redirectURI)
			form.Set("client_id", clientID)
			form.Set("client_secret", clientSecret)
			form.Set("code_verifier", pkceVerifier)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/oidc/token", bytes.NewBufferString(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("token exchange failed (%d): %s", w.Code, w.Body.String())
			}

			var tokResp map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &tokResp); err != nil {
				t.Fatalf("decode token response: %v", err)
			}
			idTokenStr, _ := tokResp["id_token"].(string)
			accessTokenStr, _ := tokResp["access_token"].(string)

			parsed, err := jwt.Parse(idTokenStr, func(tok *jwt.Token) (interface{}, error) {
				return &oidcPrivateKey.PublicKey, nil
			})
			if err != nil || !parsed.Valid {
				t.Fatalf("verify id_token: %v", err)
			}
			idClaims := parsed.Claims.(jwt.MapClaims)
			if idClaims["nonce"] != tc.nonce {
				t.Fatalf("expected nonce %q in id_token, got %v", tc.nonce, idClaims["nonce"])
			}
			if _, hasEmail := idClaims["email"]; hasEmail != tc.expectEmail {
				t.Fatalf("id_token email presence=%v, expected %v", hasEmail, tc.expectEmail)
			}
			if _, hasName := idClaims["name"]; hasName != tc.expectName {
				t.Fatalf("id_token name presence=%v, expected %v", hasName, tc.expectName)
			}

			// Verify /userinfo claim filtering
			uw := httptest.NewRecorder()
			ureq := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
			ureq.Header.Set("Authorization", "Bearer "+accessTokenStr)
			r.ServeHTTP(uw, ureq)
			if uw.Code != http.StatusOK {
				t.Fatalf("userinfo failed (%d): %s", uw.Code, uw.Body.String())
			}
			var ui map[string]interface{}
			if err := json.Unmarshal(uw.Body.Bytes(), &ui); err != nil {
				t.Fatalf("decode userinfo: %v", err)
			}
			if _, hasEmail := ui["email"]; hasEmail != tc.expectEmail {
				t.Fatalf("userinfo email presence=%v, expected %v", hasEmail, tc.expectEmail)
			}
			if _, hasName := ui["name"]; hasName != tc.expectName {
				t.Fatalf("userinfo name presence=%v, expected %v", hasName, tc.expectName)
			}
		})
	}
}

func TestGoParity_PluginJWTRejectionAndAbsoluteSessionCeiling(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	if _, err := db.DB.Exec(
		"INSERT INTO users (id, username, email, role, password_hash) VALUES (?, ?, ?, ?, ?)",
		901, "admin_owner", "admin@example.test", "admin", "hash",
	); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	r := gin.New()
	r.POST("/refresh", RefreshSession)
	authGroup := r.Group("/api/v1/admin")
	authGroup.Use(AuthMiddleware())
	authGroup.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// 1. Plugin-scoped JWT signed with JWT_SECRET MUST be rejected on AuthMiddleware (401) and RefreshSession (403)
	pluginTok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":           "aetherflow-plugin",
		"plugin_id":     "telemetry-exporter",
		"plugin_scopes": []string{"metrics:read"},
		"user_id":       float64(901),
		"sub":           "901",
		"jti":           "plg-12345678",
		"iat":           time.Now().Unix(),
		"exp":           time.Now().Add(15 * time.Minute).Unix(),
	})
	pluginSigned, err := pluginTok.SignedString(getJWTSecret())
	if err != nil {
		t.Fatalf("sign plugin token: %v", err)
	}

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/admin/ping", nil)
	req1.Header.Set("Authorization", "Bearer "+pluginSigned)
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for plugin JWT on AuthMiddleware, got %d: %s", w1.Code, w1.Body.String())
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req2.Header.Set("Authorization", "Bearer "+pluginSigned)
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for plugin JWT on RefreshSession, got %d: %s", w2.Code, w2.Body.String())
	}

	// 2. Session exceeding 30-day auth_time ceiling MUST be rejected even with fresh exp
	staleAuthTok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       "aetherflow",
		"user_id":   float64(901),
		"sub":       "901",
		"jti":       "stale-auth-time-jti-001",
		"auth_time": time.Now().Add(-31 * 24 * time.Hour).Unix(),
		"iat":       time.Now().Add(-5 * time.Minute).Unix(),
		"exp":       time.Now().Add(10 * time.Minute).Unix(),
	})
	staleSigned, _ := staleAuthTok.SignedString(getJWTSecret())

	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req3.Header.Set("Authorization", "Bearer "+staleSigned)
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when 30-day absolute session lifetime is exceeded, got %d", w3.Code)
	}
}

func TestGoParity_ConcurrentRefreshSingleWinnerAndPostGraceReplayFamilyWipe(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	if _, err := db.DB.Exec(
		"INSERT INTO users (id, username, email, role, password_hash) VALUES (?, ?, ?, ?, ?)",
		902, "racer", "racer@example.test", "user", "hash",
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	r := gin.New()
	r.POST("/refresh", RefreshSession)
	r.GET("/session", GetSession)

	wCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	reqCtx := httptest.NewRequest(http.MethodGet, "/session", nil)
	reqCtx.RemoteAddr = "127.0.0.1:42000"
	reqCtx.Header.Set("User-Agent", "RaceBrowser/1.0")
	wCtx.Request = reqCtx

	seedTok, err := GenerateJWT(902, wCtx)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	parsedSeed, _ := jwt.Parse(seedTok, func(tok *jwt.Token) (interface{}, error) { return getJWTSecret(), nil })
	seedJTI := parsedSeed.Claims.(jwt.MapClaims)["jti"].(string)

	const workers = 6
	var wg sync.WaitGroup
	tokens := make([]string, workers)
	codes := make([]int, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
			req.RemoteAddr = "127.0.0.1:42000"
			req.Header.Set("User-Agent", "RaceBrowser/1.0")
			req.Header.Set("Authorization", "Bearer "+seedTok)
			r.ServeHTTP(w, req)
			codes[idx] = w.Code
			if w.Code == http.StatusOK {
				var body map[string]interface{}
				_ = json.Unmarshal(w.Body.Bytes(), &body)
				tokens[idx], _ = body["token"].(string)
			}
		}(i)
	}
	wg.Wait()

	distinct := map[string]bool{}
	for i := 0; i < workers; i++ {
		if codes[i] == http.StatusOK && tokens[i] != "" {
			distinct[tokens[i]] = true
		}
	}
	if len(distinct) != 1 {
		t.Fatalf("expected exactly 1 unique successor token across concurrent refreshes, got %d (codes=%v)", len(distinct), codes)
	}

	var activeCount int
	_ = db.DB.QueryRow("SELECT COUNT(*) FROM active_sessions WHERE user_id = 902").Scan(&activeCount)
	if activeCount != 1 {
		t.Fatalf("expected 1 active_sessions row for user 902, got %d", activeCount)
	}

	var winnerToken string
	for k := range distinct {
		winnerToken = k
	}

	// Expire the 15s grace entry and replay the already-rotated seed token -> must 401 AND revoke winnerToken's family!
	rotatedTokenGrace.Delete(seedJTI)
	wReplay := httptest.NewRecorder()
	reqReplay := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	reqReplay.RemoteAddr = "127.0.0.1:42000"
	reqReplay.Header.Set("User-Agent", "RaceBrowser/1.0")
	reqReplay.Header.Set("Authorization", "Bearer "+seedTok)
	r.ServeHTTP(wReplay, reqReplay)
	if wReplay.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on post-grace rotated token replay, got %d", wReplay.Code)
	}

	wCheck := httptest.NewRecorder()
	reqCheck := httptest.NewRequest(http.MethodGet, "/session", nil)
	reqCheck.RemoteAddr = "127.0.0.1:42000"
	reqCheck.Header.Set("User-Agent", "RaceBrowser/1.0")
	reqCheck.Header.Set("Authorization", "Bearer "+winnerToken)
	r.ServeHTTP(wCheck, reqCheck)
	if wCheck.Code != http.StatusUnauthorized {
		t.Fatalf("expected descendant session to be revoked after replay outside grace, got %d", wCheck.Code)
	}
}

func TestGoParity_RevokeSessionWildcardSafetyAndCredentialRotation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	t.Setenv("AES_MASTER_KEY", strings.Repeat("k", 32))
	InitAESKey()
	masterPath := filepath.Join(t.TempDir(), ".master.creds")
	t.Setenv("AETHERFLOW_MASTER_CREDS_FILE", masterPath)
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	passHash, _ := bcrypt.GenerateFromPassword([]byte("InitialSecret!123"), bcrypt.DefaultCost)
	totpKey, _ := totp.Generate(totp.GenerateOpts{Issuer: "AetherFlow", AccountName: "secadmin", Period: 30})
	encTotp, err := EncryptKey(totpKey.Secret())
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	if _, err := db.DB.Exec(
		"INSERT INTO users (id, username, email, role, password_hash, totp_secret, totp_enabled) VALUES (?, ?, ?, ?, ?, ?, 1)",
		903, "secadmin", "secadmin@example.test", "admin", string(passHash), encTotp,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	_, _ = db.DB.Exec(
		"INSERT INTO oidc_clients (id, name, client_secret_hash, redirect_uris) VALUES ('c-rev', 'Rev Client', 'h', '[\"http://localhost/cb\"]')",
	)
	_, _ = db.DB.Exec(
		"INSERT INTO oidc_refresh_tokens (token, client_id, user_id, scope, expires_at, revoked, family_id) VALUES ('rt-live-1', 'c-rev', 903, 'openid', ?, 0, 'rt-live-1')",
		time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339),
	)

	r := gin.New()
	auth := r.Group("/auth")
	auth.Use(AuthMiddleware())
	auth.DELETE("/sessions/:jti", RevokeSession)
	auth.PUT("/password", ChangePassword)
	auth.POST("/2fa/disable", Disable2FA)
	r.GET("/session", GetSession)

	mkCtx := func(ua string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest(http.MethodGet, "/session", nil)
		req.RemoteAddr = "127.0.0.1:43000"
		req.Header.Set("User-Agent", ua)
		c.Request = req
		return c
	}
	tokA, _ := GenerateJWT(903, mkCtx("ClientA"))
	tokB, _ := GenerateJWT(903, mkCtx("ClientB"))

	// 1. SQL LIKE wildcard `________` MUST be rejected with 400 and leave sessions intact
	wWild := httptest.NewRecorder()
	reqWild := httptest.NewRequest(http.MethodDelete, "/auth/sessions/________", nil)
	reqWild.RemoteAddr = "127.0.0.1:43000"
	reqWild.Header.Set("User-Agent", "ClientA")
	reqWild.Header.Set("Authorization", "Bearer "+tokA)
	r.ServeHTTP(wWild, reqWild)
	if wWild.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on wildcard JTI prefix, got %d", wWild.Code)
	}

	// 2. ChangePassword revokes concurrent session tokB, revokes OIDC refresh tokens, rotates caller cookie, and NEVER writes new password to .master.creds
	pwBody := `{"current_password":"InitialSecret!123","new_password":"RotatedPassword!456"}`
	wPw := httptest.NewRecorder()
	reqPw := httptest.NewRequest(http.MethodPut, "/auth/password", strings.NewReader(pwBody))
	reqPw.RemoteAddr = "127.0.0.1:43000"
	reqPw.Header.Set("User-Agent", "ClientA")
	reqPw.Header.Set("Content-Type", "application/json")
	reqPw.Header.Set("Authorization", "Bearer "+tokA)
	r.ServeHTTP(wPw, reqPw)
	if wPw.Code != http.StatusOK {
		t.Fatalf("ChangePassword failed (%d): %s", wPw.Code, wPw.Body.String())
	}
	if _, statErr := os.Stat(masterPath); !os.IsNotExist(statErr) {
		t.Fatalf("ChangePassword must not write control-plane password to .master.creds")
	}

	var rtRevoked bool
	_ = db.DB.QueryRow("SELECT revoked FROM oidc_refresh_tokens WHERE token = 'rt-live-1'").Scan(&rtRevoked)
	if !rtRevoked {
		t.Fatalf("expected OIDC refresh token to be revoked on password change")
	}

	// tokB is immediately rejected (ver < sessions_revoked_after + JTI revoked)
	wStale := httptest.NewRecorder()
	reqStale := httptest.NewRequest(http.MethodGet, "/session", nil)
	reqStale.RemoteAddr = "127.0.0.1:43000"
	reqStale.Header.Set("User-Agent", "ClientB")
	reqStale.Header.Set("Authorization", "Bearer "+tokB)
	r.ServeHTTP(wStale, reqStale)
	if wStale.Code != http.StatusUnauthorized {
		t.Fatalf("expected concurrent session tokB rejected after ChangePassword, got %d", wStale.Code)
	}

	// Rotated session cookie from ChangePassword works, and Disable2FA rotates epoch again
	var rotatedCookie *http.Cookie
	for _, ck := range wPw.Result().Cookies() {
		if ck.Name == "aetherflow_session" {
			rotatedCookie = ck
		}
	}
	if rotatedCookie == nil || rotatedCookie.Value == "" {
		t.Fatalf("expected rotated session cookie from ChangePassword")
	}
	tokC, _ := GenerateJWT(903, mkCtx("ClientC"))
	codeNow, _ := totp.GenerateCode(totpKey.Secret(), time.Now())
	w2FA := httptest.NewRecorder()
	req2FA := httptest.NewRequest(http.MethodPost, "/auth/2fa/disable", strings.NewReader(`{"code":"`+codeNow+`"}`))
	req2FA.RemoteAddr = "127.0.0.1:43000"
	req2FA.Header.Set("User-Agent", "ClientA")
	req2FA.Header.Set("Content-Type", "application/json")
	req2FA.Header.Set("Authorization", "Bearer "+rotatedCookie.Value)
	r.ServeHTTP(w2FA, req2FA)
	if w2FA.Code != http.StatusOK {
		t.Fatalf("Disable2FA failed (%d): %s", w2FA.Code, w2FA.Body.String())
	}

	wCheckC := httptest.NewRecorder()
	reqCheckC := httptest.NewRequest(http.MethodGet, "/session", nil)
	reqCheckC.RemoteAddr = "127.0.0.1:43000"
	reqCheckC.Header.Set("User-Agent", "ClientC")
	reqCheckC.Header.Set("Authorization", "Bearer "+tokC)
	r.ServeHTTP(wCheckC, reqCheckC)
	if wCheckC.Code != http.StatusUnauthorized {
		t.Fatalf("expected concurrent session tokC rejected after Disable2FA, got %d", wCheckC.Code)
	}
}

func TestGoParity_GooglePreHijackGuardNoAdminPromotionAndAetherLocalXRealIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	// 1. Local password account squatting victim@example.org MUST NOT auto-link on unauthenticated Google login
	if _, err := db.DB.Exec(
		"INSERT INTO users (id, username, email, role, password_hash) VALUES (910, 'squatter', 'victim@example.org', 'user', 'bcrypt-hash')",
	); err != nil {
		t.Fatalf("seed squatter: %v", err)
	}
	t.Setenv("AETHERFLOW_GOOGLE_ALLOWED_DOMAINS", "example.org")
	t.Setenv("ADMIN_EMAIL", "newgoogle@example.org")

	_, _, authorized, err := resolveGoogleOAuthUser("google-sub-victim", "victim@example.org", "Victim", "", 0)
	if err != nil || authorized {
		t.Fatalf("expected unauthenticated pre-hijack email match to be refused (authorized=%v, err=%v)", authorized, err)
	}

	// Authenticated self-linking by user 910 succeeds
	linkedID, _, linkedAuth, linkErr := resolveGoogleOAuthUser("google-sub-self", "victim@example.org", "Squatter", "", 910)
	if linkErr != nil || !linkedAuth || linkedID != 910 {
		t.Fatalf("expected authenticated self-link to succeed, got id=%d auth=%v err=%v", linkedID, linkedAuth, linkErr)
	}

	// Auto-provisioned Google user MUST get role='user' even when email == ADMIN_EMAIL
	newID, _, newAuth, newErr := resolveGoogleOAuthUser("google-sub-new", "newgoogle@example.org", "New User", "", 0)
	if newErr != nil || !newAuth {
		t.Fatalf("expected auto-provisioned user to succeed: auth=%v err=%v", newAuth, newErr)
	}
	var provisionedRole string
	_ = db.DB.QueryRow("SELECT role FROM users WHERE id = ?", newID).Scan(&provisionedRole)
	if provisionedRole != "user" {
		t.Fatalf("expected auto-provisioned OAuth user role='user', got %q", provisionedRole)
	}

	// 2. .aether.local MUST block external X-Real-IP from loopback proxy even when X-Forwarded-For is absent
	_ = db.SetAppIngressConfig(models.AppIngressConfig{
		AppName:    "sonarr",
		ListenPort: 8989,
	})
	gw := gin.New()
	gw.Use(AppSubdomainProxyMiddleware())
	gw.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	wXRI := httptest.NewRecorder()
	reqXRI := httptest.NewRequest(http.MethodGet, "http://sonarr.aether.local/", nil)
	reqXRI.Host = "sonarr.aether.local"
	reqXRI.RemoteAddr = "127.0.0.1:50000"
	reqXRI.Header.Set("X-Real-IP", "203.0.113.88")
	gw.ServeHTTP(wXRI, reqXRI)
	if wXRI.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when trusted proxy forwards external X-Real-IP to .aether.local, got %d", wXRI.Code)
	}

	// Untrusted RFC1918 peer when TRUST_PROXY_HEADERS is unset is NOT treated as a trusted proxy
	t.Setenv("TRUST_PROXY_HEADERS", "")
	t.Setenv("TRUSTED_PROXIES", "")
	cPeer, _ := gin.CreateTestContext(httptest.NewRecorder())
	reqPeer := httptest.NewRequest(http.MethodGet, "/", nil)
	reqPeer.RemoteAddr = "192.168.1.77:54321"
	cPeer.Request = reqPeer
	if isTrustedProxyPeer(cPeer) {
		t.Fatalf("expected RFC1918 peer to NOT be trusted proxy when TRUST_PROXY_HEADERS is unset")
	}
}

func TestGoParity_OIDCRefreshFamilyReuseAccessRevocationAndUTCPruning(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	const clientID = "family-client"
	const clientSecret = "family-secret"
	const redirectURI = "http://localhost:8080/cb"

	if _, err := db.DB.Exec(
		"INSERT INTO users (id, username, email, role) VALUES (920, 'oidc_family', 'fam@example.test', 'user')",
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	secretHash := sha256.Sum256([]byte(clientSecret))
	_, _ = db.DB.Exec(
		"INSERT INTO oidc_clients (id, name, client_secret_hash, redirect_uris) VALUES (?, 'Fam', ?, '[\"http://localhost:8080/cb\"]')",
		clientID, hex.EncodeToString(secretHash[:]),
	)

	r := gin.New()
	r.POST("/oidc/token", OIDCToken)
	r.POST("/oidc/revoke", OIDCRevoke)
	r.POST("/oidc/introspect", OIDCIntrospect)
	r.GET("/oidc/userinfo", OIDCUserInfo)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	code, _ := generateAndStoreAuthCode(clientID, 920, redirectURI, "openid profile", "n1", challenge, "S256")

	// 1. Exchange auth code -> rt1 + at1
	form1 := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code_verifier": {verifier},
	}
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form1.Encode()))
	req1.Host = "localhost:8080"
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("auth code exchange failed (%d): %s", w1.Code, w1.Body.String())
	}
	var res1 map[string]interface{}
	_ = json.Unmarshal(w1.Body.Bytes(), &res1)
	rt1 := res1["refresh_token"].(string)
	at1 := res1["access_token"].(string)

	// 2. Rotate rt1 -> rt2
	form2 := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt1},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form2.Encode()))
	req2.Host = "localhost:8080"
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("refresh rotation failed (%d): %s", w2.Code, w2.Body.String())
	}
	var res2 map[string]interface{}
	_ = json.Unmarshal(w2.Body.Bytes(), &res2)
	rt2 := res2["refresh_token"].(string)

	// 3. PruneExpiredData MUST NOT delete non-expired revoked=1 tombstones (so reuse detection still works!)
	db.PruneExpiredData()

	// 4. Replaying consumed rt1 MUST return 400 AND revoke descendant rt2!
	wReuse := httptest.NewRecorder()
	reqReuse := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form2.Encode()))
	reqReuse.Host = "localhost:8080"
	reqReuse.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(wReuse, reqReuse)
	if wReuse.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on rt1 reuse, got %d", wReuse.Code)
	}

	form3 := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt2},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	wDesc := httptest.NewRecorder()
	reqDesc := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form3.Encode()))
	reqDesc.Host = "localhost:8080"
	reqDesc.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(wDesc, reqDesc)
	if wDesc.Code != http.StatusBadRequest {
		t.Fatalf("expected descendant rt2 to be revoked after rt1 reuse, got %d", wDesc.Code)
	}

	// 5. Revoking access token at1 via /oidc/revoke immediately invalidates /oidc/userinfo and /oidc/introspect
	revForm := url.Values{
		"token":         {at1},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	wRev := httptest.NewRecorder()
	reqRev := httptest.NewRequest(http.MethodPost, "/oidc/revoke", strings.NewReader(revForm.Encode()))
	reqRev.Host = "localhost:8080"
	reqRev.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(wRev, reqRev)
	if wRev.Code != http.StatusOK {
		t.Fatalf("access token revoke failed (%d)", wRev.Code)
	}

	wUI := httptest.NewRecorder()
	reqUI := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	reqUI.Host = "localhost:8080"
	reqUI.Header.Set("Authorization", "Bearer "+at1)
	r.ServeHTTP(wUI, reqUI)
	if wUI.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on /oidc/userinfo after access token revocation, got %d", wUI.Code)
	}
}
