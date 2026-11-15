package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
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
	"aetherflow/services"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func mintSessionTokenForTest(t *testing.T, userID int, remoteAddr, ua string) string {
	t.Helper()
	wCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	reqCtx := httptest.NewRequest(http.MethodGet, "/", nil)
	reqCtx.RemoteAddr = remoteAddr
	reqCtx.Header.Set("User-Agent", ua)
	wCtx.Request = reqCtx
	tok, err := GenerateJWT(userID, wCtx)
	if err != nil {
		t.Fatalf("GenerateJWT(%d): %v", userID, err)
	}
	return tok
}

func TestRound3_IngressAndAdminRBACAndCSRFAndSchema24(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	db.RedisClient = nil
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	var maxVer int
	if err := db.DB.QueryRow("SELECT MAX(version) FROM schema_versions").Scan(&maxVer); err != nil {
		t.Fatalf("query schema_versions: %v", err)
	}
	if maxVer != 24 {
		t.Fatalf("expected Go fresh MAX(schema_versions.version) == 24 matching Rust v4 schema ceiling, got %d", maxVer)
	}

	_, err := db.DB.Exec(
		`INSERT INTO users (id, username, email, role, password_hash) VALUES
		 (951, 'admin_r3', 'admin_r3@example.test', 'admin', 'h'),
		 (952, 'user_r3', 'user_r3@example.test', 'user', 'h')`,
	)
	if err != nil {
		t.Fatalf("seed users: %v", err)
	}

	r := gin.New()
	RegisterRoutes(r)

	adminTok := mintSessionTokenForTest(t, 951, "127.0.0.1:42001", "R3Client/1.0")
	userTok := mintSessionTokenForTest(t, 952, "127.0.0.1:42002", "R3Client/1.0")

	// 1. Unauthenticated /api/v1/ingress/configs -> 401
	{
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ingress/configs", nil)
		req.Host = "localhost:8080"
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unauthenticated GET /api/v1/ingress/configs, got %d", w.Code)
		}
	}

	// 2. Non-admin /api/v1/ingress/configs and PATCH /api/v1/ingress/apps/sonarr -> 403
	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/v1/ingress/configs", ""},
		{http.MethodPut, "/api/v1/ingress/apps/sonarr", `{"external_access_enabled":true}`},
		{http.MethodGet, "/api/v1/auth/fs", ""},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
		req.Host = "localhost:8080"
		req.RemoteAddr = "127.0.0.1:42002"
		req.Header.Set("User-Agent", "R3Client/1.0")
		req.Header.Set("Authorization", "Bearer "+userTok)
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for standard user %s %s, got %d: %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}

	// 3. Cookie-authenticated admin mutating /api/v1/admin/settings and /api/v1/ingress/apps/sonarr WITHOUT CSRF -> 403
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodPut, "/api/v1/admin/settings"},
		{http.MethodPut, "/api/v1/ingress/apps/sonarr"},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(`{}`))
		req.Host = "localhost:8080"
		req.RemoteAddr = "127.0.0.1:42001"
		req.Header.Set("User-Agent", "R3Client/1.0")
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "aetherflow_session", Value: adminTok})
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 CSRF rejection for cookie-auth %s %s without X-CSRF-Token, got %d: %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}

	// 4. Admin GET /api/v1/ingress/configs succeeds (200)
	{
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ingress/configs", nil)
		req.Host = "localhost:8080"
		req.RemoteAddr = "127.0.0.1:42001"
		req.Header.Set("User-Agent", "R3Client/1.0")
		req.Header.Set("Authorization", "Bearer "+adminTok)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for admin GET /api/v1/ingress/configs, got %d: %s", w.Code, w.Body.String())
		}
	}
}

func TestRound3_HostValidationSettingsBaseDomainAndSettingsRedaction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("ALLOWED_HOSTS", "")
	setupTestDB(t)
	db.RedisClient = nil
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	encGem, err := EncryptKey("AIzaSySuperSecretKey9876")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	if _, err := db.DB.Exec(
		`UPDATE settings SET base_domain = 'panel.example.test', gemini_api_key = ?, ollama_endpoint = 'http://10.0.0.5:11434' WHERE id = 1`,
		encGem,
	); err != nil {
		t.Fatalf("update settings: %v", err)
	}

	r := gin.New()
	r.Use(HostValidationMiddleware())
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/settings-user", func(c *gin.Context) {
		c.Set("user_id", 2)
		c.Set("user_role", "user")
		GetSettings(c)
	})
	r.GET("/settings-admin", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("user_role", "admin")
		GetSettings(c)
	})

	for _, allowedHost := range []string{"panel.example.test", "sonarr.panel.example.test:443"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		req.Host = allowedHost
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for settings base_domain host %q, got %d", allowedHost, w.Code)
		}
	}

	{
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		req.Host = "attacker.invalid"
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for untrusted host, got %d", w.Code)
		}
	}

	// Standard user must not receive masked API keys or internal LLM endpoints
	{
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/settings-user", nil)
		req.Host = "panel.example.test"
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("settings-user status=%d", w.Code)
		}
		var p SettingsPayload
		_ = json.Unmarshal(w.Body.Bytes(), &p)
		if p.GeminiApiKey != "" || p.OllamaEndpoint != "" {
			t.Fatalf("expected redacted LLM secrets/endpoints for non-admin, got key=%q endpoint=%q", p.GeminiApiKey, p.OllamaEndpoint)
		}
	}

	// Admin receives masked key suffix and internal endpoint
	{
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/settings-admin", nil)
		req.Host = "panel.example.test"
		r.ServeHTTP(w, req)
		var p SettingsPayload
		_ = json.Unmarshal(w.Body.Bytes(), &p)
		if p.GeminiApiKey != "****9876" || p.OllamaEndpoint != "http://10.0.0.5:11434" {
			t.Fatalf("unexpected admin settings payload: key=%q endpoint=%q", p.GeminiApiKey, p.OllamaEndpoint)
		}
	}
}

func TestRound3_MFAHardeningReplayAttemptCapEpochAndRecoverySingleUse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	db.RedisClient = nil
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	pwHash, _ := bcrypt.GenerateFromPassword([]byte("CorrectHorseBatteryStaple!1"), bcrypt.MinCost)
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "AetherFlow", AccountName: "mfa_r3"})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	encSecret, err := EncryptKey(key.Secret())
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}

	if _, err := db.DB.Exec(
		`INSERT INTO users (id, username, email, role, password_hash, totp_secret, totp_enabled, sessions_revoked_after)
		 VALUES (960, 'mfa_r3', 'mfa_r3@example.test', 'user', ?, ?, 1, 100)`,
		string(pwHash), encSecret,
	); err != nil {
		t.Fatalf("seed mfa user: %v", err)
	}

	recPlain := "ABCD-EFGH"
	recHash, _ := bcrypt.GenerateFromPassword([]byte(recPlain), bcrypt.MinCost)
	if _, err := db.DB.Exec(
		`INSERT INTO recovery_codes (user_id, code_hash, used) VALUES (960, ?, 0)`,
		string(recHash),
	); err != nil {
		t.Fatalf("seed recovery code: %v", err)
	}

	r := gin.New()
	r.POST("/login", LocalLogin)
	r.POST("/mfa/verify", MFALoginVerify)
	r.POST("/2fa/disable", func(c *gin.Context) {
		c.Set("user_id", 960)
		Disable2FA(c)
	})
	r.POST("/2fa/recovery/regenerate", func(c *gin.Context) {
		c.Set("user_id", 960)
		Regenerate2FARecoveryCodes(c)
	})

	// 1. Disable2FA MUST reject password-only request (400)
	{
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/2fa/disable", bytes.NewBufferString(`{"password":"CorrectHorseBatteryStaple!1"}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 when disabling 2FA with password only, got %d: %s", w.Code, w.Body.String())
		}
	}

	// 2. Regenerate2FARecoveryCodes MUST require second-factor code (400 without code)
	{
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/2fa/recovery/regenerate", bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 when regenerating recovery codes without second-factor code, got %d", w.Code)
		}
	}

	issueChallenge := func() string {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{"username":"mfa_r3","password":"CorrectHorseBatteryStaple!1"}`))
		req.RemoteAddr = "127.0.0.1:43001"
		req.Header.Set("User-Agent", "MFAClient/1.0")
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("login challenge failed (%d): %s", w.Code, w.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		tok, _ := out["mfa_token"].(string)
		if tok == "" {
			t.Fatalf("missing mfa_token in response: %s", w.Body.String())
		}
		return tok
	}

	// 3. Valid TOTP code redeems ch1, and replaying the SAME 30s TOTP code on ch2 MUST fail (last_totp_step anti-replay)
	ch1 := issueChallenge()
	ch2 := issueChallenge()
	validCode, err := totp.GenerateCode(key.Secret(), time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	{
		body, _ := json.Marshal(map[string]string{"mfa_token": ch1, "code": validCode})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mfa/verify", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:43001"
		req.Header.Set("User-Agent", "MFAClient/1.0")
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 on first TOTP use, got %d: %s", w.Code, w.Body.String())
		}
	}
	{
		body, _ := json.Marshal(map[string]string{"mfa_token": ch2, "code": validCode})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mfa/verify", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:43001"
		req.Header.Set("User-Agent", "MFAClient/1.0")
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on replayed TOTP step, got %d: %s", w.Code, w.Body.String())
		}
	}

	// 4. Recovery code is strictly single-use across challenges
	chRec1 := issueChallenge()
	chRec2 := issueChallenge()
	{
		body, _ := json.Marshal(map[string]string{"mfa_token": chRec1, "code": recPlain})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mfa/verify", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:43001"
		req.Header.Set("User-Agent", "MFAClient/1.0")
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 on first recovery code redemption, got %d: %s", w.Code, w.Body.String())
		}
	}
	{
		body, _ := json.Marshal(map[string]string{"mfa_token": chRec2, "code": recPlain})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mfa/verify", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:43001"
		req.Header.Set("User-Agent", "MFAClient/1.0")
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on reused recovery code, got %d: %s", w.Code, w.Body.String())
		}
	}

	// 5. 5-attempt brute-force cap evicts challenge permanently even if a valid recovery code is supplied on attempt 6
	recPlain2 := "JKLM-NPQR"
	recHash2, _ := bcrypt.GenerateFromPassword([]byte(recPlain2), bcrypt.MinCost)
	_, _ = db.DB.Exec(`INSERT INTO recovery_codes (user_id, code_hash, used) VALUES (960, ?, 0)`, string(recHash2))
	chCap := issueChallenge()
	for i := 0; i < 5; i++ {
		body, _ := json.Marshal(map[string]string{"mfa_token": chCap, "code": "000000"})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mfa/verify", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:43001"
		req.Header.Set("User-Agent", "MFAClient/1.0")
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d expected 401, got %d", i+1, w.Code)
		}
	}
	{
		body, _ := json.Marshal(map[string]string{"mfa_token": chCap, "code": recPlain2})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mfa/verify", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:43001"
		req.Header.Set("User-Agent", "MFAClient/1.0")
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 after 5 failed MFA attempts, got %d: %s", w.Code, w.Body.String())
		}
	}

	// 6. Credential epoch bump (e.g., password change) invalidates outstanding MFA challenge
	chEpoch := issueChallenge()
	_, _ = db.DB.Exec(`UPDATE users SET sessions_revoked_after = 200 WHERE id = 960`)
	{
		body, _ := json.Marshal(map[string]string{"mfa_token": chEpoch, "code": recPlain2})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mfa/verify", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:43001"
		req.Header.Set("User-Agent", "MFAClient/1.0")
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 when redeeming MFA challenge across credential epoch bump, got %d", w.Code)
		}
	}
}

func TestRound3_RefreshSessionLineageSurvivesRestartAndWipesFamily(t *testing.T) {
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
		`INSERT INTO users (id, username, email, role, password_hash) VALUES (970, 'lin_user', 'lin@example.test', 'user', 'h')`,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	r := gin.New()
	r.POST("/refresh", RefreshSession)
	r.GET("/protected", AuthMiddleware(), func(c *gin.Context) { c.Status(http.StatusOK) })

	s1 := mintSessionTokenForTest(t, 970, "127.0.0.1:44001", "LineageUA/1.0")

	rotate := func(tok string) (int, string) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
		req.RemoteAddr = "127.0.0.1:44001"
		req.Header.Set("User-Agent", "LineageUA/1.0")
		req.Header.Set("Authorization", "Bearer "+tok)
		r.ServeHTTP(w, req)
		var out map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out["token"]
	}

	code2, s2 := rotate(s1)
	if code2 != http.StatusOK || s2 == "" {
		t.Fatalf("rotate s1->s2 failed (%d)", code2)
	}
	code3, s3 := rotate(s2)
	if code3 != http.StatusOK || s3 == "" {
		t.Fatalf("rotate s2->s3 failed (%d)", code3)
	}

	// Simulate process restart wiping all in-memory auth caches (localBlacklist, grace window, successor chain)
	db.ClearLocalBlacklist()
	rotatedTokenGrace.Range(func(k, _ interface{}) bool {
		rotatedTokenGrace.Delete(k)
		return true
	})
	rotatedSessionSuccessor.Range(func(k, _ interface{}) bool {
		rotatedSessionSuccessor.Delete(k)
		return true
	})

	// Replaying ancestor s1 MUST return 401 AND revoke the entire session family so descendant s3 is invalidated!
	replayCode, _ := rotate(s1)
	if replayCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on post-restart s1 replay, got %d", replayCode)
	}

	wDesc := httptest.NewRecorder()
	reqDesc := httptest.NewRequest(http.MethodGet, "/protected", nil)
	reqDesc.RemoteAddr = "127.0.0.1:44001"
	reqDesc.Header.Set("User-Agent", "LineageUA/1.0")
	reqDesc.Header.Set("Authorization", "Bearer "+s3)
	r.ServeHTTP(wDesc, reqDesc)
	if wDesc.Code != http.StatusUnauthorized {
		t.Fatalf("expected descendant s3 to be invalidated after post-restart s1 replay, got %d", wDesc.Code)
	}
}

func TestRound3_WebSocketTicketTTLRoleScopingAndRevocationDisconnect(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	db.RedisClient = nil
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	_, _ = db.DB.Exec(
		`INSERT INTO users (id, username, email, role, password_hash, sessions_revoked_after) VALUES
		 (981, 'ws_admin', 'ws_admin@example.test', 'admin', 'h', 0),
		 (982, 'ws_user', 'ws_user@example.test', 'user', 'h', 0)`,
	)

	// 1. Expired WS ticket (>30s old) is rejected with 401
	wsTicketsMu.Lock()
	wsTickets["expired-r3-ticket"] = wsTicketEntry{
		UserID:    981,
		Role:      "admin",
		ClientIP:  "",
		ExpiresAt: time.Now().Add(-60 * time.Second).Unix(),
	}
	wsTicketsMu.Unlock()

	r := gin.New()
	r.GET("/ws", HandleWebSocket)
	wExp := httptest.NewRecorder()
	reqExp := httptest.NewRequest(http.MethodGet, "/ws?ticket=expired-r3-ticket", nil)
	r.ServeHTTP(wExp, reqExp)
	if wExp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired WS ticket, got %d", wExp.Code)
	}

	// 2. Hub outbound event scoping (ACTION_QUEUED admin-only; NOTIFICATION user-scoped) & JTI revocation eviction
	hub := newHub()
	go hub.run()
	time.Sleep(10 * time.Millisecond)

	adminClient := &Client{
		hub:        hub,
		send:       make(chan []byte, 16),
		userID:     981,
		role:       "admin",
		sessionJTI: "jti-ws-admin",
		sessionVer: 0,
	}
	userClient := &Client{
		hub:        hub,
		send:       make(chan []byte, 16),
		userID:     982,
		role:       "user",
		sessionJTI: "jti-ws-user",
		sessionVer: 0,
	}
	hub.register <- adminClient
	hub.register <- userClient
	defer func() {
		hub.unregister <- userClient
	}()

	targetAdmin := 981
	hub.dispatch <- hubEnvelope{
		raw:       []byte(`{"type":"ACTION_QUEUED","data":{"secret":"admin-only"}}`),
		adminOnly: true,
	}
	hub.dispatch <- hubEnvelope{
		raw:          []byte(`{"type":"NOTIFICATION","data":{"user_id":981,"title":"for-admin"}}`),
		targetUserID: &targetAdmin,
	}
	for deadline := time.Now().Add(500 * time.Millisecond); len(adminClient.send) < 2 && time.Now().Before(deadline); {
		time.Sleep(2 * time.Millisecond)
	}

	if len(adminClient.send) != 2 {
		t.Fatalf("expected adminClient to receive 2 messages, got %d", len(adminClient.send))
	}
	if len(userClient.send) != 0 {
		t.Fatalf("expected userClient to receive 0 admin/other-user messages, got %d", len(userClient.send))
	}

	// Revoke adminClient's JTI and verify next broadcast evicts and closes adminClient.send
	if err := db.RevokeToken("jti-ws-admin", time.Hour); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	// Drain buffered messages first
	for len(adminClient.send) > 0 {
		<-adminClient.send
	}
	hub.broadcast <- []byte(`{"type":"SYSTEM_METRICS","payload":{}}`)
	for deadline := time.Now().Add(500 * time.Millisecond); len(hub.dispatch) > 0 || len(hub.broadcast) > 0; {
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	select {
	case _, open := <-adminClient.send:
		if open {
			t.Fatalf("expected revoked adminClient channel to be closed")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timed out waiting for revoked adminClient channel to close")
	}
}

func TestRound5_AESMasterKeyHexPrecedenceAndLastLineEnv(t *testing.T) {
	prevKey := append([]byte(nil), aesMasterKey...)
	t.Cleanup(func() {
		aesMasterKey = prevKey
	})

	firstHex := strings.Repeat("12", 32)
	secondHex := strings.Repeat("ab", 32)
	envPath := filepath.Join(t.TempDir(), "aetherflow.env")
	content := "AES_MASTER_KEY=" + firstHex + "\nexport AES_MASTER_KEY=\"" + secondHex + "\"\n"
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	t.Setenv("AES_MASTER_KEY", "")
	t.Setenv("AETHERFLOW_ENV_FILE", envPath)

	InitAESKey()
	if len(aesMasterKey) != 32 || aesMasterKey[0] != 0xab || aesMasterKey[31] != 0xab {
		t.Fatalf("expected last-line 0xab key bytes, got len=%d", len(aesMasterKey))
	}
}

func TestRound5_RustSha256RecoveryCodeAndMalformedRevokedRowAndHeaderScrub(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	db.RedisClient = nil
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	// 1. Fresh Go migrate() reaches canonical schema version 24
	var maxVer int
	if err := db.DB.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_versions`).Scan(&maxVer); err != nil {
		t.Fatalf("query max schema version: %v", err)
	}
	if maxVer != 24 {
		t.Fatalf("expected Go MAX(schema_versions.version) == 24, got %d", maxVer)
	}

	// 2. Malformed expires_at in revoked_tokens fails closed and survives PruneExpiredData
	if _, err := db.DB.Exec(`INSERT INTO revoked_tokens (jti, expires_at) VALUES ('corrupt-jti-r5', 'not-a-timestamp')`); err != nil {
		t.Fatalf("insert corrupt revoked_token: %v", err)
	}
	db.PruneExpiredData()
	db.ClearLocalBlacklist()
	if !db.IsTokenRevoked("corrupt-jti-r5") {
		t.Fatalf("expected corrupt expires_at row in revoked_tokens to fail closed (revoked=true)")
	}
	if !db.IsTokenRevoked("") {
		t.Fatalf("expected empty JTI to fail closed (revoked=true)")
	}

	// 3. Rust sha256:v1:<32-hex-salt>:<64-hex-digest> recovery code verifies in Go
	plainCode := "ABCD-EFGH"
	compact := "ABCDEFGH"
	saltBytes := bytes.Repeat([]byte{0x5a}, 16) // 16 raw salt bytes (encoded as 32 hex chars in Rust)
	h := sha256.New()
	_, _ = h.Write([]byte("aetherflow-recovery-v1\x00"))
	_, _ = h.Write(saltBytes)
	_, _ = h.Write([]byte(compact))
	rustFormattedHash := fmt.Sprintf("sha256:v1:%x:%x", saltBytes, h.Sum(nil))
	if !verifyRecoveryCodeHash(rustFormattedHash, plainCode) {
		t.Fatalf("expected Go verifyRecoveryCodeHash to accept Rust sha256:v1:<salt>:<digest> format")
	}
	if verifyRecoveryCodeHash(rustFormattedHash, "WRNG-CODE") {
		t.Fatalf("expected wrong code to fail verifyRecoveryCodeHash")
	}

	// 4. AppSubdomainProxyMiddleware scrubs spoofed X-Aetherflow-* and X-Forwarded-User headers upstream
	var gotUpstreamHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUpstreamHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	_, portStr, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("parse upstream port: %v", err)
	}
	var upstreamPort int
	_, _ = fmt.Sscanf(portStr, "%d", &upstreamPort)

	pwHash, _ := bcrypt.GenerateFromPassword([]byte("SecretPass!99"), bcrypt.MinCost)
	if _, err := db.DB.Exec(
		`INSERT INTO users (id, username, email, role, password_hash, sessions_revoked_after) VALUES (991, 'fwd_user', 'fwd@example.test', 'user', ?, 0)`,
		string(pwHash),
	); err != nil {
		t.Fatalf("seed fwd_user: %v", err)
	}
	if _, err := db.DB.Exec(
		`INSERT INTO app_ingress_configs (app_name, public_domain, listen_port, external_access_enabled) VALUES ('sonarr', 'sonarr.example.test', ?, 1)`,
		upstreamPort,
	); err != nil {
		t.Fatalf("seed app_ingress_configs: %v", err)
	}
	tok := mintSessionTokenForTest(t, 991, "127.0.0.1:45001", "FwdUA/1.0")
	r := gin.New()
	r.Use(AppSubdomainProxyMiddleware())
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusTeapot) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://sonarr.example.test/ping", nil)
	req.Host = "sonarr.example.test"
	req.RemoteAddr = "127.0.0.1:45001"
	req.Header.Set("User-Agent", "FwdUA/1.0")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Aetherflow-Role", "admin")
	req.Header.Set("X-Forwarded-User", "spoofed-admin")
	req.Header.Set("Remote-User", "spoofed-root")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("AppSubdomainProxyMiddleware expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := gotUpstreamHeaders.Get("X-Aetherflow-User"); got != "fwd_user" {
		t.Fatalf("expected upstream X-Aetherflow-User=fwd_user, got %q", got)
	}
	if got := gotUpstreamHeaders.Get("X-Aetherflow-Role"); got != "" {
		t.Fatalf("expected spoofed X-Aetherflow-Role header to be scrubbed upstream, got %q", got)
	}
	if got := gotUpstreamHeaders.Get("X-Forwarded-User"); got != "" {
		t.Fatalf("expected spoofed X-Forwarded-User header to be scrubbed upstream, got %q", got)
	}
	if got := gotUpstreamHeaders.Get("Remote-User"); got != "" {
		t.Fatalf("expected spoofed Remote-User header to be scrubbed upstream, got %q", got)
	}
}

func TestRound5_RotationGraceRevokesImmediatelyWhenSuccessorLogsOut(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	db.RedisClient = nil
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	_, _ = db.DB.Exec(
		`INSERT INTO users (id, username, email, role, password_hash, sessions_revoked_after) VALUES (995, 'grace_u', 'grace@example.test', 'user', 'h', 0)`,
	)

	r := gin.New()
	r.POST("/refresh", RefreshSession)
	r.POST("/logout", AuthMiddleware(), Logout)
	r.GET("/protected", AuthMiddleware(), func(c *gin.Context) { c.Status(http.StatusOK) })

	s1 := mintSessionTokenForTest(t, 995, "127.0.0.1:46001", "GraceUA/1.0")
	wRot := httptest.NewRecorder()
	reqRot := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	reqRot.RemoteAddr = "127.0.0.1:46001"
	reqRot.Header.Set("User-Agent", "GraceUA/1.0")
	reqRot.Header.Set("Authorization", "Bearer "+s1)
	r.ServeHTTP(wRot, reqRot)
	if wRot.Code != http.StatusOK {
		t.Fatalf("refresh s1->s2 failed: %d", wRot.Code)
	}
	var out map[string]string
	_ = json.Unmarshal(wRot.Body.Bytes(), &out)
	s2 := out["token"]

	// Logout successor s2
	wOut := httptest.NewRecorder()
	reqOut := httptest.NewRequest(http.MethodPost, "/logout", nil)
	reqOut.RemoteAddr = "127.0.0.1:46001"
	reqOut.Header.Set("User-Agent", "GraceUA/1.0")
	reqOut.Header.Set("Authorization", "Bearer "+s2)
	r.ServeHTTP(wOut, reqOut)
	if wOut.Code != http.StatusOK {
		t.Fatalf("logout s2 failed: %d", wOut.Code)
	}

	// Predecessor s1 MUST NOT be accepted via the 15s grace window once leaf s2 is revoked!
	wGrace := httptest.NewRecorder()
	reqGrace := httptest.NewRequest(http.MethodGet, "/protected", nil)
	reqGrace.RemoteAddr = "127.0.0.1:46001"
	reqGrace.Header.Set("User-Agent", "GraceUA/1.0")
	reqGrace.Header.Set("Authorization", "Bearer "+s1)
	r.ServeHTTP(wGrace, reqGrace)
	if wGrace.Code != http.StatusUnauthorized {
		t.Fatalf("expected predecessor s1 to be rejected (401) after successor s2 logged out, got %d", wGrace.Code)
	}
}

func TestRound6_ChainedNormalRotationPreservesGraceAndOIDCWriteFailureRollsBack(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	db.RedisClient = nil
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	_, err := db.DB.Exec(
		"INSERT INTO users (id, username, password_hash, role, sessions_revoked_after) VALUES (996, 'r6user', 'hash', 'user', 0)",
	)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	r := gin.New()
	r.POST("/refresh", RefreshSession)
	r.GET("/protected", AuthMiddleware(), func(c *gin.Context) { c.Status(http.StatusOK) })

	// Rotate s0 -> s1 -> s2 within 15s grace window
	s0 := mintSessionTokenForTest(t, 996, "127.0.0.1:46002", "GraceUA/2.0")

	doRefresh := func(tok string) (int, string) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
		req.RemoteAddr = "127.0.0.1:46002"
		req.Header.Set("User-Agent", "GraceUA/2.0")
		req.Header.Set("Authorization", "Bearer "+tok)
		r.ServeHTTP(w, req)
		var resp map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		nextTok, _ := resp["token"].(string)
		return w.Code, nextTok
	}

	code1, s1 := doRefresh(s0)
	if code1 != http.StatusOK || s1 == "" {
		t.Fatalf("s0 -> s1 failed: code=%d", code1)
	}
	code2, s2 := doRefresh(s1)
	if code2 != http.StatusOK || s2 == "" {
		t.Fatalf("s1 -> s2 failed: code=%d", code2)
	}

	// Overlapping request with s0 during 15s grace must succeed (not wipe active family!)
	codeGrace, sGrace := doRefresh(s0)
	if codeGrace != http.StatusOK || sGrace != s2 {
		t.Fatalf("expected overlapping s0 refresh during grace to return latest token s2 (200), got code=%d", codeGrace)
	}

	// Verify active session s2 remains authorized
	wProt := httptest.NewRecorder()
	reqProt := httptest.NewRequest(http.MethodGet, "/protected", nil)
	reqProt.RemoteAddr = "127.0.0.1:46002"
	reqProt.Header.Set("User-Agent", "GraceUA/2.0")
	reqProt.Header.Set("Authorization", "Bearer "+s2)
	r.ServeHTTP(wProt, reqProt)
	if wProt.Code != http.StatusOK {
		t.Fatalf("expected active leaf s2 to remain valid (200), got %d", wProt.Code)
	}

	// Verify revokeAllUserCredentialsInTx aborts when oidc_refresh_tokens write fails
	if _, err := db.DB.Exec(
		`INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) VALUES ('c-r6', 'h', 'App', '["https://example.com/cb"]')`,
	); err != nil {
		t.Fatalf("insert oidc client: %v", err)
	}
	if _, err := db.DB.Exec(
		`INSERT INTO oidc_refresh_tokens (token, client_id, user_id, scope, expires_at, revoked) VALUES ('rt-r6', 'c-r6', 996, 'openid', datetime('now', '+1 hour'), 0)`,
	); err != nil {
		t.Fatalf("insert oidc refresh token: %v", err)
	}
	if _, err := db.DB.Exec(
		`CREATE TRIGGER fail_oidc_rt_revoke BEFORE UPDATE ON oidc_refresh_tokens BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END;`,
	); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	tx, txErr := db.DB.Begin()
	if txErr != nil {
		t.Fatalf("begin tx: %v", txErr)
	}
	if _, _, revErr := revokeAllUserCredentialsInTx(tx, 996); revErr == nil {
		_ = tx.Rollback()
		t.Fatalf("expected revokeAllUserCredentialsInTx to fail closed when OIDC revocation fails")
	}
	_ = tx.Rollback()
}

func TestRound7_ConcurrentSetupAdminOIDCReuseSettingsEncryptAndLegacySecretMigration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	db.RedisClient = nil
	prevKey := append([]byte(nil), aesMasterKey...)
	aesMasterKey = bytes.Repeat([]byte{0x77}, 32)
	t.Cleanup(func() {
		aesMasterKey = prevKey
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})

	// Ensure users table starts completely empty for SetupAdmin race test
	if _, err := db.DB.Exec(`DELETE FROM active_sessions; DELETE FROM users;`); err != nil {
		t.Fatalf("clear users/sessions: %v", err)
	}

	r := gin.New()
	r.POST("/setup", SetupAdmin)
	r.POST("/oidc/token", OIDCToken)
	r.POST("/2fa/disable", AuthMiddleware(), Disable2FA)

	// 1. Concurrent SetupAdmin: strictly 1 winner (200 OK) and 5 conflicts (409 Conflict)
	const workers = 6
	codes := make([]int, workers)
	startCh := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startCh
			body := fmt.Sprintf(`{"username":"admin_%d","password":"StrongSetupPassword!99"}`, idx)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = fmt.Sprintf("127.0.0.1:4700%d", idx)
			req.Header.Set("User-Agent", "SetupRaceUA/1.0")
			r.ServeHTTP(w, req)
			codes[idx] = w.Code
		}(i)
	}
	close(startCh)
	wg.Wait()

	var okCount, conflictCount int
	for _, code := range codes {
		switch code {
		case http.StatusOK:
			okCount++
		case http.StatusConflict:
			conflictCount++
		default:
			t.Fatalf("unexpected SetupAdmin status code %d in %v", code, codes)
		}
	}
	if okCount != 1 || conflictCount != workers-1 {
		t.Fatalf("expected 1x200 and %dx409 from concurrent SetupAdmin, got codes=%v", workers-1, codes)
	}
	var userCount, sessionCount int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&userCount)
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM active_sessions`).Scan(&sessionCount)
	if userCount != 1 || sessionCount != 1 {
		t.Fatalf("expected 1 user and 1 initial session after concurrent SetupAdmin, got users=%d sessions=%d", userCount, sessionCount)
	}

	// 2. MigrateLegacySecrets encrypts settings AI keys, users.totp_secret, and streaming_servers.api_key
	var adminID int
	_ = db.DB.QueryRow(`SELECT id FROM users LIMIT 1`).Scan(&adminID)
	if _, err := db.DB.Exec(
		`UPDATE settings SET gemini_api_key = 'leg-gem', openai_api_key = 'leg-oai', anthropic_api_key = 'leg-ant' WHERE id = 1`,
	); err != nil {
		t.Fatalf("seed legacy settings keys: %v", err)
	}
	if _, err := db.DB.Exec(
		`UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP', totp_enabled = 1 WHERE id = ?`,
		adminID,
	); err != nil {
		t.Fatalf("seed legacy totp_secret: %v", err)
	}
	if _, err := db.DB.Exec(
		`INSERT INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'JF', 'http://127.0.0.1:8096', 'leg-jf-key', 1)`,
	); err != nil {
		t.Fatalf("seed legacy streaming_servers key: %v", err)
	}

	if err := MigrateLegacySecrets(); err != nil {
		t.Fatalf("MigrateLegacySecrets failed: %v", err)
	}

	var gemEnc, oaiEnc, antEnc, totpEnc, jfEnc string
	_ = db.DB.QueryRow(`SELECT gemini_api_key, openai_api_key, anthropic_api_key FROM settings WHERE id = 1`).Scan(&gemEnc, &oaiEnc, &antEnc)
	_ = db.DB.QueryRow(`SELECT totp_secret FROM users WHERE id = ?`, adminID).Scan(&totpEnc)
	_ = db.DB.QueryRow(`SELECT api_key FROM streaming_servers WHERE provider = 'jellyfin'`).Scan(&jfEnc)

	for label, pair := range map[string][2]string{
		"gemini":    {gemEnc, "leg-gem"},
		"openai":    {oaiEnc, "leg-oai"},
		"anthropic": {antEnc, "leg-ant"},
		"totp":      {totpEnc, "JBSWY3DPEHPK3PXP"},
		"jellyfin":  {jfEnc, "leg-jf-key"},
	} {
		if !strings.HasPrefix(pair[0], "enc:v1:") {
			t.Fatalf("expected %s secret to be enc:v1: encrypted, got %q", label, pair[0])
		}
		dec, err := DecryptKey(pair[0])
		if err != nil || dec != pair[1] {
			t.Fatalf("DecryptKey(%s) = %q, %v; want %q", label, dec, err, pair[1])
		}
	}

	// 3. Disable2FA fails closed (500) when stored totp_secret ciphertext is tampered
	if _, err := db.DB.Exec(`UPDATE users SET totp_secret = 'enc:v1:!!!tampered!!!', totp_enabled = 1 WHERE id = ?`, adminID); err != nil {
		t.Fatalf("tamper totp_secret: %v", err)
	}
	adminTok := mintSessionTokenForTest(t, adminID, "127.0.0.1:47099", "AdminUA/1.0")
	w2FA := httptest.NewRecorder()
	req2FA := httptest.NewRequest(http.MethodPost, "/2fa/disable", strings.NewReader(`{"code":"123456"}`))
	req2FA.Header.Set("Content-Type", "application/json")
	req2FA.Header.Set("Authorization", "Bearer "+adminTok)
	req2FA.RemoteAddr = "127.0.0.1:47099"
	req2FA.Header.Set("User-Agent", "AdminUA/1.0")
	r.ServeHTTP(w2FA, req2FA)
	if w2FA.Code != http.StatusInternalServerError {
		t.Fatalf("expected Disable2FA with tampered ciphertext to fail closed with 500, got %d: %s", w2FA.Code, w2FA.Body.String())
	}

	// 4. OIDCToken refresh_token reuse revocation DB write error fails closed with 500
	if _, err := db.DB.Exec(
		`INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) VALUES ('pub-r7', '', 'PubR7', '["https://example.com/cb"]')`,
	); err != nil {
		t.Fatalf("insert public oidc client: %v", err)
	}
	if _, err := db.DB.Exec(
		`INSERT INTO oidc_refresh_tokens (token, client_id, user_id, scope, expires_at, revoked, family_id) VALUES ('reused-rt-r7', 'pub-r7', ?, 'openid', datetime('now', '+1 hour'), 1, 'fam-r7')`,
		adminID,
	); err != nil {
		t.Fatalf("insert revoked refresh token: %v", err)
	}
	if _, err := db.DB.Exec(
		`CREATE TRIGGER fail_r7_reuse_revoke BEFORE UPDATE ON oidc_refresh_tokens BEGIN SELECT RAISE(ABORT, 'simulated reuse revoke write failure'); END;`,
	); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", "pub-r7")
	form.Set("refresh_token", "reused-rt-r7")
	wOIDC := httptest.NewRecorder()
	reqOIDC := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	reqOIDC.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(wOIDC, reqOIDC)
	if wOIDC.Code != http.StatusInternalServerError {
		t.Fatalf("expected OIDCToken reuse revocation DB write failure to return 500, got %d: %s", wOIDC.Code, wOIDC.Body.String())
	}
}

func TestRound8_OIDCSessionScopingAuthCodeReplayVerify2FAConflictWSOriginAndLogRedaction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	db.RedisClient = nil
	prevKey := append([]byte(nil), aesMasterKey...)
	aesMasterKey = bytes.Repeat([]byte{0x88}, 32)
	t.Cleanup(func() {
		aesMasterKey = prevKey
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})
	t.Setenv("OIDC_KEY_PATH", filepath.Join(t.TempDir(), "oidc_r8.pem"))
	loadOrGenerateOIDCKey()

	// 1. BeginWriteTx upgrades immediately to RESERVED lock and commits cleanly
	tx, release, err := db.BeginWriteTx()
	if err != nil {
		t.Fatalf("BeginWriteTx: %v", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO users (id, username, email, role, password_hash, totp_enabled, totp_secret)
		 VALUES (980, 'r8_user', 'r8@example.test', 'user', 'h', 1, 'JBSWY3DPEHPK3PXP')`,
	); err != nil {
		release()
		t.Fatalf("insert user in write tx: %v", err)
	}
	if err := db.CommitWriteTx(tx, release); err != nil {
		t.Fatalf("CommitWriteTx: %v", err)
	}

	r := gin.New()
	r.POST("/user/2fa/verify", AuthMiddleware(), Verify2FA)
	r.POST("/logout", AuthMiddleware(), Logout)
	r.POST("/oidc/token", OIDCToken)
	r.GET("/oidc/userinfo", OIDCUserInfo)

	// 2. Verify2FA returns 409 Conflict when totp_enabled == 1
	sessA := mintSessionTokenForTest(t, 980, "127.0.0.1:48001", "R8UA/1.0")
	_ = mintSessionTokenForTest(t, 980, "127.0.0.1:48001", "R8UA/1.0")
	var jtis []string
	rows, err := db.DB.Query(`SELECT jti FROM active_sessions WHERE user_id = 980 ORDER BY rowid ASC`)
	if err != nil {
		t.Fatalf("query active_sessions: %v", err)
	}
	for rows.Next() {
		var j string
		_ = rows.Scan(&j)
		jtis = append(jtis, j)
	}
	_ = rows.Close()
	if len(jtis) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(jtis))
	}

	validCode, err := totp.GenerateCode("JBSWY3DPEHPK3PXP", time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	w2FA := httptest.NewRecorder()
	req2FA := httptest.NewRequest(http.MethodPost, "/user/2fa/verify", strings.NewReader(fmt.Sprintf(`{"code":%q}`, validCode)))
	req2FA.Header.Set("Content-Type", "application/json")
	req2FA.Header.Set("Authorization", "Bearer "+sessA)
	req2FA.RemoteAddr = "127.0.0.1:48001"
	req2FA.Header.Set("User-Agent", "R8UA/1.0")
	r.ServeHTTP(w2FA, req2FA)
	if w2FA.Code != http.StatusConflict {
		t.Fatalf("expected Verify2FA when already enabled to return 409, got %d: %s", w2FA.Code, w2FA.Body.String())
	}

	// 3. Session-scoped OIDC revocation on Logout + single-use auth-code replay family revocation
	secSum := sha256.Sum256([]byte("r8-go-secret"))
	if _, err := db.DB.Exec(
		`INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) VALUES ('r8-go-client', ?, 'R8Go', '["https://r8.example/cb"]')`,
		hex.EncodeToString(secSum[:]),
	); err != nil {
		t.Fatalf("insert oidc client: %v", err)
	}
	verifier := strings.Repeat("v", 43)
	vSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(vSum[:])

	codeA, err := generateAndStoreAuthCodeForSession("r8-go-client", 980, "https://r8.example/cb", "openid profile email", "", challenge, "S256", jtis[0])
	if err != nil {
		t.Fatalf("codeA: %v", err)
	}
	codeB, err := generateAndStoreAuthCodeForSession("r8-go-client", 980, "https://r8.example/cb", "openid profile email", "", challenge, "S256", jtis[1])
	if err != nil {
		t.Fatalf("codeB: %v", err)
	}

	exchangeCode := func(code string) (int, map[string]any) {
		f := url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"r8-go-client"},
			"client_secret": {"r8-go-secret"},
			"code":          {code},
			"redirect_uri":  {"https://r8.example/cb"},
			"code_verifier": {verifier},
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	stA, tokA := exchangeCode(codeA)
	stB, tokB := exchangeCode(codeB)
	if stA != http.StatusOK || stB != http.StatusOK {
		t.Fatalf("expected initial code exchanges 200/200, got %d/%d", stA, stB)
	}
	accessA := tokA["access_token"].(string)
	refreshA := tokA["refresh_token"].(string)
	accessB := tokB["access_token"].(string)
	refreshB := tokB["refresh_token"].(string)

	callUserInfo := func(at string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+at)
		r.ServeHTTP(w, req)
		return w.Code
	}
	if callUserInfo(accessA) != http.StatusOK || callUserInfo(accessB) != http.StatusOK {
		t.Fatalf("expected both OIDC access tokens valid before logout")
	}

	// Logout Session A -> revokes accessA + refreshA, keeps accessB alive
	wOut := httptest.NewRecorder()
	reqOut := httptest.NewRequest(http.MethodPost, "/logout", nil)
	reqOut.Header.Set("Authorization", "Bearer "+sessA)
	reqOut.RemoteAddr = "127.0.0.1:48001"
	reqOut.Header.Set("User-Agent", "R8UA/1.0")
	r.ServeHTTP(wOut, reqOut)
	if wOut.Code != http.StatusOK {
		t.Fatalf("Logout sessA failed: %d", wOut.Code)
	}
	if got := callUserInfo(accessA); got != http.StatusUnauthorized {
		t.Fatalf("expected accessA revoked after Logout sessA (401), got %d", got)
	}
	if got := callUserInfo(accessB); got != http.StatusOK {
		t.Fatalf("expected sibling session accessB to stay active (200), got %d", got)
	}
	fRefA := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"r8-go-client"},
		"client_secret": {"r8-go-secret"},
		"refresh_token": {refreshA},
	}
	wRefA := httptest.NewRecorder()
	reqRefA := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(fRefA.Encode()))
	reqRefA.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(wRefA, reqRefA)
	if wRefA.Code != http.StatusBadRequest {
		t.Fatalf("expected refreshA revoked after Logout sessA (400), got %d", wRefA.Code)
	}

	// Replay consumed codeB -> revokes accessB + refreshB immediately
	stReplayB, _ := exchangeCode(codeB)
	if stReplayB != http.StatusBadRequest {
		t.Fatalf("expected consumed codeB replay 400, got %d", stReplayB)
	}
	if got := callUserInfo(accessB); got != http.StatusUnauthorized {
		t.Fatalf("expected accessB immediately revoked on auth-code replay (401), got %d", got)
	}
	fRefB := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"r8-go-client"},
		"client_secret": {"r8-go-secret"},
		"refresh_token": {refreshB},
	}
	wRefB := httptest.NewRecorder()
	reqRefB := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(fRefB.Encode()))
	reqRefB.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(wRefB, reqRefB)
	if wRefB.Code != http.StatusBadRequest {
		t.Fatalf("expected refreshB revoked on auth-code replay (400), got %d", wRefB.Code)
	}

	// 4. CheckOrigin rejects spoofed X-Forwarded-Proto: https from untrusted external RemoteAddr
	t.Setenv("ALLOWED_ORIGINS", "")
	spoofWS := httptest.NewRequest(http.MethodGet, "http://panel.example.test/api/v1/ws", nil)
	spoofWS.Host = "panel.example.test"
	spoofWS.RemoteAddr = "203.0.113.77:54321"
	spoofWS.Header.Set("Origin", "https://panel.example.test")
	spoofWS.Header.Set("X-Forwarded-Proto", "https")
	if upgrader.CheckOrigin(spoofWS) {
		t.Fatalf("expected CheckOrigin to reject spoofed X-Forwarded-Proto: https on plain-HTTP direct peer")
	}

	// 5. RedactLogSecrets scrubs tokens, URL credentials, JSON keys, and KV passwords
	rawLog := `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret postgres://af:s3cr3t@127.0.0.1/db {"api_key":"sk-live-999"} rclone_pass=topsecret123`
	scrubbed := services.RedactLogSecrets(rawLog)
	for _, leaked := range []string{"eyJhbGciOiJIUzI1NiJ9.secret", "s3cr3t", "sk-live-999", "topsecret123"} {
		if strings.Contains(scrubbed, leaked) {
			t.Fatalf("RedactLogSecrets leaked %q in %q", leaked, scrubbed)
		}
	}
}
