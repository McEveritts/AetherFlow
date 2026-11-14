package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aetherflow/db"

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
	if maxVer != 22 {
		t.Fatalf("expected legacy Go fresh MAX(schema_versions.version) == 22 (<= 24), got %d", maxVer)
	}
	if _, err := db.DB.Exec("INSERT INTO schema_versions (version, description) VALUES (24, 'v4 schema ceiling')"); err != nil {
		t.Fatalf("seed v24 row: %v", err)
	}
	if err := db.DB.QueryRow("SELECT MAX(version) FROM schema_versions").Scan(&maxVer); err != nil || maxVer != 24 {
		t.Fatalf("expected MAX(schema_versions.version) == 24 preserved, got %d (err=%v)", maxVer, err)
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

	// Simulate process restart wiping in-memory localBlacklist
	db.ClearLocalBlacklist()

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
	time.Sleep(10 * time.Millisecond)

	targetAdmin := 981
	hub.dispatch <- hubEnvelope{
		raw:       []byte(`{"type":"ACTION_QUEUED","data":{"secret":"admin-only"}}`),
		adminOnly: true,
	}
	hub.dispatch <- hubEnvelope{
		raw:          []byte(`{"type":"NOTIFICATION","data":{"user_id":981,"title":"for-admin"}}`),
		targetUserID: &targetAdmin,
	}
	time.Sleep(15 * time.Millisecond)

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
	time.Sleep(15 * time.Millisecond)

	if _, open := <-adminClient.send; open {
		t.Fatalf("expected revoked adminClient channel to be closed")
	}
}
