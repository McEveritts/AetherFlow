package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, err := generateAndStoreAuthCode(clientID, 801, redirectURI, tc.scope, tc.nonce, "", "")
			if err != nil {
				t.Fatalf("generateAndStoreAuthCode: %v", err)
			}

			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("code", code)
			form.Set("redirect_uri", redirectURI)
			form.Set("client_id", clientID)
			form.Set("client_secret", clientSecret)

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
