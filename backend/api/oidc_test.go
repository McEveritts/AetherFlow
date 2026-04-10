package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// ── Phase 29: OIDC Provider Flow Tests ──────────────────────────────────
//
// These tests verify the OIDC provider contract: discovery document shape,
// JWKS key structure, PKCE verification, scope validation, redirect URI
// matching, and key ID computation.

// --- Discovery Document ---

func TestOIDCDiscovery_Shape(t *testing.T) {
	r := gin.New()
	r.GET("/.well-known/openid-configuration", OIDCDiscovery)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
	req.Host = "localhost:3000"
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	// Required OIDC discovery fields
	required := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"userinfo_endpoint",
		"jwks_uri",
		"revocation_endpoint",
		"introspection_endpoint",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
		"scopes_supported",
	}
	for _, field := range required {
		if _, ok := doc[field]; !ok {
			t.Errorf("Missing required OIDC discovery field: %s", field)
		}
	}
}

func TestOIDCDiscovery_AlgorithmRS256(t *testing.T) {
	r := gin.New()
	r.GET("/.well-known/openid-configuration", OIDCDiscovery)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
	req.Host = "localhost:3000"
	r.ServeHTTP(w, req)

	var doc map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &doc)

	algs, ok := doc["id_token_signing_alg_values_supported"].([]interface{})
	if !ok || len(algs) == 0 {
		t.Fatal("Missing signing algorithm values")
	}

	if algs[0] != "RS256" {
		t.Errorf("Expected RS256 as primary signing algorithm, got %v", algs[0])
	}
}

func TestOIDCDiscovery_PKCESupported(t *testing.T) {
	r := gin.New()
	r.GET("/.well-known/openid-configuration", OIDCDiscovery)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
	req.Host = "localhost:3000"
	r.ServeHTTP(w, req)

	var doc map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &doc)

	methods, ok := doc["code_challenge_methods_supported"].([]interface{})
	if !ok || len(methods) == 0 {
		t.Fatal("Missing code_challenge_methods_supported")
	}

	hasS256 := false
	for _, m := range methods {
		if m == "S256" {
			hasS256 = true
		}
	}
	if !hasS256 {
		t.Error("S256 PKCE method must be supported")
	}
}

// --- JWKS Endpoint ---

func TestOIDCJWKS_KeyShape(t *testing.T) {
	r := gin.New()
	r.GET("/jwks", OIDCJwks)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/jwks", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("Invalid JWKS JSON: %v", err)
	}

	if len(jwks.Keys) == 0 {
		t.Fatal("Expected at least one key in JWKS")
	}

	key := jwks.Keys[0]
	requiredFields := []string{"kty", "use", "kid", "alg", "n", "e"}
	for _, field := range requiredFields {
		if _, ok := key[field]; !ok {
			t.Errorf("Missing JWKS key field: %s", field)
		}
	}

	if key["kty"] != "RSA" {
		t.Errorf("Expected kty=RSA, got %v", key["kty"])
	}
	if key["alg"] != "RS256" {
		t.Errorf("Expected alg=RS256, got %v", key["alg"])
	}
	if key["use"] != "sig" {
		t.Errorf("Expected use=sig, got %v", key["use"])
	}
}

func TestOIDCJWKS_KeyIDConsistent(t *testing.T) {
	r := gin.New()
	r.GET("/jwks", OIDCJwks)

	// Call twice — kid must be stable across requests
	kids := make([]string, 2)
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/jwks", nil)
		r.ServeHTTP(w, req)

		var jwks struct {
			Keys []map[string]interface{} `json:"keys"`
		}
		json.Unmarshal(w.Body.Bytes(), &jwks)
		kids[i] = jwks.Keys[0]["kid"].(string)
	}

	if kids[0] != kids[1] {
		t.Errorf("Key ID not stable: %q vs %q", kids[0], kids[1])
	}
}

// --- PKCE Verification ---

func TestVerifyPKCE_S256_Valid(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	if !verifyPKCE(verifier, challenge, "S256") {
		t.Error("Expected valid S256 PKCE to pass")
	}
}

func TestVerifyPKCE_S256_Invalid(t *testing.T) {
	if verifyPKCE("wrong-verifier", "wrong-challenge", "S256") {
		t.Error("Expected invalid S256 PKCE to fail")
	}
}

func TestVerifyPKCE_Plain_Valid(t *testing.T) {
	verifier := "my-plain-challenge-code"
	if !verifyPKCE(verifier, verifier, "plain") {
		t.Error("Expected matching plain PKCE to pass")
	}
}

func TestVerifyPKCE_Plain_Empty(t *testing.T) {
	if verifyPKCE("", "challenge", "plain") {
		t.Error("Expected empty verifier to fail")
	}
}

func TestVerifyPKCE_EmptyVerifier(t *testing.T) {
	if verifyPKCE("", "challenge", "S256") {
		t.Error("Expected empty verifier to fail")
	}
}

func TestVerifyPKCE_UnknownMethod(t *testing.T) {
	if verifyPKCE("verifier", "challenge", "RS256") {
		t.Error("Expected unknown PKCE method to fail")
	}
}

// --- Scope Validation ---

func TestValidateOIDCScopes_Default(t *testing.T) {
	result := validateOIDCScopes("")
	if result != "openid profile email" {
		t.Errorf("Expected default scopes, got %q", result)
	}
}

func TestValidateOIDCScopes_ValidSubset(t *testing.T) {
	result := validateOIDCScopes("openid profile")
	if result != "openid profile" {
		t.Errorf("Expected 'openid profile', got %q", result)
	}
}

func TestValidateOIDCScopes_InvalidFiltered(t *testing.T) {
	result := validateOIDCScopes("openid admin root sudoers")
	if result != "openid" {
		t.Errorf("Expected only 'openid', got %q", result)
	}
}

func TestValidateOIDCScopes_AllInvalid(t *testing.T) {
	result := validateOIDCScopes("admin root")
	if result != "openid" {
		t.Errorf("Expected fallback 'openid', got %q", result)
	}
}

func TestValidateOIDCScopes_DeduplicatesScopes(t *testing.T) {
	result := validateOIDCScopes("openid openid email email")
	if result != "openid email" {
		t.Errorf("Expected deduplicated 'openid email', got %q", result)
	}
}

// --- Redirect URI Validation ---

func TestIsAllowedRedirectURI_Exact(t *testing.T) {
	stored := `["http://localhost:8080/callback","https://app.example.com/auth"]`
	if !isAllowedRedirectURI("http://localhost:8080/callback", stored) {
		t.Error("Expected exact match to be allowed")
	}
}

func TestIsAllowedRedirectURI_NotInList(t *testing.T) {
	stored := `["http://localhost:8080/callback"]`
	if isAllowedRedirectURI("http://evil.com/steal", stored) {
		t.Error("Expected non-registered URI to be rejected")
	}
}

func TestIsAllowedRedirectURI_InvalidJSON(t *testing.T) {
	if isAllowedRedirectURI("http://localhost", "not-json") {
		t.Error("Expected invalid stored URIs to reject")
	}
}

func TestIsAllowedRedirectURI_PartialMatch(t *testing.T) {
	stored := `["http://localhost:8080/callback"]`
	// Partial match should NOT work — must be exact
	if isAllowedRedirectURI("http://localhost:8080/callback?param=evil", stored) {
		t.Error("Expected partial match with query params to be rejected")
	}
}

// --- Key ID Computation ---

func TestComputeKeyID_Deterministic(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	kid1 := computeKeyID(key)
	kid2 := computeKeyID(key)

	if kid1 != kid2 {
		t.Errorf("computeKeyID not deterministic: %q != %q", kid1, kid2)
	}
	if kid1 == "" {
		t.Error("computeKeyID returned empty string")
	}
}

func TestComputeKeyID_UniquePerKey(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	kid1 := computeKeyID(key1)
	kid2 := computeKeyID(key2)

	if kid1 == kid2 {
		t.Error("Different keys should produce different key IDs")
	}
}

// --- Token Introspection (RFC 7662) ---

func TestIntrospectAccessToken_InvalidJWT(t *testing.T) {
	result := introspectAccessToken("not-a-valid-jwt", "test-client")
	if result != nil {
		t.Error("Expected nil for invalid JWT")
	}
}

func TestIntrospectAccessToken_WrongSigningMethod(t *testing.T) {
	// Create an HMAC-signed token (wrong method — introspect expects RSA)
	hmacToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "1",
		"aud": "test-client",
	})
	signed, _ := hmacToken.SignedString([]byte("secret"))

	result := introspectAccessToken(signed, "test-client")
	if result != nil {
		t.Error("Expected nil for HMAC-signed token (RSA expected)")
	}
}

func TestIntrospectAccessToken_ValidRSA(t *testing.T) {
	// Create a valid RSA-signed token using the loaded OIDC key
	claims := jwt.MapClaims{
		"sub":   "42",
		"aud":   "my-client",
		"scope": "openid profile",
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = oidcKeyID
	signed, err := token.SignedString(oidcPrivateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	result := introspectAccessToken(signed, "my-client")
	if result == nil {
		t.Fatal("Expected non-nil result for valid RSA token")
	}

	active, _ := result["active"].(bool)
	if !active {
		t.Error("Expected active=true for valid token")
	}
	if result["sub"] != "42" {
		t.Errorf("Expected sub=42, got %v", result["sub"])
	}
	if result["token_type"] != "Bearer" {
		t.Errorf("Expected token_type=Bearer, got %v", result["token_type"])
	}
}

func TestIntrospectAccessToken_WrongAudience(t *testing.T) {
	claims := jwt.MapClaims{
		"sub": "42",
		"aud": "different-client",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, _ := token.SignedString(oidcPrivateKey)

	// Introspecting with a different client_id should return nil
	result := introspectAccessToken(signed, "my-client")
	if result != nil {
		t.Error("Expected nil when audience doesn't match client_id")
	}
}
