package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ---- RSA Key Management ----

var oidcPrivateKey *rsa.PrivateKey
var oidcKeyID string

func init() {
	loadOrGenerateOIDCKey()
}

// loadOrGenerateOIDCKey loads the OIDC RSA key from disk, or generates a new one.
func loadOrGenerateOIDCKey() {
	keyPath := os.Getenv("OIDC_KEY_PATH")
	if keyPath == "" {
		// Anchor to the executable's directory (not CWD) to prevent
		// silent key regeneration when started from a different directory.
		exe, exeErr := os.Executable()
		if exeErr != nil {
			slog.Warn("OIDC: failed to resolve executable path, using CWD fallback", "error", exeErr)
			keyPath = "data/oidc_rsa.pem"
		} else {
			keyPath = filepath.Join(filepath.Dir(exe), "data", "oidc_rsa.pem")
		}
	}

	// Try to load existing key
	keyBytes, err := os.ReadFile(keyPath)
	if err == nil {
		block, _ := pem.Decode(keyBytes)
		if block != nil {
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				oidcPrivateKey = key
				oidcKeyID = computeKeyID(key)
				slog.Info("OIDC key loaded", "path", keyPath, "kid", oidcKeyID)
				return
			}
		}
	}

	// Generate new key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("OIDC: failed to generate RSA key", "error", err)
		return
	}

	oidcPrivateKey = key
	oidcKeyID = computeKeyID(key)

	// Persist to disk — create parent directory if needed
	keyDir := filepath.Dir(keyPath)
	os.MkdirAll(keyDir, 0700)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		slog.Warn("OIDC: failed to persist RSA key", "error", err)
	} else {
		slog.Info("OIDC key generated", "path", keyPath, "kid", oidcKeyID)
	}
}

// computeKeyID creates a thumbprint-based key ID from the public key.
func computeKeyID(key *rsa.PrivateKey) string {
	pubBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	hash := sha256.Sum256(pubBytes)
	return hex.EncodeToString(hash[:8])
}

// getOIDCIssuer returns the OIDC issuer URL, derived from env or request context.
func getOIDCIssuer(c *gin.Context) string {
	if issuer := os.Getenv("OIDC_ISSUER"); issuer != "" {
		return issuer
	}
	return getBaseURL(c)
}

// ---- OIDC Discovery ----

// OIDCDiscovery returns the OpenID Connect discovery document.
func OIDCDiscovery(c *gin.Context) {
	issuer := getOIDCIssuer(c)

	c.JSON(http.StatusOK, gin.H{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/api/v1/public/oidc/authorize",
		"token_endpoint":         issuer + "/api/v1/public/oidc/token",
		"userinfo_endpoint":      issuer + "/api/v1/public/oidc/userinfo",
		"jwks_uri":               issuer + "/api/v1/public/oidc/jwks",
		"revocation_endpoint":    issuer + "/api/v1/public/oidc/revoke",
		"introspection_endpoint": issuer + "/api/v1/public/oidc/introspect",
		"response_types_supported": []string{"code"},
		"subject_types_supported":  []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":     []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "name", "email", "picture", "role",
		},
		"code_challenge_methods_supported": []string{"S256", "plain"},
	})
}

// ---- JWKS ----

// OIDCJwks returns the JSON Web Key Set containing the public key.
func OIDCJwks(c *gin.Context) {
	if oidcPrivateKey == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OIDC keys not initialized"})
		return
	}

	pub := &oidcPrivateKey.PublicKey
	c.JSON(http.StatusOK, gin.H{
		"keys": []gin.H{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": oidcKeyID,
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	})
}

// ---- Authorization Endpoint ----

// OIDCAuthorize handles the authorization code flow with PKCE support.
func OIDCAuthorize(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

	if responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_response_type"})
		return
	}

	// Validate client
	var storedRedirectURIs string
	err := db.DB.QueryRow("SELECT redirect_uris FROM oidc_clients WHERE id = ?", clientID).Scan(&storedRedirectURIs)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	// Validate redirect URI
	if !isAllowedRedirectURI(redirectURI, storedRedirectURIs) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri"})
		return
	}

	// Check session — user must be logged in
	cookie, err := c.Cookie("aetherflow_session")
	if err != nil {
	// Redirect to login — URL-encode return_to to prevent open redirect (CWE-601)
		returnTo := url.QueryEscape(c.Request.URL.RequestURI())
		c.Redirect(http.StatusTemporaryRedirect, "/login?return_to="+returnTo)
		return
	}

	_, err = extractUserIDFromJWT(cookie)
	if err != nil {
		returnTo := url.QueryEscape(c.Request.URL.RequestURI())
		c.Redirect(http.StatusTemporaryRedirect, "/login?return_to="+returnTo)
		return
	}

	// Validate requested scopes against supported scopes
	validatedScope := validateOIDCScopes(scope)

	// Check if user has already granted consent for this client + scope combination.
	// If so, skip the consent screen and issue the authorization code directly.
	userID, _ := extractUserIDFromJWT(cookie)
	if hasExistingConsent(userID, clientID, validatedScope) {
		code, err := generateAndStoreAuthCode(clientID, userID, redirectURI, validatedScope, codeChallenge, codeChallengeMethod)
		if err != nil {
			slog.Error("OIDC: failed to issue auth code for returning consent", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		sep := "?"
		if strings.Contains(redirectURI, "?") {
			sep = "&"
		}
		redirectURL := fmt.Sprintf("%s%scode=%s", redirectURI, sep, code)
		if state != "" {
			redirectURL += "&state=" + url.QueryEscape(state)
		}
		c.Redirect(http.StatusTemporaryRedirect, redirectURL)
		return
	}

	// Redirect to frontend consent screen instead of auto-approving.
	// The frontend will prompt the user and then call POST /api/v1/auth/oidc/consent
	consentURL := fmt.Sprintf("/oauth/consent?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s&state=%s&code_challenge=%s&code_challenge_method=%s",
		url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(responseType),
		url.QueryEscape(validatedScope), url.QueryEscape(state), url.QueryEscape(codeChallenge), url.QueryEscape(codeChallengeMethod))

	c.Redirect(http.StatusTemporaryRedirect, consentURL)
}

// OIDCConsent is called by the frontend after the user approves the OAuth request.
// It generates the authorization code and returns the redirect URL.
func OIDCConsent(c *gin.Context) {
	userId, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		ClientID            string `json:"client_id" binding:"required"`
		RedirectURI         string `json:"redirect_uri" binding:"required"`
		ResponseType        string `json:"response_type" binding:"required"`
		Scope               string `json:"scope"`
		State               string `json:"state"`
		CodeChallenge       string `json:"code_challenge"`
		CodeChallengeMethod string `json:"code_challenge_method"`
		Approved            bool   `json:"approved"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !req.Approved {
		// User denied consent
		sep := "?"
		if strings.Contains(req.RedirectURI, "?") {
			sep = "&"
		}
		redirectURL := fmt.Sprintf("%s%serror=access_denied&error_description=User+denied+access", req.RedirectURI, sep)
		if req.State != "" {
			redirectURL += "&state=" + url.QueryEscape(req.State)
		}
		c.JSON(http.StatusOK, gin.H{"redirect_uri": redirectURL, "redirect_url": redirectURL})
		return
	}

	if req.ResponseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_response_type"})
		return
	}

	var storedRedirectURIs string
	err := db.DB.QueryRow("SELECT redirect_uris FROM oidc_clients WHERE id = ?", req.ClientID).Scan(&storedRedirectURIs)
	if err != nil || !isAllowedRedirectURI(req.RedirectURI, storedRedirectURIs) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client_or_redirect_uri"})
		return
	}

	scope := validateOIDCScopes(req.Scope)
	if scope == "" {
		scope = "openid profile email"
	}

	code, err := generateAndStoreAuthCode(req.ClientID, userId.(int), req.RedirectURI, scope, req.CodeChallenge, req.CodeChallengeMethod)
	if err != nil {
		slog.Error("OIDC: failed to store auth code", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Persist the consent grant so future requests from this client skip the consent screen
	recordConsent(userId.(int), req.ClientID, scope)

	// Redirect back with code
	sep := "?"
	if strings.Contains(req.RedirectURI, "?") {
		sep = "&"
	}
	redirectURL := fmt.Sprintf("%s%scode=%s", req.RedirectURI, sep, code)
	if req.State != "" {
		redirectURL += "&state=" + url.QueryEscape(req.State)
	}

	c.JSON(http.StatusOK, gin.H{"redirect_uri": redirectURL, "redirect_url": redirectURL})
}

// ---- Token Endpoint ----

// OIDCToken exchanges an authorization code or refresh token for tokens.
func OIDCToken(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	// Support HTTP Basic auth for client credentials
	if clientID == "" {
		basicClientID, basicSecret, ok := c.Request.BasicAuth()
		if ok {
			clientID = basicClientID
			clientSecret = basicSecret
		}
	}

	// Validate client credentials
	var storedSecretHash string
	err := db.DB.QueryRow("SELECT client_secret_hash FROM oidc_clients WHERE id = ?", clientID).Scan(&storedSecretHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	secretHash := sha256.Sum256([]byte(clientSecret))
	if hex.EncodeToString(secretHash[:]) != storedSecretHash {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	switch grantType {
	case "authorization_code":
		handleAuthCodeExchange(c, clientID)
	case "refresh_token":
		handleRefreshTokenExchange(c, clientID)
	case "urn:ietf:params:oauth:grant-type:device_code":
		handleDeviceCodeExchange(c, clientID)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}
}

func handleAuthCodeExchange(c *gin.Context, clientID string) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")

	var (
		storedClientID      string
		userID              int
		storedRedirectURI   string
		scope               string
		codeChallenge       string
		codeChallengeMethod string
		expiresAt           string
		used                bool
	)

	err := db.DB.QueryRow(
		`SELECT client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, used
		 FROM oidc_auth_codes WHERE code = ?`,
		code,
	).Scan(&storedClientID, &userID, &storedRedirectURI, &scope, &codeChallenge, &codeChallengeMethod, &expiresAt, &used)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	if used {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "code already used"})
		return
	}

	if storedClientID != clientID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	if storedRedirectURI != redirectURI {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	// Check expiry
	expTime, parseErr := time.Parse(time.RFC3339, expiresAt)
	if parseErr != nil {
		slog.Error("OIDC: failed to parse auth code expiry", "raw", expiresAt, "error", parseErr)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "malformed expiry"})
		return
	}
	if time.Now().After(expTime) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "code expired"})
		return
	}

	// Validate PKCE
	if codeChallenge != "" {
		if !verifyPKCE(codeVerifier, codeChallenge, codeChallengeMethod) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
	}

	// Phase 16: Wrap code-use + token-issue in a transaction to prevent replay attacks.
	// Without this, two concurrent requests with the same auth code could both succeed.
	tx, txErr := db.DB.Begin()
	if txErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Mark code as used within the transaction
	result, execErr := tx.Exec("UPDATE oidc_auth_codes SET used = 1 WHERE code = ? AND used = 0", code)
	if execErr != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Check that exactly 1 row was affected (code wasn't already used)
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		tx.Rollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "code already used"})
		return
	}

	if commitErr := tx.Commit(); commitErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Generate tokens
	issueOIDCTokens(c, clientID, userID, scope)
}

func handleRefreshTokenExchange(c *gin.Context, clientID string) {
	refreshToken := c.PostForm("refresh_token")

	var (
		storedClientID string
		userID         int
		scope          string
		expiresAt      string
		revoked        bool
	)

	err := db.DB.QueryRow(
		`SELECT client_id, user_id, scope, expires_at, revoked FROM oidc_refresh_tokens WHERE token = ?`,
		refreshToken,
	).Scan(&storedClientID, &userID, &scope, &expiresAt, &revoked)

	if err != nil || revoked || storedClientID != clientID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	expTime, parseErr := time.Parse(time.RFC3339, expiresAt)
	if parseErr != nil {
		slog.Error("OIDC: failed to parse refresh token expiry", "raw", expiresAt, "error", parseErr)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "malformed expiry"})
		return
	}
	if time.Now().After(expTime) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "refresh token expired"})
		return
	}

	// Phase 16: Atomic refresh token rotation.
	// Revoke-then-issue must be transactional to prevent concurrent refresh attacks.
	tx, txErr := db.DB.Begin()
	if txErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	result, execErr := tx.Exec("UPDATE oidc_refresh_tokens SET revoked = 1 WHERE token = ? AND revoked = 0", refreshToken)
	if execErr != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		tx.Rollback()
		slog.Warn("OIDC: refresh token replay detected", "client_id", clientID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "token already consumed"})
		return
	}

	if commitErr := tx.Commit(); commitErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Issue new tokens
	issueOIDCTokens(c, clientID, userID, scope)
}

func issueOIDCTokens(c *gin.Context, clientID string, userID int, scope string) {
	if oidcPrivateKey == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	issuer := getOIDCIssuer(c)

	// Fetch user info
	var username, email, avatarURL, role string
	if err := db.DB.QueryRow("SELECT username, email, avatar_url, role FROM users WHERE id = ?", userID).
		Scan(&username, &email, &avatarURL, &role); err != nil {
		slog.Error("OIDC: failed to fetch user info during token issuance", "user_id", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	now := time.Now()

	// ID Token (short-lived, 1 hour)
	idTokenClaims := jwt.MapClaims{
		"iss":     issuer,
		"sub":     fmt.Sprintf("%d", userID),
		"aud":     clientID,
		"exp":     now.Add(1 * time.Hour).Unix(),
		"iat":     now.Unix(),
		"name":    username,
		"email":   email,
		"picture": avatarURL,
		"role":    role,
	}

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
	idToken.Header["kid"] = oidcKeyID
	idTokenString, err := idToken.SignedString(oidcPrivateKey)
	if err != nil {
		slog.Error("OIDC: failed to sign id_token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Access Token (short-lived, 1 hour)
	accessTokenClaims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   fmt.Sprintf("%d", userID),
		"aud":   clientID,
		"exp":   now.Add(1 * time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": scope,
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessTokenClaims)
	accessToken.Header["kid"] = oidcKeyID
	accessTokenString, err := accessToken.SignedString(oidcPrivateKey)
	if err != nil {
		slog.Error("OIDC: failed to sign access_token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Refresh Token (long-lived, 30 days)
	refreshBytes := make([]byte, 32)
	if _, err := rand.Read(refreshBytes); err != nil {
		slog.Error("crypto/rand failure during OIDC refresh token generation", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	refreshToken := hex.EncodeToString(refreshBytes)

	db.DB.Exec(
		`INSERT INTO oidc_refresh_tokens (token, client_id, user_id, scope, expires_at) VALUES (?, ?, ?, ?, ?)`,
		refreshToken, clientID, userID, scope, now.Add(30*24*time.Hour).Format(time.RFC3339),
	)

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessTokenString,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
		"id_token":      idTokenString,
		"scope":         scope,
	})
}

// ---- UserInfo ----

// OIDCUserInfo returns standard OIDC claims for the authenticated user.
func OIDCUserInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse and validate the access token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &oidcPrivateKey.PublicKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	sub, _ := claims["sub"].(string)
	var username, email, avatarURL, role string
	if err := db.DB.QueryRow("SELECT username, email, avatar_url, role FROM users WHERE id = ?", sub).
		Scan(&username, &email, &avatarURL, &role); err != nil {
		slog.Error("OIDC: failed to fetch user info during userinfo request", "sub", sub, "error", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sub":     sub,
		"name":    username,
		"email":   email,
		"picture": avatarURL,
		"role":    role,
	})
}

// ---- Token Revocation ----

// OIDCRevoke revokes a refresh token. Requires client authentication per RFC 7009.
func OIDCRevoke(c *gin.Context) {
	// Client authentication (same as OIDCToken)
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	if clientID == "" {
		basicClientID, basicSecret, ok := c.Request.BasicAuth()
		if ok {
			clientID = basicClientID
			clientSecret = basicSecret
		}
	}

	if clientID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "client authentication required"})
		return
	}

	var storedSecretHash string
	err := db.DB.QueryRow("SELECT client_secret_hash FROM oidc_clients WHERE id = ?", clientID).Scan(&storedSecretHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	secretHash := sha256.Sum256([]byte(clientSecret))
	if hex.EncodeToString(secretHash[:]) != storedSecretHash {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	db.DB.Exec("UPDATE oidc_refresh_tokens SET revoked = 1 WHERE token = ? AND client_id = ?", token, clientID)
	c.JSON(http.StatusOK, gin.H{}) // RFC 7009: 200 even if token doesn't exist
}

// ---- Token Introspection (RFC 7662) ----

// OIDCIntrospect validates an access or refresh token and returns its claims.
// Requires client authentication via client_secret_post or HTTP Basic Auth.
// POST /api/v1/public/oidc/introspect
//
// Request: token=<string>&token_type_hint=<access_token|refresh_token>
// Response: { "active": true|false, "sub": "...", "client_id": "...", ... }
func OIDCIntrospect(c *gin.Context) {
	// ── Client Authentication ──
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	if clientID == "" {
		basicClientID, basicSecret, ok := c.Request.BasicAuth()
		if ok {
			clientID = basicClientID
			clientSecret = basicSecret
		}
	}

	if clientID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "client authentication required"})
		return
	}

	var storedSecretHash string
	err := db.DB.QueryRow("SELECT client_secret_hash FROM oidc_clients WHERE id = ?", clientID).Scan(&storedSecretHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	secretHash := sha256.Sum256([]byte(clientSecret))
	if hex.EncodeToString(secretHash[:]) != storedSecretHash {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	// ── Token Extraction ──
	tokenStr := c.PostForm("token")
	if tokenStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "token parameter required"})
		return
	}

	tokenTypeHint := c.PostForm("token_type_hint")

	// ── Try access_token (JWT) first, unless hinted otherwise ──
	if tokenTypeHint != "refresh_token" {
		if result := introspectAccessToken(tokenStr, clientID); result != nil {
			c.JSON(http.StatusOK, result)
			return
		}
	}

	// ── Try refresh_token (database) ──
	if tokenTypeHint != "access_token" {
		if result := introspectRefreshToken(tokenStr, clientID); result != nil {
			c.JSON(http.StatusOK, result)
			return
		}
	}

	// RFC 7662: inactive token → { "active": false }
	c.JSON(http.StatusOK, gin.H{"active": false})
}

// introspectAccessToken validates a JWT access token and returns its claims.
func introspectAccessToken(tokenStr, clientID string) gin.H {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &oidcPrivateKey.PublicKey, nil
	})

	if err != nil || !token.Valid {
		return nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}

	// Verify the token was issued for this client
	aud, _ := claims["aud"].(string)
	if aud != clientID {
		return nil
	}

	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)
	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)

	return gin.H{
		"active":     true,
		"sub":        sub,
		"client_id":  clientID,
		"scope":      scope,
		"exp":        int64(exp),
		"iat":        int64(iat),
		"token_type": "Bearer",
	}
}

// introspectRefreshToken checks the database for a valid, non-revoked refresh token.
func introspectRefreshToken(tokenStr, clientID string) gin.H {
	var userID int
	var scope string
	var revoked bool
	var expiresAt string

	err := db.DB.QueryRow(
		"SELECT user_id, scope, revoked, expires_at FROM oidc_refresh_tokens WHERE token = ? AND client_id = ?",
		tokenStr, clientID,
	).Scan(&userID, &scope, &revoked, &expiresAt)

	if err != nil {
		return nil
	}

	if revoked {
		return gin.H{"active": false}
	}

	// Check expiration
	expTime, err := time.Parse(time.RFC3339, expiresAt)
	if err == nil && time.Now().After(expTime) {
		return gin.H{"active": false}
	}

	return gin.H{
		"active":     true,
		"sub":        fmt.Sprintf("%d", userID),
		"client_id":  clientID,
		"scope":      scope,
		"token_type": "refresh_token",
	}
}

// ---- Helpers ----

// extractUserIDFromJWT parses a JWT and returns the user_id claim.
func extractUserIDFromJWT(tokenString string) (int, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return getJWTSecret(), nil
	})

	if err != nil || !token.Valid {
		return 0, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, fmt.Errorf("invalid claims")
	}

	userIdFloat, ok := claims["user_id"].(float64)
	if !ok {
		return 0, fmt.Errorf("no user_id in claims")
	}

	return int(userIdFloat), nil
}

// isAllowedRedirectURI checks if the redirect_uri is registered for the client.
func isAllowedRedirectURI(uri, storedURIs string) bool {
	var uris []string
	if err := json.Unmarshal([]byte(storedURIs), &uris); err != nil {
		return false
	}
	for _, allowed := range uris {
		if uri == allowed {
			return true
		}
	}
	return false
}

// verifyPKCE validates the PKCE code_verifier against the stored challenge.
func verifyPKCE(verifier, challenge, method string) bool {
	if verifier == "" {
		return false
	}

	switch method {
	case "S256":
		hash := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		return computed == challenge
	case "plain", "":
		return verifier == challenge
	default:
		return false
	}
}

// createStandardJWT creates a JWT with a unique jti, short-lived expiry, and
// client fingerprint binding. This is the single source of truth for session JWT creation.
// The fingerprint (cfp claim) is a SHA256 of IP+UserAgent, preventing stolen tokens
// from being replayed on different devices/networks.
func createStandardJWT(userID int, c *gin.Context) (string, error) {
	jti := uuid.New().String()
	fp := clientFingerprint(c)

	claims := jwt.MapClaims{
		"user_id": userID,
		"sub":     fmt.Sprintf("%d", userID),
		"iss":     "aetherflow",
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
		"jti":     jti,
		"cfp":     fp,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(getJWTSecret())
	if err != nil {
		return "", err
	}

	// Record the session for listing/revocation (best-effort)
	recordActiveSession(userID, jti, c)

	return tokenString, nil
}

// clientFingerprint produces a deterministic fingerprint of the client's identity.
// Used to bind JWTs to a specific client (IP + UserAgent) to detect session hijacking.
func clientFingerprint(c *gin.Context) string {
	raw := c.ClientIP() + "|" + c.Request.UserAgent()
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// recordActiveSession persists session metadata for the session listing endpoint.
func recordActiveSession(userID int, jti string, c *gin.Context) {
	ua := c.Request.UserAgent()
	ip := c.ClientIP()
	expiresAt := time.Now().Add(15 * time.Minute).Format(time.RFC3339)

	_, err := db.DB.Exec(
		`INSERT OR REPLACE INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at, last_active)
		 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		jti, userID, ip, ua, expiresAt,
	)
	if err != nil {
		slog.Warn("session tracking: failed to record session", "error", err)
	}
}

// lookupOIDCClient retrieves client info from the database.
func lookupOIDCClient(clientID string) (name string, redirectURIs string, err error) {
	err = db.DB.QueryRow(
		"SELECT name, redirect_uris FROM oidc_clients WHERE id = ?",
		clientID,
	).Scan(&name, &redirectURIs)
	if err == sql.ErrNoRows {
		return "", "", fmt.Errorf("client not found")
	}
	return
}

// ---- Device Code Flow ----

func generateUserCode() string {
	const charset = "BCDFGHJKLMNPQRSTVWXZ23456789"
	b := make([]byte, 8)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[num.Int64()]
	}
	return string(b[:4]) + "-" + string(b[4:])
}

func OIDCDeviceAuthorize(c *gin.Context) {
	clientID := c.PostForm("client_id")
	scope := c.PostForm("scope")
	if scope == "" {
		scope = "openid profile email"
	}

	var storedSecretHash string
	err := db.DB.QueryRow("SELECT client_secret_hash FROM oidc_clients WHERE id = ?", clientID).Scan(&storedSecretHash)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	deviceCodeBytes := make([]byte, 32)
	rand.Read(deviceCodeBytes)
	deviceCode := hex.EncodeToString(deviceCodeBytes)
	userCode := generateUserCode()
	expiresAt := time.Now().Add(10 * time.Minute)

	_, err = db.DB.Exec(
		"INSERT INTO oidc_device_codes (device_code, user_code, client_id, scope, expires_at, status) VALUES (?, ?, ?, ?, ?, 'pending')",
		deviceCode, userCode, clientID, scope, expiresAt.Format(time.RFC3339),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	issuer := getOIDCIssuer(c)
	verificationURI := issuer + "/oauth/device"

	c.JSON(http.StatusOK, gin.H{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + userCode,
		"expires_in":                600,
		"interval":                  5,
	})
}

func handleDeviceCodeExchange(c *gin.Context, clientID string) {
	deviceCode := c.PostForm("device_code")

	var (
		storedClientID string
		userIDErr      sql.NullInt64
		scope          string
		expiresAt      string
		status         string
	)

	err := db.DB.QueryRow(
		"SELECT client_id, user_id, scope, expires_at, status FROM oidc_device_codes WHERE device_code = ?",
		deviceCode,
	).Scan(&storedClientID, &userIDErr, &scope, &expiresAt, &status)

	if err != nil || storedClientID != clientID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	expTime, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || time.Now().After(expTime) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expired_token"})
		return
	}

	switch status {
	case "pending":
		c.JSON(http.StatusBadRequest, gin.H{"error": "authorization_pending"})
		return
	case "denied":
		c.JSON(http.StatusBadRequest, gin.H{"error": "access_denied"})
		return
	case "approved":
		if !userIDErr.Valid {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		db.DB.Exec("DELETE FROM oidc_device_codes WHERE device_code = ?", deviceCode)
		issueOIDCTokens(c, clientID, int(userIDErr.Int64), scope)
		return
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
}

func OIDCDeviceVerify(c *gin.Context) {
	var req struct {
		UserCode string `json:"user_code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var status string
	var scope string
	var clientID string
	err := db.DB.QueryRow("SELECT status, scope, client_id FROM oidc_device_codes WHERE user_code = ?", req.UserCode).Scan(&status, &scope, &clientID)
	
	if err != nil || status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_user_code"})
		return
	}

	var name string
	db.DB.QueryRow("SELECT name FROM oidc_clients WHERE id = ?", clientID).Scan(&name)

	c.JSON(http.StatusOK, gin.H{
		"status": status,
		"scope": scope,
		"client_id": clientID,
		"client_name": name,
	})
}

func OIDCDeviceConsent(c *gin.Context) {
	userId, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		UserCode string `json:"user_code" binding:"required"`
		Approved bool   `json:"approved"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	status := "denied"
	if req.Approved {
		status = "approved"
	}

	res, err := db.DB.Exec("UPDATE oidc_device_codes SET status = ?, user_id = ? WHERE user_code = ? AND status = 'pending'", status, userId.(int), req.UserCode)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	affected, _ := res.RowsAffected()
	if affected == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_user_code"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": status})
}

// ---- Phase 5: OIDC Helpers ----

// supportedOIDCScopes defines the scopes this provider supports.
var supportedOIDCScopes = map[string]bool{
	"openid":  true,
	"profile": true,
	"email":   true,
}

// validateOIDCScopes filters requested scopes to only those the provider supports.
// Returns a space-delimited string of valid scopes only.
func validateOIDCScopes(requested string) string {
	if strings.TrimSpace(requested) == "" {
		return "openid profile email"
	}

	var valid []string
	seen := map[string]bool{}
	for _, s := range strings.Fields(requested) {
		s = strings.TrimSpace(s)
		if supportedOIDCScopes[s] && !seen[s] {
			valid = append(valid, s)
			seen[s] = true
		}
	}

	if len(valid) == 0 {
		return "openid"
	}
	return strings.Join(valid, " ")
}

// hasExistingConsent checks if a user has previously granted consent for the given client and scopes.
func hasExistingConsent(userID int, clientID, requestedScope string) bool {
	var storedScope string
	err := db.DB.QueryRow(
		"SELECT scope FROM oidc_consents WHERE user_id = ? AND client_id = ?",
		userID, clientID,
	).Scan(&storedScope)
	if err != nil {
		return false
	}

	// Verify all requested scopes are covered by the stored consent
	storedSet := map[string]bool{}
	for _, s := range strings.Fields(storedScope) {
		storedSet[s] = true
	}
	for _, s := range strings.Fields(requestedScope) {
		if !storedSet[s] {
			return false // new scope requested — need fresh consent
		}
	}
	return true
}

// recordConsent persists (or updates) a consent grant for a user+client combination.
func recordConsent(userID int, clientID, scope string) {
	_, err := db.DB.Exec(
		`INSERT INTO oidc_consents (user_id, client_id, scope, granted_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(user_id, client_id) DO UPDATE SET scope = excluded.scope, granted_at = CURRENT_TIMESTAMP`,
		userID, clientID, scope,
	)
	if err != nil {
		slog.Error("OIDC: failed to record consent", "user_id", userID, "client_id", clientID, "error", err)
	}
}

// generateAndStoreAuthCode creates a cryptographic authorization code, persists it, and returns it.
func generateAndStoreAuthCode(clientID string, userID int, redirectURI, scope, codeChallenge, codeChallengeMethod string) (string, error) {
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return "", fmt.Errorf("crypto/rand failure: %w", err)
	}
	code := hex.EncodeToString(codeBytes)

	expiresAt := time.Now().Add(10 * time.Minute)
	_, err := db.DB.Exec(
		`INSERT INTO oidc_auth_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		code, clientID, userID, redirectURI, scope, codeChallenge, codeChallengeMethod, expiresAt.Format(time.RFC3339),
	)
	if err != nil {
		return "", err
	}
	return code, nil
}
