package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
	keyPath := strings.TrimSpace(os.Getenv("OIDC_KEY_PATH"))
	if keyPath == "" {
		if sd := strings.TrimSpace(os.Getenv("STATE_DIRECTORY")); sd != "" {
			keyPath = filepath.Join(sd, "oidc_rsa.pem")
		} else if dd := strings.TrimSpace(os.Getenv("DATA_DIR")); dd != "" {
			keyPath = filepath.Join(dd, "oidc_rsa.pem")
		} else {
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
	}

	keyPath = filepath.Clean(keyPath)

	// Try to load existing key
	keyBytes, err := os.ReadFile(keyPath) // #nosec G703 -- trusted operator OIDC_KEY_PATH environment variable
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
	_ = os.MkdirAll(keyDir, 0700) // #nosec G703 -- trusted operator OIDC_KEY_PATH environment variable
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil { // #nosec G703 -- trusted operator OIDC_KEY_PATH environment variable
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
	if issuer := strings.TrimRight(strings.TrimSpace(os.Getenv("OIDC_ISSUER")), "/"); issuer != "" {
		return issuer
	}
	return strings.TrimRight(getBaseURL(c), "/")
}

func isAcceptedOIDCIssuer(c *gin.Context, tokenIss string) bool {
	normalized := strings.TrimRight(strings.TrimSpace(tokenIss), "/")
	if normalized == "" {
		return false
	}
	if cfgIss := strings.TrimRight(strings.TrimSpace(os.Getenv("OIDC_ISSUER")), "/"); cfgIss != "" {
		return subtle.ConstantTimeCompare([]byte(normalized), []byte(cfgIss)) == 1
	}
	if c != nil && normalized == getOIDCIssuer(c) {
		return true
	}
	if pubURL := strings.TrimRight(strings.TrimSpace(os.Getenv("PUBLIC_URL")), "/"); pubURL != "" && normalized == pubURL {
		return true
	}
	parsed, err := url.Parse(normalized)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return isAllowedHost(parsed.Host)
	case "http":
		return isLoopbackHost(parsed.Host) && (strings.TrimSpace(os.Getenv("ALLOWED_HOSTS")) == "" || isAllowedHost(parsed.Host))
	default:
		return false
	}
}

func isValidPKCEChallenge(challenge string) bool {
	if len(challenge) != 43 {
		return false
	}
	for i := 0; i < len(challenge); i++ {
		ch := challenge[i]
		isAlphaNum := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
		if !isAlphaNum && ch != '-' && ch != '_' {
			return false
		}
	}
	return true
}

func isValidPKCEVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for i := 0; i < len(verifier); i++ {
		ch := verifier[i]
		isAlphaNum := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
		if !isAlphaNum && ch != '-' && ch != '.' && ch != '_' && ch != '~' {
			return false
		}
	}
	return true
}

func validatePKCERequestParams(codeChallenge, codeChallengeMethod string, _ bool) (string, bool) {
	challenge := strings.TrimSpace(codeChallenge)
	method := strings.TrimSpace(codeChallengeMethod)
	if challenge == "" {
		return "PKCE S256 code_challenge is required for authorization code requests", false
	}
	if method != "S256" {
		return "code_challenge_method must be S256", false
	}
	if !isValidPKCEChallenge(challenge) {
		return "code_challenge must be a 43-character base64url SHA-256 digest", false
	}
	return "", true
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
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "name", "email", "picture", "role",
		},
		"code_challenge_methods_supported": []string{"S256"},
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
	nonce := c.Query("nonce")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

	if responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_response_type"})
		return
	}

	// Validate client
	var storedRedirectURIs, storedSecretHash string
	err := db.DB.QueryRow(
		"SELECT redirect_uris, COALESCE(client_secret_hash, '') FROM oidc_clients WHERE id = ?",
		clientID,
	).Scan(&storedRedirectURIs, &storedSecretHash)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	// Validate redirect URI
	if !isSafeRedirectURI(redirectURI) || !isAllowedRedirectURI(redirectURI, storedRedirectURIs) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri"})
		return
	}

	if errDesc, ok := validatePKCERequestParams(codeChallenge, codeChallengeMethod, strings.TrimSpace(storedSecretHash) == ""); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": errDesc})
		return
	}

	// Check session — user must have a non-revoked, fingerprint-matching active human session
	_, _, subj, err := resolveSessionTokenWithSubject(c)
	if err != nil {
		returnTo := url.QueryEscape(c.Request.URL.RequestURI())
		c.Redirect(http.StatusTemporaryRedirect, "/login?return_to="+returnTo)
		return
	}
	userID := subj.userID

	// Validate requested scopes against supported scopes
	validatedScope := validateOIDCScopes(scope)

	// Check if user has already granted consent for this client + scope combination.
	// If so, skip the consent screen and issue the authorization code directly.
	if hasExistingConsent(userID, clientID, validatedScope) {
		code, err := generateAndStoreAuthCode(clientID, userID, redirectURI, validatedScope, nonce, codeChallenge, codeChallengeMethod)
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
	consentURL := fmt.Sprintf("/oauth/consent?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s&state=%s&nonce=%s&code_challenge=%s&code_challenge_method=%s",
		url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(responseType),
		url.QueryEscape(validatedScope), url.QueryEscape(state), url.QueryEscape(nonce),
		url.QueryEscape(codeChallenge), url.QueryEscape(codeChallengeMethod))

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
		Nonce               string `json:"nonce"`
		CodeChallenge       string `json:"code_challenge"`
		CodeChallengeMethod string `json:"code_challenge_method"`
		Approved            bool   `json:"approved"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.ResponseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_response_type"})
		return
	}

	var storedRedirectURIs, storedSecretHash string
	err := db.DB.QueryRow(
		"SELECT redirect_uris, COALESCE(client_secret_hash, '') FROM oidc_clients WHERE id = ?",
		req.ClientID,
	).Scan(&storedRedirectURIs, &storedSecretHash)
	if err != nil || !isSafeRedirectURI(req.RedirectURI) || !isAllowedRedirectURI(req.RedirectURI, storedRedirectURIs) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client_or_redirect_uri"})
		return
	}

	if !req.Approved {
		// User denied consent (only redirect after validating client and redirect_uri)
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

	if _, subErr := loadActiveHumanSubject(db.DB, userId.(int)); subErr != nil {
		if errors.Is(subErr, errSubjectSuspended) {
			c.JSON(http.StatusForbidden, gin.H{"error": "access_denied", "error_description": "Account is not active"})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	if errDesc, ok := validatePKCERequestParams(req.CodeChallenge, req.CodeChallengeMethod, strings.TrimSpace(storedSecretHash) == ""); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": errDesc})
		return
	}

	scope := validateOIDCScopes(req.Scope)
	if scope == "" {
		scope = "openid profile email"
	}

	code, err := generateAndStoreAuthCode(req.ClientID, userId.(int), req.RedirectURI, scope, req.Nonce, req.CodeChallenge, req.CodeChallengeMethod)
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
	err := db.DB.QueryRow("SELECT COALESCE(client_secret_hash, '') FROM oidc_clients WHERE id = ?", clientID).Scan(&storedSecretHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	isPublicClient := strings.TrimSpace(storedSecretHash) == ""
	if !isPublicClient {
		secretHash := sha256.Sum256([]byte(clientSecret))
		computed := hex.EncodeToString(secretHash[:])
		if subtle.ConstantTimeCompare([]byte(computed), []byte(storedSecretHash)) != 1 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
	} else if clientSecret != "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	switch grantType {
	case "authorization_code":
		handleAuthCodeExchange(c, clientID, isPublicClient)
	case "refresh_token":
		handleRefreshTokenExchange(c, clientID)
	case "urn:ietf:params:oauth:grant-type:device_code":
		if isPublicClient {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
		handleDeviceCodeExchange(c, clientID)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}
}

func handleAuthCodeExchange(c *gin.Context, clientID string, isPublicClient bool) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")

	var (
		storedClientID      string
		userID              int
		storedRedirectURI   string
		scope               string
		nonce               string
		codeChallenge       string
		codeChallengeMethod string
		expiresAt           string
		used                bool
	)

	err := db.DB.QueryRow(
		`SELECT client_id, user_id, redirect_uri, scope, COALESCE(nonce, ''), code_challenge, code_challenge_method, expires_at, used
		 FROM oidc_auth_codes WHERE code = ?`,
		code,
	).Scan(&storedClientID, &userID, &storedRedirectURI, &scope, &nonce, &codeChallenge, &codeChallengeMethod, &expiresAt, &used)

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

	// Enforce universal RFC 7636 PKCE S256 for all authorization code exchanges (public and confidential)
	if strings.TrimSpace(codeChallenge) == "" || !verifyPKCE(codeVerifier, codeChallenge, codeChallengeMethod) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "PKCE verification failed"})
		return
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
		_ = tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Check that exactly 1 row was affected (code wasn't already used)
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		_ = tx.Rollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "code already used"})
		return
	}

	if _, subErr := loadActiveHumanSubject(tx, userID); subErr != nil {
		_ = tx.Rollback()
		if errors.Is(subErr, errSubjectSuspended) {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid_grant", "error_description": "account suspended"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	payload, issueErr := prepareOIDCTokenPayload(c, tx, clientID, userID, scope, nonce, "")
	if issueErr != nil {
		_ = tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	if commitErr := tx.Commit(); commitErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, payload)
}

func handleRefreshTokenExchange(c *gin.Context, clientID string) {
	refreshToken := strings.TrimSpace(c.PostForm("refresh_token"))
	if refreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	tx, txErr := db.DB.Begin()
	if txErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var (
		storedClientID string
		userID         int
		scope          string
		expiresAt      string
		revoked        bool
		familyID       string
	)

	err := tx.QueryRow(
		`SELECT client_id, user_id, scope, expires_at, revoked, COALESCE(family_id, '')
		 FROM oidc_refresh_tokens WHERE token = ?`,
		refreshToken,
	).Scan(&storedClientID, &userID, &scope, &expiresAt, &revoked, &familyID)
	if err != nil && strings.Contains(err.Error(), "no such column") {
		err = tx.QueryRow(
			`SELECT client_id, user_id, scope, expires_at, revoked FROM oidc_refresh_tokens WHERE token = ?`,
			refreshToken,
		).Scan(&storedClientID, &userID, &scope, &expiresAt, &revoked)
	}
	if err != nil || storedClientID != clientID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	effFamily := strings.TrimSpace(familyID)
	if effFamily == "" {
		effFamily = refreshToken
	}

	if revoked {
		slog.Warn("OIDC: refresh token reuse detected; revoking token family", "client_id", clientID, "user_id", userID)
		_, _ = tx.Exec(
			"UPDATE oidc_refresh_tokens SET revoked = 1 WHERE client_id = ? AND (family_id = ? OR token = ?)",
			clientID, effFamily, refreshToken,
		)
		_ = tx.Commit()
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "token already consumed"})
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

	var clientExists int
	if err := tx.QueryRow("SELECT 1 FROM oidc_clients WHERE id = ?", clientID).Scan(&clientExists); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	if _, subErr := loadActiveHumanSubject(tx, userID); subErr != nil {
		if errors.Is(subErr, errSubjectSuspended) {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid_grant", "error_description": "account suspended"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}

	result, execErr := tx.Exec("UPDATE oidc_refresh_tokens SET revoked = 1 WHERE token = ? AND revoked = 0", refreshToken)
	if execErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		slog.Warn("OIDC: concurrent refresh token replay detected; revoking family", "client_id", clientID)
		_, _ = tx.Exec(
			"UPDATE oidc_refresh_tokens SET revoked = 1 WHERE client_id = ? AND (family_id = ? OR token = ?)",
			clientID, effFamily, refreshToken,
		)
		_ = tx.Commit()
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "token already consumed"})
		return
	}

	payload, issueErr := prepareOIDCTokenPayload(c, tx, clientID, userID, scope, "", effFamily)
	if issueErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	if commitErr := tx.Commit(); commitErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, payload)
}

type oidcDBExecer interface {
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
}

func hasOIDCScope(scopeStr, target string) bool {
	for _, s := range strings.Fields(scopeStr) {
		if s == target {
			return true
		}
	}
	return false
}

func prepareOIDCTokenPayload(c *gin.Context, execer oidcDBExecer, clientID string, userID int, scope, nonce, familyID string) (gin.H, error) {
	if oidcPrivateKey == nil {
		return nil, fmt.Errorf("OIDC private key is uninitialized")
	}

	subj, subErr := loadActiveHumanSubject(execer, userID)
	if subErr != nil {
		return nil, subErr
	}

	issuer := getOIDCIssuer(c)

	// Fetch user info
	var username, email, avatarURL, role string
	if err := execer.QueryRow("SELECT username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user') FROM users WHERE id = ?", userID).
		Scan(&username, &email, &avatarURL, &role); err != nil {
		slog.Error("OIDC: failed to fetch user info during token issuance", "user_id", userID, "error", err)
		return nil, err
	}

	now := time.Now().UTC()

	// ID Token (short-lived, 1 hour) with scope-gated claims and optional nonce
	idTokenClaims := jwt.MapClaims{
		"iss": issuer,
		"sub": fmt.Sprintf("%d", userID),
		"aud": clientID,
		"exp": now.Add(1 * time.Hour).Unix(),
		"iat": now.Unix(),
		"ver": subj.sessionsRevokedAfter,
	}
	if nonce != "" {
		idTokenClaims["nonce"] = nonce
	}
	if hasOIDCScope(scope, "profile") {
		idTokenClaims["name"] = username
		idTokenClaims["picture"] = avatarURL
		idTokenClaims["role"] = role
	}
	if hasOIDCScope(scope, "email") {
		idTokenClaims["email"] = email
	}

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
	idToken.Header["kid"] = oidcKeyID
	idTokenString, err := idToken.SignedString(oidcPrivateKey)
	if err != nil {
		slog.Error("OIDC: failed to sign id_token", "error", err)
		return nil, err
	}

	// Access Token (short-lived, 1 hour, revocable via jti + ver)
	accessJTI := uuid.New().String()
	accessTokenClaims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   fmt.Sprintf("%d", userID),
		"aud":   clientID,
		"exp":   now.Add(1 * time.Hour).Unix(),
		"iat":   now.Unix(),
		"jti":   accessJTI,
		"ver":   subj.sessionsRevokedAfter,
		"scope": scope,
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessTokenClaims)
	accessToken.Header["kid"] = oidcKeyID
	accessTokenString, err := accessToken.SignedString(oidcPrivateKey)
	if err != nil {
		slog.Error("OIDC: failed to sign access_token", "error", err)
		return nil, err
	}

	// Refresh Token (long-lived, 30 days, family-bound)
	refreshBytes := make([]byte, 32)
	if _, err := rand.Read(refreshBytes); err != nil {
		slog.Error("crypto/rand failure during OIDC refresh token generation", "error", err)
		return nil, err
	}
	refreshToken := hex.EncodeToString(refreshBytes)
	effFamily := strings.TrimSpace(familyID)
	if effFamily == "" {
		effFamily = refreshToken
	}
	refreshExpires := now.Add(30 * 24 * time.Hour).Format(time.RFC3339)

	_, err = execer.Exec(
		`INSERT INTO oidc_refresh_tokens (token, client_id, user_id, scope, expires_at, family_id) VALUES (?, ?, ?, ?, ?, ?)`,
		refreshToken, clientID, userID, scope, refreshExpires, effFamily,
	)
	if err != nil && strings.Contains(err.Error(), "no such column") {
		_, err = execer.Exec(
			`INSERT INTO oidc_refresh_tokens (token, client_id, user_id, scope, expires_at) VALUES (?, ?, ?, ?, ?)`,
			refreshToken, clientID, userID, scope, refreshExpires,
		)
	}
	if err != nil {
		slog.Error("OIDC: failed to persist refresh token", "client_id", clientID, "error", err)
		return nil, err
	}

	return gin.H{
		"access_token":  accessTokenString,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
		"id_token":      idTokenString,
		"scope":         scope,
	}, nil
}

// ---- UserInfo ----

// OIDCUserInfo returns standard OIDC claims for the authenticated user.
func OIDCUserInfo(c *gin.Context) {
	if oidcPrivateKey == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

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

	tokenIss, _ := claims["iss"].(string)
	if !isAcceptedOIDCIssuer(c, tokenIss) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "invalid issuer"})
		return
	}

	jti, _ := claims["jti"].(string)
	jti = strings.TrimSpace(jti)
	if jti == "" || db.IsTokenRevoked(jti) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "token revoked"})
		return
	}

	aud, _ := claims["aud"].(string)
	aud = strings.TrimSpace(aud)
	if aud == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	var clientExists int
	if err := db.DB.QueryRow("SELECT 1 FROM oidc_clients WHERE id = ?", aud).Scan(&clientExists); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "client revoked"})
		return
	}

	sub, _ := claims["sub"].(string)
	subID, subConvErr := strconv.Atoi(sub)
	if subConvErr != nil || subID <= 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	subj, subErr := loadActiveHumanSubject(db.DB, subID)
	if subErr != nil {
		if errors.Is(subErr, errSubjectSuspended) {
			c.JSON(http.StatusForbidden, gin.H{"error": "access_denied", "error_description": "account suspended"})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "user not found"})
		return
	}
	if claimVersion(claims) < subj.sessionsRevokedAfter {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "credentials rotated"})
		return
	}

	scope, _ := claims["scope"].(string)
	if !hasOIDCScope(scope, "openid") {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "insufficient_scope",
			"error_description": "openid scope required",
		})
		return
	}
	var username, email, avatarURL, role string
	if err := db.DB.QueryRow("SELECT username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user') FROM users WHERE id = ?", subID).
		Scan(&username, &email, &avatarURL, &role); err != nil {
		slog.Error("OIDC: failed to fetch user info during userinfo request", "sub", sub, "error", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "user not found"})
		return
	}

	resp := gin.H{
		"sub": sub,
	}
	if hasOIDCScope(scope, "profile") {
		resp["name"] = username
		resp["picture"] = avatarURL
		resp["role"] = role
	}
	if hasOIDCScope(scope, "email") {
		resp["email"] = email
	}
	c.JSON(http.StatusOK, resp)
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
	err := db.DB.QueryRow("SELECT COALESCE(client_secret_hash, '') FROM oidc_clients WHERE id = ?", clientID).Scan(&storedSecretHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	if strings.TrimSpace(storedSecretHash) == "" {
		if clientSecret != "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
	} else {
		secretHash := sha256.Sum256([]byte(clientSecret))
		computed := hex.EncodeToString(secretHash[:])
		if subtle.ConstantTimeCompare([]byte(computed), []byte(storedSecretHash)) != 1 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
	}

	token := strings.TrimSpace(c.PostForm("token"))
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	// Revoke RS256 access tokens by JTI when presented by their audience client.
	if oidcPrivateKey != nil {
		if parsed, pErr := jwt.Parse(token, func(tok *jwt.Token) (interface{}, error) {
			if _, ok := tok.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", tok.Header["alg"])
			}
			return &oidcPrivateKey.PublicKey, nil
		}); pErr == nil && parsed != nil && parsed.Valid {
			if claims, ok := parsed.Claims.(jwt.MapClaims); ok {
				aud, _ := claims["aud"].(string)
				jti, _ := claims["jti"].(string)
				jti = strings.TrimSpace(jti)
				if aud == clientID && jti != "" {
					ttl := 1 * time.Hour
					if expUnix, hasExp := claimInt64(claims, "exp"); hasExp {
						if rem := time.Until(time.Unix(expUnix, 0)); rem > 0 {
							ttl = rem + time.Minute
						}
					}
					if err := db.RevokeToken(jti, ttl); err != nil {
						slog.Error("OIDC: failed to revoke access token JTI", "client_id", clientID, "error", err)
						c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
						return
					}
				}
			}
		}
	}

	// Revoke matching refresh token (and its entire token family).
	var familyID string
	fErr := db.DB.QueryRow(
		"SELECT COALESCE(family_id, '') FROM oidc_refresh_tokens WHERE token = ? AND client_id = ?",
		token, clientID,
	).Scan(&familyID)
	if fErr == nil {
		effFamily := strings.TrimSpace(familyID)
		if effFamily == "" {
			effFamily = token
		}
		if _, err := db.DB.Exec(
			"UPDATE oidc_refresh_tokens SET revoked = 1 WHERE client_id = ? AND (family_id = ? OR token = ?)",
			clientID, effFamily, token,
		); err != nil {
			slog.Error("OIDC: failed to revoke refresh token family", "client_id", clientID, "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
	} else if !errors.Is(fErr, sql.ErrNoRows) {
		if _, err := db.DB.Exec("UPDATE oidc_refresh_tokens SET revoked = 1 WHERE token = ? AND client_id = ?", token, clientID); err != nil {
			slog.Error("OIDC: failed to revoke refresh token", "client_id", clientID, "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
	}
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
	err := db.DB.QueryRow("SELECT COALESCE(client_secret_hash, '') FROM oidc_clients WHERE id = ?", clientID).Scan(&storedSecretHash)
	if err != nil || strings.TrimSpace(storedSecretHash) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	secretHash := sha256.Sum256([]byte(clientSecret))
	computed := hex.EncodeToString(secretHash[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(storedSecretHash)) != 1 {
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
		if result := introspectAccessToken(c, tokenStr, clientID); result != nil {
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
func introspectAccessToken(c *gin.Context, tokenStr, clientID string) gin.H {
	if oidcPrivateKey == nil {
		return nil
	}

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

	iss, _ := claims["iss"].(string)
	if !isAcceptedOIDCIssuer(c, iss) {
		return nil
	}

	// Verify the token was issued for this client and the client still exists
	aud, _ := claims["aud"].(string)
	if aud != clientID {
		return nil
	}
	var clientExists int
	if err := db.DB.QueryRow("SELECT 1 FROM oidc_clients WHERE id = ?", clientID).Scan(&clientExists); err != nil {
		return nil
	}

	jti, _ := claims["jti"].(string)
	jti = strings.TrimSpace(jti)
	if jti == "" || db.IsTokenRevoked(jti) {
		return nil
	}

	sub, _ := claims["sub"].(string)
	subID, convErr := strconv.Atoi(sub)
	if convErr != nil || subID <= 0 {
		return nil
	}
	subj, subErr := loadActiveHumanSubject(db.DB, subID)
	if subErr != nil {
		return nil
	}
	if claimVersion(claims) < subj.sessionsRevokedAfter {
		return nil
	}
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
	var clientExists int
	if err := db.DB.QueryRow("SELECT 1 FROM oidc_clients WHERE id = ?", clientID).Scan(&clientExists); err != nil {
		return gin.H{"active": false}
	}

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

	// Check expiration (fail closed on malformed timestamps)
	expTime, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || time.Now().After(expTime) {
		return gin.H{"active": false}
	}

	if _, subErr := loadActiveHumanSubject(db.DB, userID); subErr != nil {
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

func isSafeRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.User != nil || u.Host == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return true
	case "http":
		h := strings.ToLower(u.Hostname())
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	default:
		return false
	}
}

// isAllowedRedirectURI checks if the redirect_uri is safe and registered for the client.
func isAllowedRedirectURI(uri, storedURIs string) bool {
	if !isSafeRedirectURI(uri) {
		return false
	}
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

// verifyPKCE validates the PKCE code_verifier against the stored S256 challenge per RFC 7636.
func verifyPKCE(verifier, challenge, method string) bool {
	if method != "S256" || !isValidPKCEVerifier(verifier) || !isValidPKCEChallenge(challenge) {
		return false
	}
	hash := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func createSessionJWTInTx(execer oidcDBExecer, userID int, c *gin.Context, authTime int64, familyID string, credentialVer int64) (string, string, error) {
	now := time.Now().UTC()
	nowUnix := now.Unix()
	if authTime <= 0 {
		authTime = nowUnix
	}
	absExp := authTime + sessionAbsoluteLifetimeSecs
	if absExp <= nowUnix {
		return "", "", fmt.Errorf("absolute session lifetime exceeded")
	}
	expUnix := nowUnix + int64((15 * time.Minute).Seconds())
	if expUnix > absExp {
		expUnix = absExp
	}

	jti := uuid.New().String()
	effFamily := strings.TrimSpace(familyID)
	if effFamily == "" {
		effFamily = jti
	}
	fp := clientFingerprint(c)

	claims := jwt.MapClaims{
		"user_id":   userID,
		"sub":       fmt.Sprintf("%d", userID),
		"iss":       "aetherflow",
		"iat":       nowUnix,
		"auth_time": authTime,
		"exp":       expUnix,
		"jti":       jti,
		"cfp":       fp,
		"ver":       credentialVer,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(getJWTSecret())
	if err != nil {
		return "", "", err
	}

	if execer != nil {
		ua := c.Request.UserAgent()
		ip := c.ClientIP()
		retainUnix := expUnix + 7200
		if retainUnix > absExp {
			retainUnix = absExp
		}
		expiresAt := time.Unix(retainUnix, 0).UTC().Format(time.RFC3339)

		_, insErr := execer.Exec(
			`INSERT OR REPLACE INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at, last_active, family_id)
			 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)`,
			jti, userID, ip, ua, expiresAt, effFamily,
		)
		if insErr != nil && strings.Contains(insErr.Error(), "no such column") {
			_, insErr = execer.Exec(
				`INSERT OR REPLACE INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at, last_active)
				 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
				jti, userID, ip, ua, expiresAt,
			)
		}
		if insErr != nil {
			slog.Warn("session tracking: failed to record session", "error", insErr)
		}
	}

	return tokenString, jti, nil
}

// createStandardJWT creates a JWT with a unique jti, short-lived expiry, 30-day absolute
// lifetime ceiling, credential epoch version, and client fingerprint binding.
func createStandardJWT(userID int, c *gin.Context) (string, error) {
	var credentialVer int64
	var execer oidcDBExecer
	if db.DB != nil {
		execer = db.DB
		_ = db.DB.QueryRow("SELECT COALESCE(sessions_revoked_after, 0) FROM users WHERE id = ?", userID).Scan(&credentialVer)
	}
	tokenString, _, err := createSessionJWTInTx(execer, userID, c, time.Now().UTC().Unix(), "", credentialVer)
	return tokenString, err
}

// clientFingerprint produces a deterministic fingerprint of the client's User-Agent.
// Binding to User-Agent (instead of ClientIP + User-Agent) prevents false
// SESSION_HIJACKED errors when browsers rotate IPv4/IPv6 connections (Happy Eyeballs)
// or transition across reverse-proxy / CGNAT sockets after HTTP keep-alive idle timeouts.
func clientFingerprint(c *gin.Context) string {
	raw := strings.TrimSpace(c.Request.UserAgent())
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// legacyClientFingerprint computes the legacy IP + User-Agent hash so in-flight
// tokens issued prior to the User-Agent-only binding continue to validate cleanly.
func legacyClientFingerprint(c *gin.Context) string {
	raw := c.ClientIP() + "|" + c.Request.UserAgent()
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// matchesClientFingerprint checks whether a token's cfp claim matches the current client.
func matchesClientFingerprint(cfp string, c *gin.Context) bool {
	if cfp == "" {
		return true
	}
	return cfp == clientFingerprint(c) || cfp == legacyClientFingerprint(c)
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
	scope := validateOIDCScopes(c.PostForm("scope"))

	var storedSecretHash string
	err := db.DB.QueryRow("SELECT COALESCE(client_secret_hash, '') FROM oidc_clients WHERE id = ?", clientID).Scan(&storedSecretHash)
	if err != nil || strings.TrimSpace(storedSecretHash) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	deviceCodeBytes := make([]byte, 32)
	if _, err := rand.Read(deviceCodeBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	deviceCode := hex.EncodeToString(deviceCodeBytes)
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)

	var userCode string
	var insErr error
	for attempt := 0; attempt < 8; attempt++ {
		userCode = generateUserCode()
		_, insErr = db.DB.Exec(
			"INSERT INTO oidc_device_codes (device_code, user_code, client_id, scope, expires_at, status) VALUES (?, ?, ?, ?, ?, 'pending')",
			deviceCode, userCode, clientID, scope, expiresAt,
		)
		if insErr == nil {
			break
		}
		if !strings.Contains(strings.ToLower(insErr.Error()), "unique") {
			break
		}
	}
	if insErr != nil {
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
		tx, txErr := db.DB.Begin()
		if txErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		res, delErr := tx.Exec(
			"DELETE FROM oidc_device_codes WHERE device_code = ? AND client_id = ? AND status = 'approved'",
			deviceCode, clientID,
		)
		if delErr != nil {
			_ = tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		affected, _ := res.RowsAffected()
		if affected == 0 {
			_ = tx.Rollback()
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
			return
		}
		if _, subErr := loadActiveHumanSubject(tx, int(userIDErr.Int64)); subErr != nil {
			_ = tx.Rollback()
			if errors.Is(subErr, errSubjectSuspended) {
				c.JSON(http.StatusForbidden, gin.H{"error": "access_denied", "error_description": "account suspended"})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
			return
		}
		payload, issueErr := prepareOIDCTokenPayload(c, tx, clientID, int(userIDErr.Int64), validateOIDCScopes(scope), "", "")
		if issueErr != nil {
			_ = tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		if commitErr := tx.Commit(); commitErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		c.JSON(http.StatusOK, payload)
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

	userCode := strings.ToUpper(strings.TrimSpace(req.UserCode))
	var status, scope, clientID, expiresAt string
	err := db.DB.QueryRow(
		"SELECT status, scope, client_id, expires_at FROM oidc_device_codes WHERE user_code = ?",
		userCode,
	).Scan(&status, &scope, &clientID, &expiresAt)
	if err != nil || status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_user_code"})
		return
	}
	expTime, parseErr := time.Parse(time.RFC3339, expiresAt)
	if parseErr != nil || time.Now().After(expTime) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_user_code"})
		return
	}

	var name string
	if err := db.DB.QueryRow("SELECT name FROM oidc_clients WHERE id = ?", clientID).Scan(&name); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_user_code"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":      status,
		"scope":       scope,
		"client_id":   clientID,
		"client_name": name,
	})
}

func OIDCDeviceConsent(c *gin.Context) {
	userId, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	callerID := userId.(int)
	if _, subErr := loadActiveHumanSubject(db.DB, callerID); subErr != nil {
		if errors.Is(subErr, errSubjectSuspended) {
			c.JSON(http.StatusForbidden, gin.H{"error": "access_denied", "error_description": "Account is not active"})
			return
		}
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

	userCode := strings.ToUpper(strings.TrimSpace(req.UserCode))
	status := "denied"
	if req.Approved {
		status = "approved"
	}

	tx, txErr := db.DB.Begin()
	if txErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	rows, qErr := tx.Query(
		"SELECT device_code, client_id, expires_at FROM oidc_device_codes WHERE user_code = ? AND status = 'pending' LIMIT 2",
		userCode,
	)
	if qErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	var validDeviceCodes []string
	var targetClientID string
	now := time.Now()
	for rows.Next() {
		var dc, cid, expStr string
		if rows.Scan(&dc, &cid, &expStr) == nil {
			if expTime, pErr := time.Parse(time.RFC3339, expStr); pErr == nil && !now.After(expTime) {
				validDeviceCodes = append(validDeviceCodes, dc)
				targetClientID = cid
			}
		}
	}
	_ = rows.Close()

	if len(validDeviceCodes) != 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_user_code"})
		return
	}
	var clientExists int
	if err := tx.QueryRow("SELECT 1 FROM oidc_clients WHERE id = ?", targetClientID).Scan(&clientExists); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_user_code"})
		return
	}

	res, err := tx.Exec(
		"UPDATE oidc_device_codes SET status = ?, user_id = ? WHERE device_code = ? AND status = 'pending'",
		status, callerID, validDeviceCodes[0],
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	affected, _ := res.RowsAffected()
	if affected != 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_user_code"})
		return
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
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
func generateAndStoreAuthCode(clientID string, userID int, redirectURI, scope, nonce, codeChallenge, codeChallengeMethod string) (string, error) {
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return "", fmt.Errorf("crypto/rand failure: %w", err)
	}
	code := hex.EncodeToString(codeBytes)

	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	_, err := db.DB.Exec(
		`INSERT INTO oidc_auth_codes (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		code, clientID, userID, redirectURI, scope, nonce, codeChallenge, codeChallengeMethod, expiresAt.Format(time.RFC3339),
	)
	if err != nil {
		return "", err
	}
	return code, nil
}
