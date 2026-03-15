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
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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
		keyPath = "data/oidc_rsa.pem"
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
				log.Printf("OIDC: loaded RSA key from %s (kid: %s)", keyPath, oidcKeyID)
				return
			}
		}
	}

	// Generate new key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("OIDC: failed to generate RSA key: %v", err)
		return
	}

	oidcPrivateKey = key
	oidcKeyID = computeKeyID(key)

	// Persist to disk
	os.MkdirAll("data", 0700)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		log.Printf("OIDC: failed to persist RSA key: %v", err)
	} else {
		log.Printf("OIDC: generated new RSA key at %s (kid: %s)", keyPath, oidcKeyID)
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
		"authorization_endpoint": issuer + "/api/v1/oidc/authorize",
		"token_endpoint":         issuer + "/api/v1/oidc/token",
		"userinfo_endpoint":      issuer + "/api/v1/oidc/userinfo",
		"jwks_uri":               issuer + "/api/v1/oidc/jwks",
		"revocation_endpoint":    issuer + "/api/v1/oidc/revoke",
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
		// Redirect to login with a return-to parameter
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("/login?return_to=%s", c.Request.URL.String()))
		return
	}

	userID, err := extractUserIDFromJWT(cookie)
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("/login?return_to=%s", c.Request.URL.String()))
		return
	}

	// Generate authorization code
	codeBytes := make([]byte, 32)
	rand.Read(codeBytes)
	code := hex.EncodeToString(codeBytes)

	if scope == "" {
		scope = "openid profile email"
	}

	expiresAt := time.Now().Add(10 * time.Minute)

	_, err = db.DB.Exec(
		`INSERT INTO oidc_auth_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		code, clientID, userID, redirectURI, scope, codeChallenge, codeChallengeMethod, expiresAt.Format(time.RFC3339),
	)
	if err != nil {
		log.Printf("OIDC: failed to store auth code: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Redirect back with code
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	redirectURL := fmt.Sprintf("%s%scode=%s", redirectURI, sep, code)
	if state != "" {
		redirectURL += "&state=" + state
	}

	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
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
	expTime, _ := time.Parse(time.RFC3339, expiresAt)
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

	// Mark code as used
	db.DB.Exec("UPDATE oidc_auth_codes SET used = 1 WHERE code = ?", code)

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

	expTime, _ := time.Parse(time.RFC3339, expiresAt)
	if time.Now().After(expTime) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "refresh token expired"})
		return
	}

	// Revoke old refresh token
	db.DB.Exec("UPDATE oidc_refresh_tokens SET revoked = 1 WHERE token = ?", refreshToken)

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
	db.DB.QueryRow("SELECT username, email, avatar_url, role FROM users WHERE id = ?", userID).
		Scan(&username, &email, &avatarURL, &role)

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
		log.Printf("OIDC: failed to sign id_token: %v", err)
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
		log.Printf("OIDC: failed to sign access_token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Refresh Token (long-lived, 30 days)
	refreshBytes := make([]byte, 32)
	rand.Read(refreshBytes)
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
	db.DB.QueryRow("SELECT username, email, avatar_url, role FROM users WHERE id = ?", sub).
		Scan(&username, &email, &avatarURL, &role)

	c.JSON(http.StatusOK, gin.H{
		"sub":     sub,
		"name":    username,
		"email":   email,
		"picture": avatarURL,
		"role":    role,
	})
}

// ---- Token Revocation ----

// OIDCRevoke revokes a refresh token.
func OIDCRevoke(c *gin.Context) {
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	db.DB.Exec("UPDATE oidc_refresh_tokens SET revoked = 1 WHERE token = ?", token)
	c.JSON(http.StatusOK, gin.H{}) // RFC 7009: 200 even if token doesn't exist
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

// createStandardJWT creates a JWT with OIDC-standard claims (used internally).
// This refactors the duplicated JWT creation pattern throughout auth.go.
func createStandardJWT(userID int) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"sub":     fmt.Sprintf("%d", userID),
		"iss":     "aetherflow",
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(time.Hour * 24 * 30).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(getJWTSecret())
}

// ---- Placeholder for consent page ----
// In a production deployment, OIDCAuthorize should render a consent page
// that shows the requesting application and requested scopes.
// For now, we auto-approve since AetherFlow is the identity provider.
// This can be expanded with a frontend consent component.

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
