package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"aetherflow/db"
	"aetherflow/models"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret []byte
var jwtSecretOnce sync.Once
var errUnauthorizedSession = errors.New("unauthorized session")

// rotatedTokenGrace tracks recently rotated JTIs for a 15-second overlap window
// so concurrent in-flight requests or multi-tab refresh races do not trigger
// false 401 logouts while db.IsTokenRevoked(jti) still reflects revocation.
const rotatedTokenGraceWindow = 15 * time.Second

type rotatedTokenGraceEntry struct {
	userID    int
	newToken  string
	expiresAt time.Time
}

var rotatedTokenGrace sync.Map

func isWithinRotationGrace(jti string) (rotatedTokenGraceEntry, bool) {
	if jti == "" {
		return rotatedTokenGraceEntry{}, false
	}
	raw, ok := rotatedTokenGrace.Load(jti)
	if !ok {
		return rotatedTokenGraceEntry{}, false
	}
	entry, ok := raw.(rotatedTokenGraceEntry)
	if !ok || time.Now().After(entry.expiresAt) {
		rotatedTokenGrace.Delete(jti)
		return rotatedTokenGraceEntry{}, false
	}
	return entry, true
}

func getJWTSecret() []byte {
	jwtSecretOnce.Do(func() {
		jwtSecret = []byte(os.Getenv("JWT_SECRET"))
		if len(jwtSecret) == 0 {
			log.Fatal("FATAL: JWT_SECRET environment variable is not set. Refusing to start with an insecure default.")
		}
	})
	return jwtSecret
}

// sessionCookieMaxAge defines the browser Max-Age (in seconds) for the aetherflow_session
// cookie. This must exceed the 15-minute JWT lifetime so the browser still sends the
// cookie to /api/v1/auth/refresh during the 2-hour silent refresh grace window.
const sessionCookieMaxAge = 86400

// secureCookie returns whether cookies should have the Secure flag set.
// Defaults to true (HTTPS-only). Set COOKIE_SECURE=false in env for local HTTP dev.
func secureCookie() bool {
	return strings.ToLower(os.Getenv("COOKIE_SECURE")) != "false"
}

// SetupAdmin godoc
// @Summary      Create initial admin
// @Description  Creates the initial admin account. Fails if any user already exists.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        req body object true "Username and Password"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}
// @Failure      409  {object}  map[string]interface{}
// @Failure      500  {object}  map[string]interface{}
// @Router       /auth/setup [post]
func SetupAdmin(c *gin.Context) {
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		slog.Error("failed to query user count during admin setup", "error", err)
		RespondError(c, http.StatusInternalServerError, ErrCodeInternal, "Database unavailable")
		return
	}
	if count > 0 {
		RespondError(c, http.StatusConflict, ErrCodeConflict, "Admin account already exists")
		return
	}

	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, err.Error())
		return
	}

	// Enforce minimum password length for security
	if len(req.Password) < 8 {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, "Password must be at least 8 characters")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		RespondError(c, http.StatusInternalServerError, ErrCodeInternal, "Failed to hash password")
		return
	}

	res, err := db.DB.Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
		req.Username, string(hash),
	)
	if err != nil {
		slog.Error("setup admin creation error", "error", err)
		RespondError(c, http.StatusInternalServerError, ErrCodeInternal, "Failed to create admin account")
		return
	}

	id, err := res.LastInsertId()
	if err != nil || id == 0 {
		slog.Error("failed to retrieve LastInsertId during admin creation", "error", err)
		RespondError(c, http.StatusInternalServerError, ErrCodeInternal, "Failed to verify new user creation")
		return
	}

	services.SaveMasterCredentials(req.Username, req.Password)

	// Issue JWT via centralized factory (includes jti + short expiry + client fingerprint)
	tokenString, err := createStandardJWT(int(id), c)
	if err != nil {
		RespondError(c, http.StatusInternalServerError, ErrCodeInternal, "Failed to create session")
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("aetherflow_session", tokenString, sessionCookieMaxAge, "/", "", secureCookie(), true)

	c.JSON(http.StatusOK, gin.H{"message": "Admin account created", "username": req.Username})
}

// LocalLogin godoc
// @Summary      Login
// @Description  Authentates a user via username and password.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        req body object true "Username and Password"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]interface{}
// @Router       /auth/login [post]
func LocalLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, err.Error())
		return
	}

	var user models.User
	var passwordHash string
	var googleId sql.NullString
	var totpEnabled bool
	err := db.DB.QueryRow(
		"SELECT id, username, email, avatar_url, role, COALESCE(password_hash, ''), google_id, COALESCE(totp_enabled, 0) FROM users WHERE username = ?",
		req.Username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.AvatarURL, &user.Role, &passwordHash, &googleId, &totpEnabled)

	user.IsOAuth = googleId.Valid && googleId.String != ""

	if err != nil {
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "Invalid username or password")
		return
	}

	if passwordHash == "" {
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "This account uses Google OAuth. Use the Google login button.")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "Invalid username or password")
		return
	}

	// ── 2FA Gate ──
	// If the user has TOTP enabled, do NOT issue a session yet.
	// Instead, return a challenge token that must be verified with a TOTP code.
	if totpEnabled {
		mfaToken := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, mfaToken); err != nil {
			InternalError(c, "Failed to generate MFA challenge")
			return
		}
		token := hex.EncodeToString(mfaToken)

		if err := db.StoreMFAChallenge(token, user.ID, 5*time.Minute); err != nil {
			InternalError(c, "Failed to store MFA challenge")
			return
		}

		slog.Info("MFA challenge issued", "user_id", user.ID, "username", user.Username)
		c.JSON(http.StatusOK, gin.H{
			"requires_mfa": true,
			"mfa_token":    token,
		})
		return
	}

	// ── Standard login (no 2FA) ──
	// Log login
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()
	db.DB.Exec("INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?, ?, ?)", user.ID, clientIP, userAgent)

	// Issue JWT via centralized factory (includes jti + short expiry + client fingerprint)
	tokenString, err := createStandardJWT(user.ID, c)
	if err != nil {
		InternalError(c, "Failed to create session")
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("aetherflow_session", tokenString, sessionCookieMaxAge, "/", "", secureCookie(), true)
	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "user": user})
}

// checkSetupNeeded is the pure logic function; returns (needed, error).
func checkSetupNeeded() (bool, error) {
	var count int
	err := db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		slog.Error("failed to query user count during setup check", "error", err)
		return false, fmt.Errorf("database unavailable: %w", err)
	}
	return count == 0, nil
}

// CheckSetupNeeded godoc
// @Summary      Check setup status
// @Description  Returns whether initial admin setup is required.
// @Tags         auth
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Failure      500  {object}  map[string]interface{}
// @Router       /auth/setup/check [get]
func CheckSetupNeeded(c *gin.Context) {
	needed, err := checkSetupNeeded()
	if err != nil {
		InternalError(c, "Failed to verify setup state")
		return
	}
	c.JSON(http.StatusOK, gin.H{"setupRequired": needed})
}

func GoogleLogin(c *gin.Context) {
	clientId := os.Getenv("GOOGLE_CLIENT_ID")
	redirectUri := os.Getenv("GOOGLE_REDIRECT_URI")

	if clientId == "" || redirectUri == "" {
		InternalError(c, "OAuth not configured")
		return
	}

	// Generate state
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		slog.Error("crypto/rand failure during OAuth state generation", "error", err)
		InternalError(c, "Failed to generate secure state")
		return
	}
	state := hex.EncodeToString(stateBytes)

	// Set state cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("oauth2_state", state, 600, "/", "", secureCookie(), true)

	scopes := []string{"openid", "email", "profile"}
	params := url.Values{}
	params.Set("client_id", clientId)
	params.Set("redirect_uri", redirectUri)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(scopes, " "))
	params.Set("state", state)
	params.Set("access_type", "offline")
	params.Set("prompt", "consent")
	authUrl := "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()

	c.Redirect(http.StatusTemporaryRedirect, authUrl)
}

const minRevocationTTL = 136 * time.Minute

func revocationTTLForClaims(claims jwt.MapClaims) time.Duration {
	ttl := minRevocationTTL
	if expVal, ok := claims["exp"].(float64); ok {
		if covered := time.Until(time.Unix(int64(expVal), 0)) + 2*time.Hour + time.Minute; covered > ttl {
			ttl = covered
		}
	}
	return ttl
}

func clearOAuthStateCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("oauth2_state", "", -1, "/", "", secureCookie(), true)
}

func resolveGoogleOAuthUser(googleId, email, name, avatarUrl string) (userID int, totpEnabled bool, authorized bool, err error) {
	googleId = strings.TrimSpace(googleId)
	email = strings.TrimSpace(email)
	if googleId == "" || email == "" {
		return 0, false, false, nil
	}

	tx, err := db.DB.Begin()
	if err != nil {
		return 0, false, false, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	err = tx.QueryRow(
		"SELECT id, COALESCE(totp_enabled, 0) FROM users WHERE google_id = ?",
		googleId,
	).Scan(&userID, &totpEnabled)
	if err == nil {
		if _, updErr := tx.Exec("UPDATE users SET avatar_url = ? WHERE id = ?", avatarUrl, userID); updErr != nil {
			return 0, false, false, updErr
		}
		if err := tx.Commit(); err != nil {
			return 0, false, false, err
		}
		return userID, totpEnabled, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, false, false, err
	}

	var matches int
	if err := tx.QueryRow("SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER(?)", email).Scan(&matches); err != nil {
		return 0, false, false, err
	}
	if matches > 1 {
		return 0, false, false, nil
	}
	if matches == 1 {
		var linkedGoogleID string
		if err := tx.QueryRow(
			"SELECT id, COALESCE(google_id, ''), COALESCE(totp_enabled, 0) FROM users WHERE LOWER(email) = LOWER(?)",
			email,
		).Scan(&userID, &linkedGoogleID, &totpEnabled); err != nil {
			return 0, false, false, err
		}
		if strings.TrimSpace(linkedGoogleID) != "" {
			return 0, false, false, nil
		}
		res, updErr := tx.Exec(
			"UPDATE users SET google_id = ?, avatar_url = ? WHERE id = ? AND COALESCE(google_id, '') = ''",
			googleId, avatarUrl, userID,
		)
		if updErr != nil {
			return 0, false, false, updErr
		}
		affected, _ := res.RowsAffected()
		if affected != 1 {
			return 0, false, false, nil
		}
		if err := tx.Commit(); err != nil {
			return 0, false, false, err
		}
		return userID, totpEnabled, true, nil
	}

	if !isGoogleEmailAllowedForProvision(email) {
		return 0, false, false, nil
	}

	rawPrefix := name
	if i := strings.Index(email, "@"); i != -1 {
		rawPrefix = email[:i]
	}
	prefix := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-' {
			return r
		}
		return -1
	}, rawPrefix)
	if len(prefix) > 48 {
		prefix = prefix[:48]
	}
	if prefix == "" {
		prefix = "user"
	}
	suffixBytes := make([]byte, 4)
	if _, randErr := io.ReadFull(rand.Reader, suffixBytes); randErr != nil {
		return 0, false, false, randErr
	}
	username := prefix + "-" + hex.EncodeToString(suffixBytes)

	role := "user"
	if adminEmail := strings.TrimSpace(os.Getenv("ADMIN_EMAIL")); adminEmail != "" && strings.EqualFold(email, adminEmail) {
		role = "admin"
	}

	res, err := tx.Exec(
		"INSERT INTO users (username, google_id, email, avatar_url, role) VALUES (?, ?, ?, ?, ?)",
		username, googleId, email, avatarUrl, role,
	)
	if err != nil {
		return 0, false, false, err
	}
	insertedID, err := res.LastInsertId()
	if err != nil {
		return 0, false, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, false, err
	}
	return int(insertedID), false, true, nil
}

func isGoogleEmailAllowedForProvision(email string) bool {
	allowedEmailsRaw := strings.TrimSpace(os.Getenv("AETHERFLOW_GOOGLE_ALLOWED_EMAILS"))
	allowedDomainsRaw := strings.TrimSpace(os.Getenv("AETHERFLOW_GOOGLE_ALLOWED_DOMAINS"))
	if allowedEmailsRaw == "" && allowedDomainsRaw == "" {
		return false
	}

	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	if normalizedEmail == "" {
		return false
	}
	parts := strings.SplitN(normalizedEmail, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.Contains(parts[1], "@") {
		return false
	}
	domain := parts[1]

	for _, entry := range strings.Split(allowedEmailsRaw, ",") {
		if candidate := strings.ToLower(strings.TrimSpace(entry)); candidate != "" && candidate == normalizedEmail {
			return true
		}
	}

	for _, entry := range strings.Split(allowedDomainsRaw, ",") {
		candidate := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(entry)), "@")
		if candidate != "" && domain == candidate {
			return true
		}
	}

	return false
}

func isConfiguredTrustedProxyIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if raw := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES")); raw != "" {
		for _, item := range strings.Split(raw, ",") {
			token := strings.TrimSpace(item)
			if token == "" {
				continue
			}
			if _, network, err := net.ParseCIDR(token); err == nil {
				if network.Contains(ip) {
					return true
				}
				continue
			}
			if parsed := net.ParseIP(strings.Trim(token, "[]")); parsed != nil && parsed.Equal(ip) {
				return true
			}
		}
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func isTrustedProxyPeer(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	remoteAddr := strings.TrimSpace(c.Request.RemoteAddr)
	if remoteAddr == "" {
		return false
	}
	host := remoteAddr
	if splitHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = splitHost
	} else if strings.HasPrefix(remoteAddr, "[") && strings.HasSuffix(remoteAddr, "]") {
		host = remoteAddr[1 : len(remoteAddr)-1]
	}
	ip := net.ParseIP(host)
	return isConfiguredTrustedProxyIP(ip)
}

func isLoopbackHost(host string) bool {
	hostname := host
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		hostname = splitHost
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		hostname = host[1 : len(host)-1]
	}
	return strings.EqualFold(hostname, "localhost") || hostname == "127.0.0.1" || hostname == "::1"
}

func GoogleCallback(c *gin.Context) {
	errParam := c.Query("error")
	if errParam != "" {
		clearOAuthStateCookie(c)
		c.Redirect(http.StatusTemporaryRedirect, "/login?error="+url.QueryEscape(errParam))
		return
	}

	code := c.Query("code")
	state := c.Query("state")

	cookieState, err := c.Cookie("oauth2_state")
	clearOAuthStateCookie(c)
	if err != nil || state == "" || state != cookieState {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=invalid_state")
		return
	}

	// Exchange code
	clientId := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectUri := os.Getenv("GOOGLE_REDIRECT_URI")

	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", clientId)
	data.Set("client_secret", clientSecret)
	data.Set("redirect_uri", redirectUri)
	data.Set("grant_type", "authorization_code")

	httpClient := &http.Client{Timeout: 10 * time.Second}
	tokenReq, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(data.Encode()))
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=token_exchange_failed")
		return
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(tokenReq)
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=token_exchange_failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=token_exchange_failed")
		return
	}

	var tokenRes map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tokenRes); err != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=token_exchange_failed")
		return
	}
	accessToken, ok := tokenRes["access_token"].(string)
	if !ok || accessToken == "" {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=no_access_token")
		return
	}

	// Fetch user info
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=userinfo_failed")
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	infoResp, err := httpClient.Do(req)
	if err != nil || infoResp.StatusCode != http.StatusOK {
		if infoResp != nil {
			infoResp.Body.Close()
		}
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=userinfo_failed")
		return
	}
	defer infoResp.Body.Close()

	var googleUser struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := json.NewDecoder(io.LimitReader(infoResp.Body, 1<<20)).Decode(&googleUser); err != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=userinfo_failed")
		return
	}

	googleId := googleUser.ID
	email := strings.TrimSpace(googleUser.Email)
	name := googleUser.Name
	avatarUrl := googleUser.Picture

	if googleId == "" {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=no_google_id")
		return
	}
	if !googleUser.VerifiedEmail || email == "" {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=email_not_verified")
		return
	}

	// Lookup, link, or provision user transactionally
	resolvedID, totpEnabled, authorized, resolveErr := resolveGoogleOAuthUser(googleId, email, name, avatarUrl)
	if resolveErr != nil {
		slog.Error("database error during OAuth callback", "error", resolveErr)
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=db_error")
		return
	}
	if !authorized {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=not_authorized")
		return
	}
	var user models.User
	user.ID = resolvedID

	if totpEnabled {
		mfaBytes := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, mfaBytes); err != nil {
			slog.Error("crypto/rand failure generating OAuth MFA challenge", "error", err)
			InternalError(c, "Failed to generate MFA challenge")
			return
		}
		challengeToken := hex.EncodeToString(mfaBytes)
		if err := db.StoreMFAChallenge(challengeToken, user.ID, 5*time.Minute); err != nil {
			slog.Error("failed to persist OAuth MFA challenge", "user_id", user.ID, "error", err)
			InternalError(c, "Failed to store MFA challenge")
			return
		}
		c.Redirect(http.StatusTemporaryRedirect, "/login?mfa="+url.QueryEscape(challengeToken))
		return
	}

	// Log login
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()
	db.DB.Exec("INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?, ?, ?)", user.ID, clientIP, userAgent)

	// Issue JWT via centralized factory (includes jti + short expiry + client fingerprint)
	tokenString, err := createStandardJWT(user.ID, c)
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=jwt_failed")
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("aetherflow_session", tokenString, sessionCookieMaxAge, "/", "", secureCookie(), true)
	c.Redirect(http.StatusTemporaryRedirect, "/")
}

// getBaseURL determines the scheme + host from the incoming request,
// with protection against host header injection (CWE-601).
func getBaseURL(c *gin.Context) string {
	trustProxy := strings.EqualFold(os.Getenv("TRUST_PROXY_HEADERS"), "true") && isTrustedProxyPeer(c)

	scheme := "https"
	if c.Request.TLS == nil {
		scheme = "http"
		// Check X-Forwarded-Proto only from an explicitly trusted reverse proxy peer
		if trustProxy {
			if proto := strings.ToLower(strings.TrimSpace(c.GetHeader("X-Forwarded-Proto"))); proto == "http" || proto == "https" {
				scheme = proto
			}
		}
	}

	// Validate X-Forwarded-Host against whitelist only from a trusted reverse proxy peer
	host := c.Request.Host
	if trustProxy {
		if fwdHost := strings.TrimSpace(c.GetHeader("X-Forwarded-Host")); fwdHost != "" && isAllowedHost(fwdHost) {
			host = fwdHost
		}
	}

	return scheme + "://" + host
}

// isAllowedHost checks if the given host is syntactically safe and permitted by ALLOWED_HOSTS
// (or is a loopback host when ALLOWED_HOSTS is unset).
func isAllowedHost(host string) bool {
	if host == "" {
		return false
	}
	for _, r := range host {
		if r < 0x20 || r == 0x7f || r == ' ' || r == '\t' || r == '/' || r == '\\' || r == '@' {
			return false
		}
	}

	allowed := os.Getenv("ALLOWED_HOSTS")
	var entries []string
	for _, h := range strings.Split(allowed, ",") {
		if trimmed := strings.TrimSpace(h); trimmed != "" {
			entries = append(entries, trimmed)
		}
	}
	if len(entries) == 0 {
		return isLoopbackHost(host)
	}
	for _, entry := range entries {
		if strings.EqualFold(entry, host) {
			return true
		}
	}
	return false
}

func validateSessionToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Prevent algorithm confusion attacks: only accept HMAC signing
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return getJWTSecret(), nil
	})
	if err != nil || !token.Valid {
		return nil, errUnauthorizedSession
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errUnauthorizedSession
	}

	return claims, nil
}

func validateResolvedSessionClaims(c *gin.Context, claims jwt.MapClaims) bool {
	userIdFloat, ok := claims["user_id"].(float64)
	if !ok {
		return false
	}
	userId := int(userIdFloat)

	if jti, hasJti := claims["jti"].(string); hasJti && jti != "" && db.IsTokenRevoked(jti) {
		if graceEntry, ok := isWithinRotationGrace(jti); !ok || graceEntry.userID != userId {
			return false
		}
	}

	if cfp, hasCfp := claims["cfp"].(string); hasCfp && cfp != "" {
		if !matchesClientFingerprint(cfp, c) {
			return false
		}
	}
	return true
}

func resolveSessionToken(c *gin.Context) (string, jwt.MapClaims, error) {
	authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenString := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if tokenString != "" {
			if claims, err := validateSessionToken(tokenString); err == nil && validateResolvedSessionClaims(c, claims) {
				return tokenString, claims, nil
			}
		}
	}

	cookie, err := c.Cookie("aetherflow_session")
	if err == nil {
		tokenString := strings.TrimSpace(cookie)
		if tokenString != "" {
			if claims, err := validateSessionToken(tokenString); err == nil && validateResolvedSessionClaims(c, claims) {
				return tokenString, claims, nil
			}
		}
	}

	return "", nil, errUnauthorizedSession
}

// GetSession godoc
// @Summary      Get current session
// @Description  Get information about the currently authenticated user session.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]interface{}
// @Router       /auth/session [get]
func GetSession(c *gin.Context) {
	_, claims, err := resolveSessionToken(c)
	if err != nil {
		Unauthorized(c, "Unauthorized")
		return
	}

	userIdFloat, ok := claims["user_id"].(float64)
	if !ok {
		Unauthorized(c, "Invalid token claims")
		return
	}
	userId := int(userIdFloat)
	var user models.User
	var googleId sql.NullString
	var totpEnabled sql.NullBool
	err = db.DB.QueryRow(
		"SELECT id, username, email, avatar_url, role, google_id, COALESCE(totp_enabled, 0) FROM users WHERE id = ?", userId,
	).Scan(&user.ID, &user.Username, &user.Email, &user.AvatarURL, &user.Role, &googleId, &totpEnabled)

	user.IsOAuth = googleId.Valid && googleId.String != ""
	user.TOTPEnabled = totpEnabled.Valid && totpEnabled.Bool

	if err != nil {
		Unauthorized(c, "User not found")
		return
	}

	c.JSON(http.StatusOK, user)
}

// Logout godoc
// @Summary      Logout
// @Description  Clears the current session and revokes the JWT in Redis.
// @Tags         auth
// @Produce      json
// @Security     ApiKeyAuth
// @Success      200  {object}  map[string]interface{}
// @Router       /auth/logout [post]
func Logout(c *gin.Context) {
	// Revoke the token durably across the full token lifetime + 2h refresh grace window
	if _, claims, err := resolveSessionToken(c); err == nil {
		if jti, ok := claims["jti"].(string); ok && jti != "" {
			rotatedTokenGrace.Delete(jti)
			ttl := revocationTTLForClaims(claims)
			if err := db.RevokeToken(jti, ttl); err != nil {
				InternalError(c, "Failed to revoke session")
				return
			}
		}
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("aetherflow_session", "", -1, "/", "", secureCookie(), true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

// RefreshSession godoc
// @Summary      Refresh session token
// @Description  Rotates the JWT session token silently using the existing valid cookie or bearer token.
// @Tags         auth
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]interface{}
// @Router       /auth/refresh [post]
func RefreshSession(c *gin.Context) {
	var tokenStr string
	authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	if tokenStr == "" {
		if cookie, err := c.Cookie("aetherflow_session"); err == nil {
			tokenStr = strings.TrimSpace(cookie)
		}
	}
	if tokenStr == "" {
		Unauthorized(c, "No session token provided")
		return
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return getJWTSecret(), nil
	})

	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		Unauthorized(c, "Invalid session token")
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		Unauthorized(c, "Invalid token claims")
		return
	}

	if expVal, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(expVal), 0)
		if time.Since(expTime) > 2*time.Hour {
			Unauthorized(c, "Refresh window expired")
			return
		}
	}

	if cfp, ok := claims["cfp"].(string); ok && cfp != "" {
		if !matchesClientFingerprint(cfp, c) {
			slog.Warn("refresh rejected: client fingerprint mismatch", "ip", c.ClientIP())
			Unauthorized(c, "Client fingerprint mismatch")
			return
		}
	}

	userIDFloat, ok := claims["user_id"].(float64)
	if !ok {
		Unauthorized(c, "Missing user ID in claims")
		return
	}
	userID := int(userIDFloat)

	var user models.User
	err = db.DB.QueryRow("SELECT id, username, role FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Username, &user.Role)
	if err != nil {
		Unauthorized(c, "User no longer exists")
		return
	}

	jti, _ := claims["jti"].(string)
	if jti != "" {
		if db.IsTokenRevoked(jti) {
			if graceEntry, ok := isWithinRotationGrace(jti); ok && graceEntry.userID == user.ID && graceEntry.newToken != "" {
				c.SetSameSite(http.SameSiteLaxMode)
				c.SetCookie("aetherflow_session", graceEntry.newToken, sessionCookieMaxAge, "/", "", secureCookie(), true)
				c.JSON(http.StatusOK, gin.H{
					"status":     "success",
					"token":      graceEntry.newToken,
					"expires_at": time.Now().Add(15 * time.Minute).Unix(),
					"user": gin.H{
						"id":       user.ID,
						"username": user.Username,
						"role":     user.Role,
					},
				})
				return
			}
			Unauthorized(c, "Session has been revoked")
			return
		}
		if err := db.RevokeToken(jti, revocationTTLForClaims(claims)); err != nil {
			InternalError(c, "Failed to revoke rotated session")
			return
		}
	}

	newToken, err := GenerateJWT(user.ID, c)
	if err != nil {
		InternalError(c, "Failed to create new session")
		return
	}

	if jti != "" {
		rotatedTokenGrace.Store(jti, rotatedTokenGraceEntry{
			userID:    user.ID,
			newToken:  newToken,
			expiresAt: time.Now().Add(rotatedTokenGraceWindow),
		})
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("aetherflow_session", newToken, sessionCookieMaxAge, "/", "", secureCookie(), true)

	c.JSON(http.StatusOK, gin.H{
		"status":     "success",
		"token":      newToken,
		"expires_at": time.Now().Add(15 * time.Minute).Unix(),
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

// AuthMiddleware validates the JWT session via Bearer token with cookie fallback
// and sets "user_id" in the Gin context for downstream handlers.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Allow RefreshSession to validate expired tokens within its 2-hour grace window
		if c.Request.URL.Path == "/api/v1/auth/refresh" || c.Request.URL.Path == "/api/auth/refresh" || c.Request.URL.Path == "/api/v1/public/auth/refresh" {
			c.Next()
			return
		}

		_, claims, err := resolveSessionToken(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, APIError{Code: ErrCodeUnauthorized, Message: "Unauthorized"})
			return
		}

		userIdFloat, ok := claims["user_id"].(float64)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, APIError{Code: ErrCodeUnauthorized, Message: "Invalid token claims"})
			return
		}
		userId := int(userIdFloat)

		// Phase 11 & 12: Robust JWT Blacklist (Redis O(1) + LRU Fallback)
		jti, hasJti := claims["jti"].(string)
		if hasJti && db.IsTokenRevoked(jti) {
			if graceEntry, ok := isWithinRotationGrace(jti); !ok || graceEntry.userID != userId {
				c.AbortWithStatusJSON(http.StatusUnauthorized, APIError{Code: ErrCodeSessionExpired, Message: "Session revoked"})
				return
			}
		}

		// Verify the user still exists in the database
		var role string
		if err := db.DB.QueryRow("SELECT role FROM users WHERE id = ?", userId).Scan(&role); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, APIError{Code: ErrCodeUnauthorized, Message: "Unauthorized"})
			return
		}

		// Phase 6: Validate client fingerprint to detect session hijacking.
		// If the JWT contains a cfp claim, it must match the current client's fingerprint.
		if cfp, hasCfp := claims["cfp"].(string); hasCfp {
			if !matchesClientFingerprint(cfp, c) {
				expectedCfp := clientFingerprint(c)
				slog.Warn("session fingerprint mismatch",
					"user_id", userId,
					"expected", cfp[:min(8, len(cfp))],
					"got", expectedCfp[:min(8, len(expectedCfp))],
					"ip", c.ClientIP(),
				)
				c.AbortWithStatusJSON(http.StatusUnauthorized, APIError{Code: ErrCodeSessionHijacked, Message: "Session bound to a different client"})
				return
			}
		}

		c.Set("user_id", userId)
		c.Set("user_role", role)
		c.Next()
	}
}

// AdminOnly checks that the authenticated user has the "admin" role.
// Must be chained AFTER AuthMiddleware() which sets "user_role" in the context.
func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("user_role")
		if !exists || role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, APIError{Code: ErrCodeForbidden, Message: "Admin access required"})
			return
		}
		c.Next()
	}
}

// UpdateProfile godoc
// @Summary      Update user profile
// @Description  Update the email of the currently authenticated user.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     ApiKeyAuth
// @Param        req body object true "Email"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]interface{}
// @Failure      500  {object}  map[string]interface{}
// @Router       /auth/profile [put]
func UpdateProfile(c *gin.Context) {
	// Use the user_id already validated and set by AuthMiddleware()
	rawUserID, exists := c.Get("user_id")
	if !exists {
		Unauthorized(c, "Unauthorized")
		return
	}
	userId, ok := rawUserID.(int)
	if !ok {
		Unauthorized(c, "Invalid user context")
		return
	}

	var req struct {
		Email string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}
	trimmedEmail := strings.TrimSpace(req.Email)
	emailParts := strings.SplitN(trimmedEmail, "@", 2)
	if len(emailParts) != 2 || emailParts[0] == "" || emailParts[1] == "" || strings.Contains(emailParts[1], "@") || strings.ContainsAny(trimmedEmail, " \t\r\n") {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, "Invalid email address")
		return
	}

	tx, txErr := db.DB.Begin()
	if txErr != nil {
		slog.Error("profile update tx error", "error", txErr)
		InternalError(c, "Failed to update profile")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var conflictCount int
	if err := tx.QueryRow(
		"SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER(?) AND id != ?",
		trimmedEmail, userId,
	).Scan(&conflictCount); err != nil {
		slog.Error("profile update email check error", "error", err)
		InternalError(c, "Failed to update profile")
		return
	}
	if conflictCount > 0 {
		RespondError(c, http.StatusConflict, ErrCodeConflict, "Email address is already in use")
		return
	}

	if _, err := tx.Exec("UPDATE users SET email = ? WHERE id = ?", trimmedEmail, userId); err != nil {
		slog.Error("profile update error", "error", err)
		InternalError(c, "Failed to update profile")
		return
	}
	if err := tx.Commit(); err != nil {
		slog.Error("profile update commit error", "error", err)
		InternalError(c, "Failed to update profile")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

// HostValidationMiddleware blocks spoofed Host headers (Open Redirect / Poisoning)
func HostValidationMiddleware() gin.HandlerFunc {
	allowedHosts := map[string]bool{
		"api.aetherflow.com": true,
		"localhost":          true,
		"localhost:8080":     true,
		"localhost:3000":     true,
		"127.0.0.1":          true,
		"127.0.0.1:8080":     true,
		"127.0.0.1:3000":     true,
	}

	envHosts := os.Getenv("ALLOWED_HOSTS")
	if envHosts != "" {
		// Explicit whitelist overrides defaults entirely
		allowedHosts = make(map[string]bool)
		for _, h := range strings.Split(envHosts, ",") {
			allowedHosts[strings.TrimSpace(h)] = true
		}
	} else {
		// Auto-discover local network IPs so the Next.js proxy
		// can forward requests with the original browser Host header.
		ifaces, err := net.Interfaces()
		if err == nil {
			for _, iface := range ifaces {
				addrs, err := iface.Addrs()
				if err != nil {
					continue
				}
				for _, addr := range addrs {
					var ip net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					}
					if ip == nil || ip.IsLoopback() {
						continue
					}
					ipStr := ip.String()
					allowedHosts[ipStr] = true
					allowedHosts[ipStr+":8080"] = true
					allowedHosts[ipStr+":3000"] = true
				}
			}
		}
		slog.Info("host validation auto-discovered", "allowed_count", len(allowedHosts))
	}

	return func(c *gin.Context) {
		if len(allowedHosts) > 0 {
			if !allowedHosts[c.Request.Host] {
				slog.Warn("host validation rejected request",
					"host", c.Request.Host,
					"ip", c.ClientIP(),
				)
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}
		}
		c.Next()
	}
}

// CSRFMiddleware validates X-CSRF-Token on mutating requests.
// Bearer-token authenticated API requests are exempt (tokens are not auto-sent by browsers).
// Only cookie-authenticated requests (e.g., OIDC flows) require CSRF validation.
// Enable by setting CSRF_ENABLED=true in the environment.
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Silent refresh requests and Bearer-token requests are exempt from CSRF
		if c.Request.URL.Path == "/api/v1/auth/refresh" || c.Request.URL.Path == "/api/auth/refresh" || c.Request.URL.Path == "/api/v1/public/auth/refresh" || strings.HasPrefix(c.GetHeader("Authorization"), "Bearer ") {
			c.Next()
			return
		}
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "DELETE" {
			token := c.GetHeader("X-CSRF-Token")
			cookie, err := c.Cookie("csrf_token")
			if err != nil || token == "" || token != cookie {
				slog.Warn("CSRF validation failed",
					"method", c.Request.Method,
					"path", c.Request.URL.Path,
					"ip", c.ClientIP(),
				)
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid CSRF token"})
				return
			}
		}
		c.Next()
	}
}

// ---- Phase 6: Session Management ----

// ListActiveSessions returns all non-expired sessions for the current user.
func ListActiveSessions(c *gin.Context) {
	rawUserID, _ := c.Get("user_id")
	userID := rawUserID.(int)

	// Clean up expired sessions first (best-effort)
	db.DB.Exec("DELETE FROM active_sessions WHERE expires_at < CURRENT_TIMESTAMP")

	rows, err := db.DB.Query(
		`SELECT jti, ip_address, user_agent, expires_at, last_active
		 FROM active_sessions WHERE user_id = ? ORDER BY last_active DESC`,
		userID,
	)
	if err != nil {
		InternalError(c, "Failed to query sessions")
		return
	}
	defer rows.Close()

	type sessionInfo struct {
		JTI        string `json:"jti"`
		IPAddress  string `json:"ip_address"`
		UserAgent  string `json:"user_agent"`
		ExpiresAt  string `json:"expires_at"`
		LastActive string `json:"last_active"`
		IsCurrent  bool   `json:"is_current"`
	}

	// Determine the current session's JTI
	var currentJTI string
	if _, claims, err := resolveSessionToken(c); err == nil {
		if jti, ok := claims["jti"].(string); ok {
			currentJTI = jti
		}
	}

	var sessions []sessionInfo
	for rows.Next() {
		var s sessionInfo
		if err := rows.Scan(&s.JTI, &s.IPAddress, &s.UserAgent, &s.ExpiresAt, &s.LastActive); err != nil {
			continue
		}
		s.IsCurrent = s.JTI == currentJTI
		// Mask JTI for security — client only sees first 8 chars for identification
		if len(s.JTI) > 8 {
			s.JTI = s.JTI[:8] + "..."
		}
		sessions = append(sessions, s)
	}

	if sessions == nil {
		sessions = []sessionInfo{}
	}

	c.JSON(http.StatusOK, gin.H{"sessions": sessions, "count": len(sessions)})
}

// RevokeSession allows a user to invalidate one of their own sessions by JTI prefix.
func RevokeSession(c *gin.Context) {
	rawUserID, _ := c.Get("user_id")
	userID := rawUserID.(int)
	jtiPrefix := c.Param("jti")

	if jtiPrefix == "" || len(jtiPrefix) < 8 {
		BadRequest(c, "Invalid session identifier")
		return
	}

	// Strip trailing "..." if the frontend sends the masked JTI
	jtiPrefix = strings.TrimSuffix(jtiPrefix, "...")

	// Look up the full JTI — scoped to USER to prevent IDOR
	var fullJTI string
	var expiresAt string
	err := db.DB.QueryRow(
		"SELECT jti, expires_at FROM active_sessions WHERE jti LIKE ? AND user_id = ?",
		jtiPrefix+"%", userID,
	).Scan(&fullJTI, &expiresAt)
	if err != nil {
		NotFoundError(c, "Session not found")
		return
	}

	// Revoke the token via the durable blacklist (>= 2h floor covering refresh grace window)
	rotatedTokenGrace.Delete(fullJTI)
	ttl := minRevocationTTL
	if expTime, err := time.Parse(time.RFC3339, expiresAt); err == nil {
		if remaining := time.Until(expTime); remaining > ttl {
			ttl = remaining
		}
	}
	if err := db.RevokeToken(fullJTI, ttl); err != nil {
		InternalError(c, "Failed to revoke session")
		return
	}

	// Remove from active sessions
	db.DB.Exec("DELETE FROM active_sessions WHERE jti = ?", fullJTI)

	c.JSON(http.StatusOK, gin.H{"message": "Session revoked"})
}

// GenerateJWT generates a standard signed JWT for an authenticated user session.
func GenerateJWT(userID int, c *gin.Context) (string, error) {
	return createStandardJWT(userID, c)
}

// ChangePassword godoc
// @Summary      Update user password
// @Description  Verifies current password and updates to a new password using bcrypt.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     ApiKeyAuth
// @Param        req body object true "Password change request"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]interface{}
// @Router       /auth/profile/password [put]
func ChangePassword(c *gin.Context) {
	rawUserID, exists := c.Get("user_id")
	if !exists {
		Unauthorized(c, "Unauthorized")
		return
	}
	userID, ok := rawUserID.(int)
	if !ok {
		Unauthorized(c, "Invalid user context")
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "current_password and new_password are required")
		return
	}

	if len(req.NewPassword) < 8 {
		BadRequest(c, "New password must be at least 8 characters")
		return
	}

	var currentHash string
	var username string
	var role string
	err := db.DB.QueryRow("SELECT username, COALESCE(role, 'member'), COALESCE(password_hash, '') FROM users WHERE id = ?", userID).Scan(&username, &role, &currentHash)
	if err != nil {
		NotFoundError(c, "User not found")
		return
	}

	if currentHash == "" {
		BadRequest(c, "Cannot change password for OAuth-only account")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.CurrentPassword)); err != nil {
		BadRequest(c, "Current password incorrect")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		InternalError(c, "Failed to hash new password")
		return
	}

	if _, err := db.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(newHash), userID); err != nil {
		InternalError(c, "Failed to update password")
		return
	}

	if role == "admin" {
		services.SaveMasterCredentials(username, req.NewPassword)
	}
	db.RecordAudit(userID, username, "password_update", "user", strconv.Itoa(userID), "Password updated successfully", c.ClientIP(), c.Request.UserAgent())

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Password updated successfully"})
}

// UpdatePassword aliases ChangePassword for router and caller compatibility.
func UpdatePassword(c *gin.Context) {
	ChangePassword(c)
}

// UpdateAvatar godoc
// @Summary      Update user avatar
// @Description  Updates the avatar URL or base64 image string for the authenticated user.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     ApiKeyAuth
// @Param        req body object true "Avatar URL or Data URI"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]interface{}
// @Router       /auth/profile/avatar [put]
func UpdateAvatar(c *gin.Context) {
	rawUserID, exists := c.Get("user_id")
	if !exists {
		Unauthorized(c, "Unauthorized")
		return
	}
	userID, ok := rawUserID.(int)
	if !ok {
		Unauthorized(c, "Invalid user context")
		return
	}

	var req struct {
		Avatar    string `json:"avatar"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "Invalid request payload")
		return
	}

	avatarVal := strings.TrimSpace(req.Avatar)
	if avatarVal == "" {
		avatarVal = strings.TrimSpace(req.AvatarURL)
	}
	if avatarVal == "" {
		BadRequest(c, "Avatar image or URL is required")
		return
	}

	// Validate scheme - disallow javascript: and file: schemes
	lowerVal := strings.ToLower(avatarVal)
	if strings.HasPrefix(lowerVal, "javascript:") || strings.HasPrefix(lowerVal, "file:") {
		BadRequest(c, "Invalid avatar URI scheme")
		return
	}

	// Enforce 2MB size limit on base64 payload or URL length
	const maxAvatarSize = 2 * 1024 * 1024
	if len(avatarVal) > maxAvatarSize {
		RespondError(c, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "Avatar payload exceeds maximum 2MB size limit")
		return
	}

	var username string
	_ = db.DB.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)

	if _, err := db.DB.Exec("UPDATE users SET avatar_url = ? WHERE id = ?", avatarVal, userID); err != nil {
		InternalError(c, "Failed to update avatar")
		return
	}

	db.RecordAudit(userID, username, "avatar_update", "user", strconv.Itoa(userID), "Avatar updated", c.ClientIP(), c.Request.UserAgent())

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Avatar updated successfully", "avatar_url": avatarVal})
}

// DeleteAvatar godoc
// @Summary      Delete user avatar
// @Description  Removes the avatar of the authenticated user.
// @Tags         auth
// @Produce      json
// @Security     ApiKeyAuth
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]interface{}
// @Router       /auth/profile/avatar [delete]
func DeleteAvatar(c *gin.Context) {
	rawUserID, exists := c.Get("user_id")
	if !exists {
		Unauthorized(c, "Unauthorized")
		return
	}
	userID, ok := rawUserID.(int)
	if !ok {
		Unauthorized(c, "Invalid user context")
		return
	}

	var username string
	_ = db.DB.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)

	if _, err := db.DB.Exec("UPDATE users SET avatar_url = '' WHERE id = ?", userID); err != nil {
		InternalError(c, "Failed to remove avatar")
		return
	}

	db.RecordAudit(userID, username, "avatar_delete", "user", strconv.Itoa(userID), "Avatar removed", c.ClientIP(), c.Request.UserAgent())

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Avatar removed successfully"})
}

// RemoveAvatar aliases DeleteAvatar for API parity.
func RemoveAvatar(c *gin.Context) {
	DeleteAvatar(c)
}

