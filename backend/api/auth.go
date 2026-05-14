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
	"strings"
	"sync"
	"time"

	"aetherflow/db"
	"aetherflow/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret []byte
var jwtSecretOnce sync.Once
var errUnauthorizedSession = errors.New("unauthorized session")

func getJWTSecret() []byte {
	jwtSecretOnce.Do(func() {
		jwtSecret = []byte(os.Getenv("JWT_SECRET"))
		if len(jwtSecret) == 0 {
			log.Fatal("FATAL: JWT_SECRET environment variable is not set. Refusing to start with an insecure default.")
		}
	})
	return jwtSecret
}

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

	// Issue JWT via centralized factory (includes jti + short expiry + client fingerprint)
	tokenString, err := createStandardJWT(int(id), c)
	if err != nil {
		RespondError(c, http.StatusInternalServerError, ErrCodeInternal, "Failed to create session")
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("aetherflow_session", tokenString, 900, "/", "", secureCookie(), true)

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
	c.SetCookie("aetherflow_session", tokenString, 900, "/", "", secureCookie(), true)
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
	authUrl := fmt.Sprintf("https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s&access_type=offline&prompt=consent",
		clientId, redirectUri, strings.Join(scopes, " "), state)

	c.Redirect(http.StatusTemporaryRedirect, authUrl)
}

func GoogleCallback(c *gin.Context) {
	// Dynamically build base URL from request
	baseURL := getBaseURL(c)

	errParam := c.Query("error")
	if errParam != "" {
		c.Redirect(http.StatusTemporaryRedirect, baseURL+"/login?error="+url.QueryEscape(errParam))
		return
	}

	code := c.Query("code")
	state := c.Query("state")

	cookieState, err := c.Cookie("oauth2_state")
	if err != nil || state != cookieState {
		c.Redirect(http.StatusTemporaryRedirect, baseURL+"/login?error=invalid_state")
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

	resp, err := http.PostForm("https://oauth2.googleapis.com/token", data)
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, baseURL+"/login?error=token_exchange_failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		c.Redirect(http.StatusTemporaryRedirect, baseURL+"/login?error=token_exchange_failed")
		return
	}

	var tokenRes map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&tokenRes)
	accessToken, ok := tokenRes["access_token"].(string)
	if !ok || accessToken == "" {
		c.Redirect(http.StatusTemporaryRedirect, baseURL+"/login?error=no_access_token")
		return
	}

	// Fetch user info
	req, _ := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Add("Authorization", "Bearer "+accessToken)
	infoResp, err := http.DefaultClient.Do(req)
	if err != nil || infoResp.StatusCode != 200 {
		c.Redirect(http.StatusTemporaryRedirect, baseURL+"/login?error=userinfo_failed")
		return
	}
	defer infoResp.Body.Close()

	infoBytes, _ := io.ReadAll(infoResp.Body)
	var userInfo map[string]interface{}
	json.Unmarshal(infoBytes, &userInfo)

	googleId, _ := userInfo["id"].(string)
	email, _ := userInfo["email"].(string)
	name, _ := userInfo["name"].(string)
	avatarUrl, _ := userInfo["picture"].(string)

	if googleId == "" {
		c.Redirect(http.StatusTemporaryRedirect, baseURL+"/login?error=no_google_id")
		return
	}

	// Upsert user
	var user models.User
	err = db.DB.QueryRow("SELECT id, username, email, avatar_url, role FROM users WHERE google_id = ?", googleId).
		Scan(&user.ID, &user.Username, &user.Email, &user.AvatarURL, &user.Role)

	if err == sql.ErrNoRows {
		// Create new user
		username := name
		if i := strings.Index(email, "@"); i != -1 {
			username = email[:i]
		}

		// Clean username
		username = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-' {
				return r
			}
			return -1
		}, username)

		var count int
		if err := db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
			slog.Error("failed to query user count during OAuth", "error", err)
			c.Redirect(http.StatusTemporaryRedirect, baseURL+"/login?error=db_error")
			return
		}

		role := "user"
		if count == 0 || email == os.Getenv("ADMIN_EMAIL") {
			role = "admin"
		}

		res, err := db.DB.Exec("INSERT INTO users (username, google_id, email, avatar_url, role) VALUES (?, ?, ?, ?, ?)",
			username, googleId, email, avatarUrl, role)

		if err != nil {
			slog.Error("user creation error during OAuth", "error", err)
			c.Redirect(http.StatusTemporaryRedirect, baseURL+"/login?error=db_error")
			return
		}

		id, _ := res.LastInsertId()
		user.ID = int(id)
		user.Username = username
		user.Email = email
		user.AvatarURL = avatarUrl
		user.Role = role
	} else if err == nil {
		// Update existing user
		db.DB.Exec("UPDATE users SET email = ?, avatar_url = ? WHERE google_id = ?", email, avatarUrl, googleId)
		user.Email = email
		user.AvatarURL = avatarUrl
	} else {
		slog.Error("database error during OAuth callback", "error", err)
		c.Redirect(http.StatusTemporaryRedirect, baseURL+"/login?error=db_error")
		return
	}

	// Log login
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()
	db.DB.Exec("INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?, ?, ?)", user.ID, clientIP, userAgent)

	// Issue JWT via centralized factory (includes jti + short expiry + client fingerprint)
	tokenString, err := createStandardJWT(user.ID, c)
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, baseURL+"/login?error=jwt_failed")
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("aetherflow_session", tokenString, 900, "/", "", secureCookie(), true)
	c.Redirect(http.StatusTemporaryRedirect, baseURL+"/")
}

// getBaseURL determines the scheme + host from the incoming request,
// with protection against host header injection (CWE-601).
func getBaseURL(c *gin.Context) string {
	scheme := "https"
	if c.Request.TLS == nil {
		// Check X-Forwarded-Proto from reverse proxy
		if proto := c.GetHeader("X-Forwarded-Proto"); proto == "http" || proto == "https" {
			scheme = proto
		} else {
			scheme = "http"
		}
	}

	// Validate X-Forwarded-Host against whitelist to prevent open redirect
	host := c.Request.Host
	if fwdHost := c.GetHeader("X-Forwarded-Host"); fwdHost != "" {
		if isAllowedHost(fwdHost) {
			host = fwdHost
		}
		// If not in whitelist, silently ignore and use c.Request.Host
	}

	return scheme + "://" + host
}

// isAllowedHost checks if the given host is in the ALLOWED_HOSTS whitelist.
// If ALLOWED_HOSTS is not set, allows all hosts (backwards compatible for dev).
func isAllowedHost(host string) bool {
	allowed := os.Getenv("ALLOWED_HOSTS")
	if allowed == "" {
		return true // No whitelist configured — allow all (dev mode)
	}
	for _, h := range strings.Split(allowed, ",") {
		if strings.TrimSpace(h) == host {
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

func resolveSessionToken(c *gin.Context) (string, jwt.MapClaims, error) {
	authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenString := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if tokenString != "" {
			if claims, err := validateSessionToken(tokenString); err == nil {
				return tokenString, claims, nil
			}
		}
	}

	cookie, err := c.Cookie("aetherflow_session")
	if err == nil {
		tokenString := strings.TrimSpace(cookie)
		if tokenString != "" {
			if claims, err := validateSessionToken(tokenString); err == nil {
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
	// Attempt to revoke the token intelligently (Phase 10 integration)
	if _, claims, err := resolveSessionToken(c); err == nil {
		if jti, ok := claims["jti"].(string); ok {
			if exp, ok := claims["exp"].(float64); ok {
				remaining := time.Until(time.Unix(int64(exp), 0))
				if remaining > 0 {
					db.RevokeToken(jti, remaining)
				}
			}
		}
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("aetherflow_session", "", -1, "/", "", secureCookie(), true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

// AuthMiddleware validates the JWT session via Bearer token with cookie fallback
// and sets "user_id" in the Gin context for downstream handlers.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
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
			c.AbortWithStatusJSON(http.StatusUnauthorized, APIError{Code: ErrCodeSessionExpired, Message: "Session revoked"})
			return
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
			expectedCfp := clientFingerprint(c)
			if cfp != expectedCfp {
				slog.Warn("session fingerprint mismatch",
					"user_id", userId,
					"expected", cfp[:8],
					"got", expectedCfp[:8],
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

	_, err := db.DB.Exec("UPDATE users SET email = ? WHERE id = ?", req.Email, userId)
	if err != nil {
		slog.Error("profile update error", "error", err)
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
		// Bearer-token API requests are inherently CSRF-safe
		if strings.HasPrefix(c.GetHeader("Authorization"), "Bearer ") {
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

	// Revoke the token via the blacklist
	if expTime, err := time.Parse(time.RFC3339, expiresAt); err == nil {
		remaining := time.Until(expTime)
		if remaining > 0 {
			db.RevokeToken(fullJTI, remaining)
		}
	}

	// Remove from active sessions
	db.DB.Exec("DELETE FROM active_sessions WHERE jti = ?", fullJTI)

	c.JSON(http.StatusOK, gin.H{"message": "Session revoked"})
}
