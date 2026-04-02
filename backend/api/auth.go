package api

import (
	"context"
	"crypto/rand"
	"time"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"aetherflow/db"
	"aetherflow/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func getJWTSecret() []byte {
	if len(jwtSecret) == 0 {
		log.Fatal("FATAL: JWT_SECRET environment variable is not set. Refusing to start with an insecure default.")
	}
	return jwtSecret
}

// secureCookie returns whether cookies should have the Secure flag set.
// Defaults to true (HTTPS-only). Set COOKIE_SECURE=false in env for local HTTP dev.
func secureCookie() bool {
	return strings.ToLower(os.Getenv("COOKIE_SECURE")) != "false"
}

// SetupAdmin creates the initial admin account (only works when no users exist)
func SetupAdmin(c *gin.Context) {
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		log.Printf("CRITICAL: Failed to query user count during admin setup: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database unavailable"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "Admin account already exists"})
		return
	}

	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Enforce minimum password length for security
	if len(req.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	res, err := db.DB.Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
		req.Username, string(hash),
	)
	if err != nil {
		log.Printf("Setup admin error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create admin account"})
		return
	}

	id, err := res.LastInsertId()
	if err != nil || id == 0 {
		log.Printf("CRITICAL: Failed to retrieve LastInsertId during admin creation: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify new user creation"})
		return
	}

	// Issue JWT via centralized factory (includes jti + short expiry)
	tokenString, err := createStandardJWT(int(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("aetherflow_session", tokenString, 900, "/", "", secureCookie(), true)

	c.JSON(http.StatusOK, gin.H{"message": "Admin account created", "username": req.Username})
}

// LocalLogin authenticates with username + password
func LocalLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	var passwordHash string
	var googleId sql.NullString
	err := db.DB.QueryRow(
		"SELECT id, username, email, avatar_url, role, COALESCE(password_hash, ''), google_id FROM users WHERE username = ?",
		req.Username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.AvatarURL, &user.Role, &passwordHash, &googleId)

	user.IsOAuth = googleId.Valid && googleId.String != ""

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	if passwordHash == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "This account uses Google OAuth. Use the Google login button."})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Log login
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()
	db.DB.Exec("INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?, ?, ?)", user.ID, clientIP, userAgent)

	// Issue JWT via centralized factory (includes jti + short expiry)
	tokenString, err := createStandardJWT(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
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
		log.Printf("CRITICAL: Failed to query user count during setup check: %v", err)
		return false, fmt.Errorf("database unavailable: %w", err)
	}
	return count == 0, nil
}

// CheckSetupNeeded returns whether initial setup is required
func CheckSetupNeeded(c *gin.Context) {
	needed, err := checkSetupNeeded()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify setup state"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"setupRequired": needed})
}

func GoogleLogin(c *gin.Context) {
	clientId := os.Getenv("GOOGLE_CLIENT_ID")
	redirectUri := os.Getenv("GOOGLE_REDIRECT_URI")

	if clientId == "" || redirectUri == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OAuth not configured"})
		return
	}

	// Generate state
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		log.Printf("CRITICAL: crypto/rand failure during OAuth state generation: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate secure state"})
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
		c.Redirect(http.StatusTemporaryRedirect, baseURL+"/login?error="+errParam)
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
			log.Printf("CRITICAL: Failed to query user count during OAuth: %v", err)
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
			log.Printf("User creation err: %v", err)
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
		log.Printf("DB error: %v", err)
		c.Redirect(http.StatusTemporaryRedirect, baseURL+"/login?error=db_error")
		return
	}

	// Log login
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()
	db.DB.Exec("INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?, ?, ?)", user.ID, clientIP, userAgent)

	// Issue JWT via centralized factory (includes jti + short expiry)
	tokenString, err := createStandardJWT(user.ID)
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

func GetSession(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Prevent algorithm confusion attacks: only accept HMAC signing
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return getJWTSecret(), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userIdFloat, ok := claims["user_id"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}
	userId := int(userIdFloat)
	var user models.User
	var googleId sql.NullString
	err = db.DB.QueryRow("SELECT id, username, email, avatar_url, role, google_id FROM users WHERE id = ?", userId).
		Scan(&user.ID, &user.Username, &user.Email, &user.AvatarURL, &user.Role, &googleId)

	user.IsOAuth = googleId.Valid && googleId.String != ""

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func Logout(c *gin.Context) {
	// Attempt to revoke the token intelligently (Phase 10 integration)
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return getJWTSecret(), nil
		})
		if token != nil && token.Valid {
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				if jti, ok := claims["jti"].(string); ok {
					if exp, ok := claims["exp"].(float64); ok {
						remaining := time.Until(time.Unix(int64(exp), 0))
						if remaining > 0 {
							db.RevokeToken(jti, remaining)
						}
					}
				}
			}
		}
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("aetherflow_session", "", -1, "/", "", secureCookie(), true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

// AuthMiddleware validates the JWT session via Bearer token and sets "user_id" in the
// Gin context for downstream handlers. Aborts with 401 on any auth failure.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Prevent algorithm confusion attacks: only accept HMAC signing
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return getJWTSecret(), nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		userIdFloat, ok := claims["user_id"].(float64)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}
		userId := int(userIdFloat)

		// Phase 11: Redis Fast Blacklist Lookup (O(1))
		jti, hasJti := claims["jti"].(string)
		if hasJti && db.RedisClient != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if db.RedisClient.Get(ctx, "blacklist:"+jti).Err() == nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: session revoked"})
				return
			}
		}

		// Verify the user still exists in the database
		var role string
		if err := db.DB.QueryRow("SELECT role FROM users WHERE id = ?", userId).Scan(&role); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
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
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden: Admin access required"})
			return
		}
		c.Next()
	}
}

func UpdateProfile(c *gin.Context) {
	// Use the user_id already validated and set by AuthMiddleware()
	rawUserID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userId, ok := rawUserID.(int)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user context"})
		return
	}

	var req struct {
		Email string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := db.DB.Exec("UPDATE users SET email = ? WHERE id = ?", req.Email, userId)
	if err != nil {
		log.Printf("Profile update error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

// HostValidationMiddleware blocks spoofed Host headers (Open Redirect / Poisoning)
func HostValidationMiddleware() gin.HandlerFunc {
	allowedHosts := map[string]bool{
		"api.aetherflow.com": true,
		"localhost:8080":     true,
		"127.0.0.1:8080":     true,
	}
	// For dev continuity, allow if ALLOWED_HOSTS is empty in env by fallback
	envHosts := os.Getenv("ALLOWED_HOSTS")
	if envHosts != "" {
		allowedHosts = make(map[string]bool)
		for _, h := range strings.Split(envHosts, ",") {
			allowedHosts[strings.TrimSpace(h)] = true
		}
	}

	return func(c *gin.Context) {
		if len(allowedHosts) > 0 {
			if !allowedHosts[c.Request.Host] {
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
				log.Printf("CSRF validation failed: method=%s path=%s ip=%s", c.Request.Method, c.Request.URL.Path, c.ClientIP())
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid CSRF token"})
				return
			}
		}
		c.Next()
	}
}

