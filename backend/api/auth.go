package api

import (
	"crypto/rand"
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
	"time"

	"aetherflow/db"
	"aetherflow/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func getJWTSecret() []byte {
	if len(jwtSecret) == 0 {
		jwtSecret = []byte("default_fallback_secret_do_not_use_in_prod")
	}
	return jwtSecret
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
	rand.Read(stateBytes)
	state := hex.EncodeToString(stateBytes)

	// Set state cookie
	c.SetCookie("oauth2_state", state, 600, "/", "", false, true)

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
	accessToken := tokenRes["access_token"].(string)

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
		db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
		
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

	// Issue JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	tokenString, err := token.SignedString(getJWTSecret())
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, baseURL+"/login?error=jwt_failed")
		return
	}

	c.SetCookie("aetherflow_session", tokenString, 3600*24*30, "/", "", false, true)
	c.Redirect(http.StatusTemporaryRedirect, baseURL+"/")
}

// getBaseURL determines the scheme + host from the incoming request
func getBaseURL(c *gin.Context) string {
	scheme := "https"
	if c.Request.TLS == nil {
		// Check X-Forwarded-Proto from Apache proxy
		if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else {
			scheme = "http"
		}
	}
	host := c.GetHeader("X-Forwarded-Host")
	if host == "" {
		host = c.Request.Host
	}
	return scheme + "://" + host
}

func GetSession(c *gin.Context) {
	cookie, err := c.Cookie("aetherflow_session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	token, err := jwt.Parse(cookie, func(token *jwt.Token) (interface{}, error) {
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

	userId := int(claims["user_id"].(float64))

	var user models.User
	err = db.DB.QueryRow("SELECT id, username, email, avatar_url, role FROM users WHERE id = ?", userId).
		Scan(&user.ID, &user.Username, &user.Email, &user.AvatarURL, &user.Role)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func Logout(c *gin.Context) {
	c.SetCookie("aetherflow_session", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie("aetherflow_session")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		token, err := jwt.Parse(cookie, func(token *jwt.Token) (interface{}, error) {
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

		userId := int(claims["user_id"].(float64))
		var role string
		err = db.DB.QueryRow("SELECT role FROM users WHERE id = ?", userId).Scan(&role)
		
		if err != nil || role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden: Admin access required"})
			return
		}

		c.Next()
	}
}

func UpdateProfile(c *gin.Context) {
	cookie, err := c.Cookie("aetherflow_session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	token, err := jwt.Parse(cookie, func(token *jwt.Token) (interface{}, error) {
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

	userId := int(claims["user_id"].(float64))

	var req struct {
		Email string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err = db.DB.Exec("UPDATE users SET email = ? WHERE id = ?", req.Email, userId)
	if err != nil {
		log.Printf("Profile update error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}
