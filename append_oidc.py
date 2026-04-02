import os

path = r'C:\Users\armyw\OneDrive\Documents\Antigravity\Projects\AetherFlow\backend\api\oidc.go'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

target_switch = '''	switch grantType {
	case "authorization_code":
		handleAuthCodeExchange(c, clientID)
	case "refresh_token":
		handleRefreshTokenExchange(c, clientID)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}'''
replacement_switch = '''	switch grantType {
	case "authorization_code":
		handleAuthCodeExchange(c, clientID)
	case "refresh_token":
		handleRefreshTokenExchange(c, clientID)
	case "urn:ietf:params:oauth:grant-type:device_code":
		handleDeviceCodeExchange(c, clientID)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}'''

if target_switch in text:
    text = text.replace(target_switch, replacement_switch)

handlers = '''
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
'''

if 'OIDCDeviceAuthorize' not in text:
    text += handlers

with open(path, 'w', encoding='utf-8', newline='') as f:
    f.write(text)

print('OIDC update complete')
