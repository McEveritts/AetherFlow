package api

import (
	"log/slog"
	"net/http"
	"time"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

// pendingTTL is the lifetime of a pending TOTP secret before it expires.
const pendingTTL = 5 * time.Minute

// Setup2FA godoc
// @Summary      Initialize 2FA enrollment
// @Description  Generates a new TOTP key for the authenticated user and returns
//               the otpauth:// URI for QR code rendering. The secret is held in
//               an ephemeral cache (Redis or in-memory) for 5 minutes until the
//               user verifies it with a valid code.
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} map[string]interface{}
// @Failure      401 {object} map[string]interface{}
// @Failure      409 {object} map[string]interface{}
// @Failure      500 {object} map[string]interface{}
// @Router       /auth/user/2fa/setup [get]
func Setup2FA(c *gin.Context) {
	rawUserID, _ := c.Get("user_id")
	userID := rawUserID.(int)

	// Check if 2FA is already enabled
	var totpEnabled bool
	if err := db.DB.QueryRow(
		"SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?", userID,
	).Scan(&totpEnabled); err != nil {
		InternalError(c, "Failed to query user")
		return
	}
	if totpEnabled {
		RespondError(c, http.StatusConflict, ErrCodeConflict, "Two-factor authentication is already enabled")
		return
	}

	// Fetch username for the TOTP issuer label
	var username string
	if err := db.DB.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username); err != nil {
		InternalError(c, "Failed to query user")
		return
	}

	// Generate the TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "AetherFlow",
		AccountName: username,
		Period:      30,
	})
	if err != nil {
		slog.Error("TOTP key generation failed", "user_id", userID, "error", err)
		InternalError(c, "Failed to generate TOTP key")
		return
	}

	// Store the raw secret in ephemeral cache (Redis + in-memory fallback)
	if err := db.Store2FAPending(userID, key.Secret(), pendingTTL); err != nil {
		slog.Error("failed to store pending 2FA secret", "user_id", userID, "error", err)
		InternalError(c, "Failed to initiate 2FA setup")
		return
	}

	slog.Info("2FA setup initiated", "user_id", userID)
	c.JSON(http.StatusOK, gin.H{
		"otpauth_uri": key.URL(),
		"secret":      key.Secret(),
	})
}

// Verify2FA godoc
// @Summary      Confirm 2FA enrollment
// @Description  Validates a TOTP code against the pending secret, then persists
//               the encrypted secret to the database and marks totp_enabled=1.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        req body object true "TOTP code"
// @Success      200 {object} map[string]interface{}
// @Failure      400 {object} map[string]interface{}
// @Failure      401 {object} map[string]interface{}
// @Failure      500 {object} map[string]interface{}
// @Router       /auth/user/2fa/verify [post]
func Verify2FA(c *gin.Context) {
	rawUserID, _ := c.Get("user_id")
	userID := rawUserID.(int)

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, "A 6-digit code is required")
		return
	}

	// Retrieve the pending secret
	secret, err := db.Get2FAPending(userID)
	if err != nil {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation,
			"No pending 2FA enrollment found. Please initiate setup again.")
		return
	}

	// Validate the TOTP code
	if !totp.Validate(req.Code, secret) {
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "Invalid verification code")
		return
	}

	// Encrypt the secret before persisting
	encrypted, err := EncryptKey(secret)
	if err != nil {
		slog.Error("failed to encrypt TOTP secret", "user_id", userID, "error", err)
		InternalError(c, "Failed to secure TOTP secret")
		return
	}

	// Persist to the database
	if _, err := db.DB.Exec(
		"UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?",
		encrypted, userID,
	); err != nil {
		slog.Error("failed to persist TOTP enrollment", "user_id", userID, "error", err)
		InternalError(c, "Failed to enable two-factor authentication")
		return
	}

	// Clean up the pending secret
	db.Delete2FAPending(userID)

	// Audit trail
	username, _ := c.Get("username")
	uname, _ := username.(string)
	if uname == "" {
		db.DB.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&uname)
	}
	db.RecordAudit(userID, uname, "2fa_enabled", "user", "", "", c.ClientIP(), c.Request.UserAgent())

	slog.Info("2FA enabled successfully", "user_id", userID)
	c.JSON(http.StatusOK, gin.H{"message": "Two-factor authentication enabled"})
}

// Disable2FA godoc
// @Summary      Disable 2FA
// @Description  Validates a current TOTP code, then clears the secret and disables 2FA.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        req body object true "TOTP code"
// @Success      200 {object} map[string]interface{}
// @Failure      400 {object} map[string]interface{}
// @Failure      401 {object} map[string]interface{}
// @Failure      500 {object} map[string]interface{}
// @Router       /auth/user/2fa/disable [post]
func Disable2FA(c *gin.Context) {
	rawUserID, _ := c.Get("user_id")
	userID := rawUserID.(int)

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, "A 6-digit code is required")
		return
	}

	// Fetch the encrypted TOTP secret from the database
	var encryptedSecret string
	var totpEnabled bool
	if err := db.DB.QueryRow(
		"SELECT COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0) FROM users WHERE id = ?", userID,
	).Scan(&encryptedSecret, &totpEnabled); err != nil {
		InternalError(c, "Failed to query user")
		return
	}

	if !totpEnabled || encryptedSecret == "" {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, "Two-factor authentication is not enabled")
		return
	}

	// Decrypt the secret
	secret, err := DecryptKey(encryptedSecret)
	if err != nil {
		slog.Error("failed to decrypt TOTP secret", "user_id", userID, "error", err)
		InternalError(c, "Failed to verify TOTP secret")
		return
	}

	// Validate the code
	if !totp.Validate(req.Code, secret) {
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "Invalid verification code")
		return
	}

	// Clear the secret and disable 2FA
	if _, err := db.DB.Exec(
		"UPDATE users SET totp_secret = '', totp_enabled = 0 WHERE id = ?", userID,
	); err != nil {
		slog.Error("failed to disable TOTP", "user_id", userID, "error", err)
		InternalError(c, "Failed to disable two-factor authentication")
		return
	}

	// Audit trail
	username, _ := c.Get("username")
	uname, _ := username.(string)
	if uname == "" {
		db.DB.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&uname)
	}
	db.RecordAudit(userID, uname, "2fa_disabled", "user", "", "", c.ClientIP(), c.Request.UserAgent())

	slog.Info("2FA disabled", "user_id", userID)
	c.JSON(http.StatusOK, gin.H{"message": "Two-factor authentication disabled"})
}
