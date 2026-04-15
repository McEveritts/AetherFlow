package api

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"aetherflow/db"
	"aetherflow/models"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// pendingTTL is the lifetime of a pending TOTP secret before it expires.
const pendingTTL = 5 * time.Minute

// recoveryCodeCount is the number of backup codes generated.
const recoveryCodeCount = 8

// recoveryCodePattern matches the XXXX-XXXX format used by recovery codes.
var recoveryCodePattern = regexp.MustCompile(`^[A-Z0-9]{4}-[A-Z0-9]{4}$`)

// ── Recovery Code Helpers ─────────────────────────────────────────────────

// generateRecoveryCodes creates N random codes in XXXX-XXXX format.
func generateRecoveryCodes(count int) ([]string, error) {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no I/O/0/1 to avoid confusion
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		code := make([]byte, 8)
		for j := 0; j < 8; j++ {
			idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
			if err != nil {
				return nil, fmt.Errorf("failed to generate random index: %w", err)
			}
			code[j] = charset[idx.Int64()]
		}
		codes[i] = string(code[:4]) + "-" + string(code[4:])
	}
	return codes, nil
}

// storeRecoveryCodes hashes and persists recovery codes for a user, replacing any existing ones.
func storeRecoveryCodes(userID int, codes []string) error {
	// Delete existing codes first
	if _, err := db.DB.Exec("DELETE FROM recovery_codes WHERE user_id = ?", userID); err != nil {
		return fmt.Errorf("failed to clear old recovery codes: %w", err)
	}

	for _, code := range codes {
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash recovery code: %w", err)
		}
		if _, err := db.DB.Exec(
			"INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
			userID, string(hash),
		); err != nil {
			return fmt.Errorf("failed to insert recovery code: %w", err)
		}
	}
	return nil
}

// validateRecoveryCode checks a code against a user's stored hashes and marks it used if valid.
func validateRecoveryCode(userID int, code string) bool {
	rows, err := db.DB.Query(
		"SELECT id, code_hash FROM recovery_codes WHERE user_id = ? AND used = 0", userID,
	)
	if err != nil {
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var hash string
		if err := rows.Scan(&id, &hash); err != nil {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(code)) == nil {
			// Valid match — mark as used
			db.DB.Exec("UPDATE recovery_codes SET used = 1 WHERE id = ?", id)
			return true
		}
	}
	return false
}

// ── Setup 2FA ─────────────────────────────────────────────────────────────

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

// ── Verify 2FA Enrollment ─────────────────────────────────────────────────

// Verify2FA godoc
// @Summary      Confirm 2FA enrollment
// @Description  Validates a TOTP code against the pending secret, then persists
//               the encrypted secret to the database, marks totp_enabled=1,
//               and generates one-time recovery codes.
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

	// Generate recovery codes
	recoveryCodes, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		slog.Error("failed to generate recovery codes", "user_id", userID, "error", err)
		// Don't fail the entire enrollment — 2FA is already enabled
		recoveryCodes = []string{}
	} else {
		if err := storeRecoveryCodes(userID, recoveryCodes); err != nil {
			slog.Error("failed to store recovery codes", "user_id", userID, "error", err)
			recoveryCodes = []string{}
		}
	}

	// Audit trail
	username, _ := c.Get("username")
	uname, _ := username.(string)
	if uname == "" {
		db.DB.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&uname)
	}
	db.RecordAudit(userID, uname, "2fa_enabled", "user", "", "", c.ClientIP(), c.Request.UserAgent())

	slog.Info("2FA enabled successfully", "user_id", userID, "recovery_codes_generated", len(recoveryCodes))
	c.JSON(http.StatusOK, gin.H{
		"message":        "Two-factor authentication enabled",
		"recovery_codes": recoveryCodes,
	})
}

// ── Disable 2FA ───────────────────────────────────────────────────────────

// Disable2FA godoc
// @Summary      Disable 2FA
// @Description  Validates a current TOTP code, then clears the secret, disables 2FA,
//               and deletes all recovery codes.
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

	// Delete all recovery codes
	db.DB.Exec("DELETE FROM recovery_codes WHERE user_id = ?", userID)

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

// ── MFA Login Verification ────────────────────────────────────────────────

// MFALoginVerify godoc
// @Summary      Complete login with MFA code
// @Description  Validates a TOTP code or recovery code against a pending MFA
//               challenge token from the login flow. On success, issues a session JWT.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        req body object true "MFA token and code"
// @Success      200 {object} map[string]interface{}
// @Failure      400 {object} map[string]interface{}
// @Failure      401 {object} map[string]interface{}
// @Failure      500 {object} map[string]interface{}
// @Router       /public/auth/mfa/verify [post]
func MFALoginVerify(c *gin.Context) {
	var req struct {
		MFAToken string `json:"mfa_token" binding:"required"`
		Code     string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, "MFA token and code are required")
		return
	}

	// Look up the challenge
	userID, err := db.GetMFAChallenge(req.MFAToken)
	if err != nil {
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "MFA challenge expired or invalid. Please log in again.")
		return
	}

	// Fetch user + encrypted TOTP secret
	var user models.User
	var encryptedSecret string
	var googleId sql.NullString
	if err := db.DB.QueryRow(
		"SELECT id, username, email, avatar_url, role, google_id, COALESCE(totp_secret, '') FROM users WHERE id = ?", userID,
	).Scan(&user.ID, &user.Username, &user.Email, &user.AvatarURL, &user.Role, &googleId, &encryptedSecret); err != nil {
		InternalError(c, "User not found")
		return
	}
	user.IsOAuth = googleId.Valid && googleId.String != ""
	user.TOTPEnabled = true

	// Determine if this is a TOTP code or a recovery code
	code := strings.TrimSpace(req.Code)
	isRecoveryCode := recoveryCodePattern.MatchString(strings.ToUpper(code))
	codeValid := false

	if isRecoveryCode {
		// Validate recovery code (bcrypt comparison + mark used)
		codeValid = validateRecoveryCode(userID, strings.ToUpper(code))
	} else {
		// Validate TOTP code
		if encryptedSecret == "" {
			RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "TOTP not configured")
			return
		}
		secret, err := DecryptKey(encryptedSecret)
		if err != nil {
			slog.Error("failed to decrypt TOTP secret during MFA login", "user_id", userID, "error", err)
			InternalError(c, "Failed to verify credentials")
			return
		}
		codeValid = totp.Validate(code, secret)
	}

	if !codeValid {
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "Invalid verification code")
		return
	}

	// ── MFA verified — complete the login ──

	// Consume the challenge token (single use)
	db.DeleteMFAChallenge(req.MFAToken)

	// Log login
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()
	db.DB.Exec("INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?, ?, ?)", user.ID, clientIP, userAgent)

	// Issue JWT
	tokenString, err := createStandardJWT(user.ID, c)
	if err != nil {
		InternalError(c, "Failed to create session")
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("aetherflow_session", tokenString, 900, "/", "", secureCookie(), true)

	method := "totp"
	if isRecoveryCode {
		method = "recovery_code"
	}
	slog.Info("MFA login verified", "user_id", user.ID, "method", method)

	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "user": user})
}

// ── Recovery Code Regeneration ────────────────────────────────────────────

// Regenerate2FARecoveryCodes godoc
// @Summary      Regenerate recovery codes
// @Description  Generates a new set of recovery codes, invalidating all previous ones.
//               Requires a valid TOTP code to authorize the regeneration.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} map[string]interface{}
// @Failure      400 {object} map[string]interface{}
// @Failure      401 {object} map[string]interface{}
// @Failure      500 {object} map[string]interface{}
// @Router       /auth/user/2fa/recovery/regenerate [post]
func Regenerate2FARecoveryCodes(c *gin.Context) {
	rawUserID, _ := c.Get("user_id")
	userID := rawUserID.(int)

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, "A valid TOTP code is required")
		return
	}

	// Verify 2FA is enabled and TOTP code is valid
	var encryptedSecret string
	var totpEnabled bool
	if err := db.DB.QueryRow(
		"SELECT COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0) FROM users WHERE id = ?", userID,
	).Scan(&encryptedSecret, &totpEnabled); err != nil {
		InternalError(c, "Failed to query user")
		return
	}

	if !totpEnabled {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, "Two-factor authentication is not enabled")
		return
	}

	secret, err := DecryptKey(encryptedSecret)
	if err != nil {
		slog.Error("failed to decrypt TOTP secret for recovery regen", "user_id", userID, "error", err)
		InternalError(c, "Failed to verify credentials")
		return
	}

	if !totp.Validate(req.Code, secret) {
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "Invalid verification code")
		return
	}

	// Generate new recovery codes (replaces old ones)
	codes, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		slog.Error("failed to generate recovery codes", "user_id", userID, "error", err)
		InternalError(c, "Failed to generate recovery codes")
		return
	}

	if err := storeRecoveryCodes(userID, codes); err != nil {
		slog.Error("failed to store recovery codes", "user_id", userID, "error", err)
		InternalError(c, "Failed to store recovery codes")
		return
	}

	// Audit trail
	username, _ := c.Get("username")
	uname, _ := username.(string)
	if uname == "" {
		db.DB.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&uname)
	}
	db.RecordAudit(userID, uname, "2fa_recovery_regenerated", "user", "", "", c.ClientIP(), c.Request.UserAgent())

	slog.Info("2FA recovery codes regenerated", "user_id", userID)
	c.JSON(http.StatusOK, gin.H{
		"message":        "Recovery codes regenerated",
		"recovery_codes": codes,
	})
}
