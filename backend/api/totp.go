package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
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
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// pendingTTL is the lifetime of a pending TOTP secret before it expires.
const pendingTTL = 5 * time.Minute

// recoveryCodeCount is the number of backup codes generated.
const recoveryCodeCount = 8

// recoveryCodePattern matches the XXXX-XXXX format used by recovery codes.
var recoveryCodePattern = regexp.MustCompile(`^[A-Z0-9]{4}-[A-Z0-9]{4}$`)

// ── Recovery Code & TOTP Step Anti-Replay Helpers ─────────────────────────

func hashRecoveryCodes(codes []string) ([]string, error) {
	hashes := make([]string, len(codes))
	for i, code := range codes {
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash recovery code: %w", err)
		}
		hashes[i] = string(hash)
	}
	return hashes, nil
}

func storeHashedRecoveryCodesInTx(tx *sql.Tx, userID int, hashes []string) error {
	if _, err := tx.Exec("DELETE FROM recovery_codes WHERE user_id = ?", userID); err != nil {
		return fmt.Errorf("failed to clear old recovery codes: %w", err)
	}
	for _, hash := range hashes {
		if _, err := tx.Exec(
			"INSERT INTO recovery_codes (user_id, code_hash, used) VALUES (?, ?, 0)",
			userID, hash,
		); err != nil {
			return fmt.Errorf("failed to insert recovery code: %w", err)
		}
	}
	return nil
}

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

func verifyRecoveryCodeHash(storedHash, rawCode string) bool {
	trimmedHash := strings.TrimSpace(storedHash)
	normalized := strings.ToUpper(strings.TrimSpace(rawCode))
	compact := strings.ReplaceAll(normalized, "-", "")
	if trimmedHash == "" || compact == "" {
		return false
	}

	if rest, ok := strings.CutPrefix(trimmedHash, "sha256:v1:"); ok {
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) != 2 {
			return false
		}
		saltBytes, sErr := hex.DecodeString(parts[0])
		expectedDigest, dErr := hex.DecodeString(parts[1])
		if sErr != nil || dErr != nil || len(saltBytes) != 16 || len(expectedDigest) != sha256.Size {
			return false
		}
		h := sha256.New()
		_, _ = h.Write([]byte("aetherflow-recovery-v1\x00"))
		_, _ = h.Write(saltBytes)
		_, _ = h.Write([]byte(compact))
		actual := h.Sum(nil)
		return subtle.ConstantTimeCompare(actual, expectedDigest) == 1
	}

	if len(trimmedHash) == 64 {
		if expectedDigest, err := hex.DecodeString(trimmedHash); err == nil && len(expectedDigest) == sha256.Size {
			sumNorm := sha256.Sum256([]byte(normalized))
			if subtle.ConstantTimeCompare(sumNorm[:], expectedDigest) == 1 {
				return true
			}
			sumComp := sha256.Sum256([]byte(compact))
			return subtle.ConstantTimeCompare(sumComp[:], expectedDigest) == 1
		}
	}

	if bcrypt.CompareHashAndPassword([]byte(trimmedHash), []byte(normalized)) == nil {
		return true
	}
	if compact != normalized && bcrypt.CompareHashAndPassword([]byte(trimmedHash), []byte(compact)) == nil {
		return true
	}
	return false
}

// validateRecoveryCodeInTx checks a recovery code inside tx and atomically marks it used
// via `WHERE id = ? AND user_id = ? AND COALESCE(used, 0) = 0` (`RowsAffected() == 1`).
func validateRecoveryCodeInTx(tx *sql.Tx, userID int, code string) bool {
	if tx == nil || userID <= 0 || code == "" {
		return false
	}
	type candidate struct {
		id   int
		hash string
	}
	rows, err := tx.Query(
		"SELECT id, code_hash FROM recovery_codes WHERE user_id = ? AND COALESCE(used, 0) = 0",
		userID,
	)
	if err != nil {
		return false
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if scanErr := rows.Scan(&c.id, &c.hash); scanErr == nil {
			candidates = append(candidates, c)
		}
	}
	_ = rows.Close()

	matchedID := -1
	for _, cand := range candidates {
		if verifyRecoveryCodeHash(cand.hash, code) {
			matchedID = cand.id
			break
		}
	}
	if matchedID == -1 {
		return false
	}

	res, err := tx.Exec(
		"UPDATE recovery_codes SET used = 1 WHERE id = ? AND user_id = ? AND COALESCE(used, 0) = 0",
		matchedID, userID,
	)
	if err != nil {
		return false
	}
	affected, rErr := res.RowsAffected()
	return rErr == nil && affected == 1
}

// matchTOTPStepAt validates a 6-digit TOTP code across [nowStep-1, nowStep, nowStep+1] with Skew: 0
// so we know the exact 30-second RFC 6238 counter step matched for anti-replay accounting.
func matchTOTPStepAt(code, secret string, now time.Time) (int64, bool) {
	trimmed := strings.TrimSpace(code)
	if len(trimmed) != 6 || secret == "" {
		return 0, false
	}
	nowStep := now.UTC().Unix() / 30
	opts := totp.ValidateOpts{
		Period:    30,
		Skew:      0,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	for _, step := range []int64{nowStep, nowStep - 1, nowStep + 1} {
		stepTime := time.Unix(step*30, 0).UTC()
		ok, err := totp.ValidateCustom(trimmed, secret, stepTime, opts)
		if err == nil && ok {
			return step, true
		}
	}
	return 0, false
}

// validateAndRecordTOTPStepInTx verifies a TOTP code and atomically advances `users.last_totp_step`
// inside tx (`COALESCE(last_totp_step, -1) < matchedStep`) so no 6-digit code can be replayed.
func validateAndRecordTOTPStepInTx(tx *sql.Tx, userID int, code, secret string) bool {
	if tx == nil || userID <= 0 {
		return false
	}
	matchedStep, ok := matchTOTPStepAt(code, secret, time.Now().UTC())
	if !ok {
		return false
	}
	res, err := tx.Exec(
		"UPDATE users SET last_totp_step = ? WHERE id = ? AND COALESCE(last_totp_step, -1) < ?",
		matchedStep, userID, matchedStep,
	)
	if err != nil && strings.Contains(err.Error(), "no such column") {
		return true
	}
	if err != nil {
		return false
	}
	affected, rErr := res.RowsAffected()
	return rErr == nil && affected == 1
}

// ── Setup 2FA ─────────────────────────────────────────────────────────────

// Setup2FA godoc
// @Summary      Initialize 2FA enrollment
// @Description  Generates a new TOTP key for the authenticated user and returns
//
//	the otpauth:// URI for QR code rendering. The secret is held in
//	an ephemeral cache (Redis or in-memory) for 5 minutes until the
//	user verifies it with a valid code.
//
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
//
//	the encrypted secret to the database, marks totp_enabled=1,
//	and generates one-time recovery codes.
//
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

	var existingEnabled int
	if err := db.DB.QueryRow("SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?", userID).Scan(&existingEnabled); err == nil && existingEnabled == 1 {
		db.Delete2FAPending(userID)
		RespondError(c, http.StatusConflict, ErrCodeConflict, "Two-factor authentication is already enabled")
		return
	}

	// Retrieve the pending secret
	secret, err := db.Get2FAPending(userID)
	if err != nil {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation,
			"No pending 2FA enrollment found. Please initiate setup again.")
		return
	}

	matchedStep, ok := matchTOTPStepAt(req.Code, secret, time.Now().UTC())
	if !ok {
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

	recoveryCodes, rcErr := generateRecoveryCodes(recoveryCodeCount)
	if rcErr != nil {
		slog.Error("failed to generate recovery codes", "user_id", userID, "error", rcErr)
		InternalError(c, "Failed to generate recovery codes")
		return
	}
	recoveryHashes, rcErr := hashRecoveryCodes(recoveryCodes)
	if rcErr != nil {
		slog.Error("failed to hash recovery codes", "user_id", userID, "error", rcErr)
		InternalError(c, "Failed to secure recovery codes")
		return
	}

	tx, release, txErr := db.BeginWriteTx()
	if txErr != nil {
		InternalError(c, "Database unavailable")
		return
	}
	defer release()

	updRes, updErr := tx.Exec(
		"UPDATE users SET totp_secret = ?, totp_enabled = 1, last_totp_step = ? WHERE id = ? AND COALESCE(totp_enabled, 0) = 0",
		encrypted, matchedStep, userID,
	)
	if updErr != nil && strings.Contains(updErr.Error(), "no such column") {
		updRes, updErr = tx.Exec(
			"UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ? AND COALESCE(totp_enabled, 0) = 0",
			encrypted, userID,
		)
	}
	if updErr != nil {
		slog.Error("failed to persist TOTP enrollment", "user_id", userID, "error", updErr)
		InternalError(c, "Failed to enable two-factor authentication")
		return
	}
	if affected, _ := updRes.RowsAffected(); affected == 0 {
		var alreadyEnabled bool
		_ = tx.QueryRow("SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?", userID).Scan(&alreadyEnabled)
		release()
		if alreadyEnabled {
			db.Delete2FAPending(userID)
			RespondError(c, http.StatusConflict, ErrCodeConflict, "Two-factor authentication is already enabled")
			return
		}
		NotFoundError(c, "User not found")
		return
	}

	if err := storeHashedRecoveryCodesInTx(tx, userID, recoveryHashes); err != nil {
		slog.Error("failed to store recovery codes", "user_id", userID, "error", err)
		InternalError(c, "Failed to persist recovery codes")
		return
	}

	if err := db.CommitWriteTx(tx, release); err != nil {
		slog.Error("failed to commit TOTP enrollment", "user_id", userID, "error", err)
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

	slog.Info("2FA enabled successfully", "user_id", userID, "recovery_codes_generated", len(recoveryCodes))
	c.JSON(http.StatusOK, gin.H{
		"message":        "Two-factor authentication enabled",
		"recovery_codes": recoveryCodes,
	})
}

// ── Disable 2FA ───────────────────────────────────────────────────────────

// Disable2FA godoc
// @Summary      Disable 2FA
// @Description  Validates a current TOTP or recovery code (never password-only), then clears
//
//	the secret, disables 2FA, deletes recovery codes, and rotates credential epoch.
//
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        req body object true "TOTP or recovery code"
// @Success      200 {object} map[string]interface{}
// @Failure      400 {object} map[string]interface{}
// @Failure      401 {object} map[string]interface{}
// @Failure      500 {object} map[string]interface{}
// @Router       /auth/user/2fa/disable [post]
func Disable2FA(c *gin.Context) {
	rawUserID, _ := c.Get("user_id")
	userID := rawUserID.(int)

	var req struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, "A valid TOTP or recovery code is required")
		return
	}
	code := strings.TrimSpace(req.Code)
	password := req.Password
	if code == "" {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, "A valid TOTP or recovery code is required to disable 2FA")
		return
	}

	var encryptedSecret, passwordHash string
	var totpEnabled bool
	if err := db.DB.QueryRow(
		"SELECT COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0), COALESCE(password_hash, '') FROM users WHERE id = ?", userID,
	).Scan(&encryptedSecret, &totpEnabled, &passwordHash); err != nil {
		InternalError(c, "Failed to query user")
		return
	}

	if !totpEnabled || encryptedSecret == "" {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, "Two-factor authentication is not enabled")
		return
	}

	if password != "" && passwordHash != "" {
		if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)) != nil {
			RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "Invalid verification factor")
			return
		}
	}

	isRecovery := recoveryCodePattern.MatchString(strings.ToUpper(code))
	var decryptedSecret string
	if !isRecovery {
		var decErr error
		decryptedSecret, decErr = DecryptKey(encryptedSecret)
		if decErr != nil {
			slog.Error("failed to decrypt TOTP secret", "user_id", userID, "error", decErr)
			InternalError(c, "Failed to verify TOTP secret")
			return
		}
	}

	tx, release, txErr := db.BeginWriteTx()
	if txErr != nil {
		InternalError(c, "Database unavailable")
		return
	}
	defer release()

	var verified bool
	if isRecovery {
		verified = validateRecoveryCodeInTx(tx, userID, strings.ToUpper(code))
	} else {
		verified = validateAndRecordTOTPStepInTx(tx, userID, code, decryptedSecret)
	}
	if !verified {
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "Invalid verification factor")
		return
	}

	if _, err := tx.Exec(
		"UPDATE users SET totp_secret = '', totp_enabled = 0 WHERE id = ?", userID,
	); err != nil {
		slog.Error("failed to disable TOTP", "user_id", userID, "error", err)
		InternalError(c, "Failed to disable two-factor authentication")
		return
	}

	_, _ = tx.Exec("DELETE FROM recovery_codes WHERE user_id = ?", userID)

	newVer, revokedJTIs, revErr := revokeAllUserCredentialsInTx(tx, userID)
	if revErr != nil {
		InternalError(c, "Failed to revoke concurrent credentials")
		return
	}

	rotatedToken, _, tokErr := createSessionJWTInTx(tx, userID, c, time.Now().UTC().Unix(), "", newVer)
	if tokErr != nil {
		InternalError(c, "Failed to rotate session")
		return
	}

	if err := db.CommitWriteTx(tx, release); err != nil {
		InternalError(c, "Failed to commit two-factor disablement")
		return
	}

	finalizeUserCredentialRevocation(userID, revokedJTIs)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("aetherflow_session", rotatedToken, sessionCookieMaxAge, "/", "", secureCookie(), true)

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
//
//	challenge token from the login flow. On success, issues a session JWT.
//
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

	tx, release, txErr := db.BeginWriteTx()
	if txErr != nil {
		InternalError(c, "Database unavailable")
		return
	}
	defer release()

	userID, challengeVer, ok, attemptErr := db.BeginMFAAttemptWithEpochInTx(tx, req.MFAToken)
	if attemptErr != nil {
		InternalError(c, "Failed to verify MFA challenge")
		return
	}
	if !ok {
		_ = db.CommitWriteTx(tx, release)
		db.EvictMFAChallengeCache(req.MFAToken)
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "MFA challenge expired or invalid. Please log in again.")
		return
	}

	subj, subErr := loadActiveHumanSubject(tx, userID)
	if subErr != nil {
		_, _ = tx.Exec("DELETE FROM mfa_challenges WHERE token = ?", req.MFAToken)
		_ = db.CommitWriteTx(tx, release)
		db.EvictMFAChallengeCache(req.MFAToken)
		if errors.Is(subErr, errSubjectSuspended) {
			RespondError(c, http.StatusForbidden, ErrCodeForbidden, "Account is not active")
			return
		}
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "User not found")
		return
	}
	if subj.sessionsRevokedAfter != challengeVer {
		_, _ = tx.Exec("DELETE FROM mfa_challenges WHERE token = ?", req.MFAToken)
		_ = db.CommitWriteTx(tx, release)
		db.EvictMFAChallengeCache(req.MFAToken)
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "MFA challenge expired or invalid. Please log in again.")
		return
	}

	// Fetch user + encrypted TOTP secret inside the same transaction
	var user models.User
	var encryptedSecret string
	var googleId sql.NullString
	var totpEnabled bool
	if err := tx.QueryRow(
		"SELECT id, username, email, avatar_url, role, google_id, COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0) FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.Username, &user.Email, &user.AvatarURL, &user.Role, &googleId, &encryptedSecret, &totpEnabled); err != nil {
		InternalError(c, "User not found")
		return
	}
	if !totpEnabled {
		_, _ = tx.Exec("DELETE FROM mfa_challenges WHERE token = ?", req.MFAToken)
		_ = db.CommitWriteTx(tx, release)
		db.EvictMFAChallengeCache(req.MFAToken)
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "TOTP not configured")
		return
	}
	user.IsOAuth = googleId.Valid && googleId.String != ""
	user.TOTPEnabled = true

	// Determine if this is a TOTP code or a recovery code
	code := strings.TrimSpace(req.Code)
	isRecoveryCode := recoveryCodePattern.MatchString(strings.ToUpper(code))
	codeValid := false

	if isRecoveryCode {
		codeValid = validateRecoveryCodeInTx(tx, userID, strings.ToUpper(code))
	} else {
		if encryptedSecret == "" {
			_ = db.CommitWriteTx(tx, release)
			RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "TOTP not configured")
			return
		}
		secret, err := DecryptKey(encryptedSecret)
		if err != nil {
			slog.Error("failed to decrypt TOTP secret during MFA login", "user_id", userID, "error", err)
			InternalError(c, "Failed to verify credentials")
			return
		}
		codeValid = validateAndRecordTOTPStepInTx(tx, userID, code, secret)
	}

	if !codeValid {
		// Commit the incremented attempt counter before returning 401
		_ = db.CommitWriteTx(tx, release)
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "Invalid verification code")
		return
	}

	consumed, consumeErr := db.ConsumeMFAChallengeWithEpochInTx(tx, req.MFAToken, userID, challengeVer)
	if consumeErr != nil || !consumed {
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "MFA challenge expired or invalid. Please log in again.")
		return
	}

	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()
	_, _ = tx.Exec("INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?, ?, ?)", user.ID, clientIP, userAgent)

	tokenString, _, err := createSessionJWTInTx(tx, user.ID, c, time.Now().UTC().Unix(), "", subj.sessionsRevokedAfter)
	if err != nil {
		InternalError(c, "Failed to create session")
		return
	}

	if err := db.CommitWriteTx(tx, release); err != nil {
		InternalError(c, "Failed to commit MFA session")
		return
	}
	db.EvictMFAChallengeCache(req.MFAToken)

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("aetherflow_session", tokenString, sessionCookieMaxAge, "/", "", secureCookie(), true)

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
//
//	Requires a valid TOTP or recovery code to authorize the regeneration.
//
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
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, "A valid TOTP or recovery code is required")
		return
	}
	code := strings.TrimSpace(req.Code)
	if code == "" {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, "A valid TOTP or recovery code is required")
		return
	}

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

	isRecovery := recoveryCodePattern.MatchString(strings.ToUpper(code))
	var secret string
	if !isRecovery {
		var decErr error
		secret, decErr = DecryptKey(encryptedSecret)
		if decErr != nil {
			slog.Error("failed to decrypt TOTP secret for recovery regen", "user_id", userID, "error", decErr)
			InternalError(c, "Failed to verify credentials")
			return
		}
	}

	codes, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		slog.Error("failed to generate recovery codes", "user_id", userID, "error", err)
		InternalError(c, "Failed to generate recovery codes")
		return
	}
	hashes, err := hashRecoveryCodes(codes)
	if err != nil {
		slog.Error("failed to hash recovery codes", "user_id", userID, "error", err)
		InternalError(c, "Failed to store recovery codes")
		return
	}

	tx, release, txErr := db.BeginWriteTx()
	if txErr != nil {
		InternalError(c, "Database unavailable")
		return
	}
	defer release()

	var verified bool
	if isRecovery {
		verified = validateRecoveryCodeInTx(tx, userID, strings.ToUpper(code))
	} else {
		verified = validateAndRecordTOTPStepInTx(tx, userID, code, secret)
	}
	if !verified {
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "Invalid verification code")
		return
	}

	if err := storeHashedRecoveryCodesInTx(tx, userID, hashes); err != nil {
		slog.Error("failed to store recovery codes", "user_id", userID, "error", err)
		InternalError(c, "Failed to store recovery codes")
		return
	}

	if err := db.CommitWriteTx(tx, release); err != nil {
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
