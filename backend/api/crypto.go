package api

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
)

var aesMasterKey []byte

func readLastAESKeyFromEnvFile(path string) string {
	cleaned := filepath.Clean(strings.TrimSpace(path))
	if cleaned == "" || !filepath.IsAbs(cleaned) {
		return ""
	}
	fd, err := syscall.Open(cleaned, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return ""
	}
	f := os.NewFile(uintptr(fd), cleaned)
	if f == nil {
		_ = syscall.Close(fd)
		return ""
	}
	defer f.Close()
	if fst, err := f.Stat(); err != nil || !fst.Mode().IsRegular() {
		return ""
	}

	var last string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		if strings.HasPrefix(line, "AES_MASTER_KEY=") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "AES_MASTER_KEY="))
			val = strings.Trim(val, `"'`)
			if val != "" {
				last = val
			}
		}
	}
	return last
}

// ParseAESKeyBytes decodes a 256-bit AES master key from 64-char hex, standard Base64, or 32-byte raw ASCII.
// Precedence checks 64-char hex BEFORE Base64 because any 64-char hex string is also valid unpadded Base64 (48 bytes).
func ParseAESKeyBytes(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) == 64 {
		if decodedHex, err := hex.DecodeString(trimmed); err == nil && len(decodedHex) == 32 {
			return decodedHex, nil
		}
	}
	if decodedB64, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decodedB64) == 32 {
		return decodedB64, nil
	}
	if len(trimmed) == 32 {
		return []byte(trimmed), nil
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	return nil, fmt.Errorf("AES_MASTER_KEY must decode to 32 bytes (64-char hex, base64, or 32-byte raw); got %d chars", len(trimmed))
}

// InitAESKey loads the AES-256 master key from AES_MASTER_KEY (or AETHERFLOW_ENV_FILE when explicitly configured).
// The key must decode to 32 bytes (64-char hex, standard base64, or 32-byte raw).
// In production (GIN_MODE=release), the server will refuse to start without it.
// In dev/test modes, a warning is logged and encryption is disabled.
func InitAESKey() {
	aesMasterKey = nil
	raw := strings.TrimSpace(os.Getenv("AES_MASTER_KEY"))
	if raw == "" && os.Getenv("AETHERFLOW_SKIP_ENV_FILES") != "1" {
		if envFile := strings.TrimSpace(os.Getenv("AETHERFLOW_ENV_FILE")); envFile != "" {
			raw = readLastAESKeyFromEnvFile(envFile)
		}
	}
	if raw == "" {
		if gin.Mode() == gin.ReleaseMode {
			log.Fatal("FATAL: AES_MASTER_KEY is required in production (GIN_MODE=release). " +
				"Set a 32-byte key (64-char hex, base64, or 32-byte raw) to enable API key encryption.")
		}
		slog.Info("WARNING: AES_MASTER_KEY not set. API key encryption is disabled (dev/test mode only).")
		return
	}

	parsed, err := ParseAESKeyBytes(raw)
	if err != nil {
		log.Fatal("FATAL: ", err)
	}
	aesMasterKey = parsed

	slog.Info("AES-256-GCM encryption key loaded successfully.")
}

// IsEncryptionEnabled returns whether AES encryption is configured.
func IsEncryptionEnabled() bool {
	return len(aesMasterKey) == 32
}

// ciphertextPrefix marks values encrypted by this module.
// Values with this prefix are parsed strictly; tampered data returns an error.
// Values WITHOUT this prefix are treated as legacy plaintext (migration-safe).
const ciphertextPrefix = "enc:v1:"

// EncryptKey encrypts plaintext using AES-256-GCM with a cryptographically random nonce.
// Returns a versioned string: "enc:v1:<base64(nonce || ciphertext)>".
func EncryptKey(plaintext string) (string, error) {
	if !IsEncryptionEnabled() {
		return plaintext, nil // Passthrough when encryption is not configured.
	}

	block, err := aes.NewCipher(aesMasterKey)
	if err != nil {
		return "", fmt.Errorf("aes cipher creation failed: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm creation failed: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}

	// Seal appends the ciphertext to the nonce slice.
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return ciphertextPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptKey decrypts a versioned ciphertext produced by EncryptKey.
// - "enc:v1:<base64>" → strict decryption; errors on tampered data
func DecryptKey(encoded string) (string, error) {
	if !IsEncryptionEnabled() {
		return encoded, nil // Passthrough when encryption is not configured.
	}

	// Versioned ciphertext: strict decryption, no silent fallback
	if strings.HasPrefix(encoded, ciphertextPrefix) {
		payload := strings.TrimPrefix(encoded, ciphertextPrefix)
		data, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return "", fmt.Errorf("versioned ciphertext base64 decode failed: %w", err)
		}
		return decryptGCM(data)
	}

	// If no match to our version, fail entirely. Legacy is no longer supported!
	return "", errors.New("ciphertext tampered or missing required version prefix")
}

// decryptGCM performs the raw AES-GCM decryption on decoded bytes.
func decryptGCM(data []byte) (string, error) {
	block, err := aes.NewCipher(aesMasterKey)
	if err != nil {
		return "", fmt.Errorf("aes cipher creation failed: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm creation failed: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("gcm decryption failed: %w", err)
	}

	return string(plaintext), nil
}

// MigrateLegacySecrets scans the database for known sensitive keys that lack the enc:v1: prefix and encrypts them.
func MigrateLegacySecrets() error {
	if !IsEncryptionEnabled() || db.DB == nil {
		return nil
	}

	tx, release, err := db.BeginWriteTx()
	if err != nil {
		return err
	}
	defer release()

	if sqlTableExists(tx, "settings") {
		var geminiKey, openaiKey, anthropicKey string
		if sErr := tx.QueryRow(
			"SELECT COALESCE(gemini_api_key, ''), COALESCE(openai_api_key, ''), COALESCE(anthropic_api_key, '') FROM settings WHERE id = 1",
		).Scan(&geminiKey, &openaiKey, &anthropicKey); sErr == nil {
			if geminiKey != "" && !strings.HasPrefix(geminiKey, ciphertextPrefix) {
				enc, encErr := EncryptKey(geminiKey)
				if encErr != nil {
					return encErr
				}
				if _, uErr := tx.Exec("UPDATE settings SET gemini_api_key = ? WHERE id = 1", enc); uErr != nil {
					return uErr
				}
				slog.Info("[crypto] Migrated legacy settings.gemini_api_key to enc:v1: format")
			}
			if openaiKey != "" && !strings.HasPrefix(openaiKey, ciphertextPrefix) {
				enc, encErr := EncryptKey(openaiKey)
				if encErr != nil {
					return encErr
				}
				if _, uErr := tx.Exec("UPDATE settings SET openai_api_key = ? WHERE id = 1", enc); uErr != nil {
					return uErr
				}
				slog.Info("[crypto] Migrated legacy settings.openai_api_key to enc:v1: format")
			}
			if anthropicKey != "" && !strings.HasPrefix(anthropicKey, ciphertextPrefix) {
				enc, encErr := EncryptKey(anthropicKey)
				if encErr != nil {
					return encErr
				}
				if _, uErr := tx.Exec("UPDATE settings SET anthropic_api_key = ? WHERE id = 1", enc); uErr != nil {
					return uErr
				}
				slog.Info("[crypto] Migrated legacy settings.anthropic_api_key to enc:v1: format")
			}
		}
	}

	if sqlTableExists(tx, "users") {
		type userTotpRow struct {
			id     int
			secret string
		}
		var pending []userTotpRow
		rows, qErr := tx.Query("SELECT id, COALESCE(totp_secret, '') FROM users WHERE COALESCE(totp_secret, '') != ''")
		if qErr != nil {
			return qErr
		}
		for rows.Next() {
			var r userTotpRow
			if sErr := rows.Scan(&r.id, &r.secret); sErr != nil {
				_ = rows.Close()
				return sErr
			}
			if r.secret != "" && !strings.HasPrefix(r.secret, ciphertextPrefix) {
				pending = append(pending, r)
			}
		}
		if rErr := rows.Err(); rErr != nil {
			_ = rows.Close()
			return rErr
		}
		_ = rows.Close()
		for _, r := range pending {
			enc, encErr := EncryptKey(r.secret)
			if encErr != nil {
				return encErr
			}
			if _, uErr := tx.Exec("UPDATE users SET totp_secret = ? WHERE id = ?", enc, r.id); uErr != nil {
				return uErr
			}
			slog.Info("[crypto] Migrated legacy users.totp_secret to enc:v1: format", "user_id", r.id)
		}
	}

	if sqlTableExists(tx, "streaming_servers") {
		type srvRow struct {
			id  int
			key string
		}
		var pending []srvRow
		rows, qErr := tx.Query("SELECT id, COALESCE(api_key, '') FROM streaming_servers WHERE COALESCE(api_key, '') != ''")
		if qErr != nil {
			return qErr
		}
		for rows.Next() {
			var r srvRow
			if sErr := rows.Scan(&r.id, &r.key); sErr != nil {
				_ = rows.Close()
				return sErr
			}
			if r.key != "" && !strings.HasPrefix(r.key, ciphertextPrefix) {
				pending = append(pending, r)
			}
		}
		if rErr := rows.Err(); rErr != nil {
			_ = rows.Close()
			return rErr
		}
		_ = rows.Close()
		for _, r := range pending {
			enc, encErr := EncryptKey(r.key)
			if encErr != nil {
				return encErr
			}
			if _, uErr := tx.Exec("UPDATE streaming_servers SET api_key = ? WHERE id = ?", enc, r.id); uErr != nil {
				return uErr
			}
			slog.Info("[crypto] Migrated legacy streaming_servers.api_key to enc:v1: format", "server_id", r.id)
		}
	}

	return db.CommitWriteTx(tx, release)
}
