package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
)

var aesMasterKey []byte

// InitAESKey loads the AES-256 master key from the AES_MASTER_KEY environment variable.
// The key must be exactly 32 bytes (either raw or base64-encoded).
// In production (GIN_MODE=release), the server will refuse to start without it.
// In dev/test modes, a warning is logged and encryption is disabled.
func InitAESKey() {
	raw := os.Getenv("AES_MASTER_KEY")
	if raw == "" {
		if gin.Mode() == gin.ReleaseMode {
			log.Fatal("FATAL: AES_MASTER_KEY is required in production (GIN_MODE=release). " +
				"Set a 32-byte key (raw or base64-encoded) to enable API key encryption.")
		}
		log.Println("WARNING: AES_MASTER_KEY not set. API key encryption is disabled (dev/test mode only).")
		return
	}

	// Try base64 first, then raw bytes.
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err == nil && len(decoded) == 32 {
		aesMasterKey = decoded
	} else if len(raw) == 32 {
		aesMasterKey = []byte(raw)
	} else {
		log.Fatal("FATAL: AES_MASTER_KEY must be exactly 32 bytes (AES-256). Got ", len(raw), " raw bytes.")
	}

	log.Println("AES-256-GCM encryption key loaded successfully.")
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
	if !IsEncryptionEnabled() {
		return nil
	}
	var apiKey string
	err := db.DB.QueryRow("SELECT COALESCE(gemini_api_key, '') FROM settings WHERE id = 1").Scan(&apiKey)
	if err != nil {
		return err
	}
	if apiKey != "" && !strings.HasPrefix(apiKey, ciphertextPrefix) {
		enc, err := EncryptKey(apiKey)
		if err != nil {
			return err
		}
		if _, err := db.DB.Exec("UPDATE settings SET gemini_api_key = ? WHERE id = 1", enc); err != nil {
			return err
		}
		log.Println("[crypto] Successfully migrated legacy gemini_api_key to enc:v1: format")
	}
	return nil
}
