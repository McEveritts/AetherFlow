package api

import (
	"os"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	// Set a test key
	os.Setenv("AES_MASTER_KEY", "test-key-exactly-32-bytes-long!!")
	defer os.Unsetenv("AES_MASTER_KEY")
	aesMasterKey = []byte("test-key-exactly-32-bytes-long!!")
	defer func() { aesMasterKey = nil }()

	tests := []struct {
		name      string
		plaintext string
	}{
		{"short key", "AIzaSyA_test_key_12345"},
		{"empty string", ""},
		{"long key", "sk-ant-this-is-a-very-long-api-key-that-should-also-work-correctly-1234567890"},
		{"special chars", "key/with+special=chars&more"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptKey(tt.plaintext)
			if err != nil {
				t.Fatalf("EncryptKey failed: %v", err)
			}

			if tt.plaintext != "" && encrypted == tt.plaintext {
				t.Error("Encrypted text should differ from plaintext")
			}

			decrypted, err := DecryptKey(encrypted)
			if err != nil {
				t.Fatalf("DecryptKey failed: %v", err)
			}

			if decrypted != tt.plaintext {
				t.Errorf("Roundtrip failed: got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	// Encrypt with one key
	os.Setenv("AES_MASTER_KEY", "test-key-exactly-32-bytes-long!!")
	aesMasterKey = []byte("test-key-exactly-32-bytes-long!!")

	encrypted, err := EncryptKey("my-secret-api-key")
	if err != nil {
		t.Fatalf("EncryptKey failed: %v", err)
	}

	// Switch to a different key
	aesMasterKey = []byte("different-key-exactly-32-bytes!!")

	// With versioned ciphertext (enc:v1: prefix), DecryptKey MUST error on wrong key.
	// This is the security-critical behavior change: no silent fallback.
	result, err := DecryptKey(encrypted)
	if err == nil {
		t.Fatal("DecryptKey with wrong key should return error for versioned ciphertext")
	}

	// Should NOT decrypt to the original plaintext
	if result == "my-secret-api-key" {
		t.Error("Decryption with wrong key should NOT produce the original plaintext")
	}

	// Cleanup
	aesMasterKey = nil
	os.Unsetenv("AES_MASTER_KEY")
}

func TestEncryptionDisabledPassthrough(t *testing.T) {
	// With no key set, encryption should be a no-op passthrough
	aesMasterKey = nil

	plaintext := "my-api-key-in-plaintext"
	encrypted, err := EncryptKey(plaintext)
	if err != nil {
		t.Fatalf("EncryptKey (disabled) failed: %v", err)
	}
	if encrypted != plaintext {
		t.Error("With encryption disabled, EncryptKey should pass through plaintext")
	}

	decrypted, err := DecryptKey(plaintext)
	if err != nil {
		t.Fatalf("DecryptKey (disabled) failed: %v", err)
	}
	if decrypted != plaintext {
		t.Error("With encryption disabled, DecryptKey should pass through plaintext")
	}
}

func TestIsValidBackupFilename(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"aetherflow_2026-03-31_15-04-05.sqlite", true},
		{"backup_test.sqlite", true},
		{"my_backup-v2.sqlite", true},
		{"../../../etc/passwd", false},
		{"backup.sqlite.sh", false},
		{"; rm -rf /", false},
		{"", false},
		{"backup.db", false},
		{"backup%00.sqlite", false},
		{"backup\x00.sqlite", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidBackupFilename(tt.name)
			if got != tt.valid {
				t.Errorf("isValidBackupFilename(%q) = %v, want %v", tt.name, got, tt.valid)
			}
		})
	}
}

// --- Phase 22: Extended Crypto Security Tests ---

func TestTamperedCiphertextDetection(t *testing.T) {
	aesMasterKey = []byte("test-key-exactly-32-bytes-long!!")
	defer func() { aesMasterKey = nil }()

	encrypted, err := EncryptKey("sensitive-api-key")
	if err != nil {
		t.Fatalf("EncryptKey failed: %v", err)
	}

	// Tamper with the ciphertext by flipping a character
	if len(encrypted) > 5 {
		tampered := []byte(encrypted)
		tampered[5] ^= 0xFF // flip bits
		tamperedStr := string(tampered)

		// DecryptKey should NOT return the original plaintext
		result, _ := DecryptKey(tamperedStr)
		if result == "sensitive-api-key" {
			t.Error("Tampered ciphertext should NOT decrypt to original plaintext")
		}
	}
}

func TestNonceUniqueness(t *testing.T) {
	aesMasterKey = []byte("test-key-exactly-32-bytes-long!!")
	defer func() { aesMasterKey = nil }()

	plaintext := "same-plaintext-for-all"
	results := make(map[string]bool)

	// Encrypt the same plaintext 20 times — each output should be unique
	// due to random nonce generation
	for i := 0; i < 20; i++ {
		encrypted, err := EncryptKey(plaintext)
		if err != nil {
			t.Fatalf("EncryptKey iteration %d failed: %v", i, err)
		}
		if results[encrypted] {
			t.Errorf("Nonce collision detected on iteration %d — same ciphertext produced for same plaintext", i)
		}
		results[encrypted] = true
	}

	if len(results) != 20 {
		t.Errorf("Expected 20 unique ciphertexts, got %d", len(results))
	}
}

func TestShortCiphertextRejection(t *testing.T) {
	aesMasterKey = []byte("test-key-exactly-32-bytes-long!!")
	defer func() { aesMasterKey = nil }()

	// Try to decrypt a very short base64 string (shorter than nonce size)
	// This should not panic and should gracefully handle it
	shortInputs := []string{
		"AAAA",     // Very short (3 bytes decoded)
		"AAAAAAAA", // Still short
		"",         // Empty
	}

	for _, input := range shortInputs {
		result, err := DecryptKey(input)
		// Should either error or return passthrough — but never panic
		if err != nil && result != "" {
			t.Errorf("Unexpected state: error=%v but result=%q", err, result)
		}
	}
}

