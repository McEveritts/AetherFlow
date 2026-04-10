package config

import (
	"os"
	"testing"
	"time"
)

func TestEnvOr(t *testing.T) {
	// Unset var should return default
	os.Unsetenv("TEST_CONFIG_XYZ")
	if got := envOr("TEST_CONFIG_XYZ", "fallback"); got != "fallback" {
		t.Errorf("expected fallback, got %s", got)
	}

	// Set var should return var
	os.Setenv("TEST_CONFIG_XYZ", "actual")
	defer os.Unsetenv("TEST_CONFIG_XYZ")
	if got := envOr("TEST_CONFIG_XYZ", "fallback"); got != "actual" {
		t.Errorf("expected actual, got %s", got)
	}
}

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"", 0},
		{"a,b,c", 3},
		{" a , b , c ", 3},
		{"single", 1},
	}
	for _, tt := range tests {
		result := splitCSV(tt.input)
		if len(result) != tt.expected {
			t.Errorf("splitCSV(%q) = %d items, want %d", tt.input, len(result), tt.expected)
		}
	}
}

func TestCoalesce(t *testing.T) {
	if got := coalesce("", "", "third"); got != "third" {
		t.Errorf("expected third, got %s", got)
	}
	if got := coalesce("first", "second"); got != "first" {
		t.Errorf("expected first, got %s", got)
	}
	if got := coalesce("", ""); got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestParseDurationOr(t *testing.T) {
	os.Setenv("TEST_DUR", "5s")
	defer os.Unsetenv("TEST_DUR")
	if got := parseDurationOr("TEST_DUR", time.Hour); got != 5*time.Second {
		t.Errorf("expected 5s, got %s", got)
	}

	os.Unsetenv("TEST_DUR_MISSING")
	if got := parseDurationOr("TEST_DUR_MISSING", 10*time.Minute); got != 10*time.Minute {
		t.Errorf("expected 10m, got %s", got)
	}

	os.Setenv("TEST_DUR_BAD", "not-a-duration")
	defer os.Unsetenv("TEST_DUR_BAD")
	if got := parseDurationOr("TEST_DUR_BAD", time.Hour); got != time.Hour {
		t.Errorf("expected 1h fallback, got %s", got)
	}
}

func TestLoadAndValidate(t *testing.T) {
	// Set minimum required env vars
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("AES_MASTER_KEY", "0123456789abcdef0123456789abcdef")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("AES_MASTER_KEY")

	Load()

	if Cfg == nil {
		t.Fatal("Cfg should not be nil after Load()")
	}
	if Cfg.JWTSecret != "test-secret" {
		t.Errorf("expected JWT_SECRET=test-secret, got %s", Cfg.JWTSecret)
	}
	if Cfg.Port != "8443" {
		// Default port
		t.Errorf("expected default port 8443, got %s", Cfg.Port)
	}

	err := Validate()
	if err != nil {
		t.Errorf("Validate() should not return fatal error: %v", err)
	}
}
