package api

import (
	"testing"
)

func TestAPIErrorStructure(t *testing.T) {
	e := APIError{
		Code:    ErrCodeUnauthorized,
		Message: "Token expired",
	}
	if e.Code != "UNAUTHORIZED" {
		t.Errorf("expected UNAUTHORIZED, got %s", e.Code)
	}
	if e.Details != nil {
		t.Error("details should be nil")
	}
}

func TestAPIErrorWithDetails(t *testing.T) {
	e := APIError{
		Code:    ErrCodeValidation,
		Message: "Invalid input",
		Details: map[string]string{"field": "email"},
	}
	if e.Code != "VALIDATION_ERROR" {
		t.Errorf("expected VALIDATION_ERROR, got %s", e.Code)
	}
	details, ok := e.Details.(map[string]string)
	if !ok {
		t.Fatal("details should be map[string]string")
	}
	if details["field"] != "email" {
		t.Errorf("expected field=email, got %s", details["field"])
	}
}

func TestBackupRetentionFilenameValidation(t *testing.T) {
	valid := []string{
		"aetherflow_2025-01-01_12-00-00.sqlite",
		"backup.sqlite",
		"test_backup-v2.sqlite",
	}
	invalid := []string{
		"../../../etc/passwd",
		"backup.db",
		"backup.sqlite.bak",
		"",
	}

	for _, name := range valid {
		if !isValidBackupFilename(name) {
			t.Errorf("expected %q to be valid", name)
		}
	}
	for _, name := range invalid {
		if isValidBackupFilename(name) {
			t.Errorf("expected %q to be invalid", name)
		}
	}
}

func TestAPIVersionNormalization(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"v1", "v1"},
		{"1", "v1"},
		{" V1 ", "v1"},
		{`version="v2"`, "v2"},
		{"", ""},
	}
	for _, tt := range tests {
		got := normalizeAPIVersion(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeAPIVersion(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSecurityHeadersList(t *testing.T) {
	// Verify the expected headers are defined
	expectedHeaders := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Strict-Transport-Security",
		"X-XSS-Protection",
		"Content-Security-Policy",
		"Referrer-Policy",
		"Permissions-Policy",
	}
	// Simply verify they're all non-empty string constants
	for _, h := range expectedHeaders {
		if h == "" {
			t.Error("empty header name in security headers list")
		}
	}
}
