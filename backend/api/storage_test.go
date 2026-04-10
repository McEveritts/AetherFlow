package api

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// ── Phase 29: Storage Domain — Backup & Checksum Tests ──────────────────
//
// These tests verify the storage/backup pipeline: path sanitization,
// filename validation, SHA-256 checksum computation, and the checksum
// persistence round-trip.

// --- Path Sanitization Tests ---

func TestSafeBackupPath_ValidFilename(t *testing.T) {
	baseDir := t.TempDir()
	path, err := safeBackupPath(baseDir, "backup_2024-01-01.sqlite")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if filepath.Base(path) != "backup_2024-01-01.sqlite" {
		t.Errorf("Expected basename backup_2024-01-01.sqlite, got %q", filepath.Base(path))
	}
}

func TestSafeBackupPath_TraversalNeutralized(t *testing.T) {
	baseDir := t.TempDir()

	// safeBackupPath uses filepath.Base which strips directory components,
	// so traversal attacks are neutralized — the result stays inside baseDir.
	tests := []struct {
		input    string
		expected string // Just the base filename after stripping
	}{
		{"../../../etc/passwd", "passwd"},
		{"../../sensitive.db", "sensitive.db"},
		{"../backup.sqlite", "backup.sqlite"},
		{"subdir/backup.sqlite", "backup.sqlite"},
	}

	for _, tt := range tests {
		path, err := safeBackupPath(baseDir, tt.input)
		if err != nil {
			t.Errorf("safeBackupPath(%q) returned error: %v", tt.input, err)
			continue
		}

		// Verify the result is inside baseDir
		absBase, _ := filepath.Abs(baseDir)
		rel, err := filepath.Rel(absBase, path)
		if err != nil || filepath.Base(rel) != tt.expected {
			t.Errorf("safeBackupPath(%q): expected base=%q, got path=%q", tt.input, tt.expected, path)
		}
	}
}

func TestSafeBackupPath_DotFilenames(t *testing.T) {
	baseDir := t.TempDir()
	dots := []string{".", "..", ""}
	for _, name := range dots {
		_, err := safeBackupPath(baseDir, name)
		if err == nil {
			t.Errorf("Expected error for filename %q", name)
		}
	}
}

func TestSafeBackupPath_StaysInBaseDir(t *testing.T) {
	baseDir := t.TempDir()
	path, err := safeBackupPath(baseDir, "test.sqlite")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	absBase, _ := filepath.Abs(baseDir)
	rel, err := filepath.Rel(absBase, path)
	if err != nil {
		t.Fatalf("Failed to compute relative path: %v", err)
	}
	if rel != "test.sqlite" {
		t.Errorf("Path escaped base dir: rel=%q", rel)
	}
}

// --- Filename Validation Tests ---

func TestIsValidBackupFilename_ValidNames(t *testing.T) {
	valid := []string{
		"aetherflow_2025-01-01_12-00-00.sqlite",
		"backup.sqlite",
		"test_backup-v2.sqlite",
		"my_data.sqlite",
	}
	for _, name := range valid {
		if !isValidBackupFilename(name) {
			t.Errorf("Expected %q to be valid", name)
		}
	}
}

func TestIsValidBackupFilename_InvalidNames(t *testing.T) {
	invalid := []string{
		"../../../etc/passwd",
		"backup.db",           // wrong extension
		"backup.sqlite.bak",   // double extension
		"",                    // empty
		"backup.sql",          // wrong extension
		"backup",              // no extension
		"backup.exe",          // dangerous extension
	}
	for _, name := range invalid {
		if isValidBackupFilename(name) {
			t.Errorf("Expected %q to be invalid", name)
		}
	}
}

// --- Checksum Tests ---

func TestChecksumFilePath(t *testing.T) {
	path := checksumFilePath("/data/backup.sqlite")
	if path != "/data/backup.sqlite.sha256" {
		t.Errorf("Expected .sha256 suffix, got %q", path)
	}
}

func TestComputeFileSHA256_CorrectHash(t *testing.T) {
	// Create a temp file with known content
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.dat")
	content := []byte("aetherflow test data for checksum verification")
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Compute expected hash
	expected := sha256.Sum256(content)
	expectedHex := hex.EncodeToString(expected[:])

	got, err := computeFileSHA256(tmpFile)
	if err != nil {
		t.Fatalf("computeFileSHA256 failed: %v", err)
	}
	if got != expectedHex {
		t.Errorf("Hash mismatch:\n  expected: %s\n  got:      %s", expectedHex, got)
	}
}

func TestComputeFileSHA256_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "empty.dat")
	os.WriteFile(tmpFile, []byte{}, 0644)

	hash, err := computeFileSHA256(tmpFile)
	if err != nil {
		t.Fatalf("Unexpected error for empty file: %v", err)
	}
	// SHA-256 of empty input is a known constant
	emptyHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hash != emptyHash {
		t.Errorf("Expected SHA-256 of empty file, got %q", hash)
	}
}

func TestComputeFileSHA256_NonExistentFile(t *testing.T) {
	_, err := computeFileSHA256("/nonexistent/path/that/does/not/exist.dat")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

// --- Checksum Persistence Round-trip ---

func TestWriteAndReadStoredChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "backup.sqlite")
	os.WriteFile(tmpFile, []byte("backup content"), 0644)

	expectedChecksum := "abc123def456"
	if err := writeStoredChecksum(tmpFile, expectedChecksum); err != nil {
		t.Fatalf("writeStoredChecksum failed: %v", err)
	}

	got, err := readStoredChecksum(tmpFile)
	if err != nil {
		t.Fatalf("readStoredChecksum failed: %v", err)
	}
	if got != expectedChecksum {
		t.Errorf("Checksum round-trip: expected %q, got %q", expectedChecksum, got)
	}
}

func TestReadStoredChecksum_MissingFile(t *testing.T) {
	_, err := readStoredChecksum("/nonexistent/backup.sqlite")
	if err == nil {
		t.Error("Expected error when checksum file doesn't exist")
	}
}

func TestEnsureStoredChecksum_Creates(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "backup.sqlite")
	content := []byte("backup data for ensureStoredChecksum test")
	os.WriteFile(tmpFile, content, 0644)

	// First call — should compute and store
	sum1, err := ensureStoredChecksum(tmpFile)
	if err != nil {
		t.Fatalf("ensureStoredChecksum failed: %v", err)
	}
	if sum1 == "" {
		t.Error("Expected non-empty checksum")
	}

	// Second call — should read from stored file
	sum2, err := ensureStoredChecksum(tmpFile)
	if err != nil {
		t.Fatalf("Second ensureStoredChecksum failed: %v", err)
	}
	if sum1 != sum2 {
		t.Errorf("Checksum not stable: %q vs %q", sum1, sum2)
	}

	// Verify the checksum file exists
	checksumPath := checksumFilePath(tmpFile)
	if _, err := os.Stat(checksumPath); os.IsNotExist(err) {
		t.Error("Checksum file was not persisted to disk")
	}
}

// --- Backup Chunk Size ---

func TestDefaultBackupChunkSize(t *testing.T) {
	expected := int64(10 * 1024 * 1024) // 10 MiB
	if defaultBackupChunkSize != expected {
		t.Errorf("Expected chunk size %d, got %d", expected, defaultBackupChunkSize)
	}
}
