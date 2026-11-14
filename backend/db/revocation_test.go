package db

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func initTempTestDB(t *testing.T, dbPath string) {
	t.Helper()
	if DB != nil {
		_ = DB.Close()
		DB = nil
	}
	t.Setenv("DB_PATH", dbPath)
	t.Setenv("AETHERFLOW_CONFIG_ROOT", filepath.Dir(dbPath))
	InitDB()
	t.Cleanup(func() {
		if DB != nil {
			_ = DB.Close()
			DB = nil
		}
		localBlacklist.Clear()
	})
}

func TestDurableRevokeAndIsTokenRevokedAcrossMemoryClear(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "revocation.sqlite")
	initTempTestDB(t, dbPath)
	RedisClient = nil

	if err := RevokeToken("jti-durable-1", 5*time.Minute); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	// Simulate fresh process by clearing in-memory cache.
	localBlacklist.Delete("jti-durable-1")

	if !IsTokenRevoked("jti-durable-1") {
		t.Fatal("expected IsTokenRevoked to return true from SQLite revoked_tokens after memory clear")
	}
	if IsTokenRevoked("jti-never-revoked") {
		t.Fatal("expected unrevoked JTI to return false while SQLite is healthy")
	}

	// Fail closed if SQLite query errors out (e.g. closed DB).
	if err := DB.Close(); err != nil {
		t.Fatalf("close DB: %v", err)
	}
	if !IsTokenRevoked("jti-never-revoked") {
		t.Fatal("expected IsTokenRevoked to fail closed (true) on SQLite error")
	}
}

func TestRevokeTokenMinimumTwoHourFloor(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "revocation_floor.sqlite")
	initTempTestDB(t, dbPath)
	RedisClient = nil

	before := time.Now().UTC()
	if err := RevokeToken("jti-short-ttl", 1*time.Second); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	var expiresRaw string
	if err := DB.QueryRow("SELECT expires_at FROM revoked_tokens WHERE jti = ?", "jti-short-ttl").Scan(&expiresRaw); err != nil {
		t.Fatalf("query revoked_tokens: %v", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresRaw)
	if err != nil {
		expiresAt, err = time.Parse("2006-01-02 15:04:05", expiresRaw)
		if err != nil {
			t.Fatalf("parse expires_at %q: %v", expiresRaw, err)
		}
	}
	if expiresAt.Sub(before) < 110*time.Minute {
		t.Fatalf("expected revocation TTL floor >= ~2h, got delta %v (expires_at=%s)", expiresAt.Sub(before), expiresRaw)
	}
}

func TestMigration20AddsNonceColumnToLegacyOIDCAuthCodes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy_v19.sqlite")
	legacyDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open legacy sqlite: %v", err)
	}
	if _, err := legacyDB.Exec(`
		CREATE TABLE oidc_auth_codes (
			code TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			user_id INTEGER NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT DEFAULT 'openid profile email',
			code_challenge TEXT DEFAULT '',
			code_challenge_method TEXT DEFAULT '',
			expires_at DATETIME NOT NULL,
			used BOOLEAN DEFAULT 0
		);
	`); err != nil {
		legacyDB.Close()
		t.Fatalf("seed legacy table: %v", err)
	}
	_ = legacyDB.Close()

	initTempTestDB(t, dbPath)

	var colCount int
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('oidc_auth_codes') WHERE name = 'nonce'").Scan(&colCount); err != nil {
		t.Fatalf("check pragma_table_info: %v", err)
	}
	if colCount != 1 {
		t.Fatalf("expected oidc_auth_codes.nonce column after migration 20, got count=%d", colCount)
	}

	var revTable string
	if err := DB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='revoked_tokens'").Scan(&revTable); err != nil {
		t.Fatalf("expected revoked_tokens table after migration 20: %v", err)
	}
}
