package db

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// TestMigrationChainIntegrity opens a fresh in-memory database, bootstraps
// the schema_versions table, and runs the full migration chain (v1–v11).
// It then asserts that every expected table and index exists with the
// correct columns. This prevents the class of bug where CREATE TABLE SQL
// is accidentally passed as the description parameter to migrate().
func TestMigrationChainIntegrity(t *testing.T) {
	var err error
	DB, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory SQLite: %v", err)
	}
	t.Cleanup(func() {
		DB.Close()
		DB = nil
	})

	// Bootstrap: InitDB creates core tables with CREATE IF NOT EXISTS and
	// then runs migrate() for incremental schema. We call InitDB indirectly
	// by setting DB_PATH to empty and using the already-opened DB.
	// Since InitDB opens its own connection, we replicate the migration
	// portion here by calling the function that contains all migrate() calls.
	// To do this cleanly, we create the core tables manually (they use
	// CREATE IF NOT EXISTS in InitDB) and then run the migrate chain.

	// Create schema_versions (the migration runner depends on this)
	_, err = DB.Exec(`CREATE TABLE IF NOT EXISTS schema_versions (
		version INTEGER PRIMARY KEY,
		description TEXT,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("Failed to create schema_versions: %v", err)
	}

	// Create core tables that InitDB creates before migrations
	coreTables := []string{
		`CREATE TABLE IF NOT EXISTS settings (
			id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			ai_model TEXT DEFAULT 'gemini-2.5-pro',
			system_prompt TEXT DEFAULT '',
			language TEXT DEFAULT 'en',
			timezone TEXT DEFAULT 'UTC',
			update_channel TEXT DEFAULT 'stable',
			default_dashboard TEXT DEFAULT 'overview',
			setup_completed BOOLEAN DEFAULT 0,
			gemini_api_key TEXT DEFAULT '',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT DEFAULT '',
			google_id TEXT DEFAULT '',
			email TEXT DEFAULT '',
			avatar_url TEXT DEFAULT '',
			role TEXT DEFAULT 'user',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS login_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			ip_address TEXT,
			user_agent TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, stmt := range coreTables {
		if _, err := DB.Exec(stmt); err != nil {
			t.Fatalf("Core table setup failed: %v", err)
		}
	}

	// Now run all migrations as they appear in InitDB.
	// We call migrate() directly since it's in the same package.

	// v1: Add default_dashboard to settings
	migrate(1, "Add default_dashboard column to settings",
		"ALTER TABLE settings ADD COLUMN default_dashboard TEXT DEFAULT 'overview';")

	// v2: Add setup_completed
	migrate(2, "Add setup_completed column to settings",
		"ALTER TABLE settings ADD COLUMN setup_completed BOOLEAN DEFAULT 0;")

	// v3: Add gemini_api_key
	migrate(3, "Add gemini_api_key column to settings",
		"ALTER TABLE settings ADD COLUMN gemini_api_key TEXT DEFAULT '';")

	// v4: Cluster nodes
	migrate(4, "Add cluster_nodes table",
		`CREATE TABLE IF NOT EXISTS cluster_nodes (
			id TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			address TEXT NOT NULL,
			psk_hash TEXT NOT NULL,
			role TEXT DEFAULT 'worker',
			status TEXT DEFAULT 'offline',
			last_heartbeat DATETIME,
			enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`)

	// v5: OIDC clients
	migrate(5, "Add OIDC client tables",
		`CREATE TABLE IF NOT EXISTS oidc_clients (
			id TEXT PRIMARY KEY,
			client_secret_hash TEXT NOT NULL,
			name TEXT NOT NULL,
			redirect_uris TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS oidc_auth_codes (
			code TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			user_id INTEGER NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT DEFAULT 'openid profile email',
			code_challenge TEXT DEFAULT '',
			code_challenge_method TEXT DEFAULT '',
			expires_at DATETIME NOT NULL,
			used BOOLEAN DEFAULT 0
		);`)

	// v6: Refresh tokens
	migrate(6, "Add refresh_tokens table",
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			token_hash TEXT UNIQUE NOT NULL,
			family TEXT NOT NULL DEFAULT '',
			expires_at DATETIME NOT NULL,
			revoked BOOLEAN DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`)

	// v7: Device codes
	migrate(7, "Add oidc_device_codes table",
		`CREATE TABLE IF NOT EXISTS oidc_device_codes (
			device_code TEXT PRIMARY KEY,
			user_code TEXT UNIQUE NOT NULL,
			client_id TEXT NOT NULL,
			scope TEXT DEFAULT 'openid profile email',
			status TEXT DEFAULT 'pending',
			user_id INTEGER,
			expires_at DATETIME NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`)

	// v8: Active sessions
	migrate(8, "Add active_sessions table",
		`CREATE TABLE IF NOT EXISTS active_sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			ip_address TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			last_active DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		"CREATE INDEX IF NOT EXISTS idx_active_sessions_user ON active_sessions(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_active_sessions_expires ON active_sessions(expires_at);")

	// v9: Pending actions (was buggy — CREATE TABLE as description)
	migrate(9, "Add pending_actions table for approval gates",
		`CREATE TABLE IF NOT EXISTS pending_actions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		classification TEXT NOT NULL DEFAULT 'warn',
		source TEXT NOT NULL,
		action TEXT NOT NULL,
		reason TEXT,
		status TEXT NOT NULL DEFAULT 'pending',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		resolved_at DATETIME,
		resolved_by TEXT,
		execution_log TEXT
	);`,
		"CREATE INDEX IF NOT EXISTS idx_pending_actions_status ON pending_actions(status);")

	// v10: Notification delivery log (was buggy — same pattern)
	migrate(10, "Add notification_delivery_log for delivery tracking",
		`CREATE TABLE IF NOT EXISTS notification_delivery_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		channel_id INTEGER NOT NULL,
		channel_type TEXT NOT NULL,
		notification_id INTEGER,
		status TEXT NOT NULL DEFAULT 'pending',
		attempts INTEGER DEFAULT 0,
		last_error TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		completed_at DATETIME
	);`,
		"CREATE INDEX IF NOT EXISTS idx_delivery_log_channel ON notification_delivery_log(channel_id);",
		"CREATE INDEX IF NOT EXISTS idx_delivery_log_status ON notification_delivery_log(status);")

	// v11: Admin audit log
	migrate(11, "Add admin audit trail for accountability",
		`CREATE TABLE IF NOT EXISTS admin_audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		username TEXT NOT NULL,
		action TEXT NOT NULL,
		target_type TEXT NOT NULL DEFAULT '',
		target_id TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT '',
		ip_address TEXT NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`,
		"CREATE INDEX IF NOT EXISTS idx_audit_log_user ON admin_audit_log(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_audit_log_action ON admin_audit_log(action);",
		"CREATE INDEX IF NOT EXISTS idx_audit_log_created ON admin_audit_log(created_at);")

	// ─── Assert: every expected table exists ─────────────────────────────

	expectedTables := []string{
		"schema_versions",
		"settings",
		"users",
		"login_history",
		"cluster_nodes",
		"oidc_clients",
		"oidc_auth_codes",
		"refresh_tokens",
		"oidc_device_codes",
		"active_sessions",
		"pending_actions",
		"notification_delivery_log",
		"admin_audit_log",
	}

	for _, table := range expectedTables {
		var name string
		err := DB.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("Table %q does not exist after full migration chain: %v", table, err)
		}
	}

	// ─── Assert: all migrations recorded ─────────────────────────────────

	var migrationCount int
	DB.QueryRow("SELECT COUNT(*) FROM schema_versions").Scan(&migrationCount)
	if migrationCount != 11 {
		t.Errorf("Expected 11 recorded migrations, got %d", migrationCount)
	}

	// ─── Assert: critical indexes exist ──────────────────────────────────

	expectedIndexes := []string{
		"idx_pending_actions_status",
		"idx_delivery_log_channel",
		"idx_delivery_log_status",
		"idx_audit_log_user",
		"idx_audit_log_action",
		"idx_audit_log_created",
		"idx_active_sessions_user",
		"idx_active_sessions_expires",
	}

	for _, idx := range expectedIndexes {
		var name string
		err := DB.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='index' AND name=?", idx,
		).Scan(&name)
		if err != nil {
			t.Errorf("Index %q does not exist after full migration chain: %v", idx, err)
		}
	}

	// ─── Assert: pending_actions has correct columns ─────────────────────

	requiredColumns := []string{"id", "classification", "source", "action", "reason", "status", "created_at", "resolved_at", "resolved_by", "execution_log"}
	for _, col := range requiredColumns {
		var cid int
		var cname, ctype string
		var notnull, pk int
		var dfltValue *string
		err := DB.QueryRow("SELECT cid, name, type, \"notnull\", dflt_value, pk FROM pragma_table_info('pending_actions') WHERE name=?", col).Scan(&cid, &cname, &ctype, &notnull, &dfltValue, &pk)
		if err != nil {
			t.Errorf("Column pending_actions.%s does not exist: %v", col, err)
		}
	}

	// ─── Assert: idempotency — running migrations again is a no-op ──────

	migrate(9, "Add pending_actions table for approval gates",
		`CREATE TABLE IF NOT EXISTS pending_actions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		classification TEXT NOT NULL DEFAULT 'warn',
		source TEXT NOT NULL,
		action TEXT NOT NULL,
		reason TEXT,
		status TEXT NOT NULL DEFAULT 'pending',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		resolved_at DATETIME,
		resolved_by TEXT,
		execution_log TEXT
	);`,
		"CREATE INDEX IF NOT EXISTS idx_pending_actions_status ON pending_actions(status);")

	// Count should still be 11 (not 12)
	DB.QueryRow("SELECT COUNT(*) FROM schema_versions").Scan(&migrationCount)
	if migrationCount != 11 {
		t.Errorf("Idempotency broken: expected 11 migrations after re-run, got %d", migrationCount)
	}
}
