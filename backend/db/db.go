package db

import (
	"database/sql"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

// migrate runs a set of SQL statements only if the given version has not
// already been applied. This keeps the migration runner fully idempotent
// across restarts and upgrades from any prior v3.0.x release.
func migrate(version int, description string, stmts ...string) {
	var count int
	if err := DB.QueryRow("SELECT COUNT(*) FROM schema_versions WHERE version = ?", version).Scan(&count); err != nil {
		slog.Error("migration: failed to query schema_versions", "version", version, "error", err)
		return
	}
	if count > 0 {
		return // already applied
	}

	for _, stmt := range stmts {
		if _, err := DB.Exec(stmt); err != nil {
			if strings.Contains(err.Error(), "duplicate column name") {
				slog.Info("migration already applied (duplicate column)", "version", version)
				continue
			}
			slog.Error("migration failed", "version", version, "error", err)
			return // stop this migration; do not mark as applied
		}
	}

	if _, err := DB.Exec("INSERT INTO schema_versions (version, description) VALUES (?, ?)", version, description); err != nil {
		slog.Warn("migration: applied SQL but failed to record version", "version", version, "error", err)
	} else {
		slog.Info("migration applied", "version", version, "description", description)
	}
}

func InitDB() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		// Anchor the database path to the executable's directory, not the CWD.
		// This prevents accidental creation of a new empty DB in a random directory.
		exe, exeErr := os.Executable()
		if exeErr != nil {
			log.Fatalf("CRITICAL: Failed to resolve executable path for DB init: %v", exeErr)
		}
		exeDir := filepath.Dir(exe)

		dbDir := filepath.Join(exeDir, "data")
		if mkErr := os.MkdirAll(dbDir, 0700); mkErr != nil {
			log.Fatalf("CRITICAL: Failed to create database directory at %s: %v", dbDir, mkErr)
		}

		dbPath = filepath.Join(dbDir, "aetherflow.sqlite")
		slog.Info("database path anchored", "path", dbPath)
	}

	var err error
	DB, err = sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatalf("Failed to open SQLite database at %s: %v", dbPath, err)
	}

	if err := DB.Ping(); err != nil {
		log.Fatalf("Failed to ping SQLite database: %v", err)
	}

	// ─── v3.1.0 Gold: Connection pool limits ───────────────────────────
	// SQLite supports only a single writer. Constraining Go's pool to one
	// connection avoids SQLITE_BUSY under concurrent request load.
	DB.SetMaxOpenConns(1)
	DB.SetMaxIdleConns(1)
	DB.SetConnMaxLifetime(0) // reuse forever

	// ─── v3.1.0 Gold: Performance PRAGMAs for bare-metal ──────────────
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",       // Write-Ahead Logging — concurrent reads
		"PRAGMA synchronous=NORMAL;",     // Safe with WAL; full sync on checkpoint only
		"PRAGMA busy_timeout=5000;",      // 5 s retry on lock contention
		"PRAGMA cache_size=-64000;",      // 64 MB page cache (negative = KiB)
		"PRAGMA foreign_keys=ON;",        // Enforce referential integrity
		"PRAGMA temp_store=MEMORY;",      // Temp tables in RAM
		"PRAGMA mmap_size=268435456;",    // 256 MB memory-mapped I/O
	}
	for _, p := range pragmas {
		if _, err := DB.Exec(p); err != nil {
			slog.Warn("PRAGMA failed", "pragma", p, "error", err)
		}
	}

	// ─── Core tables (CREATE IF NOT EXISTS — always idempotent) ────────

	// Settings (singleton row)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS settings (
			id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			ai_model TEXT DEFAULT 'gemini-3.1-pro-preview',
			system_prompt TEXT DEFAULT 'You are FlowAI, a highly intelligent infrastructure assistant connected to a local Next.js + Go Nexus environment. Always prioritize safe and performant configurations.',
			language TEXT DEFAULT 'en',
			timezone TEXT DEFAULT 'UTC',
			update_channel TEXT DEFAULT 'stable',
			default_dashboard TEXT DEFAULT 'overview',
			setup_completed BOOLEAN DEFAULT 0,
			gemini_api_key TEXT DEFAULT '',
			openai_api_key TEXT DEFAULT '',
			lm_studio_endpoint TEXT DEFAULT '',
			ollama_endpoint TEXT DEFAULT '',
			anthropic_api_key TEXT DEFAULT '',
			anthropic_endpoint TEXT DEFAULT '',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "settings", "error", err)
	}

	// Users
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT DEFAULT '',
			google_id TEXT DEFAULT '',
			email TEXT DEFAULT '',
			avatar_url TEXT DEFAULT '',
			role TEXT DEFAULT 'user',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "users", "error", err)
	}

	// Login history
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS login_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			ip_address TEXT,
			user_agent TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "login_history", "error", err)
	}

	// Cluster nodes (Phase 6)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS cluster_nodes (
			id TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			address TEXT NOT NULL,
			psk_hash TEXT NOT NULL,
			role TEXT DEFAULT 'worker',
			status TEXT DEFAULT 'offline',
			last_heartbeat DATETIME,
			enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "cluster_nodes", "error", err)
	}

	// OIDC clients (Phase 7)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS oidc_clients (
			id TEXT PRIMARY KEY,
			client_secret_hash TEXT NOT NULL,
			name TEXT NOT NULL,
			redirect_uris TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "oidc_clients", "error", err)
	}

	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS oidc_auth_codes (
			code TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			user_id INTEGER NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT DEFAULT 'openid profile email',
			code_challenge TEXT DEFAULT '',
			code_challenge_method TEXT DEFAULT '',
			expires_at DATETIME NOT NULL,
			used BOOLEAN DEFAULT 0
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "oidc_auth_codes", "error", err)
	}

	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
			token TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			user_id INTEGER NOT NULL,
			scope TEXT DEFAULT 'openid profile email',
			expires_at DATETIME NOT NULL,
			revoked BOOLEAN DEFAULT 0
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "oidc_refresh_tokens", "error", err)
	}

	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS oidc_device_codes (
			device_code TEXT PRIMARY KEY,
			user_code TEXT NOT NULL,
			client_id TEXT NOT NULL,
			scope TEXT DEFAULT 'openid profile email',
			user_id INTEGER,
			expires_at DATETIME NOT NULL,
			status TEXT DEFAULT 'pending'
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "oidc_device_codes", "error", err)
	}

	// Log bookmarks (Phase 8)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS log_bookmarks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			log_source TEXT NOT NULL,
			log_line TEXT NOT NULL,
			timestamp DATETIME NOT NULL,
			note TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "log_bookmarks", "error", err)
	}

	// Notifications (Phase 9)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS notifications (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			level TEXT NOT NULL DEFAULT 'info',
			title TEXT NOT NULL,
			message TEXT NOT NULL,
			read BOOLEAN DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "notifications", "error", err)
	}

	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS notification_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			condition_type TEXT NOT NULL,
			condition_value TEXT NOT NULL,
			level TEXT DEFAULT 'warning',
			enabled BOOLEAN DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "notification_rules", "error", err)
	}

	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS notification_channels (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			config TEXT NOT NULL,
			enabled BOOLEAN DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "notification_channels", "error", err)
	}

	// User quotas & billing (Phase 11)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS user_quotas (
			user_id INTEGER PRIMARY KEY,
			username TEXT NOT NULL,
			quota_bytes INTEGER DEFAULT 0,
			used_bytes INTEGER DEFAULT 0,
			status TEXT DEFAULT 'active',
			source TEXT DEFAULT 'manual',
			billing_provider TEXT DEFAULT '',
			billing_external_id TEXT DEFAULT '',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "user_quotas", "error", err)
	}

	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS billing_webhook_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			provider TEXT NOT NULL,
			event_id TEXT NOT NULL,
			event_type TEXT DEFAULT '',
			username TEXT DEFAULT '',
			quota_bytes INTEGER DEFAULT 0,
			status TEXT DEFAULT 'received',
			error TEXT DEFAULT '',
			payload TEXT NOT NULL,
			processed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(provider, event_id)
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "billing_webhook_events", "error", err)
	}

	// App updates (Phase 12)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS app_updates (
			package_name TEXT PRIMARY KEY,
			installed_version TEXT DEFAULT '',
			latest_version TEXT DEFAULT '',
			update_available BOOLEAN DEFAULT 0,
			update_url TEXT DEFAULT '',
			checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_error TEXT DEFAULT ''
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "app_updates", "error", err)
	}

	// Media metadata (Phase 17)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS media_metadata (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			file_path TEXT UNIQUE NOT NULL,
			filename TEXT NOT NULL,
			title TEXT DEFAULT '',
			year TEXT DEFAULT '',
			language TEXT DEFAULT '',
			quality TEXT DEFAULT '',
			subtitles_json TEXT DEFAULT '[]',
			enriched_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "media_metadata", "error", err)
	}

	// Metrics history (Phase 19)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS metrics_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			cpu_avg REAL DEFAULT 0,
			mem_used_gb REAL DEFAULT 0,
			mem_total_gb REAL DEFAULT 0,
			disk_read_bps REAL DEFAULT 0,
			disk_write_bps REAL DEFAULT 0,
			net_rx_bytes INTEGER DEFAULT 0,
			net_tx_bytes INTEGER DEFAULT 0,
			load_avg_1 REAL DEFAULT 0,
			active_conns INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "metrics_history", "error", err)
	}

	// ─── v3.1.0 Gold: Schema version tracking ─────────────────────────
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS schema_versions (
			version INTEGER PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		slog.Error("failed to create table", "table", "schema_versions", "error", err)
	}

	// ─── Versioned migrations (idempotent — safe for v3.0.x → v3.1.0) ─

	migrate(1, "Add setup_completed to settings",
		"ALTER TABLE settings ADD COLUMN setup_completed BOOLEAN DEFAULT 0;")

	migrate(2, "Add gemini_api_key to settings",
		"ALTER TABLE settings ADD COLUMN gemini_api_key TEXT DEFAULT '';")

	migrate(3, "Add password_hash to users",
		"ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT '';")

	migrate(4, "Add backup scheduling columns to settings",
		"ALTER TABLE settings ADD COLUMN backup_schedule_mode TEXT DEFAULT 'manual';",
		"ALTER TABLE settings ADD COLUMN backup_optimal_window TEXT DEFAULT '';")

	migrate(5, "v3.1.0 Gold — performance indexes",
		// Notifications: paginated list by user + read status
		"CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, read);",
		"CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at);",
		// Metrics history: timestamp-range queries + DELETE pruning
		"CREATE INDEX IF NOT EXISTS idx_metrics_history_ts ON metrics_history(timestamp);",
		// Login history: user audit trail
		"CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_login_history_created ON login_history(created_at);",
		// Users: google_id lookups (OAuth), email lookups (quota manager)
		"CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);",
		"CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
		// OIDC: auth code expiry scans, refresh token lookups
		"CREATE INDEX IF NOT EXISTS idx_oidc_auth_codes_client ON oidc_auth_codes(client_id);",
		"CREATE INDEX IF NOT EXISTS idx_oidc_auth_codes_expires ON oidc_auth_codes(expires_at);",
		"CREATE INDEX IF NOT EXISTS idx_oidc_refresh_client ON oidc_refresh_tokens(client_id);",
		"CREATE INDEX IF NOT EXISTS idx_oidc_device_codes_user_code ON oidc_device_codes(user_code);",
		"CREATE INDEX IF NOT EXISTS idx_oidc_device_codes_expires ON oidc_device_codes(expires_at);",
		// Cluster: status queries + heartbeat staleness detection
		"CREATE INDEX IF NOT EXISTS idx_cluster_nodes_status ON cluster_nodes(status);",
		// Billing webhooks: dedup lookups
		"CREATE INDEX IF NOT EXISTS idx_billing_provider_event ON billing_webhook_events(provider, event_id);",
		// Log bookmarks: user-scoped retrieval
		"CREATE INDEX IF NOT EXISTS idx_log_bookmarks_user ON log_bookmarks(user_id);",
	)

	migrate(6, "Persist smart backup next run time",
		"ALTER TABLE settings ADD COLUMN backup_next_run_at TEXT DEFAULT '';")

	migrate(7, "Add OIDC consent persistence",
		`CREATE TABLE IF NOT EXISTS oidc_consents (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			client_id TEXT NOT NULL,
			scope TEXT NOT NULL,
			granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, client_id)
		);`,
		"CREATE INDEX IF NOT EXISTS idx_oidc_consents_user_client ON oidc_consents(user_id, client_id);")

	migrate(8, "Add active sessions table for session tracking",
		`CREATE TABLE IF NOT EXISTS active_sessions (
			jti TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			ip_address TEXT DEFAULT '',
			user_agent TEXT DEFAULT '',
			expires_at DATETIME NOT NULL,
			last_active DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		"CREATE INDEX IF NOT EXISTS idx_active_sessions_user ON active_sessions(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_active_sessions_expires ON active_sessions(expires_at);")

	// ─── Migration v9: Phase 9 — pending_actions for approval gates ────
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

	// ─── Migration v10: Phase 13 — notification delivery audit log ─────
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

	// ─── Migration v11: Phase 28 — Admin action audit trail ────────────
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

	// ─── Migration v12: Phase 29 — Additional AI Providers ─────────────
	migrate(12, "Add OpenAI and Local AI provider config",
		"ALTER TABLE settings ADD COLUMN openai_api_key TEXT DEFAULT '';",
		"ALTER TABLE settings ADD COLUMN lm_studio_endpoint TEXT DEFAULT '';",
		"ALTER TABLE settings ADD COLUMN ollama_endpoint TEXT DEFAULT '';")

	// ─── Migration v13: Add Anthropic Support ─────────────
	migrate(13, "Add Anthropic API provider config",
		"ALTER TABLE settings ADD COLUMN anthropic_api_key TEXT DEFAULT '';",
		"ALTER TABLE settings ADD COLUMN anthropic_endpoint TEXT DEFAULT '';")

	// ─── Migration v14: TOTP Two-Factor Authentication ─────────────────
	migrate(14, "Add TOTP 2FA columns to users",
		"ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT '';",
		"ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0;")

	// ─── Migration v15: Recovery Codes for 2FA ─────────────────────────
	migrate(15, "Add recovery_codes table for 2FA backup codes",
		`CREATE TABLE IF NOT EXISTS recovery_codes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			code_hash TEXT NOT NULL,
			used BOOLEAN DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);`)

	// ─── Migration v16: MediaFlow Hardware Transcode Engine ────────────
	migrate(16, "Add mediaflow queue for hwaccel transcoding",
		`CREATE TABLE IF NOT EXISTS mediaflow_queue (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			file_path TEXT UNIQUE NOT NULL,
			status TEXT DEFAULT 'PENDING_APPROVAL',
			original_codec TEXT DEFAULT '',
			original_size INTEGER DEFAULT 0,
			new_codec TEXT DEFAULT '',
			new_size INTEGER DEFAULT 0,
			error_log TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		"CREATE INDEX IF NOT EXISTS idx_mediaflow_status ON mediaflow_queue(status);")

	// ─── Ensure singleton settings row ─────────────────────────────────
	DB.Exec(`INSERT OR IGNORE INTO settings (id) VALUES (1)`)

	slog.Info("database connected", "path", dbPath)
}

// ── Phase 16: Database Layer Hardening ──────────────────────────────────

// DBHealthCheck performs a lightweight health check on the database.
// Returns a map of diagnostic information suitable for health endpoint rendering.
func DBHealthCheck() (map[string]interface{}, error) {
	start := time.Now()
	var one int
	if err := DB.QueryRow("SELECT 1").Scan(&one); err != nil {
		return nil, err
	}
	latency := time.Since(start)

	// Gather table row counts for diagnostics
	tables := []string{"users", "active_sessions", "oidc_clients", "notifications", "metrics_history"}
	counts := map[string]int{}
	for _, t := range tables {
		var c int
		// Table names are hardcoded constants — no injection risk
		if err := DB.QueryRow("SELECT COUNT(*) FROM " + t).Scan(&c); err == nil {
			counts[t] = c
		}
	}

	// Check WAL size
	var walPages int
	DB.QueryRow("PRAGMA wal_checkpoint(PASSIVE)").Scan(&walPages, nil, nil)

	return map[string]interface{}{
		"status":       "healthy",
		"latency_ms":   latency.Milliseconds(),
		"table_counts": counts,
		"wal_pages":    walPages,
	}, nil
}

// PruneExpiredData removes stale records across all tables with TTL semantics.
// This should be called periodically (e.g., every 15 minutes from a background goroutine).
func PruneExpiredData() {
	now := time.Now().Format(time.RFC3339)

	pruneTargets := []struct {
		table string
		query string
	}{
		{"oidc_auth_codes", "DELETE FROM oidc_auth_codes WHERE expires_at < ? OR used = 1"},
		{"oidc_device_codes", "DELETE FROM oidc_device_codes WHERE expires_at < ?"},
		{"oidc_refresh_tokens", "DELETE FROM oidc_refresh_tokens WHERE expires_at < ? OR revoked = 1"},
		{"active_sessions", "DELETE FROM active_sessions WHERE expires_at < ?"},
		// Keep 90 days of metrics history
		{"metrics_history", "DELETE FROM metrics_history WHERE timestamp < datetime('now', '-90 days')"},
		// Keep 90 days of login history
		{"login_history", "DELETE FROM login_history WHERE created_at < datetime('now', '-90 days')"},
		// Keep 30 days of billing webhook events
		{"billing_webhook_events", "DELETE FROM billing_webhook_events WHERE processed_at < datetime('now', '-30 days')"},
	}

	for _, target := range pruneTargets {
		var result sql.Result
		var err error
		if strings.Contains(target.query, "?") {
			result, err = DB.Exec(target.query, now)
		} else {
			result, err = DB.Exec(target.query)
		}
		if err != nil {
			slog.Error("prune error", "table", target.table, "error", err)
			continue
		}
		if affected, _ := result.RowsAffected(); affected > 0 {
			slog.Info("prune completed", "table", target.table, "rows_removed", affected)
		}
	}
}

// StartPruneLoop starts a background goroutine that periodically prunes expired data.
func StartPruneLoop() {
	go func() {
		// Initial delay to let the system stabilize
		time.Sleep(30 * time.Second)
		for {
			PruneExpiredData()
			time.Sleep(15 * time.Minute)
		}
	}()
	slog.Info("database prune loop started", "interval", "15m")
}
