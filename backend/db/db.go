package db

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

// migrate runs a set of SQL statements only if the given version has not
// already been applied. This keeps the migration runner fully idempotent
// across restarts and upgrades from any prior v3.0.x release.
func migrate(version int, description string, stmts ...string) {
	var count int
	if err := DB.QueryRow("SELECT COUNT(*) FROM schema_versions WHERE version = ?", version).Scan(&count); err != nil {
		log.Printf("Migration v%d: failed to query schema_versions: %v", version, err)
		return
	}
	if count > 0 {
		return // already applied
	}

	for _, stmt := range stmts {
		if _, err := DB.Exec(stmt); err != nil {
			log.Printf("Migration v%d FAILED on [%.80s]: %v", version, stmt, err)
			return // stop this migration; do not mark as applied
		}
	}

	if _, err := DB.Exec("INSERT INTO schema_versions (version, description) VALUES (?, ?)", version, description); err != nil {
		log.Printf("Migration v%d: applied SQL but failed to record version: %v", version, err)
	} else {
		log.Printf("Applied migration v%d: %s", version, description)
	}
}

func InitDB() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		// Fallback paths, looking for aetherflow.sqlite
		paths := []string{
			filepath.Join("data", "aetherflow.sqlite"),                                   // Canonical: backend/data/
			filepath.Join("..", "backend", "data", "aetherflow.sqlite"),                   // From project root
			filepath.Join("/opt", "AetherFlow", "backend", "data", "aetherflow.sqlite"),  // Production
			filepath.Join("..", "dashboard", "db", "aetherflow.sqlite"),                   // Legacy fallback
			filepath.Join("dashboard", "db", "aetherflow.sqlite"),                         // Legacy fallback (alt)
			filepath.Join("/opt", "AetherFlow", "dashboard", "db", "aetherflow.sqlite"),  // Legacy production fallback
		}

		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				dbPath = p
				break
			}
		}
	}

	if dbPath == "" {
		log.Printf("Warning: SQLite database file not found. Set DB_PATH explicitly.")
		// We'll still try to open it so it creates a new one, but this is a fallback.
		dbPath = "aetherflow.sqlite"
	}

	var err error
	DB, err = sql.Open("sqlite3", dbPath)
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
			log.Printf("Warning: PRAGMA failed: %s — %v", p, err)
		}
	}

	// ─── Core tables (CREATE IF NOT EXISTS — always idempotent) ────────

	// Settings (singleton row)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS settings (
			id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			ai_model TEXT DEFAULT 'gemini-2.5-pro',
			system_prompt TEXT DEFAULT 'You are FlowAI, a highly intelligent infrastructure assistant connected to a local Next.js + Go Nexus environment. Always prioritize safe and performant configurations.',
			language TEXT DEFAULT 'en',
			timezone TEXT DEFAULT 'UTC',
			update_channel TEXT DEFAULT 'stable',
			default_dashboard TEXT DEFAULT 'overview',
			setup_completed BOOLEAN DEFAULT 0,
			gemini_api_key TEXT DEFAULT '',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		log.Printf("Error ensuring settings table exists: %v", err)
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
		log.Printf("Error ensuring users table exists: %v", err)
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
		log.Printf("Error ensuring login_history table exists: %v", err)
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
		log.Printf("Error ensuring cluster_nodes table exists: %v", err)
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
		log.Printf("Error ensuring oidc_clients table exists: %v", err)
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
		log.Printf("Error ensuring oidc_auth_codes table exists: %v", err)
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
		log.Printf("Error ensuring oidc_refresh_tokens table exists: %v", err)
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
		log.Printf("Error ensuring log_bookmarks table exists: %v", err)
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
		log.Printf("Error ensuring notifications table exists: %v", err)
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
		log.Printf("Error ensuring notification_rules table exists: %v", err)
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
		log.Printf("Error ensuring notification_channels table exists: %v", err)
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
		log.Printf("Error ensuring user_quotas table exists: %v", err)
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
		log.Printf("Error ensuring billing_webhook_events table exists: %v", err)
	}

	// VPN configs (Phase 10)
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS vpn_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			name TEXT NOT NULL,
			config TEXT NOT NULL,
			enabled BOOLEAN DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		log.Printf("Error ensuring vpn_configs table exists: %v", err)
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
		log.Printf("Error ensuring app_updates table exists: %v", err)
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
		log.Printf("Error ensuring media_metadata table exists: %v", err)
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
		log.Printf("Error ensuring metrics_history table exists: %v", err)
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
		log.Printf("Error ensuring schema_versions table exists: %v", err)
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
		// Cluster: status queries + heartbeat staleness detection
		"CREATE INDEX IF NOT EXISTS idx_cluster_nodes_status ON cluster_nodes(status);",
		// Billing webhooks: dedup lookups
		"CREATE INDEX IF NOT EXISTS idx_billing_provider_event ON billing_webhook_events(provider, event_id);",
		// Log bookmarks: user-scoped retrieval
		"CREATE INDEX IF NOT EXISTS idx_log_bookmarks_user ON log_bookmarks(user_id);",
	)

	// ─── Ensure singleton settings row ─────────────────────────────────
	DB.Exec(`INSERT OR IGNORE INTO settings (id) VALUES (1)`)

	log.Printf("Successfully connected to SQLite database at %s", dbPath)
}
