package db

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func InitDB() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		// Fallback paths, looking for aetherflow.sqlite
		paths := []string{
			filepath.Join("..", "dashboard", "db", "aetherflow.sqlite"),
			filepath.Join("dashboard", "db", "aetherflow.sqlite"),
			filepath.Join("/opt", "AetherFlow", "dashboard", "db", "aetherflow.sqlite"),
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

	// Create settings table if it doesn't exist
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

	// Create users table if it doesn't exist
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

	// Create login_history table
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

	// Migrate existing database columns
	_, _ = DB.Exec(`ALTER TABLE settings ADD COLUMN setup_completed BOOLEAN DEFAULT 0;`)
	_, _ = DB.Exec(`ALTER TABLE settings ADD COLUMN gemini_api_key TEXT DEFAULT '';`)
	_, _ = DB.Exec(`ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT '';`)

	// Ensure there is at least one row in settings
	DB.Exec(`INSERT OR IGNORE INTO settings (id) VALUES (1)`)

	log.Printf("Successfully connected to SQLite database at %s", dbPath)
}
