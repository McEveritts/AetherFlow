//go:build ignore

package main

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", "data/aetherflow.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	
	// 1. Insert/update admin user
	_, err = db.Exec("INSERT OR REPLACE INTO users (id, username, email, role, password_hash) VALUES (1, 'admin', 'admin@example.com', 'admin', ?)", string(hash))
	if err != nil {
		log.Fatal("user insert failed:", err)
	}

	now := time.Now().Format(time.RFC3339)
	_, err = db.Exec("INSERT INTO pending_actions (classification, source, action, reason, status, created_at) VALUES ('warn', 'ai-diagnostic', 'restart-service:prometheus', 'High memory usage detected', 'pending', ?)", now)
	if err != nil {
		log.Fatal("pending action insert failed:", err)
	}
	
	fmt.Println("Seed completed successfully")
}
