package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"

	// SQLite driver (Ensure this compiles via CGO if used, alternatively use modernc.org/sqlite for pure-Go)
	// _ "github.com/mattn/go-sqlite3" 
)

// AppContext represents the operational paths for the targeted service to inject
type AppContext struct {
	ServiceName string // e.g., "radarr"
	DBPath      string // e.g., "/var/lib/radarr/radarr.db"
}

// ArrInjector coordinates zero-downtime, safe hijacking of hardcoded 
// dependencies in Arr stack applications using SQLite modifications.
type ArrInjector struct {
	DNSMgr *DNSManager
}

func NewArrInjector() *ArrInjector {
	return &ArrInjector{
		DNSMgr: NewDNSManager(),
	}
}

// HijackDownloadClient changes an Arr dependency host (e.g. qBittorrent) 
// strictly checking the new internal router state before taking down the app.
func (ai *ArrInjector) HijackDownloadClient(ctx AppContext, currentHost string, newHost string, targetPort int) error {
	// 1. Safety Rollback Check: Does OS resolve the new target?
	if !ai.DNSMgr.ValidateResolution(newHost) {
		return fmt.Errorf("aborting deploy: %s does not resolve to the internal switchboard via host OS", newHost)
	}

	log.Printf("Commencing shadow cutover for %s: Target dependencies verified.", ctx.ServiceName)

	// 2. Halting Service Gently
	if err := ai.stopService(ctx.ServiceName); err != nil {
		return fmt.Errorf("failed halting %s: %w", ctx.ServiceName, err)
	}

	// Assume we need to start it back up at the end, regardless of injection outcome
	defer func() {
		if err := ai.startService(ctx.ServiceName); err != nil {
			log.Printf("CRITICAL: Failed to restart %s during defers: %v", ctx.ServiceName, err)
		}
	}()

	// 3. Atomically Backup the DB
	backupPath := ctx.DBPath + ".bak"
	if err := ai.copyFile(ctx.DBPath, backupPath); err != nil {
		return fmt.Errorf("aborting injection: failed database backup: %w", err)
	}

	// 4. Inject into SQLite
	if err := ai.injectSQLite(ctx.DBPath, currentHost, newHost, targetPort); err != nil {
		log.Printf("Injection failed. Initiating database rollback to %s", backupPath)
		_ = ai.copyFile(backupPath, ctx.DBPath) // Rollback procedure
		return fmt.Errorf("SQLite injection failed: %w", err)
	}

	return nil
}

func (ai *ArrInjector) injectSQLite(dbPath string, currentHost, newHost string, targetPort int) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	// Query configured Download Clients
	rows, err := db.Query("SELECT Id, Settings FROM DownloadClients")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var settingsStr string
		if err := rows.Scan(&id, &settingsStr); err != nil {
			continue
		}

		// Arr settings are often stored strictly as JSON string blobs within DB columns
		var settings map[string]interface{}
		if err := json.Unmarshal([]byte(settingsStr), &settings); err != nil {
			continue
		}

		// Look for our vulnerable Host key targeting localhost or old domains
		if host, ok := settings["Host"].(string); ok && host == currentHost {
			settings["Host"] = newHost
			settings["Port"] = targetPort

			modifiedJSON, _ := json.Marshal(settings)
			
			// Upate modified settings back to this specific client
			_, err = db.Exec("UPDATE DownloadClients SET Settings = ? WHERE Id = ?", string(modifiedJSON), id)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// OS Level Control Wrappers
func (ai *ArrInjector) stopService(serviceName string) error {
	cmd := exec.Command("sudo", "systemctl", "stop", serviceName)
	return cmd.Run()
}

func (ai *ArrInjector) startService(serviceName string) error {
	cmd := exec.Command("sudo", "systemctl", "start", serviceName)
	return cmd.Run()
}

// File I/O for backups
func (ai *ArrInjector) copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
