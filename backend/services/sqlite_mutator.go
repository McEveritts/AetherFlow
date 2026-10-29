package services

import (
	"database/sql"
	"encoding/json"
	"os"

	_ "modernc.org/sqlite"
)

// SQLiteMutator targets specific SQL row JSON payloads common across the Arr Stack apps.
type SQLiteMutator struct {
	ConfigPath string
}

func NewSQLiteMutator(path string) *SQLiteMutator {
	return &SQLiteMutator{ConfigPath: path}
}

func (sm *SQLiteMutator) Backup() error {
	if sm.ConfigPath == "" {
		return nil
	}
	if _, err := os.Stat(sm.ConfigPath); os.IsNotExist(err) {
		return nil
	}
	return copyFileStruct(sm.ConfigPath, sm.ConfigPath+".bak")
}

func (sm *SQLiteMutator) Restore() error {
	if sm.ConfigPath == "" {
		return nil
	}
	if _, err := os.Stat(sm.ConfigPath + ".bak"); os.IsNotExist(err) {
		return nil
	}
	return copyFileStruct(sm.ConfigPath+".bak", sm.ConfigPath)
}

// InjectRoutes applies specific internal map bindings across Arr targets inside DownloadClients
func (sm *SQLiteMutator) InjectRoutes(routes map[string]string) error {
	if sm.ConfigPath == "" {
		return nil
	}
	if _, err := os.Stat(sm.ConfigPath); os.IsNotExist(err) {
		return nil
	}

	dbConn, err := sql.Open("sqlite", sm.ConfigPath)
	if err != nil {
		return err
	}
	defer dbConn.Close()

	rows, err := dbConn.Query("SELECT Id, Settings FROM DownloadClients")
	if err != nil {
		return nil // Table doesn't exist yet on fresh install
	}
	defer rows.Close()

	type updateItem struct {
		id       int
		settings string
	}
	var updates []updateItem

	for rows.Next() {
		var id int
		var settingsStr string
		if err := rows.Scan(&id, &settingsStr); err != nil {
			continue
		}

		var settings map[string]interface{}
		if err := json.Unmarshal([]byte(settingsStr), &settings); err != nil {
			continue
		}

		modified := false
		if host, ok := settings["Host"].(string); ok {
			if target, present := routes[host]; present {
				settings["Host"] = target
				settings["Port"] = 80 // Route through internal Caddy switchboard
				modified = true
			}
		}

		if modified {
			modifiedJSON, _ := json.Marshal(settings)
			updates = append(updates, updateItem{id: id, settings: string(modifiedJSON)})
		}
	}
	rows.Close()

	for _, u := range updates {
		if _, err := dbConn.Exec("UPDATE DownloadClients SET Settings = ? WHERE Id = ?", u.settings, u.id); err != nil {
			return err
		}
	}
	return nil
}
