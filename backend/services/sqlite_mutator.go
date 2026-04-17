package services

import (
	"database/sql"
	"encoding/json"
)

// SQLiteMutator targets specific SQL row JSON payloads common across the Array Stack apps.
type SQLiteMutator struct {
	ConfigPath string
}

func NewSQLiteMutator(path string) *SQLiteMutator {
	return &SQLiteMutator{ConfigPath: path}
}

func (sm *SQLiteMutator) Backup() error {
	return copyFileStruct(sm.ConfigPath, sm.ConfigPath+".bak")
}

func (sm *SQLiteMutator) Restore() error {
	return copyFileStruct(sm.ConfigPath+".bak", sm.ConfigPath)
}

// InjectRoutes applies specific internal map bindings across Arr targets inside DownloadClients
func (sm *SQLiteMutator) InjectRoutes(routes map[string]string) error {
	db, err := sql.Open("sqlite3", sm.ConfigPath)
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.Query("SELECT Id, Settings FROM DownloadClients")
	if err != nil {
		return err // Or return nil silently if table doesn't exist
	}
	defer rows.Close()

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
				settings["Port"] = 80 // Hardcode API loop requirement 
				modified = true
			}
		}

		if modified {
			modifiedJSON, _ := json.Marshal(settings)
			_, err = db.Exec("UPDATE DownloadClients SET Settings = ? WHERE Id = ?", string(modifiedJSON), id)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
