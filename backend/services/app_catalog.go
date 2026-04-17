package services

import (
	"strings"
)

// AppBlueprint defines the strict architectural definitions required by the
// deployment orchestration engine to navigate differing systems natively.
type AppBlueprint struct {
	AppName         string
	DefaultPort     int
	MutatorType     string
	BinarySourceURL string
	AppDataPath     string
}

// blueprintRegistry is our static in-memory mapping catalog.
var blueprintRegistry = map[string]AppBlueprint{
	"radarr": {
		AppName:         "radarr",
		DefaultPort:     7878,
		MutatorType:     "sqlite",
		BinarySourceURL: "https://hub.aetherflow.io/bin/radarr/latest.tar.gz",
		AppDataPath:     "/var/lib/radarr/radarr.db",
	},
	"qbittorrent": {
		AppName:         "qbittorrent",
		DefaultPort:     8080,
		MutatorType:     "ini",
		BinarySourceURL: "https://hub.aetherflow.io/bin/qbittorrent/latest.tar.gz",
		AppDataPath:     "/etc/qbittorrent/qBittorrent.conf",
	},
	// Future: "homarr" => MutatorType: "json", etc.
}

// GetBlueprint securely looks up exact blueprint contexts and returns a pointer or nil if not found.
func GetBlueprint(requestedApp string) *AppBlueprint {
	cleanName := strings.ToLower(strings.TrimSpace(requestedApp))
	
	bp, exists := blueprintRegistry[cleanName]
	if !exists {
		return nil
	}
	return &bp
}
