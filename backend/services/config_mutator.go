package services

import (
	"strings"
)

// ConfigMutator defines the lifecycle schema for safely updating hardcoded internal configs
// prior to orchestrator execution spins.
type ConfigMutator interface {
	Backup() error
	InjectRoutes(routes map[string]string) error
	Restore() error
}

// GetMutatorForApp is the Factory function for parsing polymorphic configuration structures
// over the bare-metal environment apps.
func GetMutatorForApp(appName string, configPath string) ConfigMutator {
	name := strings.ToLower(appName)
	switch name {
	// Standard Arr Stack
	case "radarr", "sonarr", "readarr", "lidarr", "prowlarr":
		return NewSQLiteMutator(configPath)

	// INI structured parsers
	case "qbittorrent", "sabnzbd":
		return NewINIMutator(configPath)

	// Stub out JSON setups
	case "ombi", "homarr":
		// return NewJSONMutator(configPath) 
		return nil

	default:
		// Unknown structures fallback to nil, bypassing injection sequences safely
		return nil
	}
}
