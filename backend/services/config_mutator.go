package services

import (
	"strings"
)

// ConfigMutator defines the lifecycle schema for safely updating hardcoded internal configs
// prior to orchestrator execution spins or during blueprint post-install provisioning.
type ConfigMutator interface {
	Backup() error
	InjectRoutes(routes map[string]string) error
	Restore() error
}

// GetMutatorForApp is the Factory function for parsing polymorphic configuration structures
// over the bare-metal environment apps.
func GetMutatorForApp(appName string, configPath string) ConfigMutator {
	name := strings.ToLower(strings.TrimSpace(appName))
	lowerPath := strings.ToLower(strings.TrimSpace(configPath))

	if strings.HasSuffix(lowerPath, ".xml") {
		return NewXMLMutator(configPath, "")
	}

	switch name {
	// Standard Arr Stack (SQLite DB when pointing to .db, or XML when pointing to config.xml)
	case "radarr", "sonarr", "readarr", "lidarr", "prowlarr":
		return NewSQLiteMutator(configPath)

	// XML-configured Media Servers
	case "jellyfin":
		return NewXMLMutator(configPath, "NetworkConfiguration")

	// INI structured parsers
	case "qbittorrent", "sabnzbd", "tautulli":
		return NewINIMutator(configPath)

	// Pi-hole TOML / Lighttpd config mutator
	case "pihole", "pihole-ftl":
		return NewPiHoleMutator(configPath)

	default:
		// Unknown structures fallback to nil, bypassing injection sequences safely
		return nil
	}
}
