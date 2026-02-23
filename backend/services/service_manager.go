package services

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// GetActiveServices pulls packages from the marketplace JSON,
// and merges OS runtime status info. It also appends core system services.
func GetActiveServices() map[string]interface{} {
	servicesList := make(map[string]interface{})

	// 1. Get Marketplace Packages (Emby, Radarr, etc.)
	pkgs := GetPackages()
	if pkgs != nil {
		for _, pkg := range pkgs {
			// Only show installed packages in the ServicesTab
			if pkg.Status == "installed" || pkg.Status == "running" {
				
				// Some packages map 1:1 with systemctl unit names, 
				// others might need string manipulation or map lookups.
				// For now, we lowercase the name to guess the systemd service.
				serviceName := strings.ToLower(pkg.Name)
				
				status, uptime, version := GetServiceInfo(serviceName)

				// AetherFlow installer overrides version to "latest" usually
				if version == "-" {
					version = "latest"
				}

				servicesList[pkg.Name] = gin.H{
					"status":  status,
					"uptime":  uptime,
					"version": version,
				}
			}
		}
	}

	// 2. Append Core Platform Services
	coreServices := map[string]string{
		"Nginx HTTP Server": "nginx",
		"PHP FPM Processor": "php8.1-fpm", // Specific to Debian/Ubuntu install script
		"AetherFlow Core":   "aetherflow-api",
		"AetherFlow Web":    "aetherflow-frontend",
	}

	for displayName, systemdName := range coreServices {
		status, uptime, version := GetServiceInfo(systemdName)
		servicesList[displayName] = gin.H{
			"status":  status,
			"uptime":  uptime,
			"version": version,
		}
	}

	// 3. (Optional) Check for explicitly supported standalone apps if not in JSON
	standaloneServices := map[string]string{
		"Docker Engine": "docker",
		"Plex Media Server": "plexmediaserver", // Sometimes not in the pkgs array properly
	}

	for displayName, systemdName := range standaloneServices {
		// Only add if it's actually running or installed
		status, uptime, version := GetServiceInfo(systemdName)
		if status != "stopped" && status != "error" {
			servicesList[displayName] = gin.H{
				"status":  status,
				"uptime":  uptime,
				"version": version,
			}
		} else if _, exists := servicesList[displayName]; !exists {
			// Include it anyway with stopped status to allow restarting
			servicesList[displayName] = gin.H{
				"status":  status,
				"uptime":  uptime,
				"version": version,
			}
		}
	}


	return servicesList
}
