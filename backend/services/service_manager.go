package services

import (
	"log/slog"

	"github.com/gin-gonic/gin"
)

// Systemd core services to always check
var systemdCoreServices = map[string]string{
	"AetherFlow API":      "aetherflow-api",
	"AetherFlow Frontend": "aetherflow-frontend",
	"Apache2 Web Server":  "apache2",
}

// GetActiveServices pulls packages from the marketplace JSON,
// and merges OS runtime status info. It also appends core system services.
func GetActiveServices() map[string]interface{} {
	servicesList := make(map[string]interface{})

	// 2. Core Systemd Services
	for displayName, systemdName := range systemdCoreServices {
		status, uptime, version := GetServiceInfo(systemdName)
		servicesList[displayName] = gin.H{
			"status":     status,
			"uptime":     uptime,
			"version":    version,
			"managed_by": "systemd",
			"process":    systemdName,
			"id":         systemdName,
		}
	}

	// 3. Get Marketplace Packages — only installed ones
	pkgs, err := GetPackages()
	if err != nil {
		slog.Info("[services] unable to load package catalog", "error", err)
		return servicesList
	}

	for _, pkg := range pkgs {
		if pkg.Status != "installed" && pkg.Status != "running" {
			continue
		}

		// Use ServiceName from packages.json if available, else fall back to package name
		serviceName := pkg.ServiceName
		if serviceName == "" {
			serviceName = pkg.Name
		}

		var status, uptime, version string
		managedBy := "systemd"

		status, uptime, version = GetServiceInfo(serviceName)

		if version == "-" {
			version = "latest"
		}

		servicesList[pkg.Label] = gin.H{
			"status":     status,
			"uptime":     uptime,
			"version":    version,
			"managed_by": managedBy,
			"process":    serviceName,
			"id":         pkg.Name,
		}
	}

	return servicesList
}
