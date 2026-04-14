package services

import (
	"log/slog"

	"github.com/gin-gonic/gin"
)

// PM2 process names used by AetherFlow
var pm2CoreServices = map[string]string{
	"AetherFlow API":      "aetherflow-api",
	"AetherFlow Frontend": "aetherflow-frontend",
}

// Systemd core services to always check
var systemdCoreServices = map[string]string{
	"Apache2 Web Server": "apache2",
}

// GetActiveServices pulls packages from the marketplace JSON,
// and merges OS runtime status info. It also appends core system services.
func GetActiveServices() map[string]interface{} {
	servicesList := make(map[string]interface{})

	// Pre-fetch PM2 data once (avoids calling pm2 jlist per service)
	pm2Processes := GetPM2Services()

	// 1. Core PM2 Services (AetherFlow API + Frontend)
	for displayName, pm2Name := range pm2CoreServices {
		status, uptime, version := GetPM2ServiceInfo(pm2Processes, pm2Name)
		servicesList[displayName] = gin.H{
			"status":     status,
			"uptime":     uptime,
			"version":    version,
			"managed_by": "pm2",
			"process":    pm2Name,
		}
	}

	// 2. Core Systemd Services
	for displayName, systemdName := range systemdCoreServices {
		status, uptime, version := GetServiceInfo(systemdName)
		servicesList[displayName] = gin.H{
			"status":     status,
			"uptime":     uptime,
			"version":    version,
			"managed_by": "systemd",
			"process":    systemdName,
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
		}
	}

	return servicesList
}
