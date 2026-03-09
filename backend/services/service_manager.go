package services

import (
	"os/exec"
	"strings"
	"time"

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
	pkgs := GetPackages()
	if pkgs != nil {
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

			if pkg.ServiceType == "docker" {
				// For Docker services, check docker container status
				status, uptime, version = GetDockerServiceInfo(serviceName)
				managedBy = "docker"
			} else {
				status, uptime, version = GetServiceInfo(serviceName)
			}

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
	}

	return servicesList
}

// GetDockerServiceInfo checks Docker container status via docker inspect
func GetDockerServiceInfo(containerName string) (status, uptime, version string) {
	status = "stopped"
	uptime = "-"
	version = "-"

	// Check if Docker daemon is running first
	dockerStatus, _, _ := GetServiceInfo("docker")
	if dockerStatus != "running" {
		return
	}

	// Query container status
	statusCmd := exec.Command("docker", "inspect", "--format", "{{.State.Status}}", containerName)
	statusOut, err := statusCmd.Output()
	if err != nil {
		return // Container doesn't exist or can't be inspected
	}

	containerStatus := strings.TrimSpace(string(statusOut))
	switch containerStatus {
	case "running":
		status = "running"
	case "exited", "dead":
		status = "stopped"
	case "restarting":
		status = "error"
	default:
		status = containerStatus
	}

	// Get uptime from container start time
	if status == "running" {
		startCmd := exec.Command("docker", "inspect", "--format", "{{.State.StartedAt}}", containerName)
		startOut, err := startCmd.Output()
		if err == nil {
			startStr := strings.TrimSpace(string(startOut))
			if t, err := time.Parse(time.RFC3339Nano, startStr); err == nil {
				uptime = FormatDuration(time.Since(t))
			}
		}
	}

	// Get image version
	imageCmd := exec.Command("docker", "inspect", "--format", "{{.Config.Image}}", containerName)
	imageOut, err := imageCmd.Output()
	if err == nil {
		image := strings.TrimSpace(string(imageOut))
		if parts := strings.SplitN(image, ":", 2); len(parts) == 2 {
			version = parts[1]
		} else {
			version = "latest"
		}
	}

	return
}
