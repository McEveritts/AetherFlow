package services

import (
	"log"
	"os/exec"
	"runtime"
	"strings"
)

// GetServiceInfo queries systemctl for the status, uptime (via ActiveEnterTimestamp), and version of a given service.
func GetServiceInfo(serviceName string) (status, uptime, version string) {
	if runtime.GOOS == "windows" {
		// Mock Data for Windows dev environment
		return "running", "Mocked Uptime", "1.0.0-mock"
	}

	// Default values
	status = "stopped"
	uptime = "-"
	version = "-"

	// Query if it's active
	// systemctl is-active returns "active\n" or "inactive\n"
	cmdActive := exec.Command("systemctl", "is-active", serviceName)
	outActive, err := cmdActive.Output()
	if err == nil {
		activeStr := strings.TrimSpace(string(outActive))
		if activeStr == "active" {
			status = "running"
		}
	} else {
		// If command fails, checking if it's failed status
		cmdFailed := exec.Command("systemctl", "is-failed", serviceName)
		outFailed, errFailed := cmdFailed.Output()
		if errFailed == nil && strings.TrimSpace(string(outFailed)) == "failed" {
			status = "error"
		}
	}

	// If running, query uptime via ActiveEnterTimestamp
	if status == "running" {
		cmdUptime := exec.Command("systemctl", "show", "-p", "ActiveEnterTimestamp", serviceName)
		outUptime, errUptime := cmdUptime.Output()
		if errUptime == nil {
			uptimeStr := strings.TrimSpace(string(outUptime))
			// format typically: ActiveEnterTimestamp=Mon 2026-02-23 00:00:00 UTC
			if strings.HasPrefix(uptimeStr, "ActiveEnterTimestamp=") {
				uptimeVal := strings.TrimPrefix(uptimeStr, "ActiveEnterTimestamp=")
				if uptimeVal != "" {
					uptime = uptimeVal
				}
			}
		}
	}

	return status, uptime, version
}

// ControlService safely executes start, stop, or restart on a given service.
func ControlService(serviceName, action string) error {
	if runtime.GOOS == "windows" {
		log.Printf("[Mock Systemctl] %s triggered on %s", action, serviceName)
		return nil
	}

	log.Printf("[Systemctl] Executing: sudo systemctl %s %s", action, serviceName)
	cmd := exec.Command("sudo", "systemctl", action, serviceName)
	
	// Consider this fire-and-forget, but capture output for logs
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to %s service %s: %v\nOutput: %s", action, serviceName, err, string(output))
		return err
	}

	log.Printf("Successfully executed %s on %s", action, serviceName)
	return nil
}
