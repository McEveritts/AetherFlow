package services

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// GetServiceInfo queries systemctl for the status, uptime, and version of a given service.
func GetServiceInfo(serviceName string) (status, uptime, version string) {
	status = "stopped"
	uptime = "-"
	version = "-"

	cmdActive := exec.Command("systemctl", "is-active", serviceName)
	outActive, err := cmdActive.Output()
	if err == nil {
		activeStr := strings.TrimSpace(string(outActive))
		if activeStr == "active" {
			status = "running"
		}
	} else {
		cmdFailed := exec.Command("systemctl", "is-failed", serviceName)
		outFailed, errFailed := cmdFailed.Output()
		if errFailed == nil && strings.TrimSpace(string(outFailed)) == "failed" {
			status = "error"
		}
	}

	if status == "running" {
		cmdUptime := exec.Command("systemctl", "show", "-p", "ActiveEnterTimestamp", serviceName)
		outUptime, errUptime := cmdUptime.Output()
		if errUptime == nil {
			uptimeStr := strings.TrimSpace(string(outUptime))
			if strings.HasPrefix(uptimeStr, "ActiveEnterTimestamp=") {
				uptimeVal := strings.TrimPrefix(uptimeStr, "ActiveEnterTimestamp=")
				if uptimeVal != "" {
					uptime = FormatUptime(uptimeVal)
				}
			}
		}
	}

	return status, uptime, version
}

// PM2Process represents a single PM2 process from `pm2 jlist`
type PM2Process struct {
	Name   string `json:"name"`
	PID    int    `json:"pid"`
	PM2Env struct {
		Status    string `json:"status"`
		PMUptime  int64  `json:"pm_uptime"`
		Version   string `json:"version"`
		Instances int    `json:"instances"`
	} `json:"pm2_env"`
	Monit struct {
		Memory int64   `json:"memory"`
		CPU    float64 `json:"cpu"`
	} `json:"monit"`
}

// findPM2Binary locates the pm2 binary on the system
func findPM2Binary() string {
	// Try common locations
	paths := []string{
		"/usr/local/bin/pm2",
		"/usr/bin/pm2",
		"/root/.nvm/versions/node/*/bin/pm2", // nvm installs
	}

	for _, p := range paths {
		// Handle glob patterns
		if matches, err := filepath.Glob(p); err == nil && len(matches) > 0 {
			return matches[0]
		}
	}

	// Try which command
	if out, err := exec.Command("which", "pm2").Output(); err == nil {
		p := strings.TrimSpace(string(out))
		if p != "" {
			return p
		}
	}

	// Last resort: try PATH
	if p, err := exec.LookPath("pm2"); err == nil {
		return p
	}

	return ""
}

// GetPM2Services queries PM2 for running processes and returns a map of name -> PM2Process
func GetPM2Services() map[string]PM2Process {
	result := make(map[string]PM2Process)

	pm2Path := findPM2Binary()
	if pm2Path == "" {
		slog.Warn("pm2 binary not found")
		return result
	}

	cmd := exec.Command(pm2Path, "jlist")
	output, err := cmd.Output()
	if err != nil {
		slog.Error("PM2: failed to query jlist", "path", pm2Path, "error", err)
		return result
	}

	var processes []PM2Process
	if err := json.Unmarshal(output, &processes); err != nil {
		slog.Error("PM2: failed to parse output", "error", err)
		return result
	}

	slog.Info("PM2 processes discovered", "count", len(processes))
	for _, p := range processes {
		result[p.Name] = p
	}
	return result
}

// GetPM2ServiceInfo returns status, uptime, version for a PM2 process by name
func GetPM2ServiceInfo(pm2Processes map[string]PM2Process, processName string) (status, uptime, version string) {
	status = "stopped"
	uptime = "-"
	version = "-"

	proc, exists := pm2Processes[processName]
	if !exists {
		return
	}

	switch proc.PM2Env.Status {
	case "online":
		status = "running"
	case "stopped":
		status = "stopped"
	case "errored":
		status = "error"
	default:
		status = proc.PM2Env.Status
	}

	if status == "running" && proc.PM2Env.PMUptime > 0 {
		startTime := time.UnixMilli(proc.PM2Env.PMUptime)
		uptime = FormatDuration(time.Since(startTime))
	}

	if proc.PM2Env.Version != "" {
		version = proc.PM2Env.Version
	}

	return
}

// allowedServiceActions is the set of permitted service control verbs.
var allowedServiceActions = map[string]bool{"start": true, "stop": true, "restart": true, "status": true}

// safeServiceName strictly bounds the character set and length of service names.
var safeServiceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,63}$`)

// validateServiceName rejects names that don't match the strict allowlist.
func validateServiceName(name string) error {
	if !safeServiceName.MatchString(name) {
		return fmt.Errorf("invalid service name format: %q", name)
	}
	return nil
}

// ControlService safely executes start, stop, or restart on a given systemd service.
func ControlService(serviceName, action string) error {
	if !allowedServiceActions[action] {
		return fmt.Errorf("disallowed action: %s", action)
	}
	if err := validateServiceName(serviceName); err != nil {
		return err
	}
	slog.Info("systemctl executing", "action", action, "service", serviceName)
	cmd := exec.Command("sudo", "systemctl", action, "--", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("systemctl action failed", "action", action, "service", serviceName, "error", err, "output", string(output))
		return err
	}
	slog.Info("systemctl action succeeded", "action", action, "service", serviceName)
	return nil
}

// ControlPM2Service executes start, stop, or restart on a PM2 process.
func ControlPM2Service(processName, action string) error {
	if !allowedServiceActions[action] {
		return fmt.Errorf("disallowed action: %s", action)
	}
	if err := validateServiceName(processName); err != nil {
		return err
	}
	pm2Path := findPM2Binary()
	if pm2Path == "" {
		return fmt.Errorf("pm2 binary not found")
	}
	slog.Info("PM2 executing", "action", action, "process", processName)
	cmd := exec.Command(pm2Path, action, processName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("PM2 action failed", "action", action, "process", processName, "error", err, "output", string(output))
		return err
	}
	slog.Info("PM2 action succeeded", "action", action, "process", processName)
	return nil
}

// FormatUptime parses a systemd timestamp and returns a human-readable relative time
func FormatUptime(timestamp string) string {
	layouts := []string{
		"Mon 2006-01-02 15:04:05 MST",
		"Mon 2006-01-02 15:04:05 UTC",
		"2006-01-02 15:04:05 MST",
		"2006-01-02 15:04:05 UTC",
	}

	var t time.Time
	var err error
	for _, layout := range layouts {
		t, err = time.Parse(layout, strings.TrimSpace(timestamp))
		if err == nil {
			break
		}
	}

	if err != nil {
		return timestamp // Fallback to raw
	}

	return FormatDuration(time.Since(t))
}

// FormatDuration converts a Go duration to a short human-readable string
func FormatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
