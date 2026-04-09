package services

import (
	"os"
	"strings"
)

// EnvironmentPolicy defines the explicit runtime policy matrix for platform-specific behavior
type EnvironmentPolicy struct {
	IsWSL          bool
	SandboxEnabled bool
	RequireRoot    bool
	EnforceCgroups bool
}

// IsWSL dynamically detects if the system is running inside Windows Subsystem for Linux
func IsWSL() bool {
	data, err := os.ReadFile("/proc/version")
	if err == nil {
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, "microsoft") || strings.Contains(lower, "wsl") {
			return true
		}
	}
	return false
}

// GetRuntimePolicy creates an explicit runtime policy matrix depending on the underlying environment
func GetRuntimePolicy() EnvironmentPolicy {
	isWsl := IsWSL()
	
	// On Bare Metal, we aggressively sandbox systemd units and enforce restrictions.
	// On WSL, systemd sandboxing (like PrivateTmp, ProtectSystem, etc) often fails 
	// unless running under a very specific WSL2 systemd configuration. 
	// We safely bypass these incompatible restrictions on WSL.
	return EnvironmentPolicy{
		IsWSL:          isWsl,
		SandboxEnabled: !isWsl,
		RequireRoot:    !isWsl,
		EnforceCgroups: !isWsl,
	}
}
