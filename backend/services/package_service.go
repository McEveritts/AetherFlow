package services

import (
	"aetherflow/models"
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
)

// GetPackages reads the packages.json and determines installation status
func GetPackages() []models.Package {
	// Paths might vary based on where the Go binary is run from.
	// We'll try relative to backend/ first, then relative to root.
	configPaths := []string{
		filepath.Join("..", "dashboard", "config", "packages.json"),
		filepath.Join("dashboard", "config", "packages.json"),
		filepath.Join("/opt", "AetherFlow", "dashboard", "config", "packages.json"),
	}

	var data []byte
	var err error
	for _, p := range configPaths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil
	}

	var pkgs []models.Package
	if err := json.Unmarshal(data, &pkgs); err != nil {
		return nil
	}

	// Iterate and check status
	for i := range pkgs {
		pkgId := pkgs[i].Name
		
		// Mock hit counter
		pkgs[i].Hits = rand.Intn(50000)

		// 1. Check in-memory Installer Service Queue for active operations
		activeStatus := GetPackageJobStatus(pkgId)
		if activeStatus != "" {
			pkgs[i].Status = activeStatus
			continue
		}

		// 2. For systemd services, check if the unit actually exists on the system
		if pkgs[i].ServiceType == "systemd" && pkgs[i].ServiceName != "" {
			// Check if the systemd unit file exists (not just its status)
			unitExists := false
			checkCmd := exec.Command("systemctl", "cat", pkgs[i].ServiceName)
			if err := checkCmd.Run(); err == nil {
				unitExists = true
			}

			if unitExists {
				pkgs[i].Status = "installed"
			} else {
				pkgs[i].Status = "uninstalled"
			}
		} else {
			// Legacy lock file check
			lockPath := pkgs[i].LockFile
			if lockPath != "" {
				if _, err := os.Stat(lockPath); err == nil {
					pkgs[i].Status = "installed"
				} else {
					pkgs[i].Status = "uninstalled"
				}
			} else {
				pkgs[i].Status = "uninstalled"
			}
		}
	}

	return pkgs
}
