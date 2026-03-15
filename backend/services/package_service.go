package services

import (
	"aetherflow/models"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
)

func resolveConfigPaths(envKey, fileName string) []string {
	paths := []string{}
	if customPath := os.Getenv(envKey); customPath != "" {
		paths = append(paths, customPath)
	}

	return append(paths, []string{
		filepath.Join("config", fileName),                                     // Canonical: backend/config/
		filepath.Join("..", "backend", "config", fileName),                    // From project root
		filepath.Join("/opt", "AetherFlow", "backend", "config", fileName),   // Production
		filepath.Join("..", "dashboard", "config", fileName),                  // Legacy fallback
		filepath.Join("dashboard", "config", fileName),                        // Legacy fallback (alt)
		filepath.Join("/opt", "AetherFlow", "dashboard", "config", fileName), // Legacy production fallback
	}...)
}

func readFirstConfigFile(paths []string) ([]byte, error) {
	var (
		data []byte
		err  error
	)

	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			return data, nil
		}
	}

	return nil, err
}

func loadPackageAutomation() map[string]models.PackageAutomation {
	data, err := readFirstConfigFile(resolveConfigPaths("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", "package_automation.json"))
	if err != nil {
		return nil
	}

	var automation map[string]models.PackageAutomation
	if err := json.Unmarshal(data, &automation); err != nil {
		return nil
	}

	return automation
}

func mergePackageAutomation(pkgs []models.Package, automation map[string]models.PackageAutomation) {
	if len(automation) == 0 {
		return
	}

	for i := range pkgs {
		entry, ok := automation[pkgs[i].Name]
		if !ok {
			continue
		}

		pkgs[i].UpdateSource = entry.UpdateSource
		pkgs[i].UpdateRepo = entry.UpdateRepo
		pkgs[i].UpdateRepoURL = entry.UpdateRepoURL
		pkgs[i].UpdatePackage = entry.UpdatePackage
		pkgs[i].VersionCommand = append([]string(nil), entry.VersionCommand...)
		pkgs[i].VersionRegex = entry.VersionRegex
		pkgs[i].SandboxProfile = entry.SandboxProfile
		pkgs[i].SandboxReadWrite = append([]string(nil), entry.SandboxReadWrite...)
		pkgs[i].SandboxServiceIDs = append([]string(nil), entry.SandboxServiceIDs...)
	}
}

func mergePackageUpdateState(pkgs []models.Package) {
	updateMap := GetPackageUpdateMap()
	if len(updateMap) == 0 {
		return
	}

	for i := range pkgs {
		update, ok := updateMap[pkgs[i].Name]
		if !ok {
			continue
		}

		pkgs[i].InstalledVersion = update.InstalledVersion
		pkgs[i].LatestVersion = update.LatestVersion
		pkgs[i].UpdateAvailable = update.UpdateAvailable
		pkgs[i].UpdateCheckedAt = update.CheckedAt
		pkgs[i].UpdateURL = update.URL
		pkgs[i].UpdateError = update.LastError
	}
}

// GetPackages reads the packages.json and determines installation status.
func GetPackages() []models.Package {
	data, err := readFirstConfigFile(resolveConfigPaths("AETHERFLOW_PACKAGES_CONFIG", "packages.json"))
	if err != nil {
		return nil
	}

	var pkgs []models.Package
	if err := json.Unmarshal(data, &pkgs); err != nil {
		return nil
	}

	mergePackageAutomation(pkgs, loadPackageAutomation())

	// Iterate and check status
	for i := range pkgs {
		pkgId := pkgs[i].Name

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

	mergePackageUpdateState(pkgs)

	return pkgs
}
