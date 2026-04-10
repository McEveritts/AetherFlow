package services

import (
	"aetherflow/models"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// exeDir caches the directory containing the running executable so config
// files that live next to the binary are always discoverable regardless of
// the process's current working directory.
var exeDir string

func init() {
	if exe, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exe)
		slog.Info("[config] executable dir resolved to", "value", exeDir)
	}
}

func resolveConfigPaths(envKey, fileName string) []string {
	paths := []string{}
	if customPath := os.Getenv(envKey); customPath != "" {
		paths = append(paths, customPath)
	}

	// Executable-relative: always works no matter the CWD
	if exeDir != "" {
		paths = append(paths, filepath.Join(exeDir, "config", fileName))
	}

	return append(paths, []string{
		filepath.Join("config", fileName),                                     // CWD is backend/
		filepath.Join("backend", "config", fileName),                          // CWD is project root
		filepath.Join("..", "backend", "config", fileName),                    // CWD is a sibling dir
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
			slog.Info("[config] loaded config from", "value", p)
			return data, nil
		}
	}

	slog.Info("[config] WARNING: could not find config file; tried paths", "value", paths)
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
func GetPackages() ([]models.Package, error) {
	data, err := readFirstConfigFile(resolveConfigPaths("AETHERFLOW_PACKAGES_CONFIG", "packages.json"))
	if err != nil {
		wrapped := fmt.Errorf("load packages.json: %w", err)
		slog.Info("[packages] ERROR", "value", wrapped)
		return nil, wrapped
	}

	var pkgs []models.Package
	if err := json.Unmarshal(data, &pkgs); err != nil {
		wrapped := fmt.Errorf("parse packages.json: %w", err)
		slog.Info("[packages] ERROR", "value", wrapped)
		return nil, wrapped
	}

	mergePackageAutomation(pkgs, loadPackageAutomation())

	// Iterate and check status concurrently to eliminate CPU/IO wait blocking
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := range pkgs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			
			pkgId := pkgs[idx].Name

			// 1. Check in-memory Installer Service Queue for active operations
			activeStatus := GetPackageJobStatus(pkgId)
			if activeStatus != "" {
				mu.Lock()
				pkgs[idx].Status = activeStatus
				mu.Unlock()
				return
			}

			// 2. For systemd services, check if the unit actually exists on the system
			if pkgs[idx].ServiceType == "systemd" && pkgs[idx].ServiceName != "" {
				// Check if the systemd unit file exists (not just its status)
				unitExists := false
				checkCmd := exec.Command("systemctl", "cat", pkgs[idx].ServiceName)
				if err := checkCmd.Run(); err == nil {
					unitExists = true
				}

				mu.Lock()
				if unitExists {
					pkgs[idx].Status = "installed"
				} else {
					pkgs[idx].Status = "uninstalled"
				}
				mu.Unlock()
			} else {
				// Legacy lock file check
				lockPath := pkgs[idx].LockFile
				if lockPath != "" {
					if _, err := os.Stat(lockPath); err == nil {
						mu.Lock()
						pkgs[idx].Status = "installed"
						mu.Unlock()
					} else {
						mu.Lock()
						pkgs[idx].Status = "uninstalled"
						mu.Unlock()
					}
				} else {
					mu.Lock()
					pkgs[idx].Status = "uninstalled"
					mu.Unlock()
				}
			}
		}(i)
	}
	wg.Wait()

	mergePackageUpdateState(pkgs)

	return pkgs, nil
}
