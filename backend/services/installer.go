package services

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

var (
	// activeJobs tracks packages that are currently installing or uninstalling
	// Map keys are package IDs (e.g., "emby"), values are statuses ("installing", "uninstalling")
	activeJobs sync.Map
)

// RunPackageAction executes the specified bash script or simulates it on Windows.
// It also creates or removes the corresponding global lock file.
func RunPackageAction(action, pkgId, scriptName, lockFile string) {
	// Set the status immediately
	status := "installing"
	if action == "remove" {
		status = "uninstalling"
	}
	activeJobs.Store(pkgId, status)

	log.Printf("[%s] Starting asynchronous package action for %s...", action, pkgId)

	// Defer cleanup - regardless of success or failure, we want the UI polling to resume normal state
	defer func() {
		activeJobs.Delete(pkgId)
		log.Printf("[%s] Action finalized for %s. Removed from active queues.", action, pkgId)
	}()

	if runtime.GOOS == "windows" {
		log.Printf("[%s] Dev environment detected (Windows). Simulating 5s execution for %s...", action, pkgId)
		time.Sleep(5 * time.Second)
		
		if lockFile != "" {
			// AetherFlow expects lock files at the absolute path specified in the JSON usually (e.g., /install/.emby.lock)
			// For Windows mock dev, we will write them to the relative path `tmp/.pkg.lock` just to get the mechanism working locally
			os.MkdirAll("tmp", 0755)
			localLockPath := filepath.Join("tmp", filepath.Base(lockFile))
			
			if action == "install" {
				err := os.WriteFile(localLockPath, []byte("installed via windows mock"), 0644)
				if err != nil {
					log.Printf("Failed to write mock lock file: %v", err)
				}
			} else {
				os.Remove(localLockPath)
			}
		}
		return
	}

	// For production Linux environments
	log.Printf("[%s] Executing native OS script for %s: %s", action, pkgId, scriptName)
	
	// Adjust paths depending on where the execution originated.
	scriptPath := filepath.Join("packages", "package", action, scriptName)
	
	// Double check absolute resolution for edge cases 
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		// Fallback for paths referencing the source dir
		scriptPath = filepath.Join("..", "packages", "package", action, scriptName)
	}

	cmd := exec.Command("bash", scriptPath)
	// We're letting it run disconnected
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		log.Printf("[%s] Error running script %s: %v", action, scriptName, err)
		log.Printf("[%s] Command output: %s", action, string(output))
		return
	}

	log.Printf("[%s] Successfully executed script %s", action, scriptName)
}

// GetPackageJobStatus allows other services to query if a specific package is currently locked in an action
func GetPackageJobStatus(pkgId string) string {
	if val, ok := activeJobs.Load(pkgId); ok {
		return val.(string)
	}
	return ""
}
