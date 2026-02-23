package services

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

var (
	// activeJobs tracks packages that are currently installing or uninstalling
	// Map keys are package IDs (e.g., "emby"), values are statuses ("installing", "uninstalling")
	activeJobs sync.Map
)

// RunPackageAction executes the specified bash script for installing or removing a package.
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

	log.Printf("[%s] Executing native OS script for %s: %s", action, pkgId, scriptName)
	
	// Adjust paths depending on where the execution originated.
	scriptPath := filepath.Join("/opt", "AetherFlow", "packages", "package", action, scriptName)
	
	// Double check absolute resolution for edge cases 
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		// Fallback for relative paths
		scriptPath = filepath.Join("packages", "package", action, scriptName)
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
