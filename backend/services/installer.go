package services

import (
	"bufio"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// JobInfo holds detailed progress info for an active install/uninstall job.
type JobInfo struct {
	Status    string    `json:"status"`     // "installing" or "uninstalling"
	StartedAt time.Time `json:"started_at"`
	LogLines  int       `json:"log_lines"`  // total lines captured so far
	LastLine  string    `json:"last_line"`  // most recent meaningful log line
	Progress  int       `json:"progress"`   // estimated 0-100
}

var (
	// activeJobs tracks packages that are currently installing or uninstalling
	activeJobs sync.Map
)

// RunPackageAction executes the specified bash script for installing or removing a package.
// It streams output line-by-line so we can track progress in real time.
func RunPackageAction(action, pkgId, scriptName, lockFile string) {
	status := "installing"
	if action == "remove" {
		status = "uninstalling"
	}

	job := &JobInfo{
		Status:    status,
		StartedAt: time.Now(),
		LogLines:  0,
		LastLine:  "Starting...",
		Progress:  0,
	}
	activeJobs.Store(pkgId, job)

	log.Printf("[%s] Starting asynchronous package action for %s...", action, pkgId)

	defer func() {
		activeJobs.Delete(pkgId)
		log.Printf("[%s] Action finalized for %s. Removed from active queues.", action, pkgId)
	}()

	// Resolve script path
	scriptPath := filepath.Join("/opt", "AetherFlow", "packages", "package", action, scriptName)
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		scriptPath = filepath.Join("packages", "package", action, scriptName)
	}

	log.Printf("[%s] Executing script: %s", action, scriptPath)

	cmd := exec.Command("bash", scriptPath)
	// Merge stderr into stdout so we get everything
	cmd.Stderr = nil

	// Use a pipe to stream stdout line-by-line
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[%s] Error creating stdout pipe for %s: %v", action, scriptName, err)
		// Fallback to CombinedOutput
		output, runErr := exec.Command("bash", scriptPath).CombinedOutput()
		if runErr != nil {
			log.Printf("[%s] Fallback error: %v, output: %s", action, runErr, string(output))
		}
		return
	}
	cmd.Stderr = cmd.Stdout // merge stderr into stdout pipe

	if err := cmd.Start(); err != nil {
		log.Printf("[%s] Error starting script %s: %v", action, scriptName, err)
		return
	}

	// Stream lines and update progress
	scanner := bufio.NewScanner(stdout)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())

		// Update the job info atomically
		job.LogLines = lineCount
		if line != "" {
			job.LastLine = line
		}

		// Estimate progress: typical scripts produce 5-50 lines
		// Use a logarithmic curve that approaches 95% but never reaches 100%
		// until the script actually finishes
		estimated := int(float64(lineCount) / float64(lineCount+8) * 95)
		if estimated > 95 {
			estimated = 95
		}
		job.Progress = estimated

		log.Printf("[%s:%s] line %d: %s", action, pkgId, lineCount, line)
	}

	if err := cmd.Wait(); err != nil {
		log.Printf("[%s] Script %s exited with error: %v", action, scriptName, err)
		job.LastLine = "Error: " + err.Error()
		job.Progress = 100
		return
	}

	job.Progress = 100
	job.LastLine = "Complete!"
	log.Printf("[%s] Successfully executed script %s (%d lines)", action, scriptName, lineCount)
}

// GetPackageJobStatus returns the simple status string for backward compat
func GetPackageJobStatus(pkgId string) string {
	if val, ok := activeJobs.Load(pkgId); ok {
		if job, ok := val.(*JobInfo); ok {
			return job.Status
		}
	}
	return ""
}

// GetPackageJobInfo returns the full progress info for a package job
func GetPackageJobInfo(pkgId string) *JobInfo {
	if val, ok := activeJobs.Load(pkgId); ok {
		if job, ok := val.(*JobInfo); ok {
			return job
		}
	}
	return nil
}
