package services

import (
	"bufio"
	"log/slog"
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

	slog.Info("starting package action", "action", action, "package", pkgId)

	defer func() {
		activeJobs.Delete(pkgId)
		slog.Info("package action finalized", "action", action, "package", pkgId)
	}()

	// Resolve script path — try multiple locations so this works from any CWD
	candidates := []string{
		filepath.Join("/opt", "AetherFlow", "packages", "package", action, scriptName),
	}
	if exeDir != "" {
		// Executable lives in backend/, so packages/ is ../packages/ relative to it
		candidates = append(candidates, filepath.Join(exeDir, "..", "packages", "package", action, scriptName))
	}
	candidates = append(candidates,
		filepath.Join("packages", "package", action, scriptName),       // CWD is project root
		filepath.Join("..", "packages", "package", action, scriptName), // CWD is backend/
	)

	scriptPath := ""
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			scriptPath = c
			break
		}
	}
	if scriptPath == "" {
		slog.Error("install script not found", "action", action, "package", pkgId)
		return
	}

	slog.Info("executing script", "action", action, "path", scriptPath)

	cmd := exec.Command("bash", scriptPath)
	// Merge stderr into stdout so we get everything
	cmd.Stderr = nil

	// Use a pipe to stream stdout line-by-line
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		slog.Error("failed to create stdout pipe", "action", action, "script", scriptName, "error", err)
		// Fallback to CombinedOutput
		output, runErr := exec.Command("bash", scriptPath).CombinedOutput()
		if runErr != nil {
			slog.Error("fallback execution error", "action", action, "error", runErr, "output", string(output))
		}
		return
	}
	cmd.Stderr = cmd.Stdout // merge stderr into stdout pipe

	if err := cmd.Start(); err != nil {
		slog.Error("failed to start script", "action", action, "script", scriptName, "error", err)
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

		slog.Debug("script output", "action", action, "package", pkgId, "line", lineCount, "text", line)
	}

	if err := cmd.Wait(); err != nil {
		slog.Error("script exited with error", "action", action, "script", scriptName, "error", err)
		job.LastLine = "Error: " + err.Error()
		job.Progress = 100
		return
	}

	switch action {
	case "install":
		if err := ApplyPackageSandbox(pkgId); err != nil {
				slog.Warn("sandbox hardening warning", "package", pkgId, "error", err)
		}
		RefreshPackageUpdateByID(pkgId)
	case "remove":
		if err := DeletePackageUpdateRecord(pkgId); err != nil {
			slog.Warn("failed to clear update state", "package", pkgId, "error", err)
		}
	}

	job.Progress = 100
	job.LastLine = "Complete!"
	slog.Info("script completed successfully", "action", action, "script", scriptName, "lines", lineCount)
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
