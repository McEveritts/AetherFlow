package services

import (
	"bufio"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

// PackageEventBroadcaster is an optional callback notified when a package job changes state or progress.
type PackageEventBroadcaster func(pkgId, action, status string, progress int, lastLine string)

var (
	// activeJobs tracks packages that are currently installing or uninstalling
	activeJobs sync.Map

	progressMarkerRegex = regexp.MustCompile(`\[PROGRESS:(\d{1,3})\]\s*(.*)`)

	broadcasterMu           sync.RWMutex
	packageEventBroadcaster PackageEventBroadcaster
)

// SetPackageEventBroadcaster registers a callback for real-time WebSocket broadcasts on package actions.
func SetPackageEventBroadcaster(fn PackageEventBroadcaster) {
	broadcasterMu.Lock()
	defer broadcasterMu.Unlock()
	packageEventBroadcaster = fn
}

func notifyPackageEvent(pkgId, action, status string, progress int, lastLine string) {
	broadcasterMu.RLock()
	fn := packageEventBroadcaster
	broadcasterMu.RUnlock()
	if fn != nil {
		fn(pkgId, action, status, progress, lastLine)
	}
}

// ResolvePackageScriptPath finds the bash script location. Returns empty string if missing.
func ResolvePackageScriptPath(action, scriptName string) string {
	candidates := []string{
		filepath.Join("/opt", "AetherFlow", "current", "packages", "package", action, scriptName),
		filepath.Join("/opt", "AetherFlow", "packages", "package", action, scriptName),
	}
	if exeDir != "" {
		candidates = append(candidates,
			filepath.Join(exeDir, "packages", "package", action, scriptName),
			filepath.Join(exeDir, "..", "packages", "package", action, scriptName),
		)
	}
	candidates = append(candidates,
		filepath.Join("packages", "package", action, scriptName),
		filepath.Join("..", "packages", "package", action, scriptName),
		filepath.Join("..", "..", "packages", "package", action, scriptName),
	)

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// parseProgressLine extracts an explicit [PROGRESS:XX] milestone if present.
func parseProgressLine(line string) (int, string, bool) {
	matches := progressMarkerRegex.FindStringSubmatch(line)
	if len(matches) < 3 {
		return 0, line, false
	}
	pct, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, line, false
	}
	if pct < 0 {
		pct = 0
	} else if pct > 100 {
		pct = 100
	}
	cleanMsg := strings.TrimSpace(matches[2])
	if cleanMsg == "" {
		cleanMsg = line
	}
	return pct, cleanMsg, true
}

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
	notifyPackageEvent(pkgId, action, job.Status, job.Progress, job.LastLine)

	slog.Info("starting package action", "action", action, "package", pkgId)

	defer func() {
		// Use a delayed deletion to allow frontend SWR polling to catch failure states
		go func() {
			time.Sleep(30 * time.Second)
			activeJobs.Delete(pkgId)
			slog.Info("package action finalized", "action", action, "package", pkgId)
		}()
	}()

	scriptPath := ResolvePackageScriptPath(action, scriptName)
	if scriptPath == "" {
		slog.Error("install script not found", "action", action, "package", pkgId)
		job.Status = "failed"
		job.LastLine = "Error: Script not found"
		job.Progress = 100
		notifyPackageEvent(pkgId, action, job.Status, job.Progress, job.LastLine)
		return
	}

	slog.Info("executing script", "action", action, "path", scriptPath)

	lineCount := 0
	hasExplicitProgress := false
	updateProgress := func(line string) {
		lineCount++
		job.LogLines = lineCount

		if pct, cleanMsg, ok := parseProgressLine(line); ok {
			hasExplicitProgress = true
			if pct > job.Progress {
				job.Progress = pct
			}
			job.LastLine = cleanMsg
			notifyPackageEvent(pkgId, action, job.Status, job.Progress, job.LastLine)
		} else {
			if line != "" {
				job.LastLine = line
			}
			if !hasExplicitProgress {
				estimated := int(float64(lineCount) / float64(lineCount+8) * 95)
				if estimated > 95 {
					estimated = 95
				}
				job.Progress = estimated
			}
		}
		slog.Debug("script output", "action", action, "package", pkgId, "line", lineCount, "text", line)
	}

	allocatedPort := 0
	if action == "install" {
		allocatedPort = PreAllocateAppPort(pkgId)
	}

	if IsRunnerAvailable() {
		if err := DispatchPackageStream(action, pkgId, scriptName, updateProgress); err != nil {
			slog.Error("runner package script exited with error", "action", action, "script", scriptName, "error", err)
			job.Status = "failed"
			job.LastLine = "Error: " + err.Error()
			job.Progress = 100
			notifyPackageEvent(pkgId, action, job.Status, job.Progress, job.LastLine)
			return
		}
	} else {
		// Serialize all package operations across the host to prevent apt/dpkg lock contention.
		packageMutex.Lock()
		defer packageMutex.Unlock()

		cmd := buildHardenedPackageCommand(scriptPath, true)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			slog.Error("failed to create stdout pipe; running synchronous fallback", "action", action, "script", scriptName, "error", err)
			output, runErr := buildHardenedPackageCommand(scriptPath, true).CombinedOutput()
			job.LogLines = len(strings.Split(string(output), "\n"))
			if runErr != nil {
				job.Status = "failed"
				job.LastLine = "Error: " + runErr.Error()
				job.Progress = 100
				notifyPackageEvent(pkgId, action, job.Status, job.Progress, job.LastLine)
				slog.Error("fallback execution error", "action", action, "error", runErr)
				return
			}
		} else {
			cmd.Stderr = cmd.Stdout

			if err := cmd.Start(); err != nil {
				job.Status = "failed"
				job.LastLine = "Error: " + err.Error()
				job.Progress = 100
				notifyPackageEvent(pkgId, action, job.Status, job.Progress, job.LastLine)
				slog.Error("failed to start script", "action", action, "script", scriptName, "error", err)
				return
			}

			scanner := bufio.NewScanner(stdout)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			for scanner.Scan() {
				updateProgress(strings.TrimSpace(scanner.Text()))
			}

			if err := cmd.Wait(); err != nil {
				slog.Error("script exited with error", "action", action, "script", scriptName, "error", err)
				job.Status = "failed"
				job.LastLine = "Error: " + err.Error()
				job.Progress = 100
				notifyPackageEvent(pkgId, action, job.Status, job.Progress, job.LastLine)
				return
			}
		}
	}

	switch action {
	case "install":
		if err := ApplyPackageSandbox(pkgId); err != nil {
			slog.Warn("sandbox hardening warning", "package", pkgId, "error", err)
		}
		if bpRes, err := ApplyBlueprintPostInstall(pkgId, allocatedPort); err != nil {
			slog.Warn("blueprint post-install setup warning", "package", pkgId, "error", err)
		} else if bpRes != nil {
			slog.Info("blueprint post-install applied",
				"package", pkgId,
				"allocated_port", bpRes.AllocatedPort,
				"port_reassigned", bpRes.PortReassigned,
				"internal_domain", bpRes.InternalDomain)
		}
		RefreshPackageUpdateByID(pkgId)
	case "remove":
		if err := TeardownBlueprintUninstall(pkgId); err != nil {
			slog.Warn("blueprint uninstall teardown warning", "package", pkgId, "error", err)
		}
		if err := DeletePackageUpdateRecord(pkgId); err != nil {
			slog.Warn("failed to clear update state", "package", pkgId, "error", err)
		}
	}

	job.Progress = 100
	job.LastLine = "Complete!"
	if action == "install" {
		job.Status = "installed"
	} else {
		job.Status = "uninstalled"
	}
	notifyPackageEvent(pkgId, action, job.Status, job.Progress, job.LastLine)
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
