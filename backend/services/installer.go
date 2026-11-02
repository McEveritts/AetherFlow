package services

import (
	"aetherflow/db"
	"aetherflow/models"
	"bufio"
	"fmt"
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
	if (action != "install" && action != "remove" && action != "update") || !safeScriptName.MatchString(scriptName) {
		return ""
	}
	dirs := []string{action}
	scripts := []string{scriptName}
	if action == "update" {
		dirs = []string{"update", "install"}
		if strings.HasPrefix(scriptName, "updatepackage-") {
			pkgPart := strings.TrimPrefix(scriptName, "updatepackage-")
			scripts = []string{scriptName, "installpackage-" + pkgPart}
		} else if strings.HasPrefix(scriptName, "installpackage-") {
			pkgPart := strings.TrimPrefix(scriptName, "installpackage-")
			scripts = []string{"updatepackage-" + pkgPart, scriptName}
		}
	}

	var candidates []string
	for _, dir := range dirs {
		for _, sc := range scripts {
			candidates = append(candidates,
				filepath.Join("/opt", "AetherFlow", "current", "packages", "package", dir, sc),
				filepath.Join("/opt", "AetherFlow", "packages", "package", dir, sc),
			)
			if exeDir != "" {
				candidates = append(candidates,
					filepath.Join(exeDir, "packages", "package", dir, sc),
					filepath.Join(exeDir, "..", "packages", "package", dir, sc),
				)
			}
			candidates = append(candidates,
				filepath.Join("packages", "package", dir, sc),
				filepath.Join("..", "packages", "package", dir, sc),
				filepath.Join("..", "..", "packages", "package", dir, sc),
			)
		}
	}

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

func resolveExistingUpdatePort(pkgID string) (int, error) {
	canonicalApp := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pkgID)), ".service")
	blueprint := GetBlueprint(canonicalApp)
	if blueprint != nil {
		if blueprint.DefaultPort <= 0 {
			return 0, nil
		}
		if blueprint.AppName != "" {
			canonicalApp = blueprint.AppName
		}
	} else if canonicalApp == "af-maintainerr" {
		canonicalApp = "maintainerr"
	}

	if db.DB == nil {
		return 0, fmt.Errorf("cannot resolve existing configured port for %s: database unavailable", canonicalApp)
	}
	db.InvalidateIngressCache()
	existingConfig, err := db.GetAppIngressConfig(canonicalApp)
	if err != nil {
		return 0, fmt.Errorf("cannot read existing configured port for %s: %w", canonicalApp, err)
	}
	if existingConfig == nil {
		return 0, fmt.Errorf("missing persisted ingress port mapping for %s update", canonicalApp)
	}
	if existingConfig.ListenPort < 1024 || existingConfig.ListenPort > 65535 {
		return 0, fmt.Errorf("invalid persisted listen port %d for %s update", existingConfig.ListenPort, canonicalApp)
	}
	return existingConfig.ListenPort, nil
}

func applyPostInstallWithoutCallerRestart(pkgID string, allocatedPort int) (*BlueprintSetupResult, error) {
	cleanID := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pkgID)), ".service")
	blueprint := GetBlueprint(cleanID)
	if blueprint == nil {
		return nil, fmt.Errorf("no blueprint registered for %q", pkgID)
	}

	activePort := allocatedPort
	if blueprint.DefaultPort > 0 && activePort <= 0 {
		activePort = blueprint.DefaultPort
	}
	reassigned := blueprint.DefaultPort > 0 && activePort != blueprint.DefaultPort

	result := &BlueprintSetupResult{
		AppName:        blueprint.AppName,
		ServiceName:    blueprint.ServiceName,
		AllocatedPort:  activePort,
		DefaultPort:    blueprint.DefaultPort,
		PortReassigned: reassigned,
		InternalDomain: blueprint.InternalDomain,
	}

	ingressCfg := models.AppIngressConfig{
		AppName:    blueprint.AppName,
		ListenPort: activePort,
	}
	existing, existingErr := db.GetAppIngressConfig(blueprint.AppName)
	if existingErr == nil && existing != nil && strings.TrimSpace(existing.PublicDomain) != "" {
		ingressCfg.PublicDomain = strings.TrimSpace(existing.PublicDomain)
		ingressCfg.ExternalAccessEnabled = existing.ExternalAccessEnabled
		ingressCfg.TLSEnabled = existing.TLSEnabled
	} else if baseDomain := ResolveBaseDomain(); baseDomain != "" && activePort > 0 {
		ingressCfg.PublicDomain = FormatAppPublicDomain(blueprint.AppName, baseDomain)
		ingressCfg.ExternalAccessEnabled = true
		ingressCfg.TLSEnabled = true
	} else if existingErr == nil && existing != nil {
		ingressCfg.PublicDomain = existing.PublicDomain
		ingressCfg.ExternalAccessEnabled = existing.ExternalAccessEnabled
		ingressCfg.TLSEnabled = existing.TLSEnabled
	}

	if activePort > 0 || blueprint.IsNetworkApp {
		if err := db.SetAppIngressConfig(ingressCfg); err != nil {
			slog.Warn("failed to persist blueprint ingress config", "app", blueprint.AppName, "error", err)
		} else if activePort > 0 {
			result.IngressSynced = true
		}
	}
	result.PublicDomain = ingressCfg.PublicDomain
	result.ExternalAccessEnabled = ingressCfg.ExternalAccessEnabled
	if ingressCfg.ExternalAccessEnabled && ingressCfg.PublicDomain != "" {
		TriggerApacheCertSync()
	}

	if blueprint.InternalDomain != "" {
		dnsMgr := NewDNSManager()
		if err := dnsMgr.AppendOrUpdateDomains([]string{blueprint.InternalDomain}); err != nil {
			slog.Warn("blueprint /etc/hosts registration notice", "app", blueprint.AppName, "warning", err)
		} else {
			result.HostsSynced = true
		}
	}

	if netSynced, err := SyncNetworkDNSProviders(); err == nil && netSynced {
		result.NetworkDNSSynced = true
	}

	ClearAppRuntimeMetaCache()

	return result, nil
}

// RunPackageAction executes the specified bash script for installing, updating, or removing a package.
// It streams output line-by-line so we can track progress in real time.
func RunPackageAction(action, pkgId, scriptName, lockFile string) {
	status := "installing"
	switch action {
	case "remove":
		status = "uninstalling"
	case "update":
		status = "updating"
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
			activeJobs.CompareAndDelete(pkgId, job)
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
	} else if action == "update" {
		if ShouldPreStopOnUpdate(pkgId) {
			allocatedPort = PreAllocateAppPort(pkgId)
		} else {
			resolvedPort, err := resolveExistingUpdatePort(pkgId)
			if err != nil {
				slog.Error("failed to resolve existing port for package update", "action", action, "package", pkgId, "error", err)
				job.Status = "failed"
				job.LastLine = "Error: " + err.Error()
				job.Progress = 100
				notifyPackageEvent(pkgId, action, job.Status, job.Progress, job.LastLine)
				return
			}
			allocatedPort = resolvedPort
		}
	}

	if action == "update" && ShouldPreStopOnUpdate(pkgId) {
		updateProgress("[PROGRESS:5] Stopping running service units before binary update...")
		for _, unit := range ResolveServiceUnits(pkgId) {
			_ = ControlService(unit, "stop")
		}
	}

	if IsRunnerAvailable() {
		if err := DispatchPackageStream(action, pkgId, scriptName, allocatedPort, updateProgress); err != nil {
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

		cmd := buildHardenedPackageCommand(scriptPath, true, allocatedPort)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			slog.Error("failed to create stdout pipe; running synchronous fallback", "action", action, "script", scriptName, "error", err)
			output, runErr := buildHardenedPackageCommand(scriptPath, true, allocatedPort).CombinedOutput()
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
	case "install", "update":
		if ShouldApplyCallerSandbox(pkgId) {
			if err := ApplyPackageSandbox(pkgId); err != nil {
				slog.Warn("sandbox hardening warning", "package", pkgId, "error", err)
			}
		}
		var (
			bpRes *BlueprintSetupResult
			err   error
		)
		if ShouldRestartAfterUpdate(pkgId) {
			bpRes, err = ApplyBlueprintPostInstall(pkgId, allocatedPort)
		} else {
			bpRes, err = applyPostInstallWithoutCallerRestart(pkgId, allocatedPort)
		}
		if err != nil {
			slog.Warn("blueprint post-install setup warning", "package", pkgId, "error", err)
		} else if bpRes != nil {
			slog.Info("blueprint post-install applied",
				"package", pkgId,
				"allocated_port", bpRes.AllocatedPort,
				"port_reassigned", bpRes.PortReassigned,
				"internal_domain", bpRes.InternalDomain)
		}
		if action == "update" && ShouldRestartAfterUpdate(pkgId) {
			for _, unit := range ResolveServiceUnits(pkgId) {
				_ = ControlService(unit, "restart")
			}
		}
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
	if action == "install" || action == "update" {
		job.Status = "installed"
		RefreshPackageUpdateByID(pkgId)
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
