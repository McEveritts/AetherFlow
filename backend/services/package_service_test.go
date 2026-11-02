package services

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aetherflow/db"
	"aetherflow/models"
)

func clearActiveJobs() {
	activeJobs.Range(func(key, value any) bool {
		activeJobs.Delete(key)
		return true
	})
}

func TestGetPackagesFromLocalConfigAndStatuses(t *testing.T) {
	clearActiveJobs()
	defer clearActiveJobs()

	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, "dashboard", "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	installedLock := filepath.Join(tempDir, "installed.lock")
	if err := os.WriteFile(installedLock, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create lock file: %v", err)
	}

	fixture := []models.Package{
		{Name: "pkg-installed", Label: "Installed", LockFile: installedLock},
		{Name: "pkg-uninstalled", Label: "Uninstalled", LockFile: filepath.Join(tempDir, "missing.lock")},
		{Name: "pkg-active", Label: "Active", LockFile: filepath.Join(tempDir, "missing2.lock")},
	}
	raw, _ := json.Marshal(fixture)
	configPath := filepath.Join(configDir, "packages.json")
	if err := os.WriteFile(configPath, raw, 0644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	if err := os.Setenv("AETHERFLOW_PACKAGES_CONFIG", configPath); err != nil {
		t.Fatalf("failed to set env override: %v", err)
	}
	defer func() { _ = os.Unsetenv("AETHERFLOW_PACKAGES_CONFIG") }()

	activeJobs.Store("pkg-active", &JobInfo{Status: "installing"})

	pkgs, err := GetPackages()
	if err != nil {
		t.Fatalf("GetPackages() error = %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	statuses := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		statuses[p.Name] = p.Status
	}

	if statuses["pkg-installed"] != "installed" {
		t.Fatalf("pkg-installed status=%q want installed", statuses["pkg-installed"])
	}
	if statuses["pkg-uninstalled"] != "uninstalled" {
		t.Fatalf("pkg-uninstalled status=%q want uninstalled", statuses["pkg-uninstalled"])
	}
	if statuses["pkg-active"] != "installing" {
		t.Fatalf("pkg-active status=%q want installing", statuses["pkg-active"])
	}
}

func TestGetPackagesReturnsErrorWhenConfigMissing(t *testing.T) {
	if err := os.Setenv("AETHERFLOW_PACKAGES_CONFIG", filepath.Join(t.TempDir(), "missing-packages.json")); err != nil {
		t.Fatalf("failed to set env override: %v", err)
	}
	defer func() { _ = os.Unsetenv("AETHERFLOW_PACKAGES_CONFIG") }()

	pkgs, err := GetPackages()
	if err == nil {
		t.Fatal("expected GetPackages to return an error when config is missing")
	}
	if pkgs != nil {
		t.Fatalf("expected nil packages when config is missing, got %v", pkgs)
	}
}

func TestPackageJobInfoHelpers(t *testing.T) {
	clearActiveJobs()
	defer clearActiveJobs()

	job := &JobInfo{Status: "installing", Progress: 42, LastLine: "Running"}
	activeJobs.Store("pkg-test", job)

	if got := GetPackageJobStatus("pkg-test"); got != "installing" {
		t.Fatalf("GetPackageJobStatus=%q want installing", got)
	}

	info := GetPackageJobInfo("pkg-test")
	if info == nil {
		t.Fatal("GetPackageJobInfo returned nil")
	}
	if info.Progress != 42 || info.LastLine != "Running" {
		t.Fatalf("unexpected job info: %+v", info)
	}

	if GetPackageJobInfo("missing") != nil {
		t.Fatal("expected nil job info for missing package")
	}
	if GetPackageJobStatus("missing") != "" {
		t.Fatal("expected empty status for missing package")
	}
}

func waitForJobCompletion(t *testing.T, pkgID string) *JobInfo {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		info := GetPackageJobInfo(pkgID)
		if info == nil || (info.Status != "updating" && info.Status != "installing" && info.Status != "uninstalling") {
			activeJobs.Delete(pkgID)
			return info
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for job %s to complete", pkgID)
	return nil
}

func TestRunPackageActionUpdateCallerPolicy(t *testing.T) {
	clearActiveJobs()
	defer clearActiveJobs()
	setupBlueprintTestDB(t)

	if err := db.SetAppIngressConfig(models.AppIngressConfig{
		AppName:    "maintainerr",
		ListenPort: 6246,
	}); err != nil {
		t.Fatalf("seed maintainerr ingress config: %v", err)
	}

	sockDir, err := os.MkdirTemp("/tmp", "af-sock-*")
	if err != nil {
		t.Fatalf("mkdirtemp sock: %v", err)
	}
	defer func() { _ = os.RemoveAll(sockDir) }()
	sockPath := filepath.Join(sockDir, "r.sock")
	if err := os.Setenv("AETHERFLOW_RUNNER_SOCK", sockPath); err != nil {
		t.Fatalf("setenv AETHERFLOW_RUNNER_SOCK: %v", err)
	}
	defer func() { _ = os.Unsetenv("AETHERFLOW_RUNNER_SOCK") }()

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer listener.Close()

	var (
		mode               string
		maintainerrState   = "active"
		stateAtRunnerStart string
		systemctlCalls     []string
		sandboxCalls       []string
		packageRequests    []PackageRunnerRequest
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/systemctl", func(writer http.ResponseWriter, request *http.Request) {
		var req SystemctlRequest
		_ = json.NewDecoder(request.Body).Decode(&req)
		systemctlCalls = append(systemctlCalls, req.Action+" "+req.Service)
		if strings.Contains(req.Service, "maintainerr") {
			switch req.Action {
			case "stop":
				maintainerrState = "inactive"
			case "start", "restart":
				maintainerrState = "active"
			}
		}
		_ = json.NewEncoder(writer).Encode(RunnerResponse{Success: true})
	})
	mux.HandleFunc("/v1/package", func(writer http.ResponseWriter, request *http.Request) {
		var pkgReq PackageRunnerRequest
		_ = json.NewDecoder(request.Body).Decode(&pkgReq)
		packageRequests = append(packageRequests, pkgReq)
		stateAtRunnerStart = maintainerrState
		writer.WriteHeader(http.StatusOK)
		switch mode {
		case "staging-fail":
			_, _ = writer.Write([]byte("[AF_PROGRESS] 25 Fetching Maintainerr...\n__RUNNER_EXIT_ERROR__:staging build failed\n"))
		case "cutover-rollback":
			wasActive := stateAtRunnerStart == "active"
			maintainerrState = "inactive"
			if wasActive {
				maintainerrState = "active"
			}
			_, _ = writer.Write([]byte("[AF_PROGRESS] 75 Activating Maintainerr...\n__RUNNER_EXIT_ERROR__:readiness failed, rolled back\n"))
		default:
			maintainerrState = "active"
			_, _ = writer.Write([]byte("[AF_PROGRESS] 100 Done\n"))
		}
	})
	mux.HandleFunc("/v1/sandbox", func(writer http.ResponseWriter, request *http.Request) {
		var req SandboxRunnerRequest
		_ = json.NewDecoder(request.Body).Decode(&req)
		targetPkg := req.PackageID
		if targetPkg == "" {
			targetPkg = req.Package
		}
		sandboxCalls = append(sandboxCalls, targetPkg)
		if strings.Contains(targetPkg, "maintainerr") && maintainerrState == "active" {
			systemctlCalls = append(systemctlCalls, "sandbox-restart af-maintainerr")
			maintainerrState = "failed-post-sandbox-restart"
		}
		_ = json.NewEncoder(writer).Encode(RunnerResponse{Success: true})
	})
	mux.HandleFunc("/v1/hosts", func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(RunnerResponse{Success: true})
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()
	defer srv.Close()

	mode = "staging-fail"
	systemctlCalls = nil
	sandboxCalls = nil
	packageRequests = nil
	maintainerrState = "active"
	RunPackageAction("update", "maintainerr", "installpackage-maintainerr", "")
	waitForJobCompletion(t, "maintainerr")
	if stateAtRunnerStart != "active" {
		t.Fatalf("expected af-maintainerr to remain active when installer starts, got %q", stateAtRunnerStart)
	}
	if maintainerrState != "active" {
		t.Fatalf("expected af-maintainerr to remain active after staging failure, got %q", maintainerrState)
	}
	for _, call := range systemctlCalls {
		if strings.HasPrefix(call, "stop ") {
			t.Fatalf("caller unexpectedly stopped service on maintainerr update: %v", systemctlCalls)
		}
	}

	mode = "cutover-rollback"
	systemctlCalls = nil
	sandboxCalls = nil
	packageRequests = nil
	maintainerrState = "active"
	RunPackageAction("update", "maintainerr", "installpackage-maintainerr", "")
	waitForJobCompletion(t, "maintainerr")
	if stateAtRunnerStart != "active" {
		t.Fatalf("expected af-maintainerr to be active at installer start, got %q", stateAtRunnerStart)
	}
	if maintainerrState != "active" {
		t.Fatalf("expected rollback to restore af-maintainerr to active, got %q", maintainerrState)
	}

	mode = "ok"
	systemctlCalls = nil
	sandboxCalls = nil
	packageRequests = nil
	maintainerrState = "active"
	RunPackageAction("update", "maintainerr", "installpackage-maintainerr", "")
	waitForJobCompletion(t, "maintainerr")
	if maintainerrState != "active" {
		t.Fatalf("expected af-maintainerr to stay active without post-readiness sandbox restart, got %q", maintainerrState)
	}
	if len(sandboxCalls) != 0 {
		t.Fatalf("expected maintainerr update to skip caller post-readiness sandbox, got %v", sandboxCalls)
	}
	for _, call := range systemctlCalls {
		if strings.HasPrefix(call, "stop ") || strings.HasPrefix(call, "restart ") || strings.HasPrefix(call, "sandbox-restart ") {
			t.Fatalf("caller unexpectedly stopped/restarted maintainerr outside installer script: %v", systemctlCalls)
		}
	}

	mode = "ok"
	systemctlCalls = nil
	sandboxCalls = nil
	packageRequests = nil
	maintainerrState = "inactive"
	RunPackageAction("install", "maintainerr", "installpackage-maintainerr", "")
	waitForJobCompletion(t, "maintainerr")
	if maintainerrState != "active" {
		t.Fatalf("expected af-maintainerr install to stay active without post-readiness sandbox restart, got %q", maintainerrState)
	}
	if len(sandboxCalls) != 0 {
		t.Fatalf("expected maintainerr install to skip caller post-readiness sandbox, got %v", sandboxCalls)
	}

	mode = "ok"
	systemctlCalls = nil
	sandboxCalls = nil
	packageRequests = nil
	RunPackageAction("update", "radarr", "installpackage-radarr", "")
	waitForJobCompletion(t, "radarr")
	joined := strings.Join(systemctlCalls, ", ")
	if !strings.Contains(joined, "stop radarr") {
		t.Fatalf("expected radarr update to pre-stop radarr, got calls: %v", systemctlCalls)
	}
	if !strings.Contains(joined, "restart radarr") {
		t.Fatalf("expected radarr update to restart radarr after update, got calls: %v", systemctlCalls)
	}
	if !strings.Contains(strings.Join(sandboxCalls, ", "), "radarr") {
		t.Fatalf("expected radarr update to apply caller sandbox, got sandbox calls: %v", sandboxCalls)
	}
}

func TestRunPackageActionUpdateMaintainerrPortPreservationAndFailClosed(t *testing.T) {
	clearActiveJobs()
	defer clearActiveJobs()
	setupBlueprintTestDB(t)

	sockDir, err := os.MkdirTemp("/tmp", "af-sock-port-*")
	if err != nil {
		t.Fatalf("mkdirtemp sock: %v", err)
	}
	defer func() { _ = os.RemoveAll(sockDir) }()
	sockPath := filepath.Join(sockDir, "r.sock")
	if err := os.Setenv("AETHERFLOW_RUNNER_SOCK", sockPath); err != nil {
		t.Fatalf("setenv AETHERFLOW_RUNNER_SOCK: %v", err)
	}
	defer func() { _ = os.Unsetenv("AETHERFLOW_RUNNER_SOCK") }()

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer listener.Close()

	var (
		systemctlCalls  []string
		sandboxCalls    []string
		packageRequests []PackageRunnerRequest
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/systemctl", func(writer http.ResponseWriter, request *http.Request) {
		var req SystemctlRequest
		_ = json.NewDecoder(request.Body).Decode(&req)
		systemctlCalls = append(systemctlCalls, req.Action+" "+req.Service)
		_ = json.NewEncoder(writer).Encode(RunnerResponse{Success: true})
	})
	mux.HandleFunc("/v1/package", func(writer http.ResponseWriter, request *http.Request) {
		var pkgReq PackageRunnerRequest
		_ = json.NewDecoder(request.Body).Decode(&pkgReq)
		packageRequests = append(packageRequests, pkgReq)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("[AF_PROGRESS] 100 Done\n"))
	})
	mux.HandleFunc("/v1/sandbox", func(writer http.ResponseWriter, request *http.Request) {
		var req SandboxRunnerRequest
		_ = json.NewDecoder(request.Body).Decode(&req)
		targetPkg := req.PackageID
		if targetPkg == "" {
			targetPkg = req.Package
		}
		sandboxCalls = append(sandboxCalls, targetPkg)
		_ = json.NewEncoder(writer).Encode(RunnerResponse{Success: true})
	})
	mux.HandleFunc("/v1/hosts", func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(RunnerResponse{Success: true})
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()
	defer srv.Close()

	if err := db.SetAppIngressConfig(models.AppIngressConfig{
		AppName:    "maintainerr",
		ListenPort: 17420,
	}); err != nil {
		t.Fatalf("seed non-default maintainerr port: %v", err)
	}

	for _, aliasID := range []string{"maintainerr", "af-maintainerr", "af-maintainerr.service"} {
		systemctlCalls = nil
		sandboxCalls = nil
		packageRequests = nil
		RunPackageAction("update", aliasID, "installpackage-maintainerr", "")
		jobInfo := waitForJobCompletion(t, aliasID)
		if jobInfo == nil || jobInfo.Status != "installed" {
			t.Fatalf("expected %s update to succeed with non-default port, got %+v", aliasID, jobInfo)
		}
		if len(packageRequests) != 1 {
			t.Fatalf("expected exactly 1 runner package call for %s, got %d", aliasID, len(packageRequests))
		}
		if packageRequests[0].AppPort != 17420 {
			t.Fatalf("expected %s update to preserve non-default port 17420, got %d", aliasID, packageRequests[0].AppPort)
		}
		if len(systemctlCalls) != 0 || len(sandboxCalls) != 0 {
			t.Fatalf("unexpected caller systemctl/sandbox activity for %s: systemctl=%v sandbox=%v", aliasID, systemctlCalls, sandboxCalls)
		}
	}

	if err := db.DeleteAppIngressConfig("maintainerr"); err != nil {
		t.Fatalf("delete maintainerr ingress config: %v", err)
	}
	systemctlCalls = nil
	sandboxCalls = nil
	packageRequests = nil
	RunPackageAction("update", "maintainerr", "installpackage-maintainerr", "")
	missingJob := waitForJobCompletion(t, "maintainerr")
	if missingJob == nil || missingJob.Status != "failed" {
		t.Fatalf("expected maintainerr update with missing ingress row to fail closed, got %+v", missingJob)
	}
	if len(packageRequests) != 0 || len(systemctlCalls) != 0 || len(sandboxCalls) != 0 {
		t.Fatalf("expected zero runner/control calls on missing ingress mapping, got package=%v systemctl=%v sandbox=%v", packageRequests, systemctlCalls, sandboxCalls)
	}

	for _, invalidPort := range []int{0, -1, 80, 1023, 65536, 70000} {
		if _, err := db.DB.Exec(
			`INSERT OR REPLACE INTO app_ingress_configs (app_name, public_domain, external_access_enabled, listen_port, tls_enabled) VALUES ('maintainerr', '', 0, ?, 0)`,
			invalidPort,
		); err != nil {
			t.Fatalf("insert invalid port %d: %v", invalidPort, err)
		}
		db.InvalidateIngressCache()
		systemctlCalls = nil
		sandboxCalls = nil
		packageRequests = nil
		RunPackageAction("update", "maintainerr", "installpackage-maintainerr", "")
		invalidJob := waitForJobCompletion(t, "maintainerr")
		if invalidJob == nil || invalidJob.Status != "failed" {
			t.Fatalf("expected maintainerr update with invalid port %d to fail closed, got %+v", invalidPort, invalidJob)
		}
		if len(packageRequests) != 0 || len(systemctlCalls) != 0 || len(sandboxCalls) != 0 {
			t.Fatalf("expected zero runner/control calls on invalid port %d, got package=%v systemctl=%v sandbox=%v", invalidPort, packageRequests, systemctlCalls, sandboxCalls)
		}
	}

	if err := db.SetAppIngressConfig(models.AppIngressConfig{
		AppName:    "maintainerr",
		ListenPort: 17420,
	}); err != nil {
		t.Fatalf("restore valid maintainerr port before DB error test: %v", err)
	}
	if err := db.DB.Close(); err != nil {
		t.Fatalf("close DB to simulate read error: %v", err)
	}
	systemctlCalls = nil
	sandboxCalls = nil
	packageRequests = nil
	RunPackageAction("update", "maintainerr", "installpackage-maintainerr", "")
	dbErrJob := waitForJobCompletion(t, "maintainerr")
	if dbErrJob == nil || dbErrJob.Status != "failed" {
		t.Fatalf("expected maintainerr update on DB read error to fail closed, got %+v", dbErrJob)
	}
	if len(packageRequests) != 0 || len(systemctlCalls) != 0 || len(sandboxCalls) != 0 {
		t.Fatalf("expected zero runner/control calls on DB read error, got package=%v systemctl=%v sandbox=%v", packageRequests, systemctlCalls, sandboxCalls)
	}
}
