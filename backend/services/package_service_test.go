package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

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

	pkgs := GetPackages()
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

func TestGetPackagesReturnsNilWhenConfigMissing(t *testing.T) {
	if err := os.Setenv("AETHERFLOW_PACKAGES_CONFIG", filepath.Join(t.TempDir(), "missing-packages.json")); err != nil {
		t.Fatalf("failed to set env override: %v", err)
	}
	defer func() { _ = os.Unsetenv("AETHERFLOW_PACKAGES_CONFIG") }()

	if pkgs := GetPackages(); pkgs != nil {
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
