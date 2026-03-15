package services

import (
	"aetherflow/db"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExtractVersionAndCompare(t *testing.T) {
	if got := extractVersion("gitea version 1.22.1 built with go1.25.0", ""); got != "1.22.1" {
		t.Fatalf("extractVersion() = %q, want 1.22.1", got)
	}

	if !IsRemoteVersionNewer("1.22.1", "1.23.0") {
		t.Fatal("expected 1.23.0 to be newer than 1.22.1")
	}
	if IsRemoteVersionNewer("1.23.0", "1.22.1") {
		t.Fatal("expected 1.22.1 to not be newer than 1.23.0")
	}
}

func TestAppUpdateWatcherRefreshesGitHubPackage(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "autobrr.lock")
	configPath := filepath.Join(tempDir, "packages.json")
	automationPath := filepath.Join(tempDir, "package_automation.json")
	dbPath := filepath.Join(tempDir, "aetherflow.sqlite")

	if err := os.WriteFile(lockPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create lock file: %v", err)
	}

	packagesJSON := `[
	  {
	    "name": "autobrr",
	    "label": "Autobrr",
	    "description": "Demo package",
	    "lock_file": "` + filepath.ToSlash(lockPath) + `",
	    "category": "Downloaders"
	  }
	]`
	automationJSON := `{
	  "autobrr": {
	    "update_source": "github",
	    "update_repo": "example/autobrr",
	    "version_command": ["bash", "-lc", "printf '1.0.0\n'"]
	  }
	}`

	if err := os.WriteFile(configPath, []byte(packagesJSON), 0644); err != nil {
		t.Fatalf("failed to write packages config: %v", err)
	}
	if err := os.WriteFile(automationPath, []byte(automationJSON), 0644); err != nil {
		t.Fatalf("failed to write automation config: %v", err)
	}

	if db.DB != nil {
		_ = db.DB.Close()
	}

	envs := map[string]string{
		"AETHERFLOW_PACKAGES_CONFIG":            configPath,
		"AETHERFLOW_PACKAGE_AUTOMATION_CONFIG":  automationPath,
		"AETHERFLOW_GITHUB_API_BASE_URL":        "",
		"DB_PATH":                               dbPath,
	}
	for key, value := range envs {
		if err := os.Setenv(key, value); err != nil {
			t.Fatalf("failed to set %s: %v", key, err)
		}
	}
	t.Cleanup(func() {
		for key := range envs {
			_ = os.Unsetenv(key)
		}
		if db.DB != nil {
			_ = db.DB.Close()
		}
	})

	db.InitDB()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/example/autobrr/releases/latest" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.1.0","html_url":"https://example.test/autobrr/releases/v1.1.0"}`))
	}))
	defer server.Close()

	changed := []string{}
	watcher := NewAppUpdateWatcher(server.Client(), time.Hour, func(pkgs []string) {
		changed = append(changed, pkgs...)
	})
	watcher.githubAPIBaseURL = server.URL
	watcher.RefreshInstalledPackages()

	updateMap := GetPackageUpdateMap()
	record, ok := updateMap["autobrr"]
	if !ok {
		t.Fatal("expected autobrr update record to be persisted")
	}
	if record.InstalledVersion != "1.0.0" {
		t.Fatalf("installed version = %q, want 1.0.0", record.InstalledVersion)
	}
	if record.LatestVersion != "1.1.0" {
		t.Fatalf("latest version = %q, want 1.1.0", record.LatestVersion)
	}
	if !record.UpdateAvailable {
		t.Fatal("expected update_available to be true")
	}
	if len(changed) != 1 || changed[0] != "autobrr" {
		t.Fatalf("changed packages = %v, want [autobrr]", changed)
	}

	pkgs := GetPackages()
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if !pkgs[0].UpdateAvailable {
		t.Fatal("expected GetPackages to merge update availability")
	}
	if pkgs[0].LatestVersion != "1.1.0" {
		t.Fatalf("GetPackages latest version = %q, want 1.1.0", pkgs[0].LatestVersion)
	}
}
