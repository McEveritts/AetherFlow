package services

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestCatalog55Packages(t *testing.T) {
	t.Setenv("AETHERFLOW_PACKAGES_CONFIG", filepath.Join("..", "config", "packages.json"))
	t.Setenv("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", filepath.Join("..", "config", "package_automation.json"))

	pkgs, err := loadPackagesCatalog()
	if err != nil {
		t.Fatalf("loadPackagesCatalog() error: %v", err)
	}

	if len(pkgs) != 75 {
		t.Fatalf("expected 75 packages in packages.json, got %d", len(pkgs))
	}

	for _, p := range pkgs {
		if p.Name == "portainer" {
			t.Errorf("found purged package 'portainer' in packages.json")
		}
	}
}

func TestBlueprintRegistryCoverage(t *testing.T) {
	t.Setenv("AETHERFLOW_PACKAGES_CONFIG", filepath.Join("..", "config", "packages.json"))
	t.Setenv("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", filepath.Join("..", "config", "package_automation.json"))

	pkgs, err := loadPackagesCatalog()
	if err != nil {
		t.Fatalf("loadPackagesCatalog() error: %v", err)
	}

	for _, p := range pkgs {
		bp := GetBlueprint(p.Name)
		if bp == nil {
			t.Errorf("GetBlueprint(%q) returned nil", p.Name)
			continue
		}
		if bp.DefaultPort != p.DefaultPort {
			t.Errorf("GetBlueprint(%q).DefaultPort = %d, want %d", p.Name, bp.DefaultPort, p.DefaultPort)
		}

		if p.ServiceName != "" && p.ServiceName != "apache2" {
			svcBp := GetBlueprint(p.ServiceName)
			if svcBp == nil {
				t.Errorf("GetBlueprint(%q) (service alias for %q) returned nil", p.ServiceName, p.Name)
			}
		}
	}

	// Ensure portainer blueprint is gone
	if bp := GetBlueprint("portainer"); bp != nil {
		t.Errorf("expected GetBlueprint('portainer') to be nil, got %+v", bp)
	}
}

func TestBlueprintDependencies(t *testing.T) {
	t.Setenv("AETHERFLOW_PACKAGES_CONFIG", filepath.Join("..", "config", "packages.json"))

	cloudplow := GetBlueprint("cloudplow")
	if cloudplow == nil {
		t.Fatal("GetBlueprint('cloudplow') returned nil")
	}
	if !slices.Contains(cloudplow.Dependencies, "rclone") || !slices.Contains(cloudplow.Dependencies, "mergerfs") {
		t.Errorf("cloudplow dependencies must include rclone and mergerfs, got: %v", cloudplow.Dependencies)
	}

	rutorrent := GetBlueprint("rutorrent")
	if rutorrent == nil {
		t.Fatal("GetBlueprint('rutorrent') returned nil")
	}
	if !slices.Contains(rutorrent.Dependencies, "rtorrent") {
		t.Errorf("rutorrent dependencies must include rtorrent, got: %v", rutorrent.Dependencies)
	}

	jellyseerr := GetBlueprint("jellyseerr")
	if jellyseerr == nil {
		t.Fatal("GetBlueprint('jellyseerr') returned nil")
	}
	if !slices.Contains(jellyseerr.Dependencies, "jellyfin") || !slices.Contains(jellyseerr.Dependencies, "sonarr") || !slices.Contains(jellyseerr.Dependencies, "radarr") {
		t.Errorf("jellyseerr dependencies must include jellyfin, sonarr, radarr, got: %v", jellyseerr.Dependencies)
	}
}

func TestAutomation55CoverageAndTracking(t *testing.T) {
	t.Setenv("AETHERFLOW_PACKAGES_CONFIG", filepath.Join("..", "config", "packages.json"))
	t.Setenv("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", filepath.Join("..", "config", "package_automation.json"))

	automation := loadPackageAutomation()
	if len(automation) != 75 {
		t.Fatalf("expected exactly 75 automation entries, got %d", len(automation))
	}

	if _, ok := automation["portainer"]; ok {
		t.Error("found purged package 'portainer' in package_automation.json")
	}

	pkgs, err := GetPackages()
	if err != nil {
		t.Fatalf("GetPackages() error: %v", err)
	}

	for _, p := range pkgs {
		if !shouldTrackPackage(p) {
			t.Errorf("shouldTrackPackage(%q) returned false (UpdateSource=%q, UpdatePackage=%q, UpdateRepo=%q, VersionCommand=%v)",
				p.Name, p.UpdateSource, p.UpdatePackage, p.UpdateRepo, p.VersionCommand)
		}

		// Media, Downloaders, Cloud must include -/mnt/unionfs
		if p.Category == "Media" || p.Category == "Downloaders" || p.Category == "Cloud" {
			if !slices.Contains(p.SandboxReadWrite, "-/mnt/unionfs") {
				t.Errorf("package %q (category %q) is missing -/mnt/unionfs in sandbox_rw_paths: %v",
					p.Name, p.Category, p.SandboxReadWrite)
			}
		}
	}
}

func TestMaintainerrBlueprintAndAutomation(t *testing.T) {
	t.Setenv("AETHERFLOW_PACKAGES_CONFIG", filepath.Join("..", "config", "packages.json"))
	t.Setenv("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", filepath.Join("..", "config", "package_automation.json"))

	for _, name := range []string{"maintainerr", "af-maintainerr"} {
		blueprint := GetBlueprint(name)
		if blueprint == nil {
			t.Fatalf("GetBlueprint(%q) returned nil", name)
		}
		if blueprint.AppName != "maintainerr" || blueprint.ServiceName != "af-maintainerr" {
			t.Errorf("unexpected Maintainerr identity: %+v", blueprint)
		}
		if blueprint.DefaultPort != 6246 || blueprint.PortEnvVar != "UI_PORT" {
			t.Errorf("unexpected Maintainerr port configuration: %+v", blueprint)
		}
		if blueprint.HealthCheckPath != "/api/health/ready" || blueprint.AppDataPath != "/var/lib/maintainerr" {
			t.Errorf("unexpected Maintainerr runtime paths: %+v", blueprint)
		}
		if len(blueprint.Dependencies) != 0 {
			t.Errorf("Maintainerr must allow an existing external media server, got dependencies: %v", blueprint.Dependencies)
		}
	}

	automation, ok := loadPackageAutomation()["maintainerr"]
	if !ok {
		t.Fatal("Maintainerr automation metadata is missing")
	}
	if automation.UpdateSource != "github" || automation.UpdateRepo != "Maintainerr/Maintainerr" {
		t.Errorf("unexpected Maintainerr update source: %+v", automation)
	}
	if !slices.Equal(automation.VersionCommand, []string{"cat", "/opt/maintainerr/.af-version"}) {
		t.Errorf("unexpected Maintainerr version command: %v", automation.VersionCommand)
	}
	if automation.SandboxProfile != "node" || !slices.Equal(automation.SandboxServiceIDs, []string{"af-maintainerr.service"}) {
		t.Errorf("unexpected Maintainerr sandbox metadata: %+v", automation)
	}
	if !slices.Contains(automation.SandboxReadWrite, "/var/lib/maintainerr") {
		t.Error("Maintainerr sandbox must permit persistent database writes")
	}

	for _, id := range []string{"maintainerr", "af-maintainerr", "af-maintainerr.service"} {
		if ShouldPreStopOnUpdate(id) {
			t.Errorf("ShouldPreStopOnUpdate(%q) = true, want false for transaction-managed Maintainerr update", id)
		}
		if ShouldRestartAfterUpdate(id) {
			t.Errorf("ShouldRestartAfterUpdate(%q) = true, want false for transaction-managed Maintainerr update", id)
		}
		if ShouldApplyCallerSandbox(id) {
			t.Errorf("ShouldApplyCallerSandbox(%q) = true, want false for transaction-managed Maintainerr sandbox", id)
		}
	}
	for _, id := range []string{"radarr", "sonarr", "jellyfin"} {
		if !ShouldPreStopOnUpdate(id) {
			t.Errorf("ShouldPreStopOnUpdate(%q) = false, want true", id)
		}
		if !ShouldRestartAfterUpdate(id) {
			t.Errorf("ShouldRestartAfterUpdate(%q) = false, want true", id)
		}
		if !ShouldApplyCallerSandbox(id) {
			t.Errorf("ShouldApplyCallerSandbox(%q) = false, want true", id)
		}
	}
}

func TestPortIntegrity55(t *testing.T) {
	t.Setenv("AETHERFLOW_PACKAGES_CONFIG", filepath.Join("..", "config", "packages.json"))

	pkgs, err := loadPackagesCatalog()
	if err != nil {
		t.Fatalf("loadPackagesCatalog() error: %v", err)
	}

	seenPorts := make(map[int]string)
	for _, p := range pkgs {
		if p.DefaultPort == 0 {
			continue
		}
		if p.DefaultPort == 80 || p.DefaultPort == 443 || p.DefaultPort == 8080 {
			t.Errorf("package %q uses reserved port %d", p.Name, p.DefaultPort)
		}
		if prev, exists := seenPorts[p.DefaultPort]; exists {
			t.Errorf("port collision on %d between %q and %q", p.DefaultPort, prev, p.Name)
		}
		seenPorts[p.DefaultPort] = p.Name
	}
}
