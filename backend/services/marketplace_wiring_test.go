package services

import (
	"aetherflow/db"
	"aetherflow/models"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogBlueprintsAndAutomationCoverage(t *testing.T) {
	t.Setenv("AETHERFLOW_PACKAGES_CONFIG", filepath.Join("..", "config", "packages.json"))
	t.Setenv("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", filepath.Join("..", "config", "package_automation.json"))

	pkgs, err := loadPackagesCatalog()
	if err != nil {
		t.Fatalf("loadPackagesCatalog() failed: %v", err)
	}
	if len(pkgs) != 71 {
		t.Fatalf("expected 71 catalog packages, got %d", len(pkgs))
	}

	automation := loadPackageAutomation()
	if len(automation) == 0 {
		t.Fatal("loadPackageAutomation() returned empty map")
	}

	imgDir := filepath.Join("..", "..", "frontend", "public", "img")
	imgEntries, err := os.ReadDir(imgDir)
	if err != nil {
		t.Fatalf("os.ReadDir(%q) failed: %v", imgDir, err)
	}
	exactImgNames := make(map[string]bool, len(imgEntries))
	for _, entry := range imgEntries {
		if !entry.IsDir() {
			exactImgNames[entry.Name()] = true
		}
	}

	for _, pkg := range pkgs {
		if _, ok := automation[pkg.Name]; !ok {
			t.Errorf("package %q is missing from package_automation.json", pkg.Name)
		}

		expectedIcon := strings.ToLower(pkg.Name) + ".png"
		if !exactImgNames[expectedIcon] {
			t.Errorf("marketplace icon %q missing (or case-mismatched) in frontend/public/img", expectedIcon)
		} else {
			iconData, readErr := os.ReadFile(filepath.Join(imgDir, expectedIcon))
			if readErr != nil || len(iconData) < 64 || string(iconData[:8]) != "\x89PNG\r\n\x1a\n" {
				t.Errorf("marketplace icon %q is invalid or corrupted PNG (len=%d, err=%v)", expectedIcon, len(iconData), readErr)
			}
		}

		bp := GetBlueprint(pkg.Name)
		if bp == nil {
			t.Errorf("GetBlueprint(%q) returned nil", pkg.Name)
			continue
		}
		if bp.DefaultPort != pkg.DefaultPort {
			t.Errorf("GetBlueprint(%q).DefaultPort = %d, want %d", pkg.Name, bp.DefaultPort, pkg.DefaultPort)
		}

		// Verify service-name alias lookup works too
		if pkg.ServiceName != "" && pkg.ServiceName != "apache2" {
			svcBp := GetBlueprint(pkg.ServiceName)
			if svcBp == nil {
				t.Errorf("GetBlueprint(%q) (service alias for %q) returned nil", pkg.ServiceName, pkg.Name)
			}
		}

		// Verify both install and remove scripts exist
		installPath := ResolvePackageScriptPath("install", "installpackage-"+pkg.Name)
		if installPath == "" {
			t.Errorf("install script missing for %q", pkg.Name)
		}
		removePath := ResolvePackageScriptPath("remove", "removepackage-"+pkg.Name)
		if removePath == "" {
			t.Errorf("remove script missing for %q", pkg.Name)
		}
	}

	// Verify specific port assignments per Q2
	expectedPorts := map[string]int{
		"grafana":        3000,
		"gitea":          3002,
		"uptimekuma":     3004,
		"autoscan":       3030,
		"adguardhome":    3080,
		"navidrome":      4533,
		"kavita":         5002,
		"jellyseerr":     5055,
		"overseerr":      5056,
		"rclone":         5572,
		"n8n":            5678,
		"znc":            6501,
		"qui":            7476,
		"paperless-ngx":  8010,
		"calibreweb":     8083,
		"sabnzbd":        8085,
		"organizr":       8086,
		"rutorrent":      8087,
		"nextcloud":      8088,
		"pihole":         8089,
		"filebrowser":    8095,
		"jellyfin":       8096,
		"emby":           8097,
		"scrutiny":       8098,
		"qbittorrent":    8180,
		"vaultwarden":    8343,
		"librespeed":     8988,
		"thelounge":      9000,
		"audiobookshelf": 13378,
		"plex":           32400,
		"threadfin":      34400,
		"dispatcharr":    9191,
		"duplicati":      8200,
		"filebot":        5452,
		"listenarr":      4546,
		"notifiarr":      5454,
		"novnc":          6080,
		"kasmvnc":        6081,
		"pyload":         8000,
		"requestrr":      4545,
		"seedcross":      8019,
		"unmanic":        8888,
	}
	for app, wantPort := range expectedPorts {
		bp := GetBlueprint(app)
		if bp == nil {
			t.Fatalf("GetBlueprint(%q) returned nil", app)
		}
		if bp.DefaultPort != wantPort {
			t.Errorf("GetBlueprint(%q).DefaultPort = %d, want %d", app, bp.DefaultPort, wantPort)
		}
	}

	// Verify every web app has a unique non-conflicting DefaultPort and never collides with AetherFlow (8080) or Apache2 (80/443)
	seenPorts := make(map[int]string)
	for _, pkg := range pkgs {
		if pkg.DefaultPort == 0 {
			continue
		}
		if pkg.DefaultPort == 8080 || pkg.DefaultPort == 80 || pkg.DefaultPort == 443 {
			t.Errorf("package %q uses reserved system port %d", pkg.Name, pkg.DefaultPort)
		}
		if prevApp, exists := seenPorts[pkg.DefaultPort]; exists {
			t.Errorf("port collision on %d between %q and %q", pkg.DefaultPort, prevApp, pkg.Name)
		}
		seenPorts[pkg.DefaultPort] = pkg.Name
	}

	// Verify all 57 packages have valid, trackable update configurations
	mergedPkgs, err := GetPackages()
	if err != nil {
		t.Fatalf("GetPackages() failed: %v", err)
	}
	for _, pkg := range mergedPkgs {
		if !shouldTrackPackage(pkg) {
			t.Errorf("shouldTrackPackage(%q) returned false (UpdateSource=%q, UpdateRepo=%q, UpdateRepoURL=%q, UpdatePackage=%q)",
				pkg.Name, pkg.UpdateSource, pkg.UpdateRepo, pkg.UpdateRepoURL, pkg.UpdatePackage)
		}
		switch pkg.UpdateSource {
		case "apt", "github", "git_tags", "git":
		default:
			t.Errorf("package %q has unsupported UpdateSource %q", pkg.Name, pkg.UpdateSource)
		}
	}

	// Verify no legacy unreferenced scripts remain in packages/package/install or remove
	installEntries, err := os.ReadDir(filepath.Join("..", "..", "packages", "package", "install"))
	if err == nil {
		count := 0
		for _, e := range installEntries {
			if strings.HasPrefix(e.Name(), "installpackage-") && e.Name() != "installpackage-template" {
				count++
			}
		}
		if count != 71 {
			t.Errorf("expected 71 installpackage-* scripts, found %d", count)
		}
	}
	removeEntries, err := os.ReadDir(filepath.Join("..", "..", "packages", "package", "remove"))
	if err == nil {
		count := 0
		for _, e := range removeEntries {
			if strings.HasPrefix(e.Name(), "removepackage-") {
				count++
			}
		}
		if count != 71 {
			t.Errorf("expected 71 removepackage-* scripts, found %d", count)
		}
	}
}

func TestParseProgressLine(t *testing.T) {
	pct, msg, ok := parseProgressLine("[PROGRESS:45] Extracting archive...")
	if !ok || pct != 45 || msg != "Extracting archive..." {
		t.Fatalf("parseProgressLine got (%d, %q, %v), want (45, 'Extracting archive...', true)", pct, msg, ok)
	}

	pct, msg, ok = parseProgressLine("[2026-10-24 05:00:00] [INFO] [PROGRESS:100] Complete")
	if !ok || pct != 100 || msg != "Complete" {
		t.Fatalf("parseProgressLine got (%d, %q, %v), want (100, 'Complete', true)", pct, msg, ok)
	}

	if _, _, ok := parseProgressLine("regular log output"); ok {
		t.Fatal("expected regular log line not to match progress marker")
	}
}

func TestSubdomainGatewayHostResolution(t *testing.T) {
	setupBlueprintTestDB(t)

	// 1. Enable external access -> both internal and public domains should resolve to configured port
	err := db.SetAppIngressConfig(models.AppIngressConfig{
		AppName:               "sonarr",
		ListenPort:            8989,
		PublicDomain:          "sonarr.example.com",
		ExternalAccessEnabled: true,
		TLSEnabled:            true,
	})
	if err != nil {
		t.Fatalf("SetAppIngressConfig failed: %v", err)
	}

	if port, app, matched := ResolveAppTargetForHost("sonarr.aether.local"); !matched || app != "sonarr" || port != 8989 {
		t.Errorf("ResolveAppTargetForHost(sonarr.aether.local) = (%d, %q, %v), want (8989, sonarr, true)", port, app, matched)
	}
	if port, app, matched := ResolveAppTargetForHost("sonarr.example.com"); !matched || app != "sonarr" || port != 8989 {
		t.Errorf("ResolveAppTargetForHost(sonarr.example.com) = (%d, %q, %v), want (8989, sonarr, true)", port, app, matched)
	}

	// 2. Disable external access -> public domain must stop resolving while internal domain remains active
	err = db.SetAppIngressConfig(models.AppIngressConfig{
		AppName:               "sonarr",
		ListenPort:            8989,
		PublicDomain:          "sonarr.example.com",
		ExternalAccessEnabled: false,
		TLSEnabled:            true,
	})
	if err != nil {
		t.Fatalf("SetAppIngressConfig (disable public) failed: %v", err)
	}

	if _, _, matched := ResolveAppTargetForHost("sonarr.example.com"); matched {
		t.Errorf("expected ResolveAppTargetForHost(sonarr.example.com) to be false when ExternalAccessEnabled=false")
	}
	if port, app, matched := ResolveAppTargetForHost("sonarr.aether.local"); !matched || app != "sonarr" || port != 8989 {
		t.Errorf("expected sonarr.aether.local to remain active on port 8989, got (%d, %q, %v)", port, app, matched)
	}
}

func TestResolveServiceUnitsAndUnitFilter(t *testing.T) {
	t.Setenv("AETHERFLOW_PACKAGES_CONFIG", filepath.Join("..", "config", "packages.json"))
	t.Setenv("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", filepath.Join("..", "config", "package_automation.json"))

	containsUnit := func(units []string, want string) bool {
		for _, u := range units {
			if strings.EqualFold(strings.TrimSuffix(u, ".service"), strings.TrimSuffix(want, ".service")) {
				return true
			}
		}
		return false
	}

	// 1. deluge multi-unit
	delugeUnits := ResolveServiceUnits("deluged")
	if len(delugeUnits) != 2 || delugeUnits[0] != "deluged" || delugeUnits[1] != "deluge-web" {
		t.Errorf("ResolveServiceUnits(deluged) = %v, want [deluged deluge-web]", delugeUnits)
	}
	delugePkgUnits := ResolveServiceUnits("deluge")
	if len(delugePkgUnits) != 2 || delugePkgUnits[0] != "deluged" || delugePkgUnits[1] != "deluge-web" {
		t.Errorf("ResolveServiceUnits(deluge) = %v, want [deluged deluge-web]", delugePkgUnits)
	}

	// 2. prometheus multi-unit
	promUnits := ResolveServiceUnits("prometheus")
	if len(promUnits) != 2 || promUnits[0] != "prometheus" || promUnits[1] != "node_exporter" {
		t.Errorf("ResolveServiceUnits(prometheus) = %v, want [prometheus node_exporter]", promUnits)
	}

	// 3. paperless-ngx multi-unit (webserver, worker, scheduler)
	paperlessUnits := ResolveServiceUnits("paperless-ngx")
	if len(paperlessUnits) != 3 || !containsUnit(paperlessUnits, "paperless-webserver") || !containsUnit(paperlessUnits, "paperless-worker") || !containsUnit(paperlessUnits, "paperless-scheduler") {
		t.Errorf("ResolveServiceUnits(paperless-ngx) = %v, want [paperless-webserver paperless-worker paperless-scheduler]", paperlessUnits)
	}
	paperlessSvcUnits := ResolveServiceUnits("paperless-webserver")
	if len(paperlessSvcUnits) != 3 || !containsUnit(paperlessSvcUnits, "paperless-worker") {
		t.Errorf("ResolveServiceUnits(paperless-webserver) = %v, want 3 companion units", paperlessSvcUnits)
	}
	paperlessAliasUnits := ResolveServiceUnits("paperless")
	if len(paperlessAliasUnits) != 3 || !containsUnit(paperlessAliasUnits, "paperless-scheduler") {
		t.Errorf("ResolveServiceUnits(paperless) = %v, want 3 companion units", paperlessAliasUnits)
	}

	// 4. scrutiny multi-unit (dashboard service + collector companion)
	scrutinyUnits := ResolveServiceUnits("scrutiny")
	if len(scrutinyUnits) < 2 || !containsUnit(scrutinyUnits, "scrutiny") || !containsUnit(scrutinyUnits, "scrutiny-collector") {
		t.Errorf("ResolveServiceUnits(scrutiny) = %v, want units including scrutiny and scrutiny-collector", scrutinyUnits)
	}
	scrutinyCollectorUnits := ResolveServiceUnits("scrutiny-collector")
	if len(scrutinyCollectorUnits) < 2 || !containsUnit(scrutinyCollectorUnits, "scrutiny") {
		t.Errorf("ResolveServiceUnits(scrutiny-collector) = %v, want units including scrutiny", scrutinyCollectorUnits)
	}

	// 5. recyclarr multi-unit (service + timer)
	recyclarrUnits := ResolveServiceUnits("recyclarr")
	if len(recyclarrUnits) != 2 || !containsUnit(recyclarrUnits, "recyclarr") || !containsUnit(recyclarrUnits, "recyclarr.timer") {
		t.Errorf("ResolveServiceUnits(recyclarr) = %v, want [recyclarr recyclarr.timer]", recyclarrUnits)
	}
	recyclarrTimerUnits := ResolveServiceUnits("recyclarr.timer")
	if len(recyclarrTimerUnits) != 2 || !containsUnit(recyclarrTimerUnits, "recyclarr") {
		t.Errorf("ResolveServiceUnits(recyclarr.timer) = %v, want units including recyclarr", recyclarrTimerUnits)
	}

	// 6. rclone multi-unit (rclone rcd daemon + rclone-vfs companion)
	rcloneUnits := ResolveServiceUnits("rclone")
	if len(rcloneUnits) != 2 || !containsUnit(rcloneUnits, "rclone") || !containsUnit(rcloneUnits, "rclone-vfs") {
		t.Errorf("ResolveServiceUnits(rclone) = %v, want [rclone rclone-vfs]", rcloneUnits)
	}
	rcloneVfsUnits := ResolveServiceUnits("rclone-vfs")
	if len(rcloneVfsUnits) != 2 || !containsUnit(rcloneVfsUnits, "rclone") {
		t.Errorf("ResolveServiceUnits(rclone-vfs) = %v, want units including rclone", rcloneVfsUnits)
	}

	// Single-unit matching
	if !MatchesUnitFilter("sonarr.service", "sonarr") {
		t.Error("expected MatchesUnitFilter('sonarr.service', 'sonarr') to be true")
	}
	if !MatchesUnitFilter("sonarr", "sonarr.service") {
		t.Error("expected MatchesUnitFilter('sonarr', 'sonarr.service') to be true")
	}

	// Multi-unit matching across companion services
	if !MatchesUnitFilter("deluge-web.service", "deluged") {
		t.Error("expected MatchesUnitFilter('deluge-web.service', 'deluged') to be true for companion unit")
	}
	if !MatchesUnitFilter("deluge-web.service", "deluge") {
		t.Error("expected MatchesUnitFilter('deluge-web.service', 'deluge') to be true for companion unit")
	}
	if !MatchesUnitFilter("node_exporter.service", "prometheus") {
		t.Error("expected MatchesUnitFilter('node_exporter.service', 'prometheus') to be true for companion unit")
	}
	if !MatchesUnitFilter("paperless-worker.service", "paperless-ngx") {
		t.Error("expected MatchesUnitFilter('paperless-worker.service', 'paperless-ngx') to be true for companion unit")
	}
	if !MatchesUnitFilter("paperless-scheduler.service", "paperless-webserver") {
		t.Error("expected MatchesUnitFilter('paperless-scheduler.service', 'paperless-webserver') to be true for companion unit")
	}
	if !MatchesUnitFilter("scrutiny-collector.service", "scrutiny") {
		t.Error("expected MatchesUnitFilter('scrutiny-collector.service', 'scrutiny') to be true for companion unit")
	}
	if !MatchesUnitFilter("recyclarr.timer", "recyclarr") {
		t.Error("expected MatchesUnitFilter('recyclarr.timer', 'recyclarr') to be true for companion unit")
	}
	if !MatchesUnitFilter("rclone-vfs.service", "rclone") {
		t.Error("expected MatchesUnitFilter('rclone-vfs.service', 'rclone') to be true for companion unit")
	}

	// Negative matching
	if MatchesUnitFilter("radarr.service", "sonarr") {
		t.Error("expected MatchesUnitFilter('radarr.service', 'sonarr') to be false")
	}
	if MatchesUnitFilter("paperless-worker.service", "scrutiny") {
		t.Error("expected MatchesUnitFilter('paperless-worker.service', 'scrutiny') to be false")
	}
}
