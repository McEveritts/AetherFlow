package services

import (
	"aetherflow/db"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupBlueprintTestDB(t *testing.T) {
	t.Helper()
	tmpDir := t.TempDir()
	t.Setenv("DB_PATH", filepath.Join(tmpDir, "test_blueprint.sqlite"))
	t.Setenv("AETHERFLOW_RUNNER_SOCK", filepath.Join(tmpDir, "nonexistent-runner.sock"))
	t.Setenv("AETHERFLOW_PACKAGES_CONFIG", filepath.Join("..", "config", "packages.json"))
	t.Setenv("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", filepath.Join("..", "config", "package_automation.json"))
	db.InitDB()
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
			db.DB = nil
		}
	})
}

func TestDynamicPortResolutionOnBusyHost(t *testing.T) {
	setupBlueprintTestDB(t)

	// Bind a real ephemeral TCP listener or simulate Radarr's default port (7878) being occupied on the server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind local listener: %v", err)
	}
	defer ln.Close()
	busyPort := ln.Addr().(*net.TCPAddr).Port
	if !IsTCPPortInUse(busyPort) {
		t.Fatalf("expected IsTCPPortInUse(%d) to be true for active listener", busyPort)
	}

	// Simulate 7878 (Radarr default) and 17878 (first fallback) being occupied by existing server software
	t.Setenv("AETHERFLOW_OCCUPIED_PORTS", "7878,17878")

	port, reassigned, err := ResolveDynamicAppPort("radarr", true)
	if err != nil {
		t.Fatalf("ResolveDynamicAppPort(radarr) failed: %v", err)
	}
	if !reassigned {
		t.Fatalf("expected Radarr port to be marked reassigned when 7878 is occupied")
	}
	if port != 17879 {
		t.Errorf("ResolveDynamicAppPort(radarr) = %d, want 17879 (skipping busy 7878 and 17878)", port)
	}
}

func TestPilotAppsBlueprintLifecycleAndNetworkingDNS(t *testing.T) {
	setupBlueprintTestDB(t)

	tmpRoot := t.TempDir()
	hostsFile := filepath.Join(tmpRoot, "hosts")
	piholeDir := filepath.Join(tmpRoot, "etc", "pihole")
	dnsmasqDir := filepath.Join(tmpRoot, "etc", "dnsmasq.d")
	lighttpdDir := filepath.Join(tmpRoot, "etc", "lighttpd")

	if err := os.MkdirAll(piholeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dnsmasqDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(lighttpdDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Seed a baseline pihole.toml so PiHoleMutator can mutate webserver.port and etc_dnsmasq_d
	piholeTomlPath := filepath.Join(piholeDir, "pihole.toml")
	_ = os.WriteFile(piholeTomlPath, []byte("[webserver]\n  port = \"80o\"\n[misc]\n  etc_dnsmasq_d = false\n"), 0644)

	t.Setenv("AETHERFLOW_CONFIG_ROOT", tmpRoot)
	t.Setenv("AETHERFLOW_HOSTS_FILE", hostsFile)
	t.Setenv("AETHERFLOW_PIHOLE_DIR", piholeDir)
	t.Setenv("AETHERFLOW_DNSMASQ_DIR", dnsmasqDir)
	t.Setenv("AETHERFLOW_LAN_IP", "192.168.1.50")

	// Simulate port 8096 (Jellyfin default) being occupied on this host so Jellyfin dynamically shifts to 18096
	t.Setenv("AETHERFLOW_OCCUPIED_PORTS", "8096")

	// 1. Apply Blueprint Post-Install for the 4 pilot apps: Radarr, Sonarr, Jellyfin, Pi-hole
	pilotApps := []string{"radarr", "sonarr", "jellyfin", "pihole"}
	results := make(map[string]*BlueprintSetupResult)

	for _, app := range pilotApps {
		prePort := PreAllocateAppPort(app)
		res, err := ApplyBlueprintPostInstall(app, prePort)
		if err != nil {
			t.Fatalf("ApplyBlueprintPostInstall(%q) failed: %v", app, err)
		}
		results[app] = res
	}

	// Verify Radarr & Sonarr XML configs and default ports
	if results["radarr"].AllocatedPort != 7878 {
		t.Errorf("radarr AllocatedPort = %d, want 7878", results["radarr"].AllocatedPort)
	}
	radarrXML, err := os.ReadFile(results["radarr"].ConfigPath)
	if err != nil {
		t.Fatalf("failed reading radarr config.xml: %v", err)
	}
	if !strings.Contains(string(radarrXML), "<Port>7878</Port>") || !strings.Contains(string(radarrXML), "<AuthenticationRequired>Enabled</AuthenticationRequired>") {
		t.Errorf("unexpected radarr config.xml content:\n%s", string(radarrXML))
	}

	if results["sonarr"].AllocatedPort != 8989 {
		t.Errorf("sonarr AllocatedPort = %d, want 8989", results["sonarr"].AllocatedPort)
	}
	sonarrXML, err := os.ReadFile(results["sonarr"].ConfigPath)
	if err != nil {
		t.Fatalf("failed reading sonarr config.xml: %v", err)
	}
	if !strings.Contains(string(sonarrXML), "<Port>8989</Port>") {
		t.Errorf("unexpected sonarr config.xml content:\n%s", string(sonarrXML))
	}

	// Verify Jellyfin dynamically shifted to port 18096 and updated network.xml with KnownProxies
	if results["jellyfin"].AllocatedPort != 18096 || !results["jellyfin"].PortReassigned {
		t.Errorf("jellyfin AllocatedPort = %d (reassigned=%v), want 18096 (true)",
			results["jellyfin"].AllocatedPort, results["jellyfin"].PortReassigned)
	}
	jellyfinXML, err := os.ReadFile(results["jellyfin"].ConfigPath)
	if err != nil {
		t.Fatalf("failed reading jellyfin network.xml: %v", err)
	}
	if !strings.Contains(string(jellyfinXML), "<InternalHttpPort>18096</InternalHttpPort>") ||
		!strings.Contains(string(jellyfinXML), "<string>127.0.0.1</string>") {
		t.Errorf("unexpected jellyfin network.xml content:\n%s", string(jellyfinXML))
	}

	// Verify Pi-hole config mutation and DNS auto-wiring for all apps
	piholeToml, err := os.ReadFile(piholeTomlPath)
	if err != nil {
		t.Fatalf("failed reading pihole.toml: %v", err)
	}
	if !strings.Contains(string(piholeToml), `port = "8089o"`) || !strings.Contains(string(piholeToml), `etc_dnsmasq_d = true`) {
		t.Errorf("unexpected pihole.toml content:\n%s", string(piholeToml))
	}

	customList, err := os.ReadFile(filepath.Join(piholeDir, "custom.list"))
	if err != nil {
		t.Fatalf("failed reading Pi-hole custom.list: %v", err)
	}
	dnsmasqConf, err := os.ReadFile(filepath.Join(dnsmasqDir, "05-aetherflow-dns.conf"))
	if err != nil {
		t.Fatalf("failed reading dnsmasq 05-aetherflow-dns.conf: %v", err)
	}
	hostsData, err := os.ReadFile(hostsFile)
	if err != nil {
		t.Fatalf("failed reading hosts file: %v", err)
	}

	for _, app := range pilotApps {
		domain := app + ".aether.local"
		if !strings.Contains(string(customList), "192.168.1.50 "+domain) {
			t.Errorf("Pi-hole custom.list missing entry for %s:\n%s", domain, string(customList))
		}
		if !strings.Contains(string(dnsmasqConf), "address=/"+domain+"/192.168.1.50") {
			t.Errorf("dnsmasq config missing entry for %s:\n%s", domain, string(dnsmasqConf))
		}
		if !strings.Contains(string(hostsData), domain) {
			t.Errorf("/etc/hosts missing entry for %s:\n%s", domain, string(hostsData))
		}
		if !results[app].IngressSynced {
			t.Errorf("expected IngressSynced=true for %s", app)
		}
		resolvedPort, resolvedApp, matched := ResolveAppTargetForHost(domain)
		if !matched || resolvedApp != app || resolvedPort != results[app].AllocatedPort {
			t.Errorf("ResolveAppTargetForHost(%s) = (%d, %q, %v), want (%d, %q, true)",
				domain, resolvedPort, resolvedApp, matched, results[app].AllocatedPort, app)
		}
	}

	// 2. Test Uninstall Teardown for Sonarr
	if err := TeardownBlueprintUninstall("sonarr"); err != nil {
		t.Fatalf("TeardownBlueprintUninstall(sonarr) failed: %v", err)
	}

	// Verify Sonarr removed from SQLite app_ingress_configs, /etc/hosts, and Pi-hole custom.list
	if ing, _ := db.GetAppIngressConfig("sonarr"); ing != nil {
		t.Errorf("expected sonarr ingress config to be deleted on uninstall, got %+v", ing)
	}
	hostsAfter, _ := os.ReadFile(hostsFile)
	if strings.Contains(string(hostsAfter), "sonarr.aether.local") {
		t.Errorf("expected sonarr.aether.local to be removed from /etc/hosts:\n%s", string(hostsAfter))
	}
	if !strings.Contains(string(hostsAfter), "radarr.aether.local") {
		t.Errorf("expected radarr.aether.local to remain in /etc/hosts after uninstalling sonarr")
	}

	customListAfter, _ := os.ReadFile(filepath.Join(piholeDir, "custom.list"))
	if strings.Contains(string(customListAfter), "sonarr.aether.local") {
		t.Errorf("expected sonarr.aether.local to be purged from Pi-hole custom.list on uninstall:\n%s", string(customListAfter))
	}
}

func TestAutoSubdomainProvisioningFromSettingsBaseDomain(t *testing.T) {
	setupBlueprintTestDB(t)

	tmpRoot := t.TempDir()
	hostsFile := filepath.Join(tmpRoot, "hosts")
	piholeDir := filepath.Join(tmpRoot, "etc", "pihole")
	dnsmasqDir := filepath.Join(tmpRoot, "etc", "dnsmasq.d")
	_ = os.MkdirAll(piholeDir, 0755)
	_ = os.MkdirAll(dnsmasqDir, 0755)

	t.Setenv("AETHERFLOW_CONFIG_ROOT", tmpRoot)
	t.Setenv("AETHERFLOW_HOSTS_FILE", hostsFile)
	t.Setenv("AETHERFLOW_PIHOLE_DIR", piholeDir)
	t.Setenv("AETHERFLOW_DNSMASQ_DIR", dnsmasqDir)
	t.Setenv("AETHERFLOW_LAN_IP", "192.168.1.50")

	// 1. Configure base_domain in SQLite settings (e.g. "*.domain.com" -> normalized "domain.com")
	if err := db.SetBaseDomain("*.domain.com"); err != nil {
		t.Fatalf("SetBaseDomain failed: %v", err)
	}
	if got := ResolveBaseDomain(); got != "domain.com" {
		t.Fatalf("ResolveBaseDomain() = %q, want 'domain.com'", got)
	}

	// 2. Install Jellyfin -> should automatically configure jellyfin.domain.com with TLS & external access
	res, err := ApplyBlueprintPostInstall("jellyfin", 8096)
	if err != nil {
		t.Fatalf("ApplyBlueprintPostInstall(jellyfin) failed: %v", err)
	}
	if res.PublicDomain != "jellyfin.domain.com" || !res.ExternalAccessEnabled {
		t.Fatalf("expected PublicDomain='jellyfin.domain.com' and ExternalAccessEnabled=true, got %+v", res)
	}
	if !res.HostsSynced {
		t.Errorf("expected res.HostsSynced=true when base_domain is configured, got false")
	}

	ing, err := db.GetAppIngressConfig("jellyfin")
	if err != nil || ing == nil {
		t.Fatalf("GetAppIngressConfig(jellyfin) failed: %v", err)
	}
	if ing.PublicDomain != "jellyfin.domain.com" || !ing.ExternalAccessEnabled || !ing.TLSEnabled {
		t.Errorf("unexpected persisted ingress config for jellyfin: %+v", ing)
	}

	if port, app, matched := ResolveAppTargetForHost("jellyfin.domain.com"); !matched || app != "jellyfin" || port != 8096 {
		t.Errorf("expected Subdomain Gateway route for jellyfin.domain.com on port 8096, got port=%d app=%q matched=%v", port, app, matched)
	}

	// 3. Change base domain to "newbox.io" and verify SyncInstalledAppsBaseDomain updates Jellyfin automatically
	_ = db.SetBaseDomain("newbox.io")
	SyncInstalledAppsBaseDomain("domain.com", "newbox.io")

	ingAfter, _ := db.GetAppIngressConfig("jellyfin")
	if ingAfter == nil || ingAfter.PublicDomain != "jellyfin.newbox.io" {
		t.Errorf("expected jellyfin domain to update to 'jellyfin.newbox.io', got %+v", ingAfter)
	}

	// 4. S-04 & S-02 Regression: Disable external access on Jellyfin, migrate domain again, and verify ExternalAccessEnabled=false is preserved and blocks public host resolution
	ingAfter.ExternalAccessEnabled = false
	_ = db.SetAppIngressConfig(*ingAfter)
	_ = db.SetBaseDomain(" migrated.io ")
	SyncInstalledAppsBaseDomain("newbox.io", "migrated.io")

	ingPreserved, _ := db.GetAppIngressConfig("jellyfin")
	if ingPreserved == nil || ingPreserved.PublicDomain != "jellyfin.migrated.io" || ingPreserved.ExternalAccessEnabled {
		t.Errorf("expected SyncInstalledAppsBaseDomain to preserve ExternalAccessEnabled=false, got %+v", ingPreserved)
	}
	if _, _, matched := ResolveAppTargetForHost("jellyfin.migrated.io"); matched {
		t.Errorf("expected ResolveAppTargetForHost(jellyfin.migrated.io) to be blocked when ExternalAccessEnabled=false")
	}
	if port, _, matched := ResolveAppTargetForHost("jellyfin.aether.local"); !matched || port != 8096 {
		t.Errorf("expected internal domain jellyfin.aether.local to remain routable on port 8096, got port=%d matched=%v", port, matched)
	}
}

func TestMasterCredentialsSyncIntoAppBlueprint(t *testing.T) {
	setupBlueprintTestDB(t)

	tmpRoot := t.TempDir()
	credsFile := filepath.Join(tmpRoot, "master.creds")
	t.Setenv("AETHERFLOW_CONFIG_ROOT", tmpRoot)
	t.Setenv("AETHERFLOW_MASTER_CREDS_FILE", credsFile)
	t.Setenv("AETHERFLOW_HOSTS_FILE", filepath.Join(tmpRoot, "hosts"))

	SaveMasterCredentials("betheenvy", "Sxw%?43KaUt3pu")
	u, p, h := LoadMasterCredentials()
	if u != "betheenvy" || p != "Sxw%?43KaUt3pu" || h != "483347885649d308bb8358e79828114a" {
		t.Fatalf("LoadMasterCredentials() = (%q, %q, %q), want (betheenvy, Sxw%%?43KaUt3pu, 483347885649d308bb8358e79828114a)", u, p, h)
	}

	bp := GetBlueprint("qbittorrent")
	cfgPath, applied, err := ApplyBlueprintAppConfig(bp, 8180)
	if err != nil || !applied {
		t.Fatalf("ApplyBlueprintAppConfig(qbittorrent) failed: applied=%v err=%v", applied, err)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("failed reading qBittorrent.conf: %v", err)
	}
	content := string(raw)
	if !strings.Contains(content, `WebUI\Username=betheenvy`) || !strings.Contains(content, `WebUI\Password_PBKDF2="@ByteArray(`) {
		t.Errorf("qBittorrent.conf missing master credentials:\n%s", content)
	}

	if !isConfigPathWritable(cfgPath) {
		t.Errorf("expected isConfigPathWritable(%q) to be true for writable file", cfgPath)
	}
	nonExistentParent := filepath.Join(tmpRoot, "missing-dir", "subdir", "qBittorrent.conf")
	if isConfigPathWritable(nonExistentParent) {
		t.Errorf("expected isConfigPathWritable(%q) to be false when parent directory does not exist", nonExistentParent)
	}
}

