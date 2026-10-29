package services

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// setupCatalogEnv configures relative paths to the config directory for tests.
func setupCatalogEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AETHERFLOW_PACKAGES_CONFIG", filepath.Join("..", "config", "packages.json"))
	t.Setenv("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", filepath.Join("..", "config", "package_automation.json"))
}

// TestAdversarial_BlueprintResolutionEdgeCases tests resolution across all 57 packages,
// service names, aliases, casing variants, whitespace padding, and invalid/nonexistent queries.
func TestAdversarial_BlueprintResolutionEdgeCases(t *testing.T) {
	setupCatalogEnv(t)

	pkgs, err := loadPackagesCatalog()
	if err != nil {
		t.Fatalf("loadPackagesCatalog failed: %v", err)
	}
	if len(pkgs) != 57 {
		t.Fatalf("expected exactly 57 packages, got %d", len(pkgs))
	}

	// 1. Every package name in packages.json must resolve to a valid blueprint
	for _, pkg := range pkgs {
		t.Run("pkg_"+pkg.Name, func(t *testing.T) {
			bp := GetBlueprint(pkg.Name)
			if bp == nil {
				t.Fatalf("GetBlueprint(%q) returned nil", pkg.Name)
			}
			if bp.AppName != pkg.Name {
				t.Errorf("GetBlueprint(%q).AppName = %q, want %q", pkg.Name, bp.AppName, pkg.Name)
			}
			if bp.DefaultPort != pkg.DefaultPort {
				t.Errorf("GetBlueprint(%q).DefaultPort = %d, want %d", pkg.Name, bp.DefaultPort, pkg.DefaultPort)
			}
			if pkg.DefaultPort > 0 && bp.FallbackPortRange[0] == 0 {
				t.Errorf("GetBlueprint(%q) has uninitialized FallbackPortRange", pkg.Name)
			}
			if pkg.DefaultPort > 0 && bp.HealthCheckPath == "" {
				t.Errorf("GetBlueprint(%q) has empty HealthCheckPath", pkg.Name)
			}
			if bp.InternalDomain != fmt.Sprintf("%s.aether.local", pkg.Name) {
				t.Errorf("GetBlueprint(%q).InternalDomain = %q, want %q", pkg.Name, bp.InternalDomain, fmt.Sprintf("%s.aether.local", pkg.Name))
			}
		})
	}

	// 2. Service name alias resolution (when distinct from AppName and != "apache2")
	for _, pkg := range pkgs {
		if pkg.ServiceName != "" && pkg.ServiceName != pkg.Name && pkg.ServiceName != "apache2" {
			t.Run("service_alias_"+pkg.ServiceName, func(t *testing.T) {
				bp := GetBlueprint(pkg.ServiceName)
				if bp == nil {
					t.Fatalf("GetBlueprint(%q) for service alias of %q returned nil", pkg.ServiceName, pkg.Name)
				}
				if bp.AppName != pkg.Name {
					t.Errorf("GetBlueprint(%q).AppName = %q, want %q", pkg.ServiceName, bp.AppName, pkg.Name)
				}
			})
		}
	}

	// 3. Known service aliases registered in blueprintRegistry
	serviceAliases := map[string]string{
		"paperless-webserver": "paperless-ngx",
		"deluged":             "deluge",
		"plexmediaserver":     "plex",
		"emby-server":         "emby",
		"rclone-vfs":          "rclone",
		"grafana-server":      "grafana",
		"uptime-kuma":         "uptimekuma",
	}
	for alias, expectedApp := range serviceAliases {
		t.Run("service_alias_"+alias, func(t *testing.T) {
			bp := GetBlueprint(alias)
			if bp == nil {
				t.Fatalf("GetBlueprint(%q) returned nil, expected blueprint for %q", alias, expectedApp)
			}
			if bp.AppName != expectedApp {
				t.Errorf("GetBlueprint(%q).AppName = %q, want %q", alias, bp.AppName, expectedApp)
			}
		})
	}

	// 4. Case variants and whitespace injection
	stressVariants := []struct {
		input       string
		expectedApp string
	}{
		{"  sonarr  ", "sonarr"},
		{"\t\nradarr\r\n", "radarr"},
		{"JELLYSEERR", "jellyseerr"},
		{"pApErLeSs-NgX", "paperless-ngx"},
		{"   ADGUARDHOME   ", "adguardhome"},
		{"   rClOnE   ", "rclone"},
		{"  UNPACKERR\t", "unpackerr"},
		{"\n\tAUTOSCAN\n", "autoscan"},
		{"Recyclarr", "recyclarr"},
		{"AUDIOBOOKSHELF", "audiobookshelf"},
		{"Kavita", "kavita"},
		{"CALIBREWEB", "calibreweb"},
		{"LibreSpeed", "librespeed"},
		{"TheLounge", "thelounge"},
		{"ZNC", "znc"},
		{"Scrutiny", "scrutiny"},
		{"N8N", "n8n"},
		{"RUTORRENT", "rutorrent"},
		{"RTORRENT", "rtorrent"},
		{"MERGERFS", "mergerfs"},
		{"CLOUDPLOW", "cloudplow"},
		{"  Qui\t", "qui"},
		{"  Threadfin\n", "threadfin"},
	}
	for _, sv := range stressVariants {
		t.Run("variant_"+strings.TrimSpace(sv.input), func(t *testing.T) {
			bp := GetBlueprint(sv.input)
			if bp == nil {
				t.Fatalf("GetBlueprint(%q) returned nil", sv.input)
			}
			if bp.AppName != sv.expectedApp {
				t.Errorf("GetBlueprint(%q).AppName = %q, want %q", sv.input, bp.AppName, sv.expectedApp)
			}
		})
	}

	// 5. Non-existent, empty, and malicious inputs MUST return nil without panicking
	invalidInputs := []string{
		"",
		"   ",
		"\t\r\n",
		"portainer",
		"docker",
		"docker-compose",
		"immich",
		"autodl-irssi",
		"nonexistent_package_xyz",
		"../../etc/passwd",
		"sonarr; rm -rf /",
		"<script>alert(1)</script>",
		strings.Repeat("A", 2048),
	}
	for _, inv := range invalidInputs {
		t.Run("invalid_input_"+strings.ReplaceAll(inv, "\n", "_"), func(t *testing.T) {
			bp := GetBlueprint(inv)
			if bp != nil {
				t.Fatalf("GetBlueprint(%q) returned non-nil blueprint: %+v", inv, bp)
			}
		})
	}

	// 6. Immutability & pointer isolation check:
	// Mutating the returned AppBlueprint must not mutate internal blueprint state
	t.Run("blueprint_immutability", func(t *testing.T) {
		bp1 := GetBlueprint("jellyfin")
		if bp1 == nil {
			t.Fatal("GetBlueprint('jellyfin') returned nil")
		}
		if bp1.DefaultConfigs != nil {
			bp1.DefaultConfigs["ATTACK_KEY"] = "INJECTED_VALUE"
		}
		bp1.AppName = "HACKED_JELLYFIN"

		bp2 := GetBlueprint("jellyfin")
		if bp2 == nil {
			t.Fatal("second GetBlueprint('jellyfin') returned nil")
		}
		if bp2.AppName != "jellyfin" {
			t.Errorf("internal AppName mutated to %q", bp2.AppName)
		}
		if bp2.DefaultConfigs != nil && bp2.DefaultConfigs["ATTACK_KEY"] == "INJECTED_VALUE" {
			t.Errorf("internal DefaultConfigs map mutated by caller")
		}

		// Also check dependencies slice mutation
		cp1 := GetBlueprint("cloudplow")
		if cp1 != nil && len(cp1.Dependencies) > 0 {
			origDep := cp1.Dependencies[0]
			cp1.Dependencies[0] = "MALICIOUS_DEPENDENCY"

			cp2 := GetBlueprint("cloudplow")
			if cp2.Dependencies[0] != origDep {
				t.Errorf("internal Dependencies slice mutated to %q", cp2.Dependencies[0])
			}
		}
	})
}

// TestAdversarial_PortUniquenessAndCollisions validates:
// - Zero collisions across all 57 packages (excluding headless 0)
// - Exclusion of reserved system ports (80, 443, 8080)
// - FallbackPortRange sanity and non-collision with default ports
func TestAdversarial_PortUniquenessAndCollisions(t *testing.T) {
	setupCatalogEnv(t)

	pkgs, err := loadPackagesCatalog()
	if err != nil {
		t.Fatalf("loadPackagesCatalog failed: %v", err)
	}

	seenPorts := make(map[int]string)
	reservedPorts := map[int]string{
		80:   "HTTP / Caddy",
		443:  "HTTPS / Caddy",
		8080: "AetherFlow API",
	}

	knownHeadless := []string{
		"wireguard",
		"fail2ban",
		"rtorrent",
		"mergerfs",
		"cloudplow",
		"unpackerr",
		"recyclarr",
	}

	var headlessFound []string
	var webFacingCount int

	for _, pkg := range pkgs {
		port := pkg.DefaultPort

		if port == 0 {
			headlessFound = append(headlessFound, pkg.Name)
			if !slices.Contains(knownHeadless, pkg.Name) {
				t.Errorf("unexpected headless package %q with default_port = 0", pkg.Name)
			}
			continue
		}

		webFacingCount++

		// Check reserved ports
		if svc, isReserved := reservedPorts[port]; isReserved {
			t.Errorf("package %q uses reserved system port %d (%s)", pkg.Name, port, svc)
		}

		// Check port range validity
		if port < 1024 || port > 65535 {
			t.Errorf("package %q has out-of-range default port %d (must be 1024-65535)", pkg.Name, port)
		}

		// Check collision with another package
		if prevPkg, collides := seenPorts[port]; collides {
			t.Fatalf("PORT COLLISION: port %d is assigned to both %q and %q", port, prevPkg, pkg.Name)
		}
		seenPorts[port] = pkg.Name

		// Check FallbackPortRange in blueprint
		bp := GetBlueprint(pkg.Name)
		if bp == nil {
			t.Fatalf("missing blueprint for %q", pkg.Name)
		}
		fb := bp.FallbackPortRange
		if fb[0] != 0 || fb[1] != 0 {
			if fb[0] >= fb[1] {
				t.Errorf("package %q has invalid FallbackPortRange: [%d, %d]", pkg.Name, fb[0], fb[1])
			}
			if fb[0] <= 1024 || fb[1] > 65535 {
				t.Errorf("package %q FallbackPortRange out of range: [%d, %d]", pkg.Name, fb[0], fb[1])
			}
			// Fallback range should not overlap with reserved ports
			for rPort := range reservedPorts {
				if rPort >= fb[0] && rPort <= fb[1] {
					t.Errorf("package %q FallbackPortRange [%d, %d] spans reserved port %d", pkg.Name, fb[0], fb[1], rPort)
				}
			}
		}
	}

	if len(headlessFound) != len(knownHeadless) {
		t.Errorf("expected exactly %d headless packages, found %d: %v", len(knownHeadless), len(headlessFound), headlessFound)
	}

	if webFacingCount != 50 {
		t.Errorf("expected exactly 50 web-facing packages, found %d", webFacingCount)
	}

	if len(seenPorts) != 50 {
		t.Errorf("expected exactly 50 unique web ports, got %d", len(seenPorts))
	}
}

// TestAdversarial_MultiUnitResolution validates:
// - All companion units resolve symmetrically to the full group
// - MatchesUnitFilter across entry units, filter units, package names, companion names
// - Graceful fallback on unknown services
// - Case insensitivity and whitespace resilience
func TestAdversarial_MultiUnitResolution(t *testing.T) {
	setupCatalogEnv(t)

	type multiUnitExpectation struct {
		name          string
		queryVariants []string
		expectedUnits []string
	}

	expectedGroups := []multiUnitExpectation{
		{
			name: "paperless-ngx",
			queryVariants: []string{
				"paperless-ngx",
				"paperless-ngx.service",
				"paperless",
				"paperless.service",
				"paperless-webserver",
				"paperless-webserver.service",
				"paperless-worker",
				"paperless-worker.service",
				"paperless-scheduler",
				"paperless-scheduler.service",
				"  PAPERLESS-WORKER  ",
				"PAPERLESS-NGX",
				"\tpaperless-scheduler.service\n",
			},
			expectedUnits: []string{
				"paperless-webserver",
				"paperless-worker",
				"paperless-scheduler",
			},
		},
		{
			name: "scrutiny",
			queryVariants: []string{
				"scrutiny",
				"scrutiny.service",
				"scrutiny-collector",
				"scrutiny-collector.service",
				"scrutiny-collector.timer",
				"  Scrutiny  ",
				"SCRUTINY-COLLECTOR.SERVICE",
			},
			expectedUnits: []string{
				"scrutiny",
				"scrutiny-collector",
				"scrutiny-collector.timer",
			},
		},
		{
			name: "recyclarr",
			queryVariants: []string{
				"recyclarr",
				"recyclarr.service",
				"recyclarr.timer",
				"  recyclarr.timer  ",
				"RECYCLARR",
				"RECYCLARR.TIMER",
			},
			expectedUnits: []string{
				"recyclarr",
				"recyclarr.timer",
			},
		},
		{
			name: "rclone",
			queryVariants: []string{
				"rclone",
				"rclone.service",
				"rclone-vfs",
				"rclone-vfs.service",
				"RCLONE-VFS",
				"  rclone-vfs.service  ",
			},
			expectedUnits: []string{
				"rclone",
				"rclone-vfs",
			},
		},
		{
			name: "deluge",
			queryVariants: []string{
				"deluge",
				"deluge.service",
				"deluged",
				"deluged.service",
				"deluge-web",
				"deluge-web.service",
				"DELUGED",
				"deluge-WEB",
			},
			expectedUnits: []string{
				"deluged",
				"deluge-web",
			},
		},
		{
			name: "prometheus",
			queryVariants: []string{
				"prometheus",
				"prometheus.service",
				"node_exporter",
				"node_exporter.service",
				"PROMETHEUS",
				"NODE_EXPORTER",
			},
			expectedUnits: []string{
				"prometheus",
				"node_exporter",
			},
		},
	}

	normalizeList := func(list []string) []string {
		norm := make([]string, len(list))
		for i, s := range list {
			norm[i] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".service"))
		}
		slices.Sort(norm)
		return norm
	}

	for _, group := range expectedGroups {
		normExpected := normalizeList(group.expectedUnits)

		for _, variant := range group.queryVariants {
			t.Run(fmt.Sprintf("resolve_%s_%s", group.name, strings.TrimSpace(variant)), func(t *testing.T) {
				resolved := ResolveServiceUnits(variant)
				normResolved := normalizeList(resolved)

				if !slices.Equal(normResolved, normExpected) {
					t.Fatalf("ResolveServiceUnits(%q) = %v (norm: %v), want %v (norm: %v)",
						variant, resolved, normResolved, group.expectedUnits, normExpected)
				}
			})
		}
	}

	// Unknown / arbitrary daemon graceful fallback:
	fallbackCases := []struct {
		input    string
		expected string
	}{
		{"custom-daemon", "custom-daemon"},
		{"my-app.service", "my-app"},
		{"custom_service.service", "custom_service"},
		{"  some-service.service  ", "some-service"},
	}
	for _, fc := range fallbackCases {
		t.Run("fallback_"+fc.input, func(t *testing.T) {
			res := ResolveServiceUnits(fc.input)
			if len(res) != 1 || res[0] != fc.expected {
				t.Fatalf("ResolveServiceUnits(%q) = %v, want [%q]", fc.input, res, fc.expected)
			}
		})
	}

	// Empty and blank inputs
	blankInputs := []string{"", "   ", "\t\n", ".service", "  .service  "}
	for _, b := range blankInputs {
		t.Run("blank_"+strings.ReplaceAll(b, "\n", "_"), func(t *testing.T) {
			res := ResolveServiceUnits(b)
			if res != nil {
				t.Fatalf("ResolveServiceUnits(%q) = %v, want nil", b, res)
			}
		})
	}

	// MatchesUnitFilter Adversarial Stress
	t.Run("MatchesUnitFilter_Adversarial", func(t *testing.T) {
		// Empty filter should match EVERYTHING
		if !MatchesUnitFilter("anything.service", "") {
			t.Error("expected empty filter to match 'anything.service'")
		}
		if !MatchesUnitFilter("", "") {
			t.Error("expected empty filter to match empty entry")
		}

		// Empty entry with non-empty filter should NOT match
		if MatchesUnitFilter("", "sonarr") {
			t.Error("expected empty entry to not match non-empty filter 'sonarr'")
		}

		// All companion pairings within each group must match in BOTH directions
		for _, group := range expectedGroups {
			for _, variantFilter := range group.queryVariants {
				for _, unitEntry := range group.expectedUnits {
					// With and without .service suffix on entry
					entries := []string{
						unitEntry,
						unitEntry + ".service",
						strings.ToUpper(unitEntry),
						"  " + unitEntry + ".service  ",
					}
					for _, e := range entries {
						if !MatchesUnitFilter(e, variantFilter) {
							t.Errorf("MatchesUnitFilter(entry=%q, filter=%q) = false, want true for group %s",
								e, variantFilter, group.name)
						}
					}
				}
			}
		}

		// Negative cross-group isolation: units in one group must NEVER match filters for another group
		for i, g1 := range expectedGroups {
			for j, g2 := range expectedGroups {
				if i == j {
					continue
				}
				for _, entry := range g1.expectedUnits {
					for _, filter := range g2.expectedUnits {
						if MatchesUnitFilter(entry, filter) {
							t.Errorf("ISOLATION LEAK: MatchesUnitFilter(entry=%q from %s, filter=%q from %s) = true, want false",
								entry, g1.name, filter, g2.name)
						}
					}
				}
			}
		}

		// Negative isolation between single-unit apps
		if MatchesUnitFilter("radarr.service", "sonarr") {
			t.Error("MatchesUnitFilter('radarr.service', 'sonarr') = true, want false")
		}
		if MatchesUnitFilter("plexmediaserver.service", "jellyfin") {
			t.Error("MatchesUnitFilter('plexmediaserver.service', 'jellyfin') = true, want false")
		}
	})
}

// TestAdversarial_FallbackSwitchCompleteness verifies that even when config files are absent
// (simulated by pointing to a non-existent path), ResolveServiceUnits falls back correctly.
func TestAdversarial_FallbackSwitchCompleteness(t *testing.T) {
	t.Setenv("AETHERFLOW_PACKAGES_CONFIG", filepath.Join("..", "config", "nonexistent_packages.json"))
	t.Setenv("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", filepath.Join("..", "config", "nonexistent_automation.json"))

	fallbackTests := []struct {
		target   string
		expected []string
	}{
		{"deluged", []string{"deluged", "deluge-web"}},
		{"deluge", []string{"deluged", "deluge-web"}},
		{"prometheus", []string{"prometheus", "node_exporter"}},
		{"node_exporter", []string{"prometheus", "node_exporter"}},
		{"paperless-ngx", []string{"paperless-webserver", "paperless-worker", "paperless-scheduler"}},
		{"paperless-worker", []string{"paperless-webserver", "paperless-worker", "paperless-scheduler"}},
		{"recyclarr", []string{"recyclarr", "recyclarr.timer"}},
		{"recyclarr.timer", []string{"recyclarr", "recyclarr.timer"}},
		{"rclone", []string{"rclone", "rclone-vfs"}},
		{"rclone-vfs", []string{"rclone", "rclone-vfs"}},
	}

	for _, ft := range fallbackTests {
		t.Run("fallback_static_"+ft.target, func(t *testing.T) {
			res := ResolveServiceUnits(ft.target)
			if !slices.Equal(res, ft.expected) {
				t.Errorf("ResolveServiceUnits(%q) fallback = %v, want %v", ft.target, res, ft.expected)
			}
		})
	}

	// Scrutiny fallback test: check whether fallback returns scrutiny and scrutiny-collector
	scrutinyRes := ResolveServiceUnits("scrutiny")
	if !slices.Contains(scrutinyRes, "scrutiny") || !slices.Contains(scrutinyRes, "scrutiny-collector") {
		t.Errorf("ResolveServiceUnits('scrutiny') fallback missing scrutiny or scrutiny-collector: %v", scrutinyRes)
	}
}

// TestAdversarial_ConcurrencyStress spawns 100 parallel goroutines
// pounding GetBlueprint, ResolveServiceUnits, and MatchesUnitFilter concurrently.
func TestAdversarial_ConcurrencyStress(t *testing.T) {
	setupCatalogEnv(t)

	pkgs, err := loadPackagesCatalog()
	if err != nil {
		t.Fatalf("loadPackagesCatalog failed: %v", err)
	}

	targets := make([]string, 0, len(pkgs)*3)
	for _, p := range pkgs {
		targets = append(targets, p.Name)
		if p.ServiceName != "" {
			targets = append(targets, p.ServiceName)
		}
		targets = append(targets, strings.ToUpper(p.Name))
		targets = append(targets, "  "+p.Name+"  ")
	}
	// Add companion units and edge cases
	targets = append(targets,
		"paperless-worker", "rclone-vfs", "recyclarr.timer", "scrutiny-collector",
		"deluge-web", "node_exporter", "portainer", "", "   ", "nonexistent-svc",
	)

	const numGoroutines = 100
	const iterationsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))

			for i := 0; i < iterationsPerGoroutine; i++ {
				target := targets[rng.Intn(len(targets))]

				// 1. GetBlueprint
				bp := GetBlueprint(target)
				if bp != nil {
					// Read fields to assert no race condition or panic
					_ = bp.AppName
					_ = bp.DefaultPort
					_ = bp.InternalDomain
					if bp.DefaultConfigs != nil {
						for k, v := range bp.DefaultConfigs {
							_ = k + v
						}
					}
					if len(bp.Dependencies) > 0 {
						_ = bp.Dependencies[0]
					}
				}

				// 2. ResolveServiceUnits
				units := ResolveServiceUnits(target)
				if len(units) > 0 {
					_ = units[0]
				}

				// 3. MatchesUnitFilter
				target2 := targets[rng.Intn(len(targets))]
				_ = MatchesUnitFilter(target, target2)
			}
		}(int64(g * 1000 + 42))
	}

	wg.Wait()
}
