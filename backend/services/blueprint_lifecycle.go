package services

import (
	"aetherflow/db"
	"aetherflow/models"
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// BlueprintSetupResult captures the outcome of applying an AppBlueprint after installation or sync.
type BlueprintSetupResult struct {
	AppName               string `json:"app_name"`
	ServiceName           string `json:"service_name"`
	AllocatedPort         int    `json:"allocated_port"`
	DefaultPort           int    `json:"default_port"`
	PortReassigned        bool   `json:"port_reassigned"`
	InternalDomain        string `json:"internal_domain"`
	PublicDomain          string `json:"public_domain,omitempty"`
	ExternalAccessEnabled bool   `json:"external_access_enabled"`
	ConfigPath            string `json:"config_path,omitempty"`
	ConfigApplied         bool   `json:"config_applied"`
	CaddySynced           bool   `json:"caddy_synced"`
	HostsSynced           bool   `json:"hosts_synced"`
	NetworkDNSSynced      bool   `json:"network_dns_synced"`
}

func resolveFilesystemPath(rawPath string) string {
	if rawPath == "" {
		return ""
	}
	if root := strings.TrimSpace(os.Getenv("AETHERFLOW_CONFIG_ROOT")); root != "" {
		cleanRel := strings.TrimPrefix(filepath.Clean(rawPath), string(filepath.Separator))
		cleanRel = strings.TrimPrefix(cleanRel, "/")
		return filepath.Join(root, cleanRel)
	}
	return rawPath
}

// IsTCPPortInUse checks whether a local TCP port is already bound by an active listener
// or marked occupied via AETHERFLOW_OCCUPIED_PORTS.
func IsTCPPortInUse(port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}

	if envOccupied, ok := os.LookupEnv("AETHERFLOW_OCCUPIED_PORTS"); ok {
		for _, tok := range strings.Split(envOccupied, ",") {
			if p, err := strconv.Atoi(strings.TrimSpace(tok)); err == nil && p == port {
				return true
			}
		}
		return false
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

// ResolveDynamicAppPort determines the port for an application, dynamically reassigning
// to an available fallback port if the default port is occupied by another service or app.
func ResolveDynamicAppPort(appName string, checkHostListeners bool) (int, bool, error) {
	bp := GetBlueprint(appName)
	if bp == nil {
		return 0, false, fmt.Errorf("blueprint not found for %s", appName)
	}
	if bp.DefaultPort <= 0 {
		// Headless / non-HTTP service (e.g., WireGuard, Fail2ban)
		return 0, false, nil
	}

	// 1. Check if this app already has a persisted port in app_ingress_configs
	if existing, err := db.GetAppIngressConfig(bp.AppName); err == nil && existing != nil && existing.ListenPort > 0 {
		return existing.ListenPort, existing.ListenPort != bp.DefaultPort, nil
	}

	// 2. Build reserved port set (system ports, other apps' persisted ports, and other catalog default ports)
	reserved := map[int]string{
		80:   "http",
		443:  "https",
		2019: "caddy-admin",
		8080: "aetherflow-api",
	}

	if allConfigs, err := db.GetAllAppIngressConfigs(); err == nil {
		for _, cfg := range allConfigs {
			if !strings.EqualFold(cfg.AppName, bp.AppName) && cfg.ListenPort > 0 {
				reserved[cfg.ListenPort] = cfg.AppName
			}
		}
	}

	for _, otherBP := range GetAllBlueprints() {
		if !strings.EqualFold(otherBP.AppName, bp.AppName) && otherBP.DefaultPort > 0 {
			if _, exists := reserved[otherBP.DefaultPort]; !exists {
				reserved[otherBP.DefaultPort] = otherBP.AppName
			}
		}
	}

	// 3. Check if bp.DefaultPort is available
	_, claimedByOther := reserved[bp.DefaultPort]
	hostBusy := false
	if checkHostListeners {
		hostBusy = IsTCPPortInUse(bp.DefaultPort)
	}

	if !claimedByOther && !hostBusy {
		return bp.DefaultPort, false, nil
	}

	// 4. Dynamically scan FallbackPortRange for the first free, unreserved port
	startPort := bp.FallbackPortRange[0]
	endPort := bp.FallbackPortRange[1]
	if startPort <= 0 || endPort < startPort {
		startPort = 17000
		endPort = 19999
	}

	for candidate := startPort; candidate <= endPort; candidate++ {
		if _, taken := reserved[candidate]; taken {
			continue
		}
		if !IsTCPPortInUse(candidate) {
			slog.Info("dynamically reassigned application port due to conflict",
				"app", bp.AppName, "default_port", bp.DefaultPort, "allocated_port", candidate)
			return candidate, true, nil
		}
	}

	return bp.DefaultPort, false, fmt.Errorf("no free fallback port available in range %d-%d for %s", startPort, endPort, bp.AppName)
}

// PreAllocateAppPort probes and reserves a conflict-free port before an install script runs.
func PreAllocateAppPort(appName string) int {
	port, _, err := ResolveDynamicAppPort(appName, true)
	if err != nil {
		if bp := GetBlueprint(appName); bp != nil {
			return bp.DefaultPort
		}
		return 0
	}
	return port
}

// ApplyBlueprintAppConfig writes or mutates the application's native configuration files
// according to its AppBlueprint and dynamically allocated port.
func ApplyBlueprintAppConfig(bp *AppBlueprint, activePort int) (string, bool, error) {
	if bp == nil {
		return "", false, nil
	}

	settings := make(map[string]string)
	for k, v := range bp.DefaultConfigs {
		settings[k] = v
	}

	if activePort > 0 && bp.PortConfigKey != "" {
		if bp.MutatorType == "pihole" {
			settings[bp.PortConfigKey] = fmt.Sprintf("%do", activePort)
		} else {
			settings[bp.PortConfigKey] = strconv.Itoa(activePort)
		}
		if bp.AppName == "jellyfin" {
			settings["InternalHttpPort"] = strconv.Itoa(activePort)
			settings["PublicHttpPort"] = strconv.Itoa(activePort)
		}
	}

	configPath := resolveFilesystemPath(bp.ConfigFilePath)
	applied := false

	switch bp.AppName {
	case "radarr", "sonarr", "lidarr", "readarr", "prowlarr":
		if configPath != "" && len(settings) > 0 {
			xmlMut := NewXMLMutator(configPath, "Config")
			_ = xmlMut.Backup()
			if err := xmlMut.ApplySettings(settings); err != nil {
				slog.Warn("blueprint XML config mutation notice", "app", bp.AppName, "path", configPath, "error", err)
			} else {
				applied = true
			}
		}
		dbPath := resolveFilesystemPath(bp.AppDataPath)
		if dbPath != "" && strings.HasSuffix(strings.ToLower(dbPath), ".db") {
			sqlMut := NewSQLiteMutator(dbPath)
			_ = sqlMut.Backup()
			routes := map[string]string{
				"localhost": "qbittorrent.aether.local",
				"127.0.0.1": "qbittorrent.aether.local",
			}
			_ = sqlMut.InjectRoutes(routes)
		}

	case "jellyfin":
		if configPath != "" && len(settings) > 0 {
			xmlMut := NewXMLMutator(configPath, "NetworkConfiguration")
			_ = xmlMut.Backup()
			if err := xmlMut.ApplySettings(settings); err != nil {
				slog.Warn("blueprint Jellyfin XML config notice", "app", bp.AppName, "path", configPath, "error", err)
			} else {
				applied = true
			}
		}

	case "pihole":
		if configPath != "" {
			phMut := NewPiHoleMutator(configPath)
			_ = phMut.Backup()
			if err := phMut.ApplyPortAndSettings(activePort, settings); err == nil {
				applied = true
			}
		}
		// Also update lighttpd port config if lighttpd dir exists (Pi-hole v5 compatibility)
		lighttpdDir := resolveFilesystemPath("/etc/lighttpd")
		if info, err := os.Stat(lighttpdDir); err == nil && info.IsDir() && activePort > 0 {
			extConf := filepath.Join(lighttpdDir, "external.conf")
			_ = os.WriteFile(extConf, []byte(fmt.Sprintf("server.port := %d\n", activePort)), 0644)
			confEnabled := filepath.Join(lighttpdDir, "conf-enabled")
			if st, err := os.Stat(confEnabled); err == nil && st.IsDir() {
				_ = os.WriteFile(filepath.Join(confEnabled, "99-pihole-port.conf"), []byte(fmt.Sprintf("server.port := %d\n", activePort)), 0644)
			}
			applied = true
		}

	default:
		masterUser, masterPass, masterHA1 := LoadMasterCredentials()
		if bp.AppName == "sabnzbd" {
			whitelist := "sabnzbd.aether.local, localhost, 127.0.0.1"
			defaultPub := ""
			if baseDomain := ResolveBaseDomain(); baseDomain != "" {
				defaultPub = FormatAppPublicDomain("sabnzbd", baseDomain)
				if defaultPub != "" {
					whitelist = fmt.Sprintf("%s, %s", defaultPub, whitelist)
				}
			}
			if ing, err := db.GetAppIngressConfig("sabnzbd"); err == nil && ing != nil && ing.ExternalAccessEnabled {
				if customPub := strings.ToLower(strings.TrimSpace(ing.PublicDomain)); customPub != "" && !strings.EqualFold(customPub, defaultPub) {
					whitelist = fmt.Sprintf("%s, %s", customPub, whitelist)
				}
			}
			settings["host_whitelist"] = whitelist
			if masterUser != "" && masterPass != "" {
				settings["username"] = masterUser
				settings["password"] = masterPass
			}
		}
		if bp.AppName == "qbittorrent" && masterUser != "" && masterPass != "" {
			settings[`WebUI\Username`] = masterUser
			settings[`WebUI\Password_PBKDF2`] = GenerateQBittorrentPBKDF2(masterPass)
			if masterHA1 != "" {
				settings[`WebUI\Password_ha1`] = fmt.Sprintf("@ByteArray(%s)", masterHA1)
			}
		}
		if bp.MutatorType == "ini" && configPath != "" && len(settings) > 0 {
			stoppedUnits := []string(nil)
			if bp.AppName == "qbittorrent" && IsRunnerAvailable() && isConfigPathWritable(configPath) {
				for _, unit := range ResolveServiceUnits(bp.AppName) {
					if err := ControlService(unit, "stop"); err == nil {
						stoppedUnits = append(stoppedUnits, unit)
					}
				}
				defer func() {
					for _, unit := range stoppedUnits {
						_ = ControlService(unit, "start")
					}
				}()
			}
			iniMut := NewINIMutator(configPath)
			_ = iniMut.Backup()
			if err := iniMut.ApplySettings(settings); err == nil {
				applied = true
			}
			if bp.AppName == "qbittorrent" {
				altPath := resolveFilesystemPath("/var/lib/qbittorrent/.config/qBittorrent/config/qBittorrent.conf")
				if altDir := filepath.Dir(altPath); altDir != "" {
					if info, err := os.Stat(altDir); err == nil && info.IsDir() {
						altMut := NewINIMutator(altPath)
						_ = altMut.ApplySettings(settings)
					}
				}
			}
		} else if bp.MutatorType == "xml" && configPath != "" && len(settings) > 0 {
			xmlMut := NewXMLMutator(configPath, "")
			_ = xmlMut.Backup()
			if err := xmlMut.ApplySettings(settings); err == nil {
				applied = true
			}
		}
	}

	return configPath, applied, nil
}

// isConfigPathWritable checks whether the current process has permission to write to configPath or its parent directory.
func isConfigPathWritable(configPath string) bool {
	if configPath == "" {
		return false
	}
	if f, err := os.OpenFile(configPath, os.O_WRONLY|os.O_APPEND, 0600); err == nil {
		_ = f.Close()
		return true
	}
	dir := filepath.Dir(configPath)
	if f, err := os.CreateTemp(dir, ".af-write-check-*"); err == nil {
		name := f.Name()
		_ = f.Close()
		_ = os.Remove(name)
		return true
	}
	return false
}

// detectPrimaryLANIP resolves the server's primary non-loopback IPv4 address for LAN DNS records.
func detectPrimaryLANIP() string {
	if customIP := strings.TrimSpace(os.Getenv("AETHERFLOW_LAN_IP")); customIP != "" {
		return customIP
	}
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					return ip4.String()
				}
			}
		}
	}
	return "127.0.0.1"
}

const (
	piholeBlockStart = "# --- AETHERFLOW MANAGED DNS ---"
	piholeBlockEnd   = "# --- END AETHERFLOW MANAGED DNS ---"
)

// SyncNetworkDNSProviders synchronizes all active AetherFlow internal (.aether.local) and
// configured public application domains into installed networking/DNS apps (Pi-hole, dnsmasq, WireGuard).
func SyncNetworkDNSProviders() (bool, error) {
	domainSet := map[string]bool{
		"aetherflow.aether.local": true,
	}

	// 1. Gather domains from persisted AppIngressConfigs
	configuredApps := make(map[string]models.AppIngressConfig)
	if configs, err := db.GetAllAppIngressConfigs(); err == nil {
		for _, cfg := range configs {
			if cfg.AppName != "" {
				lowerApp := strings.ToLower(strings.TrimSpace(cfg.AppName))
				configuredApps[lowerApp] = cfg
				domainSet[fmt.Sprintf("%s.aether.local", lowerApp)] = true
			}
			if cfg.ExternalAccessEnabled && cfg.PublicDomain != "" {
				domainSet[strings.ToLower(strings.TrimSpace(cfg.PublicDomain))] = true
			}
		}
	}

	// 2. Also include any installed packages from packages.json
	baseDomain := ResolveBaseDomain()
	if pkgs, err := GetPackages(); err == nil {
		for _, pkg := range pkgs {
			if (pkg.Status == "installed" || pkg.Status == "running") && pkg.Name != "" {
				lowerName := strings.ToLower(strings.TrimSpace(pkg.Name))
				domainSet[fmt.Sprintf("%s.aether.local", lowerName)] = true
				if baseDomain != "" && pkg.DefaultPort > 0 {
					if cfg, hasCfg := configuredApps[lowerName]; hasCfg && (!cfg.ExternalAccessEnabled || strings.TrimSpace(cfg.PublicDomain) != "") {
						continue
					}
					if pub := FormatAppPublicDomain(pkg.Name, baseDomain); pub != "" {
						domainSet[pub] = true
					}
				}
			}
		}
	}

	sortedDomains := make([]string, 0, len(domainSet))
	for d := range domainSet {
		sortedDomains = append(sortedDomains, d)
	}
	sort.Strings(sortedDomains)

	lanIP := detectPrimaryLANIP()
	syncedAny := false

	// 3. Sync Pi-hole custom.list if /etc/pihole exists (or AETHERFLOW_PIHOLE_DIR is set)
	piholeDir := strings.TrimSpace(os.Getenv("AETHERFLOW_PIHOLE_DIR"))
	if piholeDir == "" {
		piholeDir = resolveFilesystemPath("/etc/pihole")
	}
	if info, err := os.Stat(piholeDir); err == nil && info.IsDir() {
		customListPath := filepath.Join(piholeDir, "custom.list")
		if err := updatePiHoleCustomList(customListPath, lanIP, sortedDomains); err != nil {
			slog.Warn("failed to update Pi-hole custom.list", "path", customListPath, "error", err)
		} else {
			syncedAny = true
		}
	}

	// 4. Sync dnsmasq config (/etc/dnsmasq.d/05-aetherflow-dns.conf) if /etc/dnsmasq.d exists
	dnsmasqDir := strings.TrimSpace(os.Getenv("AETHERFLOW_DNSMASQ_DIR"))
	if dnsmasqDir == "" {
		dnsmasqDir = resolveFilesystemPath("/etc/dnsmasq.d")
	}
	if info, err := os.Stat(dnsmasqDir); err == nil && info.IsDir() {
		dnsmasqConf := filepath.Join(dnsmasqDir, "05-aetherflow-dns.conf")
		var lines []string
		lines = append(lines, "# Automatically managed by AetherFlow Blueprint Engine")
		for _, domain := range sortedDomains {
			lines = append(lines, fmt.Sprintf("address=/%s/%s", domain, lanIP))
		}
		if err := os.WriteFile(dnsmasqConf, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
			slog.Warn("failed to write dnsmasq AetherFlow config", "path", dnsmasqConf, "error", err)
		} else {
			syncedAny = true
		}
	}

	return syncedAny, nil
}

func updatePiHoleCustomList(customListPath, lanIP string, domains []string) error {
	content, err := os.ReadFile(customListPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	var preservedLines []string
	insideBlock := false
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == piholeBlockStart {
			insideBlock = true
			continue
		}
		if trimmed == piholeBlockEnd {
			insideBlock = false
			continue
		}
		if !insideBlock {
			preservedLines = append(preservedLines, line)
		}
	}

	managed := []string{piholeBlockStart}
	for _, domain := range domains {
		managed = append(managed, fmt.Sprintf("%s %s", lanIP, domain))
	}
	managed = append(managed, piholeBlockEnd)

	finalLines := append(preservedLines, managed...)
	return os.WriteFile(customListPath, []byte(strings.Join(finalLines, "\n")+"\n"), 0644)
}

// ResolveBaseDomain determines the active server base domain for Whatbox-style automatic
// application subdomain provisioning (e.g., jellyfin.domain.com).
// Priority order:
//  1. Persisted settings.base_domain in SQLite
//  2. AETHERFLOW_BASE_DOMAIN environment variable
//  3. AETHERFLOW_DOMAIN environment variable
func ResolveBaseDomain() string {
	if dbDomain := db.GetBaseDomain(); dbDomain != "" {
		return dbDomain
	}
	if envDomain := db.NormalizeBaseDomain(os.Getenv("AETHERFLOW_BASE_DOMAIN")); envDomain != "" {
		return envDomain
	}
	if envDomain := db.NormalizeBaseDomain(os.Getenv("AETHERFLOW_DOMAIN")); envDomain != "" {
		return envDomain
	}
	return ""
}

// FormatAppPublicDomain synthesizes "<app>.<baseDomain>" (e.g. "jellyfin.domain.com")
// without double-prefixing if baseDomain already starts with "<app>.".
func FormatAppPublicDomain(appName, baseDomain string) string {
	cleanApp := strings.ToLower(strings.TrimSpace(appName))
	cleanBase := db.NormalizeBaseDomain(baseDomain)
	if cleanApp == "" || cleanBase == "" {
		return ""
	}
	prefix := cleanApp + "."
	if strings.HasPrefix(cleanBase, prefix) {
		return cleanBase
	}
	return prefix + cleanBase
}

// SyncInstalledAppsBaseDomain automatically provisions or updates "<app>.<newBaseDomain>"
// across SQLite app_ingress_configs, Caddy reverse proxy routes, and local DNS providers
// for all installed applications (and existing auto-provisioned ingress records) when the
// server's base domain is configured or changed.
func SyncInstalledAppsBaseDomain(oldBaseDomain, newBaseDomain string) {
	cleanOld := db.NormalizeBaseDomain(oldBaseDomain)
	cleanNew := db.NormalizeBaseDomain(newBaseDomain)
	if cleanNew == "" {
		return
	}

	targetApps := make(map[string]bool)
	if pkgs, err := GetPackages(); err == nil {
		for _, pkg := range pkgs {
			if (pkg.Status == "installed" || pkg.Status == "running") && pkg.DefaultPort > 0 {
				targetApps[strings.ToLower(strings.TrimSpace(pkg.Name))] = true
			}
		}
	}
	if configs, err := db.GetAllAppIngressConfigs(); err == nil {
		for _, cfg := range configs {
			if cfg.AppName != "" {
				targetApps[strings.ToLower(strings.TrimSpace(cfg.AppName))] = true
			}
		}
	}

	caddyMgr := NewCaddyManager("")
	for appName := range targetApps {
		bp := GetBlueprint(appName)
		if bp == nil || bp.DefaultPort <= 0 {
			continue
		}

		existing, _ := db.GetAppIngressConfig(bp.AppName)
		activePort := bp.DefaultPort
		if existing != nil && existing.ListenPort > 0 {
			activePort = existing.ListenPort
		}

		shouldUpdateDomain := existing == nil ||
			(strings.TrimSpace(existing.PublicDomain) == "" && cleanOld == "") ||
			(cleanOld != "" && strings.EqualFold(strings.TrimSpace(existing.PublicDomain), FormatAppPublicDomain(bp.AppName, cleanOld)))

		if !shouldUpdateDomain {
			continue
		}

		extEnabled := true
		tlsEnabled := true
		if existing != nil && strings.TrimSpace(existing.PublicDomain) != "" {
			extEnabled = existing.ExternalAccessEnabled
			tlsEnabled = existing.TLSEnabled
		}

		pubDomain := FormatAppPublicDomain(bp.AppName, cleanNew)
		cfg := models.AppIngressConfig{
			AppName:               bp.AppName,
			PublicDomain:          pubDomain,
			ExternalAccessEnabled: extEnabled,
			ListenPort:            activePort,
			TLSEnabled:            tlsEnabled,
		}
		if err := db.SetAppIngressConfig(cfg); err != nil {
			slog.Warn("failed to auto-provision base domain ingress config", "app", bp.AppName, "domain", pubDomain, "error", err)
			continue
		}

		_, _, _ = ApplyBlueprintAppConfig(bp, activePort)

		_ = caddyMgr.UpdateAppRoutes(RoutingState{
			AppName:               bp.AppName,
			ActivePort:            activePort,
			InternalDomain:        bp.InternalDomain,
			PublicDomain:          pubDomain,
			ExternalAccessEnabled: extEnabled,
		})
		if bp.InternalDomain != "" {
			_ = NewDNSManager().AppendOrUpdateDomains([]string{bp.InternalDomain})
		}
	}

	_, _ = SyncNetworkDNSProviders()
	TriggerApacheCertSync()
}

// TriggerApacheCertSync asynchronously invokes the root af-certbot-sync oneshot unit
// via the privileged runner when available so Apache2's Let's Encrypt SAN certificate
// automatically expands to cover newly provisioned subdomains.
func TriggerApacheCertSync() {
	if IsRunnerAvailable() {
		go func() {
			_ = DispatchSystemctl("af-certbot-sync", "start")
		}()
	}
}

// ApplyBlueprintPostInstall executes the complete post-installation setup for an application:
// 1. Resolves a conflict-free port (or uses preAllocatedPort).
// 2. Writes/mutates the app's native configuration file.
// 3. Persists AppIngressConfig in SQLite (auto-setting <app>.<baseDomain> if a base domain is configured).
// 4. Wires Caddy reverse proxy routes (<app>.aether.local and public domain if configured).
// 5. Registers <app>.aether.local in /etc/hosts.
// 6. Synchronizes networking DNS apps (Pi-hole / dnsmasq) with all active domains.
// 7. Restarts the service if its port or config was dynamically modified.
func ApplyBlueprintPostInstall(appName string, preAllocatedPort int) (*BlueprintSetupResult, error) {
	bp := GetBlueprint(appName)
	if bp == nil {
		return nil, fmt.Errorf("no blueprint registered for %q", appName)
	}

	activePort := preAllocatedPort
	reassigned := false
	if bp.DefaultPort > 0 {
		if activePort <= 0 {
			resolvedPort, wasReassigned, err := ResolveDynamicAppPort(bp.AppName, false)
			if err != nil {
				activePort = bp.DefaultPort
			} else {
				activePort = resolvedPort
				reassigned = wasReassigned
			}
		} else {
			reassigned = activePort != bp.DefaultPort
		}
	}

	res := &BlueprintSetupResult{
		AppName:        bp.AppName,
		ServiceName:    bp.ServiceName,
		AllocatedPort:  activePort,
		DefaultPort:    bp.DefaultPort,
		PortReassigned: reassigned,
		InternalDomain: bp.InternalDomain,
	}

	// 1. Apply application configuration (XML / INI / SQLite / Pi-hole TOML)
	cfgPath, cfgApplied, _ := ApplyBlueprintAppConfig(bp, activePort)
	res.ConfigPath = cfgPath
	res.ConfigApplied = cfgApplied

	// 2. Persist ingress configuration in SQLite (preserving existing custom public domain,
	// or automatically provisioning <app>.<baseDomain> when the server domain is known)
	ingressCfg := models.AppIngressConfig{
		AppName:    bp.AppName,
		ListenPort: activePort,
	}
	existing, existingErr := db.GetAppIngressConfig(bp.AppName)
	if existingErr == nil && existing != nil && strings.TrimSpace(existing.PublicDomain) != "" {
		ingressCfg.PublicDomain = strings.TrimSpace(existing.PublicDomain)
		ingressCfg.ExternalAccessEnabled = existing.ExternalAccessEnabled
		ingressCfg.TLSEnabled = existing.TLSEnabled
	} else if baseDomain := ResolveBaseDomain(); baseDomain != "" && activePort > 0 {
		ingressCfg.PublicDomain = FormatAppPublicDomain(bp.AppName, baseDomain)
		ingressCfg.ExternalAccessEnabled = true
		ingressCfg.TLSEnabled = true
	} else if existingErr == nil && existing != nil {
		ingressCfg.PublicDomain = existing.PublicDomain
		ingressCfg.ExternalAccessEnabled = existing.ExternalAccessEnabled
		ingressCfg.TLSEnabled = existing.TLSEnabled
	}

	if activePort > 0 || bp.IsNetworkApp {
		if err := db.SetAppIngressConfig(ingressCfg); err != nil {
			slog.Warn("failed to persist blueprint ingress config", "app", bp.AppName, "error", err)
		}
	}
	res.PublicDomain = ingressCfg.PublicDomain
	res.ExternalAccessEnabled = ingressCfg.ExternalAccessEnabled
	if ingressCfg.ExternalAccessEnabled && ingressCfg.PublicDomain != "" {
		TriggerApacheCertSync()
	}

	// 3. Register route in Caddy Reverse Proxy if the app exposes an HTTP port
	if activePort > 0 {
		caddyMgr := NewCaddyManager("")
		routeState := RoutingState{
			AppName:               bp.AppName,
			ActivePort:            activePort,
			InternalDomain:        bp.InternalDomain,
			PublicDomain:          ingressCfg.PublicDomain,
			ExternalAccessEnabled: ingressCfg.ExternalAccessEnabled,
		}
		if err := caddyMgr.UpdateAppRoutes(routeState); err != nil {
			slog.Warn("blueprint Caddy route registration notice", "app", bp.AppName, "warning", err)
		} else {
			res.CaddySynced = true
		}
	}

	// 4. Register internal domain (<app>.aether.local) in /etc/hosts
	if bp.InternalDomain != "" {
		dnsMgr := NewDNSManager()
		if err := dnsMgr.AppendOrUpdateDomains([]string{bp.InternalDomain}); err != nil {
			slog.Warn("blueprint /etc/hosts registration notice", "app", bp.AppName, "warning", err)
		} else {
			res.HostsSynced = true
		}
	}

	// 5. Synchronize networking DNS apps (Pi-hole / dnsmasq)
	if netSynced, err := SyncNetworkDNSProviders(); err == nil && netSynced {
		res.NetworkDNSSynced = true
	}

	// 6. If the port was dynamically reassigned or config was updated, restart service units so changes take effect
	if (reassigned || cfgApplied) && bp.ServiceName != "" {
		for _, unit := range ResolveServiceUnits(bp.AppName) {
			_ = ControlService(unit, "restart")
		}
	}

	return res, nil
}

// TeardownBlueprintUninstall removes all AetherFlow managed routes, DNS records, and
// persisted ingress state when an application is uninstalled.
func TeardownBlueprintUninstall(appName string) error {
	bp := GetBlueprint(appName)
	canonicalName := strings.ToLower(strings.TrimSpace(appName))
	internalDomain := fmt.Sprintf("%s.aether.local", canonicalName)
	if bp != nil {
		canonicalName = bp.AppName
		if bp.InternalDomain != "" {
			internalDomain = bp.InternalDomain
		}
	}

	// 1. Remove routes from Caddy
	caddyMgr := NewCaddyManager("")
	if err := caddyMgr.RemoveAppRoutes(canonicalName); err != nil {
		slog.Warn("blueprint Caddy route removal notice", "app", canonicalName, "warning", err)
	}

	// 2. Remove internal domain from /etc/hosts
	dnsMgr := NewDNSManager()
	if err := dnsMgr.RemoveDomains([]string{internalDomain}); err != nil {
		slog.Warn("blueprint /etc/hosts removal notice", "app", canonicalName, "warning", err)
	}

	// 3. Delete persisted ingress record from SQLite
	if err := db.DeleteAppIngressConfig(canonicalName); err != nil {
		slog.Warn("failed to delete ingress config on uninstall", "app", canonicalName, "error", err)
	}

	// 4. Re-sync networking DNS providers (Pi-hole / dnsmasq) so removed domain is purged
	_, _ = SyncNetworkDNSProviders()

	return nil
}

// ResolveAppTargetForHost inspects an incoming HTTP Host header and determines whether
// it matches an installed application's public subdomain (<app>.<baseDomain> or custom
// PublicDomain) or internal domain (<app>.aether.local), returning its loopback port and app name.
func ResolveAppTargetForHost(hostHeader string) (int, string, bool) {
	host := strings.ToLower(strings.TrimSpace(hostHeader))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "aetherflow.aether.local" {
		return 0, "", false
	}
	if net.ParseIP(host) != nil {
		return 0, "", false
	}

	baseDomain := ResolveBaseDomain()
	if baseDomain != "" {
		if host == baseDomain || host == "www."+baseDomain || host == "direct."+baseDomain || host == "aetherflow."+baseDomain {
			return 0, "", false
		}
	}

	// 1. Check persisted app_ingress_configs
	if configs, err := db.GetAllAppIngressConfigs(); err == nil {
		for _, cfg := range configs {
			if cfg.ListenPort <= 0 {
				continue
			}
			pub := strings.ToLower(strings.TrimSpace(cfg.PublicDomain))
			if cfg.ExternalAccessEnabled && pub != "" && host == pub {
				return cfg.ListenPort, cfg.AppName, true
			}
			internalDom := fmt.Sprintf("%s.aether.local", strings.ToLower(strings.TrimSpace(cfg.AppName)))
			if host == internalDom {
				return cfg.ListenPort, cfg.AppName, true
			}
		}
	}

	// 2. Fallback: match <app>.aether.local or <app>.<baseDomain> against catalog blueprints
	var candidateApp string
	isInternal := false
	if strings.HasSuffix(host, ".aether.local") {
		candidateApp = strings.TrimSuffix(host, ".aether.local")
		isInternal = true
	} else if baseDomain != "" && strings.HasSuffix(host, "."+baseDomain) {
		candidateApp = strings.TrimSuffix(host, "."+baseDomain)
	}

	if candidateApp != "" && !strings.Contains(candidateApp, ".") {
		if bp := GetBlueprint(candidateApp); bp != nil && bp.DefaultPort > 0 {
			port := bp.DefaultPort
			if ing, err := db.GetAppIngressConfig(bp.AppName); err == nil && ing != nil {
				if !isInternal {
					if !ing.ExternalAccessEnabled {
						return 0, "", false
					}
					if pub := strings.ToLower(strings.TrimSpace(ing.PublicDomain)); pub != "" && pub != host {
						return 0, "", false
					}
				}
				if ing.ListenPort > 0 {
					port = ing.ListenPort
				}
			}
			return port, bp.AppName, true
		}
	}

	return 0, "", false
}

