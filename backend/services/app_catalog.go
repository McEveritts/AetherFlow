package services

import (
	"aetherflow/models"
	"encoding/json"
	"fmt"
	"strings"
)

func loadPackagesCatalog() ([]models.Package, error) {
	data, err := readFirstConfigFile(resolveConfigPaths("AETHERFLOW_PACKAGES_CONFIG", "packages.json"))
	if err != nil {
		return nil, err
	}
	var pkgs []models.Package
	if err := json.Unmarshal(data, &pkgs); err != nil {
		return nil, err
	}
	return pkgs, nil
}

// AppBlueprint defines the strict architectural definitions required by the
// deployment orchestration engine, post-install configuration provisioner,
// dynamic port resolver, and ingress/topology/DNS services.
type AppBlueprint struct {
	AppName           string            `json:"app_name"`
	ServiceName       string            `json:"service_name,omitempty"`
	Category          string            `json:"category,omitempty"`
	DefaultPort       int               `json:"default_port"`
	FallbackPortRange [2]int            `json:"fallback_port_range,omitempty"`
	PortEnvVar        string            `json:"port_env_var,omitempty"`
	PortConfigKey     string            `json:"port_config_key,omitempty"`
	WebPath           string            `json:"web_path,omitempty"`
	HealthCheckPath   string            `json:"health_check_path,omitempty"`
	MutatorType       string            `json:"mutator_type,omitempty"`
	ConfigFilePath    string            `json:"config_file_path,omitempty"`
	BinarySourceURL   string            `json:"binary_source_url,omitempty"`
	AppDataPath       string            `json:"app_data_path,omitempty"`
	InternalDomain    string            `json:"internal_domain,omitempty"`
	IsNetworkApp      bool              `json:"is_network_app,omitempty"`
	DNSProviderType   string            `json:"dns_provider_type,omitempty"`
	DefaultConfigs    map[string]string `json:"default_configs,omitempty"`
	Dependencies      []string          `json:"dependencies,omitempty"`
}

// blueprintRegistry holds baseline definitions for all 57 catalog apps, while
// GetBlueprint dynamically overlays config/packages.json as the single source of truth.
var blueprintRegistry = map[string]AppBlueprint{
	"plex": {
		AppName:           "plex",
		ServiceName:       "plexmediaserver",
		Category:          "Media",
		DefaultPort:       32400,
		FallbackPortRange: [2]int{32401, 32499},
		WebPath:           "/web",
		HealthCheckPath:   "/identity",
		AppDataPath:       "/var/lib/plexmediaserver",
	},
	"plexmediaserver": {
		AppName:           "plex",
		ServiceName:       "plexmediaserver",
		Category:          "Media",
		DefaultPort:       32400,
		FallbackPortRange: [2]int{32401, 32499},
		WebPath:           "/web",
		HealthCheckPath:   "/identity",
		AppDataPath:       "/var/lib/plexmediaserver",
	},
	"jellyfin": {
		AppName:           "jellyfin",
		ServiceName:       "jellyfin",
		Category:          "Media",
		DefaultPort:       8096,
		FallbackPortRange: [2]int{18096, 18196},
		PortConfigKey:     "InternalHttpPort",
		HealthCheckPath:   "/System/Info/Public",
		MutatorType:       "xml",
		ConfigFilePath:    "/etc/jellyfin/network.xml",
		AppDataPath:       "/var/lib/jellyfin",
		DefaultConfigs: map[string]string{
			"InternalHttpPort":   "8096",
			"PublicHttpPort":     "8096",
			"EnableIPV4":         "true",
			"EnableRemoteAccess": "true",
			"KnownProxies":       "127.0.0.1",
		},
	},
	"emby": {
		AppName:         "emby",
		ServiceName:     "emby-server",
		Category:        "Media",
		DefaultPort:     8097,
		HealthCheckPath: "/System/Info/Public",
		AppDataPath:     "/var/lib/emby",
	},
	"emby-server": {
		AppName:         "emby",
		ServiceName:     "emby-server",
		Category:        "Media",
		DefaultPort:     8097,
		HealthCheckPath: "/System/Info/Public",
		AppDataPath:     "/var/lib/emby",
	},
	"tautulli": {
		AppName:         "tautulli",
		ServiceName:     "tautulli",
		Category:        "Media",
		DefaultPort:     8181,
		PortConfigKey:   "http_port",
		MutatorType:     "ini",
		ConfigFilePath:  "/var/lib/tautulli/config.ini",
		AppDataPath:     "/var/lib/tautulli",
		Dependencies:    []string{"plex"},
	},
	"sonarr": {
		AppName:           "sonarr",
		ServiceName:       "sonarr",
		Category:          "Media",
		DefaultPort:       8989,
		FallbackPortRange: [2]int{18989, 19089},
		PortConfigKey:     "Port",
		HealthCheckPath:   "/ping",
		MutatorType:       "sqlite",
		ConfigFilePath:    "/var/lib/sonarr/config.xml",
		BinarySourceURL:   "https://services.sonarr.tv/v1/download/main/latest?version=4&os=linux&arch=x64",
		AppDataPath:       "/var/lib/sonarr/sonarr.db",
		DefaultConfigs: map[string]string{
			"BindAddress":            "*",
			"Port":                   "8989",
			"AuthenticationMethod":   "Forms",
			"AuthenticationRequired": "DisabledForLocalAddresses",
			"AnalyticsEnabled":       "False",
			"InstanceName":           "AetherFlow Sonarr",
		},
		Dependencies: []string{"prowlarr", "qbittorrent", "sabnzbd"},
	},
	"radarr": {
		AppName:           "radarr",
		ServiceName:       "radarr",
		Category:          "Media",
		DefaultPort:       7878,
		FallbackPortRange: [2]int{17878, 17978},
		PortConfigKey:     "Port",
		HealthCheckPath:   "/ping",
		MutatorType:       "sqlite",
		ConfigFilePath:    "/var/lib/radarr/config.xml",
		BinarySourceURL:   "https://hub.aetherflow.io/bin/radarr/latest.tar.gz",
		AppDataPath:       "/var/lib/radarr/radarr.db",
		DefaultConfigs: map[string]string{
			"BindAddress":            "*",
			"Port":                   "7878",
			"AuthenticationMethod":   "Forms",
			"AuthenticationRequired": "DisabledForLocalAddresses",
			"AnalyticsEnabled":       "False",
			"InstanceName":           "AetherFlow Radarr",
		},
		Dependencies: []string{"prowlarr", "qbittorrent", "sabnzbd"},
	},
	"lidarr": {
		AppName:         "lidarr",
		ServiceName:     "lidarr",
		Category:        "Media",
		DefaultPort:     8686,
		PortConfigKey:   "Port",
		HealthCheckPath: "/ping",
		MutatorType:     "sqlite",
		ConfigFilePath:  "/var/lib/lidarr/config.xml",
		AppDataPath:     "/var/lib/lidarr/lidarr.db",
		DefaultConfigs: map[string]string{
			"BindAddress":            "*",
			"Port":                   "8686",
			"AuthenticationMethod":   "Forms",
			"AuthenticationRequired": "DisabledForLocalAddresses",
			"AnalyticsEnabled":       "False",
		},
		Dependencies: []string{"prowlarr", "qbittorrent", "sabnzbd"},
	},
	"readarr": {
		AppName:         "readarr",
		ServiceName:     "readarr",
		Category:        "Media",
		DefaultPort:     8787,
		PortConfigKey:   "Port",
		HealthCheckPath: "/ping",
		MutatorType:     "sqlite",
		ConfigFilePath:  "/var/lib/readarr/config.xml",
		AppDataPath:     "/var/lib/readarr/readarr.db",
		DefaultConfigs: map[string]string{
			"BindAddress":            "*",
			"Port":                   "8787",
			"AuthenticationMethod":   "Forms",
			"AuthenticationRequired": "DisabledForLocalAddresses",
			"AnalyticsEnabled":       "False",
		},
		Dependencies: []string{"prowlarr", "qbittorrent", "sabnzbd"},
	},
	"prowlarr": {
		AppName:         "prowlarr",
		ServiceName:     "prowlarr",
		Category:        "Media",
		DefaultPort:     9696,
		PortConfigKey:   "Port",
		HealthCheckPath: "/ping",
		MutatorType:     "sqlite",
		ConfigFilePath:  "/var/lib/prowlarr/config.xml",
		AppDataPath:     "/var/lib/prowlarr/prowlarr.db",
		DefaultConfigs: map[string]string{
			"BindAddress":            "*",
			"Port":                   "9696",
			"AuthenticationMethod":   "Forms",
			"AuthenticationRequired": "DisabledForLocalAddresses",
			"AnalyticsEnabled":       "False",
		},
		Dependencies: []string{"flaresolverr"},
	},
	"bazarr": {
		AppName:         "bazarr",
		ServiceName:     "bazarr",
		Category:        "Media",
		DefaultPort:     6767,
		HealthCheckPath: "/ping",
		AppDataPath:     "/var/lib/bazarr",
		Dependencies:    []string{"sonarr", "radarr"},
	},
	"ombi": {
		AppName:         "ombi",
		ServiceName:     "ombi",
		Category:        "Media",
		DefaultPort:     5000,
		HealthCheckPath: "/api/v1/Status",
		AppDataPath:     "/var/lib/ombi",
		Dependencies:    []string{"plex", "jellyfin", "sonarr", "radarr"},
	},
	"overseerr": {
		AppName:         "overseerr",
		ServiceName:     "overseerr",
		Category:        "Media",
		DefaultPort:     5056,
		PortEnvVar:      "PORT",
		HealthCheckPath: "/api/v1/status",
		AppDataPath:     "/var/lib/overseerr",
		Dependencies:    []string{"plex", "sonarr", "radarr"},
	},
	"jellyseerr": {
		AppName:         "jellyseerr",
		ServiceName:     "jellyseerr",
		Category:        "Media",
		DefaultPort:     5055,
		PortEnvVar:      "PORT",
		HealthCheckPath: "/api/v1/status",
		AppDataPath:     "/var/lib/jellyseerr",
		Dependencies:    []string{"jellyfin", "sonarr", "radarr"},
	},
	"jackett": {
		AppName:     "jackett",
		ServiceName: "jackett",
		Category:    "Media",
		DefaultPort: 9117,
		AppDataPath: "/var/lib/jackett",
	},
	"flaresolverr": {
		AppName:         "flaresolverr",
		ServiceName:     "flaresolverr",
		Category:        "Media",
		DefaultPort:     8191,
		PortEnvVar:      "PORT",
		HealthCheckPath: "/health",
	},
	"navidrome": {
		AppName:     "navidrome",
		ServiceName: "navidrome",
		Category:    "Media",
		DefaultPort: 4533,
		AppDataPath: "/var/lib/navidrome",
	},
	"threadfin": {
		AppName:         "threadfin",
		ServiceName:     "threadfin",
		Category:        "Media",
		DefaultPort:     34400,
		WebPath:         "/web",
		HealthCheckPath: "/web",
		AppDataPath:     "/var/lib/threadfin",
		Dependencies:    []string{"plex", "jellyfin", "emby"},
	},
	"qbittorrent": {
		AppName:           "qbittorrent",
		ServiceName:       "qbittorrent",
		Category:          "Downloaders",
		DefaultPort:       8180,
		FallbackPortRange: [2]int{18180, 18280},
		PortConfigKey:     `WebUI\Port`,
		MutatorType:       "ini",
		ConfigFilePath:    "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
		BinarySourceURL:   "https://hub.aetherflow.io/bin/qbittorrent/latest.tar.gz",
		AppDataPath:       "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
		DefaultConfigs: map[string]string{
			`WebUI\Port`:                  "8180",
			`WebUI\Address`:               "*",
			`WebUI\LocalHostAuth`:         "false",
			`WebUI\HostHeaderValidation`:  "false",
			`WebUI\CSRFProtection`:        "false",
		},
	},
	"qbittorrent-nox": {
		AppName:           "qbittorrent",
		ServiceName:       "qbittorrent",
		Category:          "Downloaders",
		DefaultPort:       8180,
		FallbackPortRange: [2]int{18180, 18280},
		PortConfigKey:     `WebUI\Port`,
		MutatorType:       "ini",
		ConfigFilePath:    "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
		BinarySourceURL:   "https://hub.aetherflow.io/bin/qbittorrent/latest.tar.gz",
		AppDataPath:       "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
	},
	"deluge":              {AppName: "deluge", ServiceName: "deluged", Category: "Downloaders", DefaultPort: 8112},
	"deluged":             {AppName: "deluge", ServiceName: "deluged", Category: "Downloaders", DefaultPort: 8112},
	"transmission":        {AppName: "transmission", ServiceName: "transmission-daemon", Category: "Downloaders", DefaultPort: 9091},
	"transmission-daemon": {AppName: "transmission", ServiceName: "transmission-daemon", Category: "Downloaders", DefaultPort: 9091},
	"sabnzbd": {
		AppName:        "sabnzbd",
		ServiceName:    "sabnzbd",
		Category:       "Downloaders",
		DefaultPort:    8085,
		PortConfigKey:  "port",
		MutatorType:    "ini",
		ConfigFilePath: "/var/lib/sabnzbd/sabnzbd.ini",
		AppDataPath:    "/var/lib/sabnzbd/sabnzbd.ini",
		DefaultConfigs: map[string]string{
			"port":           "8085",
			"host":           "0.0.0.0",
			"inet_exposure":  "4",
			"host_whitelist": "sabnzbd.aether.local, localhost, 127.0.0.1",
		},
	},
	"nzbget":      {AppName: "nzbget", ServiceName: "nzbget", Category: "Downloaders", DefaultPort: 6789},
	"flood":       {AppName: "flood", ServiceName: "flood", Category: "Downloaders", DefaultPort: 3001},
	"autobrr":     {AppName: "autobrr", ServiceName: "autobrr", Category: "Downloaders", DefaultPort: 7474},
	"qui": {
		AppName:         "qui",
		ServiceName:     "qui",
		Category:        "Downloaders",
		DefaultPort:     7476,
		WebPath:         "/",
		HealthCheckPath: "/",
		ConfigFilePath:  "/var/lib/qui/config.toml",
		AppDataPath:     "/var/lib/qui",
		Dependencies:    []string{"qbittorrent"},
	},
	"nextcloud":   {AppName: "nextcloud", ServiceName: "apache2", Category: "Cloud", DefaultPort: 8088, WebPath: "/"},
	"syncthing":   {AppName: "syncthing", ServiceName: "syncthing", Category: "Cloud", DefaultPort: 8384},
	"filebrowser": {AppName: "filebrowser", ServiceName: "filebrowser", Category: "Cloud", DefaultPort: 8095},
	"wireguard": {
		AppName:        "wireguard",
		ServiceName:    "wg-quick@wg0",
		Category:       "Network",
		DefaultPort:    0,
		ConfigFilePath: "/etc/wireguard/wg0.conf",
		AppDataPath:    "/etc/wireguard",
		IsNetworkApp:   true,
	},
	"wg-quick@wg0": {
		AppName:        "wireguard",
		ServiceName:    "wg-quick@wg0",
		Category:       "Network",
		DefaultPort:    0,
		ConfigFilePath: "/etc/wireguard/wg0.conf",
		AppDataPath:    "/etc/wireguard",
		IsNetworkApp:   true,
	},
	"pihole": {
		AppName:           "pihole",
		ServiceName:       "pihole-FTL",
		Category:          "Network",
		DefaultPort:       8089,
		FallbackPortRange: [2]int{18089, 18189},
		PortConfigKey:     "webserver.port",
		WebPath:           "/admin",
		HealthCheckPath:   "/admin/",
		MutatorType:       "pihole",
		ConfigFilePath:    "/etc/pihole/pihole.toml",
		AppDataPath:       "/etc/pihole",
		IsNetworkApp:      true,
		DNSProviderType:   "pihole",
		DefaultConfigs: map[string]string{
			"webserver.port": "8089o",
			"etc_dnsmasq_d":  "true",
		},
	},
	"pihole-ftl": {
		AppName:           "pihole",
		ServiceName:       "pihole-FTL",
		Category:          "Network",
		DefaultPort:       8089,
		FallbackPortRange: [2]int{18089, 18189},
		PortConfigKey:     "webserver.port",
		WebPath:           "/admin",
		HealthCheckPath:   "/admin/",
		MutatorType:       "pihole",
		ConfigFilePath:    "/etc/pihole/pihole.toml",
		AppDataPath:       "/etc/pihole",
		IsNetworkApp:      true,
		DNSProviderType:   "pihole",
	},
	"adguardhome": {
		AppName:           "adguardhome",
		ServiceName:       "adguardhome",
		Category:          "Network",
		DefaultPort:       3080,
		FallbackPortRange: [2]int{13080, 13180},
		PortConfigKey:     "bind_port",
		ConfigFilePath:    "/opt/AdGuardHome/AdGuardHome.yaml",
		AppDataPath:       "/opt/AdGuardHome",
		IsNetworkApp:      true,
		DNSProviderType:   "adguard",
	},
	"AdGuardHome": {
		AppName:           "adguardhome",
		ServiceName:       "adguardhome",
		Category:          "Network",
		DefaultPort:       3080,
		FallbackPortRange: [2]int{13080, 13180},
		PortConfigKey:     "bind_port",
		ConfigFilePath:    "/opt/AdGuardHome/AdGuardHome.yaml",
		AppDataPath:       "/opt/AdGuardHome",
		IsNetworkApp:      true,
		DNSProviderType:   "adguard",
	},
	"fail2ban": {
		AppName:     "fail2ban",
		ServiceName: "fail2ban",
		Category:    "Security",
		DefaultPort: 0,
		AppDataPath: "/etc/fail2ban",
	},
	"vaultwarden": {
		AppName:         "vaultwarden",
		ServiceName:     "vaultwarden",
		Category:        "Security",
		DefaultPort:     8343,
		PortEnvVar:      "ROCKET_PORT",
		HealthCheckPath: "/alive",
		AppDataPath:     "/var/lib/vaultwarden",
		IsNetworkApp:    true,
	},
	"grafana":                      {AppName: "grafana", ServiceName: "grafana-server", Category: "Monitoring", DefaultPort: 3000, HealthCheckPath: "/api/health"},
	"grafana-server":               {AppName: "grafana", ServiceName: "grafana-server", Category: "Monitoring", DefaultPort: 3000, HealthCheckPath: "/api/health"},
	"prometheus":                   {AppName: "prometheus", ServiceName: "prometheus", Category: "Monitoring", DefaultPort: 9090, HealthCheckPath: "/-/healthy"},
	"uptimekuma":                   {AppName: "uptimekuma", ServiceName: "uptime-kuma", Category: "Monitoring", DefaultPort: 3004},
	"uptime-kuma":                  {AppName: "uptimekuma", ServiceName: "uptime-kuma", Category: "Monitoring", DefaultPort: 3004},
	"netdata":                      {AppName: "netdata", ServiceName: "netdata", Category: "Monitoring", DefaultPort: 19999, HealthCheckPath: "/api/v1/info"},
	"homeassistant":                {AppName: "homeassistant", ServiceName: "home-assistant@homeassistant", Category: "Automation", DefaultPort: 8123},
	"home-assistant@homeassistant": {AppName: "homeassistant", ServiceName: "home-assistant@homeassistant", Category: "Automation", DefaultPort: 8123},
	"rtorrent": {
		AppName:     "rtorrent",
		ServiceName: "rtorrent",
		Category:    "Downloaders",
		DefaultPort: 0,
		AppDataPath: "/var/lib/rtorrent",
	},
	"rutorrent": {
		AppName:      "rutorrent",
		ServiceName:  "apache2",
		Category:     "Downloaders",
		DefaultPort:  8087,
		WebPath:      "/",
		AppDataPath:  "/var/www/rutorrent",
		Dependencies: []string{"rtorrent"},
	},
	"rclone": {
		AppName:     "rclone",
		ServiceName: "rclone",
		Category:    "Cloud",
		DefaultPort: 5572,
		WebPath:     "/",
		AppDataPath: "/var/lib/rclone",
	},
	"rclone-vfs": {
		AppName:     "rclone",
		ServiceName: "rclone-vfs",
		Category:    "Cloud",
		DefaultPort: 0,
		AppDataPath: "/mnt/remote",
	},
	"mergerfs": {
		AppName:     "mergerfs",
		ServiceName: "mergerfs",
		Category:    "Cloud",
		DefaultPort: 0,
		AppDataPath: "/mnt/unionfs",
	},
	"cloudplow": {
		AppName:      "cloudplow",
		ServiceName:  "cloudplow",
		Category:     "Cloud",
		DefaultPort:  0,
		AppDataPath:  "/opt/cloudplow",
		Dependencies: []string{"rclone", "mergerfs"},
	},
	"unpackerr": {
		AppName:     "unpackerr",
		ServiceName: "unpackerr",
		Category:    "Media",
		DefaultPort: 0,
		AppDataPath: "/var/lib/unpackerr",
	},
	"autoscan": {
		AppName:         "autoscan",
		ServiceName:     "autoscan",
		Category:        "Media",
		DefaultPort:     3030,
		WebPath:         "/",
		HealthCheckPath: "/api/v1/status",
		AppDataPath:     "/var/lib/autoscan",
	},
	"recyclarr": {
		AppName:     "recyclarr",
		ServiceName: "recyclarr",
		Category:    "Media",
		DefaultPort: 0,
		AppDataPath: "/var/lib/recyclarr",
	},
	"audiobookshelf": {
		AppName:         "audiobookshelf",
		ServiceName:     "audiobookshelf",
		Category:        "Media",
		DefaultPort:     13378,
		WebPath:         "/",
		HealthCheckPath: "/ping",
		AppDataPath:     "/var/lib/audiobookshelf",
	},
	"kavita": {
		AppName:         "kavita",
		ServiceName:     "kavita",
		Category:        "Media",
		DefaultPort:     5002,
		WebPath:         "/",
		HealthCheckPath: "/api/health",
		AppDataPath:     "/var/lib/kavita",
	},
	"calibreweb": {
		AppName:         "calibreweb",
		ServiceName:     "calibreweb",
		Category:        "Media",
		DefaultPort:     8083,
		WebPath:         "/",
		HealthCheckPath: "/",
		AppDataPath:     "/var/lib/calibre-web",
	},
	"librespeed": {
		AppName:         "librespeed",
		ServiceName:     "librespeed",
		Category:        "Network",
		DefaultPort:     8988,
		WebPath:         "/",
		HealthCheckPath: "/",
		AppDataPath:     "/opt/librespeed",
		IsNetworkApp:    true,
	},
	"thelounge": {
		AppName:         "thelounge",
		ServiceName:     "thelounge",
		Category:        "Network",
		DefaultPort:     9000,
		WebPath:         "/",
		HealthCheckPath: "/",
		AppDataPath:     "/var/lib/thelounge",
		IsNetworkApp:    true,
	},
	"znc": {
		AppName:         "znc",
		ServiceName:     "znc",
		Category:        "Network",
		DefaultPort:     6501,
		WebPath:         "/",
		HealthCheckPath: "/",
		AppDataPath:     "/var/lib/znc",
		IsNetworkApp:    true,
	},
	"scrutiny": {
		AppName:         "scrutiny",
		ServiceName:     "scrutiny",
		Category:        "Monitoring",
		DefaultPort:     8098,
		WebPath:         "/",
		HealthCheckPath: "/api/health",
		AppDataPath:     "/var/lib/scrutiny",
	},
	"paperless-ngx": {
		AppName:         "paperless-ngx",
		ServiceName:     "paperless-webserver",
		Category:        "Cloud",
		DefaultPort:     8010,
		WebPath:         "/",
		HealthCheckPath: "/",
		AppDataPath:     "/var/lib/paperless",
	},
	"paperless-webserver": {
		AppName:         "paperless-ngx",
		ServiceName:     "paperless-webserver",
		Category:        "Cloud",
		DefaultPort:     8010,
		WebPath:         "/",
		HealthCheckPath: "/",
		AppDataPath:     "/var/lib/paperless",
	},
	"n8n": {
		AppName:         "n8n",
		ServiceName:     "n8n",
		Category:        "Automation",
		DefaultPort:     5678,
		WebPath:         "/",
		HealthCheckPath: "/healthz",
		AppDataPath:     "/var/lib/n8n",
	},
	"gitea":                        {AppName: "gitea", ServiceName: "gitea", Category: "DevOps", DefaultPort: 3002},
	"organizr":                     {AppName: "organizr", ServiceName: "apache2", Category: "Utilities", DefaultPort: 8086, WebPath: "/"},
}

// GetBlueprint looks up blueprint metadata for an app name or systemd service name,
// using config/packages.json as the single source of truth for DefaultPort and WebPath.
func GetBlueprint(requestedApp string) *AppBlueprint {
	cleanName := strings.ToLower(strings.TrimSpace(requestedApp))
	if cleanName == "" {
		return nil
	}
	if cleanName == "paperless" {
		cleanName = "paperless-ngx"
	}

	var result AppBlueprint
	found := false

	if base, exists := blueprintRegistry[cleanName]; exists {
		result = base
		if base.DefaultConfigs != nil {
			clonedConfigs := make(map[string]string, len(base.DefaultConfigs))
			for k, v := range base.DefaultConfigs {
				clonedConfigs[k] = v
			}
			result.DefaultConfigs = clonedConfigs
		}
		if base.Dependencies != nil {
			result.Dependencies = append([]string(nil), base.Dependencies...)
		}
		found = true
	}

	if pkgs, err := loadPackagesCatalog(); err == nil {
		for _, pkg := range pkgs {
			pkgName := strings.ToLower(strings.TrimSpace(pkg.Name))
			svcName := strings.ToLower(strings.TrimSpace(pkg.ServiceName))
			if pkgName == cleanName || (svcName != "" && svcName == cleanName) {
				if !found {
					result = AppBlueprint{
						AppName: pkg.Name,
					}
					found = true
				}
				if result.ServiceName == "" && pkg.ServiceName != "" {
					result.ServiceName = pkg.ServiceName
				}
				if result.Category == "" && pkg.Category != "" {
					result.Category = pkg.Category
				}
				if pkg.DefaultPort > 0 {
					result.DefaultPort = pkg.DefaultPort
				}
				if pkg.WebPath != "" {
					result.WebPath = pkg.WebPath
				}
				if pkg.Category == "Network" {
					result.IsNetworkApp = true
				}
				break
			}
		}
	}

	if !found {
		return nil
	}

	if result.InternalDomain == "" && result.AppName != "" {
		result.InternalDomain = fmt.Sprintf("%s.aether.local", result.AppName)
	}
	if result.DefaultPort > 0 && result.FallbackPortRange[0] == 0 {
		result.FallbackPortRange = [2]int{17000, 19999}
	}
	if result.HealthCheckPath == "" && result.DefaultPort > 0 {
		if result.WebPath != "" {
			result.HealthCheckPath = result.WebPath
		} else {
			result.HealthCheckPath = "/"
		}
	}

	return &result
}

// GetAllBlueprints returns the resolved AppBlueprint definitions for all catalog packages.
func GetAllBlueprints() []AppBlueprint {
	pkgs, err := loadPackagesCatalog()
	if err != nil {
		var list []AppBlueprint
		seen := make(map[string]bool)
		for _, bp := range blueprintRegistry {
			if seen[bp.AppName] {
				continue
			}
			seen[bp.AppName] = true
			if resolved := GetBlueprint(bp.AppName); resolved != nil {
				list = append(list, *resolved)
			}
		}
		return list
	}

	list := make([]AppBlueprint, 0, len(pkgs))
	for _, pkg := range pkgs {
		if bp := GetBlueprint(pkg.Name); bp != nil {
			list = append(list, *bp)
		}
	}
	return list
}
