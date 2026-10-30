package services

import (
	"aetherflow/db"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AppRuntimeMeta holds runtime configuration metadata discovered from an installed
// application's native configuration files or database.
type AppRuntimeMeta struct {
	APIKey         string `json:"api_key,omitempty"`
	ConfiguredPort int    `json:"configured_port,omitempty"`
}

// AppMetaRunnerRequest represents a privileged metadata lookup request sent to the root runner.
type AppMetaRunnerRequest struct {
	AppName string `json:"app_name"`
}

type cachedAppMeta struct {
	meta      AppRuntimeMeta
	expiresAt time.Time
}

const appMetaCacheTTL = 15 * time.Second

var (
	appMetaCacheMu sync.RWMutex
	appMetaCache   = make(map[string]cachedAppMeta)

	xmlTagValueRegexCache sync.Map
	plexTokenAttrRegex    = regexp.MustCompile(`(?i)\bPlexOnlineToken\s*=\s*"([^"]+)"`)
	phpOrganizrKeyRegex   = regexp.MustCompile(`(?i)['"]organizrAPI['"]\s*=>\s*['"]([^'"]+)['"]`)
)

// ClearAppRuntimeMetaCache flushes the in-memory runtime metadata cache.
func ClearAppRuntimeMetaCache() {
	appMetaCacheMu.Lock()
	appMetaCache = make(map[string]cachedAppMeta)
	appMetaCacheMu.Unlock()
}

// GetAppRuntimeMeta returns the discovered API key and configured port for an application.
// Results are cached in memory for a short TTL so frequent service polls remain fast.
func GetAppRuntimeMeta(appName string) AppRuntimeMeta {
	canonical := normalizeAppKeyName(appName)
	if canonical == "" {
		return AppRuntimeMeta{}
	}

	now := time.Now()
	appMetaCacheMu.RLock()
	if entry, ok := appMetaCache[canonical]; ok && now.Before(entry.expiresAt) {
		appMetaCacheMu.RUnlock()
		return entry.meta
	}
	appMetaCacheMu.RUnlock()

	meta := extractAppRuntimeMetaLocal(canonical)
	if (meta.APIKey == "" || meta.ConfiguredPort <= 0) && IsRunnerAvailable() && os.Geteuid() != 0 {
		if runnerMeta, err := DispatchAppMeta(canonical); err == nil && runnerMeta != nil {
			if meta.APIKey == "" && runnerMeta.APIKey != "" {
				meta.APIKey = runnerMeta.APIKey
			}
			if meta.ConfiguredPort <= 0 && runnerMeta.ConfiguredPort > 0 {
				meta.ConfiguredPort = runnerMeta.ConfiguredPort
			}
		}
	}

	appMetaCacheMu.Lock()
	appMetaCache[canonical] = cachedAppMeta{
		meta:      meta,
		expiresAt: now.Add(appMetaCacheTTL),
	}
	appMetaCacheMu.Unlock()

	return meta
}

// DispatchAppMeta queries the root UNIX socket for application metadata when config files
// are owned by a service user and unreadable by the unprivileged aetherflow-api user.
func DispatchAppMeta(appName string) (*AppRuntimeMeta, error) {
	payload, _ := json.Marshal(AppMetaRunnerRequest{
		AppName: appName,
	})
	client := newRunnerHTTPClient(3 * time.Second)
	resp, err := client.Post("http://unix/v1/app-meta", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("runner socket app-meta request failed: %w", err)
	}
	defer resp.Body.Close()

	var result RunnerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode runner app-meta response: %w", err)
	}
	if !result.Success {
		return nil, fmt.Errorf("runner app-meta error: %s", result.Error)
	}
	var meta AppRuntimeMeta
	if result.Output != "" {
		if err := json.Unmarshal([]byte(result.Output), &meta); err != nil {
			return nil, fmt.Errorf("unmarshal runner app-meta output: %w", err)
		}
	}
	return &meta, nil
}

func normalizeAppKeyName(appName string) string {
	clean := strings.ToLower(strings.TrimSpace(appName))
	clean = strings.TrimSuffix(clean, ".service")
	switch clean {
	case "plexmediaserver":
		return "plex"
	case "emby-server":
		return "emby"
	case "pihole-ftl":
		return "pihole"
	case "transmission-daemon":
		return "transmission"
	case "deluged", "deluge-web":
		return "deluge"
	case "paperless-webserver", "paperless":
		return "paperless-ngx"
	default:
		return clean
	}
}

func extractAppRuntimeMetaLocal(appName string) AppRuntimeMeta {
	canonical := normalizeAppKeyName(appName)
	var meta AppRuntimeMeta

	switch canonical {
	case "sonarr", "radarr", "lidarr", "readarr", "prowlarr", "listenarr":
		candidates := []string{
			fmt.Sprintf("/var/lib/%s/config.xml", canonical),
			fmt.Sprintf("/var/lib/%s/config/config.xml", canonical),
		}
		if bp := GetBlueprint(canonical); bp != nil && bp.ConfigFilePath != "" {
			candidates = append([]string{bp.ConfigFilePath}, candidates...)
		}
		for _, rawPath := range candidates {
			content, ok := readConfigText(rawPath)
			if !ok {
				continue
			}
			if meta.APIKey == "" {
				meta.APIKey = extractXMLTagText(content, "ApiKey")
			}
			if meta.ConfiguredPort <= 0 {
				meta.ConfiguredPort = parseValidPort(extractXMLTagText(content, "Port"))
			}
			if meta.APIKey != "" && meta.ConfiguredPort > 0 {
				break
			}
		}

	case "bazarr":
		yamlPaths := []string{
			"/var/lib/bazarr/config/config.yaml",
			"/var/lib/bazarr/config.yaml",
			"/opt/bazarr/data/config/config.yaml",
		}
		for _, rawPath := range yamlPaths {
			content, ok := readConfigText(rawPath)
			if !ok {
				continue
			}
			if meta.APIKey == "" {
				meta.APIKey = extractYAMLKeyInSection(content, "auth", "apikey")
				if meta.APIKey == "" {
					meta.APIKey = extractYAMLKeyInSection(content, "", "apikey")
				}
			}
			if meta.ConfiguredPort <= 0 {
				meta.ConfiguredPort = parseValidPort(extractYAMLKeyInSection(content, "general", "port"))
			}
		}
		iniPaths := []string{
			"/var/lib/bazarr/config/config.ini",
			"/var/lib/bazarr/config.ini",
			"/opt/bazarr/data/config/config.ini",
		}
		for _, rawPath := range iniPaths {
			content, ok := readConfigText(rawPath)
			if !ok {
				continue
			}
			if meta.APIKey == "" {
				meta.APIKey = extractINIValue(content, "apikey", "api_key")
			}
			if meta.ConfiguredPort <= 0 {
				meta.ConfiguredPort = parseValidPort(extractINIValue(content, "port"))
			}
		}

	case "sabnzbd":
		candidates := []string{
			"/var/lib/sabnzbd/sabnzbd.ini",
			"/var/lib/sabnzbd/.sabnzbd/sabnzbd.ini",
			"/etc/sabnzbd/sabnzbd.ini",
		}
		for _, rawPath := range candidates {
			content, ok := readConfigText(rawPath)
			if !ok {
				continue
			}
			if meta.APIKey == "" {
				meta.APIKey = extractINIValue(content, "api_key", "nzb_key")
			}
			if meta.ConfiguredPort <= 0 {
				meta.ConfiguredPort = parseValidPort(extractINIValue(content, "port"))
			}
		}

	case "tautulli":
		candidates := []string{
			"/var/lib/tautulli/config.ini",
			"/opt/Tautulli/config.ini",
			"/etc/tautulli/config.ini",
		}
		for _, rawPath := range candidates {
			content, ok := readConfigText(rawPath)
			if !ok {
				continue
			}
			if meta.APIKey == "" {
				meta.APIKey = extractINIValue(content, "api_key")
			}
			if meta.ConfiguredPort <= 0 {
				meta.ConfiguredPort = parseValidPort(extractINIValue(content, "http_port", "port"))
			}
		}

	case "jackett":
		candidates := []string{
			"/var/lib/jackett/Jackett/ServerConfig.json",
			"/var/lib/jackett/ServerConfig.json",
			"/var/lib/jackett/.config/Jackett/ServerConfig.json",
		}
		for _, rawPath := range candidates {
			content, ok := readConfigText(rawPath)
			if !ok {
				continue
			}
			key, port := extractJSONKeyAndPort(content)
			if meta.APIKey == "" && key != "" {
				meta.APIKey = key
			}
			if meta.ConfiguredPort <= 0 && port > 0 {
				meta.ConfiguredPort = port
			}
		}

	case "overseerr", "jellyseerr":
		candidates := []string{
			fmt.Sprintf("/var/lib/%s/settings.json", canonical),
			fmt.Sprintf("/var/lib/%s/config/settings.json", canonical),
			fmt.Sprintf("/opt/%s/config/settings.json", canonical),
		}
		for _, rawPath := range candidates {
			content, ok := readConfigText(rawPath)
			if !ok {
				continue
			}
			key, port := extractJSONKeyAndPort(content)
			if meta.APIKey == "" && key != "" {
				meta.APIKey = key
			}
			if meta.ConfiguredPort <= 0 && port > 0 {
				meta.ConfiguredPort = port
			}
		}
		envPaths := []string{
			fmt.Sprintf("/etc/%s/%s.conf", canonical, canonical),
			fmt.Sprintf("/etc/default/%s", canonical),
		}
		for _, rawPath := range envPaths {
			if content, ok := readConfigText(rawPath); ok && meta.ConfiguredPort <= 0 {
				meta.ConfiguredPort = parseValidPort(extractINIValue(content, "PORT", "port"))
			}
		}

	case "syncthing":
		candidates := []string{
			"/var/lib/syncthing/config.xml",
			"/var/lib/syncthing/.local/state/syncthing/config.xml",
			"/var/lib/syncthing/.config/syncthing/config.xml",
		}
		for _, rawPath := range candidates {
			content, ok := readConfigText(rawPath)
			if !ok {
				continue
			}
			if meta.APIKey == "" {
				meta.APIKey = extractXMLTagText(content, "apikey")
			}
			if meta.ConfiguredPort <= 0 {
				addr := extractXMLTagText(content, "address")
				if _, portStr, err := net.SplitHostPort(addr); err == nil {
					meta.ConfiguredPort = parseValidPort(portStr)
				}
			}
		}

	case "plex":
		candidates := []string{
			"/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml",
			"/var/lib/plex/Plex Media Server/Preferences.xml",
		}
		for _, rawPath := range candidates {
			content, ok := readConfigText(rawPath)
			if !ok {
				continue
			}
			if m := plexTokenAttrRegex.FindStringSubmatch(content); len(m) == 2 {
				meta.APIKey = strings.TrimSpace(m[1])
				break
			}
		}

	case "jellyfin":
		_, _, storedKey, _ := GetStoredJellyfinConfig()
		if storedKey != "" {
			meta.APIKey = storedKey
		}
		if meta.APIKey == "" {
			dbPaths := []string{
				"/var/lib/jellyfin/data/jellyfin.db",
				"/var/lib/jellyfin/jellyfin.db",
			}
			for _, rawPath := range dbPaths {
				if token := querySQLiteSingleString(rawPath,
					"SELECT AccessToken FROM ApiKeys WHERE AccessToken IS NOT NULL AND AccessToken != '' LIMIT 1",
					"SELECT AccessToken FROM Devices WHERE AccessToken IS NOT NULL AND AccessToken != '' ORDER BY DateLastActivity DESC LIMIT 1",
				); token != "" {
					meta.APIKey = token
					break
				}
			}
		}
		netPaths := []string{
			"/etc/jellyfin/network.xml",
			"/var/lib/jellyfin/config/network.xml",
		}
		for _, rawPath := range netPaths {
			if content, ok := readConfigText(rawPath); ok {
				port := parseValidPort(extractXMLTagText(content, "InternalHttpPort"))
				if port <= 0 {
					port = parseValidPort(extractXMLTagText(content, "HttpServerPortNumber"))
				}
				if port > 0 {
					meta.ConfiguredPort = port
					break
				}
			}
		}

	case "emby":
		if envKey := strings.TrimSpace(os.Getenv("EMBY_API_KEY")); envKey != "" {
			meta.APIKey = envKey
		}
		if meta.APIKey == "" && db.DB != nil {
			var apiKey string
			err := db.DB.QueryRow(`SELECT api_key FROM streaming_servers WHERE provider = 'emby' AND enabled = 1 LIMIT 1`).Scan(&apiKey)
			if err == nil && strings.TrimSpace(apiKey) != "" {
				meta.APIKey = strings.TrimSpace(apiKey)
			}
		}
		if meta.APIKey == "" {
			dbPaths := []string{
				"/var/lib/emby/data/authentication.db",
				"/var/lib/emby/data/users.db",
			}
			for _, rawPath := range dbPaths {
				if token := querySQLiteSingleString(rawPath,
					"SELECT AccessToken FROM Tokens WHERE AccessToken IS NOT NULL AND AccessToken != '' LIMIT 1",
					"SELECT AccessToken FROM ApiKeys WHERE AccessToken IS NOT NULL AND AccessToken != '' LIMIT 1",
				); token != "" {
					meta.APIKey = token
					break
				}
			}
		}
		sysPaths := []string{
			"/var/lib/emby/config/system.xml",
			"/etc/emby/system.xml",
		}
		for _, rawPath := range sysPaths {
			if content, ok := readConfigText(rawPath); ok {
				port := parseValidPort(extractXMLTagText(content, "HttpServerPortNumber"))
				if port <= 0 {
					port = parseValidPort(extractXMLTagText(content, "PublicPort"))
				}
				if port > 0 {
					meta.ConfiguredPort = port
					break
				}
			}
		}

	case "ombi":
		dbPaths := []string{
			"/var/lib/ombi/OmbiSettings.db",
			"/etc/Ombi/OmbiSettings.db",
			"/opt/Ombi/OmbiSettings.db",
		}
		for _, rawPath := range dbPaths {
			rawJSON := querySQLiteSingleString(rawPath,
				"SELECT Content FROM GlobalSettings WHERE SettingsName = 'OmbiSettings' LIMIT 1",
			)
			if rawJSON != "" {
				key, port := extractJSONKeyAndPort(rawJSON)
				if key != "" {
					meta.APIKey = key
				}
				if port > 0 && meta.ConfiguredPort <= 0 {
					meta.ConfiguredPort = port
				}
				if meta.APIKey != "" {
					break
				}
			}
		}

	case "autobrr", "qui":
		tomlPaths := []string{
			fmt.Sprintf("/var/lib/%s/config.toml", canonical),
			fmt.Sprintf("/var/lib/%s/.config/%s/config.toml", canonical, canonical),
		}
		for _, rawPath := range tomlPaths {
			if content, ok := readConfigText(rawPath); ok {
				if meta.ConfiguredPort <= 0 {
					meta.ConfiguredPort = parseValidPort(extractINIValue(content, "port"))
				}
				if meta.APIKey == "" {
					meta.APIKey = extractINIValue(content, "api_key", "apikey")
				}
			}
		}
		dbPaths := []string{
			fmt.Sprintf("/var/lib/%s/%s.db", canonical, canonical),
			fmt.Sprintf("/var/lib/%s/.config/%s/%s.db", canonical, canonical, canonical),
		}
		for _, rawPath := range dbPaths {
			if key := querySQLiteSingleString(rawPath,
				"SELECT key FROM api_key WHERE key IS NOT NULL AND key != '' LIMIT 1",
			); key != "" {
				meta.APIKey = key
				break
			}
		}

	case "kavita":
		jsonPaths := []string{
			"/var/lib/kavita/config/appsettings.json",
			"/opt/Kavita/config/appsettings.json",
		}
		for _, rawPath := range jsonPaths {
			if content, ok := readConfigText(rawPath); ok {
				_, port := extractJSONKeyAndPort(content)
				if port > 0 {
					meta.ConfiguredPort = port
					break
				}
			}
		}
		dbPaths := []string{
			"/var/lib/kavita/config/kavita.db",
			"/opt/Kavita/config/kavita.db",
		}
		for _, rawPath := range dbPaths {
			if key := querySQLiteSingleString(rawPath,
				"SELECT ApiKey FROM AspNetUsers WHERE ApiKey IS NOT NULL AND ApiKey != '' LIMIT 1",
			); key != "" {
				meta.APIKey = key
				break
			}
		}

	case "audiobookshelf":
		envPaths := []string{
			"/etc/default/audiobookshelf",
			"/var/lib/audiobookshelf/config/.env",
		}
		for _, rawPath := range envPaths {
			if content, ok := readConfigText(rawPath); ok && meta.ConfiguredPort <= 0 {
				meta.ConfiguredPort = parseValidPort(extractINIValue(content, "PORT", "port"))
			}
		}
		dbPaths := []string{
			"/var/lib/audiobookshelf/config/absdatabase.sqlite",
			"/var/lib/audiobookshelf/absdatabase.sqlite",
		}
		for _, rawPath := range dbPaths {
			if key := querySQLiteSingleString(rawPath,
				"SELECT apiKey FROM apiKeys WHERE apiKey IS NOT NULL AND apiKey != '' LIMIT 1",
				"SELECT token FROM users WHERE token IS NOT NULL AND token != '' LIMIT 1",
			); key != "" {
				meta.APIKey = key
				break
			}
		}

	case "notifiarr":
		candidates := []string{
			"/etc/notifiarr/notifiarr.conf",
			"/var/lib/notifiarr/notifiarr.conf",
		}
		for _, rawPath := range candidates {
			content, ok := readConfigText(rawPath)
			if !ok {
				continue
			}
			key := extractINIValue(content, "api_key")
			if key != "" && key != "00000000-0000-0000-0000-000000000000" && !strings.EqualFold(key, "api-key-from-notifiarr.com") {
				meta.APIKey = key
			}
			bindAddr := extractINIValue(content, "bind_addr")
			if bindAddr != "" {
				if _, portStr, err := net.SplitHostPort(bindAddr); err == nil {
					meta.ConfiguredPort = parseValidPort(portStr)
				} else {
					meta.ConfiguredPort = parseValidPort(bindAddr)
				}
			}
		}

	case "vaultwarden":
		tokenPaths := []string{
			"/opt/AetherFlow/logs/vaultwarden_admin_token.txt",
			"/etc/vaultwarden/admin_token.txt",
		}
		for _, rawPath := range tokenPaths {
			if content, ok := readConfigText(rawPath); ok {
				firstLine := strings.TrimSpace(strings.Split(content, "\n")[0])
				if firstLine != "" {
					meta.APIKey = firstLine
					break
				}
			}
		}
		envPaths := []string{
			"/etc/vaultwarden/vaultwarden.env",
			"/var/lib/vaultwarden/.env",
		}
		for _, rawPath := range envPaths {
			content, ok := readConfigText(rawPath)
			if !ok {
				continue
			}
			if meta.APIKey == "" {
				token := extractINIValue(content, "ADMIN_TOKEN")
				if token != "" {
					meta.APIKey = token
				}
			}
			if meta.ConfiguredPort <= 0 {
				meta.ConfiguredPort = parseValidPort(extractINIValue(content, "ROCKET_PORT", "PORT"))
			}
		}

	case "organizr":
		phpPaths := []string{
			"/var/www/organizr/api/config/config.php",
			"/var/lib/organizr/www/api/config/config.php",
		}
		for _, rawPath := range phpPaths {
			content, ok := readConfigText(rawPath)
			if !ok {
				continue
			}
			if m := phpOrganizrKeyRegex.FindStringSubmatch(content); len(m) == 2 {
				meta.APIKey = strings.TrimSpace(m[1])
				break
			}
		}

	case "pihole":
		if content, ok := readConfigText("/etc/pihole/setupVars.conf"); ok {
			meta.APIKey = extractINIValue(content, "WEBPASSWORD")
		}
		if content, ok := readConfigText("/etc/pihole/pihole.toml"); ok {
			portVal := extractINIValue(content, "port")
			if portVal != "" {
				meta.ConfiguredPort = parsePiHolePort(portVal)
			}
		}

	case "paperless-ngx":
		confPaths := []string{
			"/etc/paperless.conf",
			"/opt/paperless/paperless.conf",
			"/var/lib/paperless/paperless.conf",
		}
		for _, rawPath := range confPaths {
			if content, ok := readConfigText(rawPath); ok && meta.ConfiguredPort <= 0 {
				meta.ConfiguredPort = parseValidPort(extractINIValue(content, "PAPERLESS_PORT", "PORT"))
			}
		}
		dbPaths := []string{
			"/var/lib/paperless/db.sqlite3",
			"/opt/paperless/data/db.sqlite3",
		}
		for _, rawPath := range dbPaths {
			if key := querySQLiteSingleString(rawPath,
				"SELECT key FROM authtoken_token WHERE key IS NOT NULL AND key != '' LIMIT 1",
			); key != "" {
				meta.APIKey = key
				break
			}
		}

	case "requestrr":
		candidates := []string{
			"/var/lib/requestrr/settings.json",
			"/opt/requestrr/Settings/settings.json",
		}
		for _, rawPath := range candidates {
			if content, ok := readConfigText(rawPath); ok {
				key, port := extractJSONKeyAndPort(content)
				if meta.APIKey == "" && key != "" {
					meta.APIKey = key
				}
				if meta.ConfiguredPort <= 0 && port > 0 {
					meta.ConfiguredPort = port
				}
			}
		}

	case "seedcross":
		candidates := []string{
			"/var/lib/seedcross/.env",
			"/opt/seedcross/.env",
			"/etc/seedcross/seedcross.env",
		}
		for _, rawPath := range candidates {
			if content, ok := readConfigText(rawPath); ok {
				if meta.APIKey == "" {
					meta.APIKey = extractINIValue(content, "API_KEY", "SEEDCROSS_API_KEY", "AUTH_TOKEN")
				}
				if meta.ConfiguredPort <= 0 {
					meta.ConfiguredPort = parseValidPort(extractINIValue(content, "PORT", "SEEDCROSS_PORT"))
				}
			}
		}

	case "qbittorrent":
		candidates := []string{
			"/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
			"/var/lib/qbittorrent/.config/qBittorrent/config/qBittorrent.conf",
		}
		for _, rawPath := range candidates {
			if content, ok := readConfigText(rawPath); ok {
				if port := parseValidPort(extractINIValue(content, `WebUI\Port`, "Port")); port > 0 {
					meta.ConfiguredPort = port
					break
				}
			}
		}

	case "deluge":
		if content, ok := readConfigText("/var/lib/deluge/.config/deluge/web.conf"); ok {
			_, port := extractJSONKeyAndPort(content)
			if port > 0 {
				meta.ConfiguredPort = port
			}
		}

	case "transmission":
		candidates := []string{
			"/etc/transmission-daemon/settings.json",
			"/var/lib/transmission-daemon/info/settings.json",
		}
		for _, rawPath := range candidates {
			if content, ok := readConfigText(rawPath); ok {
				_, port := extractJSONKeyAndPort(content)
				if port > 0 {
					meta.ConfiguredPort = port
					break
				}
			}
		}

	case "nzbget":
		candidates := []string{
			"/var/lib/nzbget/nzbget.conf",
			"/etc/nzbget.conf",
			"/opt/nzbget/nzbget.conf",
		}
		for _, rawPath := range candidates {
			if content, ok := readConfigText(rawPath); ok {
				if port := parseValidPort(extractINIValue(content, "ControlPort")); port > 0 {
					meta.ConfiguredPort = port
					break
				}
			}
		}

	case "gitea":
		candidates := []string{
			"/etc/gitea/app.ini",
			"/var/lib/gitea/custom/conf/app.ini",
		}
		for _, rawPath := range candidates {
			if content, ok := readConfigText(rawPath); ok {
				if port := parseValidPort(extractINIValue(content, "HTTP_PORT")); port > 0 {
					meta.ConfiguredPort = port
					break
				}
			}
		}
	}

	// Generic Blueprint fallback for configured port if still 0
	if meta.ConfiguredPort <= 0 {
		if bp := GetBlueprint(canonical); bp != nil && bp.ConfigFilePath != "" && bp.PortConfigKey != "" {
			if content, ok := readConfigText(bp.ConfigFilePath); ok {
				switch bp.MutatorType {
				case "xml":
					meta.ConfiguredPort = parseValidPort(extractXMLTagText(content, bp.PortConfigKey))
				case "ini":
					meta.ConfiguredPort = parseValidPort(extractINIValue(content, bp.PortConfigKey))
				case "pihole":
					meta.ConfiguredPort = parsePiHolePort(extractINIValue(content, bp.PortConfigKey))
				}
			}
		}
	}

	return meta
}

func parsePiHolePort(raw string) int {
	for _, part := range strings.Split(raw, ",") {
		tok := strings.TrimSpace(strings.Trim(part, `"'`))
		tok = strings.TrimRight(tok, "oOsS")
		if p := parseValidPort(tok); p > 0 {
			return p
		}
	}
	return 0
}

func readConfigText(rawPath string) (string, bool) {
	resolved := resolveFilesystemPath(rawPath)
	if resolved == "" {
		return "", false
	}
	info, err := os.Stat(resolved)
	if err != nil || info.IsDir() || info.Size() <= 0 || info.Size() > 2*1024*1024 {
		return "", false
	}
	data, err := os.ReadFile(resolved) // #nosec G304 -- resolved from static application config paths
	if err != nil {
		return "", false
	}
	return string(data), true
}

func extractXMLTagText(content, tag string) string {
	if content == "" || tag == "" {
		return ""
	}
	var re *regexp.Regexp
	if cached, ok := xmlTagValueRegexCache.Load(tag); ok {
		re = cached.(*regexp.Regexp)
	} else {
		pattern := fmt.Sprintf(`(?is)<%s>\s*([^<]*?)\s*</%s>`, regexp.QuoteMeta(tag), regexp.QuoteMeta(tag))
		re = regexp.MustCompile(pattern)
		xmlTagValueRegexCache.Store(tag, re)
	}
	if m := re.FindStringSubmatch(content); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func extractINIValue(content string, keys ...string) string {
	if content == "" || len(keys) == 0 {
		return ""
	}
	lines := strings.Split(content, "\n")
	for _, wantKey := range keys {
		wantLower := strings.ToLower(strings.TrimSpace(wantKey))
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "[") {
				continue
			}
			trimmed = strings.TrimPrefix(trimmed, "export ")
			idx := strings.IndexAny(trimmed, "=:")
			if idx <= 0 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(trimmed[:idx]))
			if k != wantLower {
				continue
			}
			val := strings.TrimSpace(trimmed[idx+1:])
			// Strip inline comments when unquoted
			if !strings.HasPrefix(val, `"`) && !strings.HasPrefix(val, `'`) {
				if hashIdx := strings.Index(val, " #"); hashIdx >= 0 {
					val = strings.TrimSpace(val[:hashIdx])
				}
			}
			val = strings.Trim(val, `"'`)
			if val != "" {
				return val
			}
		}
	}
	return ""
}

func extractYAMLKeyInSection(content, section, key string) string {
	if content == "" || key == "" {
		return ""
	}
	wantSection := strings.ToLower(strings.TrimSpace(section))
	wantKey := strings.ToLower(strings.TrimSpace(key))
	inSection := wantSection == ""

	lines := strings.Split(content, "\n")
	for _, rawLine := range lines {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		isIndented := len(rawLine) > 0 && (rawLine[0] == ' ' || rawLine[0] == '\t')
		if !isIndented && strings.HasSuffix(trimmed, ":") {
			secName := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(trimmed, ":")))
			if wantSection != "" {
				inSection = (secName == wantSection)
			}
			continue
		}
		if !inSection {
			continue
		}
		idx := strings.Index(trimmed, ":")
		if idx <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(trimmed[:idx]))
		if k != wantKey {
			continue
		}
		val := strings.TrimSpace(trimmed[idx+1:])
		if !strings.HasPrefix(val, `"`) && !strings.HasPrefix(val, `'`) {
			if hashIdx := strings.Index(val, " #"); hashIdx >= 0 {
				val = strings.TrimSpace(val[:hashIdx])
			}
		}
		val = strings.Trim(val, `"'`)
		if val != "" && val != "null" && val != "~" {
			return val
		}
	}
	return ""
}

func extractJSONKeyAndPort(content string) (string, int) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		// Deluge web.conf has two concatenated JSON objects; parse the second or use regex fallback
		dec := json.NewDecoder(strings.NewReader(content))
		var first map[string]interface{}
		if err1 := dec.Decode(&first); err1 == nil {
			var second map[string]interface{}
			if err2 := dec.Decode(&second); err2 == nil {
				raw = second
			} else {
				raw = first
			}
		}
	}
	if raw == nil {
		return "", 0
	}

	var apiKey string
	for _, k := range []string{"APIKey", "ApiKey", "apiKey", "api_key", "apikey", "token"} {
		if v, ok := raw[k].(string); ok && strings.TrimSpace(v) != "" {
			apiKey = strings.TrimSpace(v)
			break
		}
	}

	var port int
	for _, k := range []string{"Port", "port", "rpc-port", "http_port"} {
		if p := interfaceToPort(raw[k]); p > 0 {
			port = p
			break
		}
	}

	if mainObj, ok := raw["main"].(map[string]interface{}); ok {
		if apiKey == "" {
			for _, k := range []string{"apiKey", "APIKey", "api_key"} {
				if v, ok := mainObj[k].(string); ok && strings.TrimSpace(v) != "" {
					apiKey = strings.TrimSpace(v)
					break
				}
			}
		}
		if port <= 0 {
			for _, k := range []string{"port", "Port"} {
				if p := interfaceToPort(mainObj[k]); p > 0 {
					port = p
					break
				}
			}
		}
	}

	return apiKey, port
}

func interfaceToPort(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return parseValidPort(strconv.Itoa(int(val)))
	case int:
		return parseValidPort(strconv.Itoa(val))
	case string:
		return parseValidPort(val)
	default:
		return 0
	}
}

func parseValidPort(raw string) int {
	clean := strings.TrimSpace(strings.Trim(raw, `"'`))
	if clean == "" {
		return 0
	}
	p, err := strconv.Atoi(clean)
	if err != nil || p <= 0 || p > 65535 {
		return 0
	}
	return p
}

func querySQLiteSingleString(rawPath string, queries ...string) string {
	resolved := resolveFilesystemPath(rawPath)
	if resolved == "" {
		return ""
	}
	info, err := os.Stat(resolved)
	if err != nil || info.IsDir() || info.Size() <= 0 {
		return ""
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_busy_timeout=1000", filepath.ToSlash(resolved))
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return ""
	}
	defer conn.Close()

	for _, q := range queries {
		var val sql.NullString
		if err := conn.QueryRow(q).Scan(&val); err == nil && val.Valid {
			trimmed := strings.TrimSpace(val.String)
			if trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}
