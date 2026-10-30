package services

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfigFile(t *testing.T, root, relPath, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatalf("mkdir %s: %v", full, err)
	}
	if err := os.WriteFile(full, []byte(content), 0600); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

func TestGetAppRuntimeMeta_XMLAndINIConfigs(t *testing.T) {
	tmpRoot := t.TempDir()
	t.Setenv("AETHERFLOW_CONFIG_ROOT", tmpRoot)
	ClearAppRuntimeMetaCache()
	t.Cleanup(ClearAppRuntimeMetaCache)

	// 1. Sonarr XML
	writeTestConfigFile(t, tmpRoot, "/var/lib/sonarr/config.xml", `<Config>
  <BindAddress>*</BindAddress>
  <Port>8989</Port>
  <ApiKey>sonarr-secret-api-key-1234567890</ApiKey>
  <AuthenticationMethod>Forms</AuthenticationMethod>
</Config>`)

	sonarrMeta := GetAppRuntimeMeta("sonarr")
	if sonarrMeta.APIKey != "sonarr-secret-api-key-1234567890" {
		t.Fatalf("expected sonarr API key, got %q", sonarrMeta.APIKey)
	}
	if sonarrMeta.ConfiguredPort != 8989 {
		t.Fatalf("expected sonarr port 8989, got %d", sonarrMeta.ConfiguredPort)
	}

	// 2. SABnzbd INI
	writeTestConfigFile(t, tmpRoot, "/var/lib/sabnzbd/sabnzbd.ini", `[misc]
port = 8085
api_key = sabnzbd-key-abcdef123456
nzb_key = sabnzbd-nzb-key
`)
	sabMeta := GetAppRuntimeMeta("sabnzbd")
	if sabMeta.APIKey != "sabnzbd-key-abcdef123456" {
		t.Fatalf("expected sabnzbd API key, got %q", sabMeta.APIKey)
	}
	if sabMeta.ConfiguredPort != 8085 {
		t.Fatalf("expected sabnzbd port 8085, got %d", sabMeta.ConfiguredPort)
	}

	// 3. Bazarr YAML
	writeTestConfigFile(t, tmpRoot, "/var/lib/bazarr/config/config.yaml", `general:
  ip: 127.0.0.1
  port: 6767
auth:
  apikey: bazarr-yaml-api-key-999
  type: form
`)
	bazarrMeta := GetAppRuntimeMeta("bazarr")
	if bazarrMeta.APIKey != "bazarr-yaml-api-key-999" {
		t.Fatalf("expected bazarr API key, got %q", bazarrMeta.APIKey)
	}
	if bazarrMeta.ConfiguredPort != 6767 {
		t.Fatalf("expected bazarr port 6767, got %d", bazarrMeta.ConfiguredPort)
	}

	// 4. Tautulli INI
	writeTestConfigFile(t, tmpRoot, "/var/lib/tautulli/config.ini", `[General]
http_port = 8181
api_key = tautulli-secret-key-42
`)
	tautulliMeta := GetAppRuntimeMeta("tautulli")
	if tautulliMeta.APIKey != "tautulli-secret-key-42" {
		t.Fatalf("expected tautulli API key, got %q", tautulliMeta.APIKey)
	}
	if tautulliMeta.ConfiguredPort != 8181 {
		t.Fatalf("expected tautulli port 8181, got %d", tautulliMeta.ConfiguredPort)
	}
}

func TestGetAppRuntimeMeta_JSONAndSpecialConfigs(t *testing.T) {
	tmpRoot := t.TempDir()
	t.Setenv("AETHERFLOW_CONFIG_ROOT", tmpRoot)
	ClearAppRuntimeMetaCache()
	t.Cleanup(ClearAppRuntimeMetaCache)

	// 1. Jackett JSON
	writeTestConfigFile(t, tmpRoot, "/var/lib/jackett/Jackett/ServerConfig.json", `{
  "Port": 9117,
  "APIKey": "jackett-api-key-xyz987"
}`)
	jackettMeta := GetAppRuntimeMeta("jackett")
	if jackettMeta.APIKey != "jackett-api-key-xyz987" {
		t.Fatalf("expected jackett API key, got %q", jackettMeta.APIKey)
	}
	if jackettMeta.ConfiguredPort != 9117 {
		t.Fatalf("expected jackett port 9117, got %d", jackettMeta.ConfiguredPort)
	}

	// 2. Overseerr nested JSON
	writeTestConfigFile(t, tmpRoot, "/var/lib/overseerr/config/settings.json", `{
  "main": {
    "apiKey": "overseerr-main-api-key-777",
    "port": 5056
  }
}`)
	overseerrMeta := GetAppRuntimeMeta("overseerr")
	if overseerrMeta.APIKey != "overseerr-main-api-key-777" {
		t.Fatalf("expected overseerr API key, got %q", overseerrMeta.APIKey)
	}
	if overseerrMeta.ConfiguredPort != 5056 {
		t.Fatalf("expected overseerr port 5056, got %d", overseerrMeta.ConfiguredPort)
	}

	// 3. Syncthing XML
	writeTestConfigFile(t, tmpRoot, "/var/lib/syncthing/config.xml", `<configuration version="37">
  <gui enabled="true" tls="false">
    <address>127.0.0.1:8384</address>
    <apikey>syncthing-gui-key-321</apikey>
  </gui>
</configuration>`)
	stMeta := GetAppRuntimeMeta("syncthing")
	if stMeta.APIKey != "syncthing-gui-key-321" {
		t.Fatalf("expected syncthing API key, got %q", stMeta.APIKey)
	}
	if stMeta.ConfiguredPort != 8384 {
		t.Fatalf("expected syncthing port 8384, got %d", stMeta.ConfiguredPort)
	}

	// 4. Plex Preferences.xml
	writeTestConfigFile(t, tmpRoot, "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml",
		`<Preferences OldestPreviousVersion="1.40.0" PlexOnlineToken="plex-online-token-abc" />`)
	plexMeta := GetAppRuntimeMeta("plex")
	if plexMeta.APIKey != "plex-online-token-abc" {
		t.Fatalf("expected plex token, got %q", plexMeta.APIKey)
	}

	// 5. Vaultwarden token & env
	writeTestConfigFile(t, tmpRoot, "/opt/AetherFlow/logs/vaultwarden_admin_token.txt", "vw-plaintext-token-555\n")
	writeTestConfigFile(t, tmpRoot, "/etc/vaultwarden/vaultwarden.env", "ROCKET_PORT=8343\n")
	vwMeta := GetAppRuntimeMeta("vaultwarden")
	if vwMeta.APIKey != "vw-plaintext-token-555" {
		t.Fatalf("expected vaultwarden token, got %q", vwMeta.APIKey)
	}
	if vwMeta.ConfiguredPort != 8343 {
		t.Fatalf("expected vaultwarden port 8343, got %d", vwMeta.ConfiguredPort)
	}

	// 6. Organizr PHP
	writeTestConfigFile(t, tmpRoot, "/var/www/organizr/api/config/config.php", `<?php
return array(
	'organizrAPI' => 'org-api-token-888',
);`)
	orgMeta := GetAppRuntimeMeta("organizr")
	if orgMeta.APIKey != "org-api-token-888" {
		t.Fatalf("expected organizr API key, got %q", orgMeta.APIKey)
	}
}

func TestGetAppRuntimeMeta_SQLiteDatabases(t *testing.T) {
	tmpRoot := t.TempDir()
	t.Setenv("AETHERFLOW_CONFIG_ROOT", tmpRoot)
	ClearAppRuntimeMetaCache()
	t.Cleanup(ClearAppRuntimeMetaCache)

	// Create Autobrr SQLite DB
	autobrrDBPath := filepath.Join(tmpRoot, "var", "lib", "autobrr", "autobrr.db")
	if err := os.MkdirAll(filepath.Dir(autobrrDBPath), 0755); err != nil {
		t.Fatalf("mkdir autobrr db dir: %v", err)
	}
	conn, err := sql.Open("sqlite", autobrrDBPath)
	if err != nil {
		t.Fatalf("open autobrr sqlite: %v", err)
	}
	if _, err := conn.Exec(`CREATE TABLE api_key (name TEXT, key TEXT); INSERT INTO api_key VALUES ('default', 'autobrr-sqlite-key-111');`); err != nil {
		conn.Close()
		t.Fatalf("seed autobrr sqlite: %v", err)
	}
	conn.Close()

	writeTestConfigFile(t, tmpRoot, "/var/lib/autobrr/config.toml", `host = "127.0.0.1"
port = 7474
`)

	abMeta := GetAppRuntimeMeta("autobrr")
	if abMeta.APIKey != "autobrr-sqlite-key-111" {
		t.Fatalf("expected autobrr sqlite key, got %q", abMeta.APIKey)
	}
	if abMeta.ConfiguredPort != 7474 {
		t.Fatalf("expected autobrr port 7474, got %d", abMeta.ConfiguredPort)
	}
}

func TestRunnerMux_AppMetaEndpoint(t *testing.T) {
	tmpRoot := t.TempDir()
	t.Setenv("AETHERFLOW_CONFIG_ROOT", tmpRoot)
	ClearAppRuntimeMetaCache()
	t.Cleanup(ClearAppRuntimeMetaCache)

	writeTestConfigFile(t, tmpRoot, "/var/lib/radarr/config.xml", `<Config>
  <Port>7878</Port>
  <ApiKey>radarr-runner-key-007</ApiKey>
</Config>`)

	mux := NewRunnerMux()
	body, _ := json.Marshal(AppMetaRunnerRequest{AppName: "radarr"})
	req := httptest.NewRequest(http.MethodPost, "/v1/app-meta", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /v1/app-meta, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp RunnerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode RunnerResponse: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected success=true, got error=%s", resp.Error)
	}

	var meta AppRuntimeMeta
	if err := json.Unmarshal([]byte(resp.Output), &meta); err != nil {
		t.Fatalf("decode AppRuntimeMeta: %v", err)
	}
	if meta.APIKey != "radarr-runner-key-007" || meta.ConfiguredPort != 7878 {
		t.Fatalf("unexpected runner meta: %+v", meta)
	}
}
