package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"aetherflow/db"
	"aetherflow/models"

	"github.com/gin-gonic/gin"
)

func TestIngressConfigs_PersistenceAndSync(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "ingress_test.sqlite")
	t.Setenv("DB_PATH", dbPath)
	if db.DB != nil {
		_ = db.DB.Close()
	}
	db.InitDB()

	r := gin.New()
	r.GET("/ingress/configs", GetIngressConfigs)
	r.PUT("/ingress/apps/:appName", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "admin")
		UpdateAppIngressConfig(c)
	})

	// 1. Initial Get -> returns empty or valid list
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/ingress/configs", nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 from GET ingress configs, got %d", w.Code)
		}
	}

	// 2. Create/Update App Ingress Config
	{
		payload := `{"publicDomain":"plex.example.com","externalAccessEnabled":true,"listenPort":32400,"tlsEnabled":true}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/ingress/apps/plex", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 from PUT ingress config, got %d: %s", w.Code, w.Body.String())
		}

		// Verify database persistence via db.GetAppIngressConfig
		cfg, err := db.GetAppIngressConfig("plex")
		if err != nil || cfg == nil {
			t.Fatalf("expected config for 'plex' in DB, got error: %v", err)
		}
		if cfg.PublicDomain != "plex.example.com" || !cfg.ExternalAccessEnabled || cfg.ListenPort != 32400 || !cfg.TLSEnabled {
			t.Fatalf("stored config does not match: %+v", cfg)
		}
	}

	// 3. GET should now return the config
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/ingress/configs", nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var res struct {
			Configs []models.AppIngressConfig `json:"configs"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		found := false
		for _, c := range res.Configs {
			if c.AppName == "plex" && c.PublicDomain == "plex.example.com" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected to find 'plex' config in GET /ingress/configs response: %+v", res.Configs)
		}
	}

	// 4. Updating baseDomain in PUT /settings automatically provisions subdomains for existing apps
	{
		r.GET("/settings", GetSettings)
		r.PUT("/settings", updateSettings)

		// Seed an installed app ingress config without a public domain yet
		_ = db.SetAppIngressConfig(models.AppIngressConfig{
			AppName:    "jellyfin",
			ListenPort: 8096,
		})

		settingsPayload := `{"aiModel":"gemini-4-argon","language":"en","timezone":"UTC","updateChannel":"stable","defaultDashboard":"overview","setupCompleted":true,"baseDomain":"domain.com"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/settings", bytes.NewBufferString(settingsPayload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 from PUT /settings, got %d: %s", w.Code, w.Body.String())
		}

		jfCfg, err := db.GetAppIngressConfig("jellyfin")
		if err != nil || jfCfg == nil {
			t.Fatalf("expected jellyfin ingress config after baseDomain sync, got: %v", err)
		}
		if jfCfg.PublicDomain != "jellyfin.domain.com" || !jfCfg.ExternalAccessEnabled || !jfCfg.TLSEnabled {
			t.Fatalf("expected jellyfin.domain.com to be auto-provisioned, got: %+v", jfCfg)
		}
	}

	// 5. Subdomain Reverse Proxy routes <app>.<baseDomain> and /api/v2/* to the app's loopback port
	{
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("X-Upstream-App", "qbittorrent")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("qBittorrent WebUI:" + req.URL.Path))
		}))
		defer upstream.Close()

		u, err := url.Parse(upstream.URL)
		if err != nil {
			t.Fatalf("failed to parse upstream URL: %v", err)
		}
		parts := strings.Split(u.Host, ":")
		upstreamPort, _ := strconv.Atoi(parts[len(parts)-1])

		_ = db.SetAppIngressConfig(models.AppIngressConfig{
			AppName:               "qbittorrent",
			PublicDomain:          "qbittorrent.domain.com",
			ExternalAccessEnabled: true,
			ListenPort:            upstreamPort,
			TLSEnabled:            true,
		})

		gw := gin.New()
		gw.Use(AppSubdomainProxyMiddleware())
		gw.GET("/", func(c *gin.Context) {
			c.String(http.StatusOK, "AetherFlow Dashboard")
		})
		gw.POST("/api/v2/auth/login", func(c *gin.Context) {
			c.String(http.StatusNotFound, "AetherFlow API 404")
		})

		// Request to qbittorrent.domain.com/ should be proxied to upstream
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest("GET", "http://qbittorrent.domain.com/", nil)
		req1.Host = "qbittorrent.domain.com"
		gw.ServeHTTP(w1, req1)
		if w1.Code != http.StatusOK || w1.Body.String() != "qBittorrent WebUI:/" {
			t.Fatalf("expected proxied qBittorrent root, got %d: %s", w1.Code, w1.Body.String())
		}

		// Request to qbittorrent.domain.com/api/v2/auth/login should also be proxied to upstream
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("POST", "http://qbittorrent.domain.com/api/v2/auth/login", nil)
		req2.Host = "qbittorrent.domain.com"
		gw.ServeHTTP(w2, req2)
		if w2.Code != http.StatusOK || w2.Body.String() != "qBittorrent WebUI:/api/v2/auth/login" {
			t.Fatalf("expected proxied qBittorrent /api/v2/auth/login, got %d: %s", w2.Code, w2.Body.String())
		}

		// Request to base domain (domain.com) should serve AetherFlow Dashboard
		w3 := httptest.NewRecorder()
		req3, _ := http.NewRequest("GET", "http://domain.com/", nil)
		req3.Host = "domain.com"
		gw.ServeHTTP(w3, req3)
		if w3.Code != http.StatusOK || w3.Body.String() != "AetherFlow Dashboard" {
			t.Fatalf("expected AetherFlow Dashboard on base domain, got %d: %s", w3.Code, w3.Body.String())
		}

		// S-03 Regression: External client spoofing Host: qbittorrent.aether.local via X-Forwarded-For or public RemoteAddr is blocked (403)
		w4 := httptest.NewRecorder()
		req4, _ := http.NewRequest("GET", "http://qbittorrent.aether.local/", nil)
		req4.Host = "qbittorrent.aether.local"
		req4.RemoteAddr = "127.0.0.1:45678"
		req4.Header.Set("X-Forwarded-For", "198.51.100.42")
		gw.ServeHTTP(w4, req4)
		if w4.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for external client spoofing .aether.local, got %d: %s", w4.Code, w4.Body.String())
		}

		// Local LAN client requesting Host: qbittorrent.aether.local is allowed
		w5 := httptest.NewRecorder()
		req5, _ := http.NewRequest("GET", "http://qbittorrent.aether.local/", nil)
		req5.Host = "qbittorrent.aether.local"
		req5.RemoteAddr = "192.168.1.25:45678"
		gw.ServeHTTP(w5, req5)
		if w5.Code != http.StatusOK || w5.Body.String() != "qBittorrent WebUI:/" {
			t.Fatalf("expected 200 OK for LAN client accessing .aether.local, got %d: %s", w5.Code, w5.Body.String())
		}
	}
}
