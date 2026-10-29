package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

		settingsPayload := `{"aiModel":"gemini-3.8-flash","language":"en","timezone":"UTC","updateChannel":"stable","defaultDashboard":"overview","setupCompleted":true,"baseDomain":"domain.com"}`
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
}
