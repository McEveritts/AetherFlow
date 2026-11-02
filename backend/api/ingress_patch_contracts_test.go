package api

import (
	"aetherflow/db"
	"aetherflow/models"
	"bytes"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestIngressPartialUpdatePreservesTLSAndRejectsPortDrift(t *testing.T) {
	root := t.TempDir()
	t.Setenv("DB_PATH", filepath.Join(root, "ingress.sqlite"))
	t.Setenv("AETHERFLOW_CONFIG_ROOT", root)
	t.Setenv("AETHERFLOW_HOSTS_FILE", filepath.Join(root, "hosts"))
	t.Setenv("AETHERFLOW_MASTER_CREDS_FILE", filepath.Join(root, ".master.creds"))
	t.Setenv("AETHERFLOW_RUNNER_SOCK", filepath.Join(root, "absent.sock"))
	if db.DB != nil {
		_ = db.DB.Close()
	}
	db.InitDB()
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
		}
	})
	initial := models.AppIngressConfig{AppName: "radarr", PublicDomain: "radarr.example.com", ExternalAccessEnabled: true, ListenPort: 7878, TLSEnabled: true}
	if err := db.SetAppIngressConfig(initial); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.PUT("/ingress/:appName", UpdateAppIngressConfig)
	request := func(payload string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/ingress/radarr", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, req)
		return response
	}
	if response := request(`{"publicDomain":"movies.example.com"}`); response.Code != http.StatusOK {
		t.Fatalf("partial update failed: %d %s", response.Code, response.Body.String())
	}
	stored, err := db.GetAppIngressConfig("radarr")
	if err != nil || stored == nil || !stored.TLSEnabled || !stored.ExternalAccessEnabled || stored.ListenPort != 7878 || stored.PublicDomain != "movies.example.com" {
		t.Fatalf("partial update lost settings: %+v %v", stored, err)
	}
	if response := request(`{"listenPort":17878}`); response.Code != http.StatusConflict {
		t.Fatalf("unsupported port mutation succeeded: %d %s", response.Code, response.Body.String())
	}
	stored, err = db.GetAppIngressConfig("radarr")
	if err != nil || stored.ListenPort != 7878 {
		t.Fatalf("failed mutation changed persisted port: %+v %v", stored, err)
	}
	if response := request(`{"externalAccessEnabled":false,"tlsEnabled":false}`); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	stored, err = db.GetAppIngressConfig("radarr")
	if err != nil || stored.ExternalAccessEnabled || stored.TLSEnabled {
		t.Fatalf("explicit false fields were not applied: %+v %v", stored, err)
	}
	initial.ListenPort = 0
	if err := db.SetAppIngressConfig(initial); err != nil {
		t.Fatal(err)
	}
	if response := request(`{"publicDomain":"fallback.example.com"}`); response.Code != http.StatusOK {
		t.Fatalf("legacy zero-port row failed: %s", response.Body.String())
	}
	if err := db.DeleteAppIngressConfig("radarr"); err != nil {
		t.Fatal(err)
	}
	if response := request(`{"publicDomain":"new.example.com"}`); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	stored, err = db.GetAppIngressConfig("radarr")
	if err != nil || !stored.ExternalAccessEnabled || !stored.TLSEnabled {
		t.Fatalf("new domain defaults diverged: %+v %v", stored, err)
	}

}
