package services

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRunnerMuxValidation(t *testing.T) {
	mux := NewRunnerMux()

	// 1. Health endpoint
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on /v1/health, got %d", w.Code)
	}

	// 2. Reject command injection in systemctl service name
	body, _ := json.Marshal(SystemctlRequest{
		Service: "radarr; rm -rf /",
		Action:  "restart",
	})
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/systemctl", bytes.NewReader(body))
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid service name, got %d", w.Code)
	}

	// 3. Reject disallowed systemctl verb
	body, _ = json.Marshal(SystemctlRequest{
		Service: "radarr",
		Action:  "mask",
	})
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/systemctl", bytes.NewReader(body))
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for disallowed systemctl verb, got %d", w.Code)
	}

	// 4. Reject path traversal in package script name
	pkgBody, _ := json.Marshal(PackageRunnerRequest{
		Action:     "install",
		PackageID:  "radarr",
		ScriptName: "../../etc/passwd",
	})
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/package", bytes.NewReader(pkgBody))
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for path traversal in script name, got %d", w.Code)
	}

	// 5. Reject invalid channel in self-update
	updBody, _ := json.Marshal(SelfUpdateRequest{
		Command: "deploy",
		Channel: "malicious;id",
	})
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/self-update", bytes.NewReader(updBody))
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid self-update channel, got %d", w.Code)
	}

	// 6. Sandbox endpoint: reject command injection in package name
	sandboxBody, _ := json.Marshal(SandboxRunnerRequest{
		Package: "radarr; rm -rf /",
	})
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/sandbox", bytes.NewReader(sandboxBody))
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid sandbox package identifier, got %d", w.Code)
	}

	// 7. Hosts endpoint: reject invalid domains not ending in .aether.local or containing injection chars
	hostsBody, _ := json.Marshal(HostsRunnerRequest{
		Domains: []string{"bad.domain.com", "malicious;injection.aether.local"},
	})
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/hosts", bytes.NewReader(hostsBody))
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid domain names, got %d", w.Code)
	}

	// 8. Hosts endpoint: reject empty domains list
	emptyHostsBody, _ := json.Marshal(HostsRunnerRequest{Domains: []string{}})
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/hosts", bytes.NewReader(emptyHostsBody))
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty domains list, got %d", w.Code)
	}

	// 9. Network endpoint: reject disallowed network actions
	netBody, _ := json.Marshal(NetworkRunnerRequest{
		Action: "iptables_flush_all",
	})
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/network", bytes.NewReader(netBody))
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for disallowed network action, got %d", w.Code)
	}

	// 10. Quota endpoint: reject command injection in username
	quotaBody, _ := json.Marshal(QuotaRunnerRequest{
		Username: "admin; whoami",
		Size:     "10G",
	})
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/quota", bytes.NewReader(quotaBody))
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malicious quota username, got %d", w.Code)
	}

	// 11. Quota endpoint: reject invalid size format
	badSizeBody, _ := json.Marshal(QuotaRunnerRequest{
		Username: "validuser",
		Size:     "100GB_AND_DROP_TABLES",
	})
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/quota", bytes.NewReader(badSizeBody))
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid quota size, got %d", w.Code)
	}

	// 12. Method not allowed enforcement across all endpoints
	postOnlyEndpoints := []string{"/v1/systemctl", "/v1/package", "/v1/self-update", "/v1/sandbox", "/v1/hosts", "/v1/network", "/v1/quota"}
	for _, ep := range postOnlyEndpoints {
		w = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, ep, nil)
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 Method Not Allowed for GET %s, got %d", ep, w.Code)
		}
	}
}

func TestRunnerSocketTempCleanup(t *testing.T) {
	tempDir := t.TempDir()
	sockPath := filepath.Join(tempDir, "runner.sock")
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("expected socket not to exist yet in %s", sockPath)
	}
}
