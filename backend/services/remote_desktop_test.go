package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestRemoteDesktopMarketplaceIntegration(t *testing.T) {
	setupBlueprintTestDB(t)
	kasm := GetBlueprint("kasmvnc")
	if kasm == nil || kasm.ServiceName != "af-kasmvnc" || kasm.DefaultPort != 6081 || kasm.WebPath != "/" {
		t.Fatalf("unexpected KasmVNC blueprint: %+v", kasm)
	}
	alias := GetBlueprint("af-kasmvnc")
	if alias == nil || alias.AppName != "kasmvnc" {
		t.Fatalf("KasmVNC service alias = %+v", alias)
	}
	t.Setenv("AETHERFLOW_OCCUPIED_PORTS", "6081,6900")
	port, reassigned, err := ResolveDynamicAppPort("kasmvnc", true)
	if err != nil || !reassigned || port == 6081 || port <= 0 {
		t.Fatalf("KasmVNC fallback port = %d, reassigned=%v, err=%v", port, reassigned, err)
	}
	mcvnc := GetBlueprint("mcvnc")
	if mcvnc == nil || mcvnc.ServiceName != "af-mcvnc" || mcvnc.DefaultPort != 6900 || mcvnc.WebPath != "/" {
		t.Fatalf("unexpected McVNC blueprint: %+v", mcvnc)
	}
	mcvncAlias := GetBlueprint("af-mcvnc")
	if mcvncAlias == nil || mcvncAlias.AppName != "mcvnc" {
		t.Fatalf("McVNC service alias = %+v", mcvncAlias)
	}
	port, reassigned, err = ResolveDynamicAppPort("mcvnc", true)
	if err != nil || !reassigned || port == 6900 || port <= 0 {
		t.Fatalf("McVNC fallback port = %d, reassigned=%v, err=%v", port, reassigned, err)
	}
	xrdp := GetBlueprint("xrdp")
	if xrdp == nil || xrdp.DefaultPort != 0 || xrdp.WebPath != "" || xrdp.HealthCheckPath != "" {
		t.Fatalf("XRDP must not be treated as HTTP: %+v", xrdp)
	}
	port, reassigned, err = ResolveDynamicAppPort("xrdp", true)
	if err != nil || reassigned || port != 0 {
		t.Fatalf("XRDP must not allocate an HTTP port: %d, %v, %v", port, reassigned, err)
	}
	for _, target := range []string{"xrdp", "xrdp-sesman", "xrdp.service", "xrdp-sesman.service"} {
		units := ResolveServiceUnits(target)
		if !slices.Contains(units, "xrdp") || !slices.Contains(units, "xrdp-sesman") {
			t.Errorf("XRDP companion units for %s: %v", target, units)
		}
	}
	automation := loadPackageAutomation()
	if automation["kasmvnc"].UpdateRepo != "kasmtech/KasmVNC" || automation["mcvnc"].UpdateRepo != "McEveritts/McVNC" || automation["xrdp"].UpdatePackage != "xrdp" {
		t.Fatal("remote desktop update tracking is incomplete")
	}
}

func TestPackageCommandAllocatedPort(t *testing.T) {
	t.Setenv("AF_APP_PORT", "9999")
	for _, useSudo := range []bool{false, true} {
		for _, port := range []int{0, 6081, 17000} {
			cmd := buildHardenedPackageCommand("/tmp/installpackage-kasmvnc", useSudo, port)
			values := []string{}
			for _, entry := range cmd.Env {
				if strings.HasPrefix(entry, "AF_APP_PORT=") {
					values = append(values, entry)
				}
			}
			if port == 0 {
				if len(values) != 0 {
					t.Errorf("unallocated port inherited from environment: %v", values)
				}
			} else if len(values) != 1 || values[0] != "AF_APP_PORT="+strconv.Itoa(port) {
				t.Errorf("port %d not passed exactly once (sudo=%v): %v", port, useSudo, values)
			}
		}
	}
}

func TestRunnerRejectsInvalidApplicationPort(t *testing.T) {
	for _, port := range []int{-1, 1, 1023, 65536} {
		payload, _ := json.Marshal(PackageRunnerRequest{Action: "install", PackageID: "kasmvnc", ScriptName: "installpackage-kasmvnc", AppPort: port})
		response := httptest.NewRecorder()
		NewRunnerMux().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/package", bytes.NewReader(payload)))
		if response.Code != http.StatusBadRequest {
			t.Errorf("port %d: got %d, want 400", port, response.Code)
		}
	}
}

func TestDispatchPackageStreamAllocatedPort(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "runner.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AETHERFLOW_RUNNER_SOCK", socketPath)
	requests := make(chan PackageRunnerRequest, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var payload PackageRunnerRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		requests <- payload
		_, _ = fmt.Fprintln(writer, "[PROGRESS:100] Ready")
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	var lines []string
	err = DispatchPackageStream("install", "kasmvnc", "installpackage-kasmvnc", 17003, func(line string) {
		lines = append(lines, line)
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-requests:
		if payload.AppPort != 17003 || payload.PackageID != "kasmvnc" {
			t.Errorf("runner received unexpected request: %+v", payload)
		}
	default:
		t.Fatal("runner did not receive a request")
	}
	if !slices.Equal(lines, []string{"[PROGRESS:100] Ready"}) {
		t.Errorf("progress output was not streamed: %v", lines)
	}
}
