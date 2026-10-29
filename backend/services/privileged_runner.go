package services

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const DefaultRunnerSocketPath = "/run/aetherflow/runner.sock"

var (
	// packageMutex serializes all apt/dpkg/installer invocations so concurrent
	// Marketplace requests never collide on /var/lib/dpkg/lock-frontend.
	packageMutex sync.Mutex

	safeScriptName        = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
	safeChannel           = map[string]bool{"stable": true, "beta": true, "nightly": true}
	safeUsernameRegex     = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)
	safeQuotaSizeRegex    = regexp.MustCompile(`^(?:[0-9]+(?:\.[0-9]+)?\s*[KMGTPEkmgtpe]?[Bb]?|0)$`)
	safeBase64KeyRegex    = regexp.MustCompile(`^[a-zA-Z0-9+/=]{40,48}$`)
	safeCIDRRegex         = regexp.MustCompile(`^[0-9a-fA-F:./]+$`)
	safeAllowedIPsRegex   = regexp.MustCompile(`^[0-9a-fA-F:./,\s]+$`)
	safeEndpointRegex     = regexp.MustCompile(`^[a-zA-Z0-9_.:-]+$`)
	allowedNetworkActions = map[string]bool{
		"wg_show":              true,
		"wg_add_peer":          true,
		"wg_remove_peer":       true,
		"tailscale_set_routes": true,
	}
)

// RunnerSocketPath returns the configured UNIX socket path for privileged execution.
func RunnerSocketPath() string {
	if p := strings.TrimSpace(os.Getenv("AETHERFLOW_RUNNER_SOCK")); p != "" {
		return p
	}
	return DefaultRunnerSocketPath
}

// IsRunnerAvailable checks whether the root-owned UNIX socket exists.
func IsRunnerAvailable() bool {
	info, err := os.Stat(RunnerSocketPath())
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSocket != 0
}

func newRunnerHTTPClient(timeout time.Duration) *http.Client {
	sockPath := RunnerSocketPath()
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
	}
}

// SystemctlRequest represents a service control command sent to the root runner.
type SystemctlRequest struct {
	Service string `json:"service"`
	Action  string `json:"action"`
}

// PackageRunnerRequest represents a marketplace package action sent to the root runner.
type PackageRunnerRequest struct {
	Action     string `json:"action"`
	PackageID  string `json:"package_id"`
	ScriptName string `json:"script_name"`
}

// SelfUpdateRequest represents an atomic release manager request.
type SelfUpdateRequest struct {
	Command string `json:"command"` // "deploy" or "rollback"
	Channel string `json:"channel"` // "stable", "beta", "nightly"
}

// SandboxRunnerRequest represents a systemd sandboxing request.
type SandboxRunnerRequest struct {
	Package   string `json:"package"`
	PackageID string `json:"package_id,omitempty"`
}

// HostsRunnerRequest represents an /etc/hosts internal DNS update request.
type HostsRunnerRequest struct {
	Action  string   `json:"action,omitempty"`
	Domain  string   `json:"domain,omitempty"`
	Domains []string `json:"domains,omitempty"`
	IP      string   `json:"ip,omitempty"`
}

// NetworkRunnerRequest represents a WireGuard or Tailscale privileged operation.
type NetworkRunnerRequest struct {
	Subsystem  string   `json:"subsystem,omitempty"` // "wireguard" or "tailscale"
	Action     string   `json:"action"`              // "wg_show", "wg_add_peer", "wg_remove_peer", "tailscale_set_routes"
	PublicKey  string   `json:"public_key,omitempty"`
	AllowedIPs string   `json:"allowed_ips,omitempty"`
	Endpoint   string   `json:"endpoint,omitempty"`
	Routes     []string `json:"routes,omitempty"`
	Args       []string `json:"args,omitempty"`
}

// QuotaRunnerRequest represents a setdisk user quota operation.
type QuotaRunnerRequest struct {
	Username string `json:"username"`
	Size     string `json:"size"`
}

// RunnerResponse is the standard JSON response from the privileged runner.
type RunnerResponse struct {
	Success bool   `json:"success"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

// DispatchSystemctl sends a service control command over the root UNIX socket.
func DispatchSystemctl(serviceName, action string) error {
	payload, _ := json.Marshal(SystemctlRequest{
		Service: serviceName,
		Action:  action,
	})
	client := newRunnerHTTPClient(30 * time.Second)
	resp, err := client.Post("http://unix/v1/systemctl", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("runner socket request failed: %w", err)
	}
	defer resp.Body.Close()

	var result RunnerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode runner response: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("runner systemctl error: %s (%s)", result.Error, result.Output)
	}
	return nil
}

// DispatchPackageStream executes a package installer via the root UNIX socket and
// invokes onLine for each output line in real time.
func DispatchPackageStream(action, pkgID, scriptName string, onLine func(string)) error {
	payload, _ := json.Marshal(PackageRunnerRequest{
		Action:     action,
		PackageID:  pkgID,
		ScriptName: scriptName,
	})
	client := newRunnerHTTPClient(30 * time.Minute)
	resp, err := client.Post("http://unix/v1/package", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("runner socket package request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("runner rejected package action (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var exitErr string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "__RUNNER_EXIT_ERROR__:") {
			exitErr = strings.TrimPrefix(line, "__RUNNER_EXIT_ERROR__:")
			continue
		}
		if line != "" && onLine != nil {
			onLine(line)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if exitErr != "" {
		return fmt.Errorf("%s", exitErr)
	}
	return nil
}

// DispatchSelfUpdate triggers the atomic release manager via the root UNIX socket.
func DispatchSelfUpdate(command, channel string) error {
	payload, _ := json.Marshal(SelfUpdateRequest{
		Command: command,
		Channel: channel,
	})
	client := newRunnerHTTPClient(15 * time.Second)
	resp, err := client.Post("http://unix/v1/self-update", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("runner socket self-update request failed: %w", err)
	}
	defer resp.Body.Close()

	var result RunnerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode runner response: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("runner self-update error: %s", result.Error)
	}
	return nil
}

// DispatchSandbox triggers package systemd sandboxing over the root UNIX socket.
func DispatchSandbox(pkgID string) error {
	payload, _ := json.Marshal(SandboxRunnerRequest{
		Package:   pkgID,
		PackageID: pkgID,
	})
	client := newRunnerHTTPClient(30 * time.Second)
	resp, err := client.Post("http://unix/v1/sandbox", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("runner socket sandbox request failed: %w", err)
	}
	defer resp.Body.Close()

	var result RunnerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode runner response: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("runner sandbox error: %s", result.Error)
	}
	return nil
}

// DispatchHostsUpdate updates internal .aether.local DNS entries in /etc/hosts via the root UNIX socket.
func DispatchHostsUpdate(domains []string) error {
	payload, _ := json.Marshal(HostsRunnerRequest{
		Action:  "update",
		Domains: domains,
	})
	client := newRunnerHTTPClient(15 * time.Second)
	resp, err := client.Post("http://unix/v1/hosts", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("runner socket hosts request failed: %w", err)
	}
	defer resp.Body.Close()

	var result RunnerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode runner response: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("runner hosts error: %s", result.Error)
	}
	return nil
}

// DispatchHostsRemove removes internal .aether.local DNS entries from /etc/hosts via the root UNIX socket.
func DispatchHostsRemove(domains []string) error {
	payload, _ := json.Marshal(HostsRunnerRequest{
		Action:  "remove",
		Domains: domains,
	})
	client := newRunnerHTTPClient(15 * time.Second)
	resp, err := client.Post("http://unix/v1/hosts", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("runner socket hosts remove request failed: %w", err)
	}
	defer resp.Body.Close()

	var result RunnerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode runner response: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("runner hosts remove error: %s", result.Error)
	}
	return nil
}

// DispatchNetworkAction executes a privileged WireGuard or Tailscale command via the root UNIX socket.
func DispatchNetworkAction(req NetworkRunnerRequest) (*RunnerResponse, error) {
	payload, _ := json.Marshal(req)
	client := newRunnerHTTPClient(30 * time.Second)
	resp, err := client.Post("http://unix/v1/network", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("runner socket network request failed: %w", err)
	}
	defer resp.Body.Close()

	var result RunnerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode runner response: %w", err)
	}
	if !result.Success {
		return &result, fmt.Errorf("runner network error: %s (%s)", result.Error, result.Output)
	}
	return &result, nil
}

// DispatchSetQuota configures a user storage disk quota via the root UNIX socket.
func DispatchSetQuota(username, size string) error {
	payload, _ := json.Marshal(QuotaRunnerRequest{
		Username: username,
		Size:     size,
	})
	client := newRunnerHTTPClient(30 * time.Second)
	resp, err := client.Post("http://unix/v1/quota", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("runner socket quota request failed: %w", err)
	}
	defer resp.Body.Close()

	var result RunnerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode runner response: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("runner quota error: %s (%s)", result.Error, result.Output)
	}
	return nil
}

// NewRunnerMux constructs the HTTP handler mux for the root-owned UNIX socket daemon.
func NewRunnerMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RunnerResponse{Success: true, Output: "ready"})
	})

	mux.HandleFunc("/v1/systemctl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "method not allowed"})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var req SystemctlRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "invalid JSON payload"})
			return
		}

		if !allowedServiceActions[req.Action] {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "disallowed systemctl action"})
			return
		}
		if err := validateServiceName(req.Service); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: err.Error()})
			return
		}

		cmd := exec.Command("systemctl", req.Action, "--", req.Service) // #nosec G204 -- strictly validated against allowlist and regex
		out, err := cmd.CombinedOutput()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(RunnerResponse{
				Success: false,
				Output:  string(out),
				Error:   err.Error(),
			})
			return
		}

		_ = json.NewEncoder(w).Encode(RunnerResponse{
			Success: true,
			Output:  string(out),
		})
	})

	mux.HandleFunc("/v1/package", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var req PackageRunnerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		if req.Action != "install" && req.Action != "remove" {
			http.Error(w, "disallowed package action", http.StatusBadRequest)
			return
		}
		if !safeScriptName.MatchString(req.ScriptName) || !safeScriptName.MatchString(req.PackageID) {
			http.Error(w, "invalid script or package identifier", http.StatusBadRequest)
			return
		}

		scriptPath := ResolvePackageScriptPath(req.Action, req.ScriptName)
		if scriptPath == "" {
			http.Error(w, "package script not found", http.StatusNotFound)
			return
		}

		// Serialize all package operations across the host to eliminate dpkg/apt lock contention.
		packageMutex.Lock()
		defer packageMutex.Unlock()

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		flusher, _ := w.(http.Flusher)

		cmd := buildHardenedPackageCommand(scriptPath, false)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			_, _ = fmt.Fprintf(w, "__RUNNER_EXIT_ERROR__:%v\n", err)
			return
		}
		cmd.Stderr = cmd.Stdout

		if err := cmd.Start(); err != nil {
			_, _ = fmt.Fprintf(w, "__RUNNER_EXIT_ERROR__:%v\n", err)
			return
		}

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			_, _ = fmt.Fprintln(w, scanner.Text())
			if flusher != nil {
				flusher.Flush()
			}
		}

		if err := cmd.Wait(); err != nil {
			_, _ = fmt.Fprintf(w, "__RUNNER_EXIT_ERROR__:%v\n", err)
			if flusher != nil {
				flusher.Flush()
			}
		}
	})

	mux.HandleFunc("/v1/self-update", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "method not allowed"})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var req SelfUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "invalid JSON"})
			return
		}

		if req.Command == "" {
			req.Command = "deploy"
		}
		if req.Command != "deploy" && req.Command != "rollback" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "invalid self-update command"})
			return
		}
		if req.Channel == "" {
			req.Channel = "stable"
		}
		if !safeChannel[req.Channel] {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "invalid update channel"})
			return
		}

		scriptPath := ResolveReleaseManagerScript()
		if scriptPath == "" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "release-manager.sh not found"})
			return
		}

		// Launch release-manager.sh asynchronously in the root runner cgroup so it
		// survives restarting aetherflow-api.service during the symlink swap.
		go func(cmdName, channel string) {
			cmd := exec.Command("/bin/bash", scriptPath, cmdName, "--channel", channel) // #nosec G204 -- validated enum arguments
			if err := cmd.Run(); err != nil {
				slog.Error("[runner] release-manager failed", "command", cmdName, "channel", channel, "error", err)
			}
		}(req.Command, req.Channel)

		_ = json.NewEncoder(w).Encode(RunnerResponse{
			Success: true,
			Output:  "Release manager initiated in root runner cgroup",
		})
	})

	mux.HandleFunc("/v1/sandbox", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "method not allowed"})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var req SandboxRunnerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "invalid JSON"})
			return
		}

		pkg := req.Package
		if pkg == "" {
			pkg = req.PackageID
		}
		if !safeScriptName.MatchString(pkg) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "invalid package identifier"})
			return
		}

		if err := ApplyPackageSandboxLocal(pkg); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Success: false, Error: err.Error()})
			return
		}

		_ = json.NewEncoder(w).Encode(RunnerResponse{Success: true, Output: "sandbox applied"})
	})

	mux.HandleFunc("/v1/hosts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "method not allowed"})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var req HostsRunnerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "invalid JSON"})
			return
		}

		domains := req.Domains
		if len(domains) == 0 && req.Domain != "" {
			domains = []string{req.Domain}
		}
		if len(domains) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "no domains specified"})
			return
		}

		for _, d := range domains {
			if !strings.HasSuffix(d, ".aether.local") || strings.ContainsAny(d, " \t\r\n;\"'$`") || len(d) > 253 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(RunnerResponse{Error: fmt.Sprintf("invalid domain format: %q", d)})
				return
			}
		}

		dnsMgr := NewDNSManager()
		var opErr error
		if strings.EqualFold(req.Action, "remove") {
			opErr = dnsMgr.RemoveDomainsLocal(domains)
		} else {
			opErr = dnsMgr.AppendOrUpdateDomainsLocal(domains)
		}
		if opErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Success: false, Error: opErr.Error()})
			return
		}

		_ = json.NewEncoder(w).Encode(RunnerResponse{Success: true, Output: "hosts updated"})
	})

	mux.HandleFunc("/v1/network", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "method not allowed"})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var req NetworkRunnerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "invalid JSON"})
			return
		}

		if !allowedNetworkActions[req.Action] {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "disallowed network action"})
			return
		}

		out, err := executeNetworkActionLocal(req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Success: false, Output: out, Error: err.Error()})
			return
		}

		_ = json.NewEncoder(w).Encode(RunnerResponse{Success: true, Output: out})
	})

	mux.HandleFunc("/v1/quota", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "method not allowed"})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var req QuotaRunnerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "invalid JSON"})
			return
		}

		if !safeUsernameRegex.MatchString(req.Username) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "invalid username format"})
			return
		}
		if !safeQuotaSizeRegex.MatchString(req.Size) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Error: "invalid size format"})
			return
		}

		out, err := ExecuteSetQuotaLocal(req.Username, req.Size)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(RunnerResponse{Success: false, Output: out, Error: err.Error()})
			return
		}

		_ = json.NewEncoder(w).Encode(RunnerResponse{Success: true, Output: out})
	})

	return mux
}

func executeNetworkActionLocal(req NetworkRunnerRequest) (string, error) {
	switch req.Action {
	case "wg_show":
		out, err := exec.Command("wg", "show", "all", "dump").CombinedOutput()
		return string(out), err

	case "wg_add_peer":
		if !safeBase64KeyRegex.MatchString(req.PublicKey) {
			return "", fmt.Errorf("invalid public key format")
		}
		if req.AllowedIPs != "" && !safeAllowedIPsRegex.MatchString(req.AllowedIPs) {
			return "", fmt.Errorf("invalid allowed IPs format")
		}
		args := []string{"set", "wg0", "peer", req.PublicKey}
		if req.AllowedIPs != "" {
			args = append(args, "allowed-ips", req.AllowedIPs)
		}
		if req.Endpoint != "" {
			if !safeEndpointRegex.MatchString(req.Endpoint) {
				return "", fmt.Errorf("invalid endpoint format")
			}
			args = append(args, "endpoint", req.Endpoint)
		}
		cmd := exec.Command("wg", args...)
		out, err := cmd.CombinedOutput()
		return string(out), err

	case "wg_remove_peer":
		if !safeBase64KeyRegex.MatchString(req.PublicKey) {
			return "", fmt.Errorf("invalid public key format")
		}
		cmd := exec.Command("wg", "set", "wg0", "peer", req.PublicKey, "remove")
		out, err := cmd.CombinedOutput()
		return string(out), err

	case "tailscale_set_routes":
		if len(req.Routes) == 0 {
			return "", fmt.Errorf("no routes specified")
		}
		for _, r := range req.Routes {
			if !safeCIDRRegex.MatchString(r) {
				return "", fmt.Errorf("invalid route CIDR: %q", r)
			}
		}
		routeStr := strings.Join(req.Routes, ",")
		cmd := exec.Command("tailscale", "set", "--advertise-routes="+routeStr)
		out, err := cmd.CombinedOutput()
		return string(out), err

	default:
		return "", fmt.Errorf("unsupported network action: %s", req.Action)
	}
}

// ResolveReleaseManagerScript locates deploy/release-manager.sh on the host.
func ResolveReleaseManagerScript() string {
	candidates := []string{
		"/opt/AetherFlow/current/deploy/release-manager.sh",
		"/opt/AetherFlow/deploy/release-manager.sh",
	}
	if exeDir != "" {
		candidates = append(candidates,
			filepath.Join(exeDir, "deploy", "release-manager.sh"),
			filepath.Join(exeDir, "..", "deploy", "release-manager.sh"),
		)
	}
	candidates = append(candidates, filepath.Join("deploy", "release-manager.sh"), filepath.Join("..", "deploy", "release-manager.sh"))

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return filepath.Clean(c)
		}
	}
	return ""
}

// buildHardenedPackageCommand wraps a package installer script with non-interactive
// APT flags and a 120-second dpkg lock timeout to prevent apt lock failures.
func buildHardenedPackageCommand(scriptPath string, useSudo bool) *exec.Cmd {
	var cmd *exec.Cmd
	if useSudo {
		cmd = exec.Command("sudo", "-E", "-n", "bash", scriptPath) // #nosec G204 -- scriptPath resolved from verified package dir
	} else {
		cmd = exec.Command("bash", scriptPath) // #nosec G204 -- scriptPath resolved from verified package dir
	}
	cmd.Env = append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"DPKG_LOCK_TIMEOUT=120",
	)
	return cmd
}

// RunPrivilegedDaemon starts the root-owned UNIX socket listener for privileged host operations.
func RunPrivilegedDaemon() error {
	sockPath := RunnerSocketPath()
	sockDir := filepath.Dir(sockPath)
	if err := os.MkdirAll(sockDir, 0750); err != nil {
		return fmt.Errorf("create runner socket dir %s: %w", sockDir, err)
	}
	_ = os.Remove(sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("listen on unix socket %s: %w", sockPath, err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(sockPath)
	}()

	// Restrict socket permissions so only root and the aetherflow group can connect.
	if err := os.Chmod(sockPath, 0660); err != nil {
		slog.Warn("could not chmod runner socket", "path", sockPath, "error", err)
	}

	srv := &http.Server{
		Handler:           NewRunnerMux(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	slog.Info("AetherFlow Privileged Runner listening", "socket", sockPath)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-quit:
		slog.Info("Privileged Runner shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	case err := <-errCh:
		return err
	}
}
