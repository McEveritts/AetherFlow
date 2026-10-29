package services

import (
	"aetherflow/db"
	"aetherflow/models"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// DeployConfig parameters for the orchestration cycle
type DeployConfig struct {
	AppName         string
	VersionStr      string // e.g., "v3.0.1" (Green)
	ActiveSymlink   string // e.g., "/opt/radarr/active"
	BinaryStaging   string // e.g., "/opt/radarr/v3.0.1"
	CentralDBPath   string // e.g., "/var/lib/radarr/radarr.db"
	TargetInternal  string // e.g., "qbittorrent.aether.local"
	TargetCaddyPort int    // Dynamic green port
	HealthCheckPath string // Blueprint health check endpoint
	StatusChan      chan string // SSE Livestreaming
}

// Orchestrator handles the high-level deploy logic
type Orchestrator struct {
	CaddyMgr *CaddyManager
	DNSMgr   *DNSManager
}

func NewOrchestrator(caddyEndpoint string) *Orchestrator {
	return &Orchestrator{
		CaddyMgr: NewCaddyManager(caddyEndpoint),
		DNSMgr:   NewDNSManager(),
	}
}

// logToStream pushes events to internal logs and SSE channel simultaneously
func (o *Orchestrator) logToStream(ch chan string, msg string) {
	log.Println(msg)
	if ch != nil {
		select {
		case ch <- msg:
		default: // Non-blocking if channel is full
		}
	}
}

// ExecuteAtomicDeploy runs the master blue/green swap
func (o *Orchestrator) ExecuteAtomicDeploy(cfg DeployConfig) error {
	o.logToStream(cfg.StatusChan, "[STEP 1] Validating DNS resolution for internal .aether.local records...")
	if !o.DNSMgr.ValidateResolution(cfg.TargetInternal) {
		return fmt.Errorf("DNS validation failed on target: %s", cfg.TargetInternal)
	}

	o.logToStream(cfg.StatusChan, "[STEP 2] Halting Blue environment to release SQLite locks...")
	if err := o.stopService(cfg.AppName); err != nil {
		return fmt.Errorf("failed halting blue service: %w", err)
	}

	// Wait for OS locks to clear (Critical Caution block resolved)
	time.Sleep(2 * time.Second)

	// Dynamic polymorphic manipulation over app config
	mutator := GetMutatorForApp(cfg.AppName, cfg.CentralDBPath)
	if mutator != nil {
		if err := mutator.Backup(); err != nil {
			return fmt.Errorf("failed config backup: %w", err)
		}

		// Inject routing loop overrides
		routes := map[string]string{"localhost": cfg.TargetInternal, "127.0.0.1": cfg.TargetInternal}
		if err := mutator.InjectRoutes(routes); err != nil {
			mutator.Restore()
			return fmt.Errorf("configuration injection failed: %w", err)
		}
	}

	o.logToStream(cfg.StatusChan, "[STEP 4] Modifying filesystem symlinks for Green environment...")
	// Save the old symlink to rollback
	oldTarget, _ := os.Readlink(cfg.ActiveSymlink)

	// Atomic symlink swap
	tmpLink := cfg.ActiveSymlink + ".tmp"
	if err := os.Symlink(cfg.BinaryStaging, tmpLink); err != nil {
		return fmt.Errorf("failed staging symlink: %w", err)
	}
	if err := os.Rename(tmpLink, cfg.ActiveSymlink); err != nil {
		os.Remove(tmpLink)
		return fmt.Errorf("failed atomic symlink execution: %w", err)
	}

	o.logToStream(cfg.StatusChan, "[STEP 5] Updating Apache2 / Subdomain Gateway & reverse-proxy targets...")
	var prevIngress *models.AppIngressConfig
	if db.DB != nil {
		prevIngress, _ = db.GetAppIngressConfig(cfg.AppName)
		pubDomain := ""
		extEnabled := true
		tlsEnabled := true
		if prevIngress != nil {
			pubDomain = prevIngress.PublicDomain
			extEnabled = prevIngress.ExternalAccessEnabled
			tlsEnabled = prevIngress.TLSEnabled
		} else if baseDomain := ResolveBaseDomain(); baseDomain != "" {
			pubDomain = FormatAppPublicDomain(cfg.AppName, baseDomain)
		}
		_ = db.SetAppIngressConfig(models.AppIngressConfig{
			AppName:               cfg.AppName,
			PublicDomain:          pubDomain,
			ListenPort:            cfg.TargetCaddyPort,
			ExternalAccessEnabled: extEnabled,
			TLSEnabled:            tlsEnabled,
		})
	}
	routeState := RoutingState{
		AppName:               cfg.AppName,
		ActivePort:            cfg.TargetCaddyPort,
		InternalDomain:        fmt.Sprintf("%s.aether.local", cfg.AppName),
		ExternalAccessEnabled: true,
	}
	if err := o.CaddyMgr.UpdateAppRoutes(routeState); err != nil {
		if prevIngress != nil && db.DB != nil {
			_ = db.SetAppIngressConfig(*prevIngress)
		}
		o.executeRollback(cfg, oldTarget)
		return fmt.Errorf("failed routing update: %w", err)
	}

	o.logToStream(cfg.StatusChan, "[STEP 6] Spinning up Green environment...")
	if err := o.startService(cfg.AppName); err != nil {
		o.executeRollback(cfg, oldTarget)
		return fmt.Errorf("failed starting green service: %w", err)
	}

	o.logToStream(cfg.StatusChan, "[STEP 7] Performing health check on new endpoints...")
	time.Sleep(3 * time.Second) // wait for init
	healthPath := cfg.HealthCheckPath
	if healthPath == "" {
		healthPath = "/api/v3/system/status"
	}
	healthURL := fmt.Sprintf("http://127.0.0.1:%d%s", cfg.TargetCaddyPort, healthPath)
	resp, err := http.Get(healthURL)
	if err != nil || resp.StatusCode >= 400 {
		o.executeRollback(cfg, oldTarget)
		if resp != nil {
			resp.Body.Close()
		}
		return fmt.Errorf("health check failed on ping to Green environment")
	}
	if resp != nil {
		resp.Body.Close()
	}

	o.logToStream(cfg.StatusChan, "[SUCCESS] Atomic deployment verified and live.")
	return nil
}

func (o *Orchestrator) executeRollback(cfg DeployConfig, oldTarget string) {
	o.logToStream(cfg.StatusChan, "[ROLLBACK] Initiation sequence started due to deploy failure.")
	o.stopService(cfg.AppName)

	// Restore polymorphic Config Backup
	mutator := GetMutatorForApp(cfg.AppName, cfg.CentralDBPath)
	if mutator != nil {
		_ = mutator.Restore()
	}

	// Revert Symlink
	if oldTarget != "" {
		tmpLink := cfg.ActiveSymlink + ".tmp"
		os.Symlink(oldTarget, tmpLink)
		os.Rename(tmpLink, cfg.ActiveSymlink)
	}

	// Caddy routing: restore previous Caddy proxy target if configured
	if o.CaddyMgr != nil && cfg.TargetCaddyPort > 0 {
		_ = o.CaddyMgr.UpdateAppRoutes(RoutingState{
			AppName:        cfg.AppName,
			ActivePort:     cfg.TargetCaddyPort,
			InternalDomain: fmt.Sprintf("%s.aether.local", cfg.AppName),
		})
	}

	o.startService(cfg.AppName)
	o.logToStream(cfg.StatusChan, "[ROLLBACK] System restored to previous functional parameters.")
}

func (o *Orchestrator) stopService(serviceName string) error {
	return ControlService(serviceName, "stop")
}

func (o *Orchestrator) startService(serviceName string) error {
	return ControlService(serviceName, "start")
}
