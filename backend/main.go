package main

// @title           AetherFlow API
// @version         1.0
// @description     This is the AetherFlow API server.
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.swagger.io/support
// @contact.email  support@swagger.io

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8080
// @BasePath  /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"aetherflow/api"
	"aetherflow/cluster"
	"aetherflow/config"
	"aetherflow/db"
	"aetherflow/logging"
	"aetherflow/services"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

var version = "dev"

// discoverOrigins auto-detects local and public IPs and builds CORS origin list
func discoverOrigins() []string {
	origins := map[string]bool{
		"http://localhost":  true,
		"https://localhost": true,
		"http://127.0.0.1":  true,
		"https://127.0.0.1": true,
	}

	// Detect local IPs from network interfaces
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() {
					continue
				}
				ipStr := ip.String()
				origins[fmt.Sprintf("http://%s", ipStr)] = true
				origins[fmt.Sprintf("https://%s", ipStr)] = true
			}
		}
	}

	// Detect public IP via external service
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err == nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			publicIP := strings.TrimSpace(string(body))
			if publicIP != "" {
				origins[fmt.Sprintf("http://%s", publicIP)] = true
				origins[fmt.Sprintf("https://%s", publicIP)] = true
				slog.Info("detected public IP", "ip", publicIP)
			}
		}
	} else {
		slog.Warn("could not detect public IP", "error", err)
	}

	// Convert map to slice
	result := make([]string, 0, len(origins))
	for origin := range origins {
		result = append(result, origin)
	}

	slog.Info("CORS origins configured", "count", len(result))
	return result
}

func main() {
	// Try loading .env from local or parent directory
	if err := godotenv.Load("../.env"); err != nil {
		godotenv.Load() // fallback to current dir if any
	}
	// Phase 18: Initialize structured logging
	logging.Init()

	// Phase 19: Centralized configuration — load all env vars into a typed struct
	config.Load()
	if err := config.Validate(); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Initialize the Database
	db.InitDB()
	db.InitRedis()
	db.StartPruneLoop() // Phase 16: periodic cleanup of expired data

	// Initialize AES-256-GCM encryption for API key storage
	api.InitAESKey()

	// Phase 2: Migrate any plaintext DB secrets to versioned ciphertext
	if err := api.MigrateLegacySecrets(); err != nil {
		slog.Warn("failed to migrate legacy secrets", "error", err)
	}

	// Initialize the Cluster Manager
	cluster.Init()

	// Initialize the Log Aggregator (Phase 8)
	services.InitLogAggregator()

	// Initialize the Notification Engine (Phase 9)
	services.InitNotificationEngine(func(n services.Notification) {
		// Bridge: dispatch notifications via the WebSocket hub
		api.BroadcastNotification(n)
	})

	// Initialize the installed-app update watcher (Phase 12)
	services.InitAppUpdateWatcher(func(changed []string) {
		api.BroadcastMarketplaceUpdates(changed)
	})

		// Initialize the Metrics Recorder (Phase 19 — Predictive Resource Scaling)
	services.InitMetricsRecorder()

	// Initialize the Smart Backup Scheduler (Phase 20)
	services.InitSmartBackupScheduler(api.GetDecryptedGeminiKey, func() error {
		_, err := api.PerformSystemBackup()
		return err
	})

	// Phase 22 — warn if billing webhook secrets are not configured.
	// The POST /billing/webhooks/:provider endpoint is intentionally outside
	// AdminOnly (billing providers can't hold a session), so the HMAC/bearer
	// secret is the sole authentication gate.  Alert operators at boot time.
	if os.Getenv("WHMCS_WEBHOOK_SECRET") == "" && os.Getenv("BLESTA_WEBHOOK_SECRET") == "" && os.Getenv("BILLING_WEBHOOK_SECRET") == "" {
		slog.Warn("no billing webhook secret configured",
			"hint", "set WHMCS_WEBHOOK_SECRET, BLESTA_WEBHOOK_SECRET, or BILLING_WEBHOOK_SECRET")
	}

	// Warn if running in production without ALLOWED_HOSTS
	if gin.Mode() == gin.ReleaseMode && os.Getenv("ALLOWED_HOSTS") == "" {
		slog.Warn("ALLOWED_HOSTS not set in production mode",
			"risk", "open redirect attacks (CWE-601)")
	}

	// CSRF default change notification
	if os.Getenv("CSRF_DISABLED") == "" && os.Getenv("CSRF_ENABLED") != "" {
		slog.Info("CSRF_ENABLED is deprecated — CSRF is now ON by default",
			"hint", "set CSRF_DISABLED=true to disable for local development")
	}

	// Environment Detection & Runtime Policy Evaluation
	envPolicy := services.GetRuntimePolicy()
	if envPolicy.IsWSL {
		slog.Info("platform detected", "type", "WSL", "sandbox", "bypassed")
	} else {
		slog.Info("platform detected", "type", "bare-metal", "sandbox", "active")
	}

	// Start gRPC server/client based on cluster mode
	clusterMode := os.Getenv("CLUSTER_MODE")
	switch clusterMode {
	case "master":
		go func() {
			srv, err := cluster.NewGRPCServer()
			if err != nil {
				slog.Error("failed to create gRPC server", "error", err)
				return
			}
			if err := srv.Start(); err != nil {
				slog.Error("gRPC server error", "error", err)
			}
		}()
		slog.Info("cluster mode active", "role", "master")
	case "worker":
		masterAddr := os.Getenv("CLUSTER_MASTER_ADDR")
		if masterAddr == "" {
			log.Fatal("CLUSTER_MODE=worker requires CLUSTER_MASTER_ADDR to be set")
		}
		go func() {
			client, err := cluster.NewGRPCClient(masterAddr)
			if err != nil {
				slog.Error("failed to connect to cluster master", "error", err, "addr", masterAddr)
				return
			}
			defer client.Close()

			hostname, _ := os.Hostname()
			psk := os.Getenv("CLUSTER_PSK")

			if err := client.Register(hostname, fmt.Sprintf("%s:%s", hostname, os.Getenv("PORT")), psk, version); err != nil {
				slog.Error("cluster registration failed", "error", err)
				return
			}

			ctx := context.Background()
			if err := client.StartHeartbeat(ctx); err != nil {
				slog.Warn("cluster heartbeat loop ended", "error", err)
			}
		}()
		slog.Info("cluster mode active", "role", "worker", "master_addr", masterAddr)
	default:
		slog.Info("cluster mode active", "role", "standalone")
	}

	r := gin.Default()

	// P5: Limit upload size to 50MB to prevent DoS
	r.MaxMultipartMemory = 50 << 20 // 50 MB

	// CORS Configuration
	corsConfig := cors.Config{
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-API-Version", "X-AetherFlow-Signature", "X-WHMCS-Signature", "X-BLESTA-Signature"},
		ExposeHeaders:    []string{"Content-Length", "X-API-Version", "Deprecation", "Link"},
		AllowCredentials: true,
	}

	if customOrigin := os.Getenv("ALLOWED_CORS_ORIGIN"); customOrigin != "" {
		// Manual override via env var
		corsConfig.AllowOrigins = []string{customOrigin}
		slog.Info("CORS manual override", "origin", customOrigin)
	} else {
		// Auto-detect local + public IPs
		corsConfig.AllowOrigins = discoverOrigins()
	}

	r.Use(cors.New(corsConfig))

	// Register all API routes from the api package
	api.RegisterRoutes(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	slog.Info("AetherFlow backend starting", "addr", "127.0.0.1:"+port, "version", version)

	// Start Phase 14: Automated Auto-Heal Recovery process
	services.StartHealWorker(10 * time.Second)

	// Phase 12: Profiling & Optimization Listener
	go func() {
		slog.Info("pprof profiler listening", "addr", "127.0.0.1:6060")
		if err := http.ListenAndServe("127.0.0.1:6060", nil); err != nil {
			slog.Error("pprof profiler error", "error", err)
		}
	}()

	// ── Phase 24: Graceful Shutdown ─────────────────────────────────────
	// Use http.Server directly for proper lifecycle control
	srv := &http.Server{
		Addr:    "127.0.0.1:" + port,
		Handler: r,
	}

	// Start HTTP server in a goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to run server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	sig := <-quit
	slog.Info("shutdown signal received", "signal", sig.String())

	// Deadline for in-flight request draining
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// 1. Stop accepting new connections, drain existing
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("HTTP server forced shutdown", "error", err)
	}
	slog.Info("HTTP server stopped")

	// 2. Stop all background subsystems (af-heal, notifications, metrics, backup scheduler)
	// Must happen before closing DB/Redis since subsystems may issue final writes.
	services.StopAllSubsystems()
	// Brief grace period for goroutines to exit their ticker loops
	time.Sleep(500 * time.Millisecond)
	slog.Info("background subsystems stopped")

	// 3. Close database connections
	if db.DB != nil {
		if err := db.DB.Close(); err != nil {
			slog.Error("database close error", "error", err)
		} else {
			slog.Info("database connection closed")
		}
	}

	// 4. Close Redis connection
	if db.RedisClient != nil {
		if err := db.RedisClient.Close(); err != nil {
			slog.Error("Redis close error", "error", err)
		} else {
			slog.Info("Redis connection closed")
		}
	}

	slog.Info("AetherFlow backend shutdown complete")
}
