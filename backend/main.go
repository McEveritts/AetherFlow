package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"aetherflow/api"
	"aetherflow/cluster"
	"aetherflow/db"
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
				log.Printf("Detected public IP: %s", publicIP)
			}
		}
	} else {
		log.Printf("Could not detect public IP (offline?): %v", err)
	}

	// Convert map to slice
	result := make([]string, 0, len(origins))
	for origin := range origins {
		result = append(result, origin)
	}

	log.Printf("CORS allowed origins: %v", result)
	return result
}

func main() {
	// Try loading .env from local or parent directory
	if err := godotenv.Load("../.env"); err != nil {
		godotenv.Load() // fallback to current dir if any
	}

	// Initialize the Database
	db.InitDB()

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
	services.InitSmartBackupScheduler()

	// Phase 22 — warn if billing webhook secrets are not configured.
	// The POST /billing/webhooks/:provider endpoint is intentionally outside
	// AdminOnly (billing providers can't hold a session), so the HMAC/bearer
	// secret is the sole authentication gate.  Alert operators at boot time.
	if os.Getenv("WHMCS_WEBHOOK_SECRET") == "" && os.Getenv("BLESTA_WEBHOOK_SECRET") == "" && os.Getenv("BILLING_WEBHOOK_SECRET") == "" {
		log.Println("⚠  WARNING: No billing webhook secret configured (WHMCS_WEBHOOK_SECRET / BLESTA_WEBHOOK_SECRET / BILLING_WEBHOOK_SECRET). " +
			"The POST /billing/webhooks/:provider endpoint will reject all requests until a secret is set.")
	}

	// Start gRPC server/client based on cluster mode
	clusterMode := os.Getenv("CLUSTER_MODE")
	switch clusterMode {
	case "master":
		go func() {
			srv, err := cluster.NewGRPCServer()
			if err != nil {
				log.Printf("Failed to create gRPC server: %v", err)
				return
			}
			if err := srv.Start(); err != nil {
				log.Printf("gRPC server error: %v", err)
			}
		}()
		log.Println("Cluster mode: MASTER — gRPC server starting")
	case "worker":
		masterAddr := os.Getenv("CLUSTER_MASTER_ADDR")
		if masterAddr == "" {
			log.Fatal("CLUSTER_MODE=worker requires CLUSTER_MASTER_ADDR to be set")
		}
		go func() {
			client, err := cluster.NewGRPCClient(masterAddr)
			if err != nil {
				log.Printf("Failed to connect to master: %v", err)
				return
			}
			defer client.Close()

			hostname, _ := os.Hostname()
			psk := os.Getenv("CLUSTER_PSK")

			if err := client.Register(hostname, fmt.Sprintf("%s:%s", hostname, os.Getenv("PORT")), psk, version); err != nil {
				log.Printf("Cluster registration failed: %v", err)
				return
			}

			ctx := context.Background()
			if err := client.StartHeartbeat(ctx); err != nil {
				log.Printf("Cluster heartbeat loop ended: %v", err)
			}
		}()
		log.Printf("Cluster mode: WORKER — connecting to master at %s", os.Getenv("CLUSTER_MASTER_ADDR"))
	default:
		log.Println("Cluster mode: STANDALONE (set CLUSTER_MODE=master|worker to enable clustering)")
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
		log.Printf("Using manual CORS origin: %s", customOrigin)
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

	log.Printf("AetherFlow Backend listening on 127.0.0.1:%s", port)

	// Bind to localhost to prevent direct internet exposure
	if err := r.Run("127.0.0.1:" + port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
