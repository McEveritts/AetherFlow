package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"aetherflow/api"
	"aetherflow/db"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

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

	r := gin.Default()

	// CORS Configuration
	corsConfig := cors.Config{
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
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
