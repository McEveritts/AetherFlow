package main

import (
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type SystemMetrics struct {
	CPUUsage  float64            `json:"cpu_usage"`
	DiskSpace map[string]float64 `json:"disk_space"`
	IsWindows bool               `json:"is_windows"`
	Services  map[string]bool    `json:"services"`
}

func main() {
	r := gin.Default()

	// Enable Wide CORS for local frontend development
	// Ensure we only allow strictly defined origins via Env
	allowedOrigins := []string{"http://127.0.0.1:3000", "http://localhost:3000"}
	if customOrigin := os.Getenv("ALLOWED_CORS_ORIGIN"); customOrigin != "" {
		allowedOrigins = append(allowedOrigins, customOrigin)
	}

	r.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	api := r.Group("/api")
	{
		api.GET("/system/metrics", getSystemMetrics)
	}

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

// checkProcessRunning natively scans /proc without spawning the shell
func checkProcessRunning(processName string) bool {
	if runtime.GOOS == "windows" {
		// Mock Data for Windows
		return true
	}

	procNameLower := strings.ToLower(processName)

	files, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}

	for _, f := range files {
		if f.IsDir() {
			// Check if directory name is numeric (a PID)
			if _, err := strconv.Atoi(f.Name()); err == nil {
				commPath := filepath.Join("/proc", f.Name(), "comm")
				data, err := os.ReadFile(commPath)
				if err == nil {
					commStr := strings.TrimSpace(strings.ToLower(string(data)))
					if strings.Contains(commStr, procNameLower) {
						return true
					}
				}
			}
		}
	}

	return false
}

func getSystemMetrics(c *gin.Context) {
	isWindows := runtime.GOOS == "windows"

	var cpuUsage float64
	var totalDisk, usedDisk, freeDisk float64

	if isWindows {
		// Mock Data for Windows Developer Environment
		cpuUsage = float64(rand.Intn(40) + 5)
		totalDisk = 500.0
		usedDisk = 250.0
		freeDisk = 250.0
	} else {
		// Linux Production Environment
		// Fetch CPU via loadavg (simplistic representation for now)
		out, err := exec.Command("cat", "/proc/loadavg").Output()
		if err == nil {
			parts := strings.Fields(string(out))
			if len(parts) > 0 {
				if load, err := strconv.ParseFloat(parts[0], 64); err == nil {
					// Approximate CPU usage
					cpuUsage = load * 10
					if cpuUsage > 100 {
						cpuUsage = 100
					}
				}
			}
		}

		// Fetch Disk via df -h
		out, err = exec.Command("df", "/", "-k").Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			if len(lines) > 1 {
				fields := strings.Fields(lines[1])
				if len(fields) >= 4 {
					total, _ := strconv.ParseFloat(fields[1], 64)
					used, _ := strconv.ParseFloat(fields[2], 64)
					free, _ := strconv.ParseFloat(fields[3], 64)

					totalDisk = total / (1024 * 1024)
					usedDisk = used / (1024 * 1024)
					freeDisk = free / (1024 * 1024)
				}
			}
		}
	}

	// Consolidate metrics + services into one payload
	services := map[string]bool{
		"Plex Media Server": checkProcessRunning("plex"),
		"rTorrent":          checkProcessRunning("rtorrent"),
		"Sonarr":            checkProcessRunning("sonarr"),
		"Radarr":            checkProcessRunning("radarr"),
	}

	c.JSON(http.StatusOK, SystemMetrics{
		CPUUsage: cpuUsage,
		DiskSpace: map[string]float64{
			"total": totalDisk,
			"used":  usedDisk,
			"free":  freeDisk,
		},
		IsWindows: isWindows,
		Services:  services,
	})
}
