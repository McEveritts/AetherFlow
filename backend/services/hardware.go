package services

import (
	"math/rand"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"aetherflow/models"
)

func GetSystemMetricsCore() models.SystemMetrics {
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

	services := map[string]bool{
		"Plex Media Server": CheckProcessRunning("plex"),
		"rTorrent":          CheckProcessRunning("rtorrent"),
		"Sonarr":            CheckProcessRunning("sonarr"),
		"Radarr":            CheckProcessRunning("radarr"),
	}

	return models.SystemMetrics{
		CPUUsage: cpuUsage,
		DiskSpace: map[string]float64{
			"total": totalDisk,
			"used":  usedDisk,
			"free":  freeDisk,
		},
		IsWindows: isWindows,
		Services:  services,
	}
}
