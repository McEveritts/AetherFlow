package services

import (
	"fmt"
	"time"

	"aetherflow/models"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

var (
	lastNetBytesRecv uint64
	lastNetBytesSent uint64
	lastNetCheck     time.Time
)

func GetSystemMetricsCore() models.SystemMetrics {

	var cpuUsage float64
	var totalDisk, usedDisk, freeDisk float64
	var totalMem, usedMem float64
	var upSpeed, downSpeed string
	var activeConnections int
	var uptimeStr string
	var loadAvg []float64

	// 1. CPU
	cpuPercents, err := cpu.Percent(0, false)
	if err == nil && len(cpuPercents) > 0 {
		cpuUsage = cpuPercents[0]
	}

	// 2. Memory
	vMem, err := mem.VirtualMemory()
	if err == nil {
		// Convert bytes to GB
		totalMem = float64(vMem.Total) / (1024 * 1024 * 1024)
		usedMem = float64(vMem.Used) / (1024 * 1024 * 1024)
	}

	// 3. Disk (Root)
	diskPath := "/"
	dStat, err := disk.Usage(diskPath)
	if err == nil {
		// Convert bytes to GB
		totalDisk = float64(dStat.Total) / (1024 * 1024 * 1024)
		usedDisk = float64(dStat.Used) / (1024 * 1024 * 1024)
		freeDisk = float64(dStat.Free) / (1024 * 1024 * 1024)
	}

	// 4. Network
	netIO, err := net.IOCounters(false)
	if err == nil && len(netIO) > 0 {
		now := time.Now()
		if !lastNetCheck.IsZero() {
			duration := now.Sub(lastNetCheck).Seconds()
			if duration > 0 {
				recvDiff := netIO[0].BytesRecv - lastNetBytesRecv
				sentDiff := netIO[0].BytesSent - lastNetBytesSent
				downSpeed = formatBytes(float64(recvDiff) / duration) + "/s"
				upSpeed = formatBytes(float64(sentDiff) / duration) + "/s"
			}
		} else {
			downSpeed = "0 B/s"
			upSpeed = "0 B/s"
		}
		
		lastNetBytesRecv = netIO[0].BytesRecv
		lastNetBytesSent = netIO[0].BytesSent
		lastNetCheck = now
	}

	// Active Connections (Approximation)
	conns, err := net.Connections("tcp")
	if err == nil {
		established := 0
		for _, c := range conns {
			if c.Status == "ESTABLISHED" {
				established++
			}
		}
		activeConnections = established
	}

	// 5. Host Info (Uptime)
	hostInfo, err := host.Info()
	if err == nil {
		duration := time.Duration(hostInfo.Uptime) * time.Second
		days := duration / (24 * time.Hour)
		duration -= days * 24 * time.Hour
		hours := duration / time.Hour
		duration -= hours * time.Hour
		minutes := duration / time.Minute
		
		if days > 0 {
			uptimeStr = fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
		} else if hours > 0 {
			uptimeStr = fmt.Sprintf("%dh %dm", hours, minutes)
		} else {
			uptimeStr = fmt.Sprintf("%dm", minutes)
		}
	} else {
		uptimeStr = "Unknown"
	}

	loadStat, err := load.Avg()
	if err == nil {
		loadAvg = []float64{loadStat.Load1, loadStat.Load5, loadStat.Load15}
	} else {
		loadAvg = []float64{0.0, 0.0, 0.0}
	}



	// We no longer scan /proc here manually for Services since service_manager.go handles it now.
	// We'll leave the map empty so it can be populated downstream, or just return an empty map
	// the frontend expects it inside the dashboard metrics response but we merged it at the websocket level.
	// Actually to comply with the model, let's keep an empty map.
	servicesMap := make(map[string]bool)

	return models.SystemMetrics{
		CPUUsage: cpuUsage,
		DiskSpace: map[string]float64{
			"total": totalDisk,
			"used":  usedDisk,
			"free":  freeDisk,
		},
		Memory: map[string]float64{
			"total": totalMem,
			"used":  usedMem,
		},
		Network: map[string]interface{}{
			"down": downSpeed,
			"up": upSpeed,
			"active_connections": activeConnections,
		},
		Uptime: uptimeStr,
		LoadAverage: loadAvg,
		Services:  servicesMap, // Deprecated at this layer, used service_manager instead
	}
}

func formatBytes(bytes float64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%.0f B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", bytes/float64(div), "KMGTPE"[exp])
}
