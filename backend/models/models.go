package models

type SystemMetrics struct {
	CPUUsage  float64            `json:"cpu_usage"`
	DiskSpace map[string]float64 `json:"disk_space"`
	IsWindows bool               `json:"is_windows"`
	Services  map[string]bool    `json:"services"`
}
