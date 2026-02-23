package models

type SystemMetrics struct {
	CPUUsage    float64            `json:"cpu_usage"`
	DiskSpace   map[string]float64 `json:"disk_space"`
	IsWindows   bool               `json:"is_windows"`
	Services    map[string]bool    `json:"services"`
	Memory      map[string]float64 `json:"memory"`
	Network     map[string]interface{} `json:"network"` // up, down strings and active_connections int
	Uptime      string             `json:"uptime"`
	LoadAverage []float64          `json:"load_average"`
}
