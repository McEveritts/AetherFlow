package models

type ProcessInfo struct {
	PID  int32   `json:"pid"`
	Name string  `json:"name"`
	CPU  float64 `json:"cpu"`
	Mem  float64 `json:"mem"`
}

type DiskPartition struct {
	MountPoint string  `json:"mount_point"`
	Device     string  `json:"device"`
	FSType     string  `json:"fs_type"`
	TotalGB    float64 `json:"total_gb"`
	UsedGB     float64 `json:"used_gb"`
	FreeGB     float64 `json:"free_gb"`
	UsedPct    float64 `json:"used_pct"`
}

type SystemMetrics struct {
	CPUUsage      float64                `json:"cpu_usage"`
	PerCoreCPU    []float64              `json:"per_core_cpu"`
	CPUFreqMhz    float64                `json:"cpu_freq_mhz"`
	DiskSpace     map[string]float64     `json:"disk_space"`  // legacy: root partition summary
	Disks         []DiskPartition        `json:"disks"`       // all mounted partitions
	DiskIO        map[string]float64     `json:"disk_io"`
	Services      map[string]bool        `json:"services"`
	Memory        map[string]float64     `json:"memory"`
	Swap          map[string]float64     `json:"swap"`
	Network       map[string]interface{} `json:"network"`
	TotalNetBytes map[string]uint64      `json:"total_net_bytes"`
	Uptime        string                 `json:"uptime"`
	LoadAverage   []float64              `json:"load_average"`
	Processes     []ProcessInfo          `json:"processes"`
}

