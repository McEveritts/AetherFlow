package models

type ProcessInfo struct {
	PID  int32   `json:"pid"`
	Name string  `json:"name"`
	CPU  float64 `json:"cpu"`
	Mem  float64 `json:"mem"`
}

type SystemMetrics struct {
	CPUUsage      float64                `json:"cpu_usage"`
	PerCoreCPU    []float64              `json:"per_core_cpu"`
	CPUFreqMhz    float64                `json:"cpu_freq_mhz"`
	DiskSpace     map[string]float64     `json:"disk_space"`
	DiskIO        map[string]float64     `json:"disk_io"` // read_bytes_sec, write_bytes_sec
	Services      map[string]bool        `json:"services"`
	Memory        map[string]float64     `json:"memory"`
	Swap          map[string]float64     `json:"swap"` // total, used
	Network       map[string]interface{} `json:"network"`
	TotalNetBytes map[string]uint64      `json:"total_net_bytes"` // rx, tx cumulative
	Uptime        string                 `json:"uptime"`
	LoadAverage   []float64              `json:"load_average"`
	Processes     []ProcessInfo          `json:"processes"`
}
