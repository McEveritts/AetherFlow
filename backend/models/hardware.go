package models

type CPUInfo struct {
	Vendor  string `json:"vendor"`
	Model   string `json:"model"`
	Cores   uint32 `json:"cores"`
	Threads uint32 `json:"threads"`
}

type MemoryInfo struct {
	TotalBytes int64  `json:"total_bytes"`
	Banks      int    `json:"banks"`
	Type       string `json:"type"` // e.g., DDR4
}

type GPUInfo struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Driver  string `json:"driver,omitempty"`
}

type NetworkInfo struct {
	Name    string `json:"name"`
	MAC     string `json:"mac"`
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

type StorageInfo struct {
	Name       string `json:"name"`
	Model      string `json:"model"`
	SizeBytes  uint64 `json:"size_bytes"`
	DriveType  string `json:"drive_type"` // HDD, SSD, NVME
	IsRemovable bool   `json:"is_removable"`
}

type HardwareReport struct {
	SystemVendor  string        `json:"system_vendor"`
	SystemProduct string        `json:"system_product"`
	CPU           *CPUInfo      `json:"cpu,omitempty"`
	Memory        *MemoryInfo   `json:"memory,omitempty"`
	GPUs          []GPUInfo     `json:"gpus,omitempty"`
	Network       []NetworkInfo `json:"network,omitempty"`
	Storage       []StorageInfo `json:"storage,omitempty"`
}
