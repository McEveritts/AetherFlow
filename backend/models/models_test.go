package models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSystemMetricsJSONShape(t *testing.T) {
	m := SystemMetrics{
		CPUUsage:   52.3,
		PerCoreCPU: []float64{40.0, 64.6},
		CPUFreqMhz: 3200,
		DiskSpace: map[string]float64{
			"total": 1000,
			"used":  250,
			"free":  750,
		},
		Disks: []DiskPartition{
			{MountPoint: "/", Device: "/dev/sda1", FSType: "ext4", TotalGB: 1000, UsedGB: 250, FreeGB: 750, UsedPct: 25},
		},
	}

	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal SystemMetrics: %v", err)
	}
	jsonStr := string(raw)

	requiredKeys := []string{
		`"cpu_usage"`,
		`"per_core_cpu"`,
		`"cpu_freq_mhz"`,
		`"disk_space"`,
		`"mount_point"`,
	}
	for _, key := range requiredKeys {
		if !strings.Contains(jsonStr, key) {
			t.Fatalf("json missing key %s: %s", key, jsonStr)
		}
	}
}

func TestHardwareReportOmitempty(t *testing.T) {
	report := HardwareReport{
		SystemVendor:  "Acme",
		SystemProduct: "X1",
		CPU: &CPUInfo{
			Vendor:  "GenuineIntel",
			Model:   "Xeon",
			Cores:   8,
			Threads: 16,
		},
		GPUs: []GPUInfo{
			{
				Vendor:  "NVIDIA",
				Product: "A2000",
			},
		},
	}

	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal HardwareReport: %v", err)
	}
	jsonStr := string(raw)

	if strings.Contains(jsonStr, `"driver"`) {
		t.Fatalf("expected empty GPU driver to be omitted, got: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, `"system_vendor":"Acme"`) {
		t.Fatalf("expected system vendor in json: %s", jsonStr)
	}
}
