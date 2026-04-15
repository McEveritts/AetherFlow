package services

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"os"
	"time"

	"aetherflow/models"

	"github.com/jaypipes/ghw"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

var (
	lastNetBytesRecv uint64
	lastNetBytesSent uint64
	lastNetCheck     time.Time
	lastDiskReadBytes  uint64
	lastDiskWriteBytes uint64
	lastDiskCheck      time.Time
	// Process cache — refreshed every 5 seconds to avoid expensive /proc scan each tick
	cachedProcesses     []models.ProcessInfo
	lastProcessScan     time.Time
	processCacheInterval = 5 * time.Second
)

// sanitizeFloat64 clamps +Inf and NaN to 0 so json.Marshal never panics.
func sanitizeFloat64(v float64) float64 {
	if math.IsInf(v, 0) || math.IsNaN(v) {
		return 0
	}
	return v
}

// sanitizeFloat64Map sanitizes every value in a map[string]float64.
func sanitizeFloat64Map(m map[string]float64) {
	for k, v := range m {
		m[k] = sanitizeFloat64(v)
	}
}

func GetSystemMetricsCore() models.SystemMetrics {

	var cpuUsage float64
	var perCoreCPU []float64
	var cpuFreqMhz float64
	var totalDisk, usedDisk, freeDisk float64
	var totalMem, usedMem float64
	var swapTotal, swapUsed float64
	var upSpeed, downSpeed string
	var activeConnections int
	var uptimeStr string
	var loadAvg []float64
	var readBytesPerSec, writeBytesPerSec float64
	var totalRx, totalTx uint64

	// 1. CPU (aggregate)
	cpuPercents, err := cpu.Percent(0, false)
	if err == nil && len(cpuPercents) > 0 {
		cpuUsage = cpuPercents[0]
	}

	// 1b. Per-core CPU
	corePercents, err := cpu.Percent(0, true)
	if err == nil {
		perCoreCPU = corePercents
	}

	// 1c. CPU Frequency (Live Detection)
	cpuFreqMhz = getLiveCpuFreq()

	// 2. Memory
	vMem, err := mem.VirtualMemory()
	if err == nil {
		totalMem = float64(vMem.Total) / (1024 * 1024 * 1024)
		usedMem = float64(vMem.Used) / (1024 * 1024 * 1024)
	}

	// 2b. Swap
	swapMem, err := mem.SwapMemory()
	if err == nil {
		swapTotal = float64(swapMem.Total) / (1024 * 1024 * 1024)
		swapUsed = float64(swapMem.Used) / (1024 * 1024 * 1024)
	}

	// 3. Disk Partitions (all real mounts)
	var diskPartitions []models.DiskPartition
	parts, err := disk.Partitions(false) // false = only real devices, no virtual
	if err == nil {
		seen := make(map[string]bool)
		for _, p := range parts {
			// Skip snap/squashfs/tmpfs/devtmpfs mounts
			if p.Fstype == "squashfs" || p.Fstype == "tmpfs" || p.Fstype == "devtmpfs" || p.Fstype == "overlay" {
				continue
			}
			// Deduplicate by mount point
			if seen[p.Mountpoint] {
				continue
			}
			seen[p.Mountpoint] = true

			usage, err := disk.Usage(p.Mountpoint)
			if err != nil || usage.Total == 0 {
				continue
			}
			totalGB := float64(usage.Total) / (1024 * 1024 * 1024)
			usedGB := float64(usage.Used) / (1024 * 1024 * 1024)
			freeGB := float64(usage.Free) / (1024 * 1024 * 1024)

			diskPartitions = append(diskPartitions, models.DiskPartition{
				MountPoint: p.Mountpoint,
				Device:     p.Device,
				FSType:     p.Fstype,
				TotalGB:    totalGB,
				UsedGB:     usedGB,
				FreeGB:     freeGB,
				UsedPct:    usage.UsedPercent,
			})

			// Legacy: keep root partition in DiskSpace for backward compat
			if p.Mountpoint == "/" {
				totalDisk = totalGB
				usedDisk = usedGB
				freeDisk = freeGB
			}
		}
	}

	// 3b. Disk I/O
	diskIO, err := disk.IOCounters()
	if err == nil {
		var totalRead, totalWrite uint64
		for _, d := range diskIO {
			totalRead += d.ReadBytes
			totalWrite += d.WriteBytes
		}
		now := time.Now()
		if !lastDiskCheck.IsZero() {
			// Fix #13: Enforce a minimum duration floor (10ms) to prevent
			// division-by-zero yielding +Inf, which panics json.Marshal.
			duration := now.Sub(lastDiskCheck).Seconds()
			if duration < 0.01 {
				duration = 0.01
			}
			readBytesPerSec = float64(totalRead-lastDiskReadBytes) / duration
			writeBytesPerSec = float64(totalWrite-lastDiskWriteBytes) / duration
			// Guard against +Inf / NaN from edge cases
			if math.IsInf(readBytesPerSec, 0) || math.IsNaN(readBytesPerSec) {
				readBytesPerSec = 0
			}
			if math.IsInf(writeBytesPerSec, 0) || math.IsNaN(writeBytesPerSec) {
				writeBytesPerSec = 0
			}
		}
		lastDiskReadBytes = totalRead
		lastDiskWriteBytes = totalWrite
		lastDiskCheck = now
	}

	// 4. Network
	netIO, err := net.IOCounters(false)
	if err == nil && len(netIO) > 0 {
		totalRx = netIO[0].BytesRecv
		totalTx = netIO[0].BytesSent
		now := time.Now()
		if !lastNetCheck.IsZero() {
			// Fix #13: Enforce a minimum duration floor (10ms) to prevent
			// division-by-zero yielding +Inf in network speed strings.
			duration := now.Sub(lastNetCheck).Seconds()
			if duration < 0.01 {
				duration = 0.01
			}
			recvDiff := netIO[0].BytesRecv - lastNetBytesRecv
			sentDiff := netIO[0].BytesSent - lastNetBytesSent
			downSpeedVal := float64(recvDiff) / duration
			upSpeedVal := float64(sentDiff) / duration
			if math.IsInf(downSpeedVal, 0) || math.IsNaN(downSpeedVal) {
				downSpeedVal = 0
			}
			if math.IsInf(upSpeedVal, 0) || math.IsNaN(upSpeedVal) {
				upSpeedVal = 0
			}
			downSpeed = formatBytes(downSpeedVal) + "/s"
			upSpeed = formatBytes(upSpeedVal) + "/s"
		} else {
			downSpeed = "0 B/s"
			upSpeed = "0 B/s"
		}

		lastNetBytesRecv = netIO[0].BytesRecv
		lastNetBytesSent = netIO[0].BytesSent
		lastNetCheck = now
	}

	// Active Connections
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

	// 5. Uptime
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

	// 6. Load Average
	loadStat, err := load.Avg()
	if err == nil {
		loadAvg = []float64{loadStat.Load1, loadStat.Load5, loadStat.Load15}
	} else {
		loadAvg = []float64{0.0, 0.0, 0.0}
	}

	// 7. Top Processes — cached, refreshed every 5 seconds
	if time.Since(lastProcessScan) > processCacheInterval || cachedProcesses == nil {
		var freshProcs []models.ProcessInfo
		procs, err := process.Processes()
		if err == nil {
			type procEntry struct {
				pid  int32
				name string
				cpu  float64
				mem  float32
			}
			var entries []procEntry
			for _, p := range procs {
				name, err := p.Name()
				if err != nil || name == "" {
					continue
				}
				cpuPct, err := p.CPUPercent()
				if err != nil {
					cpuPct = 0
				}
				memPct, err := p.MemoryPercent()
				if err != nil {
					memPct = 0
				}
				entries = append(entries, procEntry{pid: p.Pid, name: name, cpu: cpuPct, mem: memPct})
			}
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].cpu > entries[j].cpu
			})
			limit := 10
			if len(entries) < limit {
				limit = len(entries)
			}
			for _, e := range entries[:limit] {
				freshProcs = append(freshProcs, models.ProcessInfo{
					PID:  e.pid,
					Name: e.name,
					CPU:  e.cpu,
					Mem:  float64(e.mem),
				})
			}
		}
		cachedProcesses = freshProcs
		lastProcessScan = time.Now()
	}

	servicesMap := make(map[string]bool)

	// ── Final sanitization pass ─────────────────────────────────────────
	// Clamp any +Inf / NaN float64 values to 0 so json.Marshal never
	// emits "json: unsupported value: +Inf" and returns an empty body.
	cpuUsage = sanitizeFloat64(cpuUsage)
	cpuFreqMhz = sanitizeFloat64(cpuFreqMhz)
	readBytesPerSec = sanitizeFloat64(readBytesPerSec)
	writeBytesPerSec = sanitizeFloat64(writeBytesPerSec)

	for i := range perCoreCPU {
		perCoreCPU[i] = sanitizeFloat64(perCoreCPU[i])
	}
	for i := range loadAvg {
		loadAvg[i] = sanitizeFloat64(loadAvg[i])
	}
	for i := range diskPartitions {
		diskPartitions[i].TotalGB = sanitizeFloat64(diskPartitions[i].TotalGB)
		diskPartitions[i].UsedGB = sanitizeFloat64(diskPartitions[i].UsedGB)
		diskPartitions[i].FreeGB = sanitizeFloat64(diskPartitions[i].FreeGB)
		diskPartitions[i].UsedPct = sanitizeFloat64(diskPartitions[i].UsedPct)
	}
	for i := range cachedProcesses {
		cachedProcesses[i].CPU = sanitizeFloat64(cachedProcesses[i].CPU)
		cachedProcesses[i].Mem = sanitizeFloat64(cachedProcesses[i].Mem)
	}
	totalDisk = sanitizeFloat64(totalDisk)
	usedDisk = sanitizeFloat64(usedDisk)
	freeDisk = sanitizeFloat64(freeDisk)
	totalMem = sanitizeFloat64(totalMem)
	usedMem = sanitizeFloat64(usedMem)
	swapTotal = sanitizeFloat64(swapTotal)
	swapUsed = sanitizeFloat64(swapUsed)

	// 8. GPUs
	var gpuMetrics []models.GpuMetric
	gpuInfo, err := ghw.GPU()
	if err == nil && gpuInfo != nil {
		for i, card := range gpuInfo.GraphicsCards {
			name := "GPU"
			if card.DeviceInfo != nil && card.DeviceInfo.Product != nil {
				name = card.DeviceInfo.Product.Name
			}
			gpuMetrics = append(gpuMetrics, models.GpuMetric{
				Index: i,
				Name:  name,
				// Usage and specific memory used would require NVML or similar
				// For now, we provide the detectable presence and metadata
			})
		}
	}

	return models.SystemMetrics{
		CPUUsage:   cpuUsage,
		PerCoreCPU: perCoreCPU,
		CPUFreqMhz: cpuFreqMhz,
		DiskSpace: map[string]float64{
			"total": totalDisk,
			"used":  usedDisk,
			"free":  freeDisk,
		},
		Disks: diskPartitions,
		DiskIO: map[string]float64{
			"read_bytes_sec":  readBytesPerSec,
			"write_bytes_sec": writeBytesPerSec,
		},
		Memory: map[string]float64{
			"total": totalMem,
			"used":  usedMem,
		},
		Swap: map[string]float64{
			"total": swapTotal,
			"used":  swapUsed,
		},
		Network: map[string]interface{}{
			"down": downSpeed,
			"up": upSpeed,
			"active_connections": activeConnections,
		},
		TotalNetBytes: map[string]uint64{
			"rx": totalRx,
			"tx": totalTx,
		},
		Uptime:      uptimeStr,
		LoadAverage: loadAvg,
		Processes:   cachedProcesses,
		Services:    servicesMap,
		GPUs:        gpuMetrics,
	}
}

// getLiveCpuFreq attempts to get the real-time CPU clock speed.
// It prioritizes Linux sysfs for frequency scaling but falls back to gopsutil.
func getLiveCpuFreq() float64 {
	// 1. Linux sysfs - Current Frequency (Very live)
	data, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")
	if err == nil {
		freqKHz, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
		if err == nil {
			return freqKHz / 1000.0 // KHz to MHz
		}
	}

	// 2. Fallback to gopsutil (Default OS report)
	cpuInfos, err := cpu.Info()
	if err == nil && len(cpuInfos) > 0 {
		return cpuInfos[0].Mhz
	}

	return 0
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

// GetDetailedHardware uses the ghw library (which parses pci.ids and usb.ids natively inside Linux)
// to return a robust, human-readable hardware identifier database format.
func GetDetailedHardware() models.HardwareReport {
	report := models.HardwareReport{}

	// System / Baseboard
	dmi, err := ghw.Baseboard()
	if err == nil && dmi != nil {
		report.SystemVendor = dmi.Vendor
		report.SystemProduct = dmi.Product
	}

	// CPU
	cpu, err := ghw.CPU()
	if err == nil && cpu != nil && len(cpu.Processors) > 0 {
		p := cpu.Processors[0]
		report.CPU = &models.CPUInfo{
			Vendor:  p.Vendor,
			Model:   p.Model,
			Cores:   cpu.TotalCores,
			Threads: cpu.TotalThreads,
		}
	}

	// Memory
	mem, err := ghw.Memory()
	if err == nil && mem != nil {
		report.Memory = &models.MemoryInfo{
			TotalBytes: mem.TotalPhysicalBytes,
			// Not all systems expose bank details successfully, defaulting
		}
	}

	// GPU
	gpu, err := ghw.GPU()
	if err == nil && gpu != nil {
		for _, card := range gpu.GraphicsCards {
			if card.DeviceInfo != nil {
				vendor := "Unknown"
				product := "Unknown"
				if card.DeviceInfo.Vendor != nil {
					vendor = card.DeviceInfo.Vendor.Name
				}
				if card.DeviceInfo.Product != nil {
					product = card.DeviceInfo.Product.Name
				}
				report.GPUs = append(report.GPUs, models.GPUInfo{
					Vendor:  vendor,
					Product: product,
				})
			}
		}
	}

	// Network
	net, err := ghw.Network()
	if err == nil && net != nil {
		for _, nic := range net.NICs {
			// Skip virtual loopbacks
			if nic.IsVirtual {
				continue
			}

			vendor := "Unknown"
			product := "Unknown"
			
			if nic.PCIAddress != nil {
				pci, err := ghw.PCI()
				if err == nil && pci != nil {
					info := pci.GetDevice(*nic.PCIAddress)
					if info != nil {
						if info.Vendor != nil {
							vendor = info.Vendor.Name
						}
						if info.Product != nil {
							product = info.Product.Name
						}
					}
				}
			}

			report.Network = append(report.Network, models.NetworkInfo{
				Name:    nic.Name,
				MAC:     nic.MacAddress,
				Vendor:  vendor,
				Product: product,
			})
		}
	}

	// Storage Blocks
	block, err := ghw.Block()
	if err == nil && block != nil {
		for _, disk := range block.Disks {
			report.Storage = append(report.Storage, models.StorageInfo{
				Name:       disk.Name,
				Model:      disk.Model,
				SizeBytes:  disk.SizeBytes,
				DriveType:  disk.DriveType.String(),
				IsRemovable: disk.IsRemovable,
			})
		}
	}

	return report
}
