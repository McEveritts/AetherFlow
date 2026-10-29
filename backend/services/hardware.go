package services

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	metricsMu          sync.Mutex
	lastMetricsSample  models.SystemMetrics
	lastMetricsTime    time.Time
	minMetricsInterval = 800 * time.Millisecond

	lastValidCPUUsage   float64
	lastValidPerCoreCPU []float64
	lastCPUSampleTime   time.Time
	cachedCpuMhz        float64

	lastNetBytesRecv   uint64
	lastNetBytesSent   uint64
	lastNetCheck       time.Time
	lastDiskReadBytes  uint64
	lastDiskWriteBytes uint64
	lastDiskCheck      time.Time
	// Process cache — refreshed every 5 seconds to avoid expensive /proc scan each tick
	cachedProcesses      []models.ProcessInfo
	prevProcCPUTimes     map[int32]float64
	lastProcessScan      time.Time
	processCacheInterval = 5 * time.Second

	// GPU hardware metadata & live telemetry state
	cachedGPUs       []models.GpuMetric
	gpuScanned       bool
	nvidiaSmiChecked bool
	nvidiaSmiPath    string
	lastGpuRC6Ms     = make(map[string]uint64)
	lastGpuRC6Time   = make(map[string]time.Time)
)

func init() {
	// Prime CPU, disk, and network baseline counters at startup so the first
	// dashboard sample measures a real delta instead of returning zero.
	_, _ = cpu.Percent(0, true)
	lastCPUSampleTime = time.Now()

	if cpuInfos, err := cpu.Info(); err == nil && len(cpuInfos) > 0 {
		cachedCpuMhz = cpuInfos[0].Mhz
	}

	if diskIO, err := disk.IOCounters(); err == nil {
		for _, d := range diskIO {
			lastDiskReadBytes += d.ReadBytes
			lastDiskWriteBytes += d.WriteBytes
		}
		lastDiskCheck = time.Now()
	}

	if netIO, err := net.IOCounters(false); err == nil && len(netIO) > 0 {
		lastNetBytesRecv = netIO[0].BytesRecv
		lastNetBytesSent = netIO[0].BytesSent
		lastNetCheck = time.Now()
	}

	prevProcCPUTimes = make(map[int32]float64)
}

// sanitizeFloat64 clamps +Inf and NaN to 0 so json.Marshal never panics.
func sanitizeFloat64(v float64) float64 {
	if math.IsInf(v, 0) || math.IsNaN(v) {
		return 0
	}
	return v
}

// sanitizeFloat64Map sanitizes every value in a map[string]float64.
/* func sanitizeFloat64Map(m map[string]float64) {
	for k, v := range m {
		m[k] = sanitizeFloat64(v)
	}
} */

func GetSystemMetricsCore() models.SystemMetrics {
	metricsMu.Lock()
	defer metricsMu.Unlock()

	// Prevent concurrent or closely-spaced callers (WS broadcast loop, REST polling,
	// Prometheus exporter, background evaluators) from starving each other's OS
	// counter deltas and producing 0% CPU or 0 B/s network/disk readings.
	if !lastMetricsTime.IsZero() && time.Since(lastMetricsTime) < minMetricsInterval {
		return lastMetricsSample
	}

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

	// 1. Per-core & Aggregate CPU (single source of truth via cpu.Percent(0, true))
	cpuSampleElapsed := time.Since(lastCPUSampleTime)
	corePercents, err := cpu.Percent(0, true)
	lastCPUSampleTime = time.Now()
	if err == nil && len(corePercents) > 0 {
		allZero := true
		for i, pct := range corePercents {
			clamped := math.Min(100, math.Max(0, sanitizeFloat64(pct)))
			corePercents[i] = math.Round(clamped*10) / 10
			if corePercents[i] > 0 {
				allZero = false
			}
		}
		if !allZero || len(lastValidPerCoreCPU) == 0 {
			perCoreCPU = corePercents
			lastValidPerCoreCPU = append([]float64(nil), corePercents...)
		} else if cpuSampleElapsed < 350*time.Millisecond {
			// Sub-jiffy sample window: keep last valid per-core reading
			perCoreCPU = append([]float64(nil), lastValidPerCoreCPU...)
		} else {
			// Full sample window with 0 delta ticks: gently decay instead of freezing forever
			decayed := make([]float64, len(lastValidPerCoreCPU))
			for i, prev := range lastValidPerCoreCPU {
				next := math.Round(prev*0.5*10) / 10
				if next < 0.2 {
					next = 0
				}
				decayed[i] = next
			}
			perCoreCPU = decayed
			lastValidPerCoreCPU = append([]float64(nil), decayed...)
		}

		var sum float64
		for _, pct := range perCoreCPU {
			sum += pct
		}
		cpuUsage = math.Round((sum/float64(len(perCoreCPU)))*10) / 10
		lastValidCPUUsage = cpuUsage
	} else {
		// Fallback to aggregate CPU query if per-core is unavailable
		if cpuPercents, aggErr := cpu.Percent(0, false); aggErr == nil && len(cpuPercents) > 0 {
			cpuUsage = math.Round(math.Min(100, math.Max(0, sanitizeFloat64(cpuPercents[0])))*10) / 10
			lastValidCPUUsage = cpuUsage
		} else if lastValidCPUUsage > 0 {
			cpuUsage = lastValidCPUUsage
		}
		if len(lastValidPerCoreCPU) > 0 {
			perCoreCPU = append([]float64(nil), lastValidPerCoreCPU...)
		}
	}

	// 1c. CPU Frequency (Live Detection across online cores)
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
			if totalRead >= lastDiskReadBytes {
				readBytesPerSec = float64(totalRead-lastDiskReadBytes) / duration
			}
			if totalWrite >= lastDiskWriteBytes {
				writeBytesPerSec = float64(totalWrite-lastDiskWriteBytes) / duration
			}
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
			var recvDiff, sentDiff uint64
			if netIO[0].BytesRecv >= lastNetBytesRecv {
				recvDiff = netIO[0].BytesRecv - lastNetBytesRecv
			}
			if netIO[0].BytesSent >= lastNetBytesSent {
				sentDiff = netIO[0].BytesSent - lastNetBytesSent
			}
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
		scanNow := time.Now()
		scanDuration := scanNow.Sub(lastProcessScan).Seconds()
		if scanDuration < 0.1 {
			scanDuration = 0.1
		}
		nextProcCPUTimes := make(map[int32]float64)
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
				var cpuPct float64
				if times, err := p.Times(); err == nil && times != nil {
					totalProcTime := times.User + times.System
					nextProcCPUTimes[p.Pid] = totalProcTime
					if prevTime, ok := prevProcCPUTimes[p.Pid]; ok && !lastProcessScan.IsZero() && totalProcTime >= prevTime {
						cpuPct = ((totalProcTime - prevTime) / scanDuration) * 100.0
					} else if pct, err := p.CPUPercent(); err == nil {
						cpuPct = pct
					}
				} else if pct, err := p.CPUPercent(); err == nil {
					cpuPct = pct
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
		prevProcCPUTimes = nextProcCPUTimes
		lastProcessScan = scanNow
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

	// 8. GPUs (hardware scan cached once, live utilization/temp/memory updated each tick)
	if !gpuScanned {
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
				})
			}
		}
		cachedGPUs = gpuMetrics
		gpuScanned = true
	}
	if len(cachedGPUs) > 0 {
		cachedGPUs = updateGPUMetrics(cachedGPUs)
	}

	lastMetricsSample = models.SystemMetrics{
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
		GPUs:        cachedGPUs,
	}
	lastMetricsTime = time.Now()

	return lastMetricsSample
}

// getLiveCpuFreq reads the real-time CPU clock speed across online cores.
// It prioritizes Linux cpufreq sysfs (scaling_cur_freq / cpuinfo_cur_freq),
// then /proc/cpuinfo "cpu MHz", and finally falls back to gopsutil / cachedCpuMhz.
func getLiveCpuFreq() float64 {
	// 1. Linux sysfs - Average scaling_cur_freq across online cores
	for _, pattern := range []string{
		"/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq",
		"/sys/devices/system/cpu/cpu[0-9]*/cpufreq/cpuinfo_cur_freq",
	} {
		matches, err := filepath.Glob(pattern)
		if err == nil && len(matches) > 0 {
			var sumMhz float64
			var count int
			for _, p := range matches {
				data, rErr := os.ReadFile(p)
				if rErr != nil {
					continue
				}
				freqKHz, pErr := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
				if pErr == nil && freqKHz > 0 {
					sumMhz += freqKHz / 1000.0
					count++
				}
			}
			if count > 0 {
				return math.Round((sumMhz/float64(count))*10) / 10
			}
		}
	}

	// 2. Linux /proc/cpuinfo live "cpu MHz" lines averaged across cores
	if procData, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		var sumMhz float64
		var count int
		for _, line := range strings.Split(string(procData), "\n") {
			if strings.HasPrefix(line, "cpu MHz") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					if mhz, pErr := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); pErr == nil && mhz > 0 {
						sumMhz += mhz
						count++
					}
				}
			}
		}
		if count > 0 {
			return math.Round((sumMhz/float64(count))*10) / 10
		}
	}

	// 3. Fallback to gopsutil or cached startup MHz
	if cpuInfos, err := cpu.Info(); err == nil && len(cpuInfos) > 0 && cpuInfos[0].Mhz > 0 {
		cachedCpuMhz = cpuInfos[0].Mhz
		return cachedCpuMhz
	}

	return cachedCpuMhz
}

// readSysfsFloat reads a single numeric value from a sysfs file.
func readSysfsFloat(path string) (float64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// updateGPUMetrics refreshes live utilization, temperature, and VRAM telemetry for detected GPUs.
func updateGPUMetrics(gpus []models.GpuMetric) []models.GpuMetric {
	updated := make([]models.GpuMetric, len(gpus))
	copy(updated, gpus)

	// 1. Check NVIDIA GPUs via nvidia-smi if available
	if !nvidiaSmiChecked {
		if p, err := exec.LookPath("nvidia-smi"); err == nil {
			nvidiaSmiPath = p
		}
		nvidiaSmiChecked = true
	}
	nvidiaUpdated := make(map[int]bool)
	if nvidiaSmiPath != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		out, err := exec.CommandContext(
			ctx,
			nvidiaSmiPath,
			"--query-gpu=index,utilization.gpu,temperature.gpu,memory.used,memory.total",
			"--format=csv,noheader,nounits",
		).Output()
		cancel()
		if err == nil && len(out) > 0 {
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				fields := strings.Split(line, ",")
				if len(fields) < 5 {
					continue
				}
				idx, idxErr := strconv.Atoi(strings.TrimSpace(fields[0]))
				if idxErr != nil || idx < 0 || idx >= len(updated) {
					continue
				}
				util, _ := strconv.ParseFloat(strings.TrimSpace(fields[1]), 64)
				temp, _ := strconv.ParseFloat(strings.TrimSpace(fields[2]), 64)
				memUsed, _ := strconv.ParseFloat(strings.TrimSpace(fields[3]), 64)
				memTotal, _ := strconv.ParseFloat(strings.TrimSpace(fields[4]), 64)

				updated[idx].UsagePct = math.Round(math.Min(100, math.Max(0, sanitizeFloat64(util)))*10) / 10
				updated[idx].Temp = math.Round(sanitizeFloat64(temp)*10) / 10
				updated[idx].MemoryUsed = math.Round(sanitizeFloat64(memUsed)*10) / 10
				updated[idx].MemoryTotal = math.Round(sanitizeFloat64(memTotal)*10) / 10
				nvidiaUpdated[idx] = true
			}
		}
	}

	// 2. Check Linux DRM sysfs (/sys/class/drm/card*) for Intel (i915/xe) and AMD (amdgpu) GPUs
	cards, _ := filepath.Glob("/sys/class/drm/card[0-9]*")
	sort.Strings(cards)

	for i := range updated {
		if nvidiaUpdated[i] {
			continue
		}
		if i >= len(cards) {
			break
		}
		cardDir := cards[i]
		var usagePct float64
		var gotUsage bool

		// 2a. Direct gpu_busy_percent (AMD amdgpu / newer Intel DRM)
		if busy, ok := readSysfsFloat(filepath.Join(cardDir, "device/gpu_busy_percent")); ok {
			usagePct = math.Min(100, math.Max(0, busy))
			gotUsage = true
		}

		// 2b. Intel i915 / xe RC6 idle residency counter delta (e.g. HD Graphics 630)
		if !gotUsage {
			for _, rc6Rel := range []string{"gt/gt0/rc6_residency_ms", "power/rc6_residency_ms"} {
				rc6Path := filepath.Join(cardDir, rc6Rel)
				if rc6Val, ok := readSysfsFloat(rc6Path); ok && rc6Val >= 0 {
					now := time.Now()
					curRC6 := uint64(rc6Val)
					if prevTime, hasPrev := lastGpuRC6Time[rc6Path]; hasPrev {
						dtMs := float64(now.Sub(prevTime).Milliseconds())
						prevRC6 := lastGpuRC6Ms[rc6Path]
						if dtMs >= 50 && curRC6 >= prevRC6 {
							dRC6 := float64(curRC6 - prevRC6)
							busyPct := 100.0 * (1.0 - (dRC6 / dtMs))
							usagePct = math.Min(100, math.Max(0, busyPct))
							gotUsage = true
						}
					}
					lastGpuRC6Ms[rc6Path] = curRC6
					lastGpuRC6Time[rc6Path] = now
					break
				}
			}
		}

		// 2c. Intel i915 / xe frequency scaling fallback (cur_freq vs min/max freq)
		if !gotUsage || usagePct == 0 {
			var curFreq, minFreq, maxFreq float64
			for _, p := range []string{"gt_cur_freq_mhz", "gt/gt0/rps_cur_freq_mhz"} {
				if v, ok := readSysfsFloat(filepath.Join(cardDir, p)); ok && v > 0 {
					curFreq = v
					break
				}
			}
			for _, p := range []string{"gt_min_freq_mhz", "gt/gt0/rps_min_freq_mhz", "gt_RPn_freq_mhz"} {
				if v, ok := readSysfsFloat(filepath.Join(cardDir, p)); ok && v > 0 {
					minFreq = v
					break
				}
			}
			for _, p := range []string{"gt_max_freq_mhz", "gt/gt0/rps_max_freq_mhz", "gt_RP0_freq_mhz"} {
				if v, ok := readSysfsFloat(filepath.Join(cardDir, p)); ok && v > 0 {
					maxFreq = v
					break
				}
			}
			if maxFreq > minFreq && curFreq > minFreq {
				freqPct := ((curFreq - minFreq) / (maxFreq - minFreq)) * 100.0
				if freqPct > usagePct {
					usagePct = math.Min(100, math.Max(0, freqPct))
				}
			}
		}

		updated[i].UsagePct = math.Round(sanitizeFloat64(usagePct)*10) / 10

		// 2d. Dedicated VRAM via DRM mem_info_vram_* (bytes -> MB)
		if vramTotalBytes, ok := readSysfsFloat(filepath.Join(cardDir, "device/mem_info_vram_total")); ok && vramTotalBytes > 0 {
			updated[i].MemoryTotal = math.Round((vramTotalBytes/(1024*1024))*10) / 10
			if vramUsedBytes, okUsed := readSysfsFloat(filepath.Join(cardDir, "device/mem_info_vram_used")); okUsed && vramUsedBytes >= 0 {
				updated[i].MemoryUsed = math.Round((vramUsedBytes/(1024*1024))*10) / 10
			}
		}

		// 2e. GPU / SoC Package Temperature (millidegrees C -> C)
		var tempC float64
		if hwmonMatches, _ := filepath.Glob(filepath.Join(cardDir, "device/hwmon/hwmon*/temp1_input")); len(hwmonMatches) > 0 {
			if milliC, ok := readSysfsFloat(hwmonMatches[0]); ok && milliC > 1000 {
				tempC = milliC / 1000.0
			}
		}
		if tempC == 0 {
			// Integrated GPUs share the CPU package thermal zone
			if tzMatches, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp"); len(tzMatches) > 0 {
				for _, tzPath := range tzMatches {
					if milliC, ok := readSysfsFloat(tzPath); ok && milliC >= 15000 && milliC <= 115000 {
						tempC = milliC / 1000.0
						break
					}
				}
			}
		}
		updated[i].Temp = math.Round(sanitizeFloat64(tempC)*10) / 10
	}

	return updated
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
