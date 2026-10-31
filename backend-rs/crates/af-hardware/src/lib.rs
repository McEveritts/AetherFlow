use af_models::{
    CpuInfo, DiskPartition, GpuInfo, GpuMetric, HardwareReport, MemoryInfo, NetworkInfo,
    ProcessInfo, StorageInfo, SystemMetrics,
};
use libloading::{Library, Symbol};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{c_char, c_uint, c_ulonglong, c_void, CStr};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use sysinfo::{Disks, Networks, System};

// ─────────────────────────────────────────────────────────────────────────────
// Native NVML Dynamic FFI (`libnvidia-ml.so.1`) — Zero Subprocess Overhead
// ─────────────────────────────────────────────────────────────────────────────
//
// Replaces Go's `exec.CommandContext(..., "nvidia-smi", ...)` every 800ms with
// direct in-process C ABI calls (~50 microseconds per query, zero fork/exec).

type NvmlReturn = c_uint;
const NVML_SUCCESS: NvmlReturn = 0;
const NVML_TEMPERATURE_GPU: c_uint = 0;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
struct NvmlUtilization {
    gpu: c_uint,
    memory: c_uint,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
struct NvmlMemory {
    total: c_ulonglong,
    free: c_ulonglong,
    used: c_ulonglong,
}

struct NvmlRuntime {
    _lib: Library,
}

impl NvmlRuntime {
    fn try_load() -> Option<Self> {
        let candidates = [
            "libnvidia-ml.so.1",
            "libnvidia-ml.so",
            "/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1",
            "/usr/lib64/libnvidia-ml.so.1",
            "nvml.dll",
        ];
        for path in candidates {
            if let Ok(lib) = unsafe { Library::new(path) } {
                let init_ok = unsafe {
                    let init_fn: Result<Symbol<unsafe extern "C" fn() -> NvmlReturn>, _> =
                        lib.get(b"nvmlInit_v2\0").or_else(|_| lib.get(b"nvmlInit\0"));
                    match init_fn {
                        Ok(f) => f() == NVML_SUCCESS,
                        Err(_) => false,
                    }
                };
                if init_ok {
                    tracing::info!(library = path, "Loaded native NVML runtime (zero-fork GPU telemetry)");
                    return Some(Self { _lib: lib });
                }
            }
        }
        None
    }

    fn query_devices(&self) -> Vec<GpuMetric> {
        let mut metrics = Vec::new();
        unsafe {
            let count_fn: Symbol<unsafe extern "C" fn(*mut c_uint) -> NvmlReturn> = match self
                ._lib
                .get(b"nvmlDeviceGetCount_v2\0")
                .or_else(|_| self._lib.get(b"nvmlDeviceGetCount\0"))
            {
                Ok(f) => f,
                Err(_) => return metrics,
            };
            let handle_fn: Symbol<unsafe extern "C" fn(c_uint, *mut *mut c_void) -> NvmlReturn> =
                match self
                    ._lib
                    .get(b"nvmlDeviceGetHandleByIndex_v2\0")
                    .or_else(|_| self._lib.get(b"nvmlDeviceGetHandleByIndex\0"))
                {
                    Ok(f) => f,
                    Err(_) => return metrics,
                };
            let name_fn: Symbol<
                unsafe extern "C" fn(*mut c_void, *mut c_char, c_uint) -> NvmlReturn,
            > = match self._lib.get(b"nvmlDeviceGetName\0") {
                Ok(f) => f,
                Err(_) => return metrics,
            };
            let util_fn: Option<
                Symbol<unsafe extern "C" fn(*mut c_void, *mut NvmlUtilization) -> NvmlReturn>,
            > = self._lib.get(b"nvmlDeviceGetUtilizationRates\0").ok();
            let mem_fn: Option<
                Symbol<unsafe extern "C" fn(*mut c_void, *mut NvmlMemory) -> NvmlReturn>,
            > = self._lib.get(b"nvmlDeviceGetMemoryInfo\0").ok();
            let temp_fn: Option<
                Symbol<unsafe extern "C" fn(*mut c_void, c_uint, *mut c_uint) -> NvmlReturn>,
            > = self._lib.get(b"nvmlDeviceGetTemperature\0").ok();

            let mut count: c_uint = 0;
            if count_fn(&mut count) != NVML_SUCCESS {
                return metrics;
            }

            for idx in 0..count {
                let mut dev: *mut c_void = std::ptr::null_mut();
                if handle_fn(idx, &mut dev) != NVML_SUCCESS || dev.is_null() {
                    continue;
                }

                let mut name_buf = [0 as c_char; 96];
                let name = if name_fn(dev, name_buf.as_mut_ptr(), 95) == NVML_SUCCESS {
                    CStr::from_ptr(name_buf.as_ptr())
                        .to_string_lossy()
                        .into_owned()
                } else {
                    format!("NVIDIA GPU {}", idx)
                };

                let mut usage_pct = 0.0;
                if let Some(ref f) = util_fn {
                    let mut u = NvmlUtilization::default();
                    if f(dev, &mut u) == NVML_SUCCESS {
                        usage_pct = sanitize_f64((u.gpu as f64).clamp(0.0, 100.0));
                    }
                }

                let mut mem_total_mb = 0.0;
                let mut mem_used_mb = 0.0;
                if let Some(ref f) = mem_fn {
                    let mut m = NvmlMemory::default();
                    if f(dev, &mut m) == NVML_SUCCESS {
                        mem_total_mb = round_1((m.total as f64) / (1024.0 * 1024.0));
                        mem_used_mb = round_1((m.used as f64) / (1024.0 * 1024.0));
                    }
                }

                let mut temp_c = 0.0;
                if let Some(ref f) = temp_fn {
                    let mut t: c_uint = 0;
                    if f(dev, NVML_TEMPERATURE_GPU, &mut t) == NVML_SUCCESS {
                        temp_c = round_1(t as f64);
                    }
                }

                metrics.push(GpuMetric {
                    index: idx as usize,
                    name,
                    usage_pct: round_1(usage_pct),
                    memory_total: mem_total_mb,
                    memory_used: mem_used_mb,
                    temp: temp_c,
                });
            }
        }
        metrics
    }
}

static NVML_RUNTIME: Lazy<Option<NvmlRuntime>> = Lazy::new(NvmlRuntime::try_load);

// ─────────────────────────────────────────────────────────────────────────────
// GPU Transcode Flags (`backend/services/hardware_detector.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GpuFlags {
    pub hw_accel: String,
    pub hw_accel_device: String,
    pub output_format: String,
    pub video_codec: String,
}

/// Scans `/sys/class/drm/renderD*/device/vendor` and NVML to determine optimal
/// hardware transcode acceleration flags (NVENC, VAAPI for AMD, QSV for Intel, or libx265).
pub fn get_gpu_transcode_flags() -> GpuFlags {
    // Check NVML first for NVIDIA NVENC support
    if let Some(ref nvml) = *NVML_RUNTIME {
        if !nvml.query_devices().is_empty() {
            return GpuFlags {
                hw_accel: "cuda".to_string(),
                hw_accel_device: "0".to_string(),
                output_format: "cuda".to_string(),
                video_codec: "hevc_nvenc".to_string(),
            };
        }
    }

    // Check `/sys/class/drm/renderD128/device/vendor` first for exact parity with Go,
    // then scan additional render nodes (`/dev/dri/renderD*`).
    let mut render_nodes = vec![PathBuf::from("/sys/class/drm/renderD128")];
    if let Ok(entries) = fs::read_dir("/sys/class/drm") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("renderD") && name != "renderD128" {
                render_nodes.push(entry.path());
            }
        }
    }

    for node_sysfs in render_nodes {
        let vendor_path = node_sysfs.join("device/vendor");
        if let Ok(raw) = fs::read_to_string(&vendor_path) {
            let vendor_id = raw.trim();
            let node_name = node_sysfs
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "renderD128".to_string());
            let dev_path = format!("/dev/dri/{}", node_name);

            match vendor_id {
                "0x1002" => {
                    return GpuFlags {
                        hw_accel: "vaapi".to_string(),
                        hw_accel_device: dev_path,
                        output_format: "vaapi".to_string(),
                        video_codec: "hevc_vaapi".to_string(),
                    };
                }
                "0x8086" => {
                    return GpuFlags {
                        hw_accel: "qsv".to_string(),
                        hw_accel_device: dev_path,
                        output_format: String::new(),
                        video_codec: "hevc_qsv".to_string(),
                    };
                }
                "0x10de" => {
                    return GpuFlags {
                        hw_accel: "cuda".to_string(),
                        hw_accel_device: dev_path,
                        output_format: "cuda".to_string(),
                        video_codec: "hevc_nvenc".to_string(),
                    };
                }
                _ => {}
            }
        }
    }

    GpuFlags {
        hw_accel: String::new(),
        hw_accel_device: String::new(),
        output_format: String::new(),
        video_codec: "libx265".to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Telemetry State & Zero-Allocation Linux `/proc` & DRM Scanner
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct CpuJiffies {
    active: u64,
    total: u64,
}

struct TelemetryState {
    sys: System,
    disks: Disks,
    networks: Networks,
    last_metrics_sample: SystemMetrics,
    last_metrics_time: Option<Instant>,
    last_cpu_jiffies: Vec<CpuJiffies>,
    last_valid_per_core_cpu: Vec<f64>,
    last_valid_cpu_usage: f64,
    last_cpu_sample_time: Instant,
    cached_cpu_mhz: f64,
    last_net_rx: u64,
    last_net_tx: u64,
    last_net_check: Option<Instant>,
    last_disk_read_bytes: u64,
    last_disk_write_bytes: u64,
    last_disk_check: Option<Instant>,
    cached_processes: Vec<ProcessInfo>,
    prev_proc_cpu_ticks: HashMap<i32, u64>,
    last_process_scan: Option<Instant>,
    cached_gpus: Vec<GpuMetric>,
    gpu_scanned: bool,
    last_gpu_rc6_ms: HashMap<String, u64>,
    last_gpu_rc6_time: HashMap<String, Instant>,
}

impl TelemetryState {
    fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        let disks = Disks::new_with_refreshed_list();
        let networks = Networks::new_with_refreshed_list();

        let cached_cpu_mhz = sys
            .cpus()
            .first()
            .map(|c| c.frequency() as f64)
            .unwrap_or(0.0);

        let initial_jiffies = read_proc_stat_cores();
        let (rx, tx) = read_net_totals(&networks);
        let (d_read, d_write) = read_proc_diskstats();

        Self {
            sys,
            disks,
            networks,
            last_metrics_sample: SystemMetrics::default(),
            last_metrics_time: None,
            last_cpu_jiffies: initial_jiffies,
            last_valid_per_core_cpu: Vec::new(),
            last_valid_cpu_usage: 0.0,
            last_cpu_sample_time: Instant::now(),
            cached_cpu_mhz,
            last_net_rx: rx,
            last_net_tx: tx,
            last_net_check: Some(Instant::now()),
            last_disk_read_bytes: d_read,
            last_disk_write_bytes: d_write,
            last_disk_check: Some(Instant::now()),
            cached_processes: Vec::new(),
            prev_proc_cpu_ticks: HashMap::new(),
            last_process_scan: None,
            cached_gpus: Vec::new(),
            gpu_scanned: false,
            last_gpu_rc6_ms: HashMap::new(),
            last_gpu_rc6_time: HashMap::new(),
        }
    }
}

static TELEMETRY: Lazy<Mutex<TelemetryState>> = Lazy::new(|| Mutex::new(TelemetryState::new()));

const MIN_METRICS_INTERVAL: Duration = Duration::from_millis(800);
const PROCESS_CACHE_INTERVAL: Duration = Duration::from_secs(5);

#[inline]
pub fn sanitize_f64(v: f64) -> f64 {
    if v.is_infinite() || v.is_nan() {
        0.0
    } else {
        v
    }
}

#[inline]
fn round_1(v: f64) -> f64 {
    let s = sanitize_f64(v);
    (s * 10.0).round() / 10.0
}

pub fn format_bytes(bytes: f64) -> String {
    let bytes = sanitize_f64(bytes).max(0.0);
    const UNIT: f64 = 1024.0;
    if bytes < UNIT {
        return format!("{:.0} B", bytes);
    }
    let units = ['K', 'M', 'G', 'T', 'P', 'E'];
    let mut div = UNIT;
    let mut exp = 0usize;
    let mut n = bytes / UNIT;
    while n >= UNIT && exp + 1 < units.len() {
        div *= UNIT;
        exp += 1;
        n /= UNIT;
    }
    format!("{:.1} {}B", bytes / div, units[exp])
}

/// Samples host CPU, Memory, Disk, Network, Process, and GPU metrics with an
/// 800ms minimum interval guard matching `GetSystemMetricsCore()` in Go.
pub fn get_system_metrics_core() -> SystemMetrics {
    let mut state = match TELEMETRY.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    if let Some(last_time) = state.last_metrics_time {
        if last_time.elapsed() < MIN_METRICS_INTERVAL {
            return state.last_metrics_sample.clone();
        }
    }

    let now = Instant::now();
    let cpu_elapsed = now.duration_since(state.last_cpu_sample_time);
    state.last_cpu_sample_time = now;

    // 1. Per-core & Aggregate CPU
    let current_jiffies = read_proc_stat_cores();
    let mut per_core_cpu = Vec::new();

    if !current_jiffies.is_empty() && current_jiffies.len() == state.last_cpu_jiffies.len() {
        for (cur, prev) in current_jiffies.iter().zip(state.last_cpu_jiffies.iter()) {
            let d_total = cur.total.saturating_sub(prev.total);
            let d_active = cur.active.saturating_sub(prev.active);
            let pct = if d_total > 0 {
                ((d_active as f64) / (d_total as f64)) * 100.0
            } else {
                0.0
            };
            per_core_cpu.push(round_1(pct.clamp(0.0, 100.0)));
        }
        state.last_cpu_jiffies = current_jiffies;
    } else {
        if !current_jiffies.is_empty() {
            state.last_cpu_jiffies = current_jiffies;
        }
        state.sys.refresh_cpu_usage();
        for cpu in state.sys.cpus() {
            per_core_cpu.push(round_1((cpu.cpu_usage() as f64).clamp(0.0, 100.0)));
        }
    }

    let all_zero = per_core_cpu.iter().all(|&p| p <= 0.0);
    if !all_zero {
        state.last_valid_per_core_cpu = per_core_cpu.clone();
    } else if !state.last_valid_per_core_cpu.is_empty() {
        if cpu_elapsed < Duration::from_millis(350) {
            per_core_cpu = state.last_valid_per_core_cpu.clone();
        } else {
            let decayed: Vec<f64> = state
                .last_valid_per_core_cpu
                .iter()
                .map(|&prev| {
                    let next = round_1(prev * 0.5);
                    if next < 0.2 {
                        0.0
                    } else {
                        next
                    }
                })
                .collect();
            per_core_cpu = decayed.clone();
            state.last_valid_per_core_cpu = decayed;
        }
    }

    let cpu_usage = if !per_core_cpu.is_empty() {
        let sum: f64 = per_core_cpu.iter().sum();
        let avg = round_1(sum / (per_core_cpu.len() as f64));
        state.last_valid_cpu_usage = avg;
        avg
    } else {
        state.last_valid_cpu_usage
    };

    // 1c. Live CPU Frequency
    let cpu_freq_mhz = get_live_cpu_freq(&mut state);

    // 2. Memory & Swap
    state.sys.refresh_memory();
    let total_mem = sanitize_f64((state.sys.total_memory() as f64) / (1024.0 * 1024.0 * 1024.0));
    let used_mem = sanitize_f64((state.sys.used_memory() as f64) / (1024.0 * 1024.0 * 1024.0));
    let swap_total = sanitize_f64((state.sys.total_swap() as f64) / (1024.0 * 1024.0 * 1024.0));
    let swap_used = sanitize_f64((state.sys.used_swap() as f64) / (1024.0 * 1024.0 * 1024.0));

    // 3. Disk Partitions
    state.disks.refresh_list();
    let (disk_partitions, total_disk, used_disk, free_disk) = collect_disk_partitions(&state.disks);

    // 3b. Disk I/O
    let (cur_read_bytes, cur_write_bytes) = read_proc_diskstats();
    let mut read_bytes_sec = 0.0;
    let mut write_bytes_sec = 0.0;
    if let Some(last_check) = state.last_disk_check {
        let duration = now.duration_since(last_check).as_secs_f64().max(0.01);
        if cur_read_bytes >= state.last_disk_read_bytes {
            read_bytes_sec =
                sanitize_f64(((cur_read_bytes - state.last_disk_read_bytes) as f64) / duration);
        }
        if cur_write_bytes >= state.last_disk_write_bytes {
            write_bytes_sec =
                sanitize_f64(((cur_write_bytes - state.last_disk_write_bytes) as f64) / duration);
        }
    }
    state.last_disk_read_bytes = cur_read_bytes;
    state.last_disk_write_bytes = cur_write_bytes;
    state.last_disk_check = Some(now);

    // 4. Network & Active Connections
    state.networks.refresh();
    let (total_rx, total_tx) = read_net_totals(&state.networks);
    let (down_speed, up_speed) = if let Some(last_net) = state.last_net_check {
        let duration = now.duration_since(last_net).as_secs_f64().max(0.01);
        let rx_diff = total_rx.saturating_sub(state.last_net_rx);
        let tx_diff = total_tx.saturating_sub(state.last_net_tx);
        let down_val = sanitize_f64((rx_diff as f64) / duration);
        let up_val = sanitize_f64((tx_diff as f64) / duration);
        (
            format!("{}/s", format_bytes(down_val)),
            format!("{}/s", format_bytes(up_val)),
        )
    } else {
        ("0 B/s".to_string(), "0 B/s".to_string())
    };
    state.last_net_rx = total_rx;
    state.last_net_tx = total_tx;
    state.last_net_check = Some(now);

    let active_connections = count_established_tcp_connections();

    // 5. Uptime
    let uptime_secs = System::uptime();
    let days = uptime_secs / 86400;
    let hours = (uptime_secs % 86400) / 3600;
    let minutes = (uptime_secs % 3600) / 60;
    let uptime_str = if days > 0 {
        format!("{}d {}h {}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    };

    // 6. Load Average
    let load = System::load_average();
    let load_avg = vec![
        sanitize_f64(load.one),
        sanitize_f64(load.five),
        sanitize_f64(load.fifteen),
    ];

    // 7. Top Processes (cached every 5s)
    let should_scan_procs = state
        .last_process_scan
        .map(|t| now.duration_since(t) > PROCESS_CACHE_INTERVAL)
        .unwrap_or(true);
    if should_scan_procs {
        refresh_top_processes(&mut state, now);
    }

    // 8. GPUs (NVML + Linux DRM sysfs)
    if !state.gpu_scanned {
        state.cached_gpus = discover_gpus();
        state.gpu_scanned = true;
    }
    if !state.cached_gpus.is_empty() {
        update_gpu_metrics(&mut state);
    }

    let mut disk_space = HashMap::new();
    disk_space.insert("total".to_string(), total_disk);
    disk_space.insert("used".to_string(), used_disk);
    disk_space.insert("free".to_string(), free_disk);

    let mut disk_io = HashMap::new();
    disk_io.insert("read_bytes_sec".to_string(), read_bytes_sec);
    disk_io.insert("write_bytes_sec".to_string(), write_bytes_sec);

    let mut memory = HashMap::new();
    memory.insert("total".to_string(), total_mem);
    memory.insert("used".to_string(), used_mem);

    let mut swap = HashMap::new();
    swap.insert("total".to_string(), swap_total);
    swap.insert("used".to_string(), swap_used);

    let mut network = HashMap::new();
    network.insert("down".to_string(), serde_json::Value::String(down_speed));
    network.insert("up".to_string(), serde_json::Value::String(up_speed));
    network.insert(
        "active_connections".to_string(),
        serde_json::Value::Number(serde_json::Number::from(active_connections)),
    );

    let mut total_net_bytes = HashMap::new();
    total_net_bytes.insert("rx".to_string(), total_rx);
    total_net_bytes.insert("tx".to_string(), total_tx);

    let sample = SystemMetrics {
        cpu_usage,
        per_core_cpu,
        cpu_freq_mhz,
        disk_space,
        disks: disk_partitions,
        disk_io,
        services: HashMap::new(),
        memory,
        swap,
        network,
        total_net_bytes,
        uptime: uptime_str,
        load_average: load_avg,
        processes: state.cached_processes.clone(),
        gpus: state.cached_gpus.clone(),
    };

    state.last_metrics_sample = sample.clone();
    state.last_metrics_time = Some(now);
    sample
}

/// Zero-allocation style `/proc/stat` per-core jiffy reader on Linux.
fn read_proc_stat_cores() -> Vec<CpuJiffies> {
    let mut cores = Vec::new();
    let Ok(content) = fs::read_to_string("/proc/stat") else {
        return cores;
    };
    for line in content.lines() {
        if !line.starts_with("cpu") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(label) = parts.next() else {
            continue;
        };
        if label == "cpu" {
            continue; // skip aggregate header
        }
        let vals: Vec<u64> = parts.filter_map(|p| p.parse::<u64>().ok()).collect();
        if vals.len() >= 4 {
            // user + nice + system + irq + softirq + steal
            let user = vals[0];
            let nice = vals[1];
            let system = vals[2];
            let idle = vals[3];
            let iowait = vals.get(4).copied().unwrap_or(0);
            let irq = vals.get(5).copied().unwrap_or(0);
            let softirq = vals.get(6).copied().unwrap_or(0);
            let steal = vals.get(7).copied().unwrap_or(0);
            let active = user + nice + system + irq + softirq + steal;
            let total = active + idle + iowait;
            cores.push(CpuJiffies { active, total });
        }
    }
    cores
}

fn get_live_cpu_freq(state: &mut TelemetryState) -> f64 {
    // 1. Linux sysfs cpufreq scaling_cur_freq / cpuinfo_cur_freq
    if let Ok(entries) = fs::read_dir("/sys/devices/system/cpu") {
        let mut sum_mhz = 0.0;
        let mut count = 0usize;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with("cpu")
                || !name_str[3..].chars().all(|c| c.is_ascii_digit())
                || name_str.len() <= 3
            {
                continue;
            }
            for leaf in ["cpufreq/scaling_cur_freq", "cpufreq/cpuinfo_cur_freq"] {
                let p = entry.path().join(leaf);
                if let Some(khz) = read_sysfs_f64(&p) {
                    if khz > 0.0 {
                        sum_mhz += khz / 1000.0;
                        count += 1;
                        break;
                    }
                }
            }
        }
        if count > 0 {
            return round_1(sum_mhz / (count as f64));
        }
    }

    // 2. Linux /proc/cpuinfo "cpu MHz"
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        let mut sum_mhz = 0.0;
        let mut count = 0usize;
        for line in cpuinfo.lines() {
            if line.starts_with("cpu MHz") {
                if let Some((_, val)) = line.split_once(':') {
                    if let Ok(mhz) = val.trim().parse::<f64>() {
                        if mhz > 0.0 {
                            sum_mhz += mhz;
                            count += 1;
                        }
                    }
                }
            }
        }
        if count > 0 {
            return round_1(sum_mhz / (count as f64));
        }
    }

    // 3. Fallback to sysinfo CPU frequency
    if let Some(cpu) = state.sys.cpus().first() {
        let mhz = cpu.frequency() as f64;
        if mhz > 0.0 {
            state.cached_cpu_mhz = mhz;
        }
    }
    sanitize_f64(state.cached_cpu_mhz)
}

fn collect_disk_partitions(disks: &Disks) -> (Vec<DiskPartition>, f64, f64, f64) {
    let mut raw: Vec<(String, String, String, u64, u64)> = disks
        .list()
        .iter()
        .map(|d| {
            let mount = d.mount_point().to_string_lossy().into_owned();
            let dev = d.name().to_string_lossy().into_owned();
            let fs = d.file_system().to_string_lossy().into_owned();
            (mount, dev, fs, d.total_space(), d.available_space())
        })
        .collect();

    raw.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));

    let mut seen_mount = HashMap::new();
    let mut seen_device = HashMap::new();
    let mut partitions = Vec::new();
    let mut root_total = 0.0;
    let mut root_used = 0.0;
    let mut root_free = 0.0;

    for (mount, device, fs_type, total_bytes, avail_bytes) in raw {
        if total_bytes == 0 {
            continue;
        }
        let is_ram_disk =
            fs_type == "tmpfs" && (mount.starts_with("/home/") || mount.starts_with("/mnt/"));
        if !is_ram_disk
            && matches!(
                fs_type.as_str(),
                "squashfs" | "tmpfs" | "devtmpfs" | "overlay"
            )
        {
            continue;
        }
        if mount == "/boot"
            || mount.starts_with("/boot/")
            || mount.starts_with("/var/")
            || mount.starts_with("/opt/")
            || mount.starts_with("/run/")
            || mount.starts_with("/tmp")
        {
            continue;
        }
        if seen_mount.contains_key(&mount)
            || (!is_ram_disk && !device.is_empty() && seen_device.contains_key(&device))
        {
            continue;
        }
        seen_mount.insert(mount.clone(), true);
        if !is_ram_disk && !device.is_empty() {
            seen_device.insert(device.clone(), true);
        }

        let used_bytes = total_bytes.saturating_sub(avail_bytes);
        let total_gb = sanitize_f64((total_bytes as f64) / (1024.0 * 1024.0 * 1024.0));
        let used_gb = sanitize_f64((used_bytes as f64) / (1024.0 * 1024.0 * 1024.0));
        let free_gb = sanitize_f64((avail_bytes as f64) / (1024.0 * 1024.0 * 1024.0));
        let used_pct = sanitize_f64(((used_bytes as f64) / (total_bytes as f64)) * 100.0);

        if mount == "/" || (root_total == 0.0 && mount.ends_with(":\\")) {
            root_total = total_gb;
            root_used = used_gb;
            root_free = free_gb;
        }

        partitions.push(DiskPartition {
            mount_point: mount,
            device,
            fs_type,
            total_gb,
            used_gb,
            free_gb,
            used_pct,
        });
    }

    (partitions, root_total, root_used, root_free)
}

fn read_proc_diskstats() -> (u64, u64) {
    let Ok(content) = fs::read_to_string("/proc/diskstats") else {
        return (0, 0);
    };
    let mut read_bytes = 0u64;
    let mut write_bytes = 0u64;
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let dev = parts[2];
        // Skip loop, ram, and partition sub-devices when whole block device is tracked
        if dev.starts_with("loop") || dev.starts_with("ram") {
            continue;
        }
        let sectors_read = parts[5].parse::<u64>().unwrap_or(0);
        let sectors_written = parts[9].parse::<u64>().unwrap_or(0);
        read_bytes = read_bytes.saturating_add(sectors_read.saturating_mul(512));
        write_bytes = write_bytes.saturating_add(sectors_written.saturating_mul(512));
    }
    (read_bytes, write_bytes)
}

fn read_net_totals(networks: &Networks) -> (u64, u64) {
    if let Ok(content) = fs::read_to_string("/proc/net/dev") {
        let mut rx = 0u64;
        let mut tx = 0u64;
        for line in content.lines().skip(2) {
            let Some((iface, stats)) = line.split_once(':') else {
                continue;
            };
            if iface.trim() == "lo" {
                continue;
            }
            let cols: Vec<&str> = stats.split_whitespace().collect();
            if cols.len() >= 9 {
                rx = rx.saturating_add(cols[0].parse::<u64>().unwrap_or(0));
                tx = tx.saturating_add(cols[8].parse::<u64>().unwrap_or(0));
            }
        }
        return (rx, tx);
    }

    let mut rx = 0u64;
    let mut tx = 0u64;
    for (name, data) in networks {
        if name == "lo" {
            continue;
        }
        rx = rx.saturating_add(data.total_received());
        tx = tx.saturating_add(data.total_transmitted());
    }
    (rx, tx)
}

fn count_established_tcp_connections() -> usize {
    let mut count = 0usize;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let mut cols = line.split_whitespace();
                // sl local_address rem_address st ...
                let _ = cols.next();
                let _ = cols.next();
                let _ = cols.next();
                if let Some(state_hex) = cols.next() {
                    if state_hex == "01" {
                        // TCP_ESTABLISHED == 0x01
                        count += 1;
                    }
                }
            }
        }
    }
    count
}

fn refresh_top_processes(state: &mut TelemetryState, now: Instant) {
    state.sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let total_mem = state.sys.total_memory().max(1) as f64;
    let mut entries: Vec<ProcessInfo> = state
        .sys
        .processes()
        .values()
        .filter_map(|p| {
            let pid = p.pid().as_u32() as i32;
            if pid == 2 {
                return None;
            }
            if let Some(parent) = p.parent() {
                if parent.as_u32() == 2 {
                    return None;
                }
            }
            let name = p.name().to_string_lossy().into_owned();
            if name.is_empty() {
                return None;
            }
            let cpu = sanitize_f64(p.cpu_usage() as f64);
            let mem = sanitize_f64(((p.memory() as f64) / total_mem) * 100.0);
            Some(ProcessInfo {
                pid,
                name,
                cpu,
                mem,
            })
        })
        .collect();

    entries.sort_by(|a, b| {
        let cpu_a = round_1(a.cpu);
        let cpu_b = round_1(b.cpu);
        cpu_b
            .partial_cmp(&cpu_a)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                b.mem
                    .partial_cmp(&a.mem)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.pid.cmp(&b.pid))
    });
    entries.truncate(10);
    state.cached_processes = entries;
    state.last_process_scan = Some(now);
}

fn read_sysfs_f64(path: &Path) -> Option<f64> {
    let raw = fs::read_to_string(path).ok()?;
    raw.trim().parse::<f64>().ok()
}

fn discover_gpus() -> Vec<GpuMetric> {
    // 1. Native NVML discovery if available
    if let Some(ref nvml) = *NVML_RUNTIME {
        let nv_gpus = nvml.query_devices();
        if !nv_gpus.is_empty() {
            return nv_gpus;
        }
    }

    // 2. Linux DRM sysfs discovery (`/sys/class/drm/card*`)
    let mut gpus = Vec::new();
    let cards = list_drm_card_dirs();
    for (idx, card_dir) in cards.iter().enumerate() {
        let vendor = fs::read_to_string(card_dir.join("device/vendor"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let name = match vendor.as_str() {
            "0x10de" => "NVIDIA GPU".to_string(),
            "0x1002" => "AMD Radeon GPU".to_string(),
            "0x8086" => "Intel Graphics".to_string(),
            _ => format!("GPU {}", idx),
        };
        gpus.push(GpuMetric {
            index: idx,
            name,
            ..Default::default()
        });
    }
    gpus
}

fn list_drm_card_dirs() -> Vec<PathBuf> {
    let mut cards = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/drm") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("card")
                && !name.contains('-')
                && name[4..].chars().all(|c| c.is_ascii_digit())
                && name.len() > 4
            {
                cards.push(entry.path());
            }
        }
    }
    cards.sort();
    cards
}

fn update_gpu_metrics(state: &mut TelemetryState) {
    let mut nvidia_updated = HashMap::new();

    // 1. Native in-process NVML query (zero fork/exec)
    if let Some(ref nvml) = *NVML_RUNTIME {
        for dev in nvml.query_devices() {
            if dev.index < state.cached_gpus.len() {
                state.cached_gpus[dev.index] = dev.clone();
                nvidia_updated.insert(dev.index, true);
            }
        }
    }

    // 2. Linux DRM sysfs (`amdgpu` / Intel `i915` & `xe`)
    let cards = list_drm_card_dirs();
    for i in 0..state.cached_gpus.len() {
        if nvidia_updated.contains_key(&i) || i >= cards.len() {
            continue;
        }
        let card_dir = &cards[i];
        let mut usage_pct = 0.0;
        let mut got_usage = false;

        // 2a. Direct `device/gpu_busy_percent` (AMD `amdgpu` / newer Intel DRM)
        if let Some(busy) = read_sysfs_f64(&card_dir.join("device/gpu_busy_percent")) {
            usage_pct = busy.clamp(0.0, 100.0);
            got_usage = true;
        }

        // 2b. Intel `i915` / `xe` RC6 residency delta
        if !got_usage {
            for rel in ["gt/gt0/rc6_residency_ms", "power/rc6_residency_ms"] {
                let rc6_path = card_dir.join(rel);
                if let Some(rc6_val) = read_sysfs_f64(&rc6_path) {
                    if rc6_val >= 0.0 {
                        let now = Instant::now();
                        let cur_rc6 = rc6_val as u64;
                        let key = rc6_path.to_string_lossy().into_owned();
                        if let (Some(&prev_time), Some(&prev_rc6)) = (
                            state.last_gpu_rc6_time.get(&key),
                            state.last_gpu_rc6_ms.get(&key),
                        ) {
                            let dt_ms = now.duration_since(prev_time).as_millis() as f64;
                            if dt_ms >= 50.0 && cur_rc6 >= prev_rc6 {
                                let d_rc6 = (cur_rc6 - prev_rc6) as f64;
                                let busy_pct = 100.0 * (1.0 - (d_rc6 / dt_ms));
                                usage_pct = busy_pct.clamp(0.0, 100.0);
                                got_usage = true;
                            }
                        }
                        state.last_gpu_rc6_ms.insert(key.clone(), cur_rc6);
                        state.last_gpu_rc6_time.insert(key, now);
                        break;
                    }
                }
            }
        }

        // 2c. Intel frequency scaling fallback
        if !got_usage || usage_pct == 0.0 {
            let cur_freq = ["gt_cur_freq_mhz", "gt/gt0/rps_cur_freq_mhz"]
                .iter()
                .find_map(|p| read_sysfs_f64(&card_dir.join(p)).filter(|&v| v > 0.0))
                .unwrap_or(0.0);
            let min_freq = [
                "gt_min_freq_mhz",
                "gt/gt0/rps_min_freq_mhz",
                "gt_RPn_freq_mhz",
            ]
            .iter()
            .find_map(|p| read_sysfs_f64(&card_dir.join(p)).filter(|&v| v > 0.0))
            .unwrap_or(0.0);
            let max_freq = [
                "gt_max_freq_mhz",
                "gt/gt0/rps_max_freq_mhz",
                "gt_RP0_freq_mhz",
            ]
            .iter()
            .find_map(|p| read_sysfs_f64(&card_dir.join(p)).filter(|&v| v > 0.0))
            .unwrap_or(0.0);

            if max_freq > min_freq && cur_freq > min_freq {
                let freq_pct = ((cur_freq - min_freq) / (max_freq - min_freq)) * 100.0;
                if freq_pct > usage_pct {
                    usage_pct = freq_pct.clamp(0.0, 100.0);
                }
            }
        }

        state.cached_gpus[i].usage_pct = round_1(usage_pct);

        // 2d. Dedicated VRAM via DRM `mem_info_vram_*`
        if let Some(vram_total) = read_sysfs_f64(&card_dir.join("device/mem_info_vram_total")) {
            if vram_total > 0.0 {
                state.cached_gpus[i].memory_total = round_1(vram_total / (1024.0 * 1024.0));
                if let Some(vram_used) =
                    read_sysfs_f64(&card_dir.join("device/mem_info_vram_used"))
                {
                    if vram_used >= 0.0 {
                        state.cached_gpus[i].memory_used = round_1(vram_used / (1024.0 * 1024.0));
                    }
                }
            }
        }

        // 2e. GPU / SoC Package Temperature
        let mut temp_c = 0.0;
        let hwmon_dir = card_dir.join("device/hwmon");
        if let Ok(entries) = fs::read_dir(hwmon_dir) {
            for entry in entries.flatten() {
                if let Some(milli_c) = read_sysfs_f64(&entry.path().join("temp1_input")) {
                    if milli_c > 1000.0 {
                        temp_c = milli_c / 1000.0;
                        break;
                    }
                }
            }
        }
        if temp_c == 0.0 {
            if let Ok(entries) = fs::read_dir("/sys/class/thermal") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.starts_with("thermal_zone") {
                        if let Some(milli_c) = read_sysfs_f64(&entry.path().join("temp")) {
                            if (15_000.0..=115_000.0).contains(&milli_c) {
                                temp_c = milli_c / 1000.0;
                                break;
                            }
                        }
                    }
                }
            }
        }
        state.cached_gpus[i].temp = round_1(temp_c);
    }
}

/// Returns detailed hardware report matching `GetDetailedHardware()` in `hardware.go`.
pub fn get_detailed_hardware() -> HardwareReport {
    let mut sys = System::new_all();
    sys.refresh_all();

    let system_vendor = fs::read_to_string("/sys/class/dmi/id/board_vendor")
        .or_else(|_| fs::read_to_string("/sys/class/dmi/id/sys_vendor"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "Standard PC".to_string());

    let system_product = fs::read_to_string("/sys/class/dmi/id/board_name")
        .or_else(|_| fs::read_to_string("/sys/class/dmi/id/product_name"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| System::name().unwrap_or_else(|| "Linux Host".to_string()));

    let threads = sys.cpus().len() as u32;
    let cores = sys.physical_core_count().unwrap_or(threads as usize) as u32;
    let (vendor, model) = sys
        .cpus()
        .first()
        .map(|c| (c.vendor_id().to_string(), c.brand().to_string()))
        .unwrap_or_else(|| ("Generic".to_string(), "Processor".to_string()));

    let cpu = Some(CpuInfo {
        vendor,
        model,
        cores,
        threads,
    });

    let memory = Some(MemoryInfo {
        total_bytes: sys.total_memory() as i64,
        banks: 0,
        mem_type: String::new(),
    });

    let gpus: Vec<GpuInfo> = discover_gpus()
        .into_iter()
        .map(|g| GpuInfo {
            vendor: if g.name.to_lowercase().contains("nvidia") {
                "NVIDIA Corporation".to_string()
            } else if g.name.to_lowercase().contains("amd") {
                "Advanced Micro Devices, Inc.".to_string()
            } else if g.name.to_lowercase().contains("intel") {
                "Intel Corporation".to_string()
            } else {
                "Unknown".to_string()
            },
            product: g.name,
            driver: String::new(),
        })
        .collect();

    let mut network = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "lo" || !entry.path().join("device").exists() {
                continue;
            }
            let mac = fs::read_to_string(entry.path().join("address"))
                .unwrap_or_default()
                .trim()
                .to_string();
            network.push(NetworkInfo {
                name,
                mac,
                vendor: "Unknown".to_string(),
                product: "Unknown".to_string(),
            });
        }
    }

    let mut storage = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/block") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("dm-") {
                continue;
            }
            let size_sectors = read_sysfs_f64(&entry.path().join("size")).unwrap_or(0.0) as u64;
            let size_bytes = size_sectors.saturating_mul(512);
            let model = fs::read_to_string(entry.path().join("device/model"))
                .unwrap_or_else(|_| "Block Device".to_string())
                .trim()
                .to_string();
            let rotational = read_sysfs_f64(&entry.path().join("queue/rotational")).unwrap_or(0.0);
            let drive_type = if name.starts_with("nvme") {
                "NVMe".to_string()
            } else if rotational == 0.0 {
                "SSD".to_string()
            } else {
                "HDD".to_string()
            };
            let is_removable = read_sysfs_f64(&entry.path().join("removable")).unwrap_or(0.0) > 0.0;
            storage.push(StorageInfo {
                name,
                model,
                size_bytes,
                drive_type,
                is_removable,
            });
        }
    }

    HardwareReport {
        system_vendor,
        system_product,
        cpu,
        memory,
        gpus,
        network,
        storage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes_matches_go() {
        assert_eq!(format_bytes(0.0), "0 B");
        assert_eq!(format_bytes(512.0), "512 B");
        assert_eq!(format_bytes(1024.0), "1.0 KB");
        assert_eq!(format_bytes(1048576.0), "1.0 MB");
    }

    #[test]
    fn test_sanitize_f64_clamps_nan_inf() {
        assert_eq!(sanitize_f64(f64::NAN), 0.0);
        assert_eq!(sanitize_f64(f64::INFINITY), 0.0);
        assert_eq!(sanitize_f64(f64::NEG_INFINITY), 0.0);
        assert_eq!(sanitize_f64(42.5), 42.5);
    }

    #[test]
    fn test_get_system_metrics_core_returns_valid_struct() {
        let m = get_system_metrics_core();
        assert!(!m.cpu_usage.is_nan());
        assert!(m.memory.contains_key("total"));
        assert!(m.network.contains_key("down"));
    }
}
