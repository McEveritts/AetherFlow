//! Typed telemetry adapters and history samples shared by the overview widgets.
#[cfg(test)]
use af_web_core::models::{DiskPartition, GpuMetric};
use af_web_core::models::{HardwareReport, ProcessInfo, SystemMetrics};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};

pub(super) fn number(value: &Value, paths: &[&str]) -> Option<f64> {
    paths.iter().find_map(|path| {
        let value = value.pointer(path)?;
        value
            .as_f64()
            .or_else(|| value.as_str()?.parse().ok())
            .filter(|n| n.is_finite())
    })
}
pub(super) fn raw_text(value: &Value, paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|path| {
        let value = value.pointer(path)?;
        value
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| value.as_number().map(ToString::to_string))
    })
}
pub(super) fn text(locale: &str, value: &Value, paths: &[&str]) -> String {
    af_web_core::i18n::translate(
        locale,
        &raw_text(value, paths).unwrap_or_else(|| "Unavailable".into()),
    )
}
pub(super) fn list(value: &Value, paths: &[&str]) -> Vec<Value> {
    paths
        .iter()
        .find_map(|path| value.pointer(path).and_then(Value::as_array).cloned())
        .unwrap_or_default()
}
pub(super) fn telemetry_row<T: DeserializeOwned + Serialize>(mut row: Value) -> Value {
    if let Ok(typed) = serde_json::from_value::<T>(row.clone()) {
        if let (Some(fields), Ok(Value::Object(canonical))) =
            (row.as_object_mut(), serde_json::to_value(typed))
        {
            fields.extend(canonical);
        }
    }
    row
}
pub(super) fn process_row(row: Value) -> Value {
    let mut row = telemetry_row::<ProcessInfo>(row);
    row["cpu"] = json!(number(&row, &["/cpu", "/cpu_pct", "/cpu_usage"]));
    row["mem"] = json!(number(
        &row,
        &["/mem", "/memory_pct", "/mem_pct", "/memory"]
    ));
    row
}
// Canonical host reports use bytes and a numeric bank count; older fixtures
// expose GiB and per-bank arrays. Keep both shapes usable by the view.
pub(super) fn hardware_profile(value: &Value) -> Value {
    let mut report = value.clone();
    if value.is_object() {
        let hardware: HardwareReport = crate::tabs::contracts::hardware(value);
        if let Some(memory) = hardware.memory {
            if memory.total_bytes > 0 {
                report["memory"]["total_gb"] = json!(memory.total_bytes as f64 / 1_073_741_824.0);
            }
            report["memory"]["bank_count"] = json!(memory.banks);
        }
        if !hardware.storage.is_empty() || value["storage"].is_array() {
            report["storage"] = json!(hardware.storage);
        }
    } else if let Some(total) = number(value, &["/memory/total_bytes"]) {
        report["memory"]["total_gb"] = json!(total / 1_073_741_824.0);
    }
    report
}
pub(super) fn metrics_cpu(value: &Value) -> Option<f64> {
    serde_json::from_value::<crate::tabs::contracts::Telemetry>(value.clone())
        .ok()
        .and_then(|metrics| metrics.cpu_usage)
        .filter(|n| n.is_finite())
        .or_else(|| number(value, &["/cpu_avg", "/cpu_usage", "/cpu/usage", "/cpu"]))
}
pub(super) fn metrics_memory(value: &Value) -> Option<f64> {
    if let Ok(telemetry) =
        serde_json::from_value::<crate::tabs::contracts::Telemetry>(value.clone())
    {
        let metrics: SystemMetrics = telemetry.metrics();
        let counter = |field: &str| {
            metrics
                .memory
                .get(&format!("{field}_bytes"))
                .map(|n| n / 1_073_741_824.0)
                .or_else(|| metrics.memory.get(&format!("{field}_gb")).copied())
                .or_else(|| metrics.memory.get(field).copied())
                .filter(|n| n.is_finite())
        };
        if let Some(usage) = ratio(counter("used"), counter("total")) {
            return Some(usage);
        }
    }
    number(value, &["/memory_pct", "/mem_pct"]).or_else(|| {
        ratio(
            number(value, &["/mem_used_gb"]).or_else(|| gib(value, "memory", "used")),
            number(value, &["/mem_total_gb"]).or_else(|| gib(value, "memory", "total")),
        )
    })
}
pub(super) fn percent(value: Option<f64>) -> String {
    value
        .map(|n| format!("{n:.1}%"))
        .unwrap_or_else(|| "—".into())
}
pub(super) fn ratio(used: Option<f64>, total: Option<f64>) -> Option<f64> {
    used.zip(total)
        .filter(|(_, total)| *total > 0.0)
        .map(|(used, total)| used / total * 100.0)
}
pub(super) fn gib(value: &Value, kind: &str, field: &str) -> Option<f64> {
    number(value, &[&format!("/{kind}/{field}_bytes")])
        .map(|n| n / 1_073_741_824.0)
        .or_else(|| {
            number(
                value,
                &[&format!("/{kind}/{field}_gb"), &format!("/{kind}/{field}")],
            )
        })
}
pub(super) fn bytes(locale: &str, value: Option<f64>) -> String {
    let Some(mut value) = value else {
        return af_web_core::i18n::translate(locale, "Unavailable");
    };
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", units[unit])
}
pub(super) fn rate(locale: &str, value: Option<f64>) -> String {
    let Some(value) = value else {
        return "—".into();
    };
    if value * 8.0 >= 1_000_000_000.0 {
        format!("{:.2} Gbps", value * 8.0 / 1_000_000_000.0)
    } else {
        format!("{}/s", bytes(locale, Some(value)))
    }
}
pub(super) fn parse_rate(value: &Value) -> Option<f64> {
    if let Some(n) = value.as_f64().filter(|n| n.is_finite()) {
        return Some(n);
    }
    let raw = value.as_str()?.trim();
    let split = raw
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-' && c != '+')
        .unwrap_or(raw.len());
    let n: f64 = raw[..split].parse().ok()?;
    let unit = raw[split..].trim();
    let multiplier = match unit.to_ascii_lowercase().as_str() {
        "kb/s" | "kib/s" => 1024.0,
        "mb/s" | "mib/s" => 1_048_576.0,
        "gb/s" | "gib/s" => 1_073_741_824.0,
        "kbps" => 1000.0,
        "mbps" => 1_000_000.0,
        "gbps" => 1_000_000_000.0,
        "b/s" | "bps" | "" => 1.0,
        _ => return None,
    };
    let n = n * multiplier
        / if unit.ends_with("bps") && !unit.contains('B') {
            8.0
        } else {
            1.0
        };
    (n.is_finite() && n >= 0.0).then_some(n)
}
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Sample {
    pub(super) at: f64,
    pub(super) cpu: Option<f64>,
    pub(super) memory: Option<f64>,
    pub(super) rx: Option<f64>,
    pub(super) tx: Option<f64>,
    pub(super) read: Option<f64>,
    pub(super) write: Option<f64>,
    pub(super) rx_total: Option<f64>,
    pub(super) tx_total: Option<f64>,
}
impl Sample {
    pub(super) fn parse(value: &Value, live: bool) -> Option<Self> {
        let at = value
            .get("timestamp")
            .or_else(|| value.get("recorded_at"))
            .and_then(|v| {
                v.as_f64()
                    .map(|n| if n < 1e12 { n * 1000.0 } else { n })
                    .or_else(|| v.as_str().map(js_sys::Date::parse))
            })
            .or_else(|| live.then(js_sys::Date::now))?;
        if !at.is_finite() {
            return None;
        }
        Some(Self {
            at,
            cpu: metrics_cpu(value),
            memory: metrics_memory(value),
            rx: number(value, &["/net_rx_bps", "/network/rx_bps"])
                .or_else(|| parse_rate(&value["network"]["down"])),
            tx: number(value, &["/net_tx_bps", "/network/tx_bps"])
                .or_else(|| parse_rate(&value["network"]["up"])),
            read: number(
                value,
                &["/disk_read_bps", "/disk_io/read_bps", "/disk_io/read"],
            )
            .or_else(|| parse_rate(&value["disk_io"]["read_speed"])),
            write: number(
                value,
                &["/disk_write_bps", "/disk_io/write_bps", "/disk_io/write"],
            )
            .or_else(|| parse_rate(&value["disk_io"]["write_speed"])),
            rx_total: number(
                value,
                &[
                    "/net_rx_bytes",
                    "/total_net_bytes/rx",
                    "/network/received_bytes",
                ],
            ),
            tx_total: number(
                value,
                &[
                    "/net_tx_bytes",
                    "/total_net_bytes/tx",
                    "/network/transmitted_bytes",
                ],
            ),
        })
    }
    pub(super) fn metric(&self, key: &str) -> Option<f64> {
        match key {
            "memory" => self.memory,
            "rx" => self.rx,
            "tx" => self.tx,
            "read" => self.read,
            "write" => self.write,
            _ => self.cpu,
        }
    }
}
pub(super) fn counter_delta(previous: Option<f64>, current: Option<f64>) -> Option<f64> {
    previous
        .zip(current)
        .filter(|(a, b)| *a >= 0.0 && b >= a)
        .map(|(a, b)| b - a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_telemetry_rows_preserve_extra_fields_and_legacy_counters() {
        let mut process = serde_json::to_value(ProcessInfo {
            pid: 42,
            name: "jellyfin".into(),
            cpu: 12.5,
            mem: 4.0,
        })
        .unwrap();
        process["future_counter"] = json!(9);
        let row = process_row(process);
        assert_eq!(row["pid"], 42);
        assert_eq!(row["cpu"], 12.5);
        assert_eq!(row["future_counter"], 9);
        let legacy = process_row(json!({"pid":7,"name":"legacy","cpu_pct":"2.5","memory_pct":3}));
        assert_eq!(legacy["cpu"], 2.5);
        assert_eq!(legacy["mem"], 3.0);
        let mut gpu = serde_json::to_value(GpuMetric {
            index: 1,
            name: "GPU".into(),
            usage_pct: 25.0,
            memory_total: 8192.0,
            memory_used: 2048.0,
            temp: 48.0,
        })
        .unwrap();
        gpu["vendor_extension"] = json!("preserved");
        assert_eq!(
            telemetry_row::<GpuMetric>(gpu)["vendor_extension"],
            "preserved"
        );
        let disk = serde_json::to_value(DiskPartition {
            mount_point: "/".into(),
            device: "/dev/vda1".into(),
            fs_type: "ext4".into(),
            total_gb: 100.0,
            used_gb: 30.0,
            free_gb: 70.0,
            used_pct: 30.0,
        })
        .unwrap();
        assert_eq!(telemetry_row::<DiskPartition>(disk)["free_gb"], 70.0);
        let legacy_disk = json!({"mount":"/data","total_bytes":1024,"custom":true});
        assert_eq!(
            telemetry_row::<DiskPartition>(legacy_disk.clone()),
            legacy_disk
        );
    }

    #[test]
    fn hardware_contract_uses_bytes_bank_count_and_storage() {
        let hardware = HardwareReport {
            memory: Some(af_web_core::models::MemoryInfo {
                total_bytes: 64 * 1_073_741_824,
                banks: 4,
                mem_type: "DDR5".into(),
            }),
            storage: vec![af_web_core::models::StorageInfo {
                size_bytes: 512 * 1_073_741_824,
                model: "NVMe".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let value = hardware_profile(&serde_json::to_value(hardware).unwrap());
        assert_eq!(value["memory"]["total_gb"], 64.0);
        assert_eq!(value["memory"]["bank_count"], 4);
        assert_eq!(value["storage"][0]["size_bytes"], 512u64 * 1_073_741_824);
        assert_eq!(
            hardware_profile(&json!({"memory":{"total_gb":32}}))["memory"]["total_gb"],
            32
        );
        let legacy = hardware_profile(
            &json!({"system_vendor":"Host","system_product":"Server","disks":[{"model":"Legacy drive","size_gb":500}]}),
        );
        assert_eq!(
            list(&legacy, &["/storage", "/disks"])[0]["model"],
            "Legacy drive"
        );
    }

    #[test]
    fn metrics_contract_and_partial_samples_keep_real_measurements() {
        let metrics = SystemMetrics {
            cpu_usage: 23.5,
            memory: std::collections::HashMap::from([
                ("used_bytes".into(), 8.0 * 1_073_741_824.0),
                ("total_bytes".into(), 32.0 * 1_073_741_824.0),
            ]),
            ..Default::default()
        };
        let value = serde_json::to_value(metrics).unwrap();
        assert_eq!(metrics_cpu(&value), Some(23.5));
        assert_eq!(metrics_memory(&value), Some(25.0));
        let partial =
            json!({"timestamp": 1700000000, "cpu_avg": 11, "memory": {"used": 12, "total": 64}});
        let sample = Sample::parse(&partial, false).unwrap();
        assert_eq!(sample.at, 1_700_000_000_000.0);
        assert_eq!(sample.cpu, Some(11.0));
        assert_eq!(sample.memory, Some(18.75));
        assert_eq!(counter_delta(Some(10.0), Some(2.0)), None);
        assert_eq!(parse_rate(&json!("8Mbps")), Some(1_000_000.0));
        assert_eq!(ratio(Some(1.0), Some(0.0)), None);
    }
}
