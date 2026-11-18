//! Measured host storage capacity with an observed-file fallback.
use crate::tabs::contracts;
use serde_json::Value;
#[derive(Clone, Debug, PartialEq)]
pub(super) struct StorageUsage {
    pub(super) used_bytes: u64,
    pub(super) total_bytes: Option<u64>,
    pub(super) source: Option<String>,
}
impl StorageUsage {
    pub(super) fn percent(&self) -> Option<f64> {
        self.total_bytes
            .filter(|total| *total > 0)
            .map(|total| (self.used_bytes as f64 / total as f64 * 100.0).clamp(0.0, 100.0))
    }
}
pub(super) fn host_storage(value: &Value, observed_file_bytes: u64) -> StorageUsage {
    // The adapter accepts partial frames and converts to the shared host model.
    let telemetry = contracts::decode::<contracts::Telemetry>(value);
    let metrics = serde_json::from_value::<af_web_core::models::SystemMetrics>(value.clone())
        .unwrap_or_else(|_| telemetry.metrics());
    let valid = |disk: &&af_web_core::models::DiskPartition| {
        disk.total_gb.is_finite()
            && disk.total_gb > 0.0
            && disk.used_gb.is_finite()
            && disk.used_gb >= 0.0
    };
    let measured = metrics
        .disks
        .iter()
        .filter(|disk| {
            telemetry.disks.iter().any(|source| {
                source.mount_point == disk.mount_point
                    && source.total_gb.is_some()
                    && source.used_gb.is_some()
            })
        })
        .collect::<Vec<_>>();
    let partition = measured
        .iter()
        .copied()
        .filter(valid)
        .find(|disk| disk.mount_point == "/")
        .or_else(|| {
            measured
                .iter()
                .copied()
                .filter(valid)
                .max_by(|a, b| a.total_gb.total_cmp(&b.total_gb))
        });
    let from_gib = |number: f64| (number * 1_073_741_824.0) as u64;
    if let Some(disk) = partition {
        return StorageUsage {
            used_bytes: from_gib(disk.used_gb),
            total_bytes: Some(from_gib(disk.total_gb)),
            source: Some(disk.mount_point.clone()),
        };
    }
    // disk_space counters are GiB, matching the host's total_gb/used_gb.
    if let Some((total, used)) = metrics
        .disk_space
        .get("total")
        .zip(metrics.disk_space.get("used"))
        .filter(|(total, used)| {
            total.is_finite() && **total > 0.0 && used.is_finite() && **used >= 0.0
        })
    {
        return StorageUsage {
            used_bytes: from_gib(*used),
            total_bytes: Some(from_gib(*total)),
            source: None,
        };
    }
    StorageUsage {
        used_bytes: observed_file_bytes,
        total_bytes: None,
        source: None,
    }
}
