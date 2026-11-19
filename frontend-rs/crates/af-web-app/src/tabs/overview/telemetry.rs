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
    row["cpu"] =
        json!(number(&row, &["/cpu", "/cpu_pct", "/cpu_usage"]).map(|v| (v * 10.0).round() / 10.0));
    row["mem"] = json!(
        number(&row, &["/mem", "/memory_pct", "/mem_pct", "/memory"])
            .map(|v| (v * 10.0).round() / 10.0)
    );
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
                report["memory"]["total_gb"] =
                    json!((memory.total_bytes as f64 / 1_073_741_824.0 * 10.0).round() / 10.0);
            }
            report["memory"]["bank_count"] = json!((memory.banks > 0).then_some(memory.banks));
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
    let Some(value) = value.filter(|v| v.is_finite() && *v >= 0.0) else {
        return af_web_core::i18n::translate(locale, "Unavailable");
    };
    af_web_core::charts::format_bytes_localized(value, locale)
}
pub(super) fn rate(locale: &str, value: Option<f64>) -> String {
    let Some(value) = value.filter(|v| v.is_finite() && *v >= 0.0) else {
        return "—".into();
    };
    af_web_core::charts::format_rate_localized(value, locale)
}
pub(super) fn parse_rate(value: &Value) -> Option<f64> {
    if let Some(n) = value.as_f64().filter(|n| n.is_finite() && *n >= 0.0) {
        return Some(n);
    }
    let raw = value.as_str()?.trim();
    if raw.is_empty() {
        return None;
    }
    let split = raw
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-' && c != '+')
        .unwrap_or(raw.len());
    let n: f64 = raw[..split].parse().ok()?;
    let unit = raw[split..].trim();
    let multiplier = match unit.to_ascii_lowercase().as_str() {
        "kb/s" | "kib/s" => 1024.0,
        "mb/s" | "mib/s" => 1_048_576.0,
        "gb/s" | "gib/s" => 1_073_741_824.0,
        "tb/s" | "tib/s" => 1_099_511_627_776.0,
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

pub(super) const MAX_HISTORY_SIZE: usize = 2400;
pub(super) const GAP_THRESHOLD_MS: f64 = 120_000.0;
pub(super) const MAX_COUNTER_DELTA_GAP_MS: f64 = 300_000.0;
pub(super) const DEDUP_WINDOW_MS: f64 = 250.0;
pub(super) const DAILY_GAP_THRESHOLD_MS: f64 = 1.5 * 86_400_000.0;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum TelemetryWindow {
    M1,
    #[default]
    M5,
    M15,
    H1,
    H6,
    H24,
}

impl TelemetryWindow {
    pub(super) const ALL: [Self; 6] =
        [Self::M1, Self::M5, Self::M15, Self::H1, Self::H6, Self::H24];

    pub(super) fn key(self) -> &'static str {
        match self {
            Self::M1 => "1m",
            Self::M5 => "5m",
            Self::M15 => "15m",
            Self::H1 => "1h",
            Self::H6 => "6h",
            Self::H24 => "24h",
        }
    }

    pub(super) fn span_ms(self) -> f64 {
        match self {
            Self::M1 => 60_000.0,
            Self::M5 => 5.0 * 60_000.0,
            Self::M15 => 15.0 * 60_000.0,
            Self::H1 => 60.0 * 60_000.0,
            Self::H6 => 6.0 * 60.0 * 60_000.0,
            Self::H24 => 24.0 * 60.0 * 60_000.0,
        }
    }

    #[cfg(any(test, target_arch = "wasm32"))]
    pub(super) fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "1m" => Some(Self::M1),
            "5m" => Some(Self::M5),
            "15m" => Some(Self::M15),
            "1h" => Some(Self::H1),
            "6h" => Some(Self::H6),
            "24h" | "1d" => Some(Self::H24),
            _ => None,
        }
    }

    pub(super) fn from_url_or_default() -> Self {
        #[cfg(target_arch = "wasm32")]
        {
            crate::state::query_param("window")
                .or_else(|| crate::state::query_param("range"))
                .and_then(|raw| Self::parse(&raw))
                .unwrap_or_default()
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Self::default()
        }
    }

    pub(super) fn history_url(self) -> String {
        format!(
            "/api/v1/auth/system/metrics/history?window={}&limit={MAX_HISTORY_SIZE}&downsample=1&target_points={MAX_HISTORY_SIZE}",
            self.key()
        )
    }

    pub(super) fn time_format(self) -> af_web_core::charts::ChartTimeFormat {
        match self {
            Self::H24 => af_web_core::charts::ChartTimeFormat::DateTime,
            _ => af_web_core::charts::ChartTimeFormat::Time,
        }
    }
}

pub(super) fn parse_timestamp_ms(value: &Value) -> Option<f64> {
    if let Some(n) = value.as_f64().filter(|n| n.is_finite() && *n > 0.0) {
        return Some(if n < 1e12 {
            (n * 1000.0).round()
        } else {
            n.round()
        });
    }
    value
        .as_str()
        .and_then(af_web_core::charts::parse_utc_timestamp_str_ms)
}

fn non_negative(value: Option<f64>) -> Option<f64> {
    value.filter(|n| n.is_finite() && *n >= 0.0)
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Sample {
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
    pub(crate) fn record_live(history: &mut Vec<Self>, metrics: &Value) {
        if !metrics.is_object() {
            return;
        }
        if let Some(sample) = Self::parse(metrics, true) {
            if history.last() == Some(&sample) {
                return;
            }
            history.push(sample);
            if history.len() > MAX_HISTORY_SIZE {
                history.drain(..history.len() - MAX_HISTORY_SIZE);
            }
        }
    }

    pub(super) fn parse(value: &Value, live: bool) -> Option<Self> {
        let now = if live {
            #[cfg(target_arch = "wasm32")]
            {
                Some(js_sys::Date::now())
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                None
            }
        } else {
            None
        };
        Self::parse_with_fallback_now(value, now)
    }

    pub(super) fn parse_with_fallback_now(
        value: &Value,
        fallback_now_ms: Option<f64>,
    ) -> Option<Self> {
        let at = value
            .get("timestamp")
            .or_else(|| value.get("recorded_at"))
            .and_then(parse_timestamp_ms)
            .or(fallback_now_ms)?;
        if !at.is_finite() || at <= 0.0 {
            return None;
        }
        Some(Self {
            at,
            cpu: non_negative(metrics_cpu(value)),
            memory: non_negative(metrics_memory(value)),
            rx: non_negative(number(
                value,
                &[
                    "/net_rx_bps",
                    "/net_down_bps",
                    "/network/rx_bps",
                    "/network/rx_bytes_sec",
                ],
            ))
            .or_else(|| parse_rate(&value["network"]["down"])),
            tx: non_negative(number(
                value,
                &[
                    "/net_tx_bps",
                    "/net_up_bps",
                    "/network/tx_bps",
                    "/network/tx_bytes_sec",
                ],
            ))
            .or_else(|| parse_rate(&value["network"]["up"])),
            read: non_negative(number(
                value,
                &[
                    "/disk_io/read_bytes_sec",
                    "/disk_read_bps",
                    "/disk_io/read_bps",
                    "/disk_io/read",
                ],
            ))
            .or_else(|| parse_rate(&value["disk_io"]["read_speed"])),
            write: non_negative(number(
                value,
                &[
                    "/disk_io/write_bytes_sec",
                    "/disk_write_bps",
                    "/disk_io/write_bps",
                    "/disk_io/write",
                ],
            ))
            .or_else(|| parse_rate(&value["disk_io"]["write_speed"])),
            rx_total: non_negative(number(
                value,
                &[
                    "/net_rx_bytes",
                    "/total_net_bytes/rx",
                    "/network/received_bytes",
                ],
            ))
            .or_else(|| non_negative(number(value, &["/net_rx_mb"])).map(|mb| mb * 1_048_576.0)),
            tx_total: non_negative(number(
                value,
                &[
                    "/net_tx_bytes",
                    "/total_net_bytes/tx",
                    "/network/transmitted_bytes",
                ],
            ))
            .or_else(|| non_negative(number(value, &["/net_tx_mb"])).map(|mb| mb * 1_048_576.0)),
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
        .filter(|(a, b)| a.is_finite() && b.is_finite() && *a >= 0.0 && b >= a)
        .map(|(a, b)| b - a)
}

/// Merge persisted and live samples with 250ms deduplication (preferring live),
/// gap-bounded counter-derived network rates (<= 5m gap, counter resets never
/// produce negative traffic), and exact requested window filtering.
pub(super) fn merge_samples(
    persisted: Vec<Sample>,
    live: Vec<Sample>,
    window: TelemetryWindow,
) -> Vec<Sample> {
    let mut tagged: Vec<(Sample, bool)> = persisted
        .into_iter()
        .map(|s| (s, false))
        .chain(live.into_iter().map(|s| (s, true)))
        .filter(|(s, _)| s.at.is_finite() && s.at > 0.0)
        .collect();
    if tagged.is_empty() {
        return vec![];
    }
    tagged
        .sort_by(|(a, a_live), (b, b_live)| a.at.total_cmp(&b.at).then_with(|| a_live.cmp(b_live)));
    let mut deduped: Vec<(Sample, bool)> = Vec::with_capacity(tagged.len());
    for (candidate, is_live) in tagged {
        if let Some((prev, prev_live)) = deduped.last_mut() {
            if (candidate.at - prev.at).abs() <= DEDUP_WINDOW_MS {
                if is_live || !*prev_live {
                    *prev = candidate;
                    *prev_live = is_live;
                }
                continue;
            }
        }
        deduped.push((candidate, is_live));
    }
    let mut samples: Vec<Sample> = deduped.into_iter().map(|(s, _)| s).collect();
    for i in 1..samples.len() {
        let dt_ms = samples[i].at - samples[i - 1].at;
        if dt_ms > 0.0 && dt_ms <= MAX_COUNTER_DELTA_GAP_MS {
            let elapsed = dt_ms / 1000.0;
            if samples[i].rx.is_none() {
                samples[i].rx = counter_delta(samples[i - 1].rx_total, samples[i].rx_total)
                    .map(|n| n / elapsed);
            }
            if samples[i].tx.is_none() {
                samples[i].tx = counter_delta(samples[i - 1].tx_total, samples[i].tx_total)
                    .map(|n| n / elapsed);
            }
        }
    }
    let span = window.span_ms();
    if let Some(latest) = samples.last().map(|s| s.at) {
        let cutoff = latest - span;
        samples.retain(|s| s.at >= cutoff);
    }
    if samples.len() > MAX_HISTORY_SIZE {
        samples.drain(..samples.len() - MAX_HISTORY_SIZE);
    }
    samples
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct CoverageSummary {
    pub(super) sample_count: usize,
    pub(super) observed_span_ms: f64,
    pub(super) requested_span_ms: f64,
    pub(super) gap_count: usize,
    pub(super) start_ms: Option<f64>,
    pub(super) end_ms: Option<f64>,
}

impl CoverageSummary {
    pub(super) fn is_sparse(&self) -> bool {
        self.sample_count < 2 || self.observed_span_ms <= 0.0
    }
}

pub(super) fn summarize_coverage(
    points: &[af_web_core::charts::Point],
    window: TelemetryWindow,
) -> CoverageSummary {
    let finite: Vec<_> = points
        .iter()
        .filter(|p| p.x.is_finite() && p.y.is_finite())
        .collect();
    let sample_count = finite.len();
    let start_ms = finite.first().map(|p| p.x);
    let end_ms = finite.last().map(|p| p.x);
    let observed_span_ms = match (start_ms, end_ms) {
        (Some(start), Some(end)) if end >= start => end - start,
        _ => 0.0,
    };
    let mut gap_count = 0usize;
    for pair in finite.windows(2) {
        if pair[1].x - pair[0].x > GAP_THRESHOLD_MS {
            gap_count += 1;
        }
    }
    CoverageSummary {
        sample_count,
        observed_span_ms,
        requested_span_ms: window.span_ms(),
        gap_count,
        start_ms,
        end_ms,
    }
}

pub(super) fn disk_io_share(read: Option<f64>, write: Option<f64>) -> (Option<f64>, Option<f64>) {
    let r = read.filter(|v| v.is_finite() && *v >= 0.0);
    let w = write.filter(|v| v.is_finite() && *v >= 0.0);
    match (r, w) {
        (Some(r), Some(w)) => {
            let total = r + w;
            if total > 0.0 {
                let read_pct = r / total * 100.0;
                (Some(read_pct), Some((100.0 - read_pct).max(0.0)))
            } else {
                (None, None)
            }
        }
        _ => (None, None),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct DailyUsage {
    pub(super) date: String,
    pub(super) date_ms: f64,
    pub(super) downloaded_bytes: Option<f64>,
    pub(super) uploaded_bytes: Option<f64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct DailyUsageSummary {
    pub(super) days: Vec<DailyUsage>,
    pub(super) duplicate_samples: usize,
    pub(super) conflicting_samples: usize,
    pub(super) invalid_samples: usize,
    pub(super) counter_resets: usize,
}

impl DailyUsageSummary {
    pub(super) fn has_measured_interval(&self) -> bool {
        self.days
            .iter()
            .any(|d| d.downloaded_bytes.is_some() || d.uploaded_bytes.is_some())
    }

    pub(super) fn total_downloaded(&self) -> Option<f64> {
        self.has_measured_interval()
            .then(|| self.days.iter().filter_map(|d| d.downloaded_bytes).sum())
    }

    pub(super) fn total_uploaded(&self) -> Option<f64> {
        self.has_measured_interval()
            .then(|| self.days.iter().filter_map(|d| d.uploaded_bytes).sum())
    }

    pub(super) fn chart_series(
        &self,
    ) -> (
        Vec<af_web_core::charts::Point>,
        Vec<af_web_core::charts::Point>,
    ) {
        let mut down = Vec::new();
        let mut up = Vec::new();
        for day in &self.days {
            if let Some(rx) = day.downloaded_bytes {
                down.push(af_web_core::charts::Point {
                    x: day.date_ms,
                    y: rx,
                });
            }
            if let Some(tx) = day.uploaded_bytes {
                up.push(af_web_core::charts::Point {
                    x: day.date_ms,
                    y: tx,
                });
            }
        }
        (down, up)
    }
}

#[derive(Clone)]
enum RawUsageSample {
    Valid {
        timestamp_ms: f64,
        date: String,
        date_ms: f64,
        rx_bytes: f64,
        tx_bytes: f64,
        source_index: usize,
    },
    Invalid {
        timestamp_ms: f64,
        source_index: usize,
    },
}

impl RawUsageSample {
    fn timestamp_ms(&self) -> f64 {
        match self {
            Self::Valid { timestamp_ms, .. } | Self::Invalid { timestamp_ms, .. } => *timestamp_ms,
        }
    }
    fn source_index(&self) -> usize {
        match self {
            Self::Valid { source_index, .. } | Self::Invalid { source_index, .. } => *source_index,
        }
    }
}

/// Derive truthful UTC daily transfer deltas without fabricating zero-valued
/// unobserved days. Handles duplicates, conflicting same-timestamp counters,
/// invalid samples, and counter resets identically to prior 109.1 semantics
/// while parsing legacy SQLite UTC timestamps timezone-independently.
pub(super) fn derive_daily_usage(rows: &[Value]) -> DailyUsageSummary {
    let mut parsed = Vec::with_capacity(rows.len());
    let mut invalid_samples = 0usize;

    for (source_index, row) in rows.iter().enumerate() {
        if !row.is_object() {
            invalid_samples += 1;
            continue;
        }
        let Some(timestamp_ms) = row
            .get("timestamp")
            .or_else(|| row.get("recorded_at"))
            .and_then(parse_timestamp_ms)
        else {
            invalid_samples += 1;
            continue;
        };
        let rx = row
            .get("net_rx_bytes")
            .and_then(Value::as_f64)
            .filter(|v| v.is_finite() && *v >= 0.0);
        let tx = row
            .get("net_tx_bytes")
            .and_then(Value::as_f64)
            .filter(|v| v.is_finite() && *v >= 0.0);
        let (Some(rx_bytes), Some(tx_bytes)) = (rx, tx) else {
            invalid_samples += 1;
            parsed.push(RawUsageSample::Invalid {
                timestamp_ms,
                source_index,
            });
            continue;
        };
        let Some(date) = af_web_core::charts::utc_date_from_ms(timestamp_ms) else {
            invalid_samples += 1;
            continue;
        };
        let Some(date_ms) = af_web_core::charts::parse_utc_timestamp_str_ms(&date) else {
            invalid_samples += 1;
            continue;
        };
        parsed.push(RawUsageSample::Valid {
            timestamp_ms,
            date,
            date_ms,
            rx_bytes,
            tx_bytes,
            source_index,
        });
    }

    parsed.sort_by(|a, b| {
        a.timestamp_ms()
            .total_cmp(&b.timestamp_ms())
            .then_with(|| a.source_index().cmp(&b.source_index()))
    });

    let mut by_date = std::collections::BTreeMap::<String, DailyUsage>::new();
    let mut previous: Option<(f64, f64)> = None;
    let mut duplicate_samples = 0usize;
    let mut conflicting_samples = 0usize;
    let mut counter_resets = 0usize;

    let mut i = 0;
    while i < parsed.len() {
        let ts = parsed[i].timestamp_ms();
        let start = i;
        while i < parsed.len() && parsed[i].timestamp_ms() == ts {
            i += 1;
        }
        let group = &parsed[start..i];
        if group
            .iter()
            .any(|entry| matches!(entry, RawUsageSample::Invalid { .. }))
        {
            previous = None;
            continue;
        }
        let RawUsageSample::Valid {
            date,
            date_ms,
            rx_bytes,
            tx_bytes,
            ..
        } = &group[0]
        else {
            previous = None;
            continue;
        };
        let conflict = group.iter().any(|entry| match entry {
            RawUsageSample::Valid {
                rx_bytes: r,
                tx_bytes: t,
                ..
            } => *r != *rx_bytes || *t != *tx_bytes,
            RawUsageSample::Invalid { .. } => true,
        });
        if conflict {
            conflicting_samples += 1;
            previous = None;
            continue;
        }
        duplicate_samples += group.len().saturating_sub(1);
        let day_entry = by_date.entry(date.clone()).or_insert_with(|| DailyUsage {
            date: date.clone(),
            date_ms: *date_ms,
            downloaded_bytes: None,
            uploaded_bytes: None,
        });
        if let Some((prev_rx, prev_tx)) = previous {
            let rx_reset = *rx_bytes < prev_rx;
            let tx_reset = *tx_bytes < prev_tx;
            if rx_reset {
                counter_resets += 1;
            }
            if tx_reset {
                counter_resets += 1;
            }
            let down_delta = if rx_reset {
                *rx_bytes
            } else {
                *rx_bytes - prev_rx
            };
            let up_delta = if tx_reset {
                *tx_bytes
            } else {
                *tx_bytes - prev_tx
            };
            day_entry.downloaded_bytes =
                Some(day_entry.downloaded_bytes.unwrap_or(0.0) + down_delta);
            day_entry.uploaded_bytes = Some(day_entry.uploaded_bytes.unwrap_or(0.0) + up_delta);
        }
        previous = Some((*rx_bytes, *tx_bytes));
    }

    DailyUsageSummary {
        days: by_date.into_values().collect(),
        duplicate_samples,
        conflicting_samples,
        invalid_samples,
        counter_resets,
    }
}

pub(super) fn daily_transfer_history_url(days: u32) -> String {
    format!("/api/v1/auth/system/metrics/history?days={days}&aggregate=daily_transfer")
}

pub(super) fn capacity_history_url() -> String {
    "/api/v1/admin/ai/predictions/history?days=30&aggregate=capacity".to_string()
}

/// Decode either the server-aggregated `aggregate=daily_transfer` object
/// (`{ days: [{ date, downloaded_bytes, uploaded_bytes }], counter_resets, ... }`)
/// or a legacy raw snapshot array into `DailyUsageSummary`.
pub(super) fn decode_daily_usage(payload: &Value) -> DailyUsageSummary {
    if let Some(days_arr) = payload
        .as_object()
        .and_then(|obj| obj.get("days"))
        .and_then(Value::as_array)
    {
        let mut by_date = std::collections::BTreeMap::<String, DailyUsage>::new();
        for entry in days_arr {
            let Some(raw_date) = entry.get("date").and_then(Value::as_str).map(str::trim) else {
                continue;
            };
            if raw_date.is_empty() {
                continue;
            }
            let Some(date_ms) = af_web_core::charts::parse_utc_timestamp_str_ms(raw_date) else {
                continue;
            };
            let date = af_web_core::charts::utc_date_from_ms(date_ms)
                .unwrap_or_else(|| raw_date.to_string());
            let downloaded_bytes = entry
                .get("downloaded_bytes")
                .and_then(Value::as_f64)
                .filter(|v| v.is_finite() && *v >= 0.0);
            let uploaded_bytes = entry
                .get("uploaded_bytes")
                .and_then(Value::as_f64)
                .filter(|v| v.is_finite() && *v >= 0.0);
            by_date.insert(
                date.clone(),
                DailyUsage {
                    date,
                    date_ms,
                    downloaded_bytes,
                    uploaded_bytes,
                },
            );
        }
        let count_field = |key: &str| {
            payload
                .get(key)
                .and_then(Value::as_u64)
                .map(|n| n as usize)
                .unwrap_or(0)
        };
        return DailyUsageSummary {
            days: by_date.into_values().collect(),
            duplicate_samples: count_field("duplicate_samples"),
            conflicting_samples: count_field("conflicting_samples"),
            invalid_samples: count_field("invalid_samples"),
            counter_resets: count_field("counter_resets"),
        };
    }
    derive_daily_usage(&crate::state::json_rows(payload))
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct CapacityHistorySeries {
    pub(super) cpu: Vec<af_web_core::charts::Point>,
    pub(super) memory: Vec<af_web_core::charts::Point>,
    pub(super) disk_io: Vec<af_web_core::charts::Point>,
    pub(super) network: Vec<af_web_core::charts::Point>,
    pub(super) observed_days: usize,
    pub(super) sample_count: usize,
}

/// Build bounded 30-day historical capacity plots for CPU, Memory, Disk I/O,
/// and counter-reset-safe Network throughput from persisted history rows.
pub(super) fn derive_capacity_history(rows: &[Value]) -> CapacityHistorySeries {
    use af_web_core::charts::{lttb, utc_date_from_ms, Point};
    let mut parsed: Vec<Sample> = rows
        .iter()
        .filter_map(|row| Sample::parse_with_fallback_now(row, None))
        .collect();
    if parsed.is_empty() {
        return CapacityHistorySeries::default();
    }
    parsed.sort_by(|a, b| a.at.total_cmp(&b.at));
    parsed.dedup_by(|a, b| a.at == b.at);

    let mut dates = std::collections::BTreeSet::new();
    let mut cpu = Vec::new();
    let mut memory = Vec::new();
    let mut disk_io = Vec::new();
    let mut network = Vec::new();

    for (i, sample) in parsed.iter().enumerate() {
        if let Some(day) = utc_date_from_ms(sample.at) {
            dates.insert(day);
        }
        if let Some(c) = sample.cpu {
            cpu.push(Point { x: sample.at, y: c });
        }
        if let Some(m) = sample.memory {
            memory.push(Point { x: sample.at, y: m });
        }
        if sample.read.is_some() || sample.write.is_some() {
            disk_io.push(Point {
                x: sample.at,
                y: sample.read.unwrap_or(0.0) + sample.write.unwrap_or(0.0),
            });
        }
        if let (Some(rx), Some(tx)) = (sample.rx, sample.tx) {
            network.push(Point {
                x: sample.at,
                y: rx + tx,
            });
        } else if i > 0 {
            let prev = &parsed[i - 1];
            let dt_sec = (sample.at - prev.at) / 1000.0;
            if dt_sec > 0.0 {
                let rx_d = counter_delta(prev.rx_total, sample.rx_total);
                let tx_d = counter_delta(prev.tx_total, sample.tx_total);
                if rx_d.is_some() || tx_d.is_some() {
                    network.push(Point {
                        x: sample.at,
                        y: (rx_d.unwrap_or(0.0) + tx_d.unwrap_or(0.0)) / dt_sec,
                    });
                }
            }
        }
    }

    CapacityHistorySeries {
        cpu: lttb(&cpu, 240),
        memory: lttb(&memory, 240),
        disk_io: lttb(&disk_io, 240),
        network: lttb(&network, 240),
        observed_days: dates.len(),
        sample_count: parsed.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_buffer_uses_measurement_time_for_all_metrics() {
        let m = serde_json::json!({"timestamp":"2026-11-01 05:59:45","cpu_usage":18,"disk_io":{"write_bytes_sec":42}});
        let mut samples = Vec::new();
        Sample::record_live(&mut samples, &m);
        Sample::record_live(&mut samples, &m);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].at, 1793512785000.0);
        assert_eq!(samples[0].cpu, Some(18.0));
        assert_eq!(samples[0].write, Some(42.0));
    }

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

    #[test]
    fn utc_history_merges_with_live_samples_without_timezone_shift() {
        let persisted_rows = [
            json!({"timestamp": "2026-11-19 05:22:00", "cpu_avg": 12.0, "mem_used_gb": 4.0, "mem_total_gb": 16.0}),
            json!({"timestamp": "2026-11-19 05:23:00", "cpu_avg": 14.0, "mem_used_gb": 4.5, "mem_total_gb": 16.0}),
            json!({"timestamp": "2026-11-19 05:24:00", "cpu_avg": 16.0, "mem_used_gb": 5.0, "mem_total_gb": 16.0}),
            json!({"timestamp": "2026-11-19 05:25:00", "cpu_avg": 18.0, "mem_used_gb": 5.5, "mem_total_gb": 16.0}),
            json!({"timestamp": "2026-11-19 05:25:42", "cpu_avg": 20.0, "mem_used_gb": 6.0, "mem_total_gb": 16.0}),
        ];
        let persisted: Vec<Sample> = persisted_rows
            .iter()
            .filter_map(|v| Sample::parse_with_fallback_now(v, None))
            .collect();
        assert_eq!(persisted.len(), 5);
        // Live sample arrives 18 seconds after 05:25:42 UTC (at 05:26:00 UTC).
        let live_now =
            af_web_core::charts::parse_utc_timestamp_str_ms("2026-11-19T05:26:00Z").unwrap();
        let live_sample = Sample::parse_with_fallback_now(
            &json!({"cpu_usage": 22.0, "memory": {"used": 6.0, "total": 16.0}}),
            Some(live_now),
        )
        .unwrap();
        assert_eq!(live_sample.at - persisted.last().unwrap().at, 18_000.0);
        let merged = merge_samples(persisted, vec![live_sample], TelemetryWindow::M5);
        assert_eq!(merged.len(), 6);
    }

    #[test]
    fn canonical_live_disk_io_fields_parse_nonzero_and_valid_zero_rates() {
        let now = 1_763_529_960_000.0;
        let active = Sample::parse_with_fallback_now(
            &json!({
                "cpu_usage": 15.0,
                "disk_io": { "read_bytes_sec": 4_194_304.0, "write_bytes_sec": 1_048_576.0 },
                "network": { "down": "2.5 MB/s", "up": "512 KB/s" }
            }),
            Some(now),
        )
        .unwrap();
        assert_eq!(active.read, Some(4_194_304.0));
        assert_eq!(active.write, Some(1_048_576.0));
        assert_eq!(active.rx, Some(2_621_440.0));
        assert_eq!(active.tx, Some(524_288.0));
        let (r_share, w_share) = disk_io_share(active.read, active.write);
        assert!((r_share.unwrap() - 80.0).abs() < 0.01);
        assert!((w_share.unwrap() - 20.0).abs() < 0.01);

        let idle = Sample::parse_with_fallback_now(
            &json!({
                "disk_io": { "read_bytes_sec": 0.0, "write_bytes_sec": 0.0 }
            }),
            Some(now + 1000.0),
        )
        .unwrap();
        assert_eq!(idle.read, Some(0.0));
        assert_eq!(idle.write, Some(0.0));
        assert_eq!(disk_io_share(idle.read, idle.write), (None, None));
    }

    #[test]
    fn all_six_telemetry_windows_enforce_actual_requested_span() {
        assert_eq!(TelemetryWindow::ALL.len(), 6);
        assert_eq!(TelemetryWindow::parse("1m"), Some(TelemetryWindow::M1));
        assert_eq!(TelemetryWindow::parse("5m"), Some(TelemetryWindow::M5));
        assert_eq!(TelemetryWindow::parse("15m"), Some(TelemetryWindow::M15));
        assert_eq!(TelemetryWindow::parse("1h"), Some(TelemetryWindow::H1));
        assert_eq!(TelemetryWindow::parse("6h"), Some(TelemetryWindow::H6));
        assert_eq!(TelemetryWindow::parse("24h"), Some(TelemetryWindow::H24));
        assert_eq!(TelemetryWindow::parse("invalid"), None);

        let base = 1_763_500_000_000.0;
        let samples = vec![
            Sample::parse_with_fallback_now(
                &json!({"timestamp": base - 7.0 * 3_600_000.0, "cpu_avg": 1.0}),
                None,
            )
            .unwrap(),
            Sample::parse_with_fallback_now(
                &json!({"timestamp": base - 2.0 * 3_600_000.0, "cpu_avg": 2.0}),
                None,
            )
            .unwrap(),
            Sample::parse_with_fallback_now(
                &json!({"timestamp": base - 20.0 * 60_000.0, "cpu_avg": 3.0}),
                None,
            )
            .unwrap(),
            Sample::parse_with_fallback_now(
                &json!({"timestamp": base - 10.0 * 60_000.0, "cpu_avg": 4.0}),
                None,
            )
            .unwrap(),
            Sample::parse_with_fallback_now(
                &json!({"timestamp": base - 2.0 * 60_000.0, "cpu_avg": 5.0}),
                None,
            )
            .unwrap(),
            Sample::parse_with_fallback_now(
                &json!({"timestamp": base - 30_000.0, "cpu_avg": 6.0}),
                None,
            )
            .unwrap(),
            Sample::parse_with_fallback_now(&json!({"timestamp": base, "cpu_avg": 7.0}), None)
                .unwrap(),
        ];
        assert_eq!(
            merge_samples(samples.clone(), vec![], TelemetryWindow::M1).len(),
            2
        );
        assert_eq!(
            merge_samples(samples.clone(), vec![], TelemetryWindow::M5).len(),
            3
        );
        assert_eq!(
            merge_samples(samples.clone(), vec![], TelemetryWindow::M15).len(),
            4
        );
        assert_eq!(
            merge_samples(samples.clone(), vec![], TelemetryWindow::H1).len(),
            5
        );
        assert_eq!(
            merge_samples(samples.clone(), vec![], TelemetryWindow::H6).len(),
            6
        );
        assert_eq!(
            merge_samples(samples, vec![], TelemetryWindow::H24).len(),
            7
        );
    }

    #[test]
    fn counter_derived_network_rates_ignore_large_gaps_and_resets() {
        let base = 1_763_500_000_000.0;
        let rows = vec![
            Sample::parse_with_fallback_now(&json!({"timestamp": base, "net_rx_bytes": 1000.0, "net_tx_bytes": 500.0}), None).unwrap(),
            Sample::parse_with_fallback_now(&json!({"timestamp": base + 60_000.0, "net_rx_bytes": 7000.0, "net_tx_bytes": 3500.0}), None).unwrap(),
            // Large gap (> 5m) -> must not fabricate averaged rate.
            Sample::parse_with_fallback_now(&json!({"timestamp": base + 660_000.0, "net_rx_bytes": 97000.0, "net_tx_bytes": 53500.0}), None).unwrap(),
            // Counter reset -> must not produce negative rate.
            Sample::parse_with_fallback_now(&json!({"timestamp": base + 720_000.0, "net_rx_bytes": 200.0, "net_tx_bytes": 100.0}), None).unwrap(),
        ];
        let merged = merge_samples(rows, vec![], TelemetryWindow::H1);
        assert_eq!(merged[1].rx, Some(100.0));
        assert_eq!(merged[1].tx, Some(50.0));
        assert_eq!(merged[2].rx, None);
        assert_eq!(merged[2].tx, None);
        assert_eq!(merged[3].rx, None);
        assert_eq!(merged[3].tx, None);
    }

    #[test]
    fn daily_usage_keeps_unobserved_and_zero_days_distinct_and_handles_resets_and_conflicts() {
        let rows = vec![
            // Day 1: two samples with zero delta (true zero transfer day)
            json!({"timestamp": "2026-11-10 01:00:00", "net_rx_bytes": 1000.0, "net_tx_bytes": 500.0}),
            json!({"timestamp": "2026-11-10 02:00:00", "net_rx_bytes": 1000.0, "net_tx_bytes": 500.0}),
            // Exact duplicate -> counted as duplicate, not conflict
            json!({"timestamp": "2026-11-10 02:00:00", "net_rx_bytes": 1000.0, "net_tx_bytes": 500.0}),
            // Day 2 (2026-11-11) intentionally UNOBSERVED -> must NOT appear in summary.days
            // Day 3: counter reset on rx (1000 -> 400) and normal growth on tx (500 -> 900)
            json!({"timestamp": "2026-11-12 03:00:00", "net_rx_bytes": 400.0, "net_tx_bytes": 900.0}),
            // Conflicting timestamp -> breaks continuity and increments conflicting_samples
            json!({"timestamp": "2026-11-13 00:10:00", "net_rx_bytes": 500.0, "net_tx_bytes": 1000.0}),
            json!({"timestamp": "2026-11-13 00:10:00", "net_rx_bytes": 999.0, "net_tx_bytes": 1000.0}),
            // Invalid negative sample
            json!({"timestamp": "2026-11-14 00:00:00", "net_rx_bytes": -5.0, "net_tx_bytes": 10.0}),
        ];
        let summary = derive_daily_usage(&rows);
        assert_eq!(summary.days.len(), 2);
        assert_eq!(summary.days[0].date, "2026-11-10");
        assert_eq!(summary.days[0].downloaded_bytes, Some(0.0));
        assert_eq!(summary.days[0].uploaded_bytes, Some(0.0));
        assert_eq!(summary.days[1].date, "2026-11-12");
        assert_eq!(summary.days[1].downloaded_bytes, Some(400.0));
        assert_eq!(summary.days[1].uploaded_bytes, Some(400.0));
        assert_eq!(summary.duplicate_samples, 1);
        assert_eq!(summary.conflicting_samples, 1);
        assert_eq!(summary.invalid_samples, 1);
        assert_eq!(summary.counter_resets, 1);
        assert_eq!(summary.total_downloaded(), Some(400.0));
        assert_eq!(summary.total_uploaded(), Some(400.0));

        // Single-sample day has no measured interval -> totals stay Unavailable (None).
        let single = derive_daily_usage(&[
            json!({"timestamp": "2026-11-15 12:00:00", "net_rx_bytes": 5000.0, "net_tx_bytes": 2000.0}),
        ]);
        assert_eq!(single.days.len(), 1);
        assert_eq!(single.days[0].downloaded_bytes, None);
        assert!(!single.has_measured_interval());
        assert_eq!(single.total_downloaded(), None);
    }

    #[test]
    fn capacity_history_builds_bounded_30_day_plots_safely() {
        let rows = vec![
            json!({"timestamp": "2026-11-01 00:00:00", "cpu_avg": 20.0, "mem_used_gb": 8.0, "mem_total_gb": 32.0, "disk_read_bps": 1000.0, "disk_write_bps": 500.0, "net_rx_bytes": 10_000.0, "net_tx_bytes": 5_000.0}),
            json!({"timestamp": "2026-11-02 00:00:00", "cpu_avg": 30.0, "mem_used_gb": 16.0, "mem_total_gb": 32.0, "disk_read_bps": 2000.0, "disk_write_bps": 1000.0, "net_rx_bytes": 96_400.0, "net_tx_bytes": 48_200.0}),
            // Counter reset on day 3 -> skipped from network rate rather than negative
            json!({"timestamp": "2026-11-03 00:00:00", "cpu_avg": 25.0, "mem_used_gb": 12.0, "mem_total_gb": 32.0, "disk_read_bps": 500.0, "disk_write_bps": 500.0, "net_rx_bytes": 100.0, "net_tx_bytes": 50.0}),
        ];
        let cap = derive_capacity_history(&rows);
        assert_eq!(cap.observed_days, 3);
        assert_eq!(cap.sample_count, 3);
        assert_eq!(cap.cpu.len(), 3);
        assert_eq!(cap.memory[1].y, 50.0);
        assert_eq!(cap.disk_io[0].y, 1500.0);
        assert_eq!(cap.network.len(), 1);
        assert!(cap.network[0].y > 0.0);
    }

    #[test]
    fn aggregated_daily_transfer_and_capacity_query_contracts_and_decoders() {
        assert_eq!(
            daily_transfer_history_url(7),
            "/api/v1/auth/system/metrics/history?days=7&aggregate=daily_transfer"
        );
        assert_eq!(
            daily_transfer_history_url(30),
            "/api/v1/auth/system/metrics/history?days=30&aggregate=daily_transfer"
        );
        assert_eq!(
            daily_transfer_history_url(90),
            "/api/v1/auth/system/metrics/history?days=90&aggregate=daily_transfer"
        );
        assert_eq!(
            capacity_history_url(),
            "/api/v1/admin/ai/predictions/history?days=30&aggregate=capacity"
        );

        let aggregated = json!({
            "days": [
                { "date": "2026-11-18", "downloaded_bytes": 1_048_576.0, "uploaded_bytes": 524_288.0 },
                { "date": "2026-11-15", "downloaded_bytes": null, "uploaded_bytes": null },
                { "date": "2026-11-16", "downloaded_bytes": 0.0, "uploaded_bytes": 0.0 }
            ],
            "counter_resets": 2,
            "invalid_samples": 1,
            "conflicting_samples": 3,
            "duplicate_samples": 4
        });
        let summary = decode_daily_usage(&aggregated);
        assert_eq!(summary.days.len(), 3);
        // Sorted ascending by UTC date; unobserved 2026-11-17 is omitted.
        assert_eq!(summary.days[0].date, "2026-11-15");
        assert_eq!(summary.days[0].downloaded_bytes, None);
        assert_eq!(summary.days[1].date, "2026-11-16");
        assert_eq!(summary.days[1].downloaded_bytes, Some(0.0));
        assert_eq!(summary.days[2].date, "2026-11-18");
        assert_eq!(summary.days[2].downloaded_bytes, Some(1_048_576.0));
        assert_eq!(summary.days[2].uploaded_bytes, Some(524_288.0));
        assert_eq!(summary.counter_resets, 2);
        assert_eq!(summary.invalid_samples, 1);
        assert_eq!(summary.conflicting_samples, 3);
        assert_eq!(summary.duplicate_samples, 4);
        assert_eq!(summary.total_downloaded(), Some(1_048_576.0));
        assert_eq!(summary.total_uploaded(), Some(524_288.0));
        let (down_pts, up_pts) = summary.chart_series();
        assert_eq!(down_pts.len(), 2);
        assert_eq!(up_pts.len(), 2);

        // Raw array fixture remains accepted through decode_daily_usage.
        let raw_fixture = json!([
            { "timestamp": "2026-11-10 00:00:00", "net_rx_bytes": 100.0, "net_tx_bytes": 50.0 },
            { "timestamp": "2026-11-10 06:00:00", "net_rx_bytes": 600.0, "net_tx_bytes": 250.0 }
        ]);
        let fallback = decode_daily_usage(&raw_fixture);
        assert_eq!(fallback.days.len(), 1);
        assert_eq!(fallback.total_downloaded(), Some(500.0));
        assert_eq!(fallback.total_uploaded(), Some(200.0));

        // 30-day uniformly distributed capacity response keeps all 30 observed days.
        let base_ms =
            af_web_core::charts::parse_utc_timestamp_str_ms("2026-10-20 12:00:00").unwrap();
        let cap_rows: Vec<Value> = (0..30)
            .map(|day| {
                let ts_ms = base_ms + day as f64 * 86_400_000.0;
                json!({
                    "timestamp": ts_ms,
                    "cpu_avg": 15.0 + day as f64,
                    "mem_used_gb": 16.0,
                    "mem_total_gb": 64.0,
                    "disk_read_bps": 2_097_152.0,
                    "disk_write_bps": 1_048_576.0,
                    "net_rx_bytes": (day as f64 + 1.0) * 10_000_000.0,
                    "net_tx_bytes": (day as f64 + 1.0) * 5_000_000.0
                })
            })
            .collect();
        let cap = derive_capacity_history(&cap_rows);
        assert_eq!(cap.observed_days, 30);
        assert_eq!(cap.cpu.len(), 30);
        assert_eq!(cap.memory.len(), 30);
        assert_eq!(cap.disk_io.len(), 30);
        assert_eq!(cap.network.len(), 29);
    }
}
