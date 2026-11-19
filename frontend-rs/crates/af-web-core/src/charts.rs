use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt::Write;

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ChartValueFormat {
    #[default]
    Number,
    Percent,
    Bytes,
    BytesPerSec,
    Hours,
    Count,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ChartTimeFormat {
    #[default]
    Auto,
    Time,
    DateTime,
    Date,
}

#[derive(Clone, Debug)]
pub struct RingBuffer<T> {
    capacity: usize,
    points: VecDeque<T>,
}
impl<T> RingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            points: VecDeque::with_capacity(capacity),
        }
    }
    pub fn push(&mut self, point: T) {
        if self.capacity == 0 {
            return;
        }
        if self.points.len() == self.capacity {
            self.points.pop_front();
        }
        self.points.push_back(point);
    }
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.points.iter()
    }
    pub fn len(&self) -> usize {
        self.points.len()
    }
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }
    pub fn clear(&mut self) {
        self.points.clear();
    }
}

/// Persisted SQLite timestamps without a zone represent UTC.
pub fn parse_utc_timestamp_str_ms(raw: &str) -> Option<f64> {
    use chrono::{DateTime, NaiveDate, NaiveDateTime};
    let raw = raw.trim();
    if let Ok(epoch) = raw.parse::<f64>() {
        let ms = if epoch < 1e12 { epoch * 1000.0 } else { epoch };
        return (ms.is_finite() && ms > 0.0).then(|| ms.round());
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.timestamp_millis() as f64);
    }
    for format in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(raw, format) {
            return Some(dt.and_utc().timestamp_millis() as f64);
        }
    }
    for format in ["%Y-%m-%d %H:%M:%S%.f%#z", "%Y-%m-%dT%H:%M:%S%.f%#z"] {
        if let Ok(dt) = DateTime::parse_from_str(raw, format) {
            return Some(dt.timestamp_millis() as f64);
        }
    }
    let midnight = NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .ok()?
        .and_hms_opt(0, 0, 0)?;
    Some(midnight.and_utc().timestamp_millis() as f64)
}

pub fn utc_components_from_ms(ms: f64) -> Option<(i64, u32, u32, u32, u32, u32)> {
    use chrono::{DateTime, Datelike, Timelike};
    if !ms.is_finite() {
        return None;
    }
    let dt = DateTime::from_timestamp_millis(ms.floor() as i64)?;
    Some((
        i64::from(dt.year()),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
    ))
}

/// Format UTC epoch milliseconds as `YYYY-MM-DD`.
pub fn utc_date_from_ms(ms: f64) -> Option<String> {
    let (y, m, d, _, _, _) = utc_components_from_ms(ms)?;
    Some(format!("{y:04}-{m:02}-{d:02}"))
}

/// Largest Triangle Three Buckets, retaining first/last samples and peaks.
pub fn lttb(data: &[Point], threshold: usize) -> Vec<Point> {
    let data: Vec<Point> = data
        .iter()
        .copied()
        .filter(|p| p.x.is_finite() && p.y.is_finite())
        .collect();
    let n = data.len();
    if threshold == 0 {
        return vec![];
    }
    if threshold >= n {
        return data;
    }
    if threshold == 1 {
        return vec![data[0]];
    }
    if threshold == 2 {
        return vec![data[0], data[n - 1]];
    }
    let every = (n - 2) as f64 / (threshold - 2) as f64;
    let mut out = Vec::with_capacity(threshold);
    out.push(data[0]);
    let mut a = 0;
    for i in 0..threshold - 2 {
        let avg_start = (((i + 1) as f64 * every).floor() as usize + 1).min(n - 1);
        let avg_end = (((i + 2) as f64 * every).floor() as usize + 1)
            .min(n)
            .max(avg_start + 1);
        let count = (avg_end - avg_start) as f64;
        let avg = data[avg_start..avg_end]
            .iter()
            .fold(Point::default(), |sum, p| Point {
                x: sum.x + p.x / count,
                y: sum.y + p.y / count,
            });
        let start = (i as f64 * every).floor() as usize + 1;
        let end = (((i + 1) as f64 * every).floor() as usize + 1)
            .min(n - 1)
            .max(start + 1);
        let mut best = start;
        let mut max_area = -1.0;
        for j in start..end {
            let area = ((data[a].x - avg.x) * (data[j].y - data[a].y)
                - (data[a].x - data[j].x) * (avg.y - data[a].y))
                .abs();
            if area > max_area {
                max_area = area;
                best = j;
            }
        }
        out.push(data[best]);
        a = best;
    }
    out.push(data[n - 1]);
    out
}

#[derive(Clone, Debug, PartialEq)]
pub struct LinearScale {
    pub domain: [f64; 2],
    pub ticks: Vec<f64>,
}
pub fn nice_axis_ticks(
    data_max: f64,
    intervals: usize,
    integer_only: bool,
    min_ceiling: f64,
) -> LinearScale {
    let intervals = if intervals == 0 {
        4
    } else {
        intervals.min(100)
    };
    let ceiling = if data_max.is_finite() {
        data_max.max(0.0)
    } else {
        0.0
    }
    .max(if min_ceiling.is_finite() {
        min_ceiling.max(0.0)
    } else if integer_only {
        4.0
    } else {
        1.0
    });
    if ceiling == 0.0 {
        return LinearScale {
            domain: [0.0, intervals as f64],
            ticks: (0..=intervals).map(|v| v as f64).collect(),
        };
    }
    let raw_step = ceiling / intervals as f64;
    let power = 10f64.powf(raw_step.log10().floor());
    let fraction = raw_step / power;
    let factors: &[f64] = if integer_only {
        &[1.0, 2.0, 5.0, 10.0]
    } else {
        &[1.0, 2.0, 2.5, 5.0, 10.0]
    };
    let nice = factors
        .iter()
        .find(|v| fraction <= **v)
        .copied()
        .unwrap_or(10.0);
    let step = (nice * power).max(if integer_only { 1.0 } else { 0.0001 });
    let ticks = (0..=intervals)
        .map(|n| (n as f64 * step * 1_000_000.0).round() / 1_000_000.0)
        .collect();
    LinearScale {
        domain: [0.0, step * intervals as f64],
        ticks,
    }
}

const BYTE_TIER_THRESHOLDS: [f64; 6] = [
    1.0,
    1024.0,
    1_048_576.0,
    1_073_741_824.0,
    1_099_511_627_776.0,
    1_125_899_906_842_624.0,
];

fn byte_unit_label(tier: usize, locale: &str) -> &'static str {
    let units = if locale == "fr" {
        ["o", "Kio", "Mio", "Gio", "Tio", "Pio"]
    } else {
        ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    };
    units[tier.min(units.len() - 1)]
}

fn byte_tier_for(value: f64) -> usize {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    for (idx, threshold) in BYTE_TIER_THRESHOLDS.iter().enumerate().rev() {
        if value >= *threshold {
            return idx;
        }
    }
    0
}

/// Binary-tier nice byte scale matching prior bandwidthScaleHelpers behavior.
pub fn compute_nice_byte_scale(max_data_bytes: f64) -> LinearScale {
    if !max_data_bytes.is_finite() || max_data_bytes <= 0.0 {
        return LinearScale {
            domain: [0.0, 4.0],
            ticks: vec![0.0, 1.0, 2.0, 3.0, 4.0],
        };
    }
    let tier = byte_tier_for(max_data_bytes);
    let unit_bytes = BYTE_TIER_THRESHOLDS[tier];
    let max_in_unit = max_data_bytes / unit_bytes;
    let raw_step_in_unit = max_in_unit / 4.0;
    let power = 10f64.powf(raw_step_in_unit.log10().floor());
    let normalized = raw_step_in_unit / power;
    let factors = [1.0, 2.0, 2.5, 4.0, 5.0, 10.0];
    let chosen = factors
        .iter()
        .find(|&&f| f >= normalized - 1e-9)
        .copied()
        .unwrap_or(10.0);
    let step = chosen * power * unit_bytes;
    let ticks = vec![0.0, step, 2.0 * step, 3.0 * step, 4.0 * step];
    LinearScale {
        domain: [0.0, ticks[4]],
        ticks,
    }
}

pub fn compute_value_scale(max_value: f64, format: ChartValueFormat) -> LinearScale {
    match format {
        ChartValueFormat::Percent => {
            if max_value.is_finite() && max_value > 100.0 {
                nice_axis_ticks(max_value, 4, false, 100.0)
            } else {
                LinearScale {
                    domain: [0.0, 100.0],
                    ticks: vec![0.0, 25.0, 50.0, 75.0, 100.0],
                }
            }
        }
        ChartValueFormat::Bytes | ChartValueFormat::BytesPerSec => {
            compute_nice_byte_scale(max_value)
        }
        ChartValueFormat::Count => nice_axis_ticks(max_value, 4, true, 4.0),
        ChartValueFormat::Number | ChartValueFormat::Hours => {
            nice_axis_ticks(max_value, 4, false, 1.0)
        }
    }
}

pub fn format_bytes_localized(value: f64, locale: &str) -> String {
    if !value.is_finite() || value < 0.0 {
        return crate::i18n::translate(locale, "Unavailable");
    }
    let tier = byte_tier_for(value);
    let scaled = value / BYTE_TIER_THRESHOLDS[tier];
    let unit = byte_unit_label(tier, locale);
    if tier == 0 {
        format!("{:.0} {unit}", scaled.round())
    } else {
        format!("{scaled:.1} {unit}")
    }
}

pub fn format_rate_localized(value: f64, locale: &str) -> String {
    if !value.is_finite() || value < 0.0 {
        return "—".into();
    }
    format!("{}/s", format_bytes_localized(value, locale))
}

pub fn format_percent_localized(value: f64, locale: &str) -> String {
    if !value.is_finite() {
        return "—".into();
    }
    let clean = if value == 0.0 { 0.0 } else { value };
    if matches!(locale, "de" | "dk" | "fr") {
        format!("{clean:.1} %")
    } else {
        format!("{clean:.1}%")
    }
}

pub fn format_chart_value(value: f64, format: ChartValueFormat, locale: &str) -> String {
    if !value.is_finite() {
        return "—".into();
    }
    let clean = if value == 0.0 { 0.0 } else { value };
    match format {
        ChartValueFormat::Percent => format_percent_localized(clean, locale),
        ChartValueFormat::Bytes => format_bytes_localized(clean, locale),
        ChartValueFormat::BytesPerSec => format_rate_localized(clean, locale),
        ChartValueFormat::Hours => {
            let unit = match locale {
                "de" => "Std.",
                "dk" => "t.",
                "zh" => "小时",
                _ => "h",
            };
            format!("{clean:.1} {unit}")
        }
        ChartValueFormat::Count => format!("{clean:.0}"),
        ChartValueFormat::Number => {
            if clean == 0.0 {
                "0".into()
            } else if clean.abs() < 1.0 {
                format!("{clean:.2}")
            } else if clean.abs() < 100.0 {
                format!("{clean:.1}")
            } else {
                format!("{clean:.0}")
            }
        }
    }
}

pub fn format_chart_axis_tick(
    tick: f64,
    scale_max: f64,
    format: ChartValueFormat,
    locale: &str,
) -> String {
    let clean = if !tick.is_finite() || tick == 0.0 {
        0.0
    } else {
        tick
    };
    match format {
        ChartValueFormat::Percent => {
            if matches!(locale, "de" | "dk" | "fr") {
                format!("{clean:.0} %")
            } else {
                format!("{clean:.0}%")
            }
        }
        ChartValueFormat::Bytes | ChartValueFormat::BytesPerSec => {
            let tier = byte_tier_for(scale_max);
            let scaled = clean / BYTE_TIER_THRESHOLDS[tier];
            let unit = byte_unit_label(tier, locale);
            let suffix = if format == ChartValueFormat::BytesPerSec {
                "/s"
            } else {
                ""
            };
            let num = if (scaled - scaled.round()).abs() < 1e-4 {
                format!("{:.0}", scaled.round())
            } else {
                format!("{scaled:.1}")
            };
            format!("{num} {unit}{suffix}")
        }
        ChartValueFormat::Hours => {
            let unit = match locale {
                "de" => "Std.",
                "dk" => "t.",
                "zh" => "小时",
                _ => "h",
            };
            if clean == 0.0 {
                format!("0 {unit}")
            } else if scale_max < 5.0 {
                format!("{clean:.1} {unit}")
            } else {
                format!("{clean:.0} {unit}")
            }
        }
        ChartValueFormat::Count => format!("{clean:.0}"),
        ChartValueFormat::Number => {
            if clean == 0.0 {
                "0".into()
            } else if scale_max < 0.5 {
                format!("{clean:.2}")
            } else if scale_max < 5.0 {
                format!("{clean:.1}")
            } else {
                format!("{clean:.0}")
            }
        }
    }
}

pub fn format_duration_span(seconds: u64, locale: &str) -> String {
    let (d_u, h_u, m_u, s_u) = match locale {
        "de" => ("T.", "Std.", "Min.", "Sek."),
        "dk" => ("d.", "t.", "min.", "sek."),
        "es" => ("d", "h", "min", "s"),
        "fr" => ("j", "h", "min", "s"),
        "zh" => ("天", "小时", "分钟", "秒"),
        _ => ("d", "h", "m", "s"),
    };
    if seconds < 60 {
        return format!("{seconds}{s_u}");
    }
    if seconds < 3600 {
        let mins = seconds / 60;
        let rem = seconds % 60;
        return if rem == 0 {
            format!("{mins}{m_u}")
        } else {
            format!("{mins}{m_u} {rem}{s_u}")
        };
    }
    if seconds < 86_400 {
        let hrs = seconds / 3600;
        let mins = (seconds % 3600) / 60;
        return if mins == 0 {
            format!("{hrs}{h_u}")
        } else {
            format!("{hrs}{h_u} {mins}{m_u}")
        };
    }
    let days = seconds / 86_400;
    let hrs = (seconds % 86_400) / 3600;
    if hrs == 0 {
        format!("{days}{d_u}")
    } else {
        format!("{days}{d_u} {hrs}{h_u}")
    }
}

pub fn format_chart_timestamp(
    timestamp_ms: f64,
    format: ChartTimeFormat,
    span_ms: f64,
    locale: &str,
) -> String {
    if !timestamp_ms.is_finite() {
        return "—".into();
    }
    if timestamp_ms < 60_000.0 && format != ChartTimeFormat::Date {
        return format!("#{}", timestamp_ms.round() as i64);
    }
    let effective = match format {
        ChartTimeFormat::Auto => {
            if span_ms >= 86_400_000.0 * 2.0 {
                ChartTimeFormat::Date
            } else if span_ms > 21_600_000.0 {
                ChartTimeFormat::DateTime
            } else {
                ChartTimeFormat::Time
            }
        }
        other => other,
    };
    if effective == ChartTimeFormat::Date {
        if let Some((y, m, d, _, _, _)) = utc_components_from_ms(timestamp_ms) {
            return match locale {
                "de" | "dk" => format!("{d:02}.{m:02}.{y:04}"),
                "es" | "fr" => format!("{d:02}/{m:02}/{y:04}"),
                _ => format!("{y:04}-{m:02}-{d:02}"),
            };
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        let tag = crate::i18n::bcp47_tag(locale);
        let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(timestamp_ms));
        match effective {
            ChartTimeFormat::Time => {
                let s = String::from(date.to_locale_time_string(tag));
                if !s.trim().is_empty() {
                    return s;
                }
            }
            ChartTimeFormat::DateTime | ChartTimeFormat::Auto => {
                let options = js_sys::Object::new();
                let _ = js_sys::Reflect::set(&options, &"month".into(), &"short".into());
                let _ = js_sys::Reflect::set(&options, &"day".into(), &"2-digit".into());
                let _ = js_sys::Reflect::set(&options, &"hour".into(), &"2-digit".into());
                let _ = js_sys::Reflect::set(&options, &"minute".into(), &"2-digit".into());
                let s = String::from(date.to_locale_string(tag, &options));
                if !s.trim().is_empty() {
                    return s;
                }
            }
            ChartTimeFormat::Date => {}
        }
    }
    let Some((y, m, d, h, min, sec)) = utc_components_from_ms(timestamp_ms) else {
        return "—".into();
    };
    match effective {
        ChartTimeFormat::Time => format!("{h:02}:{min:02}:{sec:02} UTC"),
        ChartTimeFormat::DateTime | ChartTimeFormat::Auto => {
            format!("{m:02}/{d:02} {h:02}:{min:02} UTC")
        }
        ChartTimeFormat::Date => format!("{y:04}-{m:02}-{d:02}"),
    }
}

pub fn format_short_axis_time(
    timestamp_ms: f64,
    format: ChartTimeFormat,
    span_ms: f64,
    locale: &str,
) -> String {
    if !timestamp_ms.is_finite() {
        return String::new();
    }
    if timestamp_ms < 60_000.0 && format != ChartTimeFormat::Date {
        return format!("#{}", timestamp_ms.round() as i64);
    }
    let effective = match format {
        ChartTimeFormat::Auto => {
            if span_ms >= 86_400_000.0 * 2.0 {
                ChartTimeFormat::Date
            } else if span_ms > 21_600_000.0 {
                ChartTimeFormat::DateTime
            } else {
                ChartTimeFormat::Time
            }
        }
        other => other,
    };
    if effective == ChartTimeFormat::Date {
        if let Some((_, m, d, _, _, _)) = utc_components_from_ms(timestamp_ms) {
            return match locale {
                "de" | "dk" => format!("{d:02}.{m:02}."),
                "es" | "fr" => format!("{d:02}/{m:02}"),
                "zh" => format!("{m}月{d}日"),
                _ => format!("{m:02}/{d:02}"),
            };
        }
    }
    format_chart_timestamp(timestamp_ms, effective, span_ms, locale)
}

pub fn compute_x_domain(series: &[&[Point]]) -> Option<[f64; 2]> {
    let mut xmin = f64::INFINITY;
    let mut xmax = f64::NEG_INFINITY;
    for points in series {
        for p in *points {
            if p.x.is_finite() && p.y.is_finite() {
                xmin = xmin.min(p.x);
                xmax = xmax.max(p.x);
            }
        }
    }
    (xmin.is_finite() && xmax.is_finite()).then_some([xmin, xmax])
}

pub fn project_x(x: f64, x_domain: [f64; 2], width: f64) -> f64 {
    if !x.is_finite() || !width.is_finite() || width <= 0.0 {
        return 0.0;
    }
    let span = x_domain[1] - x_domain[0];
    if !span.is_finite() || span.abs() < f64::EPSILON {
        width / 2.0
    } else {
        ((x - x_domain[0]) / span * width).clamp(0.0, width)
    }
}

pub fn project_y(y: f64, y_domain: [f64; 2], height: f64) -> f64 {
    if !y.is_finite() || !height.is_finite() || height <= 0.0 {
        return height.max(0.0);
    }
    let span = y_domain[1] - y_domain[0];
    if !span.is_finite() || span.abs() < f64::EPSILON {
        height
    } else {
        (height - (y - y_domain[0]) / span * height).clamp(0.0, height)
    }
}

pub fn target_x_for_cursor(cursor_x: f64, width: f64, x_domain: [f64; 2]) -> f64 {
    if !width.is_finite() || width <= 0.0 {
        return x_domain[0];
    }
    let ratio = (cursor_x / width).clamp(0.0, 1.0);
    x_domain[0] + ratio * (x_domain[1] - x_domain[0])
}

/// Find the index of the finite point closest to `target_x` in actual time/x units.
pub fn nearest_point_index_by_x(points: &[Point], target_x: f64) -> Option<usize> {
    if !target_x.is_finite() {
        return None;
    }
    let mut best_index = None;
    let mut best_distance = f64::INFINITY;
    for (index, point) in points.iter().enumerate() {
        if !point.x.is_finite() || !point.y.is_finite() {
            continue;
        }
        let distance = (point.x - target_x).abs();
        if distance < best_distance {
            best_distance = distance;
            best_index = Some(index);
        }
    }
    best_index
}

pub fn nearest_point_index_for_cursor(
    points: &[Point],
    cursor_x: f64,
    width: f64,
    x_domain: [f64; 2],
) -> Option<usize> {
    let target_x = target_x_for_cursor(cursor_x, width, x_domain);
    nearest_point_index_by_x(points, target_x)
}

pub fn scale_points_in_domain(
    points: &[Point],
    x_domain: [f64; 2],
    y_domain: [f64; 2],
    width: f64,
    height: f64,
) -> Vec<Point> {
    if !width.is_finite() || !height.is_finite() || width <= 0.0 || height <= 0.0 {
        return vec![];
    }
    points
        .iter()
        .filter(|p| p.x.is_finite() && p.y.is_finite())
        .map(|p| Point {
            x: project_x(p.x, x_domain, width),
            y: project_y(p.y, y_domain, height),
        })
        .collect()
}

pub fn build_line_path_in_domain(
    points: &[Point],
    x_domain: [f64; 2],
    y_domain: [f64; 2],
    width: f64,
    height: f64,
    gap_threshold_x: Option<f64>,
) -> String {
    if !width.is_finite() || !height.is_finite() || width <= 0.0 || height <= 0.0 {
        return String::new();
    }
    let finite: Vec<Point> = points
        .iter()
        .copied()
        .filter(|p| p.x.is_finite() && p.y.is_finite())
        .collect();
    let mut path = String::new();
    let mut prev_x: Option<f64> = None;
    for p in finite {
        let sx = project_x(p.x, x_domain, width);
        let sy = project_y(p.y, y_domain, height);
        let start_new = match (prev_x, gap_threshold_x) {
            (None, _) => true,
            (Some(px), Some(limit)) if limit > 0.0 && (p.x - px) > limit => true,
            _ => false,
        };
        let _ = write!(
            path,
            "{} {:.2} {:.2} ",
            if start_new { "M" } else { "L" },
            sx,
            sy
        );
        prev_x = Some(p.x);
    }
    path.trim_end().to_string()
}

pub fn build_area_path_in_domain(
    points: &[Point],
    x_domain: [f64; 2],
    y_domain: [f64; 2],
    width: f64,
    height: f64,
    gap_threshold_x: Option<f64>,
) -> String {
    if !width.is_finite() || !height.is_finite() || width <= 0.0 || height <= 0.0 {
        return String::new();
    }
    let finite: Vec<Point> = points
        .iter()
        .copied()
        .filter(|p| p.x.is_finite() && p.y.is_finite())
        .collect();
    if finite.is_empty() {
        return String::new();
    }
    let mut segments: Vec<Vec<Point>> = vec![];
    for p in finite {
        let split = segments
            .last()
            .and_then(|seg| seg.last())
            .is_some_and(|prev| {
                gap_threshold_x.is_some_and(|limit| limit > 0.0 && (p.x - prev.x) > limit)
            });
        if segments.is_empty() || split {
            segments.push(vec![p]);
        } else if let Some(seg) = segments.last_mut() {
            seg.push(p);
        }
    }
    let mut path = String::new();
    for seg in segments {
        if seg.len() < 2 {
            continue;
        }
        let first_x = project_x(seg[0].x, x_domain, width);
        let last_x = project_x(seg[seg.len() - 1].x, x_domain, width);
        for (i, p) in seg.iter().enumerate() {
            let sx = project_x(p.x, x_domain, width);
            let sy = project_y(p.y, y_domain, height);
            let _ = write!(
                path,
                "{} {:.2} {:.2} ",
                if i == 0 { "M" } else { "L" },
                sx,
                sy
            );
        }
        let _ = write!(
            path,
            "L {:.2} {height:.2} L {:.2} {height:.2} Z ",
            last_x, first_x
        );
    }
    path.trim_end().to_string()
}

pub fn scale_points(points: &[Point], width: f64, height: f64) -> Vec<Point> {
    let points: Vec<_> = points
        .iter()
        .filter(|p| p.x.is_finite() && p.y.is_finite())
        .collect();
    if points.is_empty()
        || !width.is_finite()
        || !height.is_finite()
        || width <= 0.0
        || height <= 0.0
    {
        return vec![];
    }
    let xmin = points.iter().map(|p| p.x).fold(f64::INFINITY, f64::min);
    let xmax = points.iter().map(|p| p.x).fold(f64::NEG_INFINITY, f64::max);
    let ymin = points.iter().map(|p| p.y).fold(0.0, f64::min);
    let ymax = nice_axis_ticks(
        points.iter().map(|p| p.y).fold(0.0, f64::max),
        4,
        false,
        1.0,
    )
    .domain[1];
    points
        .iter()
        .map(|p| Point {
            x: if xmax == xmin {
                width / 2.0
            } else {
                (p.x - xmin) / (xmax - xmin) * width
            },
            y: height - (p.y - ymin) / (ymax - ymin) * height,
        })
        .collect()
}
pub fn build_line_path(points: &[Point], width: f64, height: f64) -> String {
    let mut path = String::new();
    for (i, p) in scale_points(points, width, height).iter().enumerate() {
        let _ = write!(
            path,
            "{} {:.2} {:.2} ",
            if i == 0 { "M" } else { "L" },
            p.x,
            p.y
        );
    }
    path.trim_end().to_string()
}
pub fn build_area_path(points: &[Point], width: f64, height: f64) -> String {
    let path = build_line_path(points, width, height);
    let scaled = scale_points(points, width, height);
    match (scaled.first(), scaled.last()) {
        (Some(first), Some(last)) => format!(
            "{path} L {:.2} {height:.2} L {:.2} {height:.2} Z",
            last.x, first.x
        ),
        _ => String::new(),
    }
}
pub fn build_sparkline_path(values: &[f64], width: f64, height: f64) -> String {
    build_line_path(
        &values
            .iter()
            .enumerate()
            .map(|(i, v)| Point { x: i as f64, y: *v })
            .collect::<Vec<_>>(),
        width,
        height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ring_eviction_and_zero_capacity() {
        let mut ring = RingBuffer::new(2);
        for i in 0..4 {
            ring.push(i);
        }
        assert_eq!(ring.iter().copied().collect::<Vec<_>>(), vec![2, 3]);
        ring.clear();
        assert!(ring.is_empty());
        let mut empty = RingBuffer::new(0);
        empty.push(1);
        assert_eq!(empty.len(), 0);
    }
    #[test]
    fn lttb_preserves_endpoints_and_spike() {
        let points: Vec<_> = (0..100)
            .map(|x| Point {
                x: x as f64,
                y: if x == 51 { 100.0 } else { 0.0 },
            })
            .collect();
        let reduced = lttb(&points, 10);
        assert_eq!(reduced.len(), 10);
        assert_eq!(reduced[0], points[0]);
        assert_eq!(reduced[9], points[99]);
        assert!(reduced.iter().any(|p| p.y == 100.0));
    }
    #[test]
    fn lttb_handles_small_budgets_and_nonfinite_points() {
        let points = [
            Point { x: 0.0, y: 1.0 },
            Point {
                x: 1.0,
                y: f64::NAN,
            },
            Point { x: 2.0, y: 2.0 },
        ];
        assert!(lttb(&points, 0).is_empty());
        assert_eq!(lttb(&points, 1).len(), 1);
        assert_eq!(lttb(&points, 2).len(), 2);
        assert_eq!(lttb(&[], 10), vec![]);
    }
    #[test]
    fn paths_are_finite_and_area_closes() {
        let points = [Point { x: 1.0, y: 4.0 }, Point { x: 2.0, y: 8.0 }];
        assert!(build_area_path(&points, 200.0, 100.0).ends_with('Z'));
        assert!(build_line_path(&points, 200.0, 100.0).starts_with("M"));
        assert!(!build_sparkline_path(&[f64::NAN, 2.0], 20.0, 10.0).contains("NaN"));
        assert!(build_line_path(&[], 2.0, 2.0).is_empty());
    }
    #[test]
    fn nice_scale_matches_streaming_chart_steps() {
        assert_eq!(
            nice_axis_ticks(9.0, 4, false, 1.0).ticks,
            vec![0.0, 2.5, 5.0, 7.5, 10.0]
        );
        assert_eq!(
            nice_axis_ticks(1.0, 4, true, 4.0).ticks,
            vec![0.0, 1.0, 2.0, 3.0, 4.0]
        );
        assert_eq!(nice_axis_ticks(f64::NAN, 4, false, 0.0).domain, [0.0, 4.0]);
        assert!(nice_axis_ticks(1234.0, 4, false, 1.0).domain[1] >= 1234.0);
    }

    #[test]
    fn utc_timestamp_parser_normalizes_legacy_sqlite_and_offsets_across_dst() {
        // Legacy SQLite UTC string without offset must match explicit Z identically.
        let legacy = parse_utc_timestamp_str_ms("2026-03-29 01:30:00").unwrap();
        let explicit_z = parse_utc_timestamp_str_ms("2026-03-29T01:30:00Z").unwrap();
        // Europe/Berlin DST spring-forward: 01:30 UTC == 03:30+02:00, and 00:30 UTC == 01:30+01:00.
        let berlin_dst = parse_utc_timestamp_str_ms("2026-03-29T03:30:00+02:00").unwrap();
        let ny_dst = parse_utc_timestamp_str_ms("2026-03-28T21:30:00-04:00").unwrap();
        assert_eq!(legacy, explicit_z);
        assert_eq!(legacy, berlin_dst);
        assert_eq!(legacy, ny_dst);
        assert_eq!(utc_date_from_ms(legacy).as_deref(), Some("2026-03-29"));

        // Fall-back DST transition (Europe/Berlin Oct 25 2026, America/New_York Nov 1 2026).
        let fall_utc = parse_utc_timestamp_str_ms("2026-11-01 05:30:00").unwrap();
        let fall_est = parse_utc_timestamp_str_ms("2026-11-01T00:30:00-05:00").unwrap();
        let fall_cet = parse_utc_timestamp_str_ms("2026-11-01T06:30:00+01:00").unwrap();
        assert_eq!(fall_utc, fall_est);
        assert_eq!(fall_utc, fall_cet);

        // Leap day, fractional seconds, date-only, and numeric epochs.
        assert_eq!(
            utc_date_from_ms(parse_utc_timestamp_str_ms("2024-02-29 23:59:59.500").unwrap())
                .as_deref(),
            Some("2024-02-29")
        );
        assert!(parse_utc_timestamp_str_ms("2025-02-29 12:00:00").is_none());
        assert_eq!(
            parse_utc_timestamp_str_ms("1700000000"),
            Some(1_700_000_000_000.0)
        );
        assert_eq!(
            parse_utc_timestamp_str_ms("2026-11-19"),
            parse_utc_timestamp_str_ms("2026-11-19T00:00:00Z")
        );
    }

    #[test]
    fn true_time_hover_selects_closest_timestamp_for_gaps_and_live_burst() {
        // 5 minute-spaced persisted samples + 10 one-second live burst samples.
        let mut points = vec![
            Point { x: 0.0, y: 10.0 },
            Point {
                x: 60_000.0,
                y: 15.0,
            },
            Point {
                x: 120_000.0,
                y: 20.0,
            },
            Point {
                x: 180_000.0,
                y: 25.0,
            },
            Point {
                x: 240_000.0,
                y: 30.0,
            },
        ];
        for s in 1..=10 {
            points.push(Point {
                x: 240_000.0 + s as f64 * 1000.0,
                y: 30.0 + s as f64,
            });
        }
        let domain = compute_x_domain(&[&points]).unwrap();
        assert_eq!(domain, [0.0, 250_000.0]);
        // Hover at 50% width -> t = 125_000 ms -> closest is index 2 (120_000 ms), NOT index 7!
        let idx = nearest_point_index_for_cursor(&points, 500.0, 1000.0, domain).unwrap();
        assert_eq!(idx, 2);
        assert_eq!(points[idx].x, 120_000.0);
        // Hover at 98% width -> t = 245_000 ms -> closest is index 9 (245_000 ms).
        let burst_idx = nearest_point_index_for_cursor(&points, 980.0, 1000.0, domain).unwrap();
        assert_eq!(points[burst_idx].x, 245_000.0);
        // Uneven large gap: points at 0, 10s, 300s; hovering at 50% (150s) picks 10s (140s away < 150s away).
        let gapped = [
            Point { x: 0.0, y: 1.0 },
            Point {
                x: 10_000.0,
                y: 2.0,
            },
            Point {
                x: 300_000.0,
                y: 3.0,
            },
        ];
        let gap_domain = compute_x_domain(&[&gapped]).unwrap();
        assert_eq!(
            nearest_point_index_for_cursor(&gapped, 500.0, 1000.0, gap_domain),
            Some(1)
        );
        // Hovering at 60% (180s) picks 300s (120s away < 170s away).
        assert_eq!(
            nearest_point_index_for_cursor(&gapped, 600.0, 1000.0, gap_domain),
            Some(2)
        );
    }

    #[test]
    fn gap_aware_paths_break_across_missing_intervals_without_connecting_them() {
        let points = [
            Point { x: 0.0, y: 10.0 },
            Point {
                x: 60_000.0,
                y: 20.0,
            },
            Point {
                x: 400_000.0,
                y: 30.0,
            },
            Point {
                x: 460_000.0,
                y: 40.0,
            },
        ];
        let x_domain = [0.0, 460_000.0];
        let y_domain = [0.0, 100.0];
        let line =
            build_line_path_in_domain(&points, x_domain, y_domain, 460.0, 100.0, Some(120_000.0));
        assert_eq!(line.matches("M ").count(), 2);
        let area =
            build_area_path_in_domain(&points, x_domain, y_domain, 460.0, 100.0, Some(120_000.0));
        assert_eq!(area.matches('Z').count(), 2);
    }

    #[test]
    fn byte_scales_and_localized_labels_stay_consistent() {
        let scale = compute_nice_byte_scale(3.0 * 1_048_576.0);
        assert_eq!(scale.ticks.len(), 5);
        assert!(scale.domain[1] >= 3.0 * 1_048_576.0);
        assert_eq!(
            format_chart_axis_tick(
                scale.domain[1],
                scale.domain[1],
                ChartValueFormat::BytesPerSec,
                "en"
            ),
            "4 MiB/s"
        );
        assert_eq!(
            format_chart_axis_tick(
                scale.domain[1],
                scale.domain[1],
                ChartValueFormat::BytesPerSec,
                "fr"
            ),
            "4 Mio/s"
        );
        assert_eq!(
            format_chart_value(42.5, ChartValueFormat::Percent, "en"),
            "42.5%"
        );
        assert_eq!(
            format_chart_value(42.5, ChartValueFormat::Percent, "fr"),
            "42.5 %"
        );
        assert_eq!(
            format_chart_timestamp(
                parse_utc_timestamp_str_ms("2026-11-19 05:26:00").unwrap(),
                ChartTimeFormat::Date,
                86_400_000.0 * 30.0,
                "de"
            ),
            "19.11.2026"
        );
    }
}
