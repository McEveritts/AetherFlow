//! Service inventory normalization, lifecycle contracts, and browser helpers.
use crate::state::json_rows;
use af_web_core::{
    models::PackageLifecycleRecord,
    topology::{format_service_name, is_core_service, is_service_exception},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

/// Canonical inventory identity with runtime-specific fields kept intact.
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
struct ServiceRow {
    #[serde(deserialize_with = "crate::tabs::contracts::string")]
    id: String,
    #[serde(deserialize_with = "crate::tabs::contracts::string")]
    name: String,
    #[serde(deserialize_with = "crate::tabs::contracts::string")]
    slug: String,
    #[serde(deserialize_with = "crate::tabs::contracts::string")]
    status: String,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

pub(super) fn field(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| {
            value
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_default()
        .to_string()
}
pub(super) fn service_subtitle(info: &Value) -> String {
    let title = field(info, &["name", "slug", "id"]);
    let subtitle = field(info, &["slug", "id", "name"]);
    if !title.eq_ignore_ascii_case(&subtitle) {
        return subtitle;
    }
    let mut details = Vec::new();
    for key in ["managed_by", "process"] {
        let value = field(info, &[key]);
        if !value.is_empty() && !title.eq_ignore_ascii_case(&value) && !details.contains(&value) {
            details.push(value);
        }
    }
    if details.is_empty() {
        "Runtime unit".into()
    } else {
        details.join(" · ")
    }
}

pub(super) fn service_units(info: &Value) -> Vec<String> {
    let mut units = info["units"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    for key in ["lifecycle", "last_job"] {
        if let Ok(record) = serde_json::from_value::<PackageLifecycleRecord>(info[key].clone()) {
            units.extend(
                record
                    .service_units
                    .into_iter()
                    .filter(|unit| !unit.is_empty()),
            );
        }
    }
    units.extend(
        info["components"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|component| component["unit"].as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    );
    if units.is_empty() {
        let fallback = field(info, &["process", "id", "slug"]);
        if !fallback.is_empty() {
            units.push(fallback);
        }
    }
    units.sort();
    units.dedup();
    units
}
pub(super) fn core_service(info: &Value) -> bool {
    ["id", "slug", "process", "name"].iter().any(|key| {
        let id = info[*key]
            .as_str()
            .unwrap_or_default()
            .trim_end_matches(".service");
        is_core_service(id) || id == "aetherflow-runner"
    })
}
pub(super) fn running(info: &Value) -> bool {
    matches!(
        info["status"].as_str(),
        Some("running" | "active" | "installed")
    )
}
pub(super) fn attention(info: &Value) -> bool {
    info["needs_attention"] == true
        || is_service_exception(info)
        || matches!(info["status"].as_str(), Some("failed" | "unhealthy"))
}
pub(super) fn uptime_text(locale: &str, info: &Value) -> String {
    let reported = field(info, &["uptime"]);
    if !reported.is_empty() {
        return af_web_core::i18n::translate(locale, &reported);
    }
    ["uptime_seconds", "uptime"]
        .iter()
        .find_map(|key| info[*key].as_u64())
        .map(|seconds| {
            af_web_core::i18n::translate_with(
                locale,
                "{days}d {hours}h {minutes}m",
                &[
                    ("days", &(seconds / 86400).to_string()),
                    ("hours", &(seconds % 86400 / 3600).to_string()),
                    ("minutes", &(seconds % 3600 / 60).to_string()),
                ],
            )
        })
        .unwrap_or_else(|| af_web_core::i18n::translate(locale, "Unreported"))
}
pub(super) fn resource_metrics(info: &Value) -> Vec<(&'static str, String)> {
    let mut metrics = Vec::new();
    if let Some(cpu) = ["cpu_pct", "cpu_usage", "cpu"]
        .iter()
        .find_map(|key| info.get(key).filter(|v| v.is_number() || v.is_string()))
    {
        metrics.push((
            "CPU",
            cpu.as_f64()
                .map(|v| format!("{v:.1}%"))
                .unwrap_or_else(|| cpu.as_str().unwrap_or_default().into()),
        ));
    }
    if let Some(memory) = [
        "memory_mb",
        "memory_usage_mb",
        "memory_bytes",
        "memory",
        "memory_usage",
    ]
    .iter()
    .find_map(|key| {
        info.get(key)
            .filter(|v| v.is_number() || v.is_string())
            .map(|v| (*key, v))
    }) {
        let (key, value) = memory;
        metrics.push((
            "Memory",
            value
                .as_f64()
                .map(|n| {
                    if key.ends_with("_mb") {
                        format!("{n:.1} MiB")
                    } else if key.ends_with("_bytes") {
                        format!("{:.1} MiB", n / 1_048_576.0)
                    } else {
                        n.to_string()
                    }
                })
                .unwrap_or_else(|| value.as_str().unwrap_or_default().into()),
        ));
    }
    if let Some(port) = ["active_port", "default_port", "port"]
        .iter()
        .find_map(|key| info[*key].as_u64().filter(|n| *n > 0 && *n <= 65535))
    {
        metrics.push(("Port", port.to_string()));
    }
    metrics
}
pub(super) fn group(info: &Value) -> &'static str {
    if core_service(info) {
        "core"
    } else if attention(info) {
        "attention"
    } else if running(info) {
        "running"
    } else {
        "stopped"
    }
}
pub(super) fn service_rows(value: &Value) -> Vec<Value> {
    let mut rows = if let Some(object) = value
        .as_object()
        .filter(|v| !v.contains_key("services") && !v.contains_key("items"))
    {
        object
            .iter()
            .map(|(slug, info)| {
                let mut row = if info.is_object() {
                    info.clone()
                } else {
                    json!({"status":if info==true{"running"}else{"stopped"}})
                };
                if field(&row, &["id"]).is_empty() {
                    row["id"] = json!(slug);
                }
                if field(&row, &["name"]).is_empty() {
                    row["name"] = json!(format_service_name(slug));
                }
                row["slug"] = json!(slug);
                row
            })
            .collect::<Vec<_>>()
    } else {
        json_rows(value)
    };
    rows = rows
        .into_iter()
        .map(|row| {
            serde_json::from_value::<ServiceRow>(row.clone())
                .ok()
                .and_then(|row| serde_json::to_value(row).ok())
                .unwrap_or(row)
        })
        .collect();
    rows.sort_by_key(|v| field(v, &["name", "id"]).to_lowercase());
    rows
}
pub(super) fn shared_vhost(info: &Value) -> bool {
    !core_service(info)
        && (info["control_scope"] == "shared-vhost"
            || (info["process"] == "apache2" && info["id"] != "apache2"))
}
pub(super) fn launch_url(info: &Value, settings: &Value) -> Option<String> {
    let path = field(info, &["web_path"]);
    let path = if path.is_empty() {
        String::new()
    } else {
        format!("/{}", path.trim_start_matches('/'))
    };
    let public = field(info, &["public_domain"]);
    if info["external_access_enabled"] == true && valid_domain(&public) {
        return Some(format!(
            "{}://{public}{path}",
            if info["tls_enabled"] == false {
                "http"
            } else {
                "https"
            }
        ));
    }
    let base = field(settings, &["baseDomain", "base_domain"]);
    let id = field(info, &["id"]);
    if valid_domain(&base)
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !id.is_empty()
    {
        return Some(format!("https://{id}.{base}{path}"));
    }
    let location = web_sys::window()?.location();
    let host = location.hostname().ok()?;
    if info["bind_scope"] == "loopback"
        && !matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]" | "::1")
    {
        return None;
    }
    let port = ["active_port", "default_port", "port"]
        .iter()
        .find_map(|key| info[*key].as_u64().filter(|n| *n > 0 && *n <= 65535))?;
    let scheme = if info["web_scheme"] == "https" {
        "https"
    } else {
        "http"
    };
    Some(format!("{scheme}://{host}:{port}{path}"))
}
pub(super) fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}
pub(super) async fn copy_text(value: &str) -> Result<(), String> {
    let window = web_sys::window().ok_or("Browser unavailable")?;
    let navigator = js_sys::Reflect::get(&window, &JsValue::from_str("navigator"))
        .map_err(|_| "Clipboard unavailable")?;
    let clipboard = js_sys::Reflect::get(&navigator, &JsValue::from_str("clipboard"))
        .map_err(|_| "Clipboard unavailable")?;
    let write = js_sys::Reflect::get(&clipboard, &JsValue::from_str("writeText"))
        .map_err(|_| "Clipboard unavailable")?
        .dyn_into::<js_sys::Function>()
        .map_err(|_| "Clipboard unavailable")?;
    let promise = write
        .call1(&clipboard, &JsValue::from_str(value))
        .map_err(|_| "Clipboard access denied")?
        .dyn_into::<js_sys::Promise>()
        .map_err(|_| "Clipboard access denied")?;
    JsFuture::from(promise)
        .await
        .map_err(|_| "Clipboard access denied")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_titles_show_runtime_identity_instead() {
        assert_eq!(
            service_subtitle(
                &json!({"name":"AetherFlow API","id":"aetherflow api","managed_by":"systemd","process":"aetherflow-api"})
            ),
            "systemd · aetherflow-api"
        );
        assert_eq!(
            service_subtitle(&json!({"name":"Jellyfin","id":"jellyfin.service"})),
            "jellyfin.service"
        );
        assert_eq!(
            service_subtitle(
                &json!({"name":"Embedded API","id":"Embedded API","managed_by":"embedded"})
            ),
            "embedded"
        );
        assert_eq!(
            service_subtitle(&json!({"name":"Legacy","id":"legacy"})),
            "Runtime unit"
        );
    }

    #[test]
    fn typed_lifecycle_units_merge_with_legacy_components() {
        let record = PackageLifecycleRecord {
            package_id: "sonarr".into(),
            job_id: "job-1".into(),
            action: "install".into(),
            status: "completed".into(),
            started_at: "2026-11-16T12:00:00Z".into(),
            service_units: vec!["sonarr.service".into(), "sonarr-worker.service".into()],
            ..Default::default()
        };
        let mut last_job = serde_json::to_value(record).unwrap();
        last_job["legacy_extra"] = json!(true);
        let row = json!({"id":"sonarr","units":["sonarr.service"],"last_job":last_job,"components":[{"unit":"sonarr-worker.service"}]});
        assert_eq!(
            service_units(&row),
            ["sonarr-worker.service", "sonarr.service"]
        );
        assert_eq!(
            service_units(
                &json!({"id":"legacy","last_job":{"status":"failed"},"components":[{"unit":"old.service"}]})
            ),
            ["old.service"]
        );
        assert_eq!(
            service_units(&json!({"id":"legacy","process":"old-process"})),
            ["old-process"]
        );
        assert!(service_units(&Value::Null).is_empty());
    }

    #[test]
    fn running_services_keep_runtime_success_when_attention_is_required() {
        for row in [
            json!({"status":"running","needs_attention":true}),
            json!({"status":"running","health":"degraded"}),
            json!({"status":"running","last_job":{"status":"failed"}}),
        ] {
            assert!(running(&row));
            assert!(attention(&row));
        }
        assert!(!attention(
            &json!({"status":"running","needs_attention":false})
        ));
    }

    #[test]
    fn health_filters_and_resource_counters_keep_their_contracts() {
        let rows = service_rows(
            &json!({"jellyfin":{"status":"running","cpu_pct":4.25,"memory_bytes":1048576},"aetherflow-api":true}),
        );
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(core_service));
        let jellyfin = rows.iter().find(|row| row["id"] == "jellyfin").unwrap();
        assert_eq!(jellyfin["cpu_pct"], 4.25);
        assert_eq!(jellyfin["memory_bytes"], 1_048_576);
        for locale in ["en", "de", "dk", "es", "fr", "zh"] {
            assert_eq!(
                uptime_text(locale, &json!({"uptime": "Integrated"})),
                af_web_core::i18n::translate(locale, "Integrated"),
            );
        }
        assert_eq!(
            group(&json!({"id":"jellyfin","status":"running","last_job":{"status":"failed"}})),
            "attention"
        );
        assert_eq!(
            uptime_text("en", &json!({"uptime_seconds":90060})),
            "1d 1h 1m"
        );
        let metrics = resource_metrics(
            &json!({"cpu_pct":4.25,"memory_bytes":1048576,"active_port":70000,"default_port":8096}),
        );
        assert!(metrics.contains(&("Memory", "1.0 MiB".into())));
        assert!(metrics.contains(&("Port", "8096".into())));
    }
}
