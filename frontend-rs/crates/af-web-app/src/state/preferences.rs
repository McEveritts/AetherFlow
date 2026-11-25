use super::AppContext;
#[cfg(target_arch = "wasm32")]
use af_web_core::api::storage_get;
use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen::JsCast;

pub(super) fn normalize_theme(pref: &str) -> &'static str {
    match pref {
        "system" => "system",
        "light" => "light",
        _ => "dark",
    }
}

pub fn normalize_high_refresh_mode(pref: &str) -> &'static str {
    match pref.trim().to_ascii_lowercase().as_str() {
        "120" | "120hz" | "high" | "pro" | "promotion" | "on" | "true" => "120hz",
        "60" | "60hz" | "standard" | "off" | "false" => "standard",
        _ => "auto",
    }
}

pub fn normalize_touch_mode(pref: &str) -> &'static str {
    match pref.trim().to_ascii_lowercase().as_str() {
        "on" | "enabled" | "true" | "touch" => "on",
        "off" | "desktop" | "disabled" | "false" | "mouse" => "off",
        _ => "auto",
    }
}

pub(super) fn legacy_touch_mode_value(mode: &str) -> &'static str {
    match normalize_touch_mode(mode) {
        "on" => "enabled",
        "off" => "desktop",
        _ => "auto",
    }
}

pub fn quantize_refresh_rate(fps: f64) -> u32 {
    if !fps.is_finite() || fps <= 0.0 {
        return 60;
    }
    let buckets = [60u32, 75, 90, 120, 144, 165, 240];
    buckets
        .into_iter()
        .min_by(|a, b| {
            (fps - f64::from(*a))
                .abs()
                .total_cmp(&(fps - f64::from(*b)).abs())
        })
        .unwrap_or(60)
}

pub fn resolve_high_refresh_active(mode: &str, detected_hz: u32) -> bool {
    match normalize_high_refresh_mode(mode) {
        "120hz" => true,
        "standard" => false,
        _ => detected_hz >= 90,
    }
}

pub fn resolve_touch_mode_active(mode: &str, detected_touch: bool) -> bool {
    match normalize_touch_mode(mode) {
        "on" => true,
        "off" => false,
        _ => detected_touch,
    }
}

fn parse_bool_str(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "on" | "enabled" | "yes" => Some(true),
        "false" | "0" | "off" | "disabled" | "no" => Some(false),
        _ => None,
    }
}

pub(super) fn legacy_storage_envelope(raw: Option<&str>) -> Option<Value> {
    let parsed: Value = serde_json::from_str(raw?).ok()?;
    if let Some(state) = parsed.get("state").filter(|v| v.is_object()) {
        Some(state.clone())
    } else if parsed.is_object() {
        Some(parsed)
    } else {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HydratedPreferences {
    pub locale: Option<String>,
    pub theme: String,
    pub immersive_overview: bool,
    pub show_gpu: bool,
    pub show_transfer_history: bool,
    pub reduced_motion: bool,
    pub haptic_feedback: bool,
    pub high_refresh_mode: String,
    pub touch_mode: String,
}

pub(crate) fn hydrate_preferences_with<F>(get: F) -> HydratedPreferences
where
    F: Fn(&str) -> Option<String>,
{
    let legacy_sys = legacy_storage_envelope(get("aetherflow-system-storage").as_deref());
    let legacy_conn = legacy_storage_envelope(get("aetherflow-connection-storage").as_deref());
    let sys_field = |name: &str| legacy_sys.as_ref().and_then(|obj| obj.get(name));
    let conn_field = |name: &str| {
        legacy_conn
            .as_ref()
            .and_then(|obj| obj.get(name))
            .or_else(|| sys_field(name))
    };

    let locale = get("aetherflow-language")
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            sys_field("language")
                .and_then(Value::as_str)
                .filter(|v| !v.trim().is_empty())
                .map(String::from)
        })
        .map(|candidate| {
            if af_web_core::i18n::LOCALES.contains(&candidate.as_str()) {
                candidate
            } else {
                "en".into()
            }
        });

    let theme = get("aetherflow-theme")
        .filter(|v| !v.trim().is_empty())
        .or_else(|| sys_field("theme").and_then(Value::as_str).map(String::from))
        .map(|v| normalize_theme(&v).to_string())
        .unwrap_or_else(|| "dark".into());

    let immersive_overview = get("aetherflow-immersive-overview")
        .as_deref()
        .and_then(parse_bool_str)
        .or_else(|| {
            get("aetherflow-dashboard-density")
                .as_deref()
                .map(|d| d.trim().eq_ignore_ascii_case("immersive"))
        })
        .or_else(|| {
            conn_field("dashboardDensity")
                .and_then(Value::as_str)
                .map(|d| d.trim().eq_ignore_ascii_case("immersive"))
        })
        .unwrap_or(false);

    let show_gpu = get("aetherflow-show-gpu")
        .as_deref()
        .and_then(parse_bool_str)
        .or_else(|| conn_field("showGpuWidget").and_then(Value::as_bool))
        .unwrap_or(true);

    let show_transfer_history = get("aetherflow-show-transfer-history")
        .as_deref()
        .and_then(parse_bool_str)
        .or_else(|| conn_field("showDataUsageWidget").and_then(Value::as_bool))
        .unwrap_or(true);

    let reduced_motion = get("aetherflow-reduced-motion")
        .as_deref()
        .and_then(parse_bool_str)
        .or_else(|| sys_field("reducedMotion").and_then(Value::as_bool))
        .unwrap_or(false);

    let haptic_feedback = get("aetherflow-haptic-feedback")
        .as_deref()
        .and_then(parse_bool_str)
        .or_else(|| sys_field("hapticFeedback").and_then(Value::as_bool))
        .unwrap_or(true);

    let high_refresh_mode = get("aetherflow-high-refresh-mode")
        .or_else(|| {
            sys_field("highRefreshMode")
                .and_then(Value::as_str)
                .map(String::from)
        })
        .map(|v| normalize_high_refresh_mode(&v).to_string())
        .unwrap_or_else(|| "auto".into());

    let touch_mode = get("aetherflow-touch-mode")
        .or_else(|| {
            sys_field("touchMode")
                .and_then(Value::as_str)
                .map(String::from)
        })
        .map(|v| normalize_touch_mode(&v).to_string())
        .unwrap_or_else(|| "auto".into());

    HydratedPreferences {
        locale,
        theme,
        immersive_overview,
        show_gpu,
        show_transfer_history,
        reduced_motion,
        haptic_feedback,
        high_refresh_mode,
        touch_mode,
    }
}

pub(super) fn media_query(query: &str) -> Option<wasm_bindgen::JsValue> {
    let window = web_sys::window()?;
    js_sys::Reflect::get(&window, &"matchMedia".into())
        .ok()?
        .dyn_into::<js_sys::Function>()
        .ok()?
        .call1(&window, &query.into())
        .ok()
}

fn media_query_matches(query: &str) -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        media_query(query)
            .and_then(|mql| js_sys::Reflect::get(&mql, &"matches".into()).ok())
            .and_then(|matches| matches.as_bool())
            == Some(true)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = query;
        false
    }
}

pub(super) fn color_scheme_query() -> Option<wasm_bindgen::JsValue> {
    media_query("(prefers-color-scheme: light)")
}

pub(super) fn detect_touch_device() -> bool {
    // A hoverless desktop or headless browser can report no pointing device.
    // Use the primary pointer capability to select touch-sized controls.
    media_query_matches("(pointer: coarse)")
}

pub(super) fn detect_reduced_motion_preference() -> bool {
    media_query_matches("(prefers-reduced-motion: reduce)")
}

pub(super) fn theme_is_light(pref: &str) -> bool {
    pref == "light" || (pref == "system" && media_query_matches("(prefers-color-scheme: light)"))
}

pub fn apply_theme_dom(pref: &str) {
    let light = theme_is_light(pref);
    let mode = if light { "light" } else { "dark" };
    let theme_color = if light { "#f4f6fa" } else { "#07090e" };
    if let Some(document) = web_sys::window().and_then(|window| window.document()) {
        if let Some(root) = document.document_element() {
            // Keep unrelated root classes while replacing the effective theme.
            let classes = root.class_name();
            let mut classes: Vec<_> = classes
                .split_whitespace()
                .filter(|class| !matches!(*class, "dark" | "light"))
                .collect();
            classes.push(mode);
            let _ = root.set_attribute("class", &classes.join(" "));
            let _ = root.set_attribute("data-theme", mode);
        }
        if let Ok(Some(meta)) = document.query_selector(r#"meta[name="theme-color"]"#) {
            let _ = meta.set_attribute("content", theme_color);
        }
    }
}

pub fn apply_display_preferences_dom(context: AppContext) {
    let reduced_user = context.reduced_motion.get();
    let motion_suppressed = reduced_user || context.system_reduced_motion.get();
    let refresh_mode = context.high_refresh_mode.get();
    let detected_hz = context.detected_refresh_rate.get();
    let high_refresh =
        !motion_suppressed && resolve_high_refresh_active(&refresh_mode, detected_hz);
    let touch_pref = context.touch_mode.get();
    let detected_touch = context.detected_touch_device.get();
    let touch_active = resolve_touch_mode_active(&touch_pref, detected_touch);
    let density = if context.immersive_overview.get() {
        "immersive"
    } else {
        "compact"
    };

    #[cfg(target_arch = "wasm32")]
    if let Some(root) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    {
        if reduced_user {
            let _ = root.set_attribute("data-reduced-motion", "true");
        } else {
            let _ = root.remove_attribute("data-reduced-motion");
        }
        let _ = root.set_attribute(
            "data-refresh-mode",
            normalize_high_refresh_mode(&refresh_mode),
        );
        let _ = root.set_attribute(
            "data-high-refresh",
            if high_refresh { "true" } else { "false" },
        );
        let _ = root.set_attribute("data-touch-preference", normalize_touch_mode(&touch_pref));
        let _ = root.set_attribute(
            "data-touch-mode",
            if touch_active { "true" } else { "false" },
        );
        let _ = root.set_attribute("data-density", density);
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (reduced_user, high_refresh, touch_active, density);
}

pub fn apply_locale_dom(locale: &str) {
    if let Some(document) = web_sys::window().and_then(|window| window.document()) {
        if let Some(root) = document.document_element() {
            let _ = root.set_attribute("lang", af_web_core::i18n::bcp47_tag(locale));
        }
        // The root owns this link outside the shell, including public routes.
        if let Ok(Some(link)) = document.query_selector(".af-skip-link") {
            link.set_text_content(Some(&af_web_core::i18n::translate(
                locale,
                "Shell.skipToContent",
            )));
        }
    }
}

pub(super) fn initial_preference(key: &str) -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        storage_get(key)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = key;
        None
    }
}

pub fn detect_browser_locale(lang: Option<&str>) -> &'static str {
    match lang
        .unwrap_or_default()
        .trim()
        .split('-')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "de" => "de",
        "da" | "dk" => "dk",
        "es" => "es",
        "fr" => "fr",
        "zh" => "zh",
        _ => "en",
    }
}
