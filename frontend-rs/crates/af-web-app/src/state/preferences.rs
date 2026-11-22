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

pub fn quantize_aurora_opacity_pct(pct: f64) -> u8 {
    if !pct.is_finite() {
        return 55;
    }
    let clamped = pct.clamp(0.0, 100.0);
    (((clamped / 5.0).round() as i32) * 5).clamp(0, 100) as u8
}

pub fn normalize_aurora_opacity_pct(raw: &str) -> u8 {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return 55;
    }
    if let Some(pct_str) = trimmed.strip_suffix('%') {
        let Ok(pct) = pct_str.trim().parse::<f64>() else {
            return 55;
        };
        return quantize_aurora_opacity_pct(pct);
    }
    let Ok(val) = trimmed.parse::<f64>() else {
        return 55;
    };
    if !val.is_finite() {
        return 55;
    }
    if val < 0.0 {
        return 0;
    }
    let pct = if val <= 1.0 { val * 100.0 } else { val };
    quantize_aurora_opacity_pct(pct)
}

pub fn format_aurora_opacity_unit(pct: u8) -> String {
    let pct = quantize_aurora_opacity_pct(f64::from(pct));
    match pct {
        0 => "0".into(),
        100 => "1".into(),
        p if p % 10 == 0 => format!("0.{}", p / 10),
        p => format!("0.{p:02}"),
    }
}

pub fn normalize_card_lift(raw: &str) -> i8 {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return -4;
    }
    let stripped = trimmed.strip_suffix("px").unwrap_or(&trimmed).trim();
    match stripped {
        "false" | "off" | "none" | "flat" | "disabled" | "0" | "-0" => return 0,
        "true" | "on" | "enabled" | "spring" => return -4,
        _ => {}
    }
    let Ok(val) = stripped.parse::<f64>() else {
        return -4;
    };
    if !val.is_finite() {
        return -4;
    }
    if val.abs() < 1.0 {
        return 0;
    }
    let signed = -val.abs();
    let buckets = [-2i8, -4, -6, -8];
    buckets
        .into_iter()
        .min_by(|a, b| {
            (signed - f64::from(*a))
                .abs()
                .total_cmp(&(signed - f64::from(*b)).abs())
        })
        .unwrap_or(-4)
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
    pub aurora_opacity: u8,
    pub aurora_animation: bool,
    pub grain_display: bool,
    pub card_lift: i8,
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

    let aurora_opacity = get("aetherflow-aurora-opacity")
        .map(|v| normalize_aurora_opacity_pct(&v))
        .or_else(|| {
            sys_field("auroraOpacity").and_then(|v| {
                v.as_f64()
                    .map(|num| normalize_aurora_opacity_pct(&num.to_string()))
                    .or_else(|| v.as_str().map(normalize_aurora_opacity_pct))
            })
        })
        .unwrap_or(55);

    let aurora_animation = get("aetherflow-aurora-animation")
        .as_deref()
        .and_then(parse_bool_str)
        .or_else(|| sys_field("auroraAnimation").and_then(Value::as_bool))
        .unwrap_or(false);

    let grain_display = get("aetherflow-grain-display")
        .or_else(|| get("aetherflow-grain"))
        .as_deref()
        .and_then(parse_bool_str)
        .or_else(|| {
            sys_field("grainDisplay")
                .and_then(|v| v.as_bool().or_else(|| v.as_str().and_then(parse_bool_str)))
        })
        .unwrap_or(true);

    let card_lift = get("aetherflow-card-lift")
        .map(|v| normalize_card_lift(&v))
        .or_else(|| {
            sys_field("cardLift").and_then(|v| {
                v.as_i64()
                    .map(|n| normalize_card_lift(&n.to_string()))
                    .or_else(|| v.as_f64().map(|n| normalize_card_lift(&n.to_string())))
                    .or_else(|| v.as_bool().map(|b| if b { -4 } else { 0 }))
                    .or_else(|| v.as_str().map(normalize_card_lift))
            })
        })
        .unwrap_or(-4);

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
        aurora_opacity,
        aurora_animation,
        grain_display,
        card_lift,
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
    let mode = if theme_is_light(pref) {
        "light"
    } else {
        "dark"
    };
    if let Some(root) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    {
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
    let aurora_opacity = quantize_aurora_opacity_pct(f64::from(context.aurora_opacity.get()));
    let aurora_anim = context.aurora_animation.get() && !motion_suppressed;
    let grain = context.grain_display.get();
    let card_lift = if motion_suppressed {
        0
    } else {
        context.card_lift.get()
    };
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
        let _ = root.set_attribute("data-aurora-opacity", &aurora_opacity.to_string());
        let _ = root.set_attribute(
            "data-aurora-animation",
            if aurora_anim { "true" } else { "false" },
        );
        let _ = root.set_attribute("data-grain", if grain { "true" } else { "false" });
        let _ = root.set_attribute("data-card-lift", &card_lift.to_string());
        let _ = root.set_attribute("data-density", density);
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (
        reduced_user,
        high_refresh,
        touch_active,
        aurora_opacity,
        aurora_anim,
        grain,
        card_lift,
        density,
    );
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
