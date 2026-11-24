#[cfg(target_arch = "wasm32")]
use super::preferences::quantize_refresh_rate;
use super::preferences::{
    apply_locale_dom, color_scheme_query, detect_reduced_motion_preference, detect_touch_device,
    hydrate_preferences_with, media_query,
};
use super::AppContext;
use af_web_core::{
    api::{storage_get, ApiClient},
    ws::ConnectionState,
};
use gloo_events::EventListener;
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

#[cfg(any(test, target_arch = "wasm32"))]
pub(super) fn is_spa_fallback_path(path: &str) -> bool {
    !matches!(
        path.trim_end_matches('/'),
        "" | "/login" | "/oauth/consent" | "/oauth/device" | "/share"
    )
}

pub(super) fn purge_ai_sessions() {
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        for storage in [window.session_storage(), window.local_storage()]
            .into_iter()
            .filter_map(Result::ok)
            .flatten()
        {
            // Remove backwards so deleting an entry never skips its successor.
            for index in (0..storage.length().unwrap_or(0)).rev() {
                if let Ok(Some(key)) = storage.key(index) {
                    if key.starts_with("aetherflow-ai-sessions") {
                        let _ = storage.remove_item(&key);
                    }
                }
            }
        }
    }
}

pub(super) fn suspend_shell_interaction() {
    if let Some(document) = web_sys::window().and_then(|window| window.document()) {
        // A modal dialog can escape an ancestor's inertness, so suspend both
        // the shell and any open dialogs until the reactive shell is disposed.
        if let Ok(nodes) = document.query_selector_all(".af-shell, .af-shell dialog[open]") {
            for index in 0..nodes.length() {
                if let Some(element) = nodes
                    .item(index)
                    .and_then(|node| node.dyn_into::<web_sys::Element>().ok())
                {
                    let _ = element.set_attribute("inert", "");
                }
            }
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct SessionUser {
    #[serde(alias = "ID", alias = "user_id", alias = "userId")]
    id: i64,
    #[serde(alias = "Username", alias = "userName", alias = "name")]
    username: String,
    email: String,
    #[serde(alias = "avatarUrl")]
    avatar_url: String,
    role: String,
    #[serde(alias = "isOAuth", alias = "isOauth")]
    is_oauth: bool,
    #[serde(alias = "totpEnabled")]
    totp_enabled: bool,
}

pub(super) fn confirmed_session_identity(value: &Value) -> bool {
    serde_json::from_value::<SessionUser>(value.clone())
        .is_ok_and(|user| user.id > 0 || !user.username.trim().is_empty())
}

pub(super) fn deserialize_user(value: &Value) -> Option<af_web_core::models::User> {
    let user: SessionUser = serde_json::from_value(value.clone()).ok()?;
    Some(af_web_core::models::User {
        id: user.id,
        username: if user.username.is_empty() {
            "Operator".into()
        } else {
            user.username
        },
        email: user.email,
        avatar_url: user.avatar_url,
        role: if user.role.is_empty() {
            "user".into()
        } else {
            user.role
        },
        is_oauth: user.is_oauth,
        totp_enabled: user.totp_enabled,
        ..Default::default()
    })
}

pub(super) fn same_authenticated_identity(prev: Option<&Value>, next: Option<&Value>) -> bool {
    let (Some(prev), Some(next)) = (prev, next) else {
        return false;
    };
    match (
        prev.get("id").filter(|id| !id.is_null()),
        next.get("id").filter(|id| !id.is_null()),
    ) {
        (Some(prev), Some(next)) => prev == next,
        (None, None) => {
            let username = prev["username"]
                .as_str()
                .filter(|name| !name.trim().is_empty());
            username.is_some() && username == next["username"].as_str()
        }
        _ => false,
    }
}

fn defaulted_payload<T: Default + Serialize>(value: &Value) -> Value {
    let mut defaults = serde_json::to_value(T::default()).expect("serializable model defaults");
    if let (Some(defaults), Some(fields)) = (defaults.as_object_mut(), value.as_object()) {
        for (key, value) in fields.iter().filter(|(_, value)| !value.is_null()) {
            defaults.insert(key.clone(), value.clone());
        }
    }
    defaults
}

pub(super) fn deserialize_metrics(value: &Value) -> af_web_core::models::SystemMetrics {
    use af_web_core::models::{DiskPartition, GpuMetric, ProcessInfo, SystemMetrics};
    let mut payload = defaulted_payload::<SystemMetrics>(value);
    for key in ["disks", "gpus", "processes"] {
        if let Some(records) = payload.get_mut(key).and_then(Value::as_array_mut) {
            for record in records {
                *record = match key {
                    "disks" => defaulted_payload::<DiskPartition>(record),
                    "gpus" => defaulted_payload::<GpuMetric>(record),
                    _ => defaulted_payload::<ProcessInfo>(record),
                };
            }
        }
    }
    serde_json::from_value(payload).unwrap_or_default()
}

pub fn app() -> AppContext {
    expect_context::<AppContext>()
}
pub fn worker_pool() -> af_web_core::worker_pool::WorkerPool {
    af_web_core::worker_pool::WorkerPool::shared()
}
pub fn navigate(path: &str) {
    if let Some(window) = web_sys::window() {
        let _ = window.location().assign(path);
    }
}
pub fn query_param(key: &str) -> Option<String> {
    web_sys::window()
        .and_then(|w| w.location().search().ok())
        .and_then(|q| web_sys::UrlSearchParams::new_with_str(&q).ok())
        .and_then(|q| q.get(key))
}
pub fn current_path() -> String {
    web_sys::window()
        .map(|w| {
            format!(
                "{}{}{}",
                w.location().pathname().unwrap_or_default(),
                w.location().search().unwrap_or_default(),
                w.location().hash().unwrap_or_default()
            )
        })
        .unwrap_or_else(|| "/".into())
}
#[cfg(target_arch = "wasm32")]
fn probe_display_refresh_rate(context: AppContext) {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use wasm_bindgen::closure::Closure;

    let Some(window) = web_sys::window() else {
        return;
    };
    let raf_id = Rc::new(Cell::new(None::<i32>));
    let raf_id_cleanup = Rc::clone(&raf_id);
    type FrameCallback = Closure<dyn FnMut(f64)>;
    let callback_slot = Rc::new(RefCell::new(None::<FrameCallback>));
    let callback_slot_inner = Rc::clone(&callback_slot);
    let callback_slot_cleanup = Rc::clone(&callback_slot);
    let mut frames = 0u32;
    let mut start_ms = 0.0f64;
    let win_inner = window.clone();

    *callback_slot.borrow_mut() = Some(Closure::wrap(Box::new(move |timestamp: f64| {
        if frames == 0 {
            start_ms = timestamp;
        }
        frames += 1;
        if frames <= 18 {
            if let Some(cb) = callback_slot_inner.borrow().as_ref() {
                raf_id.set(
                    win_inner
                        .request_animation_frame(cb.as_ref().unchecked_ref())
                        .ok(),
                );
            }
        } else {
            raf_id.set(None);
            let elapsed = timestamp - start_ms;
            if elapsed > 0.0 {
                let fps = (18.0 * 1000.0) / elapsed;
                let _ = context
                    .detected_refresh_rate
                    .try_set(quantize_refresh_rate(fps));
            }
            let _ = callback_slot_inner.borrow_mut().take();
        }
    }) as Box<dyn FnMut(f64)>));

    if let Some(cb) = callback_slot.borrow().as_ref() {
        raf_id_cleanup.set(
            window
                .request_animation_frame(cb.as_ref().unchecked_ref())
                .ok(),
        );
    }

    let handles = StoredValue::new_local((raf_id_cleanup, callback_slot_cleanup));
    on_cleanup(move || {
        handles.with_value(|(raf_id, callback)| {
            if let (Some(id), Some(win)) = (raf_id.take(), web_sys::window()) {
                let _ = win.cancel_animation_frame(id);
            }
            callback.borrow_mut().take();
        })
    });
}

pub fn install_session(context: AppContext) {
    let public_route = web_sys::window()
        .and_then(|w| w.location().pathname().ok())
        .is_some_and(|p| matches!(p.trim_end_matches('/'), "/login" | "/share"));
    if public_route {
        context.auth_loading.set(false);
    } else {
        context.refresh_session();
    }
    #[cfg(target_arch = "wasm32")]
    probe_display_refresh_rate(context);
    let handles = StoredValue::new_local(Vec::<EventListener>::new());
    if let Some(window) = web_sys::window() {
        let storage = EventListener::new(&window, "storage", move |event| {
            let Some(event) = event.dyn_ref::<web_sys::StorageEvent>() else {
                return;
            };
            // Read the latest storage snapshot so delayed events cannot restore
            // a stale preference. A null key represents localStorage.clear().
            let key = event.key();
            let matches_pref = key.is_none()
                || key.as_deref().is_some_and(|k| {
                    matches!(
                        k,
                        "aetherflow-theme"
                            | "aetherflow-language"
                            | "aetherflow-immersive-overview"
                            | "aetherflow-dashboard-density"
                            | "aetherflow-show-gpu"
                            | "aetherflow-show-transfer-history"
                            | "aetherflow-reduced-motion"
                            | "aetherflow-haptic-feedback"
                            | "aetherflow-high-refresh-mode"
                            | "aetherflow-touch-mode"
                            | "aetherflow-aurora-opacity"
                            | "aetherflow-aurora-animation"
                            | "aetherflow-grain-display"
                            | "aetherflow-grain"
                            | "aetherflow-card-lift"
                            | "aetherflow-system-storage"
                            | "aetherflow-connection-storage"
                    )
                });
            if matches_pref {
                let hydrated = hydrate_preferences_with(storage_get);
                context.theme.set(hydrated.theme);
                if key.is_none()
                    || matches!(
                        key.as_deref(),
                        Some("aetherflow-language" | "aetherflow-system-storage")
                    )
                {
                    let locale = hydrated.locale.unwrap_or_else(|| "en".into());
                    context.locale.set(locale.clone());
                    context.load_locale(locale);
                }
                context.immersive_overview.set(hydrated.immersive_overview);
                context.show_gpu.set(hydrated.show_gpu);
                context
                    .show_transfer_history
                    .set(hydrated.show_transfer_history);
                context.reduced_motion.set(hydrated.reduced_motion);
                context.haptic_feedback.set(hydrated.haptic_feedback);
                context.high_refresh_mode.set(hydrated.high_refresh_mode);
                context.touch_mode.set(hydrated.touch_mode);
                context.aurora_opacity.set(hydrated.aurora_opacity);
                context.aurora_animation.set(hydrated.aurora_animation);
                context.grain_display.set(hydrated.grain_display);
                context.card_lift.set(hydrated.card_lift);
            }
            if key
                .as_deref()
                .is_some_and(|key| matches!(key, "af_login_sync" | "af_logout_sync"))
            {
                context.revalidate_external_session();
            }
        });
        let expired = EventListener::new(&window, "af:session-expired", move |_| {
            if context.auth_loading.get_untracked() {
                return;
            }
            if js_sys::Date::now() - context.authenticated_at.get_untracked() < 10_000.0 {
                context.refresh_session();
            } else {
                if context.user.with_untracked(Option::is_some) {
                    context.reset_account_scoped_state();
                    context.session_epoch.update(|epoch| *epoch += 1);
                }
                af_web_core::api::clear_csrf_token();
                context.user.set(None);
                context.connection.set(ConnectionState::Offline);
            }
        });
        let keys = EventListener::new_with_options(
            &window,
            "keydown",
            gloo_events::EventListenerOptions::enable_prevent_default(),
            move |event| {
                if let Some(event) = event.dyn_ref::<web_sys::KeyboardEvent>() {
                    if (event.ctrl_key() || event.meta_key())
                        && event.key().eq_ignore_ascii_case("k")
                    {
                        if event.cancelable() {
                            event.prevent_default();
                        }
                        context.command_open.update(|v| *v = !*v);
                    }
                }
            },
        );
        handles.set_value(vec![storage, expired, keys]);
        if let Some(query) =
            color_scheme_query().and_then(|query| query.dyn_into::<web_sys::EventTarget>().ok())
        {
            let scheme = EventListener::new(&query, "change", move |_| {
                if context.theme.with_untracked(|pref| pref == "system") {
                    // Notify DOM and Header consumers without persisting an
                    // explicit mode over the user's system preference.
                    context.theme.set("system".into());
                }
            });
            handles.update_value(|handles| handles.push(scheme));
        }
        if let Some(pointer_query) = media_query("(pointer: coarse)")
            .and_then(|query| query.dyn_into::<web_sys::EventTarget>().ok())
        {
            let pointer_listener = EventListener::new(&pointer_query, "change", move |_| {
                context.detected_touch_device.set(detect_touch_device());
            });
            handles.update_value(|handles| handles.push(pointer_listener));
        }
        if let Some(motion_query) = media_query("(prefers-reduced-motion: reduce)")
            .and_then(|query| query.dyn_into::<web_sys::EventTarget>().ok())
        {
            let motion_listener = EventListener::new(&motion_query, "change", move |_| {
                context
                    .system_reduced_motion
                    .set(detect_reduced_motion_preference());
            });
            handles.update_value(|handles| handles.push(motion_listener));
        }
    }
    on_cleanup(move || handles.update_value(Vec::clear));
    let channel = StoredValue::new_local(web_sys::BroadcastChannel::new("aetherflow-auth").ok());
    let messages = StoredValue::new_local(channel.with_value(|channel| {
        channel.as_ref().map(|channel| {
            EventListener::new(channel, "message", move |_| {
                context.revalidate_external_session()
            })
        })
    }));
    on_cleanup(move || {
        messages.set_value(None);
        channel.update_value(|channel| {
            if let Some(channel) = channel.take() {
                channel.close();
            }
        });
    });
    let interval = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        600_000,
        move || {
            if context.user.with_untracked(Option::is_some) {
                spawn_local(async {
                    let _ = ApiClient
                        .request("/api/v1/auth/refresh", "POST", None)
                        .await;
                });
            }
        },
    )));
    on_cleanup(move || interval.set_value(None));
    Effect::new(move |_| {
        context.catalog_revision.get();
        apply_locale_dom(&context.locale.get());
    });
}
