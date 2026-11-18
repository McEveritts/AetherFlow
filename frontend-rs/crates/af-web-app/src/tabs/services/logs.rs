//! Administrator journal session and export controls.
use super::helpers::{copy_text, field, service_units};
use crate::state::{app, json_rows, use_api};
use crate::tabs::l10n::{tt, Modal, SearchInput};
use af_web_ui::use_worker_rows;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

fn download_logs(name: &str, content: &str) -> Result<(), String> {
    let document = web_sys::window()
        .and_then(|w| w.document())
        .ok_or("Document unavailable")?;
    let link = document
        .create_element("a")
        .map_err(|_| "Could not create download")?;
    link.set_attribute(
        "href",
        &format!(
            "data:text/plain;charset=utf-8,{}",
            js_sys::encode_uri_component(content)
        ),
    )
    .map_err(|_| "Could not create download")?;
    let name: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    link.set_attribute("download", &format!("{name}.log"))
        .map_err(|_| "Could not create download")?;
    link.dyn_ref::<web_sys::HtmlElement>()
        .ok_or("Could not start download")?
        .click();
    Ok(())
}

fn log_level(row: &Value) -> String {
    let explicit = field(row, &["level", "severity"]).to_ascii_uppercase();
    let message = field(row, &["message", "line"]).to_ascii_uppercase();
    if let Some(priority) = row["priority"]
        .as_u64()
        .or_else(|| row["priority"].as_str()?.parse().ok())
    {
        return match priority {
            0..=3 => "ERROR",
            4 => "WARN",
            _ => "INFO",
        }
        .into();
    }
    if explicit.contains("ERR")
        || explicit.contains("CRIT")
        || message.contains("ERROR")
        || message.contains("FATAL")
    {
        "ERROR"
    } else if explicit.contains("WARN") || message.contains("WARN") {
        "WARN"
    } else {
        "INFO"
    }
    .into()
}
#[component]
pub(super) fn ServiceLogsModal(
    open: RwSignal<bool>,
    service: RwSignal<Option<Value>>,
) -> impl IntoView {
    let context = app();
    let lines = RwSignal::new("100".to_string());
    let following = RwSignal::new(true);
    let query = RwSignal::new(String::new());
    let severity = RwSignal::new("ALL".to_string());
    let units = Signal::derive(move || {
        service.with(|v| {
            let Some(v) = v else {
                return Vec::new();
            };
            service_units(v)
        })
    });
    let unit = RwSignal::new(String::new());
    Effect::new(move |_| {
        let units = units.get();
        if !units.contains(&unit.get_untracked()) {
            unit.set(units.first().cloned().unwrap_or_default());
        }
    });
    // Mounted only while an administrator has opened a service's log session.
    let logs = use_api(Signal::derive(move || {
        format!(
            "/api/v1/admin/logs?unit={}&lines={}&limit={}",
            js_sys::encode_uri_component(&unit.get()),
            lines.get(),
            lines.get()
        )
    }));
    Effect::new(move |_| {
        unit.track();
        lines.track();
        // Never relabel a previous unit's cached lines as the newly selected journal.
        logs.data.set(Value::Null);
    });
    let interval = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        2000,
        move || {
            if following.get_untracked()
                && open.get_untracked()
                && context.is_admin()
                && !logs.loading.get_untracked()
            {
                logs.refresh();
            }
        },
    )));
    on_cleanup(move || interval.set_value(None));
    let rows = Signal::derive(move || {
        let data = logs.data.get();
        let source = data["logs"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| json_rows(&data));
        let count = lines.get().parse::<usize>().unwrap_or(100);
        let start = source.len().saturating_sub(count);
        source
            .into_iter()
            .skip(start)
            .map(|v| {
                let mut row = if let Some(line) = v.as_str() {
                    json!({"message":line})
                } else {
                    v
                };
                if row["message"].is_null() {
                    row["message"] = row["line"].clone();
                }
                row["level"] = json!(log_level(&row));
                row
            })
            .collect::<Vec<_>>()
    });
    let searched = use_worker_rows(
        rows,
        query.into(),
        vec!["message".into(), "level".into(), "timestamp".into()],
    );
    let visible = Signal::derive(move || {
        let severity = severity.get();
        searched
            .get()
            .into_iter()
            .filter(|v| severity == "ALL" || v["level"] == severity)
            .collect::<Vec<_>>()
    });
    let output = move || {
        visible.with(|rows| {
            rows.iter()
                .map(|v| {
                    format!(
                        "{} [{}] {}",
                        field(v, &["timestamp", "time"]),
                        field(v, &["level"]),
                        field(v, &["message"])
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
    };
    view! {
        <Modal open title="Service Logs">
            <div class="space-y-4 min-w-0">
                <h3 class="font-semibold break-words">
                    {move || {
                        service.with(|v| v.as_ref().map(|v| field(v, &["name", "id", "slug"])))
                    }}
                </h3>
                <div
                    class="flex flex-wrap gap-3 items-center"
                    role="group"
                    aria-label=move || tt(context, "Log controls")
                >
                    <label class="text-xs text-slate-400">
                        {move || tt(context, "Unit ")}
                        <select
                            class="glass-input px-3 py-2 max-w-full"
                            aria-label=move || tt(context, "Journal unit")
                            prop:value=move || unit.get()
                            on:change=move |ev| unit.set(event_target_value(&ev))
                        >
                            {move || {
                                units
                                    .get()
                                    .into_iter()
                                    .map(|unit| {
                                        view! { <option value=unit.clone()>{unit.clone()}</option> }
                                    })
                                    .collect_view()
                            }}
                        </select>
                    </label>
                    <label class="text-xs text-slate-400">
                        {move || tt(context, "Lines ")}
                        <select
                            class="glass-input px-3 py-2"
                            aria-label=move || tt(context, "Log line count")
                            prop:value=move || lines.get()
                            on:change=move |ev| lines.set(event_target_value(&ev))
                        >
                            {["100", "500", "1000"]
                                .into_iter()
                                .map(|n| view! { <option value=n>{n}</option> })
                                .collect_view()}
                        </select>
                    </label>
                    <button
                        type="button"
                        class="glass-button px-3 py-2 min-h-11"
                        aria-pressed=move || following.get().to_string()
                        on:click=move |_| following.update(|v| *v = !*v)
                    >
                        {move || {
                            if following.get() {
                                tt(context, "Services.pauseAutoRefresh")
                            } else {
                                tt(context, "Services.resumeAutoRefresh")
                            }
                        }}
                    </button>
                    <button
                        type="button"
                        class="glass-button px-3 py-2 min-h-11"
                        disabled=move || logs.loading.get()
                        on:click=move |_| logs.refresh()
                        aria-label=move || tt(context, "Refresh logs")
                    >
                        {move || tt(context, "Common.refresh")}
                    </button>
                </div>
                <SearchInput value=query placeholder="Search journal logs" />
                <div
                    class="flex flex-wrap gap-2"
                    role="group"
                    aria-label=move || tt(context, "Log severity")
                >
                    {["ALL", "ERROR", "WARN", "INFO"]
                        .into_iter()
                        .map(|level| {
                            view! {
                                <button
                                    type="button"
                                    class="obs-tab-pill px-3 py-2 min-h-11"
                                    class:obs-tab-pill-active=move || severity.get() == level
                                    aria-pressed=move || (severity.get() == level).to_string()
                                    on:click=move |_| severity.set(level.into())
                                >
                                    {move || tt(context, level)}
                                </button>
                            }
                        })
                        .collect_view()}
                </div>
                <Show when=move || logs.error.get().is_some()>
                    <p role="alert" class="text-rose-300 text-sm">
                        {move || logs.error.get().map(|e| tt(context, &e.message))}
                    </p>
                </Show>
                <Show when=move || logs.loading.get()>
                    <p role="status" class="text-xs text-slate-500">
                        {move || tt(context, "Reading journal…")}
                    </p>
                </Show>
                <div
                    class="max-h-[50vh] min-h-48 overflow-auto obs-scroller bg-slate-950 rounded-xl p-4 font-mono text-xs space-y-2"
                    role="log"
                    aria-label=move || tt(context, "Systemd journal logs")
                    aria-live="off"
                >
                    {move || {
                        visible
                            .get()
                            .into_iter()
                            .map(|row| {
                                view! {
                                    <p class=match row["level"].as_str() {
                                        Some("ERROR") => {
                                            "text-rose-300 whitespace-pre-wrap break-all"
                                        }
                                        Some("WARN") => {
                                            "text-amber-300 whitespace-pre-wrap break-all"
                                        }
                                        _ => "text-slate-300 whitespace-pre-wrap break-all",
                                    }>
                                        {format!(
                                            "{} [{}] {}",
                                            field(&row, &["timestamp", "time"]),
                                            field(&row, &["level"]),
                                            field(&row, &["message"]),
                                        )}
                                    </p>
                                }
                            })
                            .collect_view()
                    }}
                    <Show when=move || !logs.loading.get() && visible.with(Vec::is_empty)>
                        <p class="text-slate-500">
                            {move || tt(context, "No journal lines match these filters.")}
                        </p>
                    </Show>
                </div>
                <div class="flex gap-3 justify-end">
                    <button
                        type="button"
                        class="glass-button px-4 py-2 min-h-11"
                        disabled=move || visible.with(Vec::is_empty)
                        on:click=move |_| {
                            if !context.is_admin() {
                                return;
                            }
                            let output = output();
                            spawn_local(async move {
                                match copy_text(&output).await {
                                    Ok(()) => context.toast(tt(context, "Logs copied"), false),
                                    Err(e) => context.toast(tt(context, &e), true),
                                }
                            });
                        }
                    >
                        {move || tt(context, "Copy logs")}
                    </button>
                    <button
                        type="button"
                        class="glass-button px-4 py-2 min-h-11"
                        disabled=move || visible.with(Vec::is_empty)
                        on:click=move |_| {
                            if context.is_admin() {
                                if let Err(e) = download_logs(&unit.get_untracked(), &output()) {
                                    context.toast(tt(context, &e), true);
                                }
                            }
                        }
                    >
                        {move || tt(context, "Download logs")}
                    </button>
                </div>
            </div>
        </Modal>
    }
}
