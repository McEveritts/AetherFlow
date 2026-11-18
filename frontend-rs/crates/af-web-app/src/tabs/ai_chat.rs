//! FlowAI operations console. Proposals are reviewed exclusively in the inbox.
use crate::state::{app, use_api, TabId};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{Badge, EmptyState, ObsCard};
use af_web_core::api::ApiClient;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

const PROVIDERS: [(&str, &str, &str); 6] = [
    ("gemini", "Google Gemini", "geminiApiKey"),
    ("anthropic", "Anthropic Claude", "anthropicApiKey"),
    ("openai", "OpenAI", "openaiApiKey"),
    ("ollama", "Ollama", "ollamaEndpoint"),
    ("lm-studio", "LM Studio", "lmStudioEndpoint"),
    (
        "anthropic-local",
        "Local Anthropic endpoint",
        "anthropicEndpoint",
    ),
];
fn text(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_string()
}
fn valid_model(model: &str) -> bool {
    !matches!(
        model.trim().to_ascii_lowercase().as_str(),
        "" | "gemini"
            | "anthropic"
            | "openai"
            | "localai"
            | "local-test"
            | "local"
            | "lm-studio"
            | "ollama"
            | "anthropic-local"
    )
}
fn default_model(provider: &str) -> &'static str {
    match provider {
        "openai" => "gpt-6-astra",
        "anthropic" => "claude-fable-5-1",
        "ollama" => "llama3.2:latest",
        "lm-studio" => "qwen2.5-coder-7b-instruct",
        "anthropic-local" => "claude-sonnet-5-5",
        _ => "gemini-4-argon",
    }
}
fn configured_selection(settings: &Value) -> (String, String) {
    let raw = text(settings, "aiModel");
    let local = text(settings, "localModel");
    let runtime = text(settings, "localProvider");
    let runtime = if runtime.is_empty() {
        text(settings, "localRuntime")
    } else {
        runtime
    };
    for runtime in ["ollama", "lm-studio", "anthropic-local"] {
        if raw == runtime || raw.starts_with(&format!("{runtime}:")) {
            let model = raw.strip_prefix(&format!("{runtime}:")).unwrap_or("");
            return (
                runtime.to_string(),
                if valid_model(&local) {
                    local
                } else if valid_model(model) {
                    model.to_string()
                } else {
                    default_model(runtime).to_string()
                },
            );
        }
    }
    let cloud = if raw == "gemini-4-argon" || !valid_model(&raw) {
        Some("gemini")
    } else if ["gpt-6-astra", "gpt-6.1-sol", "gpt-6.1-terra", "gpt-6-luna"].contains(&raw.as_str())
    {
        Some("openai")
    } else if [
        "claude-fable-5-1",
        "claude-opus-5-5",
        "claude-sonnet-5-5",
        "claude-haiku-5-5",
    ]
    .contains(&raw.as_str())
    {
        Some("anthropic")
    } else {
        None
    };
    let provider = if let Some(provider) = cloud {
        provider
    } else if matches!(runtime.as_str(), "ollama" | "lm-studio" | "anthropic-local") {
        &runtime
    } else if !text(settings, "anthropicEndpoint").is_empty()
        && text(settings, "anthropicEndpoint") != "https://api.anthropic.com"
    {
        "anthropic-local"
    } else if !text(settings, "ollamaEndpoint").is_empty()
        && text(settings, "ollamaEndpoint") != "http://localhost:11434"
    {
        "ollama"
    } else if !text(settings, "lmStudioEndpoint").is_empty() {
        "lm-studio"
    } else {
        "ollama"
    };
    let selected_model = if cloud.is_none() && valid_model(&local) {
        local
    } else if valid_model(&raw) {
        raw
    } else {
        default_model(provider).to_string()
    };
    (provider.to_string(), selected_model)
}
fn new_thread(locale: &str) -> Value {
    json!({"id":format!("{}-{}",js_sys::Date::now(),js_sys::Math::random()),"title":af_web_core::i18n::translate(locale, "New conversation"),"messages":[],"createdAt":js_sys::Date::new_0().to_iso_string().as_string().unwrap_or_default()})
}

fn resolve_ai_chat_endpoint(attach_telemetry: bool, is_admin: bool) -> (&'static str, bool) {
    if attach_telemetry && is_admin {
        ("/api/v1/auth/ai/support", true)
    } else {
        ("/api/v1/auth/ai/chat", false)
    }
}

/// Only one send can be pending. Its origin and append position identify the
/// optimistic turn even if the operator selects a different conversation or
/// starts a newer composer draft while the request is in flight.
#[derive(Clone)]
struct PendingTurn {
    thread_id: String,
    index: usize,
    turn: Value,
    previous_title: Value,
}

impl PendingTurn {
    fn append(threads: &mut [Value], thread_id: &str, message: &str) -> Option<Self> {
        let thread = threads
            .iter_mut()
            .find(|thread| thread["id"] == thread_id)?;
        let previous_title = thread["title"].clone();
        let messages = thread["messages"].as_array_mut()?;
        let index = messages.len();
        let turn = json!({"role":"user", "text":message});
        messages.push(turn.clone());
        if index == 0 {
            thread["title"] = json!(message.chars().take(64).collect::<String>());
        }
        Some(Self {
            thread_id: thread_id.into(),
            index,
            turn,
            previous_title,
        })
    }

    fn rollback(&self, threads: &mut [Value]) {
        let Some(thread) = threads
            .iter_mut()
            .find(|thread| thread["id"] == self.thread_id)
        else {
            return;
        };
        let Some(messages) = thread["messages"].as_array_mut() else {
            return;
        };
        if messages.get(self.index) != Some(&self.turn) {
            return;
        }
        messages.remove(self.index);
        if messages.is_empty() {
            thread["title"] = self.previous_title.clone();
        }
    }
}

// Administrator service payloads include API keys. Only health fields may leave
// the console when the operator attaches telemetry to an inference request.
fn service_health(value: &Value) -> Value {
    let entries = value.as_array().cloned().unwrap_or_else(|| {
        value
            .as_object()
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(_, v)| v.is_object())
                    .map(|(name, service)| {
                        let mut service = service.clone();
                        if service["name"].is_null() {
                            service["name"] = json!(name);
                        }
                        service
                    })
                    .collect()
            })
            .unwrap_or_default()
    });
    json!(entries
        .into_iter()
        .map(|service| {
            let mut health = json!({});
            for key in [
                "id",
                "name",
                "status",
                "health",
                "cpu",
                "memory",
                "uptime",
                "version",
                "degraded_components",
            ] {
                if let Some(value) = service.get(key) {
                    health[key] = value.clone();
                }
            }
            health
        })
        .collect::<Vec<_>>())
}

#[component]
pub fn AiChatTab() -> impl IntoView {
    let context = app();
    let settings = use_api(Signal::derive(|| "/api/v1/auth/settings".to_string()));
    let user_id = context.user.with_untracked(|u| {
        u.as_ref()
            .and_then(|u| u.get("id"))
            .filter(|id| !id.is_null())
            .map(|id| {
                id.as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| id.to_string())
            })
            .unwrap_or_default()
    });
    let storage_key = StoredValue::new(format!("aetherflow-ai-sessions:{user_id}"));
    let owner_epoch = af_web_core::api::current_auth_epoch();
    let cached = web_sys::window()
        .and_then(|window| window.session_storage().ok().flatten())
        .and_then(|storage| storage.get_item(&storage_key.get_value()).ok().flatten())
        .and_then(|s| serde_json::from_str::<Vec<Value>>(&s).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|t| t["id"].is_string() && t["messages"].is_array())
        .take(40)
        .collect::<Vec<_>>();
    let initial = if cached.is_empty() {
        vec![new_thread(&crate::tabs::l10n::locale(context))]
    } else {
        cached
    };
    let active = RwSignal::new(text(&initial[0], "id"));
    let threads = RwSignal::new(initial);
    let pending_turn = StoredValue::new(None::<PendingTurn>);
    on_cleanup(move || {
        if let Some(pending) = pending_turn.get_value() {
            // Persist the rollback here: the normal persistence effect will be
            // disposed with the view and must not leave a failed optimistic turn.
            if let Some(value) = threads.try_update(|threads| {
                pending.rollback(threads);
                serde_json::to_string(threads).unwrap_or_default()
            }) {
                if af_web_core::api::current_auth_epoch() == owner_epoch {
                    if let Some(storage) =
                        web_sys::window().and_then(|window| window.session_storage().ok().flatten())
                    {
                        let _ = storage.set_item(&storage_key.get_value(), &value);
                    }
                }
            }
        }
    });
    let input = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let failure = RwSignal::new(None::<String>);
    let provider = RwSignal::new("gemini".to_string());
    let model = RwSignal::new(String::new());
    let initialized = RwSignal::new(false);
    let attach = RwSignal::new(context.is_admin());
    Effect::new(move |_| {
        if !context.is_admin() {
            attach.set(false);
        }
    });
    let context_mode = RwSignal::new("full".to_string());
    let messages = Memo::new(move |_| {
        let id = active.get();
        threads.with(|threads| {
            threads
                .iter()
                .find(|t| t["id"] == id)
                .and_then(|t| t["messages"].as_array().cloned())
                .unwrap_or_default()
        })
    });
    Effect::new(move |_| {
        let data = settings.data.get();
        if data.is_object() && !initialized.get_untracked() {
            let (p, m) = configured_selection(&data);
            provider.set(p);
            model.set(m);
            initialized.set(true);
        }
    });
    Effect::new(move |_| {
        let value = threads.get();
        if let Some(storage) =
            web_sys::window().and_then(|window| window.session_storage().ok().flatten())
        {
            let _ = storage.set_item(
                &storage_key.get_value(),
                &serde_json::to_string(&value).unwrap_or_default(),
            );
        }
    });
    let send = Callback::new(move |(): ()| {
        let message = input.get_untracked().trim().to_string();
        let selected_model = model.get_untracked().trim().to_string();
        if busy.get_untracked() || message.is_empty() {
            return;
        }
        if !valid_model(&selected_model) {
            failure.set(Some(
                "Specify an inference model ID; provider aliases are not models.".into(),
            ));
            return;
        }
        let thread_id = active.get_untracked();
        let history = messages.get_untracked();
        let mut body = json!({"message":message,"history":history,"model":selected_model,"provider":provider.get_untracked()});
        let (endpoint, attach_telemetry) =
            resolve_ai_chat_endpoint(attach.get_untracked(), context.is_admin());
        if attach_telemetry {
            let mode = context_mode.get_untracked();
            body["context_mode"] = json!(mode);
            if mode == "full" || mode == "metrics" {
                let metrics = context.metrics.get_untracked();
                let health = service_health(&context.services.get_untracked());
                let mut snapshot = if metrics.is_object() {
                    metrics
                } else {
                    json!({"telemetry":metrics})
                };
                snapshot["service_health"] = health;
                body["metrics_snapshot"] = snapshot;
            }
            if mode == "full" || mode == "logs" {
                body["system_logs"] = json!(context.toasts.with_untracked(|items| items
                    .iter()
                    .map(|t| json!({"message":t.message,"error":t.error}))
                    .collect::<Vec<_>>()));
            }
        }
        let pending = threads
            .try_update(|threads| PendingTurn::append(threads, &thread_id, &message))
            .flatten();
        let Some(pending) = pending else {
            return;
        };
        pending_turn.set_value(Some(pending.clone()));
        input.set(String::new());
        busy.set(true);
        failure.set(None);
        spawn_local(async move {
            let result = ApiClient.post(endpoint, Some(&body)).await;
            if busy.try_get_untracked().is_none() {
                return;
            }
            pending_turn.set_value(None);
            match result {
                Ok(data) => {
                    let reply = data["reply"]
                        .as_str()
                        .or_else(|| data["response"].as_str())
                        .or_else(|| data["content"].as_str())
                        .unwrap_or("The provider returned no response text.");
                    let proposed = data
                        .get("proposed_action")
                        .filter(|v| v.is_object())
                        .cloned()
                        .unwrap_or(Value::Null);
                    let pending = data
                        .get("pending_actions")
                        .filter(|v| !v.is_null())
                        .cloned()
                        .unwrap_or(Value::Null);
                    threads.update(|threads| {if let Some(messages)=threads.iter_mut().find(|t|t["id"]==thread_id).and_then(|t|t["messages"].as_array_mut()) {
                        messages.push(json!({"role":"assistant","text":reply,"payload":proposed,"pending_actions":pending}));
                    }});
                    if proposed.is_object()
                        || pending.as_array().is_some_and(|p| !p.is_empty())
                        || pending.as_u64().is_some_and(|n| n > 0)
                    {
                        let count = pending
                            .as_array()
                            .map(Vec::len)
                            .or_else(|| pending.as_u64().map(|n| n as usize))
                            .unwrap_or(1);
                        context.pending.update(|n| *n = (*n).max(count));
                        if context.is_admin() {
                            if let Ok(data) = ApiClient
                                .get("/api/v1/admin/actions/pending?status=pending&limit=1")
                                .await
                            {
                                if context.pending.try_get_untracked().is_some() {
                                    if let Some(total) = data["total"].as_u64() {
                                        context.pending.set(total as usize);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(error) => {
                    // Roll back the origin even when another conversation is
                    // active or the composer already contains a newer edit.
                    threads.update(|threads| pending.rollback(threads));
                    failure.set(Some(error.message));
                    if active.get_untracked() == thread_id
                        && input.with_untracked(|s| s.trim().is_empty())
                    {
                        input.set(message);
                    }
                }
            }
            if busy.try_get_untracked().is_some() {
                busy.set(false);
            }
        });
    });
    view! {
        <section class="space-y-5 py-5 min-w-0 max-w-full">
            <div class="flex flex-wrap justify-between gap-3 items-center">
                <div>
                    <h2 class="text-xl font-semibold">{move || tt(context, "Tabs.aiHeading")}</h2>
                    <p class="text-sm text-slate-400">
                        {move || tt(
                            context,
                            "Diagnostics, service health and human-approved remediation.",
                        )}
                    </p>
                </div>
                <button
                    class="glass-button px-4 py-2"
                    on:click=move |_| context.select_tab(TabId::Settings)
                >
                    {move || tt(context, "AI Settings")}
                </button>
            </div>
            {move || {
                settings
                    .error
                    .get()
                    .map(|e| {
                        view! {
                            <p role="alert" class="text-rose-300">
                                {move || tt(context, &e.message)}
                            </p>
                        }
                    })
            }}
            <div class="grid grid-cols-2 md:grid-cols-3 gap-3">
                {PROVIDERS
                    .into_iter()
                    .map(|(id, label, key)| {
                        view! {
                            <button
                                type="button"
                                class="glass-card p-3 text-left min-w-0"
                                aria-pressed=move || (provider.get() == id).to_string()
                                on:click=move |_| {
                                    provider.set(id.into());
                                    model.set(default_model(id).into());
                                }
                            >
                                <span class="block text-sm font-semibold">
                                    {move || tt(context, label)}
                                </span>
                                <span class="block text-xs text-slate-400">
                                    {move || tt(context, if settings.loading.get() {
                                            "Loading configuration"
                                        } else if settings.data.with(|s| !text(s, key).is_empty()) {
                                            "Configured"
                                        } else if !context.is_admin() {
                                            "Configuration status restricted"
                                        } else {
                                            "Configure in Settings"
                                        })}
                                </span>
                                <span class="text-xs text-indigo-300">
                                    {move || {
                                        if provider.get() == id {
                                            tt_with(context, "Active · {provider}", &[("provider", &(model.get()).to_string())])
                                        } else {
                                            String::new()
                                        }
                                    }}
                                </span>
                            </button>
                        }
                    })
                    .collect_view()}
            </div>
            <label class="block text-sm space-y-2">
                {move || tt(context, "Inference model ID")}
                <input
                    class="glass-input p-3 w-full"
                    list="flowai-models"
                    prop:value=move || model.get()
                    on:input=move |e| model.set(event_target_value(&e))
                />
            </label>
            <datalist id="flowai-models">
                {[
                    "gemini-4-argon",
                    "gpt-6-astra",
                    "gpt-6.1-sol",
                    "gpt-6.1-terra",
                    "gpt-6-luna",
                    "claude-fable-5-1",
                    "claude-opus-5-5",
                    "claude-sonnet-5-5",
                    "claude-haiku-5-5",
                    "llama3.2:latest",
                    "qwen2.5-coder-7b-instruct",
                ]
                    .into_iter()
                    .map(|id| view! { <option value=id /> })
                    .collect_view()}
            </datalist>
            <div class="grid grid-cols-1 lg:grid-cols-4 gap-5 min-w-0">
                <aside class="space-y-3 min-w-0">
                    <button
                        class="glass-button-primary px-4 py-2 w-full"
                        disabled=move || busy.get()
                        on:click=move |_| {
                            let thread = new_thread(&crate::tabs::l10n::locale(context));
                            active.set(text(&thread, "id"));
                            threads
                                .update(|threads| {
                                    threads.insert(0, thread);
                                    threads.truncate(40);
                                });
                            input.set(String::new());
                            failure.set(None);
                        }
                    >
                        {move || tt(context, "New conversation")}
                    </button>
                    <p class="text-xs text-slate-400">
                        {move || tt(context, "History saved for your account in this browser.")}
                    </p>
                    <nav
                        aria-label=move || tt(context, "Conversation history")
                        class="space-y-2 max-h-96 overflow-auto"
                    >
                        {move || {
                            threads
                                .get()
                                .into_iter()
                                .map(|thread| {
                                    let id = text(&thread, "id");
                                    let delete_id = id.clone();
                                    let selected = id.clone();
                                    view! {
                                        <div class="glass-card p-2 flex gap-2 min-w-0">
                                            <button
                                                class="text-left text-sm min-w-0 flex-1 truncate"
                                                aria-current=move || {
                                                    if active.get() == selected { "true" } else { "false" }
                                                }
                                                on:click=move |_| {
                                                    active.set(id.clone());
                                                    failure.set(None);
                                                }
                                            >
                                                {text(&thread, "title")}
                                            </button>
                                            <button
                                                class="glass-button px-2"
                                                aria-label=move || tt(context, "Delete conversation")
                                                disabled=move || busy.get()
                                                on:click=move |_| {
                                                    threads
                                                        .update(|threads| {
                                                            threads.retain(|t| t["id"] != delete_id);
                                                            if threads.is_empty() {
                                                                threads.push(new_thread(&crate::tabs::l10n::locale(context)));
                                                            }
                                                        });
                                                    if active.get_untracked() == delete_id {
                                                        active.set(threads.with_untracked(|t| text(&t[0], "id")));
                                                    }
                                                }
                                            >
                                                {move || tt(context, "Delete")}
                                            </button>
                                        </div>
                                    }
                                })
                                .collect_view()
                        }}
                    </nav>
                </aside>
                <div class="lg:col-span-3 space-y-4 min-w-0">
                    <div class="flex flex-wrap gap-2">
                        {[
                            "Analyze CPU & Memory Pressure",
                            "Inspect Failing Systemd Units",
                            "Summarize Storage & Quotas",
                            "Audit Recent Security Events",
                        ]
                            .into_iter()
                            .map(|prompt| {
                                view! {
                                    <button
                                        class="glass-button px-3 py-2 text-xs"
                                        disabled=move || busy.get()
                                        on:click=move |_| input.set(tt(context, prompt))
                                    >
                                        {move || tt(context, prompt)}
                                    </button>
                                }
                            })
                            .collect_view()}
                    </div>
                    <div
                        aria-live="polite"
                        role="log"
                        aria-label=move || tt(context, "FlowAI conversation")
                        class="space-y-4 max-h-[60vh] overflow-auto min-w-0"
                    >
                        <Show when=move || messages.with(Vec::is_empty)>
                            <EmptyState
                                title="Start an operations conversation"
                                description="Choose a diagnostic prompt or ask about your infrastructure."
                            />
                        </Show>
                        {move || {
                            messages
                                .get()
                                .into_iter()
                                .map(|message| {
                                    let author = if message["role"] == "user" {
                                        "You"
                                    } else {
                                        "FlowAI"
                                    };
                                    let proposal = message["payload"].clone();
                                    let pending = message["pending_actions"].clone();
                                    let has_actions = proposal.is_object()
                                        || pending.as_array().is_some_and(|v| !v.is_empty())
                                        || pending.as_u64().is_some_and(|n| n > 0);
                                    view! {
                                        <ObsCard>
                                            <p class="text-xs text-indigo-300 mb-3">
                                                {move || tt(context, author)}
                                            </p>
                                            <af_web_ui::MarkdownView
                                                source=text(&message, "text")
                                                class="break-words overflow-x-auto"
                                            />
                                            {has_actions
                                                .then(|| {
                                                    view! {
                                                        <div
                                                            role="status"
                                                            class="mt-4 p-4 rounded-xl border border-amber-400/50 bg-amber-500/10 space-y-3"
                                                        >
                                                            <Badge label="HUMAN APPROVAL REQUIRED" tone="warning" />
                                                            <p class="text-sm">
                                                                {move || tt(
                                                                    context,
                                                                    "Review the current action status, parameters and risk in Approval Inbox before execution.",
                                                                )}
                                                            </p>
                                                            <details>
                                                                <summary class="cursor-pointer text-sm">
                                                                    {move || tt(context, "Inspect proposal")}
                                                                </summary>
                                                                <pre class="text-xs whitespace-pre-wrap break-all">
                                                                    {serde_json::to_string_pretty(
                                                                            &json!({"proposal":proposal,"pending_actions":pending}),
                                                                        )
                                                                        .unwrap_or_default()}
                                                                </pre>
                                                            </details>
                                                            <button
                                                                class="glass-button-primary px-4 py-2"
                                                                on:click=move |_| context.select_tab(TabId::Inbox)
                                                            >
                                                                {move || tt(context, "Review in Approval Inbox")}
                                                            </button>
                                                        </div>
                                                    }
                                                })}
                                        </ObsCard>
                                    }
                                })
                                .collect_view()
                        }}
                        <Show when=move || busy.get()>
                            <p role="status" class="text-indigo-300 animate-pulse">
                                {move || tt(context, "FlowAI is analyzing…")}
                            </p>
                        </Show>
                    </div>
                    {move || {
                        failure
                            .get()
                            .map(|error| {
                                view! {
                                    <p role="alert" class="text-rose-300">
                                        {move || tt(context, &error)}
                                    </p>
                                }
                            })
                    }}
                    <Show when=move || context.is_admin()>
                    <div class="flex flex-wrap gap-4 items-center text-sm">
                        <label class="flex gap-2 items-center">
                            <input
                                type="checkbox"
                                prop:checked=move || attach.get()
                                on:change=move |e| attach.set(context.is_admin() && event_target_checked(&e))
                            />
                            {move || tt(context, "Attach live telemetry and service health")}
                        </label>
                        <label>
                            {move || tt(context, "Context ")}
                            <select
                                class="glass-input px-2 py-1"
                                prop:value=move || context_mode.get()
                                on:change=move |e| context_mode.set(event_target_value(&e))
                            >
                                <option value="full">
                                    {move || tt(context, "Metrics + recent events")}
                                </option>
                                <option value="metrics">
                                    {move || tt(context, "Metrics only")}
                                </option>
                                <option value="logs">
                                    {move || tt(context, "Recent events only")}
                                </option>
                            </select>
                        </label>
                    </div>
                    </Show>
                    <form
                        class="flex gap-3 items-end"
                        on:submit=move |e| {
                            e.prevent_default();
                            send.run(());
                        }
                    >
                        <textarea
                            class="glass-input p-3 min-w-0 flex-1"
                            rows="4"
                            aria-label=move || tt(context, "Message FlowAI")
                            placeholder=move || tt(context, "Ask FlowAI…")
                            prop:value=move || input.get()
                            on:input=move |e| input.set(event_target_value(&e))
                            on:keydown=move |e: web_sys::KeyboardEvent| {
                                if e.key() == "Enter" && !e.shift_key() && !e.is_composing() {
                                    e.prevent_default();
                                    send.run(());
                                }
                            }
                        ></textarea>
                        <button
                            type="submit"
                            class="glass-button-primary px-5 py-3"
                            disabled=move || {
                                busy.get() || input.get().trim().is_empty()
                                    || !valid_model(&model.get())
                            }
                        >
                            {move || tt(context, "Send")}
                        </button>
                    </form>
                    <p class="text-xs text-slate-400">
                        {move || tt(context, "Enter to send · Shift+Enter for a new line")}
                    </p>
                </div>
            </div>
        </section>
    }
}

#[cfg(test)]
mod tests;
