//! Provider connection credentials and server identity checks.
use super::common::*;
use super::types::*;
use crate::state::{app, PeerArea};
use crate::tabs::busy::BusyGuard;
use crate::tabs::l10n::{tt, tt_with, Modal};
use af_web_core::api::ApiClient;
use af_web_core::draft::FormDraft;
use leptos::prelude::*;
use serde_json::json;
use wasm_bindgen_futures::spawn_local;
pub(super) fn supported_streaming_provider(provider: &str) -> Option<&'static str> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "jellyfin" => Some("jellyfin"),
        "emby" => Some("emby"),
        "plex" => Some("plex"),
        _ => None,
    }
}

pub(super) fn streaming_server_save_path(
    provider: &str,
    test: bool,
) -> Result<(String, &'static str), String> {
    let canonical = supported_streaming_provider(provider).ok_or_else(|| {
        "Unsupported streaming provider; expected jellyfin, emby, or plex.".to_string()
    })?;
    let path = if test {
        "/api/v1/admin/streaming/servers/test".to_string()
    } else {
        format!("/api/v1/admin/streaming/servers/{canonical}")
    };
    Ok((path, canonical))
}

#[component]
pub(super) fn StreamingServerSettings(
    open: RwSignal<bool>,
    server: RwSignal<ProviderStatus>,
    on_changed: Callback<()>,
) -> impl IntoView {
    let context = app();
    let draft = RwSignal::new(FormDraft::new(json!({})));
    let busy = RwSignal::new(false);
    let generation = RwSignal::new(0u64);
    let result = RwSignal::new(None::<String>);
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        let editable = context.is_admin() && context.can_write_area(PeerArea::Settings);
        let is_open = open.get();
        let server = server.get();
        generation.update(|ticket| *ticket = ticket.wrapping_add(1));
        busy.set(false);
        result.set(None);
        if is_open && !editable {
            open.set(false);
        }
        draft.set(FormDraft::new(if is_open && editable {
            json!({"name":server.name,"url":server.url,"apiKey":"","enabled":server.enabled.unwrap_or(true)})
        } else {
            json!({})
        }));
    });
    let save = Callback::new(move |test: bool| {
        if busy.get_untracked()
            || !open.get_untracked()
            || !context.is_admin_untracked()
            || !context.can_write_area_untracked(PeerArea::Settings)
        {
            return;
        }
        let provider = server.with_untracked(|s| s.provider.clone());
        let Ok(mut body) = draft.with_untracked(FormDraft::value) else {
            return;
        };
        if body["url"].as_str().is_none_or(|s| s.trim().is_empty()) {
            result.set(Some("A server URL is required.".into()));
            return;
        }
        let (path, canonical_provider) = match streaming_server_save_path(&provider, test) {
            Ok(target) => target,
            Err(message) => {
                result.set(Some(message));
                return;
            }
        };
        if test {
            body["provider"] = json!(canonical_provider);
        }
        let session_epoch = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let grant_epoch = context.area_revocation_epoch_untracked(PeerArea::Settings);
        generation.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = generation.get_untracked();
        busy.set(true);
        let guard = BusyGuard::for_generation(busy, generation, ticket);
        spawn_local(async move {
            let _guard = guard;
            let is_current = || {
                generation.try_get_untracked() == Some(ticket)
                    && open.try_get_untracked() == Some(true)
                    && context.session_epoch.try_get_untracked() == Some(session_epoch)
                    && context.server_epoch.try_get_untracked() == Some(server_epoch)
                    && context.area_revocation_epoch_untracked(PeerArea::Settings) == grant_epoch
                    && context.is_admin_untracked()
                    && context.can_write_area_untracked(PeerArea::Settings)
            };
            if !is_current() {
                return;
            }
            let response = ApiClient
                .request(&path, if test { "POST" } else { "PUT" }, Some(&body))
                .await;
            if !is_current() {
                return;
            }
            match response {
                Ok(data) => {
                    let failed = data["ok"] == false
                        || matches!(
                            data["server"]["status"].as_str(),
                            Some("unreachable" | "unavailable")
                        );
                    let message = data["message"]
                        .as_str()
                        .unwrap_or(if test {
                            "Server identity check completed."
                        } else {
                            "Server configuration saved."
                        })
                        .to_string();
                    if !test || !failed {
                        on_changed.run(());
                    }
                    if server.with_untracked(|s| s.provider.clone()) == provider {
                        result.set(Some(message.clone()));
                        if !test && !failed {
                            open.set(false);
                        }
                    }
                    context.toast(tt(context, &message), failed);
                }
                Err(e) => result.set(Some(e.message)),
            }
        });
    });
    view! {
        <Modal open title="Streaming server connection & identity">
            <div class="space-y-4">
                <p class="text-sm text-slate-400">
                    {move || {
                        tt_with(context, "Provider {provider} · server identity {id} · {status}", &[("provider", &(server.with(|s| s.provider.clone())).to_string()), ("id", &(server.with(|s| display(context, &s.server_id))).to_string()), ("status", &(server.with(|s| tt(context, s.status_key()))).to_string())])
                    }}
                </p>
                {["name", "url", "apiKey"]
                    .into_iter()
                    .map(|field| {
                        view! {
                            <label class="block text-sm space-y-1">
                                {move || tt(context, field)}
                                <input
                                    class="af-input p-2 w-full"
                                    disabled=move || busy.get()
                                    type=if field == "apiKey" { "password" } else { "text" }
                                    autocomplete="off"
                                    prop:value=move || {
                                        draft
                                            .with(|d| {
                                                d.value().map(|v| text(&v, field)).unwrap_or_default()
                                            })
                                    }
                                    on:input=move |e| {
                                        draft
                                            .update(|d| {
                                                let _ = d.edit(field, json!(event_target_value(&e)));
                                            })
                                    }
                                />
                            </label>
                        }
                    })
                    .collect_view()}
                <p class="text-xs text-slate-400">
                    {move || tt(
                        context,
                        "Leave the API key blank to preserve the stored credential. Identity is obtained from the upstream server, never guessed from its name.",
                    )}
                </p>
                <label class="text-sm flex gap-2">
                    <input
                        type="checkbox"
                        disabled=move || busy.get()
                        prop:checked=move || {
                            draft.with(|d| d.value().is_ok_and(|v| v["enabled"] == true))
                        }
                        on:change=move |e| {
                            draft
                                .update(|d| {
                                    let _ = d.edit("enabled", json!(event_target_checked(&e)));
                                })
                        }
                    />
                    {move || tt(context, "Enable live tracking")}
                </label>
                <div class="flex gap-3">
                    <button
                        class="af-btn px-4 py-2"
                        disabled=move || {
                            busy.get() || !context.can_write_area(crate::state::PeerArea::Settings)
                        }
                        title=move || {
                            context
                                .area_block_reason(crate::state::PeerArea::Settings, true)
                                .unwrap_or_default()
                        }
                        on:click=move |_| save.run(true)
                    >
                        {move || tt(context, "Test and verify identity")}
                    </button>
                    <button
                        class="af-btn-primary px-4 py-2"
                        disabled=move || {
                            busy.get() || !context.can_write_area(crate::state::PeerArea::Settings)
                        }
                        title=move || {
                            context
                                .area_block_reason(crate::state::PeerArea::Settings, true)
                                .unwrap_or_default()
                        }
                        on:click=move |_| save.run(false)
                    >
                        {move || tt(context, "Save connection")}
                    </button>
                </div>
                {move || {
                    result
                        .get()
                        .map(|message| {
                            view! {
                                <p role="status" class="text-sm">
                                    {move || tt(context, &message)}
                                </p>
                            }
                        })
                }}
            </div>
        </Modal>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_save_and_test_accept_jellyfin_emby_and_plex() {
        for provider in ["jellyfin", "emby", "plex", " Plex "] {
            let canonical = supported_streaming_provider(provider).expect("supported provider");
            assert_eq!(
                streaming_server_save_path(provider, false).unwrap(),
                (
                    format!("/api/v1/admin/streaming/servers/{canonical}"),
                    canonical
                )
            );
            assert_eq!(
                streaming_server_save_path(provider, true).unwrap(),
                (
                    "/api/v1/admin/streaming/servers/test".to_string(),
                    canonical
                )
            );
        }

        for invalid in ["", "demo", "../evil"] {
            assert!(supported_streaming_provider(invalid).is_none());
            assert!(streaming_server_save_path(invalid, false).is_err());
            assert!(streaming_server_save_path(invalid, true).is_err());
        }
    }
}
