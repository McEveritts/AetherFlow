//! Pairing workflows: opening/closing pairing windows, pasting pairing strings with endpoint
//! selection, comparison-code verification, and approve/cancel controls.

use super::peers::{
    endpoint_display, DetectedEndpointView, PairingAttemptView, PairingWindowSummary, PeersSnapshot,
};
use super::{
    copy_text_to_clipboard, format_countdown, pairing_cancel_path, pairing_confirm_path,
    pairing_window_close_path, peer_api_request, CompletionScope, DialogGate, MutationToken,
    PeerApiError, PeerErrorAlert, PAIRING_WINDOW_PATH, PAIR_START_PATH,
};
use crate::state::app;
use crate::tabs::busy::BusyGuard;
use crate::tabs::l10n::{tt, tt_with, Badge, Modal, ObsCard};
use af_web_core::i18n::translate_with;
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wasm_bindgen_futures::spawn_local;

pub const ENDPOINT_AUTO: &str = "__auto__";
pub const ENDPOINT_CUSTOM: &str = "__custom__";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct OpenPairingWindowRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub https_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg_port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenPairingWindowResponse {
    pub window_id: String,
    pub expires_at: i64,
    pub ttl_seconds: i64,
    pub pairing_string: String,
    pub https_url: String,
    pub endpoint: String,
    pub wg_port: u16,
    pub tunnel_ip: String,
    pub wg_pubkey: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosePairingWindowResponse {
    pub closed: bool,
    pub window_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseAllPairingWindowsResponse {
    pub closed: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StartPairingRequest {
    pub pairing_string: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartPairingResponse {
    pub link_id: String,
    pub attempt_id: String,
    pub name: String,
    pub remote_server_name: String,
    pub comparison_code: String,
    pub expires_at: i64,
    pub state: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ConfirmPairingRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfirmPairingResponse {
    pub link_id: String,
    pub name: String,
    pub state: String,
    pub attempt_id: String,
    pub confirmed: bool,
    #[serde(default)]
    pub rtt_ms: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelPairingResponse {
    pub cancelled: bool,
    pub attempt_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileWindow {
    Keep,
    ConsumedByAttempt,
    Clear,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconcileInitiated {
    Keep,
    Activated { peer_name: String },
    Clear,
}

/// Actionable draft state for the "Pair with a server" form. Retains all operator input when a
/// pairing request returns a typed error, and clears the consumed single-use string on success.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StartPairingDraft {
    pub pairing_string: String,
    pub peer_name: String,
    pub endpoint_selection: String,
    pub custom_endpoint: String,
}

impl StartPairingDraft {
    pub fn apply_submit_result(&mut self, succeeded: bool) {
        if succeeded {
            self.pairing_string.clear();
            self.peer_name.clear();
        }
    }
}

pub fn default_endpoint_selection(detected: &[DetectedEndpointView], allow_auto: bool) -> String {
    if let Some(first) = detected.first() {
        first.address.clone()
    } else if allow_auto {
        ENDPOINT_AUTO.to_string()
    } else {
        ENDPOINT_CUSTOM.to_string()
    }
}

pub fn resolve_endpoint_selection(
    selection: &str,
    custom_endpoint: &str,
) -> Result<Option<String>, &'static str> {
    let sel = selection.trim();
    if sel.is_empty() || sel == ENDPOINT_AUTO {
        return Ok(None);
    }
    if sel == ENDPOINT_CUSTOM {
        let custom = custom_endpoint.trim();
        if custom.is_empty()
            || custom
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace())
        {
            return Err("Cluster.validationEndpointRequired");
        }
        return Ok(Some(custom.to_string()));
    }
    Ok(Some(sel.to_string()))
}

pub fn format_endpoint_option(locale: &str, endpoint: &DetectedEndpointView) -> String {
    let key = if endpoint.recommended {
        "Cluster.endpointOptionRecommended"
    } else {
        "Cluster.endpointOptionStandard"
    };
    translate_with(
        locale,
        key,
        &[
            ("address", &endpoint.address),
            ("iface", &endpoint.interface),
            ("family", &endpoint.family),
        ],
    )
}

pub fn build_open_window_request(
    selection: &str,
    custom_endpoint: &str,
    https_url: &str,
    wg_port: &str,
) -> Result<OpenPairingWindowRequest, &'static str> {
    let endpoint = resolve_endpoint_selection(selection, custom_endpoint)?;
    let trimmed_url = https_url.trim();
    let https_url = if trimmed_url.is_empty() {
        None
    } else if trimmed_url.starts_with("https://") {
        Some(trimmed_url.to_string())
    } else {
        return Err("Cluster.validationHttpsUrlInvalid");
    };
    let trimmed_port = wg_port.trim();
    let wg_port = if trimmed_port.is_empty() {
        None
    } else {
        let port = trimmed_port
            .parse::<u16>()
            .ok()
            .filter(|&port| port > 0)
            .ok_or("Cluster.validationPortInvalid")?;
        Some(port)
    };
    Ok(OpenPairingWindowRequest {
        endpoint,
        https_url,
        wg_port,
    })
}

pub fn build_start_pairing_request(
    draft: &StartPairingDraft,
) -> Result<StartPairingRequest, &'static str> {
    let pairing_string = draft.pairing_string.trim();
    if pairing_string.is_empty() {
        return Err("Cluster.validationPairingStringRequired");
    }
    let endpoint = resolve_endpoint_selection(&draft.endpoint_selection, &draft.custom_endpoint)?;
    let name = {
        let trimmed = draft.peer_name.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    };
    Ok(StartPairingRequest {
        pairing_string: pairing_string.to_string(),
        name,
        endpoint,
        local_name: None,
    })
}

pub fn build_confirm_pairing_request(name_input: &str) -> ConfirmPairingRequest {
    let trimmed = name_input.trim();
    ConfirmPairingRequest {
        name: (!trimmed.is_empty()).then(|| trimmed.to_string()),
    }
}

/// Keeps the in-memory single-use pairing string only while the server still reports the same
/// open window and it has not expired. Distinguishes consumption by a pending incoming attempt so
/// the UI can dismiss the pairing-string dialog and reveal the comparison-code approval card.
pub fn reconcile_opened_window(
    window: &OpenPairingWindowResponse,
    snapshot: &PeersSnapshot,
    now_secs: i64,
) -> ReconcileWindow {
    let consumed_by_attempt = snapshot
        .pairing_attempts
        .iter()
        .any(|attempt| attempt.window_id.as_deref() == Some(window.window_id.as_str()));
    if consumed_by_attempt {
        return ReconcileWindow::ConsumedByAttempt;
    }
    if window.expires_at <= now_secs {
        return ReconcileWindow::Clear;
    }
    let still_open = snapshot
        .pairing_windows
        .iter()
        .any(|open| open.id == window.window_id && open.expires_at > now_secs);
    if still_open {
        ReconcileWindow::Keep
    } else {
        ReconcileWindow::Clear
    }
}

/// Reconciles an A-side pending comparison-code card against a refreshed peer snapshot.
pub fn reconcile_initiated_pairing(
    initiated: &StartPairingResponse,
    snapshot: &PeersSnapshot,
) -> ReconcileInitiated {
    if let Some(peer) = snapshot
        .peers
        .iter()
        .find(|peer| peer.id == initiated.link_id)
    {
        return match peer.state.as_str() {
            "active" => ReconcileInitiated::Activated {
                peer_name: peer.name.clone(),
            },
            "pending"
                if peer.pending_attempt_id.as_deref() == Some(initiated.attempt_id.as_str())
                    && peer.pending_expires_at.is_some() =>
            {
                ReconcileInitiated::Keep
            }
            _ => ReconcileInitiated::Clear,
        };
    }
    ReconcileInitiated::Clear
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum WindowModalSession {
    Closed(u64),
    Form(u64),
    Generated { epoch: u64, window_id: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowFocusTarget {
    Form,
    PairingString,
}

fn window_modal_focus_transition(
    prev: &WindowModalSession,
    next: &WindowModalSession,
) -> Option<WindowFocusTarget> {
    match (prev, next) {
        (WindowModalSession::Form(prev_epoch), WindowModalSession::Generated { epoch, .. })
        | (
            WindowModalSession::Generated {
                epoch: prev_epoch, ..
            },
            WindowModalSession::Generated { epoch, .. },
        ) if prev_epoch == epoch => Some(WindowFocusTarget::PairingString),
        (
            WindowModalSession::Generated {
                epoch: prev_epoch, ..
            },
            WindowModalSession::Form(epoch),
        ) if prev_epoch == epoch => Some(WindowFocusTarget::Form),
        _ => None,
    }
}

#[cfg(target_arch = "wasm32")]
fn try_focus_window_control(body: &web_sys::Element, target: WindowFocusTarget) -> bool {
    use wasm_bindgen::JsCast;

    if !body.is_connected() || body.closest("dialog[open]").ok().flatten().is_none() {
        return false;
    }
    let element = match target {
        WindowFocusTarget::PairingString => {
            // Confirm the generated-window branch is mounted before focusing inside it.
            let Ok(Some(textarea)) = body.query_selector("#cluster-generated-pairing-string")
            else {
                return false;
            };
            body.query_selector(r#"button[data-af-autofocus="true"]:not([disabled])"#)
                .ok()
                .flatten()
                .unwrap_or(textarea)
        }
        WindowFocusTarget::Form => {
            let Ok(Some(select)) = body.query_selector("#cluster-window-endpoint:not([disabled])")
            else {
                return false;
            };
            select
        }
    };
    let Ok(html_el) = element.dyn_into::<web_sys::HtmlElement>() else {
        return false;
    };
    if !html_el.is_connected() || html_el.matches(":disabled").unwrap_or(true) {
        return false;
    }
    let _ = html_el.focus();
    web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.active_element())
        .as_ref()
        == Some(html_el.unchecked_ref())
}

#[derive(Clone, Copy)]
struct WindowModalFocus {
    body_ref: NodeRef<leptos::html::Div>,
    timer: StoredValue<Option<gloo_timers::callback::Timeout>, LocalStorage>,
    open: RwSignal<bool>,
    opened_window: RwSignal<Option<OpenPairingWindowResponse>>,
    gate: DialogGate,
    session_epoch: RwSignal<u64>,
}

impl WindowModalFocus {
    fn clear(self) {
        self.timer.set_value(None);
    }

    #[cfg(target_arch = "wasm32")]
    fn schedule(self, token: MutationToken, target: WindowFocusTarget) {
        let matches_view = move || {
            self.opened_window
                .try_with_untracked(|w| match target {
                    WindowFocusTarget::Form => w.is_none(),
                    WindowFocusTarget::PairingString => w.is_some(),
                })
                .unwrap_or(false)
        };
        if self
            .gate
            .classify(self.session_epoch, self.open, token, matches_view)
            != CompletionScope::CurrentDialog
        {
            return;
        }
        if let Some(body) = self.body_ref.get_untracked() {
            if try_focus_window_control(&body, target) {
                return;
            }
        }
        let timer = gloo_timers::callback::Timeout::new(0, move || {
            if self
                .gate
                .classify(self.session_epoch, self.open, token, matches_view)
                != CompletionScope::CurrentDialog
            {
                return;
            }
            if let Some(body) = self.body_ref.get_untracked() {
                let _ = try_focus_window_control(&body, target);
            }
        });
        self.timer.set_value(Some(timer));
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn schedule(self, token: MutationToken, target: WindowFocusTarget) {
        let _ = (
            self.body_ref,
            self.timer,
            self.open,
            self.opened_window,
            self.gate,
            self.session_epoch,
            token,
            target,
        );
    }
}

#[component]
pub fn OpenPairingWindowModal(
    open: RwSignal<bool>,
    detected_endpoints: Signal<Vec<DetectedEndpointView>>,
    opened_window: RwSignal<Option<OpenPairingWindowResponse>>,
    now_secs: RwSignal<i64>,
    on_refresh: Callback<()>,
) -> impl IntoView {
    let context = app();
    let endpoint_selection = RwSignal::new(ENDPOINT_AUTO.to_string());
    let custom_endpoint = RwSignal::new(String::new());
    let https_url = RwSignal::new(String::new());
    let wg_port = RwSignal::new(String::new());
    let error = RwSignal::new(None::<PeerApiError>);
    let gate = DialogGate::new();
    let body_ref = NodeRef::<leptos::html::Div>::new();
    let focus = WindowModalFocus {
        body_ref,
        timer: StoredValue::new_local(None::<gloo_timers::callback::Timeout>),
        open,
        opened_window,
        gate,
        session_epoch: context.session_epoch,
    };
    let last_session = StoredValue::new(WindowModalSession::Closed(
        context.session_epoch.get_untracked(),
    ));

    on_cleanup(move || {
        focus.clear();
    });

    // Track open/close, active window view, and session transitions independently from
    // background detected-endpoint polls so polls never cancel an in-flight modal mutation.
    Effect::new(move |_| {
        let is_open = open.get();
        let epoch = context.session_epoch.get();
        let active_window_id = if is_open {
            opened_window.with(|w| w.as_ref().map(|win| win.window_id.clone()))
        } else {
            None
        };
        let next_session = if !is_open {
            WindowModalSession::Closed(epoch)
        } else if let Some(window_id) = active_window_id {
            WindowModalSession::Generated { epoch, window_id }
        } else {
            WindowModalSession::Form(epoch)
        };
        let prev_session = last_session.get_value();
        if prev_session == next_session {
            return;
        }
        last_session.set_value(next_session.clone());
        focus.clear();
        let next_gen = gate.reset();
        error.set(None);

        if matches!(next_session, WindowModalSession::Closed(_)) {
            // Clear sensitive single-use pairing string when the modal is dismissed.
            if opened_window.with_untracked(Option::is_some) {
                opened_window.set(None);
            }
        } else if let Some(target) = window_modal_focus_transition(&prev_session, &next_session) {
            focus.schedule(
                MutationToken {
                    session_epoch: epoch,
                    generation: next_gen,
                },
                target,
            );
        }
    });

    Effect::new(move |_| {
        if open.get() {
            let detected = detected_endpoints.get();
            let current_sel = endpoint_selection.get_untracked();
            let selection_valid = current_sel == ENDPOINT_AUTO
                || current_sel == ENDPOINT_CUSTOM
                || detected.iter().any(|ep| ep.address == current_sel);
            if !selection_valid || (current_sel == ENDPOINT_AUTO && !detected.is_empty()) {
                endpoint_selection.set(default_endpoint_selection(&detected, true));
            }
        }
    });

    let open_window = move || {
        if gate.is_busy_untracked() || !context.is_admin() {
            return;
        }
        let req = match build_open_window_request(
            &endpoint_selection.get_untracked(),
            &custom_endpoint.get_untracked(),
            &https_url.get_untracked(),
            &wg_port.get_untracked(),
        ) {
            Ok(req) => req,
            Err(key) => {
                error.set(Some(PeerApiError::client(tt(context, key))));
                return;
            }
        };
        let body = match serde_json::to_value(&req) {
            Ok(val) => val,
            Err(err) => {
                error.set(Some(PeerApiError::client(err.to_string())));
                return;
            }
        };
        error.set(None);
        let (token, mut busy_guard) = gate.begin(context.session_epoch);
        spawn_local(async move {
            let result = peer_api_request::<OpenPairingWindowResponse>(
                PAIRING_WINDOW_PATH,
                "POST",
                Some(&body),
            )
            .await;
            match gate.classify(context.session_epoch, open, token, || {
                opened_window
                    .try_with_untracked(Option::is_none)
                    .unwrap_or(false)
            }) {
                CompletionScope::ExpiredSession => return,
                CompletionScope::StaleDialog => {
                    if result.is_ok() {
                        on_refresh.run(());
                    }
                    return;
                }
                CompletionScope::CurrentDialog => {}
            }
            busy_guard.release();
            match result {
                Ok(resp) => {
                    opened_window.set(Some(resp));
                    on_refresh.run(());
                }
                Err(api_err) => {
                    // Retain entered endpoint, HTTPS URL, and port on failure.
                    error.set(Some(api_err));
                }
            }
        });
    };

    let close_current_window = move || {
        if gate.is_busy_untracked() || !context.is_admin() {
            return;
        }
        let Some(window) = opened_window.get_untracked() else {
            return;
        };
        let window_id = window.window_id.clone();
        let path = pairing_window_close_path(&window_id);
        error.set(None);
        let (token, mut busy_guard) = gate.begin(context.session_epoch);
        spawn_local(async move {
            let result =
                peer_api_request::<ClosePairingWindowResponse>(&path, "DELETE", None).await;
            match gate.classify(context.session_epoch, open, token, || {
                opened_window
                    .try_with_untracked(|cur| {
                        cur.as_ref().is_some_and(|open| open.window_id == window_id)
                    })
                    .unwrap_or(false)
            }) {
                CompletionScope::ExpiredSession => return,
                CompletionScope::StaleDialog => {
                    if result.is_ok() {
                        on_refresh.run(());
                    }
                    return;
                }
                CompletionScope::CurrentDialog => {}
            }
            busy_guard.release();
            match result {
                Ok(_) => {
                    opened_window.set(None);
                    on_refresh.run(());
                    context.toast("Cluster.windowClosedToast", false);
                }
                Err(api_err) => error.set(Some(api_err)),
            }
        });
    };

    view! {
        <Modal
            open=open
            title=Signal::derive(move || tt(context, "Cluster.openWindowTitle"))
        >
            <div node_ref=body_ref class="space-y-4">
                <p class="text-sm text-slate-300">
                    {move || tt(context, "Cluster.openWindowIntro")}
                </p>

                <PeerErrorAlert error=error />

                <Show
                    when=move || opened_window.with(Option::is_some)
                    fallback=move || {
                        view! {
                            <form
                                class="space-y-4"
                                on:submit=move |event| {
                                    event.prevent_default();
                                    open_window();
                                }
                            >
                                <div class="space-y-1.5">
                                    <label
                                        for="cluster-window-endpoint"
                                        class="block text-sm font-medium text-slate-200"
                                    >
                                        {move || tt(context, "Cluster.endpointPickerLabel")}
                                    </label>
                                    <select
                                        id="cluster-window-endpoint"
                                        data-af-autofocus="true"
                                        aria-describedby="cluster-window-endpoint-hint"
                                        class="glass-input px-3 py-2 w-full"
                                        disabled=move || gate.is_busy()
                                        prop:value=move || endpoint_selection.get()
                                        on:change=move |event| {
                                            endpoint_selection.set(event_target_value(&event));
                                        }
                                    >
                                        {move || {
                                            let locale = crate::tabs::l10n::locale(context);
                                            detected_endpoints
                                                .get()
                                                .into_iter()
                                                .map(|ep| {
                                                    let label = format_endpoint_option(&locale, &ep);
                                                    view! { <option value=ep.address>{label}</option> }
                                                })
                                                .collect_view()
                                        }}
                                        <option value=ENDPOINT_AUTO>
                                            {move || tt(context, "Cluster.endpointAutoOption")}
                                        </option>
                                        <option value=ENDPOINT_CUSTOM>
                                            {move || tt(context, "Cluster.endpointCustomOption")}
                                        </option>
                                    </select>
                                    <p id="cluster-window-endpoint-hint" class="text-xs text-slate-400">
                                        {move || tt(context, "Cluster.endpointPickerHint")}
                                    </p>
                                </div>

                                <Show when=move || { endpoint_selection.get() == ENDPOINT_CUSTOM }>
                                    <div class="space-y-1.5">
                                        <label
                                            for="cluster-window-custom-endpoint"
                                            class="block text-sm font-medium text-slate-200"
                                        >
                                            {move || tt(context, "Cluster.customEndpointLabel")}
                                        </label>
                                        <input
                                            id="cluster-window-custom-endpoint"
                                            type="text"
                                            autocomplete="off"
                                            class="glass-input px-3 py-2 w-full"
                                            placeholder=move || tt(context, "Cluster.endpointHostPlaceholder")
                                            disabled=move || gate.is_busy()
                                            prop:value=move || custom_endpoint.get()
                                            on:input=move |event| {
                                                custom_endpoint.set(event_target_value(&event));
                                            }
                                        />
                                    </div>
                                </Show>

                                <div class="grid sm:grid-cols-2 gap-4">
                                    <div class="space-y-1.5">
                                        <label
                                            for="cluster-window-https-url"
                                            class="block text-sm font-medium text-slate-200"
                                        >
                                            {move || tt(context, "Cluster.httpsUrlOptionalLabel")}
                                        </label>
                                        <input
                                            id="cluster-window-https-url"
                                            type="url"
                                            autocomplete="off"
                                            aria-describedby="cluster-window-https-url-hint"
                                            class="glass-input px-3 py-2 w-full"
                                            placeholder="https://peer.example.com"
                                            disabled=move || gate.is_busy()
                                            prop:value=move || https_url.get()
                                            on:input=move |event| https_url.set(event_target_value(&event))
                                        />
                                        <p id="cluster-window-https-url-hint" class="text-xs text-slate-400">
                                            {move || tt(context, "Cluster.httpsUrlOptionalHint")}
                                        </p>
                                    </div>
                                    <div class="space-y-1.5">
                                        <label
                                            for="cluster-window-wg-port"
                                            class="block text-sm font-medium text-slate-200"
                                        >
                                            {move || tt(context, "Cluster.wgPortLabel")}
                                        </label>
                                        <input
                                            id="cluster-window-wg-port"
                                            type="number"
                                            min="1"
                                            max="65535"
                                            inputmode="numeric"
                                            aria-describedby="cluster-window-wg-port-hint"
                                            class="glass-input px-3 py-2 w-full"
                                            placeholder="51821"
                                            disabled=move || gate.is_busy()
                                            prop:value=move || wg_port.get()
                                            on:input=move |event| wg_port.set(event_target_value(&event))
                                        />
                                        <p id="cluster-window-wg-port-hint" class="text-xs text-slate-400">
                                            {move || tt(context, "Cluster.wgPortHint")}
                                        </p>
                                    </div>
                                </div>

                                <div class="flex flex-wrap justify-end gap-3 pt-2">
                                    <button
                                        type="button"
                                        class="glass-button px-4 py-2"
                                        disabled=move || gate.is_busy()
                                        on:click=move |_| open.set(false)
                                    >
                                        {move || tt(context, "Common.cancel")}
                                    </button>
                                    <button
                                        type="submit"
                                        class="glass-button-primary px-4 py-2"
                                        disabled=move || gate.is_busy()
                                    >
                                        {move || {
                                            if gate.is_busy() {
                                                tt(context, "Cluster.openingWindow")
                                            } else {
                                                tt(context, "Cluster.openWindowSubmit")
                                            }
                                        }}
                                    </button>
                                </div>
                            </form>
                        }
                    }
                >
                    {move || {
                        opened_window.get().map(|window| {
                            let expires_at = window.expires_at;
                            let copy_value = window.pairing_string.clone();
                            let endpoint_meta = format!(
                                "{} · {}",
                                endpoint_display(&window.endpoint, window.wg_port),
                                window.tunnel_ip
                            );
                            view! {
                                <div class="space-y-4">
                                    <p class="text-sm text-amber-300">
                                        {move || tt(context, "Cluster.pairingStringPrivateWarning")}
                                    </p>

                                    <div class="flex flex-wrap items-center justify-between gap-2 text-xs">
                                        <span class="font-mono text-slate-300 break-all">
                                            {endpoint_meta}
                                        </span>
                                        <span
                                            aria-live="off"
                                            class=move || {
                                                if now_secs.get() >= expires_at {
                                                    "af-badge af-badge-danger font-mono"
                                                } else {
                                                    "af-badge af-badge-warning font-mono"
                                                }
                                            }
                                        >
                                            {move || {
                                                let locale = crate::tabs::l10n::locale(context);
                                                format_countdown(&locale, expires_at, now_secs.get()).0
                                            }}
                                        </span>
                                    </div>

                                    <div class="space-y-1.5">
                                        <label
                                            for="cluster-generated-pairing-string"
                                            class="block text-xs font-medium text-slate-400"
                                        >
                                            {move || tt(context, "Cluster.pairingStringLabel")}
                                        </label>
                                        <textarea
                                            id="cluster-generated-pairing-string"
                                            readonly
                                            rows="4"
                                            class="glass-input px-3 py-2 w-full font-mono text-xs break-all"
                                            prop:value=window.pairing_string.clone()
                                        ></textarea>
                                    </div>

                                    <div class="flex flex-wrap justify-between items-center gap-3 pt-1">
                                        <button
                                            type="button"
                                            class="glass-button px-4 py-2"
                                            data-tone="danger"
                                            disabled=move || gate.is_busy()
                                            on:click=move |_| close_current_window()
                                        >
                                            {move || tt(context, "Cluster.closeWindowAction")}
                                        </button>
                                        <button
                                            type="button"
                                            data-af-autofocus="true"
                                            class="glass-button-primary px-4 py-2"
                                            disabled=move || { now_secs.get() >= expires_at }
                                            on:click=move |_| {
                                                copy_text_to_clipboard(context, copy_value.clone());
                                            }
                                        >
                                            {move || tt(context, "Cluster.copyPairingString")}
                                        </button>
                                    </div>
                                </div>
                            }
                        })
                    }}
                </Show>
            </div>
        </Modal>
    }
}

#[component]
pub fn ActivePairingWindowsCard(
    windows: Signal<Vec<PairingWindowSummary>>,
    now_secs: RwSignal<i64>,
    opened_window: RwSignal<Option<OpenPairingWindowResponse>>,
    on_refresh: Callback<()>,
) -> impl IntoView {
    let context = app();
    let busy = RwSignal::new(false);
    let error = RwSignal::new(None::<PeerApiError>);

    let close_one = move |window_id: String| {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        let epoch = context.session_epoch.get_untracked();
        let path = pairing_window_close_path(&window_id);
        error.set(None);
        busy.set(true);
        let mut busy_guard = BusyGuard::new(busy);
        spawn_local(async move {
            let result =
                peer_api_request::<ClosePairingWindowResponse>(&path, "DELETE", None).await;
            if busy.try_get_untracked().is_none()
                || context.session_epoch.try_get_untracked() != Some(epoch)
            {
                return;
            }
            match result {
                Ok(_) => {
                    if opened_window.with_untracked(|w| {
                        w.as_ref().is_some_and(|open| open.window_id == window_id)
                    }) {
                        opened_window.set(None);
                    }
                    on_refresh.run(());
                    context.toast("Cluster.windowClosedToast", false);
                }
                Err(api_err) => error.set(Some(api_err)),
            }
            busy_guard.release();
        });
    };

    let close_all = move || {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        let epoch = context.session_epoch.get_untracked();
        error.set(None);
        busy.set(true);
        let mut busy_guard = BusyGuard::new(busy);
        spawn_local(async move {
            let result = peer_api_request::<CloseAllPairingWindowsResponse>(
                PAIRING_WINDOW_PATH,
                "DELETE",
                None,
            )
            .await;
            if busy.try_get_untracked().is_none()
                || context.session_epoch.try_get_untracked() != Some(epoch)
            {
                return;
            }
            match result {
                Ok(resp) => {
                    opened_window.set(None);
                    on_refresh.run(());
                    context.toast_with(
                        "Cluster.allWindowsClosedToast",
                        &[("count", &resp.closed.to_string())],
                        false,
                    );
                }
                Err(api_err) => error.set(Some(api_err)),
            }
            busy_guard.release();
        });
    };

    view! {
        <Show when=move || !windows.with(Vec::is_empty)>
            <ObsCard>
                <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
                    <div>
                        <h3 class="text-base font-semibold">
                            {move || tt(context, "Cluster.activeWindowsHeading")}
                        </h3>
                        <p class="text-xs text-slate-400 mt-0.5">
                            {move || tt(context, "Cluster.activeWindowsHint")}
                        </p>
                    </div>
                    <Show when=move || { windows.with(Vec::len) > 1 }>
                        <button
                            type="button"
                            class="glass-button px-3 py-1.5 text-sm"
                            data-tone="danger"
                            disabled=move || busy.get()
                            on:click=move |_| close_all()
                        >
                            {move || tt(context, "Cluster.closeAllWindowsAction")}
                        </button>
                    </Show>
                </div>

                <PeerErrorAlert
                    error=error
                    on_dismiss=Callback::new(move |()| error.set(None))
                />

                <div role="list" class="space-y-2 mt-3">
                    <For
                        each=move || windows.get()
                        key=|win| win.id.clone()
                        let:win
                    >
                        {
                            let expires_at = win.expires_at;
                            let short_id: String = win.id.chars().take(8).collect();
                            let win_id = win.id.clone();
                            view! {
                                <div
                                    role="listitem"
                                    class="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/10 p-3 text-sm"
                                >
                                    <div class="flex flex-wrap items-center gap-3 min-w-0">
                                        <span class="font-mono text-slate-200">
                                            {move || tt_with(
                                                context,
                                                "Cluster.windowRowLabel",
                                                &[("id", &short_id)],
                                            )}
                                        </span>
                                        <span
                                            aria-live="off"
                                            class=move || {
                                                if now_secs.get() >= expires_at {
                                                    "af-badge af-badge-danger font-mono"
                                                } else {
                                                    "af-badge af-badge-warning font-mono"
                                                }
                                            }
                                        >
                                            {move || {
                                                let locale = crate::tabs::l10n::locale(context);
                                                format_countdown(&locale, expires_at, now_secs.get()).0
                                            }}
                                        </span>
                                    </div>
                                    <button
                                        type="button"
                                        class="glass-button px-3 py-1.5 text-xs"
                                        data-tone="danger"
                                        disabled=move || busy.get()
                                        on:click=move |_| close_one(win_id.clone())
                                    >
                                        {move || tt(context, "Cluster.closeWindowAction")}
                                    </button>
                                </div>
                            }
                        }
                    </For>
                </div>
            </ObsCard>
        </Show>
    }
}

#[component]
pub fn StartPairingModal(
    open: RwSignal<bool>,
    detected_endpoints: Signal<Vec<DetectedEndpointView>>,
    initiated_pairing: RwSignal<Option<StartPairingResponse>>,
    on_refresh: Callback<()>,
) -> impl IntoView {
    let context = app();
    let draft = RwSignal::new(StartPairingDraft::default());
    let error = RwSignal::new(None::<PeerApiError>);
    let gate = DialogGate::new();
    let last_session = StoredValue::new((false, context.session_epoch.get_untracked()));

    // Track open/close and session transitions separately from background endpoint refreshes.
    Effect::new(move |_| {
        let is_open = open.get();
        let epoch = context.session_epoch.get();
        let next_session = (is_open, epoch);
        if last_session.get_value() == next_session {
            return;
        }
        last_session.set_value(next_session);
        gate.reset();
        error.set(None);
        if !is_open {
            draft.update(|d| d.pairing_string = String::new());
        }
    });

    Effect::new(move |_| {
        if open.get() {
            let detected = detected_endpoints.get();
            draft.update(|d| {
                let valid = d.endpoint_selection == ENDPOINT_CUSTOM
                    || detected.iter().any(|ep| ep.address == d.endpoint_selection);
                if d.endpoint_selection.is_empty() || !valid {
                    d.endpoint_selection = default_endpoint_selection(&detected, false);
                }
            });
        }
    });

    let submit = move || {
        if gate.is_busy_untracked() || !context.is_admin() {
            return;
        }
        let snapshot_draft = draft.get_untracked();
        let req = match build_start_pairing_request(&snapshot_draft) {
            Ok(req) => req,
            Err(key) => {
                error.set(Some(PeerApiError::client(tt(context, key))));
                return;
            }
        };
        let body = match serde_json::to_value(&req) {
            Ok(val) => val,
            Err(err) => {
                error.set(Some(PeerApiError::client(err.to_string())));
                return;
            }
        };
        error.set(None);
        let (token, mut busy_guard) = gate.begin(context.session_epoch);
        spawn_local(async move {
            let result =
                peer_api_request::<StartPairingResponse>(PAIR_START_PATH, "POST", Some(&body))
                    .await;
            match gate.classify(context.session_epoch, open, token, || true) {
                CompletionScope::ExpiredSession => return,
                CompletionScope::StaleDialog => {
                    if result.is_ok() {
                        on_refresh.run(());
                    }
                    return;
                }
                CompletionScope::CurrentDialog => {}
            }
            busy_guard.release();
            match result {
                Ok(resp) => {
                    let remote_name = resp.remote_server_name.clone();
                    draft.update(|d| d.apply_submit_result(true));
                    initiated_pairing.set(Some(resp));
                    open.set(false);
                    on_refresh.run(());
                    context.toast_with(
                        "Cluster.pairingStartedToast",
                        &[("peer", &remote_name)],
                        false,
                    );
                }
                Err(api_err) => {
                    // Retain pairing string, name, and endpoint selection so operator can act on error.
                    draft.update(|d| d.apply_submit_result(false));
                    error.set(Some(api_err));
                }
            }
        });
    };

    view! {
        <Modal
            open=open
            title=Signal::derive(move || tt(context, "Cluster.pairServerTitle"))
        >
            <form
                class="space-y-4"
                on:submit=move |event| {
                    event.prevent_default();
                    submit();
                }
            >
                <p class="text-sm text-slate-300">
                    {move || tt(context, "Cluster.pairServerIntro")}
                </p>

                <PeerErrorAlert error=error />

                <div class="space-y-1.5">
                    <label
                        for="cluster-pair-string"
                        class="block text-sm font-medium text-slate-200"
                    >
                        {move || tt(context, "Cluster.pastePairingStringLabel")}
                    </label>
                    <textarea
                        id="cluster-pair-string"
                        data-af-autofocus="true"
                        rows="4"
                        required
                        autocomplete="off"
                        spellcheck="false"
                        class="glass-input px-3 py-2 w-full font-mono text-xs break-all"
                        placeholder=move || tt(context, "Cluster.pastePairingStringPlaceholder")
                        disabled=move || gate.is_busy()
                        prop:value=move || draft.with(|d| d.pairing_string.clone())
                        on:input=move |event| {
                            let val = event_target_value(&event);
                            draft.update(|d| d.pairing_string = val);
                        }
                    ></textarea>
                </div>

                <div class="space-y-1.5">
                    <label
                        for="cluster-pair-name"
                        class="block text-sm font-medium text-slate-200"
                    >
                        {move || tt(context, "Cluster.peerNameOptionalLabel")}
                    </label>
                    <input
                        id="cluster-pair-name"
                        type="text"
                        autocomplete="off"
                        aria-describedby="cluster-pair-name-hint"
                        class="glass-input px-3 py-2 w-full"
                        placeholder="media-2"
                        disabled=move || gate.is_busy()
                        prop:value=move || draft.with(|d| d.peer_name.clone())
                        on:input=move |event| {
                            let val = event_target_value(&event);
                            draft.update(|d| d.peer_name = val);
                        }
                    />
                    <p id="cluster-pair-name-hint" class="text-xs text-slate-400">
                        {move || tt(context, "Cluster.peerNameOptionalHint")}
                    </p>
                </div>

                <div class="space-y-1.5">
                    <label
                        for="cluster-pair-endpoint"
                        class="block text-sm font-medium text-slate-200"
                    >
                        {move || tt(context, "Cluster.endpointPickerLabel")}
                    </label>
                    <select
                        id="cluster-pair-endpoint"
                        aria-describedby="cluster-pair-endpoint-hint"
                        class="glass-input px-3 py-2 w-full"
                        disabled=move || gate.is_busy()
                        prop:value=move || draft.with(|d| d.endpoint_selection.clone())
                        on:change=move |event| {
                            let val = event_target_value(&event);
                            draft.update(|d| d.endpoint_selection = val);
                        }
                    >
                        {move || {
                            let locale = crate::tabs::l10n::locale(context);
                            detected_endpoints
                                .get()
                                .into_iter()
                                .map(|ep| {
                                    let label = format_endpoint_option(&locale, &ep);
                                    view! { <option value=ep.address>{label}</option> }
                                })
                                .collect_view()
                        }}
                        <option value=ENDPOINT_CUSTOM>
                            {move || tt(context, "Cluster.endpointCustomOption")}
                        </option>
                    </select>
                    <p id="cluster-pair-endpoint-hint" class="text-xs text-slate-400">
                        {move || tt(context, "Cluster.endpointPickerHint")}
                    </p>
                </div>

                <Show when=move || { draft.with(|d| d.endpoint_selection == ENDPOINT_CUSTOM) }>
                    <div class="space-y-1.5">
                        <label
                            for="cluster-pair-custom-endpoint"
                            class="block text-sm font-medium text-slate-200"
                        >
                            {move || tt(context, "Cluster.customEndpointLabel")}
                        </label>
                        <input
                            id="cluster-pair-custom-endpoint"
                            type="text"
                            autocomplete="off"
                            class="glass-input px-3 py-2 w-full"
                            placeholder=move || tt(context, "Cluster.endpointHostPlaceholder")
                            disabled=move || gate.is_busy()
                            prop:value=move || draft.with(|d| d.custom_endpoint.clone())
                            on:input=move |event| {
                                let val = event_target_value(&event);
                                draft.update(|d| d.custom_endpoint = val);
                            }
                        />
                    </div>
                </Show>

                <div class="flex flex-wrap justify-end gap-3 pt-2">
                    <button
                        type="button"
                        class="glass-button px-4 py-2"
                        disabled=move || gate.is_busy()
                        on:click=move |_| open.set(false)
                    >
                        {move || tt(context, "Common.cancel")}
                    </button>
                    <button
                        type="submit"
                        class="glass-button-primary px-4 py-2"
                        disabled=move || gate.is_busy()
                    >
                        {move || {
                            if gate.is_busy() {
                                tt(context, "Cluster.startingPairing")
                            } else {
                                tt(context, "Cluster.startPairingSubmit")
                            }
                        }}
                    </button>
                </div>
            </form>
        </Modal>
    }
}

#[component]
pub fn InitiatedPairingCard(
    initiated: RwSignal<Option<StartPairingResponse>>,
    now_secs: RwSignal<i64>,
    on_refresh: Callback<()>,
) -> impl IntoView {
    let context = app();
    let busy = RwSignal::new(false);
    let error = RwSignal::new(None::<PeerApiError>);

    let cancel_initiated = move || {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        let Some(pending) = initiated.get_untracked() else {
            return;
        };
        let epoch = context.session_epoch.get_untracked();
        let path = pairing_cancel_path(&pending.attempt_id);
        error.set(None);
        busy.set(true);
        let mut busy_guard = BusyGuard::new(busy);
        spawn_local(async move {
            let result = peer_api_request::<CancelPairingResponse>(&path, "DELETE", None).await;
            if busy.try_get_untracked().is_none()
                || context.session_epoch.try_get_untracked() != Some(epoch)
            {
                return;
            }
            match result {
                Ok(_) => {
                    initiated.set(None);
                    on_refresh.run(());
                    context.toast("Cluster.pairingAttemptCancelledToast", false);
                }
                Err(api_err) => error.set(Some(api_err)),
            }
            busy_guard.release();
        });
    };

    view! {
        <Show when=move || initiated.with(Option::is_some)>
            {move || {
                initiated.get().map(|pending| {
                    let expires_at = pending.expires_at;
                    let peer_label = pending.remote_server_name.clone();
                    let peer_label_desc = pending.remote_server_name.clone();
                    let code = pending.comparison_code.clone();
                    view! {
                        <ObsCard>
                            <div class="space-y-4">
                                <div class="flex flex-wrap items-start justify-between gap-3">
                                    <div>
                                        <h3 class="text-base font-semibold">
                                            {move || tt_with(
                                                context,
                                                "Cluster.outgoingPendingHeading",
                                                &[("peer", &peer_label)],
                                            )}
                                        </h3>
                                        <p class="text-sm text-slate-300 mt-1">
                                            {move || tt_with(
                                                context,
                                                "Cluster.outgoingPendingInstructions",
                                                &[("peer", &peer_label_desc)],
                                            )}
                                        </p>
                                    </div>
                                    <span
                                        aria-live="off"
                                        class=move || {
                                            if now_secs.get() >= expires_at {
                                                "af-badge af-badge-danger font-mono"
                                            } else {
                                                "af-badge af-badge-warning font-mono"
                                            }
                                        }
                                    >
                                        {move || {
                                            let locale = crate::tabs::l10n::locale(context);
                                            format_countdown(&locale, expires_at, now_secs.get()).0
                                        }}
                                    </span>
                                </div>

                                <div class="rounded-xl border border-indigo-400/35 bg-white/5 p-4 text-center space-y-1">
                                    <p class="text-xs uppercase tracking-wider text-indigo-300">
                                        {move || tt(context, "Cluster.comparisonCodeLabel")}
                                    </p>
                                    <p
                                        class="text-3xl font-mono font-bold tracking-[0.25em] text-white select-all"
                                        aria-label=move || {
                                            format!(
                                                "{}: {}",
                                                tt(context, "Cluster.comparisonCodeLabel"),
                                                code
                                            )
                                        }
                                    >
                                        {pending.comparison_code.clone()}
                                    </p>
                                </div>

                                <PeerErrorAlert
                                    error=error
                                    on_dismiss=Callback::new(move |()| error.set(None))
                                />

                                <div class="flex justify-end">
                                    <button
                                        type="button"
                                        class="glass-button px-4 py-2 text-sm"
                                        data-tone="danger"
                                        disabled=move || busy.get()
                                        on:click=move |_| cancel_initiated()
                                    >
                                        {move || tt(context, "Cluster.cancelPendingLinkAction")}
                                    </button>
                                </div>
                            </div>
                        </ObsCard>
                    }
                })
            }}
        </Show>
    }
}

#[component]
pub fn PendingAttemptsPanel(
    attempts: Signal<Vec<PairingAttemptView>>,
    now_secs: RwSignal<i64>,
    on_refresh: Callback<()>,
) -> impl IntoView {
    let context = app();
    let name_overrides = RwSignal::new(BTreeMap::<String, String>::new());
    let attempt_errors = RwSignal::new(BTreeMap::<String, PeerApiError>::new());
    let busy_attempt = RwSignal::new(None::<String>);

    let approve = move |attempt_id: String| {
        if busy_attempt.with_untracked(Option::is_some) || !context.is_admin() {
            return;
        }
        let custom_name =
            name_overrides.with_untracked(|map| map.get(&attempt_id).cloned().unwrap_or_default());
        let req = build_confirm_pairing_request(&custom_name);
        let body = match serde_json::to_value(&req) {
            Ok(val) => val,
            Err(err) => {
                attempt_errors.update(|map| {
                    map.insert(attempt_id.clone(), PeerApiError::client(err.to_string()));
                });
                return;
            }
        };
        let epoch = context.session_epoch.get_untracked();
        let path = pairing_confirm_path(&attempt_id);
        attempt_errors.update(|map| {
            map.remove(&attempt_id);
        });
        busy_attempt.set(Some(attempt_id.clone()));
        spawn_local(async move {
            let result =
                peer_api_request::<ConfirmPairingResponse>(&path, "POST", Some(&body)).await;
            if busy_attempt.try_get_untracked().is_none()
                || context.session_epoch.try_get_untracked() != Some(epoch)
            {
                return;
            }
            match result {
                Ok(resp) => {
                    name_overrides.update(|map| {
                        map.remove(&attempt_id);
                    });
                    attempt_errors.update(|map| {
                        map.remove(&attempt_id);
                    });
                    on_refresh.run(());
                    context.toast_with(
                        "Cluster.pairingConfirmedToast",
                        &[("peer", &resp.name)],
                        false,
                    );
                }
                Err(api_err) => {
                    // Retain optional name override and display typed action text for retry.
                    attempt_errors.update(|map| {
                        map.insert(attempt_id.clone(), api_err);
                    });
                }
            }
            busy_attempt.set(None);
        });
    };

    let cancel = move |attempt_id: String| {
        if busy_attempt.with_untracked(Option::is_some) || !context.is_admin() {
            return;
        }
        let epoch = context.session_epoch.get_untracked();
        let path = pairing_cancel_path(&attempt_id);
        attempt_errors.update(|map| {
            map.remove(&attempt_id);
        });
        busy_attempt.set(Some(attempt_id.clone()));
        spawn_local(async move {
            let result = peer_api_request::<CancelPairingResponse>(&path, "DELETE", None).await;
            if busy_attempt.try_get_untracked().is_none()
                || context.session_epoch.try_get_untracked() != Some(epoch)
            {
                return;
            }
            match result {
                Ok(_) => {
                    name_overrides.update(|map| {
                        map.remove(&attempt_id);
                    });
                    attempt_errors.update(|map| {
                        map.remove(&attempt_id);
                    });
                    on_refresh.run(());
                    context.toast("Cluster.pairingAttemptCancelledToast", false);
                }
                Err(api_err) => {
                    attempt_errors.update(|map| {
                        map.insert(attempt_id.clone(), api_err);
                    });
                }
            }
            busy_attempt.set(None);
        });
    };

    view! {
        <Show when=move || !attempts.with(Vec::is_empty)>
            <ObsCard>
                <div class="mb-4">
                    <h3 class="text-base font-semibold">
                        {move || tt(context, "Cluster.pendingAttemptsHeading")}
                    </h3>
                    <p class="text-sm text-slate-400 mt-1">
                        {move || tt(context, "Cluster.pendingAttemptsIntro")}
                    </p>
                </div>

                <div role="list" class="space-y-4">
                    <For
                        each=move || attempts.get()
                        key=|attempt| attempt.id.clone()
                        let:attempt
                    >
                        {
                            let expires_at = attempt.expires_at;
                            let remote_name_opt = attempt
                                .remote_name
                                .clone()
                                .filter(|s| !s.trim().is_empty());
                            let source_opt = attempt.source_ip.clone();
                            let endpoint_opt = attempt.remote_endpoint.clone();
                            let tunnel_ip_opt = attempt.remote_tunnel_ip.clone();
                            let code_opt = attempt.comparison_code.clone();
                            let input_id = format!("cluster-attempt-name-{}", attempt.id);
                            let att_id_val = attempt.id.clone();
                            let att_id_input = attempt.id.clone();
                            let att_id_err = attempt.id.clone();
                            let att_id_dismiss = attempt.id.clone();
                            let att_id_approve = attempt.id.clone();
                            let att_id_cancel = attempt.id.clone();
                            let att_id_busy_label = attempt.id.clone();
                            let remote_name_heading = remote_name_opt.clone();
                            let placeholder_name_opt = remote_name_opt;
                            let code_for_aria = code_opt.clone();

                            view! {
                                <article
                                    role="listitem"
                                    class="rounded-xl border border-indigo-400/35 bg-white/5 p-4 space-y-4"
                                >
                                    <div class="flex flex-wrap items-start justify-between gap-3">
                                        <div class="space-y-1 min-w-0">
                                            <div class="flex flex-wrap items-center gap-2">
                                                <h4 class="font-semibold break-all">
                                                    {move || {
                                                        remote_name_heading
                                                            .clone()
                                                            .unwrap_or_else(|| tt(context, "Unknown"))
                                                    }}
                                                </h4>
                                                <Badge label="Cluster.statusPending" tone="warning" />
                                            </div>
                                            <p class="text-xs font-mono text-slate-400 break-all">
                                                {move || {
                                                    let locale = crate::tabs::l10n::locale(context);
                                                    let source = source_opt
                                                        .clone()
                                                        .unwrap_or_else(|| tt(context, "Not reported"));
                                                    let endpoint = endpoint_opt
                                                        .clone()
                                                        .unwrap_or_else(|| tt(context, "Not reported"));
                                                    let tunnel_ip = tunnel_ip_opt
                                                        .clone()
                                                        .unwrap_or_else(|| tt(context, "Not reported"));
                                                    translate_with(
                                                        &locale,
                                                        "Cluster.attemptSourceSummary",
                                                        &[
                                                            ("source", &source),
                                                            ("endpoint", &endpoint),
                                                            ("tunnel_ip", &tunnel_ip),
                                                        ],
                                                    )
                                                }}
                                            </p>
                                        </div>
                                        <span
                                            aria-live="off"
                                            class=move || {
                                                if now_secs.get() >= expires_at {
                                                    "af-badge af-badge-danger font-mono"
                                                } else {
                                                    "af-badge af-badge-warning font-mono"
                                                }
                                            }
                                        >
                                            {move || {
                                                let locale = crate::tabs::l10n::locale(context);
                                                format_countdown(&locale, expires_at, now_secs.get()).0
                                            }}
                                        </span>
                                    </div>

                                    <div class="rounded-xl border border-white/10 bg-black/25 p-3 text-center space-y-1">
                                        <p class="text-xs uppercase tracking-wider text-indigo-300">
                                            {move || tt(context, "Cluster.comparisonCodeLabel")}
                                        </p>
                                        <p
                                            class="text-3xl font-mono font-bold tracking-[0.25em] text-white select-all"
                                            aria-label=move || {
                                                let code_val = code_for_aria
                                                    .clone()
                                                    .unwrap_or_else(|| tt(context, "Not reported"));
                                                format!(
                                                    "{}: {}",
                                                    tt(context, "Cluster.comparisonCodeLabel"),
                                                    code_val
                                                )
                                            }
                                        >
                                            {move || {
                                                code_opt
                                                    .clone()
                                                    .unwrap_or_else(|| tt(context, "Not reported"))
                                            }}
                                        </p>
                                    </div>

                                    <PeerErrorAlert
                                        error=Signal::derive(move || {
                                            attempt_errors.with(|map| map.get(&att_id_err).cloned())
                                        })
                                        on_dismiss=Callback::new(move |()| {
                                            attempt_errors.update(|map| {
                                                map.remove(&att_id_dismiss);
                                            });
                                        })
                                    />

                                    <div class="flex flex-wrap items-end justify-between gap-3">
                                        <div class="flex-1 min-w-[200px] space-y-1">
                                            <label
                                                for=input_id.clone()
                                                class="block text-xs font-medium text-slate-300"
                                            >
                                                {move || tt(context, "Cluster.attemptLocalNameLabel")}
                                            </label>
                                            <input
                                                id=input_id
                                                type="text"
                                                autocomplete="off"
                                                class="glass-input px-3 py-2 w-full text-sm"
                                                placeholder=move || {
                                                    let fallback = placeholder_name_opt
                                                        .clone()
                                                        .unwrap_or_else(|| tt(context, "Unknown"));
                                                    tt_with(
                                                        context,
                                                        "Cluster.attemptLocalNamePlaceholder",
                                                        &[("name", &fallback)],
                                                    )
                                                }
                                                disabled=move || busy_attempt.with(Option::is_some)
                                                prop:value=move || {
                                                    name_overrides.with(|map| {
                                                        map.get(&att_id_val)
                                                            .cloned()
                                                            .unwrap_or_default()
                                                    })
                                                }
                                                on:input=move |event| {
                                                    let value = event_target_value(&event);
                                                    name_overrides.update(|map| {
                                                        map.insert(att_id_input.clone(), value);
                                                    });
                                                }
                                            />
                                        </div>
                                        <div class="flex flex-wrap gap-2">
                                            <button
                                                type="button"
                                                class="glass-button px-4 py-2 text-sm"
                                                data-tone="danger"
                                                disabled=move || busy_attempt.with(Option::is_some)
                                                on:click=move |_| cancel(att_id_cancel.clone())
                                            >
                                                {move || tt(context, "Cluster.cancelAttemptAction")}
                                            </button>
                                            <button
                                                type="button"
                                                class="glass-button-primary px-4 py-2 text-sm"
                                                disabled=move || {
                                                    now_secs.get() >= expires_at
                                                        || busy_attempt.with(Option::is_some)
                                                }
                                                on:click=move |_| approve(att_id_approve.clone())
                                            >
                                                {move || {
                                                    if busy_attempt.with(|cur| {
                                                        cur.as_deref()
                                                            == Some(att_id_busy_label.as_str())
                                                    }) {
                                                        tt(context, "Cluster.approvingPairing")
                                                    } else {
                                                        tt(context, "Cluster.approvePairingAction")
                                                    }
                                                }}
                                            </button>
                                        </div>
                                    </div>
                                </article>
                            }
                        }
                    </For>
                </div>
            </ObsCard>
        </Show>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tabs::cluster::peers::PeerLinkView;
    use serde_json::json;

    #[test]
    fn endpoint_picker_prefers_recommended_detected_and_supports_custom_option() {
        let detected = vec![
            DetectedEndpointView {
                interface: "eth1".into(),
                address: "10.20.0.5".into(),
                family: "ipv4".into(),
                recommended: true,
            },
            DetectedEndpointView {
                interface: "eth0".into(),
                address: "203.0.113.10".into(),
                family: "ipv4".into(),
                recommended: false,
            },
        ];

        assert_eq!(default_endpoint_selection(&detected, true), "10.20.0.5");
        assert_eq!(default_endpoint_selection(&detected, false), "10.20.0.5");
        assert_eq!(default_endpoint_selection(&[], true), ENDPOINT_AUTO);
        assert_eq!(default_endpoint_selection(&[], false), ENDPOINT_CUSTOM);

        assert_eq!(
            format_endpoint_option("en", &detected[0]),
            "10.20.0.5 (eth1 · ipv4 · Recommended)"
        );
        assert_eq!(
            format_endpoint_option("en", &detected[1]),
            "203.0.113.10 (eth0 · ipv4)"
        );

        assert_eq!(resolve_endpoint_selection(ENDPOINT_AUTO, "").unwrap(), None);
        assert_eq!(
            resolve_endpoint_selection("10.20.0.5", "").unwrap(),
            Some("10.20.0.5".into())
        );
        assert_eq!(
            resolve_endpoint_selection(ENDPOINT_CUSTOM, "  peer.internal.lan  ").unwrap(),
            Some("peer.internal.lan".into())
        );
        assert_eq!(
            resolve_endpoint_selection(ENDPOINT_CUSTOM, "   ").unwrap_err(),
            "Cluster.validationEndpointRequired"
        );
    }

    #[test]
    fn open_window_start_pairing_and_confirm_requests_match_strict_backend_schemas() {
        let open_default = build_open_window_request(ENDPOINT_AUTO, "", "", "").unwrap();
        assert_eq!(serde_json::to_value(&open_default).unwrap(), json!({}));

        let open_full = build_open_window_request(
            ENDPOINT_CUSTOM,
            "10.20.0.9",
            "https://media-2.example.com",
            "51822",
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&open_full).unwrap(),
            json!({
                "endpoint": "10.20.0.9",
                "https_url": "https://media-2.example.com",
                "wg_port": 51822
            })
        );
        assert_eq!(
            build_open_window_request(ENDPOINT_AUTO, "", "http://insecure.local", "").unwrap_err(),
            "Cluster.validationHttpsUrlInvalid"
        );
        assert_eq!(
            build_open_window_request(ENDPOINT_AUTO, "", "", "0").unwrap_err(),
            "Cluster.validationPortInvalid"
        );

        let mut draft = StartPairingDraft {
            pairing_string: " afpair1:eyJ0ZXN0IjoxfQ ".into(),
            peer_name: "media-2".into(),
            endpoint_selection: ENDPOINT_CUSTOM.into(),
            custom_endpoint: "10.20.0.1".into(),
        };
        let start_req = build_start_pairing_request(&draft).unwrap();
        assert_eq!(
            serde_json::to_value(&start_req).unwrap(),
            json!({
                "pairing_string": "afpair1:eyJ0ZXN0IjoxfQ",
                "name": "media-2",
                "endpoint": "10.20.0.1"
            })
        );

        // Failed submission retains actionable input; successful submission clears consumed string.
        draft.apply_submit_result(false);
        assert_eq!(draft.pairing_string, " afpair1:eyJ0ZXN0IjoxfQ ");
        assert_eq!(draft.peer_name, "media-2");
        assert_eq!(draft.custom_endpoint, "10.20.0.1");

        draft.apply_submit_result(true);
        assert!(draft.pairing_string.is_empty());
        assert!(draft.peer_name.is_empty());
        assert_eq!(draft.custom_endpoint, "10.20.0.1");

        assert_eq!(
            build_start_pairing_request(&draft).unwrap_err(),
            "Cluster.validationPairingStringRequired"
        );

        assert_eq!(
            serde_json::to_value(build_confirm_pairing_request("  ")).unwrap(),
            json!({})
        );
        assert_eq!(
            serde_json::to_value(build_confirm_pairing_request("seedbox-1")).unwrap(),
            json!({"name": "seedbox-1"})
        );
    }

    #[test]
    fn pairing_responses_and_state_reconciliation_match_backend_fixtures() {
        let opened: OpenPairingWindowResponse = serde_json::from_value(json!({
            "window_id": "win-1",
            "expires_at": 1_700_000_600,
            "ttl_seconds": 600,
            "pairing_string": "afpair1:encoded",
            "https_url": "https://media-2.example.com",
            "endpoint": "10.0.0.20",
            "wg_port": 51821,
            "tunnel_ip": "10.231.0.2",
            "wg_pubkey": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        }))
        .unwrap();

        let started: StartPairingResponse = serde_json::from_value(json!({
            "link_id": "link-9",
            "attempt_id": "att-9",
            "name": "media-2",
            "remote_server_name": "media-2",
            "comparison_code": "482910",
            "expires_at": 1_700_000_600,
            "state": "pending"
        }))
        .unwrap();

        let confirmed: ConfirmPairingResponse = serde_json::from_value(json!({
            "link_id": "link-9",
            "name": "seedbox-1",
            "state": "active",
            "attempt_id": "att-9",
            "confirmed": true,
            "rtt_ms": 1.3
        }))
        .unwrap();
        assert!(confirmed.confirmed);
        assert_eq!(confirmed.state, "active");

        let cancelled: CancelPairingResponse = serde_json::from_value(json!({
            "cancelled": true,
            "attempt_id": "att-9"
        }))
        .unwrap();
        assert!(cancelled.cancelled);

        // Window stays retained while open and unexpired, clears once consumed or expired.
        let snapshot_open = PeersSnapshot {
            pairing_windows: vec![PairingWindowSummary {
                id: "win-1".into(),
                expires_at: 1_700_000_600,
            }],
            ..Default::default()
        };
        assert_eq!(
            reconcile_opened_window(&opened, &snapshot_open, 1_700_000_100),
            ReconcileWindow::Keep
        );
        assert_eq!(
            reconcile_opened_window(&opened, &snapshot_open, 1_700_000_600),
            ReconcileWindow::Clear
        );
        assert_eq!(
            reconcile_opened_window(&opened, &PeersSnapshot::default(), 1_700_000_100),
            ReconcileWindow::Clear
        );
        let snapshot_consumed = PeersSnapshot {
            pairing_attempts: vec![PairingAttemptView {
                id: "att-1".into(),
                window_id: Some("win-1".into()),
                remote_name: Some("seedbox-1".into()),
                comparison_code: Some("482910".into()),
                status: "pending".into(),
                expires_at: 1_700_000_600,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            reconcile_opened_window(&opened, &snapshot_consumed, 1_700_000_100),
            ReconcileWindow::ConsumedByAttempt
        );

        // Initiated pairing stays while pending, reports activation when active, clears if revoked.
        let pending_snap = PeersSnapshot {
            peers: vec![PeerLinkView {
                id: "link-9".into(),
                name: "media-2".into(),
                state: "pending".into(),
                pending_attempt_id: Some(started.attempt_id.clone()),
                pending_expires_at: Some(started.expires_at),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            reconcile_initiated_pairing(&started, &pending_snap),
            ReconcileInitiated::Keep
        );
        assert_eq!(
            reconcile_initiated_pairing(&started, &PeersSnapshot::default()),
            ReconcileInitiated::Clear
        );
        let cleanup_snap = PeersSnapshot {
            peers: vec![PeerLinkView {
                pending_attempt_id: None,
                pending_expires_at: None,
                ..pending_snap.peers[0].clone()
            }],
            ..Default::default()
        };
        assert_eq!(
            reconcile_initiated_pairing(&started, &cleanup_snap),
            ReconcileInitiated::Clear
        );

        let active_snap = PeersSnapshot {
            peers: vec![PeerLinkView {
                id: "link-9".into(),
                name: "media-2".into(),
                state: "active".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            reconcile_initiated_pairing(&started, &active_snap),
            ReconcileInitiated::Activated {
                peer_name: "media-2".into()
            }
        );

        let revoked_snap = PeersSnapshot {
            peers: vec![PeerLinkView {
                id: "link-9".into(),
                name: "media-2".into(),
                state: "revoked".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            reconcile_initiated_pairing(&started, &revoked_snap),
            ReconcileInitiated::Clear
        );
    }

    #[test]
    fn window_modal_focus_transitions_only_move_focus_for_same_session_view_swaps() {
        let closed = WindowModalSession::Closed(1);
        let form = WindowModalSession::Form(1);
        let win1 = WindowModalSession::Generated {
            epoch: 1,
            window_id: "win-1".into(),
        };
        let win2 = WindowModalSession::Generated {
            epoch: 1,
            window_id: "win-2".into(),
        };
        let other_epoch_form = WindowModalSession::Form(2);
        let other_epoch_win = WindowModalSession::Generated {
            epoch: 2,
            window_id: "win-1".into(),
        };

        assert_eq!(window_modal_focus_transition(&closed, &form), None);
        assert_eq!(window_modal_focus_transition(&closed, &win1), None);
        assert_eq!(window_modal_focus_transition(&form, &closed), None);
        assert_eq!(window_modal_focus_transition(&win1, &closed), None);
        assert_eq!(
            window_modal_focus_transition(&form, &win1),
            Some(WindowFocusTarget::PairingString)
        );
        assert_eq!(
            window_modal_focus_transition(&win1, &win2),
            Some(WindowFocusTarget::PairingString)
        );
        assert_eq!(
            window_modal_focus_transition(&win1, &form),
            Some(WindowFocusTarget::Form)
        );
        assert_eq!(window_modal_focus_transition(&form, &other_epoch_win), None);
        assert_eq!(
            window_modal_focus_transition(&win1, &other_epoch_form),
            None
        );
    }
}
