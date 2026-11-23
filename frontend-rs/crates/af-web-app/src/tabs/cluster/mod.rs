//! Peer Clustering tab (`/?tab=cluster`): link list, pairing window, pairing flow,
//! comparison-code confirmation, endpoint editing, and link revocation.

pub mod pairing;
pub mod peers;

use crate::state::{app, owned_resource_reads, run_resource_read, AppContext, ResourceReads};
use crate::tabs::busy::BusyGuard;
use crate::tabs::l10n::{tt, tt_with, EmptyState, ObsCard};
use af_web_core::api::{percent_encode_header_component, ApiClient, ApiError};
use af_web_core::i18n::{translate, translate_with};
use leptos::prelude::*;
use pairing::{
    reconcile_initiated_pairing, reconcile_opened_window, ActivePairingWindowsCard,
    InitiatedPairingCard, OpenPairingWindowModal, OpenPairingWindowResponse, PendingAttemptsPanel,
    ReconcileInitiated, ReconcileWindow, StartPairingModal, StartPairingResponse,
};
use peers::{is_unlinked_empty_state, PeerListSection, PeersSnapshot};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use wasm_bindgen_futures::{spawn_local, JsFuture};

pub const PEERS_LIST_PATH: &str = "/api/v1/admin/peers";
pub const PAIRING_WINDOW_PATH: &str = "/api/v1/admin/peers/pairing-window";
pub const PAIR_START_PATH: &str = "/api/v1/admin/peers/pair";

pub fn pairing_window_close_path(window_id: &str) -> String {
    format!(
        "{PAIRING_WINDOW_PATH}/{}",
        percent_encode_header_component(window_id)
    )
}

pub fn pairing_confirm_path(attempt_id: &str) -> String {
    format!(
        "/api/v1/admin/peers/pairing/{}/confirm",
        percent_encode_header_component(attempt_id)
    )
}

pub fn pairing_cancel_path(attempt_id: &str) -> String {
    format!(
        "/api/v1/admin/peers/pairing/{}",
        percent_encode_header_component(attempt_id)
    )
}

pub fn peer_endpoint_path(link_id: &str) -> String {
    format!(
        "/api/v1/admin/peers/{}/endpoint",
        percent_encode_header_component(link_id)
    )
}

pub fn peer_revoke_path(link_id: &str) -> String {
    format!(
        "/api/v1/admin/peers/{}",
        percent_encode_header_component(link_id)
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PeerApiErrorDetail {
    status: u16,
    code: Option<String>,
    server: Option<String>,
    step: Option<String>,
    message: String,
    action: Option<String>,
}

/// Structured peer API error preserving backend `{code, server, step, message, action}` fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerApiError(Box<PeerApiErrorDetail>);

impl PeerApiError {
    fn from_parts(
        status: u16,
        code: Option<String>,
        server: Option<String>,
        step: Option<String>,
        message: String,
        action: Option<String>,
    ) -> Self {
        Self(Box::new(PeerApiErrorDetail {
            status,
            code,
            server,
            step,
            message,
            action,
        }))
    }

    pub fn client(message: impl Into<String>) -> Self {
        Self::from_parts(0, None, None, None, message.into(), None)
    }

    #[cfg(test)]
    pub fn status(&self) -> u16 {
        self.0.status
    }

    pub fn code(&self) -> Option<&str> {
        self.0.code.as_deref()
    }

    pub fn server(&self) -> Option<&str> {
        self.0.server.as_deref()
    }

    pub fn step(&self) -> Option<&str> {
        self.0.step.as_deref()
    }

    pub fn message(&self) -> &str {
        &self.0.message
    }

    pub fn action(&self) -> Option<&str> {
        self.0.action.as_deref()
    }

    pub fn context_summary(&self, locale: &str) -> Option<String> {
        match (self.server(), self.step(), self.code()) {
            (Some(server), Some(step), Some(code)) => Some(translate_with(
                locale,
                "Cluster.errorContext",
                &[("server", server), ("step", step), ("code", code)],
            )),
            (Some(server), Some(step), None) => Some(translate_with(
                locale,
                "Cluster.errorServerStep",
                &[("server", server), ("step", step)],
            )),
            (_, _, Some(code)) => Some(translate_with(
                locale,
                "Cluster.errorCodeOnly",
                &[("code", code)],
            )),
            _ => None,
        }
    }
}

impl From<ApiError> for PeerApiError {
    fn from(error: ApiError) -> Self {
        Self::from_parts(error.status, error.code, None, None, error.message, None)
    }
}

fn non_empty_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

/// Decodes a raw peer API response, preserving typed backend error `action`, `server`, `step`,
/// `code`, and `message` fields when the HTTP status is non-success.
pub fn parse_peer_api_response<T: DeserializeOwned>(
    status: u16,
    ok: bool,
    body_text: &str,
) -> Result<T, PeerApiError> {
    let trimmed = body_text.trim();
    if !ok {
        if let Ok(json) = serde_json::from_str::<Value>(trimmed) {
            let message = non_empty_field(&json, "message")
                .or_else(|| non_empty_field(&json, "error"))
                .unwrap_or_else(|| format!("Request failed (HTTP {status})"));
            return Err(PeerApiError::from_parts(
                status,
                non_empty_field(&json, "code"),
                non_empty_field(&json, "server"),
                non_empty_field(&json, "step"),
                message,
                non_empty_field(&json, "action"),
            ));
        }
        return Err(PeerApiError::from_parts(
            status,
            None,
            None,
            None,
            if trimmed.is_empty() {
                format!("Request failed (HTTP {status})")
            } else {
                trimmed.chars().take(240).collect()
            },
            None,
        ));
    }

    if trimmed.is_empty() {
        return serde_json::from_value(Value::Null).map_err(|err| {
            PeerApiError::from_parts(
                status,
                None,
                None,
                None,
                format!("Invalid API response: {err}"),
                None,
            )
        });
    }

    serde_json::from_str::<T>(trimmed).map_err(|err| {
        PeerApiError::from_parts(
            status,
            None,
            None,
            None,
            format!("Invalid API response: {err}"),
            None,
        )
    })
}

/// Sends an authenticated local same-origin request to `/api/v1/admin/peers*` via `ApiClient.fetch`
/// (preserving session refresh, CSRF token handling, and typed `PeerError` bodies).
pub async fn peer_api_request<T: DeserializeOwned>(
    path: &str,
    method: &str,
    body: Option<&Value>,
) -> Result<T, PeerApiError> {
    let response = ApiClient
        .fetch(path, method, body)
        .await
        .map_err(PeerApiError::from)?;
    let status = response.status();
    let ok = response.ok();
    let text = response.text().await.map_err(PeerApiError::from)?;
    parse_peer_api_response(status, ok, &text)
}

pub fn current_unix_secs() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0).floor() as i64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0)
    }
}

/// Formats a remaining pairing window or attempt countdown (`mm:ss remaining` or `Expired`).
pub fn format_countdown(locale: &str, expires_at: i64, now_secs: i64) -> (String, bool) {
    let remaining = expires_at.saturating_sub(now_secs);
    if remaining <= 0 {
        return (translate(locale, "Cluster.expired"), true);
    }
    let minutes = remaining / 60;
    let seconds = remaining % 60;
    let formatted = format!("{minutes:02}:{seconds:02}");
    (
        translate_with(
            locale,
            "Cluster.countdownRemaining",
            &[("time", &formatted)],
        ),
        false,
    )
}

pub fn copy_text_to_clipboard(context: AppContext, value: String) {
    if value.is_empty() {
        return;
    }
    spawn_local(async move {
        if let Some(window) = web_sys::window() {
            match JsFuture::from(window.navigator().clipboard().write_text(&value)).await {
                Ok(_) => context.toast("Copied to clipboard", false),
                Err(_) => context.toast("Clipboard unavailable; select and copy the value", true),
            }
        }
    });
}

/// Tracks the active open/target/view generation of a mounted `<Modal>` so async completions
/// from a dismissed or replaced dialog cannot unlock a newer busy state, close the dialog,
/// overwrite its form/error, or reveal a predecessor's secret.
#[derive(Clone, Copy)]
pub(super) struct DialogGate {
    generation: RwSignal<u64>,
    busy: RwSignal<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MutationToken {
    pub(super) session_epoch: u64,
    pub(super) generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CompletionScope {
    /// Component disposed or user session epoch changed; discard all effects.
    ExpiredSession,
    /// Same session, but the dialog was dismissed or moved to another target/view.
    StaleDialog,
    /// Same session and still the exact active dialog generation.
    CurrentDialog,
}

impl DialogGate {
    pub(super) fn new() -> Self {
        Self {
            generation: RwSignal::new(0),
            busy: RwSignal::new(false),
        }
    }

    pub(super) fn is_busy(self) -> bool {
        self.busy.get()
    }

    pub(super) fn is_busy_untracked(self) -> bool {
        self.busy.get_untracked()
    }

    /// Advances the local dialog generation and clears `busy`, invalidating any in-flight
    /// mutation from a prior open/close/target/view cycle without altering auth session epoch.
    pub(super) fn reset(self) -> u64 {
        self.generation.update(|g| *g = g.wrapping_add(1));
        self.busy.set(false);
        self.generation.get_untracked()
    }

    /// Marks the current dialog generation busy and binds a generation-checked `BusyGuard`.
    pub(super) fn begin(self, session_epoch: RwSignal<u64>) -> (MutationToken, BusyGuard) {
        let token = MutationToken {
            session_epoch: session_epoch.get_untracked(),
            generation: self.generation.get_untracked(),
        };
        self.busy.set(true);
        let guard = BusyGuard::for_generation(self.busy, self.generation, token.generation);
        (token, guard)
    }

    /// Classifies an async completion against disposal, session epoch, open state, generation,
    /// and a target/view match predicate.
    pub(super) fn classify(
        self,
        session_epoch: RwSignal<u64>,
        open: RwSignal<bool>,
        token: MutationToken,
        target_matches: impl FnOnce() -> bool,
    ) -> CompletionScope {
        let Some(current_gen) = self.generation.try_get_untracked() else {
            return CompletionScope::ExpiredSession;
        };
        if session_epoch.try_get_untracked() != Some(token.session_epoch) {
            return CompletionScope::ExpiredSession;
        }
        if open.try_get_untracked() != Some(true)
            || current_gen != token.generation
            || !target_matches()
        {
            return CompletionScope::StaleDialog;
        }
        CompletionScope::CurrentDialog
    }
}

#[component]
pub fn PeerErrorAlert(
    #[prop(into)] error: Signal<Option<PeerApiError>>,
    #[prop(optional)] on_dismiss: Option<Callback<()>>,
) -> impl IntoView {
    let context = app();
    view! {
        <Show when=move || error.get().is_some()>
            {move || {
                error.get().map(|err| {
                    let locale = crate::tabs::l10n::locale(context);
                    let meta = err.context_summary(&locale);
                    let action = err.action().map(str::to_string);
                    let message = err.message().to_string();
                    view! {
                        <div
                            role="alert"
                            class="af-danger-banner space-y-1.5"
                        >
                            <div class="flex items-start justify-between gap-3">
                                <p class="font-medium break-words">{message}</p>
                                {on_dismiss.map(|dismiss| {
                                    view! {
                                        <button
                                            type="button"
                                            class="glass-button px-2.5 py-1 text-xs shrink-0"
                                            aria-label=move || tt(context, "Cluster.dismissError")
                                            on:click=move |_| dismiss.run(())
                                        >
                                            "×"
                                        </button>
                                    }
                                })}
                            </div>
                            {action.map(|next_step| {
                                view! {
                                    <p class="text-slate-200 break-words">
                                        <span class="font-semibold text-amber-300">
                                            {move || tt(context, "Cluster.errorNextStep")}
                                        </span>
                                        ": "
                                        {next_step}
                                    </p>
                                }
                            })}
                            {meta.map(|context_line| {
                                view! {
                                    <p class="text-xs font-mono text-slate-400 break-all">
                                        {context_line}
                                    </p>
                                }
                            })}
                        </div>
                    }
                })
            }}
        </Show>
    }
}

#[component]
pub fn ClusterTab() -> impl IntoView {
    let context = app();
    view! {
        <Show
            when=move || context.is_admin()
            fallback=move || {
                view! {
                    <EmptyState title="Common.adminRequired" />
                }
            }
        >
            <ClusterAdminContent />
        </Show>
    }
}

#[component]
fn ClusterAdminContent() -> impl IntoView {
    let context = app();
    let snapshot = RwSignal::new(None::<PeersSnapshot>);
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(None::<PeerApiError>);
    let revision = RwSignal::new(0u64);
    let generation = RwSignal::new(0u64);
    let reads = owned_resource_reads();
    let last_epoch = StoredValue::new(context.session_epoch.get_untracked());

    let allow_modal_open = RwSignal::new(false);
    let pair_modal_open = RwSignal::new(false);
    let opened_window = RwSignal::new(None::<OpenPairingWindowResponse>);
    let initiated_pairing = RwSignal::new(None::<StartPairingResponse>);
    let now_secs = RwSignal::new(current_unix_secs());

    let trigger_refresh = Callback::new(move |()| {
        revision.update(|rev| *rev += 1);
    });

    Effect::new(move |_| {
        let epoch = context.session_epoch.get();
        if last_epoch.get_value() != epoch {
            snapshot.set(None);
            load_error.set(None);
            allow_modal_open.set(false);
            pair_modal_open.set(false);
            opened_window.set(None);
            initiated_pairing.set(None);
            last_epoch.set_value(epoch);
        }
        let requested_revision = revision.get();
        if !context.is_admin() {
            reads.with_value(ResourceReads::cancel);
            loading.set(false);
            return;
        }
        generation.update(|ticket| *ticket += 1);
        let ticket = generation.get_untracked();
        loading.set(true);
        let Some(job) = reads.try_update_value(ResourceReads::next) else {
            return;
        };
        spawn_local(async move {
            let work = async move {
                if generation.try_get_untracked() != Some(ticket)
                    || revision.try_get_untracked() != Some(requested_revision)
                    || context.session_epoch.try_get_untracked() != Some(epoch)
                {
                    return None;
                }
                Some(peer_api_request::<PeersSnapshot>(PEERS_LIST_PATH, "GET", None).await)
            };
            let Some(Some(result)) = run_resource_read(job, work).await else {
                return;
            };
            if generation.try_get_untracked() != Some(ticket)
                || revision.try_get_untracked() != Some(requested_revision)
                || context.session_epoch.try_get_untracked() != Some(epoch)
            {
                return;
            }
            match result {
                Ok(data) => {
                    let now = current_unix_secs();
                    now_secs.set(now);
                    if let Some(current_window) = opened_window.get_untracked() {
                        match reconcile_opened_window(&current_window, &data, now) {
                            ReconcileWindow::Keep => {}
                            ReconcileWindow::ConsumedByAttempt => {
                                opened_window.set(None);
                                allow_modal_open.set(false);
                            }
                            ReconcileWindow::Clear => {
                                opened_window.set(None);
                            }
                        }
                    }
                    if let Some(current_initiated) = initiated_pairing.get_untracked() {
                        match reconcile_initiated_pairing(&current_initiated, &data) {
                            ReconcileInitiated::Keep => {}
                            ReconcileInitiated::Activated { peer_name } => {
                                initiated_pairing.set(None);
                                context.toast_with(
                                    "Cluster.pairingCompletedToast",
                                    &[("peer", &peer_name)],
                                    false,
                                );
                            }
                            ReconcileInitiated::Clear => {
                                initiated_pairing.set(None);
                            }
                        }
                    }
                    snapshot.set(Some(data));
                    load_error.set(None);
                }
                Err(error) => {
                    load_error.set(Some(error));
                }
            }
            loading.set(false);
        });
    });

    let poll_timer = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        10_000,
        move || {
            if !loading.get_untracked() && context.is_admin() {
                revision.update(|rev| *rev += 1);
            }
        },
    )));
    let countdown_timer = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        1_000,
        move || {
            let has_countdown = opened_window.with_untracked(Option::is_some)
                || initiated_pairing.with_untracked(Option::is_some)
                || snapshot.with_untracked(|snap| {
                    snap.as_ref().is_some_and(|data| {
                        !data.pairing_windows.is_empty()
                            || !data.pairing_attempts.is_empty()
                            || data
                                .peers
                                .iter()
                                .any(|peer| peer.pending_expires_at.is_some())
                    })
                });
            if has_countdown {
                now_secs.set(current_unix_secs());
            }
        },
    )));
    on_cleanup(move || {
        poll_timer.set_value(None);
        countdown_timer.set_value(None);
    });

    let detected_endpoints = Memo::new(move |_| {
        snapshot
            .get()
            .map(|data| data.detected_endpoints)
            .unwrap_or_default()
    });
    let active_windows = Memo::new(move |_| {
        snapshot
            .get()
            .map(|data| data.pairing_windows)
            .unwrap_or_default()
    });
    let pending_attempts = Memo::new(move |_| {
        snapshot
            .get()
            .map(|data| data.pairing_attempts)
            .unwrap_or_default()
    });
    let peers_list = Memo::new(move |_| snapshot.get().map(|data| data.peers).unwrap_or_default());
    let rtt_warn_ms =
        Memo::new(move |_| snapshot.get().map(|data| data.rtt_warn_ms).unwrap_or(25.0));

    view! {
        <section class="space-y-6 py-5 min-w-0 max-w-full">
            <ObsCard>
                <div class="flex flex-wrap justify-between items-start gap-4 mb-4">
                    <div class="space-y-1.5 min-w-0">
                        <h2 class="text-lg font-semibold">
                            {move || tt(context, "Tabs.clusterHeading")}
                        </h2>
                        <p class="text-sm text-slate-400">
                            {move || {
                                match snapshot.get() {
                                    None => tt(context, "Common.loading"),
                                    Some(ref data) if is_unlinked_empty_state(data) => {
                                        tt(context, "Cluster.standaloneSummary")
                                    }
                                    Some(ref data) => {
                                        let total = data.peers.len().to_string();
                                        let healthy = data
                                            .peers
                                            .iter()
                                            .filter(|peer| peer.state == "active")
                                            .count()
                                            .to_string();
                                        let protocol = data.peer_protocol.to_string();
                                        tt_with(
                                            context,
                                            "Cluster.peersSummary",
                                            &[
                                                ("total", &total),
                                                ("healthy", &healthy),
                                                ("protocol", &protocol),
                                            ],
                                        )
                                    }
                                }
                            }}
                        </p>
                        <Show when=move || {
                            snapshot
                                .with(|snap| snap.as_ref().and_then(|d| d.identity.as_ref()).is_some())
                        }>
                            <p class="text-xs font-mono text-slate-400">
                                {move || {
                                    snapshot
                                        .with(|snap| {
                                            snap.as_ref()
                                                .and_then(|d| d.identity.as_ref())
                                                .map(|id| {
                                                    tt_with(
                                                        context,
                                                        "Cluster.localTunnelSummary",
                                                        &[
                                                            ("ip", &id.tunnel_ip),
                                                            ("port", &id.wg_port.to_string()),
                                                        ],
                                                    )
                                                })
                                        })
                                        .unwrap_or_default()
                                }}
                            </p>
                        </Show>
                    </div>
                    <div class="flex flex-wrap gap-3">
                        <button
                            type="button"
                            class="glass-button px-4 py-2"
                            disabled=move || loading.get()
                            aria-label=move || tt(context, "Cluster.refreshPeers")
                            on:click=move |_| trigger_refresh.run(())
                        >
                            {move || tt(context, "Common.refresh")}
                        </button>
                        <button
                            type="button"
                            class="glass-button px-4 py-2"
                            on:click=move |_| allow_modal_open.set(true)
                        >
                            {move || tt(context, "Cluster.allowServerAction")}
                        </button>
                        <button
                            type="button"
                            class="glass-button-primary px-4 py-2"
                            on:click=move |_| pair_modal_open.set(true)
                        >
                            {move || tt(context, "Cluster.pairServerAction")}
                        </button>
                    </div>
                </div>

                <Show when=move || loading.get() && snapshot.with(Option::is_none)>
                    <p role="status" class="text-sm text-slate-400 py-3">
                        {move || tt(context, "Common.loading")}
                    </p>
                </Show>

                <Show when=move || load_error.get().is_some()>
                    <div class="space-y-3 my-3">
                        <PeerErrorAlert error=load_error />
                        <div>
                            <button
                                type="button"
                                class="glass-button px-3 py-2 text-sm"
                                on:click=move |_| trigger_refresh.run(())
                            >
                                {move || tt(context, "Common.retry")}
                            </button>
                        </div>
                    </div>
                </Show>
            </ObsCard>

            <InitiatedPairingCard
                initiated=initiated_pairing
                now_secs=now_secs
                on_refresh=trigger_refresh
            />

            <PendingAttemptsPanel
                attempts=pending_attempts.into()
                now_secs=now_secs
                on_refresh=trigger_refresh
            />

            <ActivePairingWindowsCard
                windows=active_windows.into()
                now_secs=now_secs
                opened_window=opened_window
                on_refresh=trigger_refresh
            />

            <PeerListSection
                peers=peers_list.into()
                rtt_warn_ms=rtt_warn_ms.into()
                now_secs=now_secs
                loaded=Signal::derive(move || snapshot.with(Option::is_some))
                on_refresh=trigger_refresh
            />

            <OpenPairingWindowModal
                open=allow_modal_open
                detected_endpoints=detected_endpoints.into()
                opened_window=opened_window
                now_secs=now_secs
                on_refresh=trigger_refresh
            />

            <StartPairingModal
                open=pair_modal_open
                detected_endpoints=detected_endpoints.into()
                initiated_pairing=initiated_pairing
                on_refresh=trigger_refresh
            />
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::TabId;
    use af_web_core::api::{api_url, set_active_server, should_attach_csrf};
    use serde_json::json;

    #[test]
    fn cluster_tab_preserves_tab_id_query_key_and_admin_guard() {
        assert_eq!(TabId::Cluster.key(), "cluster");
        assert_eq!(TabId::from_key("cluster"), TabId::Cluster);
        assert!(TabId::Cluster.is_admin_only());
    }

    #[test]
    fn peer_management_routes_stay_local_same_origin_and_attach_csrf_on_mutations() {
        set_active_server(Some("media-2".into()));

        let list = PEERS_LIST_PATH.to_string();
        let open_window = PAIRING_WINDOW_PATH.to_string();
        let close_window = pairing_window_close_path("win-1/with space");
        let start_pair = PAIR_START_PATH.to_string();
        let confirm_attempt = pairing_confirm_path("att-123");
        let cancel_attempt = pairing_cancel_path("att-123");
        let update_endpoint = peer_endpoint_path("link-42");
        let revoke_link = peer_revoke_path("link-42");

        assert_eq!(list, "/api/v1/admin/peers");
        assert_eq!(open_window, "/api/v1/admin/peers/pairing-window");
        assert_eq!(
            close_window,
            "/api/v1/admin/peers/pairing-window/win-1%2Fwith%20space"
        );
        assert_eq!(start_pair, "/api/v1/admin/peers/pair");
        assert_eq!(
            confirm_attempt,
            "/api/v1/admin/peers/pairing/att-123/confirm"
        );
        assert_eq!(cancel_attempt, "/api/v1/admin/peers/pairing/att-123");
        assert_eq!(update_endpoint, "/api/v1/admin/peers/link-42/endpoint");
        assert_eq!(revoke_link, "/api/v1/admin/peers/link-42");

        // Even while a remote peer server is active, all peer-clustering management controls
        // MUST remain on the local managing origin and never get prefixed with `/api/v1/peers/{id}`.
        for route in [
            &list,
            &open_window,
            &close_window,
            &start_pair,
            &confirm_attempt,
            &cancel_attempt,
            &update_endpoint,
            &revoke_link,
        ] {
            assert_eq!(
                api_url(route),
                *route,
                "route drifted off local origin: {route}"
            );
        }

        // Read does not attach CSRF; all state-changing admin peer routes do.
        assert!(!should_attach_csrf("GET", &list, None));
        assert!(should_attach_csrf("POST", &open_window, None));
        assert!(should_attach_csrf("DELETE", &open_window, None));
        assert!(should_attach_csrf("DELETE", &close_window, None));
        assert!(should_attach_csrf("POST", &start_pair, None));
        assert!(should_attach_csrf("POST", &confirm_attempt, None));
        assert!(should_attach_csrf("DELETE", &cancel_attempt, None));
        assert!(should_attach_csrf("PUT", &update_endpoint, None));
        assert!(should_attach_csrf("DELETE", &revoke_link, None));

        set_active_server(None);
    }

    #[test]
    fn typed_peer_error_envelopes_preserve_code_server_step_message_and_action() {
        let codes = [
            (410, "CODE_EXPIRED", "media-2", "public_pairing_request", "Pairing window expired", "Open a new pairing window and start pairing again"),
            (409, "CODE_USED", "media-2", "public_pairing_request", "Pairing code was already consumed", "Open a fresh pairing window to generate a new single-use pairing string"),
            (410, "WINDOW_CLOSED", "media-2", "public_pairing_request", "No open pairing window is available", "Open a pairing window on the target server before pasting the pairing string"),
            (409, "KEY_MISMATCH", "seedbox-1", "start_pairing", "Peer key mismatch", "Verify the peer WireGuard identity, remove any conflicting peer entry, and re-pair"),
            (409, "TUNNEL_IP_CONFLICT", "seedbox-1", "start_pairing", "Tunnel IP conflict", "Verify AF_PEER_TUNNEL_CIDR addresses do not overlap and retry pairing"),
            (502, "ENDPOINT_UNREACHABLE", "media-2", "start_pairing", "Target server unreachable", "Confirm the server URL, TLS certificate, and firewall reachability, then retry"),
            (504, "HANDSHAKE_TIMEOUT", "media-2", "confirm_pairing", "Tunnel hello timed out", "Confirm UDP port 51821 and the selected endpoint are reachable between both servers, then retry confirmation"),
            (422, "VERSION_INCOMPATIBLE", "media-2", "start_pairing", "Protocol mismatch", "Update both AetherFlow servers to a compatible peer protocol version and retry"),
            (400, "CLOCK_SKEW", "media-2", "public_pairing_request", "System clocks differ by 420s", "Synchronize system clocks with NTP on both servers and retry pairing"),
            (403, "LINK_REVOKED", "media-2", "update_peer_endpoint", "Cannot update endpoint for revoked link", "Remove the revoked link and re-pair the servers if access is still needed"),
        ];

        for (status, code, server, step, message, action) in codes {
            let body = json!({
                "code": code,
                "server": server,
                "step": step,
                "message": message,
                "action": action,
            })
            .to_string();

            let err = parse_peer_api_response::<Value>(status, false, &body).unwrap_err();
            assert_eq!(err.status(), status);
            assert_eq!(err.code(), Some(code));
            assert_eq!(err.server(), Some(server));
            assert_eq!(err.step(), Some(step));
            assert_eq!(err.message(), message);
            assert_eq!(err.action(), Some(action));
            let ctx = err.context_summary("en").unwrap();
            assert!(ctx.contains(server));
            assert!(ctx.contains(step));
            assert!(ctx.contains(code));
        }

        // Non-typed fallback JSON and empty body degrade safely without losing status.
        let generic = parse_peer_api_response::<Value>(500, false, r#"{"error":"Runner offline"}"#)
            .unwrap_err();
        assert_eq!(generic.message(), "Runner offline");
        assert!(generic.action().is_none());

        let empty = parse_peer_api_response::<Value>(502, false, "").unwrap_err();
        assert_eq!(empty.message(), "Request failed (HTTP 502)");
    }

    #[test]
    fn countdown_formats_remaining_time_and_expiry_across_locales() {
        assert_eq!(
            format_countdown("en", 1_700_000_600, 1_700_000_000),
            ("10:00 remaining".to_string(), false)
        );
        assert_eq!(
            format_countdown("en", 1_700_000_065, 1_700_000_000),
            ("01:05 remaining".to_string(), false)
        );
        assert_eq!(
            format_countdown("en", 1_700_000_000, 1_700_000_000),
            ("Expired".to_string(), true)
        );
        assert_eq!(
            format_countdown("en", 1_699_999_990, 1_700_000_000),
            ("Expired".to_string(), true)
        );
        for locale in ["de", "dk", "es", "fr", "zh"] {
            let (text, expired) = format_countdown(locale, 1_700_000_090, 1_700_000_000);
            assert!(!expired);
            assert!(text.contains("01:30"), "{locale}: {text}");
            let (exp_text, expired) = format_countdown(locale, 1_700_000_000, 1_700_000_000);
            assert!(expired);
            assert_ne!(exp_text, "Cluster.expired", "{locale}");
        }
    }

    #[test]
    fn dialog_gate_isolates_dismissed_and_reopened_mutations_without_changing_session_epoch() {
        let owner = Owner::new();
        owner.with(|| {
            let session_epoch = RwSignal::new(7u64);
            let open = RwSignal::new(true);
            let gate = DialogGate::new();

            // Open #1 starts an async mutation.
            let gen1 = gate.reset();
            let (token1, guard1) = gate.begin(session_epoch);
            assert_eq!(token1.generation, gen1);
            assert_eq!(token1.session_epoch, 7);
            assert!(gate.is_busy_untracked());
            assert_eq!(
                gate.classify(session_epoch, open, token1, || true),
                CompletionScope::CurrentDialog
            );

            // Closing the dialog immediately marks the in-flight mutation stale even before reset.
            open.set(false);
            assert_eq!(
                gate.classify(session_epoch, open, token1, || true),
                CompletionScope::StaleDialog
            );

            // Lifecycle reset clears busy for the next open without touching auth session epoch.
            let gen_closed = gate.reset();
            assert_ne!(gen_closed, gen1);
            assert!(!gate.is_busy_untracked());
            assert_eq!(session_epoch.get_untracked(), 7);

            // Reopen and start mutation #2 while mutation #1 is still in flight.
            open.set(true);
            let gen2 = gate.reset();
            let (token2, mut guard2) = gate.begin(session_epoch);
            assert_eq!(token2.generation, gen2);
            assert!(gate.is_busy_untracked());

            // Stale completion #1 is classified as StaleDialog and dropping its guard keeps #2 busy.
            assert_eq!(
                gate.classify(session_epoch, open, token1, || true),
                CompletionScope::StaleDialog
            );
            drop(guard1);
            assert!(
                gate.is_busy_untracked(),
                "stale guard must not clear busy state of replacement request"
            );

            // Target mismatch on the same generation is also treated as stale.
            assert_eq!(
                gate.classify(session_epoch, open, token2, || false),
                CompletionScope::StaleDialog
            );

            // Active completion #2 matches and releases busy cleanly.
            assert_eq!(
                gate.classify(session_epoch, open, token2, || true),
                CompletionScope::CurrentDialog
            );
            guard2.release();
            assert!(!gate.is_busy_untracked());

            // Session epoch change expires the token completely (no stale same-session refresh).
            let (token3, guard3) = gate.begin(session_epoch);
            session_epoch.set(8);
            assert_eq!(
                gate.classify(session_epoch, open, token3, || true),
                CompletionScope::ExpiredSession
            );
            drop(guard3);
        });
    }

    #[test]
    fn dialog_gate_treats_disposed_owner_as_expired_session() {
        let owner = Owner::new();
        let (session_epoch, open, gate, token, guard) = owner.with(|| {
            let session_epoch = RwSignal::new(1u64);
            let open = RwSignal::new(true);
            let gate = DialogGate::new();
            let (token, guard) = gate.begin(session_epoch);
            (session_epoch, open, gate, token, guard)
        });
        owner.cleanup();
        assert_eq!(
            gate.classify(session_epoch, open, token, || true),
            CompletionScope::ExpiredSession
        );
        drop(guard);
    }
}
