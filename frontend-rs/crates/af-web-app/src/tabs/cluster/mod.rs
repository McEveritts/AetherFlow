//! Peer Clustering tab (`/?tab=cluster`): link list, pairing window, pairing flow,
//! comparison-code confirmation, endpoint editing, access grants, media storage, distributed
//! Jellyfin transcoding, and link revocation.

pub mod grants;
pub mod pairing;
pub mod peers;
pub mod storage;
pub mod transcode;

use crate::state::{app, owned_resource_reads, run_resource_read, AppContext, ResourceReads};
use crate::tabs::busy::BusyGuard;
use crate::tabs::l10n::{tt, tt_with, EmptyState};
use af_web_core::api::{
    api_url_for_server, clear_csrf_token, cookie_value, current_auth_epoch, ensure_same_auth_epoch,
    is_csrf_rejection, percent_encode_header_component, ApiClient, ApiError, API_ACCEPT,
    API_VERSION,
};
use af_web_core::i18n::{translate, translate_with};
use leptos::prelude::*;
use pairing::{
    reconcile_initiated_pairing, reconcile_opened_window, ActivePairingWindowsCard,
    InitiatedPairingCard, OpenPairingWindowModal, OpenPairingWindowResponse, PendingAttemptsPanel,
    ReconcileInitiated, ReconcileWindow, StartPairingModal, StartPairingResponse,
};
use peers::{is_unlinked_empty_state, PeerListSection, PeersSnapshot};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use serde_json::Value;
use transcode::TranscodeSection;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{spawn_local, JsFuture};

pub const PEERS_LIST_PATH: &str = "/api/v1/admin/peers";
pub const PAIRING_WINDOW_PATH: &str = "/api/v1/admin/peers/pairing-window";
pub const PAIR_START_PATH: &str = "/api/v1/admin/peers/pair";
pub const PEER_TRANSCODE_PATH: &str = "/api/v1/admin/peers/transcode";
pub const LOCAL_JELLYFIN_PACKAGE_UPDATE_PATH: &str = "/api/v1/admin/packages/jellyfin/update";

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

pub fn peer_grant_path(link_id: &str) -> String {
    format!(
        "/api/v1/admin/peers/{}/grant",
        percent_encode_header_component(link_id)
    )
}

pub fn peer_grant_offer_path(link_id: &str) -> String {
    format!(
        "/api/v1/admin/peers/{}/grant-offer",
        percent_encode_header_component(link_id)
    )
}

pub fn peer_exports_path(link_id: &str) -> String {
    format!(
        "/api/v1/admin/peers/{}/exports",
        percent_encode_header_component(link_id)
    )
}

pub fn peer_mounts_path(link_id: &str) -> String {
    format!(
        "/api/v1/admin/peers/{}/mounts",
        percent_encode_header_component(link_id)
    )
}

pub fn local_fs_browse_path(dir: &str) -> String {
    format!(
        "/api/v1/auth/fs?path={}",
        percent_encode_header_component(dir)
    )
}

/// Builds the Jellyfin package update endpoint for `Update to match`:
/// - `None`: local server `POST /api/v1/admin/packages/jellyfin/update`
/// - `Some(link_id)`: proxied peer `POST /api/v1/peers/{encoded_link_id}/admin/packages/jellyfin/update`
pub fn peer_package_update_path(link_id: Option<&str>) -> String {
    match link_id {
        Some(id) => format!(
            "/api/v1/peers/{}/admin/packages/jellyfin/update",
            percent_encode_header_component(id.trim())
        ),
        None => LOCAL_JELLYFIN_PACKAGE_UPDATE_PATH.to_string(),
    }
}

const MAX_REQUEST_ID_CHARS: usize = 128;

pub(super) fn sanitize_request_id(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_REQUEST_ID_CHARS)
        .collect();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn deserialize_sanitized_request_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    Ok(raw.as_deref().and_then(sanitize_request_id))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PeerApiErrorDetail {
    status: u16,
    code: Option<String>,
    server: Option<String>,
    step: Option<String>,
    message: String,
    action: Option<String>,
    #[serde(default, deserialize_with = "deserialize_sanitized_request_id")]
    request_id: Option<String>,
}

/// Pre-formatted lines rendered by [`PeerErrorAlert`] for a given locale.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerErrorBannerContent {
    pub message: String,
    pub next_step_label: Option<String>,
    pub action: Option<String>,
    pub metadata: Option<String>,
    pub request_id_line: Option<String>,
}

/// Structured peer API error preserving backend `{code, server, step, message, action, request_id}`
/// fields and HTTP `X-Request-ID` correlation metadata.
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
        request_id: Option<String>,
    ) -> Self {
        let request_id = request_id.as_deref().and_then(sanitize_request_id);
        Self(Box::new(PeerApiErrorDetail {
            status,
            code,
            server,
            step,
            message,
            action,
            request_id,
        }))
    }

    pub fn client(message: impl Into<String>) -> Self {
        Self::from_parts(0, None, None, None, message.into(), None, None)
    }

    pub(super) fn from_envelope(
        status: u16,
        code: Option<String>,
        server: Option<String>,
        step: Option<String>,
        message: String,
        action: Option<String>,
        request_id: Option<String>,
    ) -> Self {
        Self::from_parts(status, code, server, step, message, action, request_id)
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

    pub fn request_id(&self) -> Option<&str> {
        self.0
            .request_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
    }

    fn metadata_summary(&self, locale: &str) -> Option<String> {
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

    pub fn request_id_summary(&self, locale: &str) -> Option<String> {
        self.request_id()
            .map(|id| translate_with(locale, "Cluster.errorRequestId", &[("id", id)]))
    }

    pub fn context_summary(&self, locale: &str) -> Option<String> {
        match (
            self.metadata_summary(locale),
            self.request_id_summary(locale),
        ) {
            (Some(meta), Some(rid)) => Some(format!("{meta} · {rid}")),
            (Some(meta), None) => Some(meta),
            (None, Some(rid)) => Some(rid),
            (None, None) => None,
        }
    }

    pub fn banner_content(&self, locale: &str) -> PeerErrorBannerContent {
        let action = self.action().map(str::to_string);
        let next_step_label = action
            .as_ref()
            .map(|_| translate(locale, "Cluster.errorNextStep"));
        PeerErrorBannerContent {
            message: self.message().to_string(),
            next_step_label,
            action,
            metadata: self.metadata_summary(locale),
            request_id_line: self.request_id_summary(locale),
        }
    }
}

impl From<ApiError> for PeerApiError {
    fn from(error: ApiError) -> Self {
        Self::from_parts(
            error.status,
            error.code,
            None,
            None,
            error.message,
            None,
            None,
        )
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

fn response_request_id(headers: &web_sys::Headers) -> Option<String> {
    headers
        .get("X-Request-ID")
        .ok()
        .flatten()
        .as_deref()
        .and_then(sanitize_request_id)
}

/// Decodes a raw peer API response, preserving typed backend error `action`, `server`, `step`,
/// `code`, `message`, and `request_id` fields (falling back to the HTTP `X-Request-ID` response
/// header when the JSON body omits `request_id`) when the HTTP status is non-success or decoding
/// fails.
pub fn parse_peer_api_response_with_request_id<T: DeserializeOwned>(
    status: u16,
    ok: bool,
    body_text: &str,
    header_request_id: Option<&str>,
) -> Result<T, PeerApiError> {
    let fallback_request_id = header_request_id.and_then(sanitize_request_id);
    let trimmed = body_text.trim();
    if !ok {
        if let Ok(json) = serde_json::from_str::<Value>(trimmed) {
            let message = non_empty_field(&json, "message")
                .or_else(|| non_empty_field(&json, "error"))
                .unwrap_or_else(|| format!("Request failed (HTTP {status})"));
            let request_id = non_empty_field(&json, "request_id")
                .as_deref()
                .and_then(sanitize_request_id)
                .or(fallback_request_id);
            return Err(PeerApiError::from_parts(
                status,
                non_empty_field(&json, "code"),
                non_empty_field(&json, "server"),
                non_empty_field(&json, "step"),
                message,
                non_empty_field(&json, "action"),
                request_id,
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
            fallback_request_id,
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
                fallback_request_id,
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
            fallback_request_id,
        )
    })
}

/// Decodes a raw peer API response without an external `X-Request-ID` header fallback.
pub fn parse_peer_api_response<T: DeserializeOwned>(
    status: u16,
    ok: bool,
    body_text: &str,
) -> Result<T, PeerApiError> {
    parse_peer_api_response_with_request_id(status, ok, body_text, None)
}

/// Sends an authenticated local same-origin request to `/api/v1/admin/peers*` via `ApiClient.fetch`,
/// returning both the parsed payload and any sanitized `X-Request-ID` response header.
pub(super) async fn peer_api_request_with_request_id<T: DeserializeOwned>(
    path: &str,
    method: &str,
    body: Option<&Value>,
) -> Result<(T, Option<String>), PeerApiError> {
    let response = ApiClient
        .fetch(path, method, body)
        .await
        .map_err(PeerApiError::from)?;
    let status = response.status();
    let ok = response.ok();
    let header_request_id = response_request_id(&response.headers());
    let text = response.text().await.map_err(PeerApiError::from)?;
    let value =
        parse_peer_api_response_with_request_id(status, ok, &text, header_request_id.as_deref())?;
    Ok((value, header_request_id))
}

/// Sends an authenticated local same-origin request to `/api/v1/admin/peers*` via `ApiClient.fetch`
/// (preserving session refresh, CSRF token handling, and typed `PeerError` bodies).
pub async fn peer_api_request<T: DeserializeOwned>(
    path: &str,
    method: &str,
    body: Option<&Value>,
) -> Result<T, PeerApiError> {
    peer_api_request_with_request_id(path, method, body)
        .await
        .map(|(value, _)| value)
}

/// Sends a strictly local same-origin GET request (bypassing peer proxy rewriting even while a
/// remote server is selected in the dashboard switcher) for browsing local export directories.
/// If the access cookie needs rotation (HTTP 401), refreshes once via local `/api/v1/admin/peers`.
pub async fn local_same_origin_get<T: DeserializeOwned>(path: &str) -> Result<T, PeerApiError> {
    let response = ApiClient
        .public_fetch(path, "GET", None)
        .await
        .map_err(PeerApiError::from)?;
    let status = response.status();
    let ok = response.ok();
    let header_request_id = response_request_id(&response.headers());
    let text = response.text().await.map_err(PeerApiError::from)?;
    if status == 401
        && ApiClient
            .fetch(PEERS_LIST_PATH, "GET", None)
            .await
            .is_ok_and(|res| res.ok())
    {
        let retried = ApiClient
            .public_fetch(path, "GET", None)
            .await
            .map_err(PeerApiError::from)?;
        let retry_status = retried.status();
        let retry_ok = retried.ok();
        let retry_request_id = response_request_id(&retried.headers());
        let retry_text = retried.text().await.map_err(PeerApiError::from)?;
        return parse_peer_api_response_with_request_id(
            retry_status,
            retry_ok,
            &retry_text,
            retry_request_id.as_deref(),
        );
    }
    parse_peer_api_response_with_request_id(status, ok, &text, header_request_id.as_deref())
}

fn read_local_csrf_cookie() -> Option<String> {
    let cookies = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.dyn_into::<web_sys::HtmlDocument>().ok())
        .and_then(|d| d.cookie().ok())
        .unwrap_or_default();
    cookie_value(&cookies, "csrf_token").filter(|s| !s.is_empty())
}

async fn fetch_local_csrf_token(force_refresh: bool) -> Result<String, PeerApiError> {
    if !force_refresh {
        if let Some(token) = read_local_csrf_cookie() {
            return Ok(token);
        }
    }
    let response = ApiClient
        .public_fetch("/api/v1/public/csrf-token", "GET", None)
        .await
        .map_err(PeerApiError::from)?;
    let text = response.text().await.map_err(PeerApiError::from)?;
    if let Ok(json) = serde_json::from_str::<Value>(text.trim()) {
        if let Some(token) = json["csrf_token"].as_str().filter(|s| !s.is_empty()) {
            return Ok(token.to_string());
        }
    }
    read_local_csrf_cookie().ok_or_else(|| PeerApiError::client("CSRF token unavailable"))
}

struct LocalPostResponse {
    status: u16,
    ok: bool,
    text: String,
    request_id: Option<String>,
}

async fn send_local_post_once(
    path: &str,
    body_json: Option<&str>,
    csrf: &str,
) -> Result<LocalPostResponse, PeerApiError> {
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    init.set_credentials(web_sys::RequestCredentials::Include);
    init.set_cache(web_sys::RequestCache::NoStore);
    let headers = web_sys::Headers::new()
        .map_err(|_| PeerApiError::client("Failed to prepare request headers"))?;
    for (key, value) in [
        ("X-API-Version", API_VERSION),
        ("Accept", API_ACCEPT),
        ("X-Requested-With", "XMLHttpRequest"),
        ("Cache-Control", "no-store"),
        ("X-CSRF-Token", csrf),
    ] {
        headers
            .set(key, value)
            .map_err(|_| PeerApiError::client("Failed to set request header"))?;
    }
    if let Some(payload) = body_json {
        headers
            .set("Content-Type", "application/json")
            .map_err(|_| PeerApiError::client("Failed to set Content-Type header"))?;
        init.set_body(&JsValue::from_str(payload));
    }
    init.set_headers(&headers);
    let window =
        web_sys::window().ok_or_else(|| PeerApiError::client("Browser window unavailable"))?;
    let response_js = JsFuture::from(window.fetch_with_str_and_init(path, &init))
        .await
        .map_err(|err| {
            PeerApiError::client(
                err.as_string()
                    .unwrap_or_else(|| "Network request failed".to_string()),
            )
        })?;
    let response: web_sys::Response = response_js
        .dyn_into()
        .map_err(|_| PeerApiError::client("Invalid browser response"))?;
    let status = response.status();
    let ok = response.ok();
    let request_id = response_request_id(&response.headers());
    let text_promise = response
        .text()
        .map_err(|_| PeerApiError::client("Failed to read response body"))?;
    let text = JsFuture::from(text_promise)
        .await
        .map_err(|_| PeerApiError::client("Failed to decode response body"))?
        .as_string()
        .unwrap_or_default();
    Ok(LocalPostResponse {
        status,
        ok,
        text,
        request_id,
    })
}

/// Sends a strictly local same-origin authenticated POST with `X-CSRF-Token` attached
/// (bypassing peer proxy rewriting even while a remote peer is selected in the dashboard
/// switcher), supporting single session refresh on 401 and CSRF retry on 403.
pub async fn local_same_origin_post<T: DeserializeOwned>(
    path: &str,
    body: Option<&Value>,
) -> Result<T, PeerApiError> {
    if api_url_for_server(None, path) != path {
        return Err(PeerApiError::client("API path must be local"));
    }
    let origin_epoch = current_auth_epoch();
    let body_json = body.map(Value::to_string);
    let mut csrf = fetch_local_csrf_token(false).await?;
    ensure_same_auth_epoch(origin_epoch, current_auth_epoch()).map_err(PeerApiError::from)?;

    let mut refreshed = false;
    let mut csrf_retried = false;
    let mut resp = send_local_post_once(path, body_json.as_deref(), &csrf).await?;
    ensure_same_auth_epoch(origin_epoch, current_auth_epoch()).map_err(PeerApiError::from)?;

    loop {
        if resp.status == 401 && !refreshed {
            refreshed = true;
            if !ApiClient
                .fetch(PEERS_LIST_PATH, "GET", None)
                .await
                .is_ok_and(|res| res.ok())
            {
                break;
            }
            ensure_same_auth_epoch(origin_epoch, current_auth_epoch())
                .map_err(PeerApiError::from)?;
            clear_csrf_token();
            csrf = fetch_local_csrf_token(true).await?;
            ensure_same_auth_epoch(origin_epoch, current_auth_epoch())
                .map_err(PeerApiError::from)?;
            resp = send_local_post_once(path, body_json.as_deref(), &csrf).await?;
            ensure_same_auth_epoch(origin_epoch, current_auth_epoch())
                .map_err(PeerApiError::from)?;
            continue;
        }
        if resp.status == 403
            && !csrf_retried
            && serde_json::from_str::<Value>(resp.text.trim())
                .is_ok_and(|json| is_csrf_rejection(403, &json))
        {
            csrf_retried = true;
            clear_csrf_token();
            csrf = fetch_local_csrf_token(true).await?;
            ensure_same_auth_epoch(origin_epoch, current_auth_epoch())
                .map_err(PeerApiError::from)?;
            resp = send_local_post_once(path, body_json.as_deref(), &csrf).await?;
            ensure_same_auth_epoch(origin_epoch, current_auth_epoch())
                .map_err(PeerApiError::from)?;
            continue;
        }
        break;
    }

    parse_peer_api_response_with_request_id(
        resp.status,
        resp.ok,
        &resp.text,
        resp.request_id.as_deref(),
    )
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

    /// Captures the current session epoch and dialog generation without altering busy state.
    pub(super) fn current_token(self, session_epoch: RwSignal<u64>) -> MutationToken {
        MutationToken {
            session_epoch: session_epoch.get_untracked(),
            generation: self.generation.get_untracked(),
        }
    }

    /// Marks the current dialog generation busy and binds a generation-checked `BusyGuard`.
    pub(super) fn begin(self, session_epoch: RwSignal<u64>) -> (MutationToken, BusyGuard) {
        let token = self.current_token(session_epoch);
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
                    let content = err.banner_content(&locale);
                    let action_row = content.next_step_label.zip(content.action);
                    view! {
                        <div
                            role="alert"
                            class="af-danger-banner space-y-1.5"
                        >
                            <div class="flex items-start justify-between gap-3">
                                <p class="font-medium break-words">{content.message}</p>
                                {on_dismiss.map(|dismiss| {
                                    view! {
                                        <button
                                            type="button"
                                            class="af-btn px-2.5 py-1 text-xs shrink-0"
                                            aria-label=move || tt(context, "Cluster.dismissError")
                                            on:click=move |_| dismiss.run(())
                                        >
                                            "×"
                                        </button>
                                    }
                                })}
                            </div>
                            {action_row.map(|(label, next_step)| {
                                view! {
                                    <p class="text-slate-200 break-words">
                                        <span class="font-semibold text-amber-300">
                                            {label}
                                        </span>
                                        ": "
                                        {next_step}
                                    </p>
                                }
                            })}
                            {content.metadata.map(|context_line| {
                                view! {
                                    <p class="text-xs font-mono text-slate-400 break-all">
                                        {context_line}
                                    </p>
                                }
                            })}
                            {content.request_id_line.map(|rid_line| {
                                view! {
                                    <p
                                        data-testid="peer-error-request-id"
                                        class="text-xs font-mono text-slate-400 break-all"
                                    >
                                        {rid_line}
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
                    context.apply_peers_snapshot(data.clone());
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
            <header class="af-canvas-section pb-5 space-y-4">
                <div class="flex flex-wrap justify-between items-start gap-4">
                    <div class="space-y-1.5 min-w-0">
                        <h2 class="text-lg font-semibold">
                            {move || tt(context, "Tabs.clusterHeading")}
                        </h2>
                        <Show when=move || context.is_remote()>
                            <p
                                role="note"
                                data-testid="cluster-local-scope-note"
                                class="text-xs text-cyan-200 bg-cyan-500/10 border border-cyan-500/30 rounded-lg px-3 py-1.5"
                            >
                                {move || tt(context, "PeerSwitch.clusterLocalNote")}
                            </p>
                        </Show>
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
                            class="af-btn px-4 py-2"
                            disabled=move || loading.get()
                            aria-label=move || tt(context, "Cluster.refreshPeers")
                            on:click=move |_| trigger_refresh.run(())
                        >
                            {move || tt(context, "Common.refresh")}
                        </button>
                        <button
                            type="button"
                            class="af-btn px-4 py-2"
                            on:click=move |_| allow_modal_open.set(true)
                        >
                            {move || tt(context, "Cluster.allowServerAction")}
                        </button>
                        <button
                            type="button"
                            class="af-btn-primary px-4 py-2"
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
                                class="af-btn px-3 py-2 text-sm"
                                on:click=move |_| trigger_refresh.run(())
                            >
                                {move || tt(context, "Common.retry")}
                            </button>
                        </div>
                    </div>
                </Show>
            </header>

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

            <TranscodeSection
                peers=peers_list.into()
                parent_revision=revision
                on_refresh_peers=trigger_refresh
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
        let peer_grant = peer_grant_path("link-42");
        let peer_grant_encoded = peer_grant_path("link 42/a");
        let peer_grant_offer = peer_grant_offer_path("link-42");
        let peer_exports = peer_exports_path("link-42");
        let peer_exports_encoded = peer_exports_path("link 42/a");
        let peer_mounts = peer_mounts_path("link-42");
        let peer_mounts_encoded = peer_mounts_path("link 42/a");
        let fs_browse = local_fs_browse_path("/srv/media/movies");
        let peer_transcode = PEER_TRANSCODE_PATH.to_string();
        let pkg_update_local = peer_package_update_path(None);
        let pkg_update_peer = peer_package_update_path(Some("link-42"));
        let pkg_update_peer_encoded = peer_package_update_path(Some("link 42/a"));

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
        assert_eq!(peer_grant, "/api/v1/admin/peers/link-42/grant");
        assert_eq!(
            peer_grant_encoded,
            "/api/v1/admin/peers/link%2042%2Fa/grant"
        );
        assert_eq!(peer_grant_offer, "/api/v1/admin/peers/link-42/grant-offer");
        assert_eq!(peer_exports, "/api/v1/admin/peers/link-42/exports");
        assert_eq!(
            peer_exports_encoded,
            "/api/v1/admin/peers/link%2042%2Fa/exports"
        );
        assert_eq!(peer_mounts, "/api/v1/admin/peers/link-42/mounts");
        assert_eq!(
            peer_mounts_encoded,
            "/api/v1/admin/peers/link%2042%2Fa/mounts"
        );
        assert_eq!(fs_browse, "/api/v1/auth/fs?path=%2Fsrv%2Fmedia%2Fmovies");
        assert_eq!(peer_transcode, "/api/v1/admin/peers/transcode");
        assert_eq!(pkg_update_local, "/api/v1/admin/packages/jellyfin/update");
        assert_eq!(
            pkg_update_peer,
            "/api/v1/peers/link-42/admin/packages/jellyfin/update"
        );
        assert_eq!(
            pkg_update_peer_encoded,
            "/api/v1/peers/link%2042%2Fa/admin/packages/jellyfin/update"
        );

        // Even while a remote peer server is active, all peer-clustering management controls
        // and explicit peer-prefixed package alignment paths MUST keep their exact target.
        for route in [
            &list,
            &open_window,
            &close_window,
            &start_pair,
            &confirm_attempt,
            &cancel_attempt,
            &update_endpoint,
            &revoke_link,
            &peer_grant,
            &peer_grant_offer,
            &peer_exports,
            &peer_mounts,
            &peer_transcode,
            &pkg_update_peer,
            &pkg_update_peer_encoded,
        ] {
            assert_eq!(
                api_url(route),
                *route,
                "route drifted off expected target: {route}"
            );
        }
        // Local package alignment validates strictly on local origin without peer prefixing.
        assert_eq!(
            api_url_for_server(None, &pkg_update_local),
            pkg_update_local
        );

        // Read does not attach CSRF; all state-changing admin peer and package align routes do.
        assert!(!should_attach_csrf("GET", &list, None));
        assert!(!should_attach_csrf("GET", &peer_grant, None));
        assert!(!should_attach_csrf("GET", &peer_exports, None));
        assert!(!should_attach_csrf("GET", &peer_mounts, None));
        assert!(!should_attach_csrf("GET", &peer_transcode, None));
        assert!(should_attach_csrf("POST", &open_window, None));
        assert!(should_attach_csrf("DELETE", &open_window, None));
        assert!(should_attach_csrf("DELETE", &close_window, None));
        assert!(should_attach_csrf("POST", &start_pair, None));
        assert!(should_attach_csrf("POST", &confirm_attempt, None));
        assert!(should_attach_csrf("DELETE", &cancel_attempt, None));
        assert!(should_attach_csrf("PUT", &update_endpoint, None));
        assert!(should_attach_csrf("DELETE", &revoke_link, None));
        assert!(should_attach_csrf("PUT", &peer_grant, None));
        assert!(should_attach_csrf("DELETE", &peer_grant, None));
        assert!(should_attach_csrf("POST", &peer_grant_offer, None));
        assert!(should_attach_csrf("POST", &peer_exports, None));
        assert!(should_attach_csrf("DELETE", &peer_exports, None));
        assert!(should_attach_csrf("POST", &peer_mounts, None));
        assert!(should_attach_csrf("DELETE", &peer_mounts, None));
        assert!(should_attach_csrf("PUT", &peer_transcode, None));
        assert!(should_attach_csrf("POST", &pkg_update_local, None));
        assert!(should_attach_csrf("POST", &pkg_update_peer, None));
        assert!(should_attach_csrf("POST", &pkg_update_peer_encoded, None));

        // 204 No Content empty responses parse cleanly as Value::Null for DELETE mutations.
        assert_eq!(
            parse_peer_api_response::<Value>(204, true, "").unwrap(),
            Value::Null
        );

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
        assert_eq!(empty.request_id(), None);
    }

    #[test]
    fn peer_error_extracts_request_id_from_body_and_falls_back_to_header() {
        // 1. Body request_id alone.
        let body_only = json!({
            "code": "PEER_INTERNAL_ERROR",
            "server": "media-2",
            "step": "confirm_pairing",
            "message": "Runner call failed",
            "action": "Inspect logs and retry",
            "request_id": "  req-body-123  "
        })
        .to_string();
        let err = parse_peer_api_response_with_request_id::<Value>(500, false, &body_only, None)
            .unwrap_err();
        assert_eq!(err.request_id(), Some("req-body-123"));
        assert_eq!(
            err.request_id_summary("en").as_deref(),
            Some("Request ID: req-body-123")
        );
        let ctx = err.context_summary("en").unwrap();
        assert!(ctx.contains("media-2"));
        assert!(ctx.contains("confirm_pairing"));
        assert!(ctx.contains("PEER_INTERNAL_ERROR"));
        assert!(ctx.contains("Request ID: req-body-123"));

        // 2. Header fallback when JSON body omits request_id.
        let no_body_rid = json!({
            "code": "LINK_DOWN",
            "server": "media-2",
            "step": "deliver_grant_token",
            "message": "Tunnel unreachable",
            "action": "Check UDP 51821"
        })
        .to_string();
        let err = parse_peer_api_response_with_request_id::<Value>(
            502,
            false,
            &no_body_rid,
            Some("  hdr-fallback-456  "),
        )
        .unwrap_err();
        assert_eq!(err.request_id(), Some("hdr-fallback-456"));

        // 3. Header fallback when JSON body has blank/whitespace request_id.
        let blank_body_rid = json!({
            "code": "LINK_DOWN",
            "message": "Tunnel unreachable",
            "request_id": "   \t\n  "
        })
        .to_string();
        let err = parse_peer_api_response_with_request_id::<Value>(
            502,
            false,
            &blank_body_rid,
            Some("hdr-fallback-789"),
        )
        .unwrap_err();
        assert_eq!(err.request_id(), Some("hdr-fallback-789"));

        // 4. Body request_id takes precedence over X-Request-ID header.
        let err = parse_peer_api_response_with_request_id::<Value>(
            500,
            false,
            &body_only,
            Some("hdr-ignored-999"),
        )
        .unwrap_err();
        assert_eq!(err.request_id(), Some("req-body-123"));

        // 5. Absent when both body and header omit or contain only whitespace/control chars.
        let err = parse_peer_api_response_with_request_id::<Value>(
            502,
            false,
            &no_body_rid,
            Some(" \r\n\t "),
        )
        .unwrap_err();
        assert_eq!(err.request_id(), None);
        assert_eq!(err.request_id_summary("en"), None);
        assert!(!err.context_summary("en").unwrap().contains("Request ID"));

        // 6. Non-JSON error bodies and decode failures preserve sanitized header X-Request-ID.
        let plain = parse_peer_api_response_with_request_id::<Value>(
            502,
            false,
            "",
            Some("req-plain\r\n-502"),
        )
        .unwrap_err();
        assert_eq!(plain.request_id(), Some("req-plain-502"));
        assert_eq!(
            plain.context_summary("en").as_deref(),
            Some("Request ID: req-plain-502")
        );

        let oversized = "x".repeat(200);
        let invalid_json = parse_peer_api_response_with_request_id::<Value>(
            200,
            true,
            "{not-json",
            Some(&oversized),
        )
        .unwrap_err();
        assert_eq!(
            invalid_json.request_id().map(str::len),
            Some(MAX_REQUEST_ID_CHARS)
        );

        // 7. Direct serde deserialization defaults missing request_id to None and sanitizes present values.
        let legacy: PeerApiError = serde_json::from_value(json!({
            "status": 410,
            "code": "CODE_EXPIRED",
            "server": "media-2",
            "step": "pair",
            "message": "Expired",
            "action": "Retry"
        }))
        .unwrap();
        assert_eq!(legacy.request_id(), None);

        let with_rid: PeerApiError = serde_json::from_value(json!({
            "status": 500,
            "code": "PEER_INTERNAL_ERROR",
            "server": "media-2",
            "step": "pair",
            "message": "Failed",
            "action": "Retry",
            "request_id": "  req-serde-42\n"
        }))
        .unwrap();
        assert_eq!(with_rid.request_id(), Some("req-serde-42"));
    }

    #[test]
    fn peer_error_alert_renders_request_id_across_locales_and_omits_when_absent() {
        let err_with_rid = parse_peer_api_response_with_request_id::<Value>(
            502,
            false,
            &json!({
                "code": "LINK_DOWN",
                "server": "media-2",
                "step": "confirm_pairing",
                "message": "Tunnel hello timed out",
                "action": "Check UDP 51821",
                "request_id": "req-render-42"
            })
            .to_string(),
            None,
        )
        .unwrap_err();

        for locale in ["en", "de", "dk", "es", "fr", "zh"] {
            let banner = err_with_rid.banner_content(locale);
            assert_eq!(banner.message, "Tunnel hello timed out");
            assert_eq!(banner.action.as_deref(), Some("Check UDP 51821"));
            let next_step_label = banner.next_step_label.as_deref().expect("next step label");
            assert_ne!(next_step_label, "Cluster.errorNextStep", "{locale}");
            let meta = banner.metadata.as_deref().expect("metadata summary");
            assert!(meta.contains("media-2"), "{locale}: {meta}");
            assert!(meta.contains("confirm_pairing"), "{locale}: {meta}");
            assert!(meta.contains("LINK_DOWN"), "{locale}: {meta}");
            assert!(
                !meta.contains("req-render-42"),
                "banner metadata line must not duplicate request_id: {locale}: {meta}"
            );
            let rid_line = banner
                .request_id_line
                .as_deref()
                .expect("request_id banner line");
            assert!(rid_line.contains("req-render-42"), "{locale}: {rid_line}");
            assert!(!rid_line.contains("Cluster.errorRequestId"), "{locale}");

            let summary = err_with_rid
                .context_summary(locale)
                .expect("context summary");
            assert!(summary.contains("media-2"), "{locale}: {summary}");
            assert!(summary.contains("req-render-42"), "{locale}: {summary}");
        }

        // Generic error with header-only request_id renders request_id line even without server/step/code.
        let header_only_err = parse_peer_api_response_with_request_id::<Value>(
            500,
            false,
            r#"{"error":"Runner offline"}"#,
            Some("req-hdr-only-7"),
        )
        .unwrap_err();
        let hdr_banner = header_only_err.banner_content("en");
        assert_eq!(hdr_banner.message, "Runner offline");
        assert_eq!(hdr_banner.action, None);
        assert_eq!(hdr_banner.next_step_label, None);
        assert_eq!(hdr_banner.metadata, None);
        assert_eq!(
            hdr_banner.request_id_line.as_deref(),
            Some("Request ID: req-hdr-only-7")
        );

        // Error without request_id omits request_id_line cleanly.
        let no_rid_err = PeerApiError::client("Local validation error");
        let no_rid_banner = no_rid_err.banner_content("en");
        assert_eq!(no_rid_banner.message, "Local validation error");
        assert_eq!(no_rid_banner.metadata, None);
        assert_eq!(no_rid_banner.request_id_line, None);

        // Reactive locale switches in AppContext update the banner request_id line dynamically.
        Owner::new().with(|| {
            let context = AppContext::new();
            let current_en = err_with_rid.banner_content(&context.locale.get_untracked());
            assert_eq!(
                current_en.request_id_line.as_deref(),
                Some("Request ID: req-render-42")
            );
            context.locale.set("de".into());
            let current_de = err_with_rid.banner_content(&context.locale.get_untracked());
            assert_eq!(
                current_de.request_id_line.as_deref(),
                Some("Anfrage-ID: req-render-42")
            );
            context.locale.set("fr".into());
            let current_fr = err_with_rid.banner_content(&context.locale.get_untracked());
            assert_eq!(
                current_fr.request_id_line.as_deref(),
                Some("ID de requête\u{00a0}: req-render-42")
            );
            context.locale.set("zh".into());
            let current_zh = err_with_rid.banner_content(&context.locale.get_untracked());
            assert_eq!(
                current_zh.request_id_line.as_deref(),
                Some("请求 ID：req-render-42")
            );
        });
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
