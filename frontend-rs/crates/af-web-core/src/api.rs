use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

thread_local! {
    static ACTIVE_SERVER: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn normalize_active_server(server: Option<String>) -> Option<String> {
    let trimmed = server?.trim().to_string();
    if trimmed.is_empty() || matches!(trimmed.as_str(), "." | "..") {
        return None;
    }
    Some(trimmed)
}

pub fn set_active_server(server: Option<String>) {
    let normalized = normalize_active_server(server);
    let changed = ACTIVE_SERVER.with(|slot| {
        let mut guard = slot.borrow_mut();
        if *guard == normalized {
            false
        } else {
            *guard = normalized;
            true
        }
    });
    if changed {
        bump_server_epoch_and_abort();
    }
}

pub fn active_server() -> Option<String> {
    ACTIVE_SERVER.with(|slot| slot.borrow().clone())
}

pub fn peer_proxy_id(input: &str) -> Option<String> {
    let path = request_path(input);
    let rest = path.strip_prefix("/api/v1/peers/")?;
    let (id, suffix) = rest.split_once('/')?;
    if id.is_empty() || suffix.is_empty() {
        return None;
    }
    let decoded = percent_decode_str(id).decode_utf8().ok()?;
    let trimmed = decoded.trim();
    if trimmed.is_empty() || matches!(trimmed, "." | "..") {
        return None;
    }
    Some(trimmed.to_string())
}

pub fn is_peer_proxy_path(input: &str) -> bool {
    peer_proxy_id(input).is_some()
}

pub fn is_server_scoped_path(input: &str) -> bool {
    let path = request_path(input);
    let Some(rest) = path.strip_prefix("/api/v1/") else {
        return false;
    };
    if rest.is_empty()
        || rest == "admin/peers"
        || rest.starts_with("admin/peers/")
        || is_dashboard_auth_path(rest)
    {
        return false;
    }
    true
}

fn is_dashboard_auth_path(path: &str) -> bool {
    matches!(
        path,
        "auth/session"
            | "auth/logout"
            | "auth/refresh"
            | "auth/login"
            | "auth/mfa/verify"
            | "auth/setup"
            | "auth/setup/check"
            | "auth/profile/password"
            | "csrf-token"
            | "public/csrf-token"
    ) || [
        "auth/google",
        "auth/oidc",
        "auth/sessions",
        "auth/user/2fa",
        "oidc",
        "peer-pairing",
        "public/auth",
    ]
    .into_iter()
    .any(|prefix| {
        path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

pub fn api_url(path: &str) -> String {
    api_url_for_server(active_server().as_deref(), path)
}

pub fn api_url_for_server(server: Option<&str>, path: &str) -> String {
    if path.starts_with('/') && validate_local_api_path(path).is_err() {
        return "#".to_string();
    }
    rewrite_api_path_for_server(server, path)
}

fn rewrite_api_path(path: &str) -> String {
    rewrite_api_path_for_server(active_server().as_deref(), path)
}

fn rewrite_api_path_for_server(server: Option<&str>, path: &str) -> String {
    let Some(server) = server.map(str::trim).filter(|value| !value.is_empty()) else {
        return path.to_string();
    };
    let Some(rest) = path.strip_prefix("/api/v1/") else {
        return path.to_string();
    };
    let rest_path = rest.split(['?', '#']).next().unwrap_or("");
    if rest_path.is_empty()
        || rest_path == "peers"
        || rest_path.starts_with("peers/")
        || rest_path == "admin/peers"
        || rest_path.starts_with("admin/peers/")
        || is_dashboard_auth_path(rest_path)
    {
        return path.to_string();
    }
    let encoded_server = percent_encode_header_component(server);
    format!("/api/v1/peers/{encoded_server}/{rest}")
}

static AUTH_EPOCH: AtomicU64 = AtomicU64::new(0);
static SERVER_EPOCH: AtomicU64 = AtomicU64::new(0);
static AUTH_REVALIDATING: AtomicBool = AtomicBool::new(false);

pub fn current_auth_epoch() -> u64 {
    AUTH_EPOCH.load(Ordering::SeqCst)
}

pub fn current_server_epoch() -> u64 {
    SERVER_EPOCH.load(Ordering::SeqCst)
}

pub fn bump_server_epoch_and_abort() -> u64 {
    let epoch = SERVER_EPOCH.fetch_add(1, Ordering::SeqCst) + 1;
    #[cfg(target_arch = "wasm32")]
    browser::abort_server_scoped_controllers();
    epoch
}

pub fn ensure_same_server_epoch(origin_epoch: u64, current_epoch: u64) -> Result<(), ApiError> {
    if origin_epoch != current_epoch {
        return Err(ApiError {
            status: 0,
            code: Some("SERVER_CHANGED".into()),
            message: "Server changed; request cancelled".into(),
        });
    }
    Ok(())
}

pub fn bump_auth_epoch_and_abort() -> u64 {
    let epoch = AUTH_EPOCH.fetch_add(1, Ordering::SeqCst) + 1;
    clear_csrf_token();
    browser::clear_cached_refresh();
    #[cfg(target_arch = "wasm32")]
    browser::abort_active_controllers();
    epoch
}

/// Block account-owned requests before invalidating the previous session.
pub fn suspend_for_auth_revalidation() {
    AUTH_REVALIDATING.store(true, Ordering::SeqCst);
    bump_auth_epoch_and_abort();
}

pub fn auth_revalidation_pending() -> bool {
    AUTH_REVALIDATING.load(Ordering::SeqCst)
}

/// A stale session probe must never reopen the request gate.
pub fn resume_after_auth_revalidation(origin_epoch: u64) -> bool {
    if current_auth_epoch() != origin_epoch {
        return false;
    }
    AUTH_REVALIDATING.store(false, Ordering::SeqCst);
    true
}

fn allowed_during_auth_revalidation(path: &str, method: &str) -> bool {
    (method.eq_ignore_ascii_case("GET") && request_path(path) == "/api/v1/auth/session")
        || is_login_endpoint(path)
}

fn ensure_auth_request_allowed(path: &str, method: &str) -> Result<(), ApiError> {
    if auth_revalidation_pending() && !allowed_during_auth_revalidation(path, method) {
        return Err(ApiError {
            status: 401,
            code: Some("SESSION_CHANGED".into()),
            message: "Session changed; request cancelled".into(),
        });
    }
    Ok(())
}

pub fn ensure_same_auth_epoch(origin_epoch: u64, current_epoch: u64) -> Result<(), ApiError> {
    if origin_epoch != current_epoch {
        return Err(ApiError {
            status: 401,
            code: Some("SESSION_CHANGED".into()),
            message: "Session changed; request cancelled".into(),
        });
    }
    Ok(())
}

pub const API_VERSION: &str = "v1";
pub const API_ACCEPT: &str = "application/vnd.aetherflow.v1+json";
pub const SESSION_EXPIRED_EVENT: &str = "af:session-expired";
pub const LOGOUT_SYNC: &str = "af_logout_sync";
pub const LOGIN_SYNC: &str = "af_login_sync";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
    pub code: Option<String>,
}
impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for ApiError {}

pub const BODY_LIMIT_EXCEEDED: &str = "BODY_LIMIT_EXCEEDED";

fn declared_body_too_large(length: Option<&str>, max_bytes: u32) -> bool {
    length.map(str::trim).is_some_and(|length| {
        !length.is_empty()
            && length.bytes().all(|byte| byte.is_ascii_digit())
            && !matches!(length.parse::<u64>(), Ok(length) if length <= u64::from(max_bytes))
    })
}

fn body_limit_error() -> ApiError {
    ApiError {
        status: 0,
        message: "Response body exceeds the byte limit".into(),
        code: Some(BODY_LIMIT_EXCEEDED.into()),
    }
}

fn remaining_body_bytes(remaining: u32, received: u32) -> Result<u32, ApiError> {
    remaining.checked_sub(received).ok_or_else(body_limit_error)
}

/// Forget the cached token after authentication changes rotate the CSRF cookie.
pub fn clear_csrf_token() {
    browser::clear_cached_csrf_token();
}

/// Encode a UTF-8 header component using RFC 3986's unreserved character set.
pub fn percent_encode_header_component(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 15) as usize] as char);
        }
    }
    encoded
}

fn validate_header_ascii(value: &str) -> Result<(), ApiError> {
    if value.is_ascii() {
        Ok(())
    } else {
        Err(ApiError {
            status: 0,
            message: "Header components must be ASCII; percent-encode UTF-8 values".into(),
            code: Some("INVALID_HEADER_VALUE".into()),
        })
    }
}

fn validate_local_api_path(path: &str) -> Result<(), ApiError> {
    let route = path.split(['?', '#']).next().unwrap_or_default();
    // The browser strips some controls and normalizes dot segments before sending a request.
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.bytes().any(|b| b.is_ascii_control() || b == b'\\')
        || (route.starts_with("/api/v1/") && route.contains("//"))
        || route.split('/').any(|segment| {
            [".", "..", "%2e", ".%2e", "%2e.", "%2e%2e"]
                .iter()
                .any(|dot| segment.eq_ignore_ascii_case(dot))
        })
    {
        return Err(ApiError {
            status: 0,
            message: "API path must be local".into(),
            code: None,
        });
    }
    Ok(())
}

fn prepare_api_request_path(path: &str, method: &str) -> Result<String, ApiError> {
    validate_local_api_path(path)?;
    let resolved = rewrite_api_path(path);
    ensure_auth_request_allowed(&resolved, method)?;
    Ok(resolved)
}

fn is_valid_peer_segment(segment: &str) -> bool {
    if segment.is_empty()
        || segment
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace() || b == b'\\')
    {
        return false;
    }
    let Ok(decoded) = percent_decode_str(segment).decode_utf8() else {
        return false;
    };
    !decoded.is_empty() && !matches!(decoded.as_ref(), "." | "..")
}

fn peer_prefixed_api_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/api/v1/peers/")?;
    let (peer_id, leaf) = rest.split_once('/')?;
    if !is_valid_peer_segment(peer_id) || leaf.is_empty() || leaf.starts_with('/') {
        return None;
    }
    Some(format!("/api/v1/{leaf}"))
}

pub fn request_path(input: &str) -> String {
    if input.starts_with("https://") || input.starts_with("http://") {
        url::Url::parse(input)
            .map(|url| url.path().to_string())
            .unwrap_or_default()
    } else {
        input.split(['?', '#']).next().unwrap_or("").to_string()
    }
}
pub fn should_attach_csrf(method: &str, input: &str, authorization: Option<&str>) -> bool {
    if matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    ) || authorization.is_some_and(|a| a.starts_with("Bearer "))
    {
        return false;
    }
    let path = request_path(input);
    let peer_leaf = peer_prefixed_api_path(&path);
    let effective_path = peer_leaf.as_deref().unwrap_or(path.as_str());
    if matches!(
        path.as_str(),
        "/api/v1/auth/refresh" | "/api/v1/public/auth/refresh" | "/api/auth/refresh"
    ) {
        return false;
    }
    [
        "/api/v1/auth/",
        "/api/v1/public/auth/",
        "/api/auth/",
        "/api/v1/admin/",
        "/api/admin/",
        "/api/v1/ingress/",
        "/api/ingress/",
        "/plugins/",
        "/api/v1/mcbrowser/",
        "/api/v1/fileshare/",
        "/api/v1/oauth/",
        "/api/v1/share/",
    ]
    .iter()
    .any(|prefix| effective_path.starts_with(prefix))
}
pub fn is_login_endpoint(input: &str) -> bool {
    let path = request_path(input);
    [
        "/api/v1/auth/login",
        "/api/v1/public/auth/login",
        "/api/v1/public/auth/mfa",
        "/api/v1/public/auth/setup",
    ]
    .iter()
    .any(|p| path.starts_with(p))
}
pub fn should_refresh_on_401(input: &str) -> bool {
    let path = request_path(input);
    !is_login_endpoint(&path)
        && ![
            "/api/v1/auth/refresh",
            "/api/v1/public/auth/refresh",
            "/api/v1/auth/logout",
        ]
        .iter()
        .any(|p| path.starts_with(p))
}

/// A plugin's upstream credentials are independent of the dashboard session.
/// The same-origin proxy supplies this marker only after host authentication;
/// a middleware 401 has no marker and must still recover or expire the session.
fn is_host_authentication_failure(status: u16, input: &str, plugin_marker: Option<&str>) -> bool {
    if status != 401 {
        return false;
    }
    let path = request_path(input);
    let proxy_id = ["/api/v1/auth/plugins/", "/api/auth/plugins/", "/plugins/"]
        .iter()
        .find_map(|prefix| path.strip_prefix(prefix))
        .and_then(|rest| rest.split_once('/'))
        .filter(|(_, rest)| *rest == "proxy" || rest.starts_with("proxy/"))
        .and_then(|(id, _)| percent_decode_str(id).decode_utf8().ok());
    !proxy_id.is_some_and(|id| !id.is_empty() && plugin_marker == Some(id.as_ref()))
}

/// Upstream peer authorization failures on `/api/v1/peers/{id}/...` must retain
/// the managing server's local dashboard session. Only when the managing server's
/// own session is invalid should a 401 refresh or expire local auth.
fn should_treat_as_host_auth_failure(
    status: u16,
    input: &str,
    plugin_marker: Option<&str>,
    peer_marker: Option<&str>,
    local_session_authenticated: Option<bool>,
) -> bool {
    if !is_host_authentication_failure(status, input, plugin_marker) {
        return false;
    }
    if let Some(peer_id) = peer_proxy_id(input) {
        if peer_marker.is_some_and(|marker| marker == peer_id) {
            return false;
        }
        if local_session_authenticated == Some(true) {
            return false;
        }
    }
    true
}

pub fn is_csrf_rejection(status: u16, data: &serde_json::Value) -> bool {
    status == 403
        && (data["code"]
            .as_str()
            .is_some_and(|code| code.starts_with("CSRF_"))
            || ["message", "error"].iter().any(|key| {
                data[*key]
                    .as_str()
                    .is_some_and(|message| message.to_ascii_uppercase().contains("CSRF"))
            }))
}

/// Each request may rotate its session once and recover a stale CSRF token once,
/// in either order. A second rejection is returned to the caller unchanged.
#[derive(Default)]
struct RequestRetries {
    refresh_attempted: bool,
    csrf_retried: bool,
}
impl RequestRetries {
    fn take_refresh(&mut self, status: u16, path: &str) -> bool {
        if self.refresh_attempted || status != 401 || !should_refresh_on_401(path) {
            return false;
        }
        self.refresh_attempted = true;
        true
    }

    fn csrf_eligible(
        &self,
        status: u16,
        method: &str,
        path: &str,
        authorization: Option<&str>,
    ) -> bool {
        !self.csrf_retried && status == 403 && should_attach_csrf(method, path, authorization)
    }

    fn take_csrf_retry(
        &mut self,
        status: u16,
        method: &str,
        path: &str,
        authorization: Option<&str>,
        data: &serde_json::Value,
    ) -> bool {
        if !self.csrf_eligible(status, method, path, authorization)
            || !is_csrf_rejection(status, data)
        {
            return false;
        }
        self.csrf_retried = true;
        true
    }
}
pub fn cookie_value(cookies: &str, name: &str) -> Option<String> {
    cookies.split(';').map(str::trim).find_map(|entry| {
        entry
            .split_once('=')
            .filter(|(key, _)| *key == name)
            .and_then(|(_, value)| {
                percent_decode_str(value)
                    .decode_utf8()
                    .ok()
                    .map(|v| v.into_owned())
            })
    })
}

mod browser {
    use super::*;
    use futures::{
        future::{LocalBoxFuture, Shared},
        FutureExt,
    };
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{HtmlDocument, RequestCredentials, RequestInit, Response};

    type SharedToken = Shared<LocalBoxFuture<'static, Result<String, ApiError>>>;
    type SharedRefresh = Shared<LocalBoxFuture<'static, Result<bool, ApiError>>>;
    thread_local! {
        static CSRF:RefCell<Option<SharedToken>> = const { RefCell::new(None) };
        static CSRF_VALUE: RefCell<Option<String>> = const { RefCell::new(None) };
        static REFRESH:RefCell<Option<SharedRefresh>> = const { RefCell::new(None) };
    }
    #[cfg(target_arch = "wasm32")]
    thread_local! {
        static ACTIVE_CONTROLLERS: RefCell<std::collections::BTreeMap<u64, (bool, web_sys::AbortController)>> = const { RefCell::new(std::collections::BTreeMap::new()) };
    }
    #[cfg(target_arch = "wasm32")]
    static NEXT_CONTROLLER_ID: AtomicU64 = AtomicU64::new(0);

    struct RequestAbort {
        controller: web_sys::AbortController,
        _caller_abort: Option<gloo_events::EventListener>,
        origin_server_epoch: Option<u64>,
        finished: bool,
        #[cfg(target_arch = "wasm32")]
        id: u64,
    }
    impl RequestAbort {
        fn new(
            signal: Option<&web_sys::AbortSignal>,
            server_scoped: bool,
        ) -> Result<Self, ApiError> {
            let controller = web_sys::AbortController::new().map_err(js_error)?;
            let caller_abort = signal.map(|signal| {
                if signal.aborted() {
                    controller.abort();
                }
                let controller = controller.clone();
                gloo_events::EventListener::new(signal, "abort", move |_| controller.abort())
            });
            let origin_server_epoch = server_scoped.then(current_server_epoch);
            #[cfg(target_arch = "wasm32")]
            let id = NEXT_CONTROLLER_ID.fetch_add(1, Ordering::Relaxed);
            #[cfg(target_arch = "wasm32")]
            ACTIVE_CONTROLLERS.with(|controllers| {
                controllers
                    .borrow_mut()
                    .insert(id, (server_scoped, controller.clone()));
            });
            Ok(Self {
                controller,
                _caller_abort: caller_abort,
                origin_server_epoch,
                finished: false,
                #[cfg(target_arch = "wasm32")]
                id,
            })
        }

        fn ensure_active(&self, origin_epoch: u64) -> Result<(), ApiError> {
            ensure_same_auth_epoch(origin_epoch, current_auth_epoch())?;
            if let Some(origin_server_epoch) = self.origin_server_epoch {
                ensure_same_server_epoch(origin_server_epoch, current_server_epoch())?;
            }
            if self.controller.signal().aborted() {
                return Err(ApiError {
                    status: 0,
                    code: Some("ABORTED".into()),
                    message: "Request cancelled".into(),
                });
            }
            Ok(())
        }

        fn finish(&mut self) {
            self.finished = true;
        }
    }
    impl Drop for RequestAbort {
        fn drop(&mut self) {
            #[cfg(target_arch = "wasm32")]
            ACTIVE_CONTROLLERS.with(|controllers| controllers.borrow_mut().remove(&self.id));
            if !self.finished {
                self.controller.abort();
            }
        }
    }

    struct BodyReader(web_sys::ReadableStreamDefaultReader);

    impl Drop for BodyReader {
        fn drop(&mut self) {
            self.0.release_lock();
        }
    }

    /// An API response owns its transport until its body is consumed.
    /// Dropping it (including while a body future is pending) aborts unread bytes.
    /// Only metadata and consuming body operations are exposed, so a Response or
    /// its body promise cannot escape without the request guard.
    pub struct RawResponse {
        response: Response,
        request: RequestAbort,
        origin_epoch: u64,
    }
    impl RawResponse {
        pub fn ok(&self) -> bool {
            self.response.ok()
        }

        pub fn status(&self) -> u16 {
            self.response.status()
        }

        pub fn headers(&self) -> web_sys::Headers {
            self.response.headers()
        }

        pub async fn blob(mut self) -> Result<web_sys::Blob, ApiError> {
            self.request.ensure_active(self.origin_epoch)?;
            let result = JsFuture::from(self.response.blob().map_err(js_error)?).await;
            self.request.ensure_active(self.origin_epoch)?;
            let blob = result.map_err(js_error)?.dyn_into().map_err(js_error)?;
            self.request.finish();
            Ok(blob)
        }

        pub async fn text(mut self) -> Result<String, ApiError> {
            self.request.ensure_active(self.origin_epoch)?;
            let result = JsFuture::from(self.response.text().map_err(js_error)?).await;
            self.request.ensure_active(self.origin_epoch)?;
            let text = result.map_err(js_error)?.as_string().unwrap_or_default();
            self.request.finish();
            Ok(text)
        }

        pub async fn json(mut self) -> Result<JsValue, ApiError> {
            self.request.ensure_active(self.origin_epoch)?;
            let result = JsFuture::from(self.response.json().map_err(js_error)?).await;
            self.request.ensure_active(self.origin_epoch)?;
            let json = result.map_err(js_error)?;
            self.request.finish();
            Ok(json)
        }

        /// Consume the body within a byte limit and assign the caller's chosen media type.
        pub async fn blob_limited(
            mut self,
            max_bytes: u32,
            content_type: &str,
        ) -> Result<web_sys::Blob, ApiError> {
            let blob = self.read_limited_blob(max_bytes, content_type).await?;
            self.request.finish();
            Ok(blob)
        }

        /// Apply the limit to the received bytes and decode them as Fetch text.
        pub async fn text_limited(mut self, max_bytes: u32) -> Result<String, ApiError> {
            let blob = self.read_limited_blob(max_bytes, "").await?;
            let result = JsFuture::from(blob.text()).await;
            self.request.ensure_active(self.origin_epoch)?;
            let text = result.map_err(js_error)?.as_string().unwrap_or_default();
            self.request.finish();
            Ok(text)
        }

        async fn read_limited_blob(
            &self,
            max_bytes: u32,
            content_type: &str,
        ) -> Result<web_sys::Blob, ApiError> {
            self.request.ensure_active(self.origin_epoch)?;
            let declared = self.headers().get("Content-Length").map_err(js_error)?;
            if declared_body_too_large(declared.as_deref(), max_bytes) {
                return Err(body_limit_error());
            }

            let parts = js_sys::Array::new();
            if let Some(stream) = self.response.body() {
                let reader = BodyReader(
                    web_sys::ReadableStreamDefaultReader::new(&stream).map_err(js_error)?,
                );
                let done_key = JsValue::from_str("done");
                let value_key = JsValue::from_str("value");
                let mut remaining = max_bytes;
                loop {
                    let result = JsFuture::from(reader.0.read()).await;
                    self.request.ensure_active(self.origin_epoch)?;
                    let result = result.map_err(js_error)?;
                    let done = js_sys::Reflect::get(&result, &done_key).map_err(js_error)?;
                    if done.as_bool() == Some(true) {
                        break;
                    }
                    let bytes = js_sys::Reflect::get(&result, &value_key)
                        .map_err(js_error)?
                        .dyn_into::<js_sys::Uint8Array>()
                        .map_err(js_error)?;
                    let received = bytes.byte_length();
                    remaining = remaining_body_bytes(remaining, received)?;
                    if received != 0 {
                        parts.push(bytes.as_ref());
                    }
                }
            }
            let options = web_sys::BlobPropertyBag::new();
            options.set_type(content_type);
            web_sys::Blob::new_with_buffer_source_sequence_and_options(parts.as_ref(), &options)
                .map_err(js_error)
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub(super) fn abort_active_controllers() {
        let controllers = ACTIVE_CONTROLLERS.with(|slot| std::mem::take(&mut *slot.borrow_mut()));
        for (_, controller) in controllers.into_values() {
            controller.abort();
        }
    }
    #[cfg(target_arch = "wasm32")]
    pub(super) fn abort_server_scoped_controllers() {
        let to_abort = ACTIVE_CONTROLLERS.with(|slot| {
            let mut map = slot.borrow_mut();
            let mut scoped = Vec::new();
            let ids: Vec<u64> = map
                .iter()
                .filter_map(|(&id, (is_scoped, _))| (*is_scoped).then_some(id))
                .collect();
            for id in ids {
                if let Some((_, controller)) = map.remove(&id) {
                    scoped.push(controller);
                }
            }
            scoped
        });
        for controller in to_abort {
            controller.abort();
        }
    }
    fn js_error(error: JsValue) -> ApiError {
        ApiError {
            status: 0,
            message: error
                .as_string()
                .unwrap_or_else(|| "Network request failed".into()),
            code: None,
        }
    }
    fn document_cookie() -> String {
        web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.dyn_into::<HtmlDocument>().ok())
            .and_then(|d| d.cookie().ok())
            .unwrap_or_default()
    }
    pub(super) fn clear_cached_csrf_token() {
        CSRF.with(|slot| slot.replace(None));
        CSRF_VALUE.with(|slot| slot.replace(None));
    }
    pub(super) fn clear_cached_refresh() {
        REFRESH.with(|slot| slot.replace(None));
    }
    fn clear_csrf_cookie_and_cache() {
        clear_csrf_token();
        if let Some(document) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.dyn_into::<HtmlDocument>().ok())
        {
            let _ = document.set_cookie("csrf_token=; Max-Age=0; path=/; SameSite=Strict");
        }
    }
    pub fn storage_get(key: &str) -> Option<String> {
        web_sys::window()?
            .local_storage()
            .ok()??
            .get_item(key)
            .ok()?
    }
    pub fn storage_set(key: &str, value: &str) {
        if let Some(storage) = web_sys::window()
            .and_then(|w| w.local_storage().ok())
            .flatten()
        {
            let _ = storage.set_item(key, value);
        }
    }
    pub fn broadcast_login() {
        storage_set(LOGIN_SYNC, &js_sys::Date::now().to_string());
    }
    pub fn broadcast_expired() {
        storage_set(LOGOUT_SYNC, &js_sys::Date::now().to_string());
        if let (Some(window), Ok(event)) = (
            web_sys::window(),
            web_sys::CustomEvent::new(SESSION_EXPIRED_EVENT),
        ) {
            let _ = window.dispatch_event(&event);
        }
    }
    async fn raw_fetch(
        path: &str,
        method: &str,
        body: Option<&str>,
        csrf: Option<&str>,
        authorization: Option<&str>,
        signal: Option<&web_sys::AbortSignal>,
    ) -> Result<Response, ApiError> {
        validate_local_api_path(path)?;
        let init = RequestInit::new();
        init.set_method(method);
        init.set_credentials(RequestCredentials::Include);
        init.set_cache(web_sys::RequestCache::NoStore);
        init.set_signal(signal);
        let headers = web_sys::Headers::new().map_err(js_error)?;
        for (key, value) in [
            ("X-API-Version", API_VERSION),
            ("Accept", API_ACCEPT),
            ("X-Requested-With", "XMLHttpRequest"),
            ("Cache-Control", "no-store"),
        ] {
            headers.set(key, value).map_err(js_error)?;
        }
        if let Some(token) = csrf {
            headers.set("X-CSRF-Token", token).map_err(js_error)?;
        }
        if let Some(token) = authorization {
            headers.set("Authorization", token).map_err(js_error)?;
        }
        if let Some(body) = body {
            headers
                .set("Content-Type", "application/json")
                .map_err(js_error)?;
            init.set_body(&JsValue::from_str(body));
        }
        init.set_headers(&headers);
        let window = web_sys::window()
            .ok_or_else(|| js_error(JsValue::from_str("Browser window unavailable")))?;
        JsFuture::from(window.fetch_with_str_and_init(path, &init))
            .await
            .map_err(js_error)?
            .dyn_into::<Response>()
            .map_err(js_error)
    }
    async fn response_json(response: &Response) -> Result<serde_json::Value, ApiError> {
        let text = JsFuture::from(response.text().map_err(js_error)?)
            .await
            .map_err(js_error)?
            .as_string()
            .unwrap_or_default();
        parse_json_response(response.status(), &text)
    }
    fn parse_json_response(status: u16, text: &str) -> Result<serde_json::Value, ApiError> {
        if text.trim().is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_str(text).map_err(|e| ApiError {
            status,
            message: format!("Invalid API response: {e}"),
            code: None,
        })
    }
    async fn csrf_token() -> Result<String, ApiError> {
        let origin_epoch = current_auth_epoch();
        if let Some(token) = CSRF_VALUE.with(|slot| slot.borrow().clone()) {
            return Ok(token);
        }
        if let Some(token) =
            cookie_value(&document_cookie(), "csrf_token").filter(|s| !s.is_empty())
        {
            return Ok(token);
        }
        let future = CSRF.with(|slot| {
            let mut slot = slot.borrow_mut();
            slot.get_or_insert_with(|| {
                async move {
                    let result = async {
                        let mut request = RequestAbort::new(None, false)?;
                        let signal = request.controller.signal();
                        request.ensure_active(origin_epoch)?;
                        let response = raw_fetch(
                            "/api/v1/public/csrf-token",
                            "GET",
                            None,
                            None,
                            None,
                            Some(&signal),
                        )
                        .await;
                        request.ensure_active(origin_epoch)?;
                        let response = response?;
                        let data = response_json(&response).await;
                        request.ensure_active(origin_epoch)?;
                        let data = data?;
                        let token = data["csrf_token"]
                            .as_str()
                            .filter(|token| !token.is_empty())
                            .map(str::to_string)
                            .or_else(|| {
                                cookie_value(&document_cookie(), "csrf_token")
                                    .filter(|token| !token.is_empty())
                            })
                            .ok_or_else(|| ApiError {
                                status: response.status(),
                                message: "CSRF token unavailable".into(),
                                code: None,
                            })?;
                        CSRF_VALUE.with(|slot| slot.replace(Some(token.clone())));
                        request.finish();
                        Ok(token)
                    }
                    .await;
                    ensure_same_auth_epoch(origin_epoch, current_auth_epoch())?;
                    CSRF.with(|slot| slot.replace(None));
                    result
                }
                .boxed_local()
                .shared()
            })
            .clone()
        });
        let result = future.await;
        ensure_same_auth_epoch(origin_epoch, current_auth_epoch())?;
        result
    }
    async fn csrf_retry_token(
        response: &Response,
        method: &str,
        path: &str,
        authorization: Option<&str>,
        retries: &mut RequestRetries,
        origin_epoch: u64,
    ) -> Result<Option<String>, ApiError> {
        ensure_same_auth_epoch(origin_epoch, current_auth_epoch())?;
        if !retries.csrf_eligible(response.status(), method, path, authorization) {
            return Ok(None);
        }
        // Inspect a copy: forbidden responses unrelated to CSRF must retain
        // their original body for fetch callers, including multipart uploads.
        let Ok(copy) = response.clone() else {
            return Ok(None);
        };
        let data = response_json(&copy).await;
        ensure_same_auth_epoch(origin_epoch, current_auth_epoch())?;
        let Ok(data) = data else {
            return Ok(None);
        };
        if !retries.take_csrf_retry(response.status(), method, path, authorization, &data) {
            return Ok(None);
        }
        clear_csrf_cookie_and_cache();
        let token = csrf_token().await;
        ensure_same_auth_epoch(origin_epoch, current_auth_epoch())?;
        token.map(Some)
    }
    fn peer_proxy_marker(response: &Response) -> Option<String> {
        response
            .headers()
            .get("X-AetherFlow-Proxied-Peer")
            .ok()
            .flatten()
            .or_else(|| response.headers().get("X-AF-Proxied-Peer").ok().flatten())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    async fn local_session_is_authenticated(origin_epoch: u64) -> Result<bool, ApiError> {
        let mut request = RequestAbort::new(None, false)?;
        let signal = request.controller.signal();
        request.ensure_active(origin_epoch)?;
        let response = raw_fetch(
            "/api/v1/auth/session",
            "GET",
            None,
            None,
            None,
            Some(&signal),
        )
        .await;
        request.ensure_active(origin_epoch)?;
        let response = response?;
        let ok = response.ok();
        request.finish();
        Ok(ok)
    }

    async fn check_host_authentication_failure(
        response: &Response,
        path: &str,
        origin_epoch: u64,
    ) -> Result<bool, ApiError> {
        let plugin_marker = response
            .headers()
            .get("X-AetherFlow-Proxied-Plugin")
            .ok()
            .flatten();
        let peer_marker = peer_proxy_marker(response);
        if !should_treat_as_host_auth_failure(
            response.status(),
            path,
            plugin_marker.as_deref(),
            peer_marker.as_deref(),
            None,
        ) {
            return Ok(false);
        }
        if is_peer_proxy_path(path) {
            let local_ok = local_session_is_authenticated(origin_epoch).await?;
            return Ok(should_treat_as_host_auth_failure(
                response.status(),
                path,
                plugin_marker.as_deref(),
                peer_marker.as_deref(),
                Some(local_ok),
            ));
        }
        Ok(true)
    }

    async fn refresh() -> Result<bool, ApiError> {
        let origin_epoch = current_auth_epoch();
        let future = REFRESH.with(|slot| {
            slot.borrow_mut()
                .get_or_insert_with(|| {
                    async move {
                        let mut request = RequestAbort::new(None, false)?;
                        let signal = request.controller.signal();
                        request.ensure_active(origin_epoch)?;
                        let response = raw_fetch(
                            "/api/v1/auth/refresh",
                            "POST",
                            None,
                            None,
                            None,
                            Some(&signal),
                        )
                        .await;
                        request.ensure_active(origin_epoch)?;
                        REFRESH.with(|slot| slot.replace(None));
                        request.finish();
                        Ok(response.is_ok_and(|response| response.ok()))
                    }
                    .boxed_local()
                    .shared()
                })
                .clone()
        });
        let result = future.await;
        ensure_same_auth_epoch(origin_epoch, current_auth_epoch())?;
        result
    }
    #[derive(Clone, Copy, Default)]
    pub struct ApiClient;
    impl ApiClient {
        /// Public password-protected shares use their scoped cookie and must not
        /// rotate or expire the operator's separate authenticated session.
        pub async fn public_fetch(
            &self,
            path: &str,
            method: &str,
            body: Option<&serde_json::Value>,
        ) -> Result<RawResponse, ApiError> {
            let origin_epoch = current_auth_epoch();
            let request = RequestAbort::new(None, false)?;
            let signal = request.controller.signal();
            let body = body.map(serde_json::Value::to_string);
            request.ensure_active(origin_epoch)?;
            let response =
                raw_fetch(path, method, body.as_deref(), None, None, Some(&signal)).await;
            request.ensure_active(origin_epoch)?;
            let response = response?;
            Ok(RawResponse {
                response,
                request,
                origin_epoch,
            })
        }
        pub async fn public_request(
            &self,
            path: &str,
            method: &str,
            body: Option<&serde_json::Value>,
        ) -> Result<serde_json::Value, ApiError> {
            let response = self.public_fetch(path, method, body).await?;
            let status = response.status();
            let ok = response.ok();
            let data = parse_json_response(status, &response.text().await?)?;
            if !ok {
                return Err(ApiError {
                    status,
                    message: data["message"]
                        .as_str()
                        .or_else(|| data["error"].as_str())
                        .unwrap_or("Share unavailable")
                        .to_string(),
                    code: data["code"].as_str().map(str::to_string),
                });
            }
            Ok(data)
        }
        pub async fn fetch(
            &self,
            path: &str,
            method: &str,
            body: Option<&serde_json::Value>,
        ) -> Result<RawResponse, ApiError> {
            self.fetch_authorized(path, method, body, None).await
        }
        pub async fn fetch_authorized(
            &self,
            path: &str,
            method: &str,
            body: Option<&serde_json::Value>,
            authorization: Option<&str>,
        ) -> Result<RawResponse, ApiError> {
            let origin_epoch = current_auth_epoch();
            let result = self
                .fetch_authorized_guarded(path, method, body, authorization, origin_epoch)
                .await;
            ensure_same_auth_epoch(origin_epoch, current_auth_epoch())?;
            let (response, request) = result?;
            Ok(RawResponse {
                response,
                request,
                origin_epoch,
            })
        }
        async fn fetch_authorized_guarded(
            &self,
            path: &str,
            method: &str,
            body: Option<&serde_json::Value>,
            authorization: Option<&str>,
            origin_epoch: u64,
        ) -> Result<(Response, RequestAbort), ApiError> {
            let rewritten = prepare_api_request_path(path, method)?;
            let path = rewritten.as_str();
            let request = RequestAbort::new(None, is_server_scoped_path(path))?;
            let signal = request.controller.signal();
            request.ensure_active(origin_epoch)?;
            let body = body.map(serde_json::Value::to_string);
            let csrf = if should_attach_csrf(method, path, authorization) {
                let token = csrf_token().await;
                request.ensure_active(origin_epoch)?;
                token.ok()
            } else {
                None
            };
            let response = raw_fetch(
                path,
                method,
                body.as_deref(),
                csrf.as_deref(),
                authorization,
                Some(&signal),
            )
            .await;
            request.ensure_active(origin_epoch)?;
            let mut response = response?;
            let mut retries = RequestRetries::default();
            loop {
                request.ensure_active(origin_epoch)?;
                let host_auth_failure =
                    check_host_authentication_failure(&response, path, origin_epoch).await?;
                request.ensure_active(origin_epoch)?;
                if host_auth_failure && retries.take_refresh(response.status(), path) {
                    let refreshed = refresh().await;
                    request.ensure_active(origin_epoch)?;
                    // Refresh rotates cookies; discard the cached token on both
                    // success and failure before resolving the current session.
                    clear_csrf_token();
                    if !refreshed? {
                        break;
                    }
                    let csrf = if should_attach_csrf(method, path, authorization) {
                        let token = csrf_token().await;
                        request.ensure_active(origin_epoch)?;
                        token.ok()
                    } else {
                        None
                    };
                    let retried = raw_fetch(
                        path,
                        method,
                        body.as_deref(),
                        csrf.as_deref(),
                        authorization,
                        Some(&signal),
                    )
                    .await;
                    request.ensure_active(origin_epoch)?;
                    response = retried?;
                    continue;
                }
                let csrf = csrf_retry_token(
                    &response,
                    method,
                    path,
                    authorization,
                    &mut retries,
                    origin_epoch,
                )
                .await;
                request.ensure_active(origin_epoch)?;
                if let Some(csrf) = csrf? {
                    let retried = raw_fetch(
                        path,
                        method,
                        body.as_deref(),
                        Some(&csrf),
                        authorization,
                        Some(&signal),
                    )
                    .await;
                    request.ensure_active(origin_epoch)?;
                    response = retried?;
                    continue;
                }
                break;
            }
            if check_host_authentication_failure(&response, path, origin_epoch).await?
                && !is_login_endpoint(path)
            {
                request.ensure_active(origin_epoch)?;
                broadcast_expired();
            }
            Ok((response, request))
        }
        pub async fn request(
            &self,
            path: &str,
            method: &str,
            body: Option<&serde_json::Value>,
        ) -> Result<serde_json::Value, ApiError> {
            self.request_typed(path, method, body).await
        }
        pub async fn request_typed<T: serde::de::DeserializeOwned>(
            &self,
            path: &str,
            method: &str,
            body: Option<&serde_json::Value>,
        ) -> Result<T, ApiError> {
            let origin_epoch = current_auth_epoch();
            let result = self
                .fetch_authorized_guarded(path, method, body, None, origin_epoch)
                .await;
            ensure_same_auth_epoch(origin_epoch, current_auth_epoch())?;
            let (response, mut request) = result?;
            let data = response_json(&response).await;
            request.ensure_active(origin_epoch)?;
            let data = data?;
            if !response.ok() {
                return Err(ApiError {
                    status: response.status(),
                    message: data["message"]
                        .as_str()
                        .or_else(|| data["error"].as_str())
                        .unwrap_or("Request failed")
                        .to_string(),
                    code: data["code"].as_str().map(str::to_string),
                });
            }
            let data = serde_json::from_value(data).map_err(|error| ApiError {
                status: response.status(),
                message: format!("Invalid API response: {error}"),
                code: None,
            })?;
            request.finish();
            Ok(data)
        }
        pub async fn get(&self, path: &str) -> Result<serde_json::Value, ApiError> {
            self.request(path, "GET", None).await
        }
        pub async fn get_typed<T: serde::de::DeserializeOwned>(
            &self,
            path: &str,
        ) -> Result<T, ApiError> {
            self.request_typed(path, "GET", None).await
        }
        pub async fn post_typed<T: serde::de::DeserializeOwned>(
            &self,
            path: &str,
            body: Option<&serde_json::Value>,
        ) -> Result<T, ApiError> {
            self.request_typed(path, "POST", body).await
        }
        pub async fn put_typed<T: serde::de::DeserializeOwned>(
            &self,
            path: &str,
            body: Option<&serde_json::Value>,
        ) -> Result<T, ApiError> {
            self.request_typed(path, "PUT", body).await
        }
        pub async fn patch_typed<T: serde::de::DeserializeOwned>(
            &self,
            path: &str,
            body: Option<&serde_json::Value>,
        ) -> Result<T, ApiError> {
            self.request_typed(path, "PATCH", body).await
        }
        pub async fn delete_typed<T: serde::de::DeserializeOwned>(
            &self,
            path: &str,
            body: Option<&serde_json::Value>,
        ) -> Result<T, ApiError> {
            self.request_typed(path, "DELETE", body).await
        }
        /// Probe authentication on a public consent screen without rotating cookies
        /// or broadcasting session expiry when there is no operator session yet.
        pub async fn probe_session(&self) -> Result<serde_json::Value, ApiError> {
            self.public_request("/api/v1/auth/session", "GET", None)
                .await
        }
        pub async fn post(
            &self,
            path: &str,
            body: Option<&serde_json::Value>,
        ) -> Result<serde_json::Value, ApiError> {
            self.request(path, "POST", body).await
        }
        pub async fn put(
            &self,
            path: &str,
            body: Option<&serde_json::Value>,
        ) -> Result<serde_json::Value, ApiError> {
            self.request(path, "PUT", body).await
        }
        pub async fn patch(
            &self,
            path: &str,
            body: Option<&serde_json::Value>,
        ) -> Result<serde_json::Value, ApiError> {
            self.request(path, "PATCH", body).await
        }
        pub async fn delete(
            &self,
            path: &str,
            body: Option<&serde_json::Value>,
        ) -> Result<serde_json::Value, ApiError> {
            self.request(path, "DELETE", body).await
        }
        /// Binary, multipart, or custom-header authenticated transport (e.g. McBrowser
        /// chunked `Uint8Array`/`Blob` uploads and `If-Match` ETag-guarded file writes).
        pub async fn fetch_raw_body(
            &self,
            path: &str,
            method: &str,
            body: Option<&JsValue>,
            content_type: Option<&str>,
            extra_headers: &[(&str, &str)],
        ) -> Result<RawResponse, ApiError> {
            self.fetch_raw_body_with_signal(path, method, body, content_type, extra_headers, None)
                .await
        }
        pub async fn fetch_raw_body_with_signal(
            &self,
            path: &str,
            method: &str,
            body: Option<&wasm_bindgen::JsValue>,
            content_type: Option<&str>,
            extra_headers: &[(&str, &str)],
            signal: Option<&web_sys::AbortSignal>,
        ) -> Result<RawResponse, ApiError> {
            let rewritten = prepare_api_request_path(path, method)?;
            let path = rewritten.as_str();
            let origin_epoch = current_auth_epoch();
            let request = RequestAbort::new(signal, is_server_scoped_path(path))?;
            let request_signal = request.controller.signal();
            let signal = Some(&request_signal);
            request.ensure_active(origin_epoch)?;
            async fn send_custom(
                path: &str,
                method: &str,
                body: Option<&JsValue>,
                content_type: Option<&str>,
                extra_headers: &[(&str, &str)],
                csrf_val: Option<&str>,
                signal: Option<&web_sys::AbortSignal>,
            ) -> Result<Response, ApiError> {
                let init = RequestInit::new();
                init.set_method(method);
                init.set_credentials(RequestCredentials::Include);
                init.set_cache(web_sys::RequestCache::NoStore);
                init.set_signal(signal);
                let headers = web_sys::Headers::new().map_err(js_error)?;
                for (key, value) in [
                    ("X-API-Version", API_VERSION),
                    ("X-Requested-With", "XMLHttpRequest"),
                    ("Cache-Control", "no-store"),
                ] {
                    headers.set(key, value).map_err(js_error)?;
                }
                if let Some(token) = csrf_val {
                    validate_header_ascii(token)?;
                    headers.set("X-CSRF-Token", token).map_err(js_error)?;
                }
                if let Some(ct) = content_type {
                    validate_header_ascii(ct)?;
                    headers.set("Content-Type", ct).map_err(js_error)?;
                }
                for (k, v) in extra_headers {
                    validate_header_ascii(k)?;
                    validate_header_ascii(v)?;
                    headers.set(k, v).map_err(js_error)?;
                }
                if let Some(payload) = body {
                    init.set_body(payload);
                }
                init.set_headers(&headers);
                let window = web_sys::window()
                    .ok_or_else(|| js_error(JsValue::from_str("Browser window unavailable")))?;
                JsFuture::from(window.fetch_with_str_and_init(path, &init))
                    .await
                    .map_err(js_error)?
                    .dyn_into::<Response>()
                    .map_err(js_error)
            }
            let authorization = extra_headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("Authorization"))
                .map(|(_, value)| *value);
            let csrf = if should_attach_csrf(method, path, authorization) {
                let token = csrf_token().await;
                request.ensure_active(origin_epoch)?;
                token.ok()
            } else {
                None
            };
            let response = send_custom(
                path,
                method,
                body,
                content_type,
                extra_headers,
                csrf.as_deref(),
                signal,
            )
            .await;
            request.ensure_active(origin_epoch)?;
            let mut response = response?;
            let mut retries = RequestRetries::default();
            loop {
                request.ensure_active(origin_epoch)?;
                let host_auth_failure =
                    check_host_authentication_failure(&response, path, origin_epoch).await?;
                request.ensure_active(origin_epoch)?;
                if host_auth_failure && retries.take_refresh(response.status(), path) {
                    let refreshed = refresh().await;
                    request.ensure_active(origin_epoch)?;
                    clear_csrf_token();
                    if !refreshed? {
                        break;
                    }
                    let csrf = if should_attach_csrf(method, path, authorization) {
                        let token = csrf_token().await;
                        request.ensure_active(origin_epoch)?;
                        token.ok()
                    } else {
                        None
                    };
                    let retried = send_custom(
                        path,
                        method,
                        body,
                        content_type,
                        extra_headers,
                        csrf.as_deref(),
                        signal,
                    )
                    .await;
                    request.ensure_active(origin_epoch)?;
                    response = retried?;
                    continue;
                }
                let csrf = csrf_retry_token(
                    &response,
                    method,
                    path,
                    authorization,
                    &mut retries,
                    origin_epoch,
                )
                .await;
                request.ensure_active(origin_epoch)?;
                if let Some(csrf) = csrf? {
                    let retried = send_custom(
                        path,
                        method,
                        body,
                        content_type,
                        extra_headers,
                        Some(&csrf),
                        signal,
                    )
                    .await;
                    request.ensure_active(origin_epoch)?;
                    response = retried?;
                    continue;
                }
                break;
            }
            if check_host_authentication_failure(&response, path, origin_epoch).await?
                && !is_login_endpoint(path)
            {
                request.ensure_active(origin_epoch)?;
                broadcast_expired();
            }
            request.ensure_active(origin_epoch)?;
            Ok(RawResponse {
                response,
                request,
                origin_epoch,
            })
        }
    }
    #[cfg(test)]
    mod token_cache_tests {
        use super::*;

        #[test]
        fn clearing_token_invalidates_cached_and_inflight_tokens() {
            CSRF_VALUE.with(|slot| slot.replace(Some("cached-token".into())));
            CSRF.with(|slot| {
                slot.replace(Some(
                    futures::future::ready(Ok("in-flight-token".into()))
                        .boxed_local()
                        .shared(),
                ))
            });
            clear_csrf_token();
            assert!(CSRF_VALUE.with(|slot| slot.borrow().is_none()));
            assert!(CSRF.with(|slot| slot.borrow().is_none()));
        }

        #[test]
        fn account_change_advances_epoch_clears_credentials_and_blocks_retries() {
            let path = "/api/v1/mcbrowser/files";
            let rejection = serde_json::json!({"code": "CSRF_TOKEN_INVALID"});
            for status in [401, 403] {
                CSRF_VALUE.with(|slot| slot.replace(Some("old-account-token".into())));
                let origin_epoch = current_auth_epoch();
                let advanced_epoch = bump_auth_epoch_and_abort();
                assert_eq!(advanced_epoch, origin_epoch + 1);
                assert_eq!(current_auth_epoch(), advanced_epoch);
                assert!(CSRF_VALUE.with(|slot| slot.borrow().is_none()));
                let mut retries = RequestRetries::default();
                let result = ensure_same_auth_epoch(origin_epoch, current_auth_epoch()).map(|()| {
                    retries.take_refresh(status, path)
                        || retries.take_csrf_retry(status, "POST", path, None, &rejection)
                });
                assert_eq!(result.unwrap_err().code.as_deref(), Some("SESSION_CHANGED"));
                assert!(!retries.refresh_attempted);
                assert!(!retries.csrf_retried);
            }
        }
    }
}
pub use browser::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_declared_body_lengths_are_rejected_before_reading() {
        for value in ["1048577", " 1048577 ", "18446744073709551616"] {
            assert!(declared_body_too_large(Some(value), 1024 * 1024), "{value}");
        }
        for value in [
            None,
            Some(""),
            Some("1048576"),
            Some("001"),
            Some("3, 7"),
            Some("+1"),
        ] {
            assert!(!declared_body_too_large(value, 1024 * 1024), "{value:?}");
        }
    }

    #[test]
    fn actual_chunk_budget_accepts_the_boundary_and_rejects_the_next_byte() {
        for limit in [1024 * 1024, 20 * 1024 * 1024, u32::MAX] {
            let remaining = remaining_body_bytes(limit, limit - 7).unwrap();
            assert_eq!(remaining_body_bytes(remaining, 0).unwrap(), 7);
            assert_eq!(remaining_body_bytes(remaining, 6).unwrap(), 1);
            let remaining = remaining_body_bytes(remaining, 7).unwrap();
            assert_eq!(remaining_body_bytes(remaining, 0).unwrap(), 0);
            assert_eq!(
                remaining_body_bytes(remaining, 1)
                    .unwrap_err()
                    .code
                    .as_deref(),
                Some(BODY_LIMIT_EXCEEDED)
            );
        }
    }

    #[test]
    fn revalidation_allows_session_and_public_login_but_blocks_account_requests() {
        assert!(allowed_during_auth_revalidation(
            "/api/v1/auth/session",
            "GET"
        ));
        assert!(allowed_during_auth_revalidation(
            "/api/v1/public/auth/login",
            "POST"
        ));
        assert!(allowed_during_auth_revalidation(
            "/api/v1/public/auth/mfa/verify",
            "POST"
        ));
        for (path, method) in [
            ("/api/v1/auth/session", "POST"),
            ("/api/v1/auth/mcbrowser/file", "POST"),
            ("/api/v1/auth/mcbrowser/uploads", "PATCH"),
            ("/api/v1/admin/quotas/5/refresh", "POST"),
            ("/api/v1/auth/system/metrics", "GET"),
        ] {
            assert!(
                !allowed_during_auth_revalidation(path, method),
                "{method} {path}"
            );
        }
    }

    #[test]
    fn epoch_policy_accepts_only_the_original_session() {
        for epoch in [0, 1, 42, u64::MAX] {
            assert!(ensure_same_auth_epoch(epoch, epoch).is_ok());
        }
        for (origin, current) in [(0, 1), (1, 2), (7, 9), (u64::MAX, 0)] {
            assert_eq!(
                ensure_same_auth_epoch(origin, current).unwrap_err(),
                ApiError {
                    status: 401,
                    code: Some("SESSION_CHANGED".into()),
                    message: "Session changed; request cancelled".into(),
                }
            );
        }
    }
    #[test]
    fn header_components_percent_encode_utf8_and_reserved_ascii() {
        for (input, expected) in [
            (
                "媒体/文档.txt",
                "%E5%AA%92%E4%BD%93%2F%E6%96%87%E6%A1%A3.txt",
            ),
            ("médias/été.txt", "m%C3%A9dias%2F%C3%A9t%C3%A9.txt"),
            ("größe.txt", "gr%C3%B6%C3%9Fe.txt"),
            ("blåbær.txt", "bl%C3%A5b%C3%A6r.txt"),
            ("español/niño.txt", "espa%C3%B1ol%2Fni%C3%B1o.txt"),
            (
                "/mnt/media/my file+100%.txt",
                "%2Fmnt%2Fmedia%2Fmy%20file%2B100%25.txt",
            ),
            ("AZaz09-._~", "AZaz09-._~"),
            ("", ""),
        ] {
            assert_eq!(percent_encode_header_component(input), expected);
            assert!(validate_header_ascii(expected).is_ok());
        }
    }
    #[test]
    fn raw_unicode_header_values_return_a_clean_error() {
        for value in ["媒体", "médias", "größe", "blåbær", "español", "\u{80}"] {
            assert_eq!(
                validate_header_ascii(value).unwrap_err().code.as_deref(),
                Some("INVALID_HEADER_VALUE")
            );
        }
    }
    #[test]
    fn clearing_csrf_token_is_safe_and_idempotent_on_every_target() {
        clear_csrf_token();
        clear_csrf_token();
    }
    #[test]
    fn csrf_mutations_cover_all_legacy_and_current_routes() {
        for path in [
            "/api/v1/auth/settings",
            "/api/v1/public/auth/setup",
            "/api/auth/login",
            "/api/v1/admin/users",
            "/api/admin/users",
            "/api/v1/ingress/apps/sonarr",
            "/api/ingress/apps/sonarr",
            "/plugins/example/action",
            "/api/v1/mcbrowser/files",
            "/api/v1/fileshare/upload",
            "/api/v1/oauth/authorize",
            "/api/v1/share/password",
        ] {
            for method in ["POST", "PUT", "DELETE", "PATCH", "post"] {
                for input in [
                    path.to_string(),
                    format!("{path}?download=1#fragment"),
                    format!("https://host{path}?download=1"),
                ] {
                    assert!(should_attach_csrf(method, &input, None), "{method} {input}");
                    for read in ["GET", "HEAD", "OPTIONS", "get"] {
                        assert!(!should_attach_csrf(read, &input, None), "{read} {input}");
                    }
                    assert!(!should_attach_csrf(method, &input, Some("Bearer token")));
                }
            }
        }
    }
    #[test]
    fn csrf_read_and_bearer_exemptions() {
        for method in ["GET", "HEAD", "OPTIONS"] {
            assert!(!should_attach_csrf(method, "/api/v1/auth/settings", None));
        }
        assert!(!should_attach_csrf(
            "POST",
            "/api/v1/admin/users",
            Some("Bearer token")
        ));
        assert!(!should_attach_csrf("POST", "/external", None));
        for path in [
            "/api/v1/ingress-other/apps/sonarr",
            "/api/ingress-other/apps/sonarr",
            "/plugins-other/action",
            "/api/v1/mcbrowser-other/files",
            "/api/v1/fileshare-other/upload",
            "/api/v1/oauth-other/authorize",
            "/api/v1/share-other/password",
        ] {
            assert!(!should_attach_csrf("POST", path, None), "{path}");
        }
        assert!(should_attach_csrf(
            "POST",
            "/plugins/example/action",
            Some("Basic token")
        ));
    }
    #[test]
    fn refresh_exemptions_are_exact() {
        for p in [
            "/api/v1/auth/refresh",
            "/api/v1/public/auth/refresh",
            "/api/auth/refresh",
        ] {
            assert!(!should_attach_csrf("POST", p, None));
        }
        assert!(should_attach_csrf(
            "POST",
            "/api/v1/auth/refresh/other",
            None
        ));
    }
    #[test]
    fn absolute_request_paths_are_normalized() {
        assert!(should_attach_csrf(
            "POST",
            "https://host/api/v1/admin/users?x=1",
            None
        ));
        assert_eq!(
            request_path("/api/v1/auth/session?x=1"),
            "/api/v1/auth/session"
        );
    }
    #[test]
    fn cookie_parser_handles_escaping_and_equals() {
        assert_eq!(
            cookie_value("x=1; csrf_token=a%2Bb%3D; y=2", "csrf_token"),
            Some("a+b=".into())
        );
        assert_eq!(cookie_value("csrf_token_bad=abc", "csrf_token"), None);
    }
    #[test]
    fn session_refresh_allowed_but_login_never_loops() {
        assert!(should_refresh_on_401("/api/v1/auth/session"));
        for path in [
            "/api/v1/auth/refresh",
            "/api/v1/public/auth/login",
            "/api/v1/public/auth/mfa/verify",
            "/api/v1/public/auth/setup",
            "/api/v1/auth/logout",
        ] {
            assert!(!should_refresh_on_401(path));
        }
    }
    #[test]
    fn marked_plugin_unauthorized_is_scoped_to_the_exact_proxy() {
        for path in [
            "/api/v1/auth/plugins/demo/proxy",
            "/api/v1/auth/plugins/demo/proxy/private?x=1",
            "/api/auth/plugins/de%6do/proxy/data",
            "/plugins/demo/proxy/data",
        ] {
            assert!(
                !is_host_authentication_failure(401, path, Some("demo")),
                "{path}"
            );
            // Host authentication runs before the proxy and cannot carry its marker.
            assert!(is_host_authentication_failure(401, path, None), "{path}");
            assert!(
                is_host_authentication_failure(401, path, Some("other")),
                "{path}"
            );
        }
        for path in [
            "/api/v1/auth/session",
            "/api/v1/admin/users",
            "/api/v1/auth/plugins/demo/proxy-other",
            "/api/v1/auth/plugins/demo/ui",
            "/plugins//proxy",
        ] {
            assert!(
                is_host_authentication_failure(401, path, Some("demo")),
                "{path}"
            );
        }
        for status in [0, 200, 403, 429, 503] {
            assert!(!is_host_authentication_failure(
                status,
                "/api/v1/auth/session",
                None
            ));
        }
    }
    #[test]
    fn csrf_rejection_requires_403_and_a_csrf_error_payload() {
        for data in [
            serde_json::json!({"code":"CSRF_TOKEN_INVALID"}),
            serde_json::json!({"message":"CSRF token mismatch"}),
            serde_json::json!({"message":"Missing csrf token"}),
            serde_json::json!({"error":"CsRf validation failed"}),
            serde_json::json!({"code":null,"message":"expired Csrf cookie"}),
        ] {
            assert!(is_csrf_rejection(403, &data), "{data}");
            for status in [0, 200, 400, 401, 404, 429, 500] {
                assert!(!is_csrf_rejection(status, &data), "{status}: {data}");
            }
        }
        for data in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"code":"FORBIDDEN","message":"Admin role required"}),
            serde_json::json!({"code":"NOT_CSRF_FAILURE"}),
            serde_json::json!({"code":403,"message":false,"error":{}}),
            serde_json::json!(["CSRF"]),
        ] {
            assert!(!is_csrf_rejection(403, &data), "{data}");
        }
    }
    #[test]
    fn post_refresh_response_can_recover_csrf_once() {
        let mut retries = RequestRetries::default();
        let path = "/api/v1/mcbrowser/files";
        let rejection = serde_json::json!({"code":"CSRF_TOKEN_MISMATCH"});
        assert!(retries.take_refresh(401, path));
        assert!(retries.take_csrf_retry(403, "PUT", path, None, &rejection));
        assert!(!retries.take_refresh(401, path));
        assert!(!retries.take_csrf_retry(403, "PUT", path, None, &rejection));
        assert!(!retries.take_refresh(200, path));
        assert!(!retries.take_csrf_retry(200, "PUT", path, None, &rejection));
    }
    #[test]
    fn csrf_recovery_can_precede_a_single_session_refresh() {
        let mut retries = RequestRetries::default();
        let path = "/plugins/example/action";
        let rejection = serde_json::json!({"message":"CSRF token expired"});
        assert!(retries.take_csrf_retry(403, "POST", path, None, &rejection));
        assert!(retries.take_refresh(401, path));
        assert!(!retries.take_csrf_retry(403, "POST", path, None, &rejection));
        // Failed refreshes consume their retry too, so an expired session cannot loop.
        assert!(!retries.take_refresh(401, path));
    }
    #[test]
    fn unrelated_forbidden_errors_and_exempt_routes_do_not_retry() {
        let mut retries = RequestRetries::default();
        let path = "/api/v1/admin/users";
        let rejection = serde_json::json!({"code":"CSRF_TOKEN_MISSING"});
        for (method, path, authorization) in [
            ("GET", path, None),
            ("HEAD", path, None),
            ("OPTIONS", path, None),
            ("POST", path, Some("Bearer token")),
            ("POST", "/api/v1/auth/refresh", None),
            ("POST", "/unrelated", None),
        ] {
            assert!(!retries.take_csrf_retry(403, method, path, authorization, &rejection));
        }
        assert!(!retries.take_csrf_retry(
            403,
            "POST",
            path,
            None,
            &serde_json::json!({"code":"FORBIDDEN","message":"Admin required"}),
        ));
        assert!(retries.take_csrf_retry(403, "POST", path, None, &rejection));
    }
    #[test]
    fn refresh_retries_exclude_login_refresh_logout_and_non_401_statuses() {
        let mut retries = RequestRetries::default();
        for path in [
            "/api/v1/public/auth/login",
            "/api/v1/public/auth/mfa/verify",
            "/api/v1/public/auth/setup",
            "/api/v1/auth/refresh",
            "/api/v1/public/auth/refresh",
            "/api/v1/auth/logout",
        ] {
            assert!(!retries.take_refresh(401, path), "{path}");
        }
        for status in [200, 400, 403, 404, 500] {
            assert!(!retries.take_refresh(status, "/api/v1/auth/session"));
        }
        assert!(retries.take_refresh(401, "/api/v1/auth/session"));
        assert!(!retries.take_refresh(401, "/api/v1/auth/session"));
    }

    struct ActiveServerGuard;
    impl ActiveServerGuard {
        fn new(server: Option<&str>) -> Self {
            set_active_server(server.map(str::to_string));
            Self
        }
    }
    impl Drop for ActiveServerGuard {
        fn drop(&mut self) {
            set_active_server(None);
        }
    }

    #[test]
    fn active_server_state_handles_local_active_switch_and_reset() {
        let _guard = ActiveServerGuard::new(None);
        assert_eq!(active_server(), None);
        assert_eq!(api_url("/api/v1/auth/services"), "/api/v1/auth/services");

        set_active_server(Some("media-2".into()));
        assert_eq!(active_server().as_deref(), Some("media-2"));
        assert_eq!(
            api_url("/api/v1/auth/services"),
            "/api/v1/peers/media-2/auth/services"
        );

        set_active_server(Some("  storage-3  ".into()));
        assert_eq!(active_server().as_deref(), Some("storage-3"));
        assert_eq!(
            api_url("/api/v1/auth/services"),
            "/api/v1/peers/storage-3/auth/services"
        );

        for blank in ["", "   ", "\t\n"] {
            set_active_server(Some(blank.into()));
            assert_eq!(active_server(), None, "{blank:?}");
            assert_eq!(api_url("/api/v1/auth/services"), "/api/v1/auth/services");
        }

        set_active_server(Some("media-2".into()));
        set_active_server(None);
        assert_eq!(active_server(), None);
        assert_eq!(api_url("/api/v1/auth/services"), "/api/v1/auth/services");
    }

    #[test]
    fn api_url_enforces_exact_boundaries_single_prefix_and_query_retention() {
        let _guard = ActiveServerGuard::new(Some("media-2"));

        for (input, expected) in [
            (
                "/api/v1/auth/services",
                "/api/v1/peers/media-2/auth/services",
            ),
            (
                "/api/v1/admin/users?page=2&limit=50",
                "/api/v1/peers/media-2/admin/users?page=2&limit=50",
            ),
            (
                "/api/v1/auth/deploy/stream?appName=mediaflow_engine",
                "/api/v1/peers/media-2/auth/deploy/stream?appName=mediaflow_engine",
            ),
            (
                "/api/v1/auth/fileshare/download/a%20b.zip?path=%2Fmedia#part",
                "/api/v1/peers/media-2/auth/fileshare/download/a%20b.zip?path=%2Fmedia#part",
            ),
            (
                "/api/v1/auth/ws/logs?unit=jellyfin.service&lines=200",
                "/api/v1/peers/media-2/auth/ws/logs?unit=jellyfin.service&lines=200",
            ),
            (
                "/api/v1/peers-other/status?x=1",
                "/api/v1/peers/media-2/peers-other/status?x=1",
            ),
            (
                "/api/v1/admin/peers-audit?limit=10",
                "/api/v1/peers/media-2/admin/peers-audit?limit=10",
            ),
        ] {
            let rewritten = api_url(input);
            assert_eq!(rewritten, expected, "{input}");
            // Re-running api_url on an already-prefixed path must be idempotent.
            assert_eq!(api_url(&rewritten), expected, "idempotent: {input}");
        }

        for unchanged in [
            "",
            "/health",
            "/health/ready",
            "/metrics",
            "/api/v1",
            "/api/v1?x=1",
            "/api/v1#top",
            "/api/v1/",
            "/api/v1/?x=1",
            "/api/v1/#top",
            "/api/v10/auth/services",
            "/api/v2/auth/services",
            "/api/auth/services",
            "/plugins/demo/proxy",
            "relative/api/v1/auth/services",
            "https://evil.example/api/v1/auth/services",
            "/api/v1/peers",
            "/api/v1/peers?include=health",
            "/api/v1/peers/",
            "/api/v1/peers/other-peer/auth/services?x=1",
            "/api/v1/peers/media-2/auth/services?x=1",
        ] {
            assert_eq!(api_url(unchanged), unchanged, "{unchanged}");
        }
    }

    #[test]
    fn api_url_keeps_admin_peer_controls_local() {
        let _guard = ActiveServerGuard::new(Some("media-2"));

        for path in [
            "/api/v1/admin/peers",
            "/api/v1/admin/peers?state=active",
            "/api/v1/admin/peers#links",
            "/api/v1/admin/peers/",
            "/api/v1/admin/peers/pair",
            "/api/v1/admin/peers/pairing-window",
            "/api/v1/admin/peers/media-2",
            "/api/v1/admin/peers/media-2/grant?preset=read",
            "/api/v1/admin/peers/media-2/endpoint",
            "/api/v1/admin/peers/transcode",
        ] {
            assert_eq!(api_url(path), path, "{path}");
        }

        assert_eq!(
            api_url("/api/v1/admin/users"),
            "/api/v1/peers/media-2/admin/users"
        );
        assert_eq!(
            api_url("/api/v1/admin/peers-other"),
            "/api/v1/peers/media-2/admin/peers-other"
        );
    }

    #[test]
    fn dashboard_auth_uses_the_local_session_when_a_peer_is_selected() {
        let _guard = ActiveServerGuard::new(Some("media-2"));

        for path in [
            "/api/v1/auth/session?details=1",
            "/api/v1/auth/logout",
            "/api/v1/auth/refresh",
            "/api/v1/auth/login",
            "/api/v1/auth/mfa/verify",
            "/api/v1/auth/setup/check",
            "/api/v1/auth/sessions",
            "/api/v1/auth/sessions/session-a",
            "/api/v1/auth/profile/password",
            "/api/v1/auth/user/2fa/verify",
            "/api/v1/auth/oidc/device/consent",
            "/api/v1/peer-pairing/request",
            "/api/v1/public/auth/setup",
            "/api/v1/public/auth/refresh",
            "/api/v1/public/auth/login",
            "/api/v1/public/auth/mfa/verify",
            "/api/v1/public/auth/google/login",
            "/api/v1/public/csrf-token",
            "/api/v1/csrf-token",
        ] {
            assert_eq!(api_url(path), path);
        }
        assert_eq!(
            api_url("/api/v1/auth/ws/ticket"),
            "/api/v1/peers/media-2/auth/ws/ticket"
        );
        assert!(allowed_during_auth_revalidation(
            &api_url("/api/v1/auth/session"),
            "GET"
        ));
    }

    #[test]
    fn malformed_active_server_ids_cannot_change_authority_or_add_path_segments() {
        let _guard = ActiveServerGuard::new(None);
        let base = url::Url::parse("https://local.example").unwrap();

        for dot_or_blank in ["", "   ", ".", "..", " . ", " .. "] {
            set_active_server(Some(dot_or_blank.into()));
            assert_eq!(active_server(), None, "{dot_or_blank:?}");
            assert_eq!(
                api_url("/api/v1/auth/services?limit=10"),
                "/api/v1/auth/services?limit=10"
            );
        }

        for raw_id in [
            "peer/evil",
            "../admin",
            "peer/../admin",
            "//evil.example",
            "https://evil.example:8443",
            "@evil.example",
            "peer\\evil",
            "peer?injected=1#frag",
            "peer#frag",
            "peer\r\nX-Injected: 1",
            "%2e%2e",
            "peer 1",
            "média-2",
        ] {
            set_active_server(Some(raw_id.into()));
            let rewritten = api_url("/api/v1/auth/services?limit=10");
            let expected_segment = percent_encode_header_component(raw_id.trim());
            assert_eq!(
                rewritten,
                format!("/api/v1/peers/{expected_segment}/auth/services?limit=10"),
                "{raw_id:?}"
            );
            assert!(validate_local_api_path(&rewritten).is_ok(), "{raw_id:?}");
            assert_eq!(api_url(&rewritten), rewritten, "idempotent: {raw_id:?}");

            let resolved = base.join(&rewritten).unwrap();
            assert_eq!(resolved.scheme(), "https", "{raw_id:?}");
            assert_eq!(resolved.host_str(), Some("local.example"), "{raw_id:?}");
            assert_eq!(resolved.port(), None, "{raw_id:?}");
            assert_eq!(resolved.query(), Some("limit=10"), "{raw_id:?}");
            assert_eq!(resolved.fragment(), None, "{raw_id:?}");
            let segments: Vec<&str> = resolved.path_segments().unwrap().collect();
            assert_eq!(
                segments,
                vec![
                    "api",
                    "v1",
                    "peers",
                    expected_segment.as_str(),
                    "auth",
                    "services"
                ],
                "{raw_id:?}"
            );
        }
    }

    #[test]
    fn request_boundary_rewrites_once_and_rejects_non_local_paths() {
        let _guard = ActiveServerGuard::new(None);

        assert_eq!(
            prepare_api_request_path("/api/v1/auth/services?x=1", "GET").unwrap(),
            "/api/v1/auth/services?x=1"
        );

        set_active_server(Some("media-2".into()));
        let once = prepare_api_request_path("/api/v1/auth/services?x=1", "GET").unwrap();
        assert_eq!(once, "/api/v1/peers/media-2/auth/services?x=1");
        assert_eq!(
            prepare_api_request_path(&once, "GET").unwrap(),
            "/api/v1/peers/media-2/auth/services?x=1"
        );
        assert_eq!(
            prepare_api_request_path("/api/v1/admin/peers/pair", "POST").unwrap(),
            "/api/v1/admin/peers/pair"
        );
        assert!(!allowed_during_auth_revalidation(
            "/api/v1/peers/media-2/auth/session",
            "GET"
        ));

        for non_local in [
            "",
            "relative/api/v1/auth/services",
            "https://evil.example/api/v1/auth/services",
            "http://evil.example/api/v1/peers/media-2/admin/users",
            "//evil.example/api/v1/auth/services",
            "/api/v1/auth/services\\evil",
            "/\\evil.example/api/v1/auth/services",
        ] {
            let err = prepare_api_request_path(non_local, "POST").unwrap_err();
            assert_eq!(
                err,
                ApiError {
                    status: 0,
                    message: "API path must be local".into(),
                    code: None,
                },
                "{non_local}"
            );
        }
    }

    #[test]
    fn malformed_root_relative_paths_are_rejected_before_routing() {
        for server in [None, Some("media-2")] {
            let _guard = ActiveServerGuard::new(server);
            for path in [
                "/api/v1/auth/a\tb",
                "/api/v1/auth/a\nb",
                "/api/v1/auth/a\rb",
                "/api/v1/auth/a\x7fb",
                "/api/v1/auth//settings",
                "/api/v1/./auth/settings",
                "/api/v1/peers/./status",
                "/api/v1/admin/peers/%2E%2e",
                "/api/v1/peers/media-2/%2e./status",
                "/api/v1/peers/media-2/.%2E/status",
            ] {
                assert!(prepare_api_request_path(path, "POST").is_err(), "{path:?}");
                assert_eq!(api_url(path), "#", "{path:?}");
            }
            assert!(prepare_api_request_path("/api/v1/auth/files?name=a%2F..%2Fb", "GET").is_ok());
        }
    }

    #[test]
    fn csrf_matches_valid_peer_prefixed_leaf_paths_without_broadening() {
        for leaf in [
            "auth/settings",
            "public/auth/setup",
            "admin/users",
            "ingress/apps/sonarr",
            "mcbrowser/files",
            "fileshare/upload",
            "oauth/authorize",
            "share/password",
        ] {
            let path = format!("/api/v1/peers/media-2/{leaf}");
            for method in ["POST", "PUT", "DELETE", "PATCH", "post"] {
                for input in [
                    path.clone(),
                    format!("{path}?download=1#fragment"),
                    format!("https://host{path}?download=1"),
                ] {
                    assert!(should_attach_csrf(method, &input, None), "{method} {input}");
                    for read in ["GET", "HEAD", "OPTIONS", "get"] {
                        assert!(!should_attach_csrf(read, &input, None), "{read} {input}");
                    }
                    assert!(!should_attach_csrf(method, &input, Some("Bearer token")));
                }
            }
            assert!(should_attach_csrf("POST", &path, Some("Basic token")));
        }

        // Local admin peer controls remain CSRF-protected on mutations.
        assert!(should_attach_csrf("POST", "/api/v1/admin/peers/pair", None));
        assert!(should_attach_csrf(
            "DELETE",
            "/api/v1/admin/peers/media-2",
            None
        ));

        // The managing server applies its refresh exemption only at the local endpoint.
        assert!(should_attach_csrf(
            "POST",
            "/api/v1/peers/media-2/auth/refresh",
            None
        ));
        assert!(should_attach_csrf(
            "POST",
            "/api/v1/peers/media-2/public/auth/refresh",
            None
        ));
        assert!(should_attach_csrf(
            "POST",
            "/api/v1/peers/media-2/auth/refresh/other",
            None
        ));

        // Unrelated, non-v1, double-prefixed, or malformed peer paths must not match.
        for path in [
            "/api/v1/peers/media-2",
            "/api/v1/peers/media-2/",
            "/api/v1/peers/media-2/unrelated",
            "/api/v1/peers/media-2/health",
            "/api/v1/peers/media-2/auth",
            "/api/v1/peers/media-2/auth-other/settings",
            "/api/v1/peers/media-2/admin-other/users",
            "/api/v1/peers/media-2/ingress-other/apps/sonarr",
            "/api/v1/peers/media-2/mcbrowser-other/files",
            "/api/v1/peers/media-2/fileshare-other/upload",
            "/api/v1/peers/media-2/oauth-other/authorize",
            "/api/v1/peers/media-2/share-other/password",
            "/api/v1/peers/media-2/plugins/example/action",
            "/api/v1/peers/media-2/api/admin/users",
            "/api/v1/peers/media-2/peers/other/admin/users",
            "/api/v1/peers//admin/users",
            "/api/v1/peers/./admin/users",
            "/api/v1/peers/../admin/users",
            "/api/v1/peers/%2e/admin/users",
            "/api/v1/peers/%2e%2e/admin/users",
            "/api/v1/peers/.%2e/admin/users",
            "/api/v1/peers/%2E./admin/users",
            "/api/v1/peers/media-2//admin/users",
            "/api/v1/peers/media-2\\evil/admin/users",
            "/api/v1/peers/media 2/admin/users",
            "/api/v1/peers-other/media-2/admin/users",
            "/api/peers/media-2/admin/users",
            "//evil.example/api/v1/peers/media-2/admin/users",
        ] {
            assert!(!should_attach_csrf("POST", path, None), "{path}");
        }

        // Peer-prefixed CSRF 403 recovers once, while peer scope denial does not retry.
        let mut retries = RequestRetries::default();
        let peer_path = "/api/v1/peers/media-2/admin/users";
        assert!(!retries.take_csrf_retry(
            403,
            "POST",
            peer_path,
            None,
            &serde_json::json!({"code":"PEER_SCOPE_DENIED","message":"Read-only grant"}),
        ));
        assert!(retries.take_csrf_retry(
            403,
            "POST",
            peer_path,
            None,
            &serde_json::json!({"error":"Invalid CSRF token"}),
        ));
        assert!(!retries.take_csrf_retry(
            403,
            "POST",
            peer_path,
            None,
            &serde_json::json!({"error":"Invalid CSRF token"}),
        ));
    }

    #[test]
    fn peer_upstream_auth_failures_retain_local_dashboard_session() {
        let peer_path = "/api/v1/peers/media-2/auth/services";
        assert_eq!(peer_proxy_id(peer_path).as_deref(), Some("media-2"));
        assert!(is_peer_proxy_path(peer_path));
        assert!(!is_peer_proxy_path("/api/v1/auth/services"));
        assert!(!is_peer_proxy_path("/api/v1/admin/peers/media-2"));

        // Matching peer proxy marker suppresses host auth expiry immediately.
        assert!(!should_treat_as_host_auth_failure(
            401,
            peer_path,
            None,
            Some("media-2"),
            None,
        ));
        // Confirmed healthy local session retains dashboard auth even without marker.
        assert!(!should_treat_as_host_auth_failure(
            401,
            peer_path,
            None,
            None,
            Some(true),
        ));
        // Mismatched marker with expired local session still expires host auth.
        assert!(should_treat_as_host_auth_failure(
            401,
            peer_path,
            None,
            Some("other-peer"),
            Some(false),
        ));
        // 403 peer authorization errors never expire host auth.
        assert!(!should_treat_as_host_auth_failure(
            403,
            peer_path,
            None,
            None,
            Some(false),
        ));
        // Local 401 continues to trigger normal host auth recovery/expiry.
        assert!(should_treat_as_host_auth_failure(
            401,
            "/api/v1/auth/services",
            None,
            None,
            Some(true),
        ));
    }

    #[test]
    fn server_epoch_tracks_server_switches_and_scopes_abortable_paths() {
        let _guard = ActiveServerGuard::new(None);
        let initial = current_server_epoch();

        // Setting the same server is a no-op.
        set_active_server(None);
        assert_eq!(current_server_epoch(), initial);

        set_active_server(Some("media-2".into()));
        let after_first = current_server_epoch();
        assert!(after_first > initial);
        assert!(ensure_same_server_epoch(after_first, after_first).is_ok());
        assert_eq!(
            ensure_same_server_epoch(initial, after_first)
                .unwrap_err()
                .code
                .as_deref(),
            Some("SERVER_CHANGED")
        );

        // Local auth and local peer management stay immune from server-scoped aborts.
        assert!(!is_server_scoped_path("/api/v1/auth/session"));
        assert!(!is_server_scoped_path("/api/v1/auth/refresh"));
        assert!(!is_server_scoped_path("/api/v1/public/csrf-token"));
        assert!(!is_server_scoped_path("/api/v1/admin/peers"));
        assert!(!is_server_scoped_path("/api/v1/admin/peers/media-2/grants"));
        assert!(!is_server_scoped_path("/health/ready"));

        // Dashboard and peer-proxied endpoints are server-scoped.
        assert!(is_server_scoped_path("/api/v1/auth/services"));
        assert!(is_server_scoped_path("/api/v1/admin/settings"));
        assert!(is_server_scoped_path("/api/v1/peers/media-2/auth/services"));
        assert!(is_server_scoped_path(
            "/api/v1/peers/media-2/auth/mcbrowser/uploads/0123456789abcdef0123456789abcdef"
        ));

        set_active_server(None);
        assert!(current_server_epoch() > after_first);
    }
}
