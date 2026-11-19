use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static AUTH_EPOCH: AtomicU64 = AtomicU64::new(0);
static AUTH_REVALIDATING: AtomicBool = AtomicBool::new(false);

pub fn current_auth_epoch() -> u64 {
    AUTH_EPOCH.load(Ordering::SeqCst)
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
    .any(|prefix| path.starts_with(prefix))
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
    use std::cell::RefCell;
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
        static ACTIVE_CONTROLLERS: RefCell<std::collections::BTreeMap<u64, web_sys::AbortController>> = const { RefCell::new(std::collections::BTreeMap::new()) };
    }
    #[cfg(target_arch = "wasm32")]
    static NEXT_CONTROLLER_ID: AtomicU64 = AtomicU64::new(0);

    struct RequestAbort {
        controller: web_sys::AbortController,
        _caller_abort: Option<gloo_events::EventListener>,
        finished: bool,
        #[cfg(target_arch = "wasm32")]
        id: u64,
    }
    impl RequestAbort {
        fn new(signal: Option<&web_sys::AbortSignal>) -> Result<Self, ApiError> {
            let controller = web_sys::AbortController::new().map_err(js_error)?;
            let caller_abort = signal.map(|signal| {
                if signal.aborted() {
                    controller.abort();
                }
                let controller = controller.clone();
                gloo_events::EventListener::new(signal, "abort", move |_| controller.abort())
            });
            #[cfg(target_arch = "wasm32")]
            let id = NEXT_CONTROLLER_ID.fetch_add(1, Ordering::Relaxed);
            #[cfg(target_arch = "wasm32")]
            ACTIVE_CONTROLLERS.with(|controllers| {
                controllers.borrow_mut().insert(id, controller.clone());
            });
            Ok(Self {
                controller,
                _caller_abort: caller_abort,
                finished: false,
                #[cfg(target_arch = "wasm32")]
                id,
            })
        }

        fn ensure_active(&self, origin_epoch: u64) -> Result<(), ApiError> {
            ensure_same_auth_epoch(origin_epoch, current_auth_epoch())?;
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
        for controller in controllers.into_values() {
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
        // Cookie/CSRF transports are local-origin only, including caller-supplied paths.
        if !path.starts_with('/') || path.starts_with("//") || path.contains('\\') {
            return Err(ApiError {
                status: 0,
                message: "API path must be local".into(),
                code: None,
            });
        }
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
                        let mut request = RequestAbort::new(None)?;
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
    async fn refresh() -> Result<bool, ApiError> {
        let origin_epoch = current_auth_epoch();
        let future = REFRESH.with(|slot| {
            slot.borrow_mut()
                .get_or_insert_with(|| {
                    async move {
                        let mut request = RequestAbort::new(None)?;
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
            let request = RequestAbort::new(None)?;
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
            ensure_auth_request_allowed(path, method)?;
            let request = RequestAbort::new(None)?;
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
                if is_host_authentication_failure(
                    response.status(),
                    path,
                    response
                        .headers()
                        .get("X-AetherFlow-Proxied-Plugin")
                        .ok()
                        .flatten()
                        .as_deref(),
                ) && retries.take_refresh(response.status(), path)
                {
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
            if is_host_authentication_failure(
                response.status(),
                path,
                response
                    .headers()
                    .get("X-AetherFlow-Proxied-Plugin")
                    .ok()
                    .flatten()
                    .as_deref(),
            ) && !is_login_endpoint(path)
            {
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
            ensure_auth_request_allowed(path, method)?;
            let origin_epoch = current_auth_epoch();
            let request = RequestAbort::new(signal)?;
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
            if !path.starts_with('/') || path.starts_with("//") || path.contains('\\') {
                return Err(ApiError {
                    status: 0,
                    message: "API path must be local".into(),
                    code: None,
                });
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
                if is_host_authentication_failure(
                    response.status(),
                    path,
                    response
                        .headers()
                        .get("X-AetherFlow-Proxied-Plugin")
                        .ok()
                        .flatten()
                        .as_deref(),
                ) && retries.take_refresh(response.status(), path)
                {
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
            if is_host_authentication_failure(
                response.status(),
                path,
                response
                    .headers()
                    .get("X-AetherFlow-Proxied-Plugin")
                    .ok()
                    .flatten()
                    .as_deref(),
            ) && !is_login_endpoint(path)
            {
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
}
