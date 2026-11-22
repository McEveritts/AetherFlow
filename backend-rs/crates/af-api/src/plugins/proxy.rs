use super::manifest::{find_validated_plugin, plugin_requires_admin};
use super::registry::try_read_registry_state;
use super::types::PROXY_HTTP_CLIENT;
use super::MAX_PLUGIN_PROXY_BODY_BYTES;
use crate::auth::{api_error, AuthUser};
use af_models::{PLUGIN_PORT_RANGE_END, PLUGIN_PORT_RANGE_START};
use axum::body::Body;
use axum::extract::{Extension, Path, Request};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// This internal response marker survives the routing and auth layers and cannot
// be supplied by an upstream plugin as an HTTP header. The outer security-header
// middleware uses it to isolate every proxied representation as a document.
#[derive(Clone, Copy)]
pub(crate) struct ProxiedPluginResponse;

fn mark_plugin_proxy_response(mut response: Response) -> Response {
    response.extensions_mut().insert(ProxiedPluginResponse);
    response
}

pub async fn proxy_plugin_root_handler(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    req: Request,
) -> Response {
    mark_plugin_proxy_response(proxy_plugin_request_inner(id, String::new(), auth_user, req).await)
}

pub async fn proxy_plugin_wildcard_handler(
    Path((id, rest)): Path<(String, String)>,
    Extension(auth_user): Extension<AuthUser>,
    req: Request,
) -> Response {
    mark_plugin_proxy_response(proxy_plugin_request_inner(id, rest, auth_user, req).await)
}

#[allow(clippy::result_large_err)]
pub(super) async fn collect_proxy_body(body: Body) -> Result<axum::body::Bytes, Response> {
    match axum::body::to_bytes(body, MAX_PLUGIN_PROXY_BODY_BYTES).await {
        Ok(bytes) => Ok(bytes),
        Err(error) => {
            use std::error::Error;
            if error
                .source()
                .is_some_and(|cause| cause.is::<http_body_util::LengthLimitError>())
            {
                Err(api_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "PAYLOAD_TOO_LARGE",
                    "Plugin proxy request body exceeds 2 MiB limit",
                ))
            } else {
                Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_BODY",
                    "Failed to read plugin proxy request body",
                ))
            }
        }
    }
}

#[allow(clippy::result_large_err)]
pub(super) async fn collect_proxy_response(
    mut upstream_resp: reqwest::Response,
) -> Result<Vec<u8>, Response> {
    let mut resp_bytes = Vec::new();
    loop {
        match upstream_resp.chunk().await {
            Ok(Some(chunk)) => {
                if resp_bytes.len().saturating_add(chunk.len()) > MAX_PLUGIN_PROXY_BODY_BYTES {
                    return Err(api_error(
                        StatusCode::BAD_GATEWAY,
                        "PLUGIN_RESPONSE_TOO_LARGE",
                        "Plugin upstream response exceeded maximum 2 MiB size limit",
                    ));
                }
                resp_bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                return Err(api_error(
                    StatusCode::BAD_GATEWAY,
                    "PLUGIN_READ_ERROR",
                    format!("Failed reading plugin response: {}", e),
                ));
            }
        }
    }

    Ok(resp_bytes)
}

async fn proxy_plugin_request_inner(
    id: String,
    subpath: String,
    auth_user: AuthUser,
    req: Request,
) -> Response {
    // Reject plugin tokens from calling the plugin proxy to prevent recursive proxy loops
    if auth_user.jti.starts_with("plg-") {
        return api_error(
            StatusCode::FORBIDDEN,
            "PLUGIN_PROXY_FORBIDDEN",
            "Plugin tokens cannot invoke the host plugin proxy",
        );
    }

    let manifest = match find_validated_plugin(&id) {
        Ok(m) => m,
        Err(response) => return *response,
    };

    if plugin_requires_admin(&manifest.permissions) {
        if let Err(response) = crate::auth::require_admin(&auth_user) {
            return *response;
        }
    }

    let state = match try_read_registry_state(&manifest.id) {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!(plugin = %manifest.id, %error, "Failed to read plugin registry state for proxy");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PLUGIN_REGISTRY_ERROR",
                "Failed to read plugin registry state",
            );
        }
    };
    if !state.enabled || state.status == "stopped" {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "PLUGIN_STOPPED",
            format!("Plugin '{}' is not enabled or running", manifest.id),
        );
    }

    let port = state.allocated_port;
    if !(PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&port) {
        return api_error(
            StatusCode::BAD_GATEWAY,
            "INVALID_UPSTREAM_PORT",
            "Plugin port is outside the permitted loopback range",
        );
    }

    let clean_subpath = subpath.trim_start_matches('/');
    let raw_uri_path = req.uri().path().to_ascii_lowercase();
    let lower_subpath = clean_subpath.to_ascii_lowercase();
    if clean_subpath.contains("..")
        || clean_subpath.contains('\\')
        || clean_subpath.starts_with("//")
        || lower_subpath.contains("%2e")
        || lower_subpath.contains("%2f")
        || lower_subpath.contains("%5c")
        || raw_uri_path.contains("..")
        || raw_uri_path.contains("%2e")
        || raw_uri_path.contains("%5c")
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_PROXY_PATH",
            "Path traversal in plugin proxy request is forbidden",
        );
    }

    let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    if !target_addr.ip().is_loopback() {
        return api_error(
            StatusCode::FORBIDDEN,
            "SSRF_BLOCKED",
            "Plugin upstream must resolve strictly to 127.0.0.1 loopback",
        );
    }

    let query_suffix = req
        .uri()
        .query()
        .filter(|q| !q.is_empty())
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let target_url = if clean_subpath.is_empty() {
        format!("http://127.0.0.1:{}/{}", port, query_suffix)
    } else {
        format!(
            "http://127.0.0.1:{}/{}{}",
            port, clean_subpath, query_suffix
        )
    };

    let method = req.method().clone();
    let req_headers = req.headers().clone();

    let body_bytes = match collect_proxy_body(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };

    let reqwest_method = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return api_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "INVALID_METHOD",
                "Unsupported HTTP method",
            )
        }
    };

    let mut upstream_req = PROXY_HTTP_CLIENT
        .request(reqwest_method, &target_url)
        .body(body_bytes.to_vec());

    // Forward safe headers ONLY — strip Cookie, Authorization, X-CSRF-Token, identity headers, and hop-by-hop headers
    for (name, val) in req_headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if lower.starts_with("x-aetherflow-")
            || matches!(
                lower.as_str(),
                "cookie"
                    | "authorization"
                    | "x-csrf-token"
                    | "remote-user"
                    | "x-remote-user"
                    | "x-forwarded-user"
                    | "x-forwarded-email"
                    | "x-forwarded-groups"
                    | "host"
                    | "connection"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
                    | "transfer-encoding"
                    | "upgrade"
                    | "content-length"
            )
        {
            continue;
        }
        if let (Ok(r_name), Ok(r_val)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(val.as_bytes()),
        ) {
            upstream_req = upstream_req.header(r_name, r_val);
        }
    }

    upstream_req = upstream_req
        .header("X-AetherFlow-Plugin-Id", &manifest.id)
        .header("X-AetherFlow-User", &auth_user.username)
        .header("X-AetherFlow-Role", &auth_user.role);

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            return api_error(
                StatusCode::BAD_GATEWAY,
                "PLUGIN_UPSTREAM_UNAVAILABLE",
                format!("Plugin '{}' upstream failed: {}", manifest.id, e),
            )
        }
    };

    // Block upstream redirects so plugins cannot redirect operators to external origins
    if upstream_resp.status().is_redirection() {
        return api_error(
            StatusCode::BAD_GATEWAY,
            "PLUGIN_REDIRECT_BLOCKED",
            "Plugin upstream redirects are disallowed by security policy",
        );
    }

    let status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let upstream_headers = upstream_resp.headers().clone();

    let resp_bytes = match collect_proxy_response(upstream_resp).await {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };

    let mut response = Response::builder()
        .status(status)
        .body(Body::from(resp_bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());

    let out_headers = response.headers_mut();
    for (name, val) in upstream_headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        // Never allow a plugin upstream to set cookies on the AetherFlow host origin!
        if matches!(
            lower.as_str(),
            "set-cookie"
                | "set-cookie2"
                | "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "upgrade"
                | "location"
                | "content-security-policy"
                | "x-frame-options"
        ) {
            continue;
        }
        if let (Ok(h_name), Ok(h_val)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(val.as_bytes()),
        ) {
            out_headers.insert(h_name, h_val);
        }
    }
    out_headers.insert(
        "X-AetherFlow-Proxied-Plugin",
        HeaderValue::from_str(&manifest.id).unwrap_or_else(|_| HeaderValue::from_static("plugin")),
    );

    response
}
