//! Admin VPN HTTP contracts. All host operations cross the privileged runner.
use crate::auth::{api_error, AuthUser};
use af_models::NetworkRunnerRequest;
use axum::extract::{Extension, Path, Query};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

type CachedStatus = Option<(String, Instant, Value)>;
static STATUS: Lazy<Mutex<CachedStatus>> = Lazy::new(|| Mutex::new(None));
#[cfg(test)]
mod tests;

fn response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn request(action: &str) -> NetworkRunnerRequest {
    NetworkRunnerRequest {
        action: action.into(),
        ..Default::default()
    }
}

fn failure(error: impl std::fmt::Display) -> Response {
    let message = error.to_string();
    let (status, code) = if message.contains("NOT_FOUND:") {
        (StatusCode::NOT_FOUND, "NOT_FOUND")
    } else if message.contains("CONFLICT:") {
        (StatusCode::CONFLICT, "CONFLICT")
    } else if [
        "Invalid",
        "invalid",
        "must be",
        "must have",
        "required",
        "At most",
        "Too many",
        "No Tailscale settings",
        "Client addresses",
        "Network and broadcast",
        "Use the advertise",
        "Select an exit",
        "Exit node must",
        "Peer name",
        "Endpoint must",
        "Disable SaveConfig",
    ]
    .iter()
    .any(|text| message.contains(text))
    {
        (StatusCode::BAD_REQUEST, "INVALID_NETWORK_CONFIGURATION")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "NETWORK_OPERATION_FAILED")
    };
    let mut result = api_error(status, code, message);
    result
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    result
}

async fn runner(req: &NetworkRunnerRequest) -> anyhow::Result<Value> {
    let result = af_runner::dispatch_network_control(req).await?;
    let value: Value = serde_json::from_str(&result.output)?;
    if !value.is_object() {
        anyhow::bail!("Invalid network runner response");
    }
    Ok(value)
}

fn unavailable(error: &str) -> Value {
    let message = format!(
        "Privileged VPN runner is unavailable: {error}. Check aetherflow-runner in Services."
    );
    json!({"platform":std::env::consts::OS,"runner_available":false,
        "checked_at":chrono::Utc::now().to_rfc3339(),"wireguard_available":false,"tailscale_available":false,
        "wireguard":{"installed":false,"state":"error","error":message,"interface":"wg0","public_key":"",
            "listen_port":"","address":[],"peers":[],"service_state":"unknown","config_available":false},
        "tailscale":{"installed":false,"state":"error","error":message,"backend_state":"Unknown",
            "self":null,"peers":[],"health":[],"advertised_routes":[],"accept_routes":false,
            "advertise_exit_node":false,"exit_node":"","exit_node_allow_lan_access":false,
            "magic_dns":false,"route_approval":"managed_in_admin_console","service_state":"unknown"}})
}

async fn status() -> Value {
    let socket = af_runner::runner_socket_path();
    let mut cache = STATUS.lock().await;
    if let Some((key, at, value)) = &*cache {
        if *key == socket && at.elapsed() < Duration::from_secs(3) {
            return value.clone();
        }
    }
    let value = match runner(&request("network_status")).await {
        Ok(value) => value,
        Err(error) => unavailable(&error.to_string()),
    };
    *cache = Some((socket, Instant::now(), value.clone()));
    value
}

async fn mutate(req: NetworkRunnerRequest, user: AuthUser, created: bool) -> Response {
    let action = req.action.clone();
    let target = if req.public_key.is_empty() {
        req.subsystem.clone()
    } else {
        req.public_key.clone()
    };
    let result = runner(&req).await;
    // Invalidate on failures too: host-side recovery may have changed observed state.
    if action != "wg_keygen" {
        *STATUS.lock().await = None;
    }
    let success = result.is_ok();
    tokio::task::spawn_blocking(move || {
        af_db::record_audit(
            user.user_id,
            &user.username,
            &format!("network_{action}"),
            "network",
            &target,
            if success { "completed" } else { "failed" },
            "",
            "",
        )
    });
    match result {
        Ok(value) => response(
            if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            value,
        ),
        Err(error) => failure(error),
    }
}

pub async fn get_network_status() -> Response {
    response(StatusCode::OK, status().await)
}

async fn provider_status(provider: &str, peers_only: bool) -> Response {
    let all = status().await;
    let provider = &all[provider];
    if provider["state"] == "error" {
        return failure(
            provider["error"]
                .as_str()
                .unwrap_or("VPN status unavailable"),
        );
    }
    response(
        StatusCode::OK,
        if peers_only {
            json!({"peers":provider["peers"]})
        } else {
            provider.clone()
        },
    )
}

pub async fn get_wireguard_peers() -> Response {
    provider_status("wireguard", true).await
}
pub async fn get_tailscale_peers() -> Response {
    provider_status("tailscale", true).await
}
pub async fn get_tailscale_status() -> Response {
    provider_status("tailscale", false).await
}
pub async fn tailscale_routes() -> Response {
    provider_status("tailscale", false).await
}

pub async fn generate_wireguard_keys(Extension(user): Extension<AuthUser>) -> Response {
    mutate(request("wg_keygen"), user, false).await
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRequest {
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    allowed_ips: String,
    #[serde(default)]
    endpoint: String,
    persistent_keepalive: Option<u16>,
}

fn peer_request(action: &str, payload: PeerRequest) -> NetworkRunnerRequest {
    NetworkRunnerRequest {
        action: action.into(),
        public_key: payload.public_key,
        allowed_ips: payload.allowed_ips,
        endpoint: payload.endpoint,
        options: json!({"name":payload.name,"persistent_keepalive":payload.persistent_keepalive}),
        ..Default::default()
    }
}

pub async fn add_wireguard_peer(
    Extension(user): Extension<AuthUser>,
    Json(payload): Json<PeerRequest>,
) -> Response {
    mutate(peer_request("wg_add_peer", payload), user, true).await
}

pub async fn update_wireguard_peer(
    Path(key): Path<String>,
    Extension(user): Extension<AuthUser>,
    Json(mut payload): Json<PeerRequest>,
) -> Response {
    if !payload.public_key.is_empty() && payload.public_key != key {
        return failure("Invalid request: a peer public key cannot be changed");
    }
    payload.public_key = key;
    mutate(peer_request("wg_update_peer", payload), user, false).await
}

pub async fn remove_wireguard_peer(
    Path(key): Path<String>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let mut req = request("wg_remove_peer");
    req.public_key = key;
    mutate(req, user, false).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutesRequest {
    routes: Vec<String>,
}
pub async fn advertise_tailscale_routes(
    Extension(user): Extension<AuthUser>,
    Json(payload): Json<RoutesRequest>,
) -> Response {
    let mut req = request("tailscale_set_routes");
    req.routes = payload.routes;
    mutate(req, user, false).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectRequest {
    #[serde(default)]
    reauth: bool,
}
pub async fn tailscale_connect(
    Extension(user): Extension<AuthUser>,
    Json(payload): Json<ConnectRequest>,
) -> Response {
    let mut req = request("tailscale_connect");
    req.options = json!({"reauth":payload.reauth});
    mutate(req, user, false).await
}
pub async fn tailscale_disconnect(Extension(user): Extension<AuthUser>) -> Response {
    mutate(request("tailscale_disconnect"), user, false).await
}
pub async fn tailscale_logout(Extension(user): Extension<AuthUser>) -> Response {
    mutate(request("tailscale_logout"), user, false).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsRequest {
    accept_routes: Option<bool>,
    advertise_exit_node: Option<bool>,
    exit_node: Option<String>,
    exit_node_allow_lan_access: Option<bool>,
}
pub async fn tailscale_settings(
    Extension(user): Extension<AuthUser>,
    Json(payload): Json<SettingsRequest>,
) -> Response {
    let mut options = serde_json::Map::new();
    if let Some(value) = payload.accept_routes {
        options.insert("accept_routes".into(), json!(value));
    }
    if let Some(value) = payload.advertise_exit_node {
        options.insert("advertise_exit_node".into(), json!(value));
    }
    if let Some(value) = payload.exit_node {
        options.insert("exit_node".into(), json!(value));
    }
    if let Some(value) = payload.exit_node_allow_lan_access {
        options.insert("exit_node_allow_lan_access".into(), json!(value));
    }
    if options.is_empty() {
        return failure("Invalid request: no Tailscale settings supplied");
    }
    let mut req = request("tailscale_settings");
    req.options = Value::Object(options);
    mutate(req, user, false).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRequest {
    action: String,
}
pub async fn network_service(
    Path(provider): Path<String>,
    Extension(user): Extension<AuthUser>,
    Json(payload): Json<ServiceRequest>,
) -> Response {
    if !matches!(provider.as_str(), "wireguard" | "tailscale")
        || !matches!(payload.action.as_str(), "start" | "stop" | "restart")
    {
        return failure("Invalid VPN service or action");
    }
    let mut req = request("network_service");
    req.subsystem = provider;
    req.options = json!({"service_action":payload.action});
    mutate(req, user, false).await
}

#[derive(Deserialize)]
pub struct DiagnosticsQuery {
    provider: String,
}
pub async fn network_diagnostics(Query(query): Query<DiagnosticsQuery>) -> Response {
    if !matches!(query.provider.as_str(), "wireguard" | "tailscale") {
        return failure("Invalid VPN provider");
    }
    let mut req = request("network_diagnostics");
    req.subsystem = query.provider;
    match runner(&req).await {
        Ok(value) => response(StatusCode::OK, value),
        Err(error) => failure(error),
    }
}
