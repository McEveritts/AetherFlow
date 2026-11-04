//! AetherFlow Rust Plugin SDK Template (`{{PLUGIN_ID}}` / `{{PLUGIN_NAME}}`)
//!
//! Operates as a host-managed or standalone companion HTTP service that communicates with
//! verified AetherFlow v4.0.0 HTTP routes using a short-lived scoped plugin token (`AETHERFLOW_PLUGIN_TOKEN`):
//! - `GET /api/v1/public/marketplace` (unauthenticated public catalog route)
//! - `GET /api/v1/auth/system/metrics` (authenticated via `Authorization: Bearer <scoped_plugin_token>`)

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

/// Placeholder plugin identifier replaced during scaffold instantiation.
pub const PLUGIN_ID: &str = "{{PLUGIN_ID}}";
/// Placeholder human-readable plugin name replaced during scaffold instantiation.
pub const PLUGIN_NAME: &str = "{{PLUGIN_NAME}}";

/// Verified AetherFlow v4.0.0 public marketplace endpoint (`backend-rs/crates/af-api/src/routes.rs`).
pub const PATH_PUBLIC_MARKETPLACE: &str = "/api/v1/public/marketplace";
/// Verified AetherFlow v4.0.0 authenticated system metrics endpoint (`backend-rs/crates/af-api/src/routes.rs`).
pub const PATH_AUTH_SYSTEM_METRICS: &str = "/api/v1/auth/system/metrics";
/// Verified AetherFlow v4.0.0 public liveness endpoint (`backend-rs/crates/af-api/src/routes.rs`).
pub const PATH_PUBLIC_HEALTH: &str = "/health";

/// Default base URL for the local AetherFlow Rust control plane (`aetherflow-api`).
pub const DEFAULT_API_BASE_URL: &str = "http://127.0.0.1:8080";
/// Default bind address for the standalone companion service.
pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1";
/// Default TCP port for the standalone companion service.
pub const DEFAULT_PLUGIN_PORT: u16 = 9123;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginConfig {
    pub api_base_url: String,
    pub bearer_token: Option<String>,
    pub bind_addr: String,
    pub port: u16,
}

impl PluginConfig {
    /// Loads configuration from environment variables with safe local defaults.
    pub fn from_env() -> Self {
        let raw_base = env::var("AETHERFLOW_API_BASE_URL").unwrap_or_default();
        let raw_token = env::var("AETHERFLOW_PLUGIN_TOKEN").ok();
        let bind_addr = env::var("PLUGIN_BIND_ADDR")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_BIND_ADDR.to_string());
        let port = env::var("PLUGIN_PORT")
            .ok()
            .and_then(|v| v.trim().parse::<u16>().ok())
            .filter(|&p| p > 0)
            .unwrap_or(DEFAULT_PLUGIN_PORT);

        Self {
            api_base_url: normalize_base_url(&raw_base),
            bearer_token: sanitize_token(raw_token.as_deref()),
            bind_addr,
            port,
        }
    }

    /// Formats the socket address string (`<bind_addr>:<port>`) and parses it.
    pub fn socket_addr(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        format!("{}:{}", self.bind_addr, self.port).parse()
    }
}

/// Normalizes the AetherFlow base URL by trimming whitespace and trailing slashes,
/// falling back to `http://127.0.0.1:8080` when empty.
pub fn normalize_base_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        DEFAULT_API_BASE_URL.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Strips placeholder or empty tokens so unconfigured templates do not send invalid headers.
pub fn sanitize_token(raw: Option<&str>) -> Option<String> {
    let token = raw?.trim();
    if token.is_empty()
        || token == "replace-me"
        || token == "replace-with-scoped-plugin-token"
        || token == "replace-with-operator-session-jwt"
    {
        None
    } else {
        Some(token.to_string())
    }
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid endpoint path '{0}': must start with '/'")]
    InvalidPath(String),
    #[error("missing AETHERFLOW_PLUGIN_TOKEN for authenticated route '{0}'")]
    MissingAuthToken(String),
    #[error("invalid authorization header value")]
    InvalidAuthHeader,
    #[error("HTTP transport error calling {url}: {source}")]
    Transport {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("AetherFlow API {status} at {url}: {body}")]
    UpstreamStatus {
        url: String,
        status: u16,
        body: String,
    },
    #[error("failed to decode JSON from {url}: {source}")]
    InvalidJson {
        url: String,
        #[source]
        source: serde_json::Error,
    },
}

/// HTTP client wrapper for verified AetherFlow v4.0.0 control-plane endpoints.
#[derive(Debug, Clone)]
pub struct AetherFlowClient {
    base_url: String,
    bearer_token: Option<String>,
    http: reqwest::Client,
}

impl AetherFlowClient {
    pub fn new(base_url: impl AsRef<str>, bearer_token: Option<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            base_url: normalize_base_url(base_url.as_ref()),
            bearer_token: sanitize_token(bearer_token.as_deref()),
            http,
        }
    }

    pub fn from_config(config: &PluginConfig) -> Self {
        Self::new(&config.api_base_url, config.bearer_token.clone())
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn has_bearer_token(&self) -> bool {
        self.bearer_token.is_some()
    }

    /// Constructs the full request URL for a verified control-plane path.
    pub fn endpoint_url(&self, path: &str) -> Result<String, ClientError> {
        let trimmed = path.trim();
        if !trimmed.starts_with('/') {
            return Err(ClientError::InvalidPath(trimmed.to_string()));
        }
        Ok(format!("{}{}", self.base_url, trimmed))
    }

    /// Builds request headers, attaching `Authorization: Bearer <token>` when present.
    pub fn build_headers(&self, require_auth: bool, path: &str) -> Result<HeaderMap, ClientError> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        match &self.bearer_token {
            Some(token) => {
                let raw = format!("Bearer {}", token);
                let header_val =
                    HeaderValue::from_str(&raw).map_err(|_| ClientError::InvalidAuthHeader)?;
                headers.insert(AUTHORIZATION, header_val);
            }
            None if require_auth => {
                return Err(ClientError::MissingAuthToken(path.to_string()));
            }
            None => {}
        }

        Ok(headers)
    }

    /// Performs a `GET` request against an AetherFlow JSON route.
    pub async fn get_json(&self, path: &str, require_auth: bool) -> Result<Value, ClientError> {
        let url = self.endpoint_url(path)?;
        let headers = self.build_headers(require_auth, path)?;

        let response = self
            .http
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|source| ClientError::Transport {
                url: url.clone(),
                source,
            })?;

        let status = response.status();
        let body_text = response.text().await.map_err(|source| ClientError::Transport {
            url: url.clone(),
            source,
        })?;

        if !status.is_success() {
            return Err(ClientError::UpstreamStatus {
                url,
                status: status.as_u16(),
                body: body_text.trim().to_string(),
            });
        }

        serde_json::from_str::<Value>(&body_text).map_err(|source| ClientError::InvalidJson {
            url,
            source,
        })
    }

    /// Queries the public marketplace catalog (`GET /api/v1/public/marketplace`).
    pub async fn get_public_marketplace(&self) -> Result<Value, ClientError> {
        self.get_json(PATH_PUBLIC_MARKETPLACE, false).await
    }

    /// Queries authenticated system metrics (`GET /api/v1/auth/system/metrics`).
    /// Requires a valid short-lived scoped plugin token in `AETHERFLOW_PLUGIN_TOKEN`.
    pub async fn get_system_metrics(&self) -> Result<Value, ClientError> {
        self.get_json(PATH_AUTH_SYSTEM_METRICS, true).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub status: String,
    pub plugin_id: String,
    pub plugin_name: String,
    pub sdk: String,
    pub runtime_mode: String,
    pub auth_token_configured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotResponse {
    pub plugin_id: String,
    pub runtime_mode: String,
    pub system_metrics: Option<Value>,
    pub system_metrics_notice: Option<String>,
    pub marketplace_count: Option<usize>,
}

/// Builds the Axum router for the plugin companion service.
pub fn build_router(client: Arc<AetherFlowClient>) -> Router {
    Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/status", get(healthz_handler))
        .route("/snapshot", get(snapshot_handler))
        .with_state(client)
}

async fn healthz_handler(State(client): State<Arc<AetherFlowClient>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        plugin_id: PLUGIN_ID.to_string(),
        plugin_name: PLUGIN_NAME.to_string(),
        sdk: "rust".to_string(),
        runtime_mode: "managed".to_string(),
        auth_token_configured: client.has_bearer_token(),
    })
}

async fn snapshot_handler(State(client): State<Arc<AetherFlowClient>>) -> Response {
    let marketplace = match client.get_public_marketplace().await {
        Ok(payload) => payload,
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": err.to_string(),
                    "plugin_id": PLUGIN_ID,
                })),
            )
                .into_response();
        }
    };

    let marketplace_count = marketplace
        .get("packages")
        .and_then(|v| v.as_array())
        .or_else(|| marketplace.as_array())
        .map(|arr| arr.len());

    let (system_metrics, system_metrics_notice) = if client.has_bearer_token() {
        match client.get_system_metrics().await {
            Ok(metrics) => (Some(metrics), None),
            Err(err) => (
                None,
                Some(format!(
                    "authenticated metrics request failed ({}): {}",
                    PATH_AUTH_SYSTEM_METRICS, err
                )),
            ),
        }
    } else {
        (
            None,
            Some(format!(
                "AETHERFLOW_PLUGIN_TOKEN not configured; skipped {} (plugin-scoped token minting is not yet active in backend-rs)",
                PATH_AUTH_SYSTEM_METRICS
            )),
        )
    };

    (
        StatusCode::OK,
        Json(SnapshotResponse {
            plugin_id: PLUGIN_ID.to_string(),
            runtime_mode: "standalone-companion".to_string(),
            system_metrics,
            system_metrics_notice,
            marketplace_count,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_base_urls_and_defaults() {
        assert_eq!(normalize_base_url(""), DEFAULT_API_BASE_URL);
        assert_eq!(normalize_base_url("   "), DEFAULT_API_BASE_URL);
        assert_eq!(
            normalize_base_url("http://127.0.0.1:8080/"),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            normalize_base_url("https://flow.example.com///"),
            "https://flow.example.com"
        );
    }

    #[test]
    fn sanitizes_placeholder_tokens() {
        assert_eq!(sanitize_token(None), None);
        assert_eq!(sanitize_token(Some("")), None);
        assert_eq!(sanitize_token(Some("replace-me")), None);
        assert_eq!(
            sanitize_token(Some("replace-with-operator-session-jwt")),
            None
        );
        assert_eq!(
            sanitize_token(Some("  eyJhbGciOiJIUzI1NiJ9.test.sig  ")),
            Some("eyJhbGciOiJIUzI1NiJ9.test.sig".to_string())
        );
    }

    #[test]
    fn verifies_aetherflow_v4_endpoint_paths_and_auth_headers() {
        let unauth_client = AetherFlowClient::new("http://127.0.0.1:8080/", None);
        assert_eq!(
            unauth_client.endpoint_url(PATH_PUBLIC_MARKETPLACE).unwrap(),
            "http://127.0.0.1:8080/api/v1/public/marketplace"
        );
        assert_eq!(
            unauth_client.endpoint_url(PATH_AUTH_SYSTEM_METRICS).unwrap(),
            "http://127.0.0.1:8080/api/v1/auth/system/metrics"
        );
        assert!(unauth_client.endpoint_url("api/system/metrics").is_err());

        // Public route succeeds without token
        let pub_headers = unauth_client
            .build_headers(false, PATH_PUBLIC_MARKETPLACE)
            .unwrap();
        assert!(pub_headers.get(AUTHORIZATION).is_none());

        // Protected route fails cleanly when token is omitted
        let err = unauth_client
            .build_headers(true, PATH_AUTH_SYSTEM_METRICS)
            .unwrap_err();
        assert!(matches!(err, ClientError::MissingAuthToken(_)));

        // Protected route attaches Bearer header when operator JWT is configured
        let auth_client = AetherFlowClient::new(
            "http://127.0.0.1:8080",
            Some("eyJhbGciOiJIUzI1NiJ9.operator.jwt".to_string()),
        );
        let auth_headers = auth_client
            .build_headers(true, PATH_AUTH_SYSTEM_METRICS)
            .unwrap();
        assert_eq!(
            auth_headers.get(AUTHORIZATION).unwrap().to_str().unwrap(),
            "Bearer eyJhbGciOiJIUzI1NiJ9.operator.jwt"
        );
    }
}
