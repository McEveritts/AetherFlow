use super::PLUGIN_TOKEN_AUDIENCE;
use crate::auth::api_error;
use af_runner::PluginRunnerError;
use axum::http::StatusCode;
use axum::response::Response;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginScopeRule {
    pub method: String,
    pub route: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RawScopeEntry {
    Simple(String),
    Structured(PluginScopeRule),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginLifecycleHooks {
    #[serde(default)]
    pub on_start: String,
    #[serde(default)]
    pub on_stop: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginBackendSpec {
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub manifest_path: String,
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub binary_name: String,
    #[serde(default = "default_health_path")]
    pub health_path: String,
    #[serde(default = "default_port_allocation")]
    pub port_allocation: String,
}

fn default_health_path() -> String {
    "/healthz".to_string()
}

fn default_port_allocation() -> String {
    "dynamic".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginFrontendSpec {
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub bundle: String,
    #[serde(default = "default_frontend_slot")]
    pub slot: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

fn default_frontend_slot() -> String {
    "marketplace".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub sdk: String,
    #[serde(default)]
    pub contract_version: String,
    #[serde(default)]
    pub runtime_status: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub api_scopes: Vec<RawScopeEntry>,
    #[serde(default)]
    pub lifecycle_hooks: PluginLifecycleHooks,
    #[serde(default)]
    pub backend: PluginBackendSpec,
    #[serde(default)]
    pub frontend: PluginFrontendSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedPluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub sdk: String,
    pub contract_version: String,
    pub runtime_status: String,
    pub description: String,
    pub author: String,
    pub permissions: Vec<String>,
    pub granted_scopes: Vec<PluginScopeRule>,
    pub lifecycle_hooks: PluginLifecycleHooks,
    pub backend: PluginBackendSpec,
    pub frontend: PluginFrontendSpec,
    #[serde(skip)]
    pub plugin_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRegistryState {
    pub plugin_id: String,
    pub enabled: bool,
    pub allocated_port: u16,
    pub token_epoch: i64,
    pub status: String,
    pub last_health_at: Option<String>,
    pub last_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRuntimeView {
    pub id: String,
    pub name: String,
    pub version: String,
    pub sdk: String,
    pub contract_version: String,
    pub runtime_status: String,
    pub description: String,
    pub author: String,
    pub permissions: Vec<String>,
    pub granted_scopes: Vec<PluginScopeRule>,
    pub enabled: bool,
    pub status: String,
    pub healthy: bool,
    pub allocated_port: u16,
    pub health_path: String,
    pub ui_url: String,
    pub proxy_base_url: String,
    pub slot: String,
    pub capabilities: Vec<String>,
    pub last_health_at: Option<String>,
    pub last_error: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoped Short-Lived Plugin Token Claims & Validation
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginTokenClaims {
    pub typ: String,
    pub iss: String,
    #[serde(default = "default_plugin_aud")]
    pub aud: String,
    pub sub: String,
    pub plugin_id: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub epoch: i64,
    pub scopes: Vec<PluginScopeRule>,
}

fn default_plugin_aud() -> String {
    PLUGIN_TOKEN_AUDIENCE.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginLifecycleError {
    IsolationUnavailable(String),
    InvalidInput(String),
    Runtime(String),
}

impl std::fmt::Display for PluginLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IsolationUnavailable(msg) | Self::InvalidInput(msg) | Self::Runtime(msg) => {
                f.write_str(msg)
            }
        }
    }
}

impl std::error::Error for PluginLifecycleError {}

impl From<PluginRunnerError> for PluginLifecycleError {
    fn from(value: PluginRunnerError) -> Self {
        match value {
            PluginRunnerError::IsolationUnavailable(msg) => Self::IsolationUnavailable(msg),
            PluginRunnerError::InvalidRequest(msg) => Self::InvalidInput(msg),
            PluginRunnerError::Runtime(msg) => Self::Runtime(msg),
        }
    }
}

impl PluginLifecycleError {
    pub fn into_api_response(self) -> Response {
        match self {
            Self::IsolationUnavailable(msg) => api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "PLUGIN_ISOLATION_UNAVAILABLE",
                msg,
            ),
            Self::InvalidInput(msg) => {
                api_error(StatusCode::BAD_REQUEST, "INVALID_PLUGIN_CONFIG", msg)
            }
            Self::Runtime(msg) => api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PLUGIN_LIFECYCLE_ERROR",
                msg,
            ),
        }
    }
}

pub(super) struct ActivePluginRuntime {
    pub(super) port: u16,
    pub(super) runtime_id: Uuid,
    pub(super) monitor: Option<tokio::task::JoinHandle<()>>,
}

pub(super) static ACTIVE_PROCESSES: Lazy<Mutex<HashMap<String, ActivePluginRuntime>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
pub(super) static PLUGIN_LIFECYCLE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
pub(super) static PLUGIN_HEALTH: Lazy<Mutex<HashMap<String, (u16, bool)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
pub(super) static ACTIVE_PLUGIN_JTIS: Lazy<Mutex<HashMap<String, HashMap<String, i64>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
pub(super) static PROXY_HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(3))
        .no_proxy()
        .build()
        .expect("plugin proxy client")
});
