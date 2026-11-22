use serde::{Deserialize, Serialize};

/// Ports available for configurable marketplace apps when their default is busy.
pub const MARKETPLACE_FALLBACK_PORT_RANGE: [i32; 2] = [17000, 19999];
/// Secondary port role persisted for Rclone split-port GUI `--api-addr`.
pub const RCLONE_RC_API_PORT_ROLE: &str = "rc_api";
/// Preferred secondary RC API port for Rclone split-port GUI mode when GUI is not on 5573.
pub const RCLONE_DEFAULT_RC_API_PORT: i32 = 5573;
/// Alternate preferred secondary RC API port when Rclone's GUI itself is bound to 5573.
pub const RCLONE_ALT_RC_API_PORT: i32 = 5574;

// ─────────────────────────────────────────────────────────────────────────────
// Marketplace & Package Automation Models
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Package {
    pub name: String,
    pub label: String,
    pub description: String,
    pub lock_file: String,
    pub category: String,

    #[serde(default)]
    pub hits: i32,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub service_type: String,
    #[serde(default)]
    pub service_name: String,
    #[serde(skip_serializing_if = "crate::is_zero_i32", default)]
    pub default_port: i32,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub web_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_scope: Option<String>,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_source: String,
    #[serde(default)]
    pub require_download_sha256: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_repo: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_repo_url: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_package: String,
    #[serde(default)]
    pub update_channel: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub version_command: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub version_regex: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub sandbox_profile: String,
    #[serde(
        rename = "sandbox_rw_paths",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub sandbox_read_write: Vec<String>,
    #[serde(
        rename = "sandbox_service_units",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub sandbox_service_ids: Vec<String>,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub installed_version: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub latest_version: String,
    #[serde(default)]
    pub update_available: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_checked_at: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_url: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PackageAutomation {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_source: String,
    #[serde(default)]
    pub require_download_sha256: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_repo: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_repo_url: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_package: String,
    #[serde(default)]
    pub update_channel: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub version_command: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub version_regex: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub sandbox_profile: String,
    #[serde(
        rename = "sandbox_rw_paths",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub sandbox_read_write: Vec<String>,
    #[serde(
        rename = "sandbox_service_units",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub sandbox_service_ids: Vec<String>,
}

/// Applies the automation policy for a catalog entry, if one is defined.
pub fn merge_package_automation(package: &mut Package, automation: &PackageAutomation) {
    package.update_source = automation.update_source.clone();
    package.require_download_sha256 = automation.require_download_sha256;
    package.update_repo = automation.update_repo.clone();
    package.update_repo_url = automation.update_repo_url.clone();
    package.update_package = automation.update_package.clone();
    package.update_channel = automation.update_channel.clone();
    package.version_command = automation.version_command.clone();
    package.version_regex = automation.version_regex.clone();
    package.sandbox_profile = automation.sandbox_profile.clone();
    package.sandbox_read_write = automation.sandbox_read_write.clone();
    package.sandbox_service_ids = automation.sandbox_service_ids.clone();
}

/// The server resolved the app's launch target and found no usable route.
pub const APP_LAUNCH_SCOPE_UNAVAILABLE: &str = "unavailable";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MarketplaceApp {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub job_id: Option<String>,
    pub id: String,
    pub name: String,
    pub desc: String,
    pub hits: i32,
    pub category: String,
    pub status: String,
    #[serde(skip_serializing_if = "crate::is_zero_i32", default)]
    pub default_port: i32,
    #[serde(skip_serializing_if = "crate::is_zero_i32", default)]
    pub active_port: i32,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub internal_domain: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub public_domain: String,
    #[serde(default)]
    pub external_access_enabled: bool,
    #[serde(default)]
    pub tls_enabled: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub web_path: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub bind_scope: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub web_scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_scope: Option<String>,
    pub progress: i32,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub log_line: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub installed_version: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub latest_version: String,
    #[serde(default)]
    pub update_available: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_checked_at: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_url: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_error: String,
    #[serde(default)]
    pub inventory_known: bool,
    #[serde(skip_serializing_if = "crate::is_false", default)]
    pub inventory_authenticated: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub inventory_mode: String,
    /// True only on authenticated inventory when an uninstalled, idle package
    /// has positive AetherFlow retained-ownership evidence eligible for explicit
    /// purge via `POST /api/v1/admin/packages/:id/uninstall?purge=true`.
    #[serde(skip_serializing_if = "crate::is_false", default)]
    pub retained_data_present: bool,
    /// Terminal outcome of the most recent lifecycle job. Deliberately carries
    /// no error text because this catalog is served without authentication;
    /// failure detail is available from the authenticated progress endpoint.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_job: Option<MarketplaceJobOutcome>,
}

pub const INVENTORY_MODE_AUTHENTICATED: &str = "authenticated";
pub const INVENTORY_MODE_PUBLIC_REDACTED: &str = "public_redacted";
pub const INVENTORY_MODE_HEADER: &str = "X-AetherFlow-Inventory-Mode";
pub const INVENTORY_AUTHENTICATED_HEADER: &str = "X-AetherFlow-Inventory-Authenticated";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MarketplaceJobOutcome {
    pub job_id: String,
    pub action: String,
    /// `completed` or `failed`.
    pub status: String,
    pub started_at: String,
    pub finished_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_target_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub achieved_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sanitized_summary: Option<String>,
}

pub type MarketplaceLastJob = MarketplaceJobOutcome;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PackageLifecycleRecord {
    pub package_id: String,
    pub job_id: String,
    pub action: String,
    pub status: String,
    pub started_at: String,
    #[serde(default)]
    pub finished_at: String,
    #[serde(default)]
    pub owner_id: String,
    #[serde(default)]
    pub service_units: Vec<String>,
    #[serde(default)]
    pub failure_category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sanitized_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_target_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub achieved_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PackageJobOutcomeRecord {
    pub job_id: String,
    pub package_id: String,
    pub action: String,
    /// completed, failed, or interrupted (completion could not be confirmed).
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub message: String,
    pub started_at: String,
    pub finished_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sanitized_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_target_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub achieved_version: Option<String>,
    /// Durable rollback/recovery confirmation for failed in-place operations
    /// (e.g. `"prior_state_verified"`). Empty/None always fails closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_state: Option<String>,
}
