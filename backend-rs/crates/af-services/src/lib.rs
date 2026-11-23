pub mod lifecycle_cache;
pub mod mutators;
mod service_observations;
pub mod workers;

#[cfg(all(test, unix))]
mod http_lifecycle_regressions;
#[cfg(all(test, unix))]
mod inventory_regressions;
#[cfg(all(test, unix))]
mod native_metadata_regressions;
#[cfg(all(test, unix))]
mod readiness_regressions;

use af_models::{Package, PackageAutomation};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::process::Command;

// ─────────────────────────────────────────────────────────────────────────────
// Package Catalog, Automation & Marketplace Orchestration
// ─────────────────────────────────────────────────────────────────────────────

const EMBEDDED_PACKAGES_JSON: &str = include_str!("../../../../config/packages.json");
const EMBEDDED_AUTOMATION_JSON: &str = include_str!("../../../../config/package_automation.json");

mod package_jobs;
pub use package_jobs::*;
pub use workers::{
    cancel_inflight_mediaflow_job, is_path_within_allowed_mediaflow_roots, mediaflow_allowed_roots,
    mediaflow_allowed_roots_from_raw, open_and_pin_mediaflow_source,
    open_and_pin_mediaflow_source_in_roots, parse_stored_mediaflow_identity,
    publish_mediaflow_progress, subscribe_mediaflow_progress, CancelInflightOutcome,
    MediaflowSourceIdentity, PinnedMediaflowSource, DEFAULT_MEDIAFLOW_ROOTS,
    MEDIAFLOW_CANCELLED_MSG, MEDIAFLOW_MISSING_IDENTITY_MSG,
    MEDIAFLOW_SOURCE_CHANGED_BEFORE_EXEC_MSG, MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG,
};

mod blueprints;
mod catalog;
mod service_control;
mod service_status;
mod streaming;

pub use blueprints::{
    format_app_public_domain, get_all_blueprints, get_blueprint, is_package_installed,
    package_has_legacy_upgrade_receipt, package_receipt_port, resolve_app_internal_domain,
    resolve_base_domain, AppBlueprint, BlueprintSetupResult, BlueprintStatusView,
};

pub use catalog::{
    authorize_service_control_target, get_package_catalog, get_packages, get_packages_with_jobs,
    resolve_owning_package_id, CORE_SERVICE_IDS, PACKAGE_LIFECYCLE_MUTEX,
};
#[cfg(test)]
use catalog::{config_search_candidates, read_catalog_file, CATALOG_READ_COUNT};
use catalog::{
    launch_target, package_lock_installed, populate_package_core_statuses, INVENTORY_CORE_UNITS,
};

pub use service_control::{
    control_service, control_service_with_manager, is_service_control_timeout, runner_systemctl,
};
#[cfg(test)]
use service_control::{control_service_with_budget, guarded_service_command};

pub use service_status::{
    aggregate_component_statuses, classify_systemd_unit_show_output, clear_service_status_cache,
    format_uptime, format_uptime_duration, get_active_services, get_active_services_with_jobs,
    get_pm2_service_info, get_pm2_services, get_service_info, get_service_info_detailed,
    get_systemd_unit_info, is_rclone_vfs_configured, resolve_canonical_service_id,
    resolve_controllable_service_units, resolve_controllable_service_units_with,
    resolve_service_bind_scope, resolve_service_component_policies,
    resolve_service_component_policies_with, resolve_service_control_scope, resolve_service_units,
    resolve_service_web_scheme, service_bind_scope_for_id, service_web_scheme_for_id,
    should_pre_stop_on_update, ServiceComponentPolicy, ServiceComponentStatus, ServiceStatusItem,
};
use service_status::{
    async_status_command_output, get_pm2_services_with_timeout, is_zero_i32,
    pm2_service_info_from_observations, qbittorrent_bind_scope, query_systemd_unit_with_timeout,
    resolve_service_units_with_catalog, service_component_policies_with_catalog,
};
#[cfg(test)]
use service_status::{
    get_service_info_for_policies, policies_for_units, query_single_systemd_unit_status,
    SERVICE_INFO_CACHE,
};

pub use streaming::{
    forbidden_streaming_ip, is_streaming_demo_mode, set_streaming_demo_mode,
    streaming_http_client_builder, validate_server_url, ActiveStreamSession, BreakdownEntry,
    StreamTypeDistribution, StreamingAnalytics, StreamingDashboardResponse,
    StreamingHistoryEstimate, StreamingHistoryItem, StreamingLibraryCounts, StreamingLiveSummary,
    StreamingServerStatus, StreamingTimeSeriesPoint, StreamingTitleStat, StreamingUserStat,
};

// ─────────────────────────────────────────────────────────────────────────────
// Notifications & Rules
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Notification {
    pub id: i64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user_id: Option<i64>,
    pub level: String,
    pub title: String,
    pub message: String,
    pub read: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationRule {
    pub id: i64,
    pub name: String,
    pub condition_type: String,
    pub condition_value: String,
    pub level: String,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationChannel {
    pub id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub channel_type: String,
    pub config: serde_json::Value,
    pub enabled: bool,
    pub created_at: String,
}

pub fn list_notifications(
    user_id: i64,
    limit: i64,
    offset: i64,
) -> anyhow::Result<(Vec<Notification>, i64)> {
    let (rows, unread) = af_db::list_notifications_for_user(user_id, limit, offset)?;
    let list = rows
        .into_iter()
        .map(|row| Notification {
            id: row.id,
            user_id: row.user_id,
            level: row.level,
            title: row.title,
            message: row.message,
            read: row.read,
            created_at: row.created_at,
        })
        .collect();
    Ok((list, unread))
}

#[cfg(test)]
mod tests;
