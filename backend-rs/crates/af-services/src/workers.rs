//! Background Orchestration Workers.
//!
//! Provides four background tasks and on-demand package update utilities:
//! 1. [`start_metrics_recorder`] — 60-second system metrics snapshotter & hourly 90-day retention pruner.
//! 2. [`start_heal_worker`] — `af-heal` systemd service watchdog with exponential backoff (`10s * 2^attempt`, max 3 retries), pending-action approval queuing (default `AF_HEAL_AUTO_APPROVE=false`), and admin notifications.
//! 3. [`start_smart_backup_scheduler`] — 30-minute scheduled SQLite online backup (`VACUUM INTO` + `.sha256` sidecar).
//! 4. [`start_app_update_watcher`] & [`refresh_all_package_updates`] / [`refresh_package_update_by_id`] / [`get_package_update_map`] —
//!    upstream GitHub / apt / git-tag release checker and thread-safe update cache.

use af_models::Package;
use af_release::lifecycle::libc;
use chrono::{Timelike, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};
use tokio::process::Command;

// ─────────────────────────────────────────────────────────────────────────────
// 1. Metrics History Recorder
// ─────────────────────────────────────────────────────────────────────────────

static METRICS_RECORDER_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Spawns a background tokio task (60-second interval) that samples
/// [`af_hardware::get_system_metrics_core()`], computes CPU usage, memory/swap
/// percentages, disk read/write MB/s, and network rx/tx MB/s, inserts a row into
/// `metrics_history`, and prunes rows older than 90 days every hour.
pub fn start_metrics_recorder() {
    start_mediaflow_poller();
    if METRICS_RECORDER_ACTIVE.swap(true, Ordering::SeqCst) {
        return;
    }

    tokio::spawn(async move {
        tracing::info!(
            interval_secs = 60,
            retention_days = 90,
            "metrics recorder initialized"
        );

        ensure_metrics_history_columns();

        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        // Skip immediate burst tick so initial sample happens after first interval or startup settle
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut last_prune = Instant::now();
        let mut prev_net_rx: Option<u64> = None;
        let mut prev_net_tx: Option<u64> = None;
        let mut prev_sample_at: Option<Instant> = None;

        loop {
            ticker.tick().await;

            record_metrics_snapshot(&mut prev_net_rx, &mut prev_net_tx, &mut prev_sample_at);

            if last_prune.elapsed() >= Duration::from_secs(3600) {
                prune_old_metrics();
                last_prune = Instant::now();
            }
        }
    });
}

/// Ensures the `metrics_history` table has both the extended columns requested by
/// the Rust telemetry schema (`cpu_usage`, `memory_pct`, `swap_pct`, `disk_read_mb`,
/// `disk_write_mb`, `net_rx_mb`, `net_tx_mb`) and the legacy Go columns so all queries succeed.
fn ensure_metrics_history_columns() {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };

    ensure_metrics_history_columns_with_connection(&conn);
}

fn ensure_metrics_history_columns_with_connection(conn: &rusqlite::Connection) {
    let alter_stmts = [
        "ALTER TABLE metrics_history ADD COLUMN cpu_usage REAL DEFAULT 0;",
        "ALTER TABLE metrics_history ADD COLUMN memory_pct REAL DEFAULT 0;",
        "ALTER TABLE metrics_history ADD COLUMN swap_pct REAL DEFAULT 0;",
        "ALTER TABLE metrics_history ADD COLUMN disk_read_mb REAL DEFAULT 0;",
        "ALTER TABLE metrics_history ADD COLUMN disk_write_mb REAL DEFAULT 0;",
        "ALTER TABLE metrics_history ADD COLUMN net_rx_mb REAL DEFAULT 0;",
        "ALTER TABLE metrics_history ADD COLUMN net_tx_mb REAL DEFAULT 0;",
        "CREATE INDEX IF NOT EXISTS idx_metrics_history_ts_id ON metrics_history(timestamp DESC, id DESC);",
        "CREATE INDEX IF NOT EXISTS idx_metrics_history_norm_ts_id ON metrics_history(replace(CAST(timestamp AS TEXT), 'T', ' ') DESC, id DESC);",
    ];

    for stmt in alter_stmts {
        let _ = conn.execute_batch(stmt);
    }
}

fn record_metrics_snapshot(
    prev_net_rx: &mut Option<u64>,
    prev_net_tx: &mut Option<u64>,
    prev_sample_at: &mut Option<Instant>,
) {
    let metrics = af_hardware::get_system_metrics_core();
    let now_inst = Instant::now();
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let cpu_usage = af_hardware::sanitize_f64(metrics.cpu_usage);

    let mem_used_gb = metrics.memory.get("used").copied().unwrap_or(0.0);
    let mem_total_gb = metrics.memory.get("total").copied().unwrap_or(0.0);
    let memory_pct = if mem_total_gb > 0.0 {
        af_hardware::sanitize_f64(((mem_used_gb / mem_total_gb) * 100.0).clamp(0.0, 100.0))
    } else {
        0.0
    };

    let swap_used_gb = metrics.swap.get("used").copied().unwrap_or(0.0);
    let swap_total_gb = metrics.swap.get("total").copied().unwrap_or(0.0);
    let swap_pct = if swap_total_gb > 0.0 {
        af_hardware::sanitize_f64(((swap_used_gb / swap_total_gb) * 100.0).clamp(0.0, 100.0))
    } else {
        0.0
    };

    let disk_read_bps = metrics
        .disk_io
        .get("read_bytes_sec")
        .copied()
        .unwrap_or(0.0);
    let disk_write_bps = metrics
        .disk_io
        .get("write_bytes_sec")
        .copied()
        .unwrap_or(0.0);
    let disk_read_mb = af_hardware::sanitize_f64(disk_read_bps / (1024.0 * 1024.0));
    let disk_write_mb = af_hardware::sanitize_f64(disk_write_bps / (1024.0 * 1024.0));

    let total_rx = metrics.total_net_bytes.get("rx").copied().unwrap_or(0);
    let total_tx = metrics.total_net_bytes.get("tx").copied().unwrap_or(0);

    let (net_rx_mb, net_tx_mb) = match (*prev_net_rx, *prev_net_tx, *prev_sample_at) {
        (Some(last_rx), Some(last_tx), Some(last_at)) => {
            let dt = now_inst.duration_since(last_at).as_secs_f64().max(1.0);
            let rx_mb_s = (total_rx.saturating_sub(last_rx) as f64) / (1024.0 * 1024.0 * dt);
            let tx_mb_s = (total_tx.saturating_sub(last_tx) as f64) / (1024.0 * 1024.0 * dt);
            (
                af_hardware::sanitize_f64(rx_mb_s),
                af_hardware::sanitize_f64(tx_mb_s),
            )
        }
        _ => (
            parse_speed_str_to_mb_s(
                metrics
                    .network
                    .get("down")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0 B/s"),
            ),
            parse_speed_str_to_mb_s(
                metrics
                    .network
                    .get("up")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0 B/s"),
            ),
        ),
    };

    *prev_net_rx = Some(total_rx);
    *prev_net_tx = Some(total_tx);
    *prev_sample_at = Some(now_inst);

    let load_avg_1 = metrics.load_average.first().copied().unwrap_or(0.0);
    let active_conns = metrics
        .network
        .get("active_connections")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    let Ok(conn) = af_db::get_conn() else {
        return;
    };

    let res = conn.execute(
        "INSERT INTO metrics_history (
            timestamp, cpu_usage, memory_pct, swap_pct, disk_read_mb, disk_write_mb, net_rx_mb, net_tx_mb,
            cpu_avg, mem_used_gb, mem_total_gb, disk_read_bps, disk_write_bps, net_rx_bytes, net_tx_bytes, load_avg_1, active_conns
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?2, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            timestamp,
            cpu_usage,
            memory_pct,
            swap_pct,
            disk_read_mb,
            disk_write_mb,
            net_rx_mb,
            net_tx_mb,
            mem_used_gb,
            mem_total_gb,
            disk_read_bps,
            disk_write_bps,
            total_rx as i64,
            total_tx as i64,
            load_avg_1,
            active_conns,
        ],
    );

    if let Err(err) = res {
        tracing::error!(error = %err, "metrics recorder: failed to store snapshot");
    }
}

fn parse_speed_str_to_mb_s(raw: &str) -> f64 {
    let cleaned = raw.trim().trim_end_matches("/s").trim();
    let mut parts = cleaned.split_whitespace();
    let Some(val_str) = parts.next() else {
        return 0.0;
    };
    let Ok(val) = val_str.parse::<f64>() else {
        return 0.0;
    };
    let unit = parts.next().unwrap_or("B").to_uppercase();
    let mult = match unit.as_str() {
        "B" => 1.0 / (1024.0 * 1024.0),
        "KB" | "KIB" => 1.0 / 1024.0,
        "MB" | "MIB" => 1.0,
        "GB" | "GIB" => 1024.0,
        "TB" | "TIB" => 1024.0 * 1024.0,
        _ => 0.0,
    };
    af_hardware::sanitize_f64(val * mult)
}

fn prune_old_metrics() {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    match conn.execute(af_db::PRUNE_METRICS_HISTORY_SQL, []) {
        Ok(rows) if rows > 0 => {
            tracing::info!(
                count = rows,
                retention = "90d",
                "metrics recorder: pruned old entries"
            );
        }
        Err(err) => {
            tracing::error!(error = %err, "metrics recorder: failed to prune old entries");
        }
        _ => {}
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Auto-Heal Worker `af_heal`
// ─────────────────────────────────────────────────────────────────────────────

static HEAL_WORKER_ACTIVE: AtomicBool = AtomicBool::new(false);

const MAX_HEAL_RETRIES: u32 = 3;
const BASE_BACKOFF_SECS: u64 = 10;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ServiceHealState {
    failure_count: u32,
    next_retry_at: Option<Instant>,
    exhausted: bool,
}

static HEAL_STATES: Lazy<Mutex<HashMap<String, ServiceHealState>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Spawns the `af-heal` background recovery worker (`interval_secs` interval, e.g., 10s).
///
/// Checks critical managed systemd services (`apache2`, `aetherflow-runner`, plus any
/// installed systemd apps whose lockfile exists in `/install/`), tracks failure counts
/// and exponential backoff (`10s * 2^attempt`, max 3 retries before marking `exhausted`
/// until the service recovers). When `AF_HEAL_AUTO_APPROVE` is `false` (default), queues
/// deduplicated restart requests in `pending_actions` (capped at 50 pending entries); when
/// `AF_HEAL_AUTO_APPROVE=true` (`1` / `true`), dispatches [`af_runner::dispatch_heal_restart`].
/// Delivers warning/error notifications to all admin users via [`notify_all_admin_users`].
pub fn start_heal_worker(interval_secs: u64) {
    if HEAL_WORKER_ACTIVE.swap(true, Ordering::SeqCst) {
        return;
    }

    let period = Duration::from_secs(interval_secs.max(1));

    tokio::spawn(async move {
        tracing::info!(
            interval_secs = period.as_secs(),
            max_retries = MAX_HEAL_RETRIES,
            "af-heal recovery orchestrator initialized"
        );

        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            perform_heal_check().await;
        }
    });
}

fn resolve_fs_path(path_str: &str) -> PathBuf {
    resolve_installed_path(Path::new(path_str))
}

fn resolve_installed_path(path: &Path) -> PathBuf {
    for env_key in ["AETHERFLOW_FS_ROOT", "AETHERFLOW_INSTALL_ROOT"] {
        if let Ok(root) = env::var(env_key) {
            let trimmed = root.trim();
            if !trimmed.is_empty() {
                let root_path = Path::new(trimmed);
                if path.starts_with(root_path) {
                    return path.to_path_buf();
                }
                let path_str = path.to_string_lossy();
                let rel = path_str.trim_start_matches('/');
                let rebased = root_path.join(rel);
                if path.exists() && !rebased.exists() {
                    return path.to_path_buf();
                }
                return rebased;
            }
        }
    }
    path.to_path_buf()
}

/// Collects the list of critical systemd units (`apache2`, `aetherflow-runner`) and
/// any installed systemd packages whose lockfile exists in `/install/`.
pub(crate) fn is_component_policy_monitored(policy: &crate::ServiceComponentPolicy) -> bool {
    matches!(policy.role, "required" | "timer" | "socket")
        || (policy.role == "optional" && policy.configured)
}

struct HealPollInventory {
    monitored: Vec<(String, String)>,
    installed: HashSet<String>,
}

fn collect_monitored_systemd_units() -> anyhow::Result<HealPollInventory> {
    let mut units: Vec<(String, String)> = vec![
        ("apache2".to_string(), "Apache2 Web Server".to_string()),
        (
            "aetherflow-runner".to_string(),
            "AetherFlow Runner".to_string(),
        ),
    ];
    let mut seen: HashSet<String> = units.iter().map(|(u, _)| u.clone()).collect();
    let mut installed = seen.clone();
    let pkgs = crate::get_package_catalog()?;
    let rclone_vfs_configured = crate::is_rclone_vfs_configured();

    for pkg in &pkgs {
        let is_installed = crate::package_lock_installed(pkg)?;
        if pkg.service_type == "pm2" || pkg.service_type == "docker" {
            continue;
        }
        if pkg.lock_file.is_empty() || !pkg.lock_file.starts_with("/install/") {
            continue;
        }
        if !is_installed {
            continue;
        }

        for policy in
            crate::service_component_policies_with_catalog(&pkg.name, rclone_vfs_configured, &pkgs)
        {
            installed.insert(policy.unit.clone());
            if !is_component_policy_monitored(&policy) {
                continue;
            }
            let unit = policy.unit;
            if seen.insert(unit.clone()) {
                let label = if pkg.label.trim().is_empty() {
                    pkg.name.clone()
                } else {
                    pkg.label.clone()
                };
                units.push((unit, label));
            }
        }
    }
    Ok(HealPollInventory {
        monitored: units,
        installed,
    })
}

/// Checks if a systemd unit is healthy (`active`) or if `systemctl` is unavailable
/// (e.g. non-systemd dev/test hosts). Returns `Some(false)` only when systemd reports
/// a failed/inactive state for an installed unit.
async fn check_systemd_unit_healthy(unit: &str) -> Option<bool> {
    let output = crate::async_status_command_output(
        "systemctl",
        &["is-active", unit],
        Duration::from_secs(10),
    )
    .await
    .ok()?;

    let status_text = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_lowercase();
    match status_text.as_str() {
        "active" | "activating" | "reloading" => Some(true),
        "deactivating" => None,
        "failed" | "inactive" => {
            // Inactive oneshot jobs are healthy between timer/mount invocations.
            // Query unit metadata for failed jobs too, rather than restarting a
            // scheduled collector outside its timer's schedule.
            {
                if let Ok(load_out) = crate::async_status_command_output(
                    "systemctl",
                    &["show", "-p", "LoadState", "-p", "Type", unit],
                    Duration::from_secs(5),
                )
                .await
                {
                    let load_state = String::from_utf8_lossy(&load_out.stdout)
                        .trim()
                        .to_lowercase();
                    if !load_out.status.success() || !unit_metadata_allows_recovery(&load_state) {
                        return None;
                    }
                } else {
                    return None;
                }
            }
            Some(false)
        }
        _ => None,
    }
}

fn unit_metadata_allows_recovery(metadata: &str) -> bool {
    metadata
        .lines()
        .any(|line| line.trim() == "loadstate=loaded")
        && !metadata.lines().any(|line| line.trim() == "type=oneshot")
}

// Healthy polling uses one read-only journal snapshot and never owns either
// lifecycle mutation lock. Reconciliation belongs to an actual restart attempt.
fn collect_heal_poll_units() -> anyhow::Result<Option<HealPollInventory>> {
    let jobs = crate::package_job_snapshot()?;
    if !jobs.active.is_empty() {
        return Ok(None);
    }
    Ok(Some(collect_monitored_systemd_units()?))
}

fn parse_heal_auto_approve(raw: Option<&str>) -> bool {
    raw.map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true"))
        .unwrap_or(false)
}

fn is_heal_auto_approve_enabled() -> bool {
    parse_heal_auto_approve(env::var("AF_HEAL_AUTO_APPROVE").ok().as_deref())
}

#[cfg(test)]
mod heal_worker_unit_tests {
    use super::*;

    #[test]
    fn heal_auto_approve_defaults_to_false_and_requires_explicit_opt_in() {
        assert!(!parse_heal_auto_approve(None));
        assert!(!parse_heal_auto_approve(Some("")));
        assert!(!parse_heal_auto_approve(Some("false")));
        assert!(!parse_heal_auto_approve(Some("0")));
        assert!(parse_heal_auto_approve(Some("true")));
        assert!(parse_heal_auto_approve(Some("TRUE")));
        assert!(parse_heal_auto_approve(Some(" 1 ")));
    }
}

fn notify_all_admin_users(level: &str, title: &str, message: &str) {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    let mut admin_ids = Vec::new();
    if let Ok(mut stmt) =
        conn.prepare("SELECT id FROM users WHERE LOWER(TRIM(role)) = 'admin' ORDER BY id ASC")
    {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, i64>(0)) {
            for uid in rows.flatten() {
                admin_ids.push(uid);
            }
        }
    }
    for uid in admin_ids {
        let _ = conn.execute(
            "INSERT INTO notifications (user_id, level, title, message, read) VALUES (?1, ?2, ?3, ?4, 0)",
            params![uid, level, title, message],
        );
    }
}

fn queue_pending_heal_restart_dedup(unit: &str, display_name: &str) -> Option<i64> {
    let action_cmd = format!("systemctl restart {unit}");
    let reason = format!(
        "Service {} ({}) reported unhealthy; approve supervised systemd restart.",
        display_name, unit
    );
    // Invariant: emit queued admin notifications only after SQLite commits a positive row ID.
    match af_db::queue_action_if_not_pending("warn", "af-heal", &action_cmd, &reason) {
        af_db::QueueActionOutcome::Queued { action_id } if action_id > 0 => Some(action_id),
        af_db::QueueActionOutcome::CapacityReached {
            pending_count,
            limit,
        } => {
            tracing::warn!(
                unit = %unit,
                service = %display_name,
                pending_count,
                limit,
                "af-heal: skipped queueing restart approval because pending_actions cap was reached"
            );
            None
        }
        af_db::QueueActionOutcome::DbError(error) => {
            tracing::warn!(
                unit = %unit,
                service = %display_name,
                %error,
                "af-heal: failed to persist pending restart action; suppressing queued notification"
            );
            None
        }
        af_db::QueueActionOutcome::AlreadyPending
        | af_db::QueueActionOutcome::SkippedSafe
        | af_db::QueueActionOutcome::Queued { .. } => None,
    }
}

async fn perform_heal_check() {
    let inventory = match tokio::task::spawn_blocking(collect_heal_poll_units).await {
        Ok(Ok(Some(units))) => units,
        result => {
            if let Ok(Err(error)) = result {
                tracing::warn!(%error, "af-heal: lifecycle state unknown; skipping this check");
            }
            return;
        }
    };
    if let Ok(mut states) = HEAL_STATES.lock() {
        states.retain(|unit, _| {
            inventory.installed.contains(unit) || af_runner::is_package_execution_active(unit)
        });
    }
    let now = Instant::now();
    let auto_approve = is_heal_auto_approve_enabled();

    for (unit, display_name) in inventory.monitored {
        if af_runner::is_package_execution_active(&unit) {
            continue;
        }
        let Some(is_healthy) = check_systemd_unit_healthy(&unit).await else {
            continue;
        };

        if is_healthy {
            if let Ok(mut guard) = HEAL_STATES.lock() {
                if let Some(st) = guard.get_mut(&unit) {
                    if st.failure_count > 0 || st.exhausted {
                        tracing::info!(
                            unit = %unit,
                            service = %display_name,
                            "af-heal: service recovered and is active; resetting backoff state"
                        );
                        *st = ServiceHealState::default();
                    }
                }
            }
            continue;
        }

        // Service is unhealthy — evaluate backoff and retry budget
        let (should_attempt, attempt_num, newly_exhausted) = {
            let Ok(mut guard) = HEAL_STATES.lock() else {
                continue;
            };
            let st = guard.entry(unit.clone()).or_default();

            if st.exhausted {
                (false, st.failure_count, false)
            } else if st.failure_count >= MAX_HEAL_RETRIES {
                st.exhausted = true;
                (false, st.failure_count, true)
            } else if let Some(next_at) = st.next_retry_at {
                if now < next_at {
                    (false, st.failure_count, false)
                } else {
                    (true, st.failure_count + 1, false)
                }
            } else {
                (true, st.failure_count + 1, false)
            }
        };

        if newly_exhausted {
            tracing::error!(
                unit = %unit,
                service = %display_name,
                max_retries = MAX_HEAL_RETRIES,
                "af-heal: retry budget exhausted — manual intervention required"
            );
            notify_all_admin_users(
                "error",
                "af-heal Restart Retries Exhausted",
                &format!(
                    "Service {} ({}) failed after {} auto-heal restart attempts. Manual intervention required.",
                    display_name, unit, MAX_HEAL_RETRIES
                ),
            );
            continue;
        }

        if !should_attempt {
            continue;
        }

        let Ok(_lifecycle_guard) = crate::PACKAGE_LIFECYCLE_MUTEX.try_lock() else {
            return;
        };
        // Only an unhealthy unit with an eligible retry reaches this mutation
        // preflight. The runner rechecks the reservation while taking its guard.
        if tokio::task::spawn_blocking(crate::has_active_package_jobs)
            .await
            .unwrap_or(true)
        {
            return;
        }

        if !auto_approve {
            if let Some(action_id) = queue_pending_heal_restart_dedup(&unit, &display_name) {
                tracing::warn!(
                    action_id,
                    unit = %unit,
                    service = %display_name,
                    "af-heal: queued pending restart action (AF_HEAL_AUTO_APPROVE=false)"
                );
                notify_all_admin_users(
                    "warning",
                    "af-heal Restart Approval Required",
                    &format!(
                        "Service {} ({}) is unhealthy. A pending restart action was queued for administrator approval.",
                        display_name, unit
                    ),
                );
            }
            continue;
        }

        let previous_state = {
            let Ok(mut states) = HEAL_STATES.lock() else {
                continue;
            };
            let state = states.entry(unit.clone()).or_default();
            let previous = state.clone();
            state.failure_count = attempt_num;
            state.next_retry_at = Some(
                Instant::now()
                    + Duration::from_secs(
                        BASE_BACKOFF_SECS.saturating_mul(1u64 << (attempt_num - 1)),
                    ),
            );
            previous
        };

        tracing::warn!(
            unit = %unit,
            service = %display_name,
            attempt = attempt_num,
            max_retries = MAX_HEAL_RETRIES,
            "af-heal: attempting automatic service restart"
        );

        match af_runner::dispatch_heal_restart(&unit).await {
            Ok(false) => {
                if let Ok(mut states) = HEAL_STATES.lock() {
                    states.insert(unit.clone(), previous_state);
                }
            }
            Ok(true) => {
                tracing::info!(
                    unit = %unit,
                    service = %display_name,
                    attempt = attempt_num,
                    "af-heal: restart command succeeded"
                );
                notify_all_admin_users(
                    "warning",
                    "af-heal Auto-Recovery",
                    &format!(
                        "Automatically restarted {} ({}) on attempt {}/{}.",
                        display_name, unit, attempt_num, MAX_HEAL_RETRIES
                    ),
                );
            }
            Err(err) => {
                tracing::error!(
                    unit = %unit,
                    service = %display_name,
                    attempt = attempt_num,
                    error = %err,
                    "af-heal: restart attempt failed"
                );

                // If that was the 3rd attempt and it failed immediately, mark exhausted
                if attempt_num >= MAX_HEAL_RETRIES {
                    let mark_exhausted = if let Ok(mut guard) = HEAL_STATES.lock() {
                        let st = guard.entry(unit.clone()).or_default();
                        if !st.exhausted {
                            st.exhausted = true;
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if mark_exhausted {
                        notify_all_admin_users(
                            "error",
                            "af-heal Recovery Exhausted",
                            &format!(
                                "Failed to recover {} ({}) after {} attempts: {}",
                                display_name, unit, MAX_HEAL_RETRIES, err
                            ),
                        );
                    }
                } else {
                    notify_all_admin_users(
                        "warning",
                        "af-heal Restart Attempt Failed",
                        &format!(
                            "Attempt {}/{} to restart {} ({}) failed: {}",
                            attempt_num, MAX_HEAL_RETRIES, display_name, unit, err
                        ),
                    );
                }
            }
        }
    }
}

fn insert_user_notification(user_id: i64, level: &str, title: &str, message: &str) {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    let _ = conn.execute(
        "INSERT INTO notifications (user_id, level, title, message, read) VALUES (?1, ?2, ?3, ?4, 0)",
        params![user_id, level, title, message],
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Smart Backup Scheduler
// ─────────────────────────────────────────────────────────────────────────────

static SMART_BACKUP_ACTIVE: AtomicBool = AtomicBool::new(false);
static LAST_BACKUP_DATE: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));

/// Spawns a background tokio task (30-minute interval) that reads
/// `smart_backup_enabled` and `smart_backup_hour` from `settings`.
///
/// When `smart_backup_enabled == "true"` and the current UTC hour matches
/// `smart_backup_hour` and no backup has run today (tracked by `YYYY-MM-DD`),
/// performs an online SQLite backup (`VACUUM INTO` into the backups directory
/// with a `.sha256` sidecar) and updates `smart_backup_last_run` in `settings`.
pub fn start_smart_backup_scheduler() {
    if SMART_BACKUP_ACTIVE.swap(true, Ordering::SeqCst) {
        return;
    }

    tokio::spawn(async move {
        tracing::info!(interval_mins = 30, "smart backup scheduler initialized");

        ensure_smart_backup_columns();

        let mut ticker = tokio::time::interval(Duration::from_secs(30 * 60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            let _ = tokio::task::spawn_blocking(check_and_run_smart_backup).await;
        }
    });
}

/// Structured telemetry analysis for Smart Backup window selection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OptimalBackupWindowAnalysis {
    pub hour: u32,
    pub optimal_hour: u32,
    pub confidence: f64,
    pub source: String,
    pub sample_count: usize,
    pub distinct_hours: usize,
    pub avg_cpu_pct: f64,
    pub avg_memory_pct: f64,
    pub combined_load_score: f64,
    pub reason: String,
}

/// Computes the next upcoming `optimal_hour:00:00 UTC` at least 1 hour in the future.
pub fn compute_next_optimal_backup_at(
    now: chrono::DateTime<Utc>,
    optimal_hour: u32,
) -> chrono::DateTime<Utc> {
    let clamped_hour = optimal_hour.min(23);
    let today_naive = now
        .date_naive()
        .and_hms_opt(clamped_hour, 0, 0)
        .unwrap_or_else(|| now.date_naive().and_hms_opt(3, 0, 0).unwrap());
    let mut candidate = chrono::DateTime::<Utc>::from_naive_utc_and_offset(today_naive, Utc);
    let min_future = now + chrono::Duration::hours(1);
    while candidate < min_future {
        candidate += chrono::Duration::days(1);
    }
    candidate
}

fn metrics_history_has_extended_columns(conn: &rusqlite::Connection) -> (bool, bool) {
    let mut has_cpu_usage = false;
    let mut has_memory_pct = false;
    if let Ok(mut stmt) = conn.prepare("PRAGMA table_info(metrics_history)") {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(1)) {
            for col in rows.flatten() {
                if col.eq_ignore_ascii_case("cpu_usage") {
                    has_cpu_usage = true;
                } else if col.eq_ignore_ascii_case("memory_pct") {
                    has_memory_pct = true;
                }
            }
        }
    }
    (has_cpu_usage, has_memory_pct)
}

/// Evaluates `metrics_history` grouped by UTC hour (`0..23`) to find the lowest average
/// CPU + memory utilization window. When `< 24` samples exist, returns a transparent
/// low-confidence heuristic default (`confidence: 0.35`, `source: "heuristic_default"`, `optimal_hour: 3`).
pub fn analyze_optimal_backup_window(conn: &rusqlite::Connection) -> OptimalBackupWindowAnalysis {
    let (has_cpu_usage, has_memory_pct) = metrics_history_has_extended_columns(conn);
    let cpu_expr = if has_cpu_usage {
        "CASE WHEN COALESCE(cpu_usage, 0.0) > 0.0 THEN cpu_usage ELSE COALESCE(cpu_avg, 0.0) END"
    } else {
        "COALESCE(cpu_avg, 0.0)"
    };
    let mem_expr = if has_memory_pct {
        "CASE WHEN COALESCE(memory_pct, 0.0) > 0.0 THEN memory_pct WHEN COALESCE(mem_total_gb, 0.0) > 0.0 THEN (COALESCE(mem_used_gb, 0.0) / mem_total_gb) * 100.0 ELSE 0.0 END"
    } else {
        "CASE WHEN COALESCE(mem_total_gb, 0.0) > 0.0 THEN (COALESCE(mem_used_gb, 0.0) / mem_total_gb) * 100.0 ELSE 0.0 END"
    };

    let sql = format!(
        "SELECT
            CAST(strftime('%H', replace(CAST(timestamp AS TEXT), 'T', ' ')) AS INTEGER) AS utc_hour,
            COUNT(*) AS cnt,
            AVG({cpu_expr}) AS avg_cpu,
            AVG({mem_expr}) AS avg_mem
         FROM metrics_history
         WHERE timestamp IS NOT NULL
           AND strftime('%H', replace(CAST(timestamp AS TEXT), 'T', ' ')) IS NOT NULL
         GROUP BY utc_hour
         HAVING utc_hour BETWEEN 0 AND 23
         ORDER BY utc_hour ASC"
    );

    let mut buckets: Vec<(u32, usize, f64, f64, f64)> = Vec::new();
    let mut total_samples: usize = 0;

    if let Ok(mut stmt) = conn.prepare(&sql) {
        if let Ok(rows) = stmt.query_map([], |r| {
            let hr = r.get::<_, i64>(0)?.clamp(0, 23) as u32;
            let cnt = r.get::<_, i64>(1)?.max(0) as usize;
            let avg_cpu = r.get::<_, f64>(2).unwrap_or(0.0).clamp(0.0, 100.0);
            let avg_mem = r.get::<_, f64>(3).unwrap_or(0.0).clamp(0.0, 100.0);
            let score = (avg_cpu + avg_mem) / 2.0;
            Ok((hr, cnt, avg_cpu, avg_mem, score))
        }) {
            for item in rows.flatten() {
                total_samples = total_samples.saturating_add(item.1);
                buckets.push(item);
            }
        }
    }

    if total_samples < 24 || buckets.is_empty() {
        return OptimalBackupWindowAnalysis {
            hour: 3,
            optimal_hour: 3,
            confidence: 0.35,
            source: "heuristic_default".to_string(),
            sample_count: total_samples,
            distinct_hours: buckets.len(),
            avg_cpu_pct: 0.0,
            avg_memory_pct: 0.0,
            combined_load_score: 0.0,
            reason: format!(
                "Insufficient metrics_history telemetry ({} sample(s) < 24 minimum); defaulting to heuristic 03:00 UTC maintenance window",
                total_samples
            ),
        };
    }

    let distinct_hours = buckets.len();
    let best = buckets
        .iter()
        .copied()
        .min_by(|a, b| {
            a.4.partial_cmp(&b.4)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.0.cmp(&b.0))
        })
        .unwrap();

    let coverage_ratio = (distinct_hours as f64 / 24.0).clamp(0.0, 1.0);
    let volume_ratio = (total_samples as f64 / 168.0).clamp(0.0, 1.0);
    let raw_conf = (0.50 + 0.25 * coverage_ratio + 0.20 * volume_ratio).clamp(0.50, 0.95);
    let confidence = (raw_conf * 100.0).round() / 100.0;
    let avg_cpu_pct = (best.2 * 10.0).round() / 10.0;
    let avg_memory_pct = (best.3 * 10.0).round() / 10.0;
    let combined_load_score = (best.4 * 10.0).round() / 10.0;

    OptimalBackupWindowAnalysis {
        hour: best.0,
        optimal_hour: best.0,
        confidence,
        source: "metrics_history".to_string(),
        sample_count: total_samples,
        distinct_hours,
        avg_cpu_pct,
        avg_memory_pct,
        combined_load_score,
        reason: format!(
            "Lowest observed CPU ({avg_cpu_pct:.1}%) + memory ({avg_memory_pct:.1}%) load at {:02}:00 UTC across {} sample(s) covering {}/24 UTC hour(s)",
            best.0, total_samples, distinct_hours
        ),
    }
}

pub fn ensure_smart_backup_columns() {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    let stmts = [
        "ALTER TABLE settings ADD COLUMN smart_backup_enabled TEXT DEFAULT 'false';",
        "ALTER TABLE settings ADD COLUMN smart_backup_hour INTEGER DEFAULT 3;",
        "ALTER TABLE settings ADD COLUMN smart_backup_last_run TEXT DEFAULT '';",
    ];
    for s in stmts {
        let _ = conn.execute_batch(s);
    }
}

fn check_and_run_smart_backup() {
    ensure_smart_backup_columns();

    let (enabled, target_hour, is_smart_mode, persisted_last_run, persisted_next_run) = {
        let Ok(conn) = af_db::get_conn() else {
            return;
        };

        let row: Result<(String, i64, String, String, String), _> = conn.query_row(
            "SELECT
                LOWER(COALESCE(CAST(smart_backup_enabled AS TEXT), 'false')),
                COALESCE(CAST(smart_backup_hour AS INTEGER), 3),
                COALESCE(CAST(smart_backup_last_run AS TEXT), ''),
                LOWER(COALESCE(backup_schedule_mode, 'manual')),
                COALESCE(CAST(backup_next_run_at AS TEXT), '')
             FROM settings WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        );

        match row {
            Ok((en, hr, last_run, sched_mode, next_run)) => {
                let smart_mode = sched_mode == "smart";
                let is_enabled = en == "true" || en == "1" || smart_mode;
                let resolved_hr = if smart_mode {
                    let analysis = analyze_optimal_backup_window(&conn);
                    if analysis.source == "metrics_history" {
                        analysis.optimal_hour
                    } else {
                        hr.clamp(0, 23) as u32
                    }
                } else {
                    hr.clamp(0, 23) as u32
                };
                (is_enabled, resolved_hr, smart_mode, last_run, next_run)
            }
            Err(_) => return,
        }
    };

    if !enabled {
        return;
    }

    let now = Utc::now();
    let trimmed_next_run = persisted_next_run.trim();
    if !trimmed_next_run.is_empty() {
        if let Ok(next_dt) = chrono::DateTime::parse_from_rfc3339(trimmed_next_run) {
            if now < next_dt.with_timezone(&Utc) {
                return;
            }
        } else if now.hour() != target_hour {
            return;
        }
    } else if now.hour() != target_hour {
        return;
    }

    let today_str = now.format("%Y-%m-%d").to_string();

    // Check in-memory and persisted `smart_backup_last_run` date prefix
    if persisted_last_run.starts_with(&today_str) {
        if let Ok(mut guard) = LAST_BACKUP_DATE.lock() {
            *guard = today_str;
        }
        return;
    }

    if let Ok(guard) = LAST_BACKUP_DATE.lock() {
        if *guard == today_str {
            return;
        }
    }

    tracing::info!(
        date = %today_str,
        hour_utc = target_hour,
        "smart backup: initiating scheduled online SQLite backup"
    );

    match execute_online_sqlite_backup() {
        Ok(backup_path) => {
            let now_after = Utc::now();
            let now_rfc3339 = now_after.to_rfc3339();
            if let Ok(mut guard) = LAST_BACKUP_DATE.lock() {
                *guard = today_str;
            }
            if let Ok(conn) = af_db::get_conn() {
                let next_hour = if is_smart_mode {
                    let analysis = analyze_optimal_backup_window(&conn);
                    let window_json = serde_json::to_string(&analysis).unwrap_or_default();
                    let _ = conn.execute(
                        "UPDATE settings SET smart_backup_hour = ?1, backup_optimal_window = ?2 WHERE id = 1",
                        params![analysis.optimal_hour as i64, window_json],
                    );
                    analysis.optimal_hour
                } else {
                    target_hour
                };
                let mut next_dt = compute_next_optimal_backup_at(now_after, next_hour);
                if next_dt.date_naive() <= now_after.date_naive() {
                    next_dt += chrono::Duration::days(1);
                }
                let next_run = next_dt.to_rfc3339();
                let _ = conn.execute(
                    "UPDATE settings SET smart_backup_last_run = ?1, backup_next_run_at = ?2, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
                    params![now_rfc3339, next_run],
                );
            }
            tracing::info!(
                path = %backup_path.display(),
                "smart backup: completed online SQLite backup with SHA-256 sidecar"
            );
        }
        Err(err) => {
            tracing::error!(error = %err, "smart backup: scheduled backup failed");
        }
    }
}

fn resolve_backups_directory() -> PathBuf {
    let db_path_str = af_db::get_db_path();
    let db_path_opt = if db_path_str != ":memory:" && !db_path_str.starts_with("file:") {
        Some(Path::new(&db_path_str))
    } else {
        None
    };
    let default_data_backups = env::var("DATA_DIR")
        .ok()
        .or_else(|| env::var("AETHERFLOW_DATA_DIR").ok())
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .map(|dir| format!("{dir}/backups"))
        .unwrap_or_else(|| "/var/lib/aetherflow/backups".to_string());
    af_models::resolve_active_backup_dir_from_env(None, db_path_opt, &default_data_backups)
}

fn execute_online_sqlite_backup() -> anyhow::Result<PathBuf> {
    let backup_dir = resolve_backups_directory();
    let _maint_lock = af_host::HostMaintenanceLockGuard::acquire_default(
        Some(&backup_dir),
        Duration::from_secs(30),
    )
    .map_err(|e| anyhow::anyhow!("smart backup maintenance lock unavailable: {e}"))?;
    let db_path_str = af_db::get_db_path();
    let db_path = PathBuf::from(&db_path_str);

    let ts = Utc::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let config = af_host::HostBackupConfig {
        backup_dir,
        app_version: format!("v{}", env!("CARGO_PKG_VERSION")),
        sqlite_db_path: Some(db_path),
        snapshot_options: af_host::SnapshotOptions::default(),
        config_targets: vec![],
        chunk_size_bytes: None,
        max_retained_backups: af_host::DEFAULT_MAX_RETAINED_BACKUPS,
        retention_days: af_host::DEFAULT_RETENTION_DAYS,
    };

    let receipt = af_host::create_sqlite_snapshot_backup(&config, Some(&ts))
        .map_err(|e| anyhow::anyhow!("af_host snapshot backup failed: {}", e))?;

    let _ = af_host::prune_backup_inventory(
        &config.backup_dir,
        config.max_retained_backups,
        config.retention_days,
    );

    Ok(receipt.primary_artifact_path)
}

mod mediaflow;
mod package_updates;

pub use mediaflow::*;
pub use package_updates::*;

#[cfg(test)]
mod tests;
