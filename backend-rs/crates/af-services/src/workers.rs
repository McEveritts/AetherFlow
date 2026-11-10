//! Background Orchestration Workers (`metrics_recorder.go`, `af_heal.go`, `smart_backup.go`, `app_updates.go`).
//!
//! Provides four background tasks and on-demand package update utilities:
//! 1. [`start_metrics_recorder`] — 60-second system metrics snapshotter & hourly 7-day retention pruner.
//! 2. [`start_heal_worker`] — `af-heal` systemd service watchdog with exponential backoff (`10s * 2^attempt`, max 3 retries) and notifications.
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
// 1. Metrics History Recorder (`backend/services/metrics_recorder.go`)
// ─────────────────────────────────────────────────────────────────────────────

static METRICS_RECORDER_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Spawns a background tokio task (60-second interval) that samples
/// [`af_hardware::get_system_metrics_core()`], computes CPU usage, memory/swap
/// percentages, disk read/write MB/s, and network rx/tx MB/s, inserts a row into
/// `metrics_history`, and prunes rows older than 7 days every hour.
pub fn start_metrics_recorder() {
    start_mediaflow_poller();
    if METRICS_RECORDER_ACTIVE.swap(true, Ordering::SeqCst) {
        return;
    }

    tokio::spawn(async move {
        tracing::info!(
            interval_secs = 60,
            retention_days = 7,
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
    let cutoff = (Utc::now() - chrono::Duration::days(7)).to_rfc3339();
    match conn.execute(
        "DELETE FROM metrics_history WHERE timestamp < ?1 OR timestamp < datetime('now', '-7 days')",
        params![cutoff],
    ) {
        Ok(rows) if rows > 0 => {
            tracing::info!(
                count = rows,
                retention = "7d",
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
// 2. Auto-Heal Worker `af_heal` (`backend/services/af_heal.go`)
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
/// Checks critical managed systemd services (`nginx`, `smbd`, `wsdd`, plus any
/// installed systemd apps whose lockfile exists in `/install/`), tracks failure counts
/// and exponential backoff (`10s * 2^attempt`, max 3 retries before marking `exhausted`
/// until the service recovers), attempts [`crate::control_service(unit, "restart")`],
/// and records a warning/error notification into `notifications` (`user_id = 1`) on
/// auto-heal restart or retry exhaustion.
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

/// Collects the list of critical systemd units (`nginx`, `smbd`, `wsdd`) and
/// any installed systemd packages whose lockfile exists in `/install/`.
fn is_component_policy_monitored(policy: &crate::ServiceComponentPolicy) -> bool {
    matches!(policy.role, "required" | "timer") || (policy.role == "optional" && policy.configured)
}

struct HealPollInventory {
    monitored: Vec<(String, String)>,
    installed: HashSet<String>,
}

fn collect_monitored_systemd_units() -> anyhow::Result<HealPollInventory> {
    let mut units: Vec<(String, String)> = vec![
        ("nginx".to_string(), "Nginx".to_string()),
        ("smbd".to_string(), "Samba (smbd)".to_string()),
        ("wsdd".to_string(), "WSDD".to_string()),
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
            insert_user_notification(
                1,
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
                insert_user_notification(
                    1,
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
                        insert_user_notification(
                            1,
                            "error",
                            "af-heal Recovery Exhausted",
                            &format!(
                                "Failed to recover {} ({}) after {} attempts: {}",
                                display_name, unit, MAX_HEAL_RETRIES, err
                            ),
                        );
                    }
                } else {
                    insert_user_notification(
                        1,
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
// 3. Smart Backup Scheduler (`backend/services/smart_backup.go`)
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
        tracing::info!(
            interval_mins = 30,
            "smart backup scheduler initialized"
        );

        ensure_smart_backup_columns();

        let mut ticker = tokio::time::interval(Duration::from_secs(30 * 60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            let _ = tokio::task::spawn_blocking(check_and_run_smart_backup).await;
        }
    });
}

fn ensure_smart_backup_columns() {
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

    let (enabled, target_hour, persisted_last_run) = {
        let Ok(conn) = af_db::get_conn() else {
            return;
        };

        let row: Result<(String, i64, String, String), _> = conn.query_row(
            "SELECT
                LOWER(COALESCE(CAST(smart_backup_enabled AS TEXT), 'false')),
                COALESCE(CAST(smart_backup_hour AS INTEGER), 3),
                COALESCE(CAST(smart_backup_last_run AS TEXT), ''),
                LOWER(COALESCE(backup_schedule_mode, 'manual'))
             FROM settings WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        );

        match row {
            Ok((en, hr, last_run, sched_mode)) => {
                let is_enabled = en == "true" || en == "1" || sched_mode == "smart";
                (is_enabled, hr.clamp(0, 23) as u32, last_run)
            }
            Err(_) => return,
        }
    };

    if !enabled {
        return;
    }

    let now = Utc::now();
    if now.hour() != target_hour {
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
            let now_rfc3339 = Utc::now().to_rfc3339();
            if let Ok(mut guard) = LAST_BACKUP_DATE.lock() {
                *guard = today_str;
            }
            if let Ok(conn) = af_db::get_conn() {
                let next_run = (Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
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
    af_models::resolve_active_backup_dir_from_env(None, db_path_opt, "data/backups")
}

fn execute_online_sqlite_backup() -> anyhow::Result<PathBuf> {
    let backup_dir = resolve_backups_directory();
    let db_path_str = af_db::get_db_path();
    let db_path = PathBuf::from(&db_path_str);

    let ts = Utc::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let config = af_host::HostBackupConfig {
        backup_dir,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
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

// ─────────────────────────────────────────────────────────────────────────────
// 4. Package Update Watcher & On-Demand Checkers (`backend/services/app_updates.go`)
// ─────────────────────────────────────────────────────────────────────────────

/// Represents the cached update status for an individual marketplace package,
/// supporting both Rust field names and Go wire aliases (`package_name`, `update_url`, `last_error`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackageUpdateRecord {
    #[serde(alias = "package_name")]
    pub package_id: String,
    pub installed: bool,
    pub installed_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub checked_at: String,
    #[serde(alias = "update_url")]
    pub release_url: String,
    #[serde(alias = "last_error", default, serialize_with = "serialize_update_error")]
    pub error: String,
    #[serde(default)]
    pub source_key: String,
}

/// Thread-safe in-memory cache of package update records keyed by `package_id`.
pub static PACKAGE_UPDATE_CACHE: Lazy<Mutex<HashMap<String, PackageUpdateRecord>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static APP_UPDATE_WATCHER_ACTIVE: AtomicBool = AtomicBool::new(false);

static GITHUB_RELEASE_CACHE: Lazy<Mutex<HashMap<String, (String, String, Instant, String)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static GIT_REMOTE_HEAD_CACHE: Lazy<Mutex<HashMap<String, (String, String, Instant, String)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static GITHUB_RATE_LIMIT_UNTIL: Lazy<Mutex<HashMap<String, Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn normalize_api_origin(url_or_base: &str) -> String {
    let trimmed = url_or_base.trim();
    if let Ok(parsed) = reqwest::Url::parse(trimmed) {
        let scheme = parsed.scheme();
        let host = parsed.host_str().unwrap_or("");
        let port_part = match parsed.port() {
            Some(p) => format!(":{}", p),
            None => String::new(),
        };
        format!("{}://{}{}", scheme, host, port_part).to_ascii_lowercase()
    } else {
        trimmed.trim_end_matches('/').to_ascii_lowercase()
    }
}

pub fn sha256_hex_12(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    hex::encode(&result[..6])
}

pub fn sanitize_git_remote_url_for_display(raw_url: &str) -> String {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Ok(parsed) = reqwest::Url::parse(trimmed) {
        let scheme = parsed.scheme().to_ascii_lowercase();
        let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
        let port_part = match parsed.port() {
            Some(443) if scheme == "https" => String::new(),
            Some(80) if scheme == "http" => String::new(),
            Some(22) if scheme == "ssh" => String::new(),
            Some(p) => format!(":{}", p),
            None => String::new(),
        };
        let user_part = if scheme == "ssh" {
            let uname = parsed.username();
            if !uname.is_empty() {
                format!("{}@", uname)
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        let path = parsed.path();
        format!("{}://{}{}{}{}", scheme, user_part, host, port_part, path)
    } else if let Some((user_host, path)) = trimmed.split_once(':') {
        let without_frag = path.split('#').next().unwrap_or(path);
        let without_query = without_frag.split('?').next().unwrap_or(without_frag);
        let clean_path = without_query.trim_start_matches('/');
        if let Some((user, host)) = user_host.split_once('@') {
            let clean_user = if let Some((u, _)) = user.split_once(':') {
                u
            } else {
                user
            };
            format!("ssh://{}@{}/{}", clean_user, host.to_ascii_lowercase(), clean_path)
        } else {
            format!("ssh://{}/{}", user_host.to_ascii_lowercase(), clean_path)
        }
    } else {
        let without_frag = trimmed.split('#').next().unwrap_or(trimmed);
        let without_query = without_frag.split('?').next().unwrap_or(without_frag);
        without_query.to_string()
    }
}

pub fn validate_release_url_origin(url: &str, expected_api_base: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    let Ok(expected) = reqwest::Url::parse(expected_api_base) else {
        return false;
    };
    parsed.scheme() == expected.scheme()
        && parsed.host_str().unwrap_or("").eq_ignore_ascii_case(expected.host_str().unwrap_or(""))
        && parsed.port_or_known_default() == expected.port_or_known_default()
}

pub fn validate_github_releases_next_url(next_url: &str, github_api_base: &str, clean_repo: &str) -> bool {
    if !validate_release_url_origin(next_url, github_api_base) {
        return false;
    }
    let Ok(parsed) = reqwest::Url::parse(next_url) else {
        return false;
    };
    let Ok(expected) = reqwest::Url::parse(github_api_base) else {
        return false;
    };
    let base_path = expected.path().trim_end_matches('/');
    let next_path = parsed.path().trim_end_matches('/');
    let Some(repo_suffix) = next_path.strip_prefix(base_path) else {
        return false;
    };
    let expected_repo_suffix = format!("/repos/{}/releases", clean_repo.trim_matches('/'));
    repo_suffix.eq_ignore_ascii_case(&expected_repo_suffix)
}

fn extract_canonical_query_hash_suffix(raw: &str) -> (&str, Option<String>) {
    if let Some(idx) = raw.find("?q#") {
        if raw.len() >= idx + 15 {
            let hex = &raw[idx + 3..idx + 15];
            let after_ok = raw.len() == idx + 15 || raw.as_bytes()[idx + 15] == b'#';
            if hex.bytes().all(|b| b.is_ascii_hexdigit()) && after_ok {
                return (&raw[..idx], Some(format!("?q#{}", hex.to_ascii_lowercase())));
            }
        }
    }
    (raw, None)
}

fn split_git_repo_remote_and_branch(rest: &str) -> (&str, Option<&str>) {
    if let Some((left, right)) = rest.rsplit_once('#') {
        if left.ends_with("?q") && right.len() == 12 && right.bytes().all(|b| b.is_ascii_hexdigit()) {
            return (rest, None);
        }
        return (left, Some(right));
    }
    (rest, None)
}

pub fn normalize_git_remote_url_preserve_path_case(raw_url: &str) -> String {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let (trimmed_base, existing_q_hash) = extract_canonical_query_hash_suffix(trimmed);
    if let Some(q_hash) = existing_q_hash {
        let base = normalize_git_remote_url_preserve_path_case(trimmed_base);
        return format!("{}{}", base, q_hash);
    }
    if let Some((prefix, after_scheme)) = trimmed.split_once("://") {
        if let Some((userinfo, rest)) = after_scheme.split_once('@') {
            if let Some(hex) = userinfo.strip_prefix("cred#") {
                if hex.len() == 12 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    let temp_url = format!("{}://cred@{}", prefix, rest);
                    if let Ok(parsed) = reqwest::Url::parse(&temp_url) {
                        let scheme = parsed.scheme().to_ascii_lowercase();
                        let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
                        let port_part = match parsed.port() {
                            Some(443) if scheme == "https" => String::new(),
                            Some(80) if scheme == "http" => String::new(),
                            Some(22) if scheme == "ssh" => String::new(),
                            Some(p) => format!(":{}", p),
                            None => String::new(),
                        };
                        let path = parsed.path();
                        let query_part = match parsed.query() {
                            Some(q) if !q.is_empty() => format!("?q#{}", sha256_hex_12(q.as_bytes())),
                            _ => String::new(),
                        };
                        return format!("{}://cred#{}@{}{}{}{}", scheme, hex, host, port_part, path, query_part);
                    }
                }
            }
        }
    }
    if let Ok(parsed) = reqwest::Url::parse(trimmed) {
        let scheme = parsed.scheme().to_ascii_lowercase();
        let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
        let port_part = match parsed.port() {
            Some(443) if scheme == "https" => String::new(),
            Some(80) if scheme == "http" => String::new(),
            Some(22) if scheme == "ssh" => String::new(),
            Some(p) => format!(":{}", p),
            None => String::new(),
        };
        let user_part = if parsed.password().is_some() {
            let userinfo = format!("{}:{}", parsed.username(), parsed.password().unwrap());
            format!("cred#{}@", sha256_hex_12(userinfo.as_bytes()))
        } else if !parsed.username().is_empty() {
            if scheme == "http" || scheme == "https" {
                format!("cred#{}@", sha256_hex_12(parsed.username().as_bytes()))
            } else {
                format!("{}@", parsed.username())
            }
        } else {
            String::new()
        };
        let path = parsed.path();
        let query_part = match parsed.query() {
            Some(q) if !q.is_empty() => format!("?q#{}", sha256_hex_12(q.as_bytes())),
            _ => String::new(),
        };
        format!("{}://{}{}{}{}{}", scheme, user_part, host, port_part, path, query_part)
    } else if let Some((user_host, path)) = trimmed.split_once(':') {
        let without_frag = path.split('#').next().unwrap_or(path);
        let (clean_path_raw, query_opt) = match without_frag.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (without_frag, None),
        };
        let clean_path = clean_path_raw
            .trim_start_matches('/')
            .trim_end_matches('/')
            .trim_end_matches(".git");
        let query_part = match query_opt {
            Some(q) if !q.is_empty() => format!("?q#{}", sha256_hex_12(q.as_bytes())),
            _ => String::new(),
        };
        if let Some((user, host)) = user_host.split_once('@') {
            let user_part = if let Some((u, pass)) = user.split_once(':') {
                let userinfo = format!("{}:{}", u, pass);
                format!("cred#{}@", sha256_hex_12(userinfo.as_bytes()))
            } else {
                format!("{}@", user)
            };
            format!("ssh://{}{}/{}{}", user_part, host.to_ascii_lowercase(), clean_path, query_part)
        } else {
            format!("ssh://{}/{}{}", user_host.to_ascii_lowercase(), clean_path, query_part)
        }
    } else {
        let without_frag = trimmed.split('#').next().unwrap_or(trimmed);
        let (clean_raw, query_opt) = match without_frag.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (without_frag, None),
        };
        let query_part = match query_opt {
            Some(q) if !q.is_empty() => format!("?q#{}", sha256_hex_12(q.as_bytes())),
            _ => String::new(),
        };
        let clean_with_cred = if let Some((userinfo, rest)) = clean_raw.split_once('@') {
            if let Some((u, pass)) = userinfo.split_once(':') {
                let full_cred = format!("{}:{}", u, pass);
                format!("cred#{}@{}", sha256_hex_12(full_cred.as_bytes()), rest)
            } else {
                clean_raw.to_string()
            }
        } else {
            clean_raw.to_string()
        };
        let clean_path = clean_with_cred.trim_end_matches('/').trim_end_matches(".git");
        format!("{}{}", clean_path, query_part)
    }
}

pub fn is_github_rate_limited_for_origin(github_api_base: &str, bucket: &str) -> bool {
    let origin = sanitize_api_base_for_source_key(github_api_base);
    let now = Instant::now();
    let Ok(guard) = GITHUB_RATE_LIMIT_UNTIL.lock() else {
        return false;
    };
    let req_bucket = bucket.trim().to_ascii_lowercase();
    let buckets = [req_bucket.as_str(), "core", "default"];
    for b in buckets {
        let key = format!("{}|{}", origin, b);
        if let Some(&until) = guard.get(&key) {
            if now < until {
                return true;
            }
        }
    }
    false
}

pub fn github_rate_limit_remaining_secs_for_origin(github_api_base: &str, bucket: &str) -> u64 {
    let origin = sanitize_api_base_for_source_key(github_api_base);
    let now = Instant::now();
    let Ok(guard) = GITHUB_RATE_LIMIT_UNTIL.lock() else {
        return 0;
    };
    let req_bucket = bucket.trim().to_ascii_lowercase();
    let buckets = [req_bucket.as_str(), "core", "default"];
    let mut max_remaining = 0u64;
    for b in buckets {
        let key = format!("{}|{}", origin, b);
        if let Some(&until) = guard.get(&key) {
            if until > now {
                let secs = (until - now).as_secs();
                max_remaining = max_remaining.max(secs);
            }
        }
    }
    max_remaining
}

pub fn is_github_api_rate_limited(github_api_base: &str, bucket: &str) -> bool {
    is_github_rate_limited_for_origin(github_api_base, bucket)
}

pub fn record_github_api_rate_limit(github_api_base: &str, bucket: &str, cooldown: Duration) {
    let origin = sanitize_api_base_for_source_key(github_api_base);
    let bucket_name = if bucket.trim().is_empty() {
        "default".to_string()
    } else {
        bucket.trim().to_ascii_lowercase()
    };
    let key = format!("{}|{}", origin, bucket_name);
    let until = Instant::now() + cooldown;
    if let Ok(mut guard) = GITHUB_RATE_LIMIT_UNTIL.lock() {
        guard.insert(key, until);
    }
}

pub fn clear_github_rate_limits() {
    if let Ok(mut guard) = GITHUB_RATE_LIMIT_UNTIL.lock() {
        guard.clear();
    }
}

pub fn sanitize_api_base_for_source_key(raw_base: &str) -> String {
    let trimmed = raw_base.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Ok(parsed) = reqwest::Url::parse(trimmed) {
        let scheme = parsed.scheme().to_ascii_lowercase();
        let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
        let port_part = match parsed.port() {
            Some(443) if scheme == "https" => String::new(),
            Some(80) if scheme == "http" => String::new(),
            Some(22) if scheme == "ssh" => String::new(),
            Some(p) => format!(":{}", p),
            None => String::new(),
        };
        let path = parsed.path().trim_end_matches('/');
        format!("{}://{}{}{}", scheme, host, port_part, path)
    } else {
        let s = af_release::lifecycle::sanitize_persisted_lifecycle_text(trimmed);
        let without_frag = s.split('#').next().unwrap_or(&s);
        let (raw_base, query_opt) = match without_frag.split_once('?') {
            Some((b, q)) => (b, Some(q)),
            None => (without_frag, None),
        };
        let query_part = match query_opt {
            Some(q) if !q.is_empty() => format!("?q#{}", sha256_hex_12(q.as_bytes())),
            _ => String::new(),
        };
        let base_no_slash = raw_base.trim_end_matches('/');
        let normalized_base = if let Some((scheme, rest)) = base_no_slash.split_once("://") {
            let scheme_lower = scheme.to_ascii_lowercase();
            if let Some((host, path)) = rest.split_once('/') {
                format!("{}://{}/{}", scheme_lower, host.to_ascii_lowercase(), path)
            } else {
                format!("{}://{}", scheme_lower, rest.to_ascii_lowercase())
            }
        } else {
            base_no_slash.to_string()
        };
        format!("{}{}", normalized_base, query_part)
    }
}

pub fn sanitize_source_key_for_persistence(raw_key: &str) -> String {
    let trimmed = raw_key.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // 1. git-repo:<remote>#<branch>
    if let Some(rest) = trimmed.strip_prefix("git-repo:") {
        let (remote, branch_opt) = split_git_repo_remote_and_branch(rest);
        let norm_remote = normalize_git_remote_url_preserve_path_case(remote);
        let combined = match branch_opt {
            Some(b) => format!("git-repo:{}#{}", norm_remote, b),
            None => format!("git-repo:{}", norm_remote),
        };
        return af_release::lifecycle::sanitize_persisted_lifecycle_text(&combined);
    }

    // 2. Canonical src:api_base|remote|repo|channel or similar
    if let Some((src, rest)) = trimmed.split_once(':') {
        let src_lower = src.to_ascii_lowercase();
        let parts: Vec<&str> = rest.split('|').collect();
        match src_lower.as_str() {
            "github" | "github_release" | "github-release" | "github-tag" => {
                if parts.len() >= 2 {
                    let api_base = sanitize_api_base_for_source_key(parts[0]);
                    let repo = parts[1].trim().to_ascii_lowercase();
                    let channel_suffix = if parts.len() >= 3 {
                        format!("|{}", parts[2].trim().to_ascii_lowercase())
                    } else {
                        String::new()
                    };
                    let key = format!("{}:{}|{}{}", src, api_base, repo, channel_suffix);
                    return af_release::lifecycle::sanitize_persisted_lifecycle_text(&key);
                }
            }
            "git" | "git_tag" | "git_tags" | "git_commit" | "git_head" => {
                if parts.len() >= 3 {
                    let api_base = sanitize_api_base_for_source_key(parts[0]);
                    let norm_remote = normalize_git_remote_url_preserve_path_case(parts[1]);
                    let repo_slug = parts[2].trim();
                    let channel_suffix = if parts.len() >= 4 {
                        format!("|{}", parts[3].trim().to_ascii_lowercase())
                    } else {
                        String::new()
                    };
                    let key = format!("{}:{}|{}|{}{}", src, api_base, norm_remote, repo_slug, channel_suffix);
                    return af_release::lifecycle::sanitize_persisted_lifecycle_text(&key);
                }
            }
            _ => {}
        }
    }

    af_release::lifecycle::sanitize_persisted_lifecycle_text(trimmed)
}

pub fn canonical_update_source_key(github_api_base: &str, pkg: &Package) -> String {
    let (effective_source, effective_apt_pkg) = effective_update_source_and_apt_package(pkg);
    let src = if effective_source.trim().is_empty() && pkg.name == "threadfin" {
        "github".to_string()
    } else {
        effective_source.trim().to_ascii_lowercase()
    };
    let api_base = sanitize_api_base_for_source_key(github_api_base);
    let base_key = match src.as_str() {
        "github" | "github_release" => {
            let repo = if pkg.name == "threadfin" && pkg.update_repo.trim().is_empty() {
                "threadfin/threadfin"
            } else {
                pkg.update_repo.trim()
            };
            format!("github:{}|{}", api_base, repo.to_ascii_lowercase())
        }
        "git" | "git_tag" | "git_tags" | "git_commit" | "git_head" => {
            let effective_remote = if !pkg.update_repo_url.trim().is_empty() {
                normalize_git_remote_url_preserve_path_case(pkg.update_repo_url.trim())
            } else if !pkg.update_repo.trim().is_empty() {
                normalize_git_remote_url_preserve_path_case(&format!("https://github.com/{}.git", pkg.update_repo.trim()))
            } else {
                String::new()
            };
            let repo_slug = pkg.update_repo.trim();
            format!("{}:{}|{}|{}", src, api_base, effective_remote, repo_slug)
        }
        "pypi" => {
            let pypi_pkg = if pkg.name == "pyload" && pkg.update_package.trim().is_empty() {
                "pyload-ng"
            } else if !pkg.update_package.trim().is_empty() {
                pkg.update_package.trim()
            } else {
                pkg.name.trim()
            };
            format!("pypi:{}", pypi_pkg.to_ascii_lowercase())
        }
        "apt" => {
            let apt_pkg = if !effective_apt_pkg.trim().is_empty() {
                effective_apt_pkg.trim()
            } else if !pkg.update_package.trim().is_empty() {
                pkg.update_package.trim()
            } else {
                pkg.name.trim()
            };
            format!("apt:{}", apt_pkg.to_ascii_lowercase())
        }
        _ => {
            if !pkg.update_package.trim().is_empty() {
                format!("{}:{}", src, pkg.update_package.trim().to_ascii_lowercase())
            } else if !pkg.update_repo.trim().is_empty() {
                format!("{}:{}|{}", src, api_base, pkg.update_repo.trim().to_ascii_lowercase())
            } else {
                format!("{}:{}", src, pkg.name.trim().to_ascii_lowercase())
            }
        }
    };
    let channel = if pkg.update_channel.trim().is_empty() {
        "stable"
    } else {
        pkg.update_channel.trim()
    }
    .to_ascii_lowercase();
    let full_key = format!("{}|{}", base_key, channel);
    af_release::lifecycle::sanitize_persisted_lifecycle_text(&full_key)
}

pub fn github_release_cache() -> std::sync::MutexGuard<'static, HashMap<String, (String, String, Instant, String)>> {
    GITHUB_RELEASE_CACHE.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn git_remote_head_cache() -> std::sync::MutexGuard<'static, HashMap<String, (String, String, Instant, String)>> {
    GIT_REMOTE_HEAD_CACHE.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn git_head_cache_key(repo_url: &str, repo: &str) -> String {
    let effective_remote_url = if !repo_url.trim().is_empty() {
        normalize_git_remote_url_preserve_path_case(repo_url.trim())
    } else if !repo.trim().is_empty() {
        normalize_git_remote_url_preserve_path_case(&format!("https://github.com/{}.git", repo.trim()))
    } else {
        String::new()
    };
    format!(
        "{}|{}",
        effective_remote_url,
        repo.trim()
    )
}


pub fn github_release_cache_key(github_api_base: &str, repo: &str) -> String {
    github_release_cache_key_for_channel(github_api_base, repo, "stable")
}

pub fn github_release_cache_key_for_channel(github_api_base: &str, repo: &str, channel: &str) -> String {
    let effective_channel_owned = {
        let t = channel.trim().to_ascii_lowercase();
        if t.is_empty() {
            "stable".to_string()
        } else {
            t
        }
    };
    let effective_channel = effective_channel_owned.as_str();
    format!(
        "{}|{}|{}",
        sanitize_api_base_for_source_key(github_api_base),
        repo.trim().to_ascii_lowercase(),
        effective_channel
    )
}

pub fn get_cached_github_release_stale(
    github_api_base: &str,
    repo: &str,
) -> Option<(String, String, String)> {
    get_cached_github_release_stale_for_channel(github_api_base, repo, "stable")
}

pub fn get_cached_github_release_stale_for_channel(
    github_api_base: &str,
    repo: &str,
    channel: &str,
) -> Option<(String, String, String)> {
    let clean_repo = repo.trim().to_ascii_lowercase();
    if clean_repo.is_empty() {
        return None;
    }
    let effective_channel_owned = {
        let t = channel.trim().to_ascii_lowercase();
        if t.is_empty() {
            "stable".to_string()
        } else {
            t
        }
    };
    let effective_channel = effective_channel_owned.as_str();
    let cache_key = github_release_cache_key_for_channel(github_api_base, &clean_repo, effective_channel);
    let cache = github_release_cache();
    if let Some((ver, url, _, obs)) = cache.get(&cache_key) {
        if tag_allowed_by_channel(ver, effective_channel) {
            return Some((ver.clone(), url.clone(), obs.clone()));
        }
    }
    None
}

static DOTTED_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:\d+:)?\d+\.\d+(?:\.\d+)*(?:~[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)")
        .unwrap()
});
static DEFAULT_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:\d+:)?[0-9]+(?:\.[0-9]+)*(?:~[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)")
        .unwrap()
});
static SYNTHETIC_COMMIT_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)-([0-9a-fA-F]{7,40})$").unwrap()
});

#[derive(Debug, Deserialize)]
struct GitHubReleaseResponse {
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
}

#[derive(Debug, Deserialize)]
struct PyPiInfo {
    #[serde(default)]
    version: String,
    #[serde(default)]
    project_urls: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct PyPiResponse {
    info: PyPiInfo,
}

/// Helper recognizing 7..=40 character lowercase/uppercase hexadecimal strings (`^[0-9a-fA-F]{7,40}$`)
/// that contain NO dots (`.`), and either are 40 chars OR contain at least one hex letter `[a-fA-F]`.
pub fn is_git_commit_sha(token: &str) -> bool {
    let t = token.trim();
    if t.len() < 7 || t.len() > 40 || t.contains('.') {
        return false;
    }
    if !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    t.bytes().any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F'))
}

/// Normalizes a version token or tag into a canonical version string.
pub fn normalize_version_token(raw: &str) -> String {
    let extracted = extract_version(raw, "");
    if !extracted.is_empty() {
        extracted
    } else {
        raw.trim()
            .strip_prefix('v')
            .or_else(|| raw.trim().strip_prefix('V'))
            .unwrap_or(raw.trim())
            .to_string()
    }
}

/// Parses a synthetic commit-suffixed version such as `0.1.0-6e840ac`.
pub fn parse_synthetic_commit_version(token: &str) -> Option<(&str, &str)> {
    let s = token
        .trim()
        .strip_prefix('v')
        .or_else(|| token.trim().strip_prefix('V'))
        .unwrap_or(token.trim());
    let (prefix, sha) = s.rsplit_once('-')?;
    if sha.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if !is_git_commit_sha(sha) {
        return None;
    }
    if prefix
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    {
        Some((prefix, sha))
    } else {
        None
    }
}

/// Parses a multi-component manifest like `frontend:<sha>,backend:<sha>,proxy:<sha>` or generic `comp1:1.1,comp2:2.0`.
pub fn parse_component_manifest(token: &str) -> Option<HashMap<String, String>> {
    let s = token.trim();
    if !s.contains(':') && !s.contains('=') {
        return None;
    }
    let parts: Vec<&str> = s.split(',').collect();
    let mut seen = std::collections::HashSet::new();
    for p in &parts {
        let trimmed = p.trim();
        if trimmed.is_empty() {
            return None;
        }
        let (k, _) = if let Some(idx) = trimmed.find(['=', ':']) {
            (&trimmed[..idx], &trimmed[idx + 1..])
        } else {
            return None;
        };
        let key = k.trim().to_lowercase();
        if key.is_empty() || !seen.insert(key) {
            return None;
        }
    }
    af_release::lifecycle::parse_component_manifest(s)
}

pub fn normalize_component_manifest(map: &HashMap<String, String>) -> String {
    if map.contains_key("frontend")
        && map.contains_key("backend")
        && map.contains_key("proxy")
        && map.len() == 3
    {
        format!(
            "frontend:{},backend:{},proxy:{}",
            map["frontend"], map["backend"], map["proxy"]
        )
    } else {
        let mut keys: Vec<_> = map.keys().collect();
        keys.sort();
        keys.iter()
            .map(|k| format!("{}:{}", k, map[*k]))
            .collect::<Vec<_>>()
            .join(",")
    }
}

pub fn is_component_manifest(token: &str) -> bool {
    parse_component_manifest(token).is_some()
}

/// Status text is public (Marketplace) and visible to ordinary Services viewers.
/// Only fixed summaries may cross this boundary, including historical DB/cache rows.
pub fn public_update_error(error: &str) -> String {
    let lower = error.to_ascii_lowercase();
    if lower.contains("rate limit") {
        return "GitHub API rate limit reached; retaining last confirmed version".to_string();
    }
    if lower.starts_with("installed version check failed") {
        return error.to_string();
    }
    match error {
        "" => String::new(),
        "Installed version could not be confirmed"
        | "Latest version could not be confirmed"
        | "Installed version could not be confirmed; Latest version could not be confirmed"
        | "Installed version probe returned no output; retaining last known installed version"
        | "GitHub API rate limit reached; retaining last confirmed version" => error.to_string(),
        _ => "Update status could not be confirmed".to_string(),
    }
}

/// Sanitizes internal update check error messages into stable, safe descriptions.
pub fn sanitize_update_check_error(error: &str) -> String {
    let lower = error.to_ascii_lowercase();
    if lower.contains("rate limit") {
        "GitHub API rate limit reached; retaining last confirmed version".to_string()
    } else {
        public_update_error(error)
    }
}

fn serialize_update_error<S: serde::Serializer>(error: &str, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&public_update_error(error))
}

pub fn ensure_app_updates_columns() {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    ensure_app_updates_columns_with_connection(&conn);
}

pub fn ensure_app_updates_columns_with_connection(conn: &rusqlite::Connection) {
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS app_updates (
            package_name TEXT PRIMARY KEY,
            installed_version TEXT,
            latest_version TEXT,
            update_available BOOLEAN,
            update_url TEXT,
            checked_at DATETIME,
            last_error TEXT,
            source_key TEXT NOT NULL DEFAULT ''
        );
        ALTER TABLE app_updates ADD COLUMN source_key TEXT NOT NULL DEFAULT '';",
    );
}

pub fn load_previous_package_update_records() -> HashMap<String, PackageUpdateRecord> {
    ensure_app_updates_columns();
    let mut result = HashMap::new();

    if let Ok(conn) = af_db::get_conn() {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT package_name, COALESCE(installed_version, ''), COALESCE(latest_version, ''),
                    COALESCE(update_available, 0), COALESCE(update_url, ''),
                    COALESCE(CAST(checked_at AS TEXT), ''), COALESCE(last_error, ''),
                    COALESCE(source_key, '')
             FROM app_updates",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                let pkg_id: String = r.get(0)?;
                let installed_ver: String = r.get(1)?;
                Ok(PackageUpdateRecord {
                    package_id: pkg_id,
                    installed: !installed_ver.is_empty(),
                    installed_version: installed_ver,
                    latest_version: r.get(2)?,
                    update_available: r.get(3)?,
                    release_url: r.get(4)?,
                    checked_at: r.get(5)?,
                    error: r.get(6)?,
                    source_key: r.get(7)?,
                })
            }) {
                for row in rows.flatten() {
                    result.insert(row.package_id.clone(), row);
                }
            }
        }
    }
    result
}

/// Returns persisted and cached update records with safe status summaries.
pub fn get_package_update_map() -> HashMap<String, PackageUpdateRecord> {
    let mut result = load_previous_package_update_records();

    if let Ok(mut cache) = PACKAGE_UPDATE_CACHE.lock() {
        for (k, v) in &result {
            cache.entry(k.clone()).or_insert_with(|| v.clone());
        }
        for (k, v) in cache.iter() {
            result.insert(k.clone(), v.clone());
        }
    }

    for record in result.values_mut() {
        record.error = public_update_error(&record.error);
    }
    result
}

/// Refreshes the update status of a single package by ID (`pkg_id`), updating both
/// [`PACKAGE_UPDATE_CACHE`] and the `app_updates` table in SQLite.
pub async fn refresh_package_update_by_id(pkg_id: &str) -> Option<PackageUpdateRecord> {
    let trimmed = pkg_id.trim();
    if trimmed.is_empty() {
        return None;
    }

    let pkgs = crate::get_packages().ok()?;
    let pkg = pkgs.into_iter().find(|p| p.name == trimmed)?;

    let client = build_github_http_client();
    let base_url = resolve_github_api_base_url();

    let (record, notify) = check_single_package(&client, &base_url, &pkg).await;
    if notify {
        let label = if pkg.label.trim().is_empty() {
            &pkg.name
        } else {
            &pkg.label
        };
        insert_user_notification(
            1,
            "info",
            &format!("{} update available", label),
            &format!(
                "Installed {}, latest {}.",
                record.installed_version, record.latest_version
            ),
        );
    }

    Some(record)
}

/// Inspects all installed packages from [`crate::get_packages()`], detects local version
/// via binary `--version` / `dpkg-query` / version file where available, queries the
/// upstream GitHub release API (or `apt-cache` / `git ls-remote`), compares versions,
/// caches the results in [`PACKAGE_UPDATE_CACHE`] and `app_updates`, and returns the list.
pub async fn refresh_all_package_updates() -> anyhow::Result<Vec<PackageUpdateRecord>> {
    // Inventory errors must remain unknown, never a successful empty check.
    // Journal/catalog/lock inspection can block, so keep it off the async thread.
    let pkgs = tokio::task::spawn_blocking(crate::get_packages).await??;

    let client = build_github_http_client();
    let base_url = resolve_github_api_base_url();
    let mut records = Vec::new();

    for pkg in pkgs {
        let is_installed = package_is_installed(&pkg);
        if !is_installed || !should_track_package(&pkg) {
            continue;
        }

        let (record, notify) = check_single_package(&client, &base_url, &pkg).await;
        if notify {
            let label = if pkg.label.trim().is_empty() {
                &pkg.name
            } else {
                &pkg.label
            };
            insert_user_notification(
                1,
                "info",
                &format!("{} update available", label),
                &format!(
                    "Installed {}, latest {}.",
                    record.installed_version, record.latest_version
                ),
            );
        }
        records.push(record);
    }

    Ok(records)
}

/// Spawns the background App Update Watcher task, running an initial check after a
/// 45-second delay and repeating every 6 hours (or `AETHERFLOW_UPDATE_WATCH_INTERVAL`).
pub fn start_app_update_watcher() {
    if APP_UPDATE_WATCHER_ACTIVE.swap(true, Ordering::SeqCst) {
        return;
    }

    let interval = resolve_update_watch_interval();

    tokio::spawn(async move {
        tracing::info!(
            initial_delay_secs = 45,
            interval_secs = interval.as_secs(),
            "app update watcher initialized"
        );

        tokio::time::sleep(Duration::from_secs(45)).await;
        if let Err(error) = refresh_all_package_updates().await {
            tracing::warn!(error = %error, "application update watcher could not confirm inventory");
        }

        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Consume immediate first tick
        ticker.tick().await;

        loop {
            ticker.tick().await;
            if let Err(error) = refresh_all_package_updates().await {
                tracing::warn!(error = %error, "application update watcher could not confirm inventory");
            }
        }
    });
}

fn resolve_update_watch_interval() -> Duration {
    if let Ok(raw) = env::var("AETHERFLOW_UPDATE_WATCH_INTERVAL") {
        let trimmed = raw.trim();
        if let Some(secs_str) = trimmed.strip_suffix('s') {
            if let Ok(s) = secs_str.parse::<u64>() {
                if s > 0 {
                    return Duration::from_secs(s);
                }
            }
        } else if let Some(mins_str) = trimmed.strip_suffix('m') {
            if let Ok(m) = mins_str.parse::<u64>() {
                if m > 0 {
                    return Duration::from_secs(m * 60);
                }
            }
        } else if let Some(hrs_str) = trimmed.strip_suffix('h') {
            if let Ok(h) = hrs_str.parse::<u64>() {
                if h > 0 {
                    return Duration::from_secs(h * 3600);
                }
            }
        } else if let Ok(s) = trimmed.parse::<u64>() {
            if s > 0 {
                return Duration::from_secs(s);
            }
        }
    }
    Duration::from_secs(6 * 3600)
}

fn resolve_github_api_base_url() -> String {
    if let Ok(raw) = env::var("AETHERFLOW_GITHUB_API_BASE_URL") {
        let trimmed = raw.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "https://api.github.com".to_string()
}

pub fn build_update_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("AetherFlow-Updater")
        .build()
        .unwrap_or_default()
}

fn parse_effective_origin(url: &reqwest::Url) -> Option<(String, String, u16)> {
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url.host_str()?.to_ascii_lowercase();
    let effective_port = url.port().unwrap_or(match scheme.as_str() {
        "https" => 443,
        "http" => 80,
        _ => return None,
    });
    Some((scheme, host, effective_port))
}

fn parse_effective_origin_str(raw: &str) -> Option<(String, String, u16)> {
    let parsed = if raw.starts_with("https://") || raw.starts_with("http://") {
        reqwest::Url::parse(raw).ok()?
    } else {
        reqwest::Url::parse(&format!("https://{}", raw)).ok()?
    };
    parse_effective_origin(&parsed)
}

pub fn should_attach_github_token(request_url: &str, configured_api_base: &str) -> bool {
    let Ok(req_url) = reqwest::Url::parse(request_url) else {
        return false;
    };
    let Some((req_scheme, req_host, req_port)) = parse_effective_origin(&req_url) else {
        return false;
    };

    let is_loopback = {
        let h = req_host.trim().trim_start_matches('[').trim_end_matches(']');
        h == "127.0.0.1" || h == "localhost" || h == "::1"
    };

    // Reject plain http:// on non-loopback hosts
    if req_scheme != "https" && !is_loopback {
        return false;
    }

    // Reject untrusted third-party package registry hosts
    if req_host == "pypi.org"
        || req_host.ends_with(".pypi.org")
        || req_host == "files.pythonhosted.org"
        || req_host.ends_with(".pythonhosted.org")
        || req_host == "crates.io"
        || req_host.ends_with(".crates.io")
        || req_host == "registry.npmjs.org"
        || req_host.ends_with(".npmjs.org")
        || req_host == "gitlab.com"
        || req_host.ends_with(".gitlab.com")
        || req_host == "bitbucket.org"
        || req_host.ends_with(".bitbucket.org")
    {
        return false;
    }

    // 1. Built-in GitHub hosts: ONLY trust when scheme == "https" AND effective_port == 443!
    if req_scheme == "https" && req_port == 443 && matches!(req_host.as_str(), "api.github.com" | "github.com") {
        return true;
    }

    // 2. Exact origin match with configured_api_base AND (https OR loopback)
    if let Some((base_scheme, base_host, base_port)) = parse_effective_origin_str(configured_api_base) {
        if req_scheme == base_scheme && req_host == base_host && req_port == base_port && (req_scheme == "https" || is_loopback) {
            return true;
        }
    }

    // 3. AF_TRUSTED_GITHUB_ORIGINS environment variable
    if req_scheme == "https" {
        if let Ok(trusted) = env::var("AF_TRUSTED_GITHUB_ORIGINS") {
            for entry in trusted.split(',') {
                let entry_trimmed = entry.trim();
                if entry_trimmed.is_empty() {
                    continue;
                }
                if let Some((e_scheme, e_host, e_port)) = parse_effective_origin_str(entry_trimmed) {
                    if req_scheme == e_scheme && req_host == e_host && req_port == e_port {
                        return true;
                    }
                }
            }
        }
    }

    false
}

pub fn is_trusted_github_api_url(url: &str, github_api_base: &str) -> bool {
    should_attach_github_token(url, github_api_base)
}

fn build_github_http_client() -> reqwest::Client {
    build_update_http_client()
}

#[cfg(test)]
#[tokio::test]
async fn github_release_observation_follows_canonical_repository_redirect() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for redirect in [true, false] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let length = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..length]);
            let repository = if redirect { "davidnewhall/unpackerr" } else { "Unpackerr/unpackerr" };
            let (target_path, is_matched) = if request.starts_with(&format!("GET /repos/{repository}/releases?per_page=30 ")) {
                ("releases?per_page=30", true)
            } else if request.starts_with(&format!("GET /repos/{repository}/releases/latest ")) {
                ("releases/latest", true)
            } else {
                ("", false)
            };
            assert!(is_matched, "unexpected request: {request}");
            let response = if redirect {
                format!("HTTP/1.1 301 Moved Permanently\r\nLocation: http://{address}/repos/Unpackerr/unpackerr/{target_path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            } else {
                let body = r#"[{"tag_name":"v0.14.2","html_url":"https://github.com/Unpackerr/unpackerr/releases/tag/v0.14.2"}]"#;
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
            };
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let observed = detect_latest_github_release(
        &build_github_http_client(), &format!("http://{address}"), "davidnewhall/unpackerr",
    ).await.unwrap();
    server.await.unwrap();
    assert_eq!(observed.0, "0.14.2");
    assert!(observed.1.contains("Unpackerr/unpackerr"));
}

fn should_track_package(pkg: &Package) -> bool {
    if pkg.name == "readarr" {
        return true;
    }
    if pkg.update_source.is_empty() {
        return false;
    }
    match pkg.update_source.as_str() {
        "apt" => !pkg.update_package.is_empty(),
        "github" | "github_release" | "git_tags" | "git" | "git_commit" | "git_head" => {
            !pkg.version_command.is_empty()
                && (!pkg.update_repo.is_empty() || !pkg.update_repo_url.is_empty())
        }
        "pypi" => !pkg.version_command.is_empty(),
        "retired" | "legacy" | "pinned" => true,
        _ => !pkg.version_command.is_empty(),
    }
}

fn package_is_installed(pkg: &Package) -> bool {
    !pkg.lock_file.is_empty() && resolve_fs_path(&pkg.lock_file).exists()
}

pub fn is_package_installed(pkg: &Package) -> bool {
    package_is_installed(pkg) || crate::is_package_installed(&pkg.name)
}

pub async fn probe_package_update(
    client: &reqwest::Client,
    github_api_base: &str,
    pkg: &Package,
) -> (PackageUpdateRecord, bool) {
    let is_installed = package_is_installed(pkg);

    let installed_res = detect_installed_version(pkg).await;
    let installed_failed_early = installed_res.is_err()
        || installed_res.as_ref().map(|v| v.trim().is_empty()).unwrap_or(false);
    let installed_err_msg = installed_res.as_ref().err().map(|e| e.to_string());

    let latest_res = detect_latest_version(client, github_api_base, pkg).await;

    let observed_at = match &latest_res {
        Ok((_, _, obs)) => obs.clone(),
        Err(_) => String::new(),
    };

    let expected_source_key = canonical_update_source_key(github_api_base, pkg);
    let prev_record = get_package_update_map().get(&pkg.name).cloned();
    let (update_source, _) = effective_update_source_and_apt_package(pkg);
    let mut record = build_package_update_record_for_source(
        github_api_base,
        update_source,
        &pkg.name,
        is_installed,
        installed_res,
        latest_res
            .as_ref()
            .map(|(v, u, _)| (v.clone(), u.clone()))
            .map_err(|e| anyhow::anyhow!("{}", e)),
        prev_record.as_ref(),
        observed_at,
        &expected_source_key,
    );

    let source_matched = prev_record
        .as_ref()
        .map(|r| {
            !r.source_key.trim().is_empty() && r.source_key.trim() == expected_source_key.trim()
        })
        .unwrap_or(false);

    if record.latest_version.is_empty()
        && latest_res.is_err()
        && (pkg.update_source == "github_release" || pkg.update_source == "github")
        && !pkg.update_repo.is_empty()
    {
        if let Some((cached_v, cached_u, cached_obs)) = get_cached_github_release_stale_for_channel(github_api_base, &pkg.update_repo, &pkg.update_channel) {
            if tag_allowed_by_channel_for_source(&cached_v, &pkg.update_channel, &pkg.update_source) {
                record.latest_version = cached_v;
                if record.release_url.is_empty() {
                    record.release_url = cached_u;
                }
                if prev_record.is_none() || !source_matched {
                    record.checked_at = cached_obs;
                }
            }
        }
    }

    let is_retired = matches!(pkg.update_source.as_str(), "retired" | "legacy" | "pinned") || pkg.name == "readarr";
    let is_readarr_404 = pkg.name == "readarr" && !record.installed_version.is_empty() && match &latest_res {
        Err(e) => {
            let msg = e.to_string();
            msg.contains("404") || msg.contains("not found")
        }
        _ => false,
    };

    let installed_failed = installed_failed_early
        || record.error.to_ascii_lowercase().contains("installed version");

    if is_retired || is_readarr_404 {
        if record.latest_version.is_empty() {
            if pkg.name == "readarr" {
                record.latest_version = "0.4.18.2805".to_string();
            } else if !record.installed_version.is_empty() {
                record.latest_version = record.installed_version.clone();
            }
        }
        if installed_failed {
            if let Some(ref e) = installed_err_msg {
                record.error = format!("Installed version check failed: {e}");
            } else if record.error.is_empty() {
                record.error = "Installed version check failed: probe returned no output".to_string();
            }
            record.update_available = false;
        } else {
            if !record.installed_version.is_empty() && !record.latest_version.is_empty() {
                record.update_available = record.installed
                    && is_remote_version_newer_for_source(
                        &record.installed_version,
                        &record.latest_version,
                        &pkg.update_source,
                    );
            } else {
                record.update_available = false;
            }
            record.error = String::new();
        }
    }

    let notify = persist_and_cache_package_update(&record);
    (record, notify)
}

pub fn resolve_installed_package_version(
    installed_opt: Option<&str>,
    prev_record: Option<&PackageUpdateRecord>,
) -> (String, bool) {
    if let Some(v) = installed_opt {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return (trimmed.to_string(), false);
        }
    }
    let fallback = prev_record
        .map(|r| r.installed_version.trim().to_string())
        .unwrap_or_default();
    let fell_back = !fallback.is_empty();
    (fallback, fell_back)
}

pub async fn detect_installed_package_version(pkg: &Package) -> anyhow::Result<String> {
    detect_installed_version(pkg).await
}

pub fn open_dir_nofollow_stepwise(dir_path: &Path) -> Result<std::os::fd::OwnedFd, String> {
    use std::os::fd::FromRawFd;
    if !dir_path.is_absolute() {
        return Err(format!("path {:?} is not absolute", dir_path));
    }
    let root_fd = unsafe {
        libc::open(
            b"/\0".as_ptr() as *const libc::c_char,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("failed to open root directory '/': {}", err));
    }
    let mut current_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(root_fd) };

    for comp in dir_path.components() {
        match comp {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::ParentDir => {
                return Err("parent directory traversal ('..') is not permitted".to_string());
            }
            std::path::Component::Normal(name) => {
                use std::os::fd::AsRawFd;
                use std::os::unix::ffi::OsStrExt;
                let c_name = std::ffi::CString::new(name.as_bytes())
                    .map_err(|e| format!("invalid component name {:?}: {}", name, e))?;
                let next_fd = unsafe {
                    libc::openat(
                        current_fd.as_raw_fd(),
                        c_name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next_fd < 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(format!(
                        "failed to open dir component {:?} in {:?}: {}",
                        name, dir_path, err
                    ));
                }
                current_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(next_fd) };
            }
            std::path::Component::Prefix(_) => {
                return Err("path prefix is not supported on Unix".to_string());
            }
        }
    }

    Ok(current_fd)
}

pub fn read_receipt_bounded_nofollow(path: &Path) -> Result<Option<String>, String> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    if !path.is_absolute() {
        return Err(format!("receipt path {:?} must be absolute", path));
    }

    let parent = match path.parent() {
        Some(p) => p,
        None => return Err(format!("receipt path {:?} has no parent", path)),
    };
    let file_name = match path.file_name() {
        Some(f) => f,
        None => return Err(format!("receipt path {:?} has no file name", path)),
    };

    let parent_fd = match open_dir_nofollow_stepwise(parent) {
        Ok(fd) => fd,
        Err(e) => {
            if e.contains("No such file or directory") {
                return Ok(None);
            }
            return Err(e);
        }
    };

    let c_file_name = std::ffi::CString::new(file_name.as_bytes())
        .map_err(|e| format!("invalid file name {:?}: {}", file_name, e))?;

    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    let fstatat_res = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            c_file_name.as_ptr(),
            &mut stat_buf,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };

    if fstatat_res < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(format!("fstatat failed for {:?}: {}", path, err));
    }

    if (stat_buf.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!(
            "receipt {:?} is not a regular file (mode: {:o})",
            path, stat_buf.st_mode
        ));
    }

    if stat_buf.st_size < 0 || stat_buf.st_size > 64 * 1024 {
        return Err(format!(
            "receipt {:?} file size ({}) exceeds 64 KiB limit",
            path, stat_buf.st_size
        ));
    }

    let file_fd = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            c_file_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if file_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("openat failed for {:?}: {}", path, err));
    }
    let owned_file_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(file_fd) };

    let mut opened_stat: libc::stat = unsafe { std::mem::zeroed() };
    let fstat_res = unsafe { libc::fstat(owned_file_fd.as_raw_fd(), &mut opened_stat) };
    if fstat_res < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("fstat failed on opened receipt {:?}: {}", path, err));
    }
    if (opened_stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!(
            "opened receipt {:?} is not a regular file (mode: {:o})",
            path, opened_stat.st_mode
        ));
    }
    if opened_stat.st_dev != stat_buf.st_dev || opened_stat.st_ino != stat_buf.st_ino {
        return Err(format!(
            "receipt {:?} changed identity between stat and open",
            path
        ));
    }

    let mut file = std::fs::File::from(owned_file_fd);
    let mut content = String::new();
    let mut reader = (&mut file).take(64 * 1024 + 1);
    reader
        .read_to_string(&mut content)
        .map_err(|e| format!("reading receipt {:?}: {}", path, e))?;

    if content.len() > 64 * 1024 {
        return Err(format!(
            "receipt {:?} content exceeded 64 KiB limit",
            path
        ));
    }

    Ok(Some(content))
}

fn read_af_version_receipt(pkg: &Package) -> Option<String> {
    static AF_VER_PATH_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(/[A-Za-z0-9_./-]*/\.(?:af-version|af-components\.json))").unwrap());
    let mut candidate_paths = Vec::new();
    let is_filebot = pkg.name.eq_ignore_ascii_case("filebot");
    let opt_name = if is_filebot { "filebot-node" } else { pkg.name.as_str() };
    if let Some(ref root) = resolve_configured_fs_root() {
        candidate_paths.push(root.join(format!("opt/{}/.af-version", opt_name)));
        candidate_paths.push(root.join(format!("opt/{}/.af-components.json", opt_name)));
        candidate_paths.push(root.join(format!("var/lib/{}/.af-version", pkg.name)));
        candidate_paths.push(root.join(format!("var/lib/{}/.af-components.json", pkg.name)));
        for token in &pkg.version_command {
            for cap in AF_VER_PATH_RE.captures_iter(token) {
                if let Some(m) = cap.get(1) {
                    let rel = m.as_str().trim_start_matches('/');
                    candidate_paths.push(root.join(rel));
                }
            }
        }
    }
    candidate_paths.push(resolve_fs_path(&format!("/opt/{}/.af-version", opt_name)));
    candidate_paths.push(resolve_fs_path(&format!("/opt/{}/.af-components.json", opt_name)));
    candidate_paths.push(resolve_fs_path(&format!("/var/lib/{}/.af-version", pkg.name)));
    candidate_paths.push(resolve_fs_path(&format!("/var/lib/{}/.af-components.json", pkg.name)));
    for token in &pkg.version_command {
        for cap in AF_VER_PATH_RE.captures_iter(token) {
            if let Some(m) = cap.get(1) {
                candidate_paths.push(resolve_fs_path(m.as_str()));
            }
        }
    }
    if is_filebot {
        candidate_paths.retain(|p| {
            let s = p.to_string_lossy();
            !s.ends_with("opt/filebot/.af-version") && !s.ends_with("opt/filebot/.af-components.json")
        });
    }

    for path in candidate_paths {
        match read_receipt_bounded_nofollow(&path) {
            Ok(Some(contents)) => {
                let version = extract_version(&contents, &pkg.version_regex);
                if version.is_empty() {
                    let t = contents.trim();
                    if !t.is_empty() {
                        return Some(t.to_string());
                    }
                } else {
                    return Some(version);
                }
            }
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "rejected insecure or invalid receipt");
                continue;
            }
        }
    }
    None
}

fn resolve_git_dir_for_probe(logical_path: &str) -> Option<PathBuf> {
    let clean = logical_path.trim_start_matches('/');
    let candidates = [
        resolve_configured_fs_root().map(|r| r.join(clean)),
        Some(resolve_fs_path(logical_path)),
    ];
    candidates.into_iter().flatten().find(|p| p.exists())
}

async fn probe_live_git_version(pkg: &Package, budget: Duration) -> Option<Result<String, anyhow::Error>> {
    if pkg.name == "piped" || pkg.update_repo.eq_ignore_ascii_case("TeamPiped/Piped") {
        let fe_dir = resolve_git_dir_for_probe("/opt/piped/frontend/.git")
            .or_else(|| resolve_git_dir_for_probe("/opt/piped/.git"));
        let be_dir = resolve_git_dir_for_probe("/opt/piped/backend/.git")
            .or_else(|| resolve_git_dir_for_probe("/opt/piped-backend/.git"));
        let pr_dir = resolve_git_dir_for_probe("/opt/piped/proxy/.git")
            .or_else(|| resolve_git_dir_for_probe("/opt/piped-proxy/.git"));

        if fe_dir.is_some() || be_dir.is_some() || pr_dir.is_some() {
            let (Some(fe), Some(be), Some(pr)) = (fe_dir, be_dir, pr_dir) else {
                return Some(Err(anyhow::anyhow!("Incomplete or failed live git probe for piped components")));
            };

            let run_rev_parse = |git_dir: PathBuf| async move {
                let mut cmd = Command::new("git");
                cmd.args(["--git-dir", &git_dir.to_string_lossy(), "rev-parse", "HEAD"]);
                let out = update_probe_output(cmd, budget).await?;
                if !out.status.success() {
                    anyhow::bail!("git rev-parse HEAD failed in {}", git_dir.display());
                }
                let head = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if head.is_empty() {
                    anyhow::bail!("empty git HEAD in {}", git_dir.display());
                }
                Ok(head)
            };

            let (fe_res, be_res, pr_res) = tokio::join!(
                run_rev_parse(fe),
                run_rev_parse(be),
                run_rev_parse(pr),
            );

            match (fe_res, be_res, pr_res) {
                (Ok(fe_sha), Ok(be_sha), Ok(pr_sha)) => {
                    Some(Ok(format!(
                        "frontend:{},backend:{},proxy:{}",
                        fe_sha.to_ascii_lowercase(),
                        be_sha.to_ascii_lowercase(),
                        pr_sha.to_ascii_lowercase()
                    )))
                }
                _ => Some(Err(anyhow::anyhow!("Incomplete or failed live git probe for piped components"))),
            }
        } else {
            None
        }
    } else if pkg.update_source == "git"
        || resolve_git_dir_for_probe(&format!("/opt/{}/source/.git", pkg.name)).is_some()
        || resolve_git_dir_for_probe(&format!("/opt/{}/.git", pkg.name)).is_some()
    {
        if let Some(git_dir) = resolve_git_dir_for_probe(&format!("/opt/{}/source/.git", pkg.name))
            .or_else(|| resolve_git_dir_for_probe(&format!("/opt/{}/.git", pkg.name)))
        {
            let mut cmd = Command::new("git");
            cmd.args(["--git-dir", &git_dir.to_string_lossy(), "rev-parse", "HEAD"]);
            match update_probe_output(cmd, budget).await {
                Ok(out) if out.status.success() => {
                    let head = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !head.is_empty() {
                        Some(Ok(head.to_ascii_lowercase()))
                    } else {
                        Some(Err(anyhow::anyhow!("empty git HEAD in {}", git_dir.display())))
                    }
                }
                Ok(out) => {
                    Some(Err(anyhow::anyhow!(
                        "git rev-parse HEAD failed with {}: {}",
                        out.status,
                        String::from_utf8_lossy(&out.stderr).trim()
                    )))
                }
                Err(e) => Some(Err(e)),
            }
        } else {
            None
        }
    } else {
        None
    }
}

fn is_regular_executable(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.file_type().is_file() && (meta.permissions().mode() & 0o111) != 0 {
            return true;
        }
        if meta.file_type().is_symlink() {
            let path_str = path.to_string_lossy();
            if path_str.starts_with("/usr/bin/") || path_str.starts_with("/usr/local/bin/") {
                if let Ok(target_meta) = fs::metadata(path) {
                    if target_meta.file_type().is_file() && (target_meta.permissions().mode() & 0o111) != 0 {
                        if let Ok(canonical) = fs::canonicalize(path) {
                            let can_str = canonical.to_string_lossy();
                            if !can_str.starts_with("/tmp")
                                && !can_str.starts_with("/var/tmp")
                                && !can_str.starts_with("/dev/shm")
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
    #[cfg(not(unix))]
    {
        meta.file_type().is_file()
    }
}

fn dir_has_runtime_files(dir_path: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir_path) else {
        return false;
    };
    for entry in entries.flatten() {
        let entry_path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let lower = name_str.to_ascii_lowercase();

        if lower == ".af-version" || lower == ".af-components.json" || lower == "." || lower == ".." {
            continue;
        }

        if lower.ends_with(".lock")
            || lower.ends_with(".log")
            || lower.ends_with(".tmp")
            || lower.ends_with(".pid")
            || lower.ends_with(".bak")
            || lower.ends_with(".json")
            || lower.ends_with(".txt")
            || lower.ends_with(".conf")
            || lower.ends_with(".ini")
            || lower.ends_with(".yaml")
            || lower.ends_with(".yml")
            || lower.ends_with(".toml")
            || lower.ends_with(".db")
            || lower.ends_with(".sqlite")
        {
            continue;
        }

        if let Ok(meta) = fs::symlink_metadata(&entry_path) {
            if meta.file_type().is_dir() {
                if name_str == "bin" && dir_has_runtime_files(&entry_path) {
                    return true;
                }
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.file_type().is_file() && (meta.permissions().mode() & 0o111) != 0 {
                    return true;
                }
            }
            #[cfg(not(unix))]
            {
                if meta.file_type().is_file() {
                    return true;
                }
            }
        }
    }
    false
}

fn tokenize_systemd_command(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = cmd.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            '\\' if in_double => {
                if let Some(&next_c) = chars.peek() {
                    if next_c == '"' || next_c == '\\' || next_c == '$' || next_c == '`' {
                        chars.next();
                        cur.push(next_c);
                        continue;
                    }
                }
                cur.push('\\');
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    tokens.push(cur);
                    cur = String::new();
                }
            }
            c => {
                cur.push(c);
            }
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

pub fn is_valid_systemd_service_unit(resolved_unit_path: &Path, pkg: &Package) -> bool {
    let content = match read_receipt_bounded_nofollow(resolved_unit_path) {
        Ok(Some(c)) => c,
        _ => return false,
    };

    if content.trim().is_empty() {
        return false;
    }

    let mut exec_commands: Vec<String> = Vec::new();
    let mut working_directory: Option<PathBuf> = None;
    let mut current_section = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].trim().to_string();
            continue;
        }

        let Some((raw_key, raw_val)) = trimmed.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        let val = raw_val.trim();

        if key == "ExecStart" || key == "WorkingDirectory" {
            if current_section != "Service" {
                return false;
            }
        }

        if current_section != "Service" {
            continue;
        }

        if key == "WorkingDirectory" {
            if !val.is_empty() {
                working_directory = Some(PathBuf::from(val));
            }
            continue;
        }

        if key == "ExecStart" {
            if val.is_empty() {
                exec_commands.clear();
            } else {
                exec_commands.push(val.to_string());
            }
            continue;
        }
    }

    if exec_commands.is_empty() {
        return false;
    }

    const INTERPRETERS: &[&str] = &[
        "sh", "bash", "dash", "zsh", "env", "python", "python3", "python2",
        "node", "nodejs", "java", "ruby", "perl", "php", "dotnet",
    ];

    for cmd_str in &exec_commands {
        let mut raw = cmd_str.as_str();
        while raw.starts_with(['-', '@', '+', '!']) {
            raw = raw[1..].trim_start();
        }
        if raw.is_empty() {
            return false;
        }

        let tokens = tokenize_systemd_command(raw);
        if tokens.is_empty() {
            return false;
        }

        let exec_bin = &tokens[0];
        let resolved_exec = resolve_fs_path(exec_bin);
        if !is_regular_executable(&resolved_exec) {
            return false;
        }

        let bin_name = Path::new(exec_bin)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(exec_bin)
            .to_ascii_lowercase();

        let is_interpreter = INTERPRETERS.contains(&bin_name.as_str());

        if is_interpreter {
            for arg in &tokens[1..] {
                if arg.starts_with('-') {
                    continue;
                }
                let cand_path = if arg.starts_with('/') {
                    Some(PathBuf::from(arg))
                } else if let Some(ref wd) = working_directory {
                    Some(wd.join(arg))
                } else if arg.contains('.') || arg.contains('/') {
                    Some(PathBuf::from(arg))
                } else {
                    None
                };

                if let Some(p) = cand_path {
                    let resolved_p = resolve_fs_path(&p.to_string_lossy());
                    let is_file = fs::symlink_metadata(&resolved_p)
                        .map(|m| m.file_type().is_file())
                        .unwrap_or(false);
                    if !is_file {
                        return false;
                    }
                    break;
                }
            }

            let mut secondary_evidence = false;

            if pkg.name.eq_ignore_ascii_case("filebot") {
                let resolved_app = resolve_fs_path("/opt/filebot-node/server/app.js");
                if fs::symlink_metadata(&resolved_app)
                    .map(|m| m.file_type().is_file())
                    .unwrap_or(false)
                {
                    secondary_evidence = true;
                }
            }

            let candidate_dirs = [
                format!("/opt/{}", pkg.name),
                format!("/opt/{}/bin", pkg.name),
                format!("/var/lib/{}", pkg.name),
                format!("/etc/{}", pkg.name),
            ];
            for dir in &candidate_dirs {
                let resolved_dir = resolve_fs_path(dir);
                if dir_has_runtime_files(&resolved_dir) {
                    secondary_evidence = true;
                    break;
                }
            }

            if !secondary_evidence {
                let bin_paths = [
                    format!("/usr/local/bin/{}", pkg.name),
                    format!("/usr/bin/{}", pkg.name),
                    format!("/opt/{}/{}", pkg.name, pkg.name),
                    format!("/opt/{}/bin/{}", pkg.name, pkg.name),
                ];
                for b in &bin_paths {
                    let resolved_b = resolve_fs_path(b);
                    if is_regular_executable(&resolved_b) {
                        secondary_evidence = true;
                        break;
                    }
                }
            }

            if !secondary_evidence {
                let (update_source, apt_pkg) = effective_update_source_and_apt_package(pkg);
                if (update_source == "apt" || !pkg.update_package.is_empty()) && !apt_pkg.is_empty() {
                    let mut cmd = std::process::Command::new("dpkg-query");
                    if let Some(ref root) = resolve_configured_fs_root() {
                        let dpkg_dir = root.join("var/lib/dpkg");
                        if dpkg_dir.exists() {
                            cmd.arg(format!("--admindir={}", dpkg_dir.display()));
                        }
                    }
                    cmd.args(["-W", "-f=${Status}", apt_pkg]);
                    if let Ok(out) = cmd.output() {
                        if out.status.success() {
                            let status_str = String::from_utf8_lossy(&out.stdout);
                            if status_str.trim() == "install ok installed" {
                                secondary_evidence = true;
                            }
                        }
                    }
                }
            }

            if !secondary_evidence {
                return false;
            }
        }
    }

    true
}

fn has_independent_runtime_evidence(pkg: &Package) -> bool {
    if !is_package_installed(pkg) {
        return false;
    }

    if pkg.name.eq_ignore_ascii_case("filebot") {
        let resolved_app = resolve_fs_path("/opt/filebot-node/server/app.js");
        if fs::symlink_metadata(&resolved_app)
            .map(|m| m.file_type().is_file())
            .unwrap_or(false)
        {
            return true;
        }
    }

    // 1. Systemd unit file exists and is valid
    let mut unit_paths = vec![
        format!("/etc/systemd/system/{}.service", pkg.name),
        format!("/lib/systemd/system/{}.service", pkg.name),
    ];
    if !pkg.service_name.is_empty() {
        let u_str = if pkg.service_name.ends_with(".service") {
            pkg.service_name.clone()
        } else {
            format!("{}.service", pkg.service_name)
        };
        unit_paths.push(format!("/etc/systemd/system/{}", u_str));
        unit_paths.push(format!("/lib/systemd/system/{}", u_str));
    }
    for u in &unit_paths {
        let resolved = resolve_fs_path(u);
        if is_valid_systemd_service_unit(&resolved, pkg) {
            return true;
        }
    }

    // 2. Binary exists
    let bin_paths = [
        format!("/usr/local/bin/{}", pkg.name),
        format!("/usr/bin/{}", pkg.name),
        format!("/opt/{}/{}", pkg.name, pkg.name),
        format!("/opt/{}/bin/{}", pkg.name, pkg.name),
    ];
    for b in &bin_paths {
        let resolved = resolve_fs_path(b);
        if is_regular_executable(&resolved) {
            return true;
        }
    }
    if let Some(cmd_prog) = pkg.version_command.first() {
        if cmd_prog.starts_with('/') && !cmd_prog.ends_with("/cat") {
            let resolved = resolve_fs_path(cmd_prog);
            if is_regular_executable(&resolved) {
                return true;
            }
        }
    }

    // 3. Install directory contains actual runtime files beyond .af-version and .af-components.json
    let candidate_dirs = [
        format!("/opt/{}", pkg.name),
        format!("/opt/{}/bin", pkg.name),
        format!("/var/lib/{}", pkg.name),
        format!("/etc/{}", pkg.name),
    ];
    for dir in &candidate_dirs {
        let resolved = resolve_fs_path(dir);
        if dir_has_runtime_files(&resolved) {
            return true;
        }
    }

    false
}

pub async fn probe_installed_package_version_strict(pkg: &Package) -> anyhow::Result<String> {
    let receipt_opt = read_af_version_receipt(pkg);
    let cmd_only_reads_af_ver = pkg
        .version_command
        .first()
        .map(|s| s == "cat")
        .unwrap_or(false)
        && pkg
            .version_command
            .iter()
            .any(|arg| arg.contains(".af-version"));

    if let Some(git_res) = probe_live_git_version(pkg, Duration::from_secs(5)).await {
        match git_res {
            Ok(live_git_ver) => {
                if let Some(ref receipt_ver) = receipt_opt {
                    if !af_release::lifecycle::versions_match_target(receipt_ver, &live_git_ver)
                        && !af_release::lifecycle::versions_match_target(&live_git_ver, receipt_ver)
                    {
                        anyhow::bail!(
                            "Stale or mismatched .af-version receipt ({receipt_ver}) vs live git state ({live_git_ver})"
                        );
                    }
                }
                return Ok(live_git_ver);
            }
            Err(e) => return Err(e),
        }
    }

    let (update_source, _) = effective_update_source_and_apt_package(pkg);
    let has_live_command = !cmd_only_reads_af_ver && (!pkg.version_command.is_empty() || update_source == "apt");
    let live_res = if has_live_command {
        Some(run_live_version_command(pkg, Duration::from_secs(10)).await)
    } else {
        None
    };

    match (live_res, receipt_opt) {
        (Some(Ok(live_ver)), Some(receipt_ver)) => {
            if !af_release::lifecycle::versions_match_target(&receipt_ver, &live_ver)
                && !af_release::lifecycle::versions_match_target(&live_ver, &receipt_ver)
            {
                anyhow::bail!(
                    "Stale or mismatched .af-version receipt ({receipt_ver}) vs live runtime ({live_ver})"
                );
            }
            Ok(live_ver)
        }
        (Some(Ok(live_ver)), None) => Ok(live_ver),
        (Some(Err(e)), _) => Err(e),
        (None, Some(receipt_ver)) => {
            if !has_independent_runtime_evidence(pkg) {
                anyhow::bail!("No independent runtime evidence found alongside .af-version receipt");
            }
            Ok(receipt_ver)
        }
        (None, None) => {
            anyhow::bail!("no installed version probe configured or available for {}", pkg.name);
        }
    }
}

async fn check_single_package(
    client: &reqwest::Client,
    github_api_base: &str,
    pkg: &Package,
) -> (PackageUpdateRecord, bool) {
    probe_package_update(client, github_api_base, pkg).await
}

#[cfg(test)]
fn build_package_update_record(
    pkg_name: &str,
    is_installed: bool,
    installed_res: anyhow::Result<String>,
    latest_res: anyhow::Result<(String, String)>,
    prev_record: Option<&PackageUpdateRecord>,
    checked_at: String,
) -> PackageUpdateRecord {
    build_package_update_record_for_source(
        "https://api.github.com",
        "",
        pkg_name,
        is_installed,
        installed_res,
        latest_res,
        prev_record,
        checked_at,
        "",
    )
}

#[allow(clippy::too_many_arguments)]
fn build_package_update_record_for_source(
    github_api_base: &str,
    update_source: &str,
    pkg_name: &str,
    is_installed: bool,
    installed_res: anyhow::Result<String>,
    latest_res: anyhow::Result<(String, String)>,
    prev_record: Option<&PackageUpdateRecord>,
    checked_at: String,
    expected_source_key: &str,
) -> PackageUpdateRecord {
    let mut err_parts = Vec::new();
    let (installed_version, installed_fell_back) = match &installed_res {
        Ok(v) if !v.trim().is_empty() => (v.trim().to_string(), false),
        Ok(_) => {
            let (fallback, fell_back) = resolve_installed_package_version(None, prev_record);
            if is_installed && fell_back {
                tracing::warn!(package = pkg_name, "installed version probe returned empty output");
            }
            (fallback, is_installed && fell_back)
        }
        Err(e) => {
            tracing::warn!(package = pkg_name, error = %e, "installed version observation failed");
            let (fallback, fell_back) = resolve_installed_package_version(None, prev_record);
            (fallback, is_installed && fell_back)
        }
    };

    let resolved_expected_key = if !expected_source_key.trim().is_empty() {
        expected_source_key.trim().to_string()
    } else if let Ok(catalog) = crate::get_package_catalog() {
        if let Some(pkg) = catalog.iter().find(|p| p.name.eq_ignore_ascii_case(pkg_name)) {
            canonical_update_source_key(github_api_base, pkg)
        } else {
            let synth = Package {
                name: pkg_name.to_string(),
                update_source: update_source.to_string(),
                update_repo: pkg_name.to_string(),
                update_package: pkg_name.to_string(),
                ..Default::default()
            };
            canonical_update_source_key(github_api_base, &synth)
        }
    } else {
        let synth = Package {
            name: pkg_name.to_string(),
            update_source: update_source.to_string(),
            update_repo: pkg_name.to_string(),
            update_package: pkg_name.to_string(),
            ..Default::default()
        };
        canonical_update_source_key(github_api_base, &synth)
    };

    let source_matched = prev_record
        .map(|r| {
            !r.source_key.trim().is_empty() && r.source_key.trim() == resolved_expected_key.trim()
        })
        .unwrap_or(false);

    let current_channel = if let Some((_, ch)) = resolved_expected_key.rsplit_once('|') {
        let ch_clean = ch.trim();
        if (resolved_expected_key.starts_with("github:") || resolved_expected_key.starts_with("git"))
            && resolved_expected_key.matches('|').count() < 2
        {
            "stable"
        } else if ch_clean.is_empty() || ch_clean.contains('/') {
            "stable"
        } else {
            ch_clean
        }
    } else {
        "stable"
    };

    let effective_update_source = if !update_source.trim().is_empty() {
        update_source.trim()
    } else if let Some((src, _)) = resolved_expected_key.split_once(':') {
        src.trim()
    } else {
        ""
    };

    let valid_prev_upstream = if source_matched {
        prev_record
    } else {
        None
    };

    let mut stale_cache_observed_at: Option<String> = None;
    let mut used_prev_latest = false;

    let (latest_version, release_url) = match &latest_res {
        Ok((v, u)) => (v.clone(), u.clone()),
        Err(e) => {
            tracing::warn!(package = pkg_name, error = %e, "latest version observation failed");
            err_parts.push("Latest version could not be confirmed");
            let mut prev_ver = valid_prev_upstream
                .filter(|r| !r.latest_version.trim().is_empty() && tag_allowed_by_channel_for_source(&r.latest_version, current_channel, effective_update_source))
                .map(|r| r.latest_version.clone())
                .unwrap_or_default();
            let mut prev_url = if !prev_ver.is_empty() {
                valid_prev_upstream
                    .map(|r| r.release_url.clone())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            if !prev_ver.is_empty() {
                used_prev_latest = true;
            } else {
                if let Ok(pkgs) = crate::get_packages() {
                    if let Some(pkg) = pkgs.iter().find(|p| p.name == pkg_name) {
                        if (pkg.update_source == "github_release" || pkg.update_source == "github") && !pkg.update_repo.is_empty() {
                            let ch = if !pkg.update_channel.trim().is_empty() {
                                &pkg.update_channel
                            } else {
                                current_channel
                            };
                            if let Some((cached_v, cached_u, cached_obs)) = get_cached_github_release_stale_for_channel(github_api_base, &pkg.update_repo, ch) {
                                if tag_allowed_by_channel_for_source(&cached_v, ch, &pkg.update_source) {
                                    prev_ver = cached_v;
                                    if prev_url.is_empty() {
                                        prev_url = cached_u;
                                    }
                                    stale_cache_observed_at = Some(cached_obs);
                                }
                            }
                        }
                        if prev_ver.is_empty() {
                            if pkg.name == "threadfin" {
                                let fallback = af_runner::resolve_threadfin_target_version();
                                if !fallback.is_empty() {
                                    prev_ver = fallback.clone();
                                    if prev_url.is_empty() {
                                        prev_url = format!("https://github.com/Threadfin/Threadfin/releases/tag/{fallback}");
                                    }
                                }
                            }
                        }
                    }
                }
                if prev_ver.is_empty() {
                    if let Some((cached_v, cached_u, cached_obs)) = get_cached_github_release_stale_for_channel(github_api_base, pkg_name, current_channel) {
                        if tag_allowed_by_channel_for_source(&cached_v, current_channel, effective_update_source) {
                            prev_ver = cached_v;
                            if prev_url.is_empty() {
                                prev_url = cached_u;
                            }
                            stale_cache_observed_at = Some(cached_obs);
                        }
                    }
                }
            }
            (prev_ver, prev_url)
        }
    };

    if installed_res.is_err() || installed_res.as_ref().map(|v| v.trim().is_empty()).unwrap_or(false) {
        if is_installed && installed_fell_back && latest_res.is_ok() {
            err_parts.push("Installed version probe returned no output; retaining last known installed version");
        } else {
            err_parts.insert(0, "Installed version could not be confirmed");
        }
    }

    let update_available = if !is_installed {
        false
    } else if latest_res.is_ok() {
        if installed_res.is_ok() && !installed_fell_back && !installed_version.is_empty() && !installed_version.eq_ignore_ascii_case("unknown") {
            is_version_newer_for_source(&installed_version, &latest_version, effective_update_source)
        } else {
            // Installed probe failed/fell back; do not claim a confirmed update against fresh upstream
            false
        }
    } else if used_prev_latest {
        // Upstream latest_res failed, but previous latest_version was retained
        if installed_res.is_ok() && !installed_fell_back && !installed_version.is_empty() && !installed_version.eq_ignore_ascii_case("unknown") {
            // Fresh installed observation succeeded: recompute availability against retained latest_version!
            is_version_newer_for_source(&installed_version, &latest_version, effective_update_source)
        } else {
            // Installed probe also failed/fell back: preserve previous availability if channel allowed
            valid_prev_upstream
                .filter(|r| tag_allowed_by_channel_for_source(&r.latest_version, current_channel, effective_update_source))
                .map(|record| record.update_available)
                .unwrap_or(false)
        }
    } else {
        false
    };

    let checked_at = if latest_res.is_err() {
        if used_prev_latest {
            valid_prev_upstream
                .map(|p| p.checked_at.clone())
                .unwrap_or_default()
        } else {
            stale_cache_observed_at.unwrap_or_default()
        }
    } else {
        checked_at
    };

    PackageUpdateRecord {
        package_id: pkg_name.to_string(),
        installed: is_installed,
        installed_version,
        latest_version,
        update_available,
        checked_at,
        release_url,
        error: err_parts.join("; "),
        source_key: resolved_expected_key,
    }
}

async fn update_probe_output(
    command: Command,
    budget: Duration,
) -> anyhow::Result<std::process::Output> {
    // The supervisor retains process-tree ownership through cancellation,
    // deadline/output failure and pipe cleanup; a response timeout is not enough.
    af_runner::bounded_command::output(command, budget, 1024 * 1024)
        .await
        .map_err(Into::into)
}

fn effective_update_source_and_apt_package(pkg: &Package) -> (&str, &str) {
    if af_runner::select_package_engine(&pkg.name) == af_runner::PackageEngineMode::DeclarativeRust
        && matches!(
            pkg.name.as_str(),
            "prometheus" | "netdata" | "mergerfs"
        )
    {
        let apt_pkg = if pkg.update_package.is_empty() {
            pkg.name.as_str()
        } else {
            pkg.update_package.as_str()
        };
        return ("apt", apt_pkg);
    }
    let src = pkg.update_source.as_str();
    if src == "github_release" || src == "github" {
        ("github", pkg.update_package.as_str())
    } else {
        (src, pkg.update_package.as_str())
    }
}

fn resolve_configured_fs_root() -> Option<PathBuf> {
    for env_key in ["AETHERFLOW_FS_ROOT", "AETHERFLOW_INSTALL_ROOT"] {
        if let Ok(root) = env::var(env_key) {
            let trimmed = root.trim();
            if !trimmed.is_empty() && trimmed != "/" {
                return Some(PathBuf::from(trimmed));
            }
        }
    }
    None
}

pub async fn run_live_version_command(pkg: &Package, budget: Duration) -> anyhow::Result<String> {
    if let Some(git_res) = probe_live_git_version(pkg, budget).await {
        return git_res;
    }
    let (update_source, apt_package) = effective_update_source_and_apt_package(pkg);
    match update_source {
        "apt" => {
            if apt_package.is_empty() {
                anyhow::bail!("no apt package configured for {}", pkg.name);
            }
            let mut command = Command::new("dpkg-query");
            if let Some(ref root) = resolve_configured_fs_root() {
                let dpkg_dir = root.join("var/lib/dpkg");
                if dpkg_dir.exists() {
                    command.arg(format!("--admindir={}", dpkg_dir.display()));
                }
            }
            command.args(["-W", "-f=${Version}", apt_package]);
            let out = update_probe_output(command, budget).await?;

            if !out.status.success() {
                anyhow::bail!(
                    "dpkg-query exited with {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }

            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let version = extract_version(&combined, &pkg.version_regex);
            if version.is_empty() {
                anyhow::bail!("unable to parse installed apt version for {}", pkg.name);
            }
            Ok(version)
        }
        _ => {
            if pkg.version_command.is_empty() {
                anyhow::bail!("no version command configured");
            }
            let mut version_command = pkg.version_command.clone();
            if version_command.len() == 3
                && (version_command[0] == "bash" || version_command[0] == "sh")
                && (version_command[1] == "-lc" || version_command[1] == "-c")
            {
                let script = &version_command[2];
                if script.contains(".af-version") {
                    let mut clean = script.as_str();
                    if let Some(pos) = clean.rfind("||") {
                        let rhs = clean[pos + 2..].trim();
                        if rhs.starts_with("cat ") && rhs.contains(".af-version") {
                            clean = clean[..pos].trim();
                        }
                    }
                    if clean.starts_with("if [ -s ")
                        && clean.contains(".af-version")
                        && clean.contains("; else ")
                        && clean.ends_with("; fi")
                    {
                        if let Some(idx1) = clean.find("; else ") {
                            if let Some(idx2) = clean.rfind("; fi") {
                                if idx1 < idx2 {
                                    let mut inner = clean[idx1 + 7..idx2].trim();
                                    if inner.starts_with("bash -lc ") {
                                        inner = inner[9..].trim().trim_matches('\'').trim_matches('"');
                                    }
                                    clean = inner;
                                }
                            }
                        }
                    }
                    version_command[2] = clean.to_string();
                }
            }
            let raw_prog = &version_command[0];
            let resolved_prog = resolve_fs_path(raw_prog);
            let prog: PathBuf = if resolved_prog.exists() {
                resolved_prog
            } else if raw_prog == "/usr/local/bin/prometheus" {
                let alt = resolve_fs_path("/usr/bin/prometheus");
                if alt.exists() {
                    alt
                } else {
                    resolved_prog
                }
            } else {
                PathBuf::from(raw_prog)
            };
            let args: Vec<String> = version_command[1..]
                .iter()
                .map(|arg| {
                    if arg.starts_with('/') {
                        let rebased = resolve_fs_path(arg);
                        if rebased.exists() {
                            return rebased.to_string_lossy().into_owned();
                        }
                    }
                    arg.clone()
                })
                .collect();
            let mut command = Command::new(&prog);
            if let Some(ref root) = resolve_configured_fs_root() {
                command.env("AETHERFLOW_FS_ROOT", root);
            }
            command.args(&args);
            let out = update_probe_output(command, budget).await?;

            if !out.status.success() {
                anyhow::bail!(
                    "version command exited with {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }

            let stdout_str = String::from_utf8_lossy(&out.stdout);
            let stderr_str = String::from_utf8_lossy(&out.stderr);
            let combined = format!(
                "{}\n{}",
                stdout_str,
                stderr_str
            );

            for line in combined.lines() {
                let trimmed_line = line.trim();
                if let Some(manifest) = parse_component_manifest(trimmed_line) {
                    return Ok(normalize_component_manifest(&manifest));
                }
            }

            if update_source == "git" {
                return parse_git_head(&stdout_str);
            }

            let version = extract_version(&combined, &pkg.version_regex);
            if version.is_empty() {
                anyhow::bail!("unable to parse version output");
            }
            Ok(version)
        }
    }
}

async fn detect_installed_version(pkg: &Package) -> anyhow::Result<String> {
    probe_installed_package_version_strict(pkg).await
}

pub async fn detect_latest_piped_manifest() -> anyhow::Result<(String, String, String)> {
    let (fe, be, px) = tokio::try_join!(
        detect_latest_git_head("https://github.com/TeamPiped/Piped.git", "TeamPiped/Piped"),
        detect_latest_git_head("https://github.com/TeamPiped/Piped-Backend.git", "TeamPiped/Piped-Backend"),
        detect_latest_git_head("https://github.com/TeamPiped/Piped-Proxy.git", "TeamPiped/Piped-Proxy"),
    )?;
    let manifest = format!("frontend:{},backend:{},proxy:{}", fe.0, be.0, px.0);
    let oldest = [&fe.2, &be.2, &px.2]
        .into_iter()
        .min_by_key(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .unwrap()
        .clone();
    Ok((manifest, "https://github.com/TeamPiped/Piped/commits/HEAD".to_string(), oldest))
}

async fn detect_latest_version(
    client: &reqwest::Client,
    github_api_base: &str,
    pkg: &Package,
) -> anyhow::Result<(String, String, String)> {
    if pkg.name == "readarr" {
        let ver = if !pkg.update_package.is_empty() {
            pkg.update_package.clone()
        } else {
            "0.4.18.2805".to_string()
        };
        return Ok((ver, String::new(), Utc::now().to_rfc3339()));
    }
    if pkg.name == "threadfin" {
        if af_runner::resolve_threadfin_sha256_override().is_some() {
            let target_ver = af_runner::resolve_threadfin_target_version();
            let release_url = format!(
                "https://github.com/Threadfin/Threadfin/releases/tag/{}",
                target_ver
            );
            return Ok((target_ver, release_url, Utc::now().to_rfc3339()));
        }
        let repo = if pkg.update_repo.trim().is_empty() {
            "Threadfin/Threadfin"
        } else {
            pkg.update_repo.trim()
        };
        return detect_latest_github_release_for_channel(client, github_api_base, repo, &pkg.update_channel).await;
    }
    if pkg.name == "piped"
        && pkg.update_repo == "TeamPiped/Piped"
        && (pkg.update_repo_url.is_empty() || pkg.update_repo_url.contains("github.com/TeamPiped/Piped"))
    {
        return detect_latest_piped_manifest().await;
    }
    let (update_source, apt_package) = effective_update_source_and_apt_package(pkg);
    match update_source {
        "retired" | "legacy" | "pinned" => {
            let ver = if !pkg.update_package.is_empty() {
                pkg.update_package.clone()
            } else if pkg.name == "readarr" {
                "0.4.18.2805".to_string()
            } else {
                String::new()
            };
            Ok((ver, String::new(), Utc::now().to_rfc3339()))
        }
        "pypi" => {
            let pypi_pkg = if pkg.name == "pyload" {
                "pyload-ng"
            } else if !pkg.update_package.is_empty() {
                &pkg.update_package
            } else {
                &pkg.name
            };
            detect_latest_pypi_version(client, pypi_pkg).await
        }
        "apt" => detect_latest_apt_version(apt_package).await,
        "github" | "github_release" => {
            detect_latest_github_release_for_channel(client, github_api_base, &pkg.update_repo, &pkg.update_channel).await
        }
        "git_tags" | "git" | "git_commit" | "git_head" => {
            let repo_url = if !pkg.update_repo_url.is_empty() {
                pkg.update_repo_url.clone()
            } else if !pkg.update_repo.is_empty() {
                format!("https://github.com/{}.git", pkg.update_repo)
            } else {
                String::new()
            };
            if update_source == "git" || update_source == "git_commit" || update_source == "git_head" {
                detect_latest_git_head(&repo_url, &pkg.update_repo).await
            } else {
                detect_latest_git_tag_for_channel(&repo_url, &pkg.update_repo, &pkg.update_channel).await
            }
        }
        other => anyhow::bail!("unsupported update source {:?}", other),
    }
}

pub async fn detect_latest_pypi_version(
    client: &reqwest::Client,
    package_name: &str,
) -> anyhow::Result<(String, String, String)> {
    if package_name.trim().is_empty() {
        anyhow::bail!("missing PyPI package name");
    }
    let url = format!("https://pypi.org/pypi/{}/json", package_name.trim());
    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .header("User-Agent", "AetherFlow-Updater")
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("PyPI API returned {}", resp.status());
    }

    let pypi: PyPiResponse = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("decode PyPI response: {}", e))?;

    let version = extract_version(&pypi.info.version, "");
    if version.is_empty() {
        anyhow::bail!("unable to parse PyPI version {:?}", pypi.info.version);
    }

    let homepage = pypi
        .info
        .project_urls
        .as_ref()
        .and_then(|urls| {
            urls.get("Homepage")
                .or_else(|| urls.get("homepage"))
                .or_else(|| urls.get("Source"))
                .or_else(|| urls.get("source"))
        })
        .cloned()
        .unwrap_or_else(|| format!("https://pypi.org/project/{}/{}/", package_name.trim(), version));

    Ok((version, homepage, Utc::now().to_rfc3339()))
}

pub async fn detect_latest_git_head(repo_url: &str, repo: &str) -> anyhow::Result<(String, String, String)> {
    let url = if !repo_url.trim().is_empty() {
        repo_url.trim().to_string()
    } else if !repo.trim().is_empty() {
        format!("https://github.com/{}.git", repo.trim())
    } else {
        anyhow::bail!("missing repository URL");
    };

    let cache_key = git_head_cache_key(repo_url, repo);

    if let Ok(cache) = GIT_REMOTE_HEAD_CACHE.lock() {
        if let Some((head, h_url, timestamp, observed_at)) = cache.get(&cache_key) {
            if timestamp.elapsed() < Duration::from_secs(15 * 60) {
                return Ok((head.clone(), h_url.clone(), observed_at.clone()));
            }
        }
    }

    let mut command = Command::new("git");
    command.args(["ls-remote", "--exit-code", &url, "HEAD"]);
    let output = update_probe_output(command, Duration::from_secs(20)).await?;
    if !output.status.success() {
        anyhow::bail!(
            "git ls-remote HEAD failed: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let head = parse_git_head(&String::from_utf8_lossy(&output.stdout))?;
    let sanitized_url = sanitize_git_remote_url_for_display(&url);
    let mut clean_url = sanitized_url.trim_end_matches(".git").to_string();
    if clean_url.is_empty() && !repo.trim().is_empty() {
        clean_url = format!("https://github.com/{}", repo.trim());
    }
    let res = (
        head,
        af_release::lifecycle::sanitize_persisted_lifecycle_text(&format!("{}/commits/HEAD", clean_url)),
    );
    let now_rfc3339 = Utc::now().to_rfc3339();
    if let Ok(mut cache) = GIT_REMOTE_HEAD_CACHE.lock() {
        cache.insert(cache_key.clone(), (res.0.clone(), res.1.clone(), Instant::now(), now_rfc3339.clone()));
    }
    Ok((res.0, res.1, now_rfc3339))
}

pub async fn detect_git_remote_head(repo_url: &str, repo: &str) -> anyhow::Result<(String, String, String)> {
    detect_latest_git_head(repo_url, repo).await
}

async fn detect_latest_apt_version(package_name: &str) -> anyhow::Result<(String, String, String)> {
    let mut command = Command::new("apt-cache");
    command.args(["policy", package_name]);
    let out = update_probe_output(command, Duration::from_secs(15)).await?;

    if !out.status.success() {
        anyhow::bail!(
            "apt-cache exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Candidate:") {
            let candidate = rest.trim();
            if candidate != "(none)" && !candidate.is_empty() {
                let version = normalize_tag_or_version_prefix(candidate).trim();
                if !version.is_empty() {
                    return Ok((version.to_string(), String::new(), Utc::now().to_rfc3339()));
                }
            }
            break;
        }
    }

    anyhow::bail!("candidate version not found")
}

pub async fn detect_latest_github_release(
    client: &reqwest::Client,
    github_api_base: &str,
    repo: &str,
) -> anyhow::Result<(String, String, String)> {
    detect_latest_github_release_for_channel(client, github_api_base, repo, "stable").await
}

fn parse_github_link_next_url(header_val: &str) -> Option<String> {
    for part in header_val.split(',') {
        let part = part.trim();
        if part.ends_with("rel=\"next\"") || part.contains("rel=\"next\"") {
            if let Some(start) = part.find('<') {
                if let Some(end) = part.find('>') {
                    if start < end {
                        return Some(part[start + 1..end].trim().to_string());
                    }
                }
            }
        }
    }
    None
}

pub async fn detect_latest_github_release_for_channel(
    client: &reqwest::Client,
    github_api_base: &str,
    repo: &str,
    channel: &str,
) -> anyhow::Result<(String, String, String)> {
    if repo.trim().is_empty() {
        anyhow::bail!("missing GitHub repo");
    }

    let clean_repo = repo.trim();
    let effective_channel_owned = {
        let t = channel.trim().to_ascii_lowercase();
        if t.is_empty() {
            "stable".to_string()
        } else {
            t
        }
    };
    let effective_channel = effective_channel_owned.as_str();
    let cache_key = github_release_cache_key_for_channel(github_api_base, clean_repo, effective_channel);

    if let Ok(cache) = GITHUB_RELEASE_CACHE.lock() {
        if let Some((ver, url, timestamp, observed_at)) = cache.get(&cache_key) {
            if timestamp.elapsed() < Duration::from_secs(15 * 60) {
                if tag_allowed_by_channel(ver, effective_channel) {
                    return Ok((ver.clone(), url.clone(), observed_at.clone()));
                }
            }
        }
    }

    let is_rate_limited = is_github_api_rate_limited(github_api_base, "releases");
    if is_rate_limited {
        anyhow::bail!("GitHub API rate limit backoff active for {clean_repo}");
    }

    let is_stable = effective_channel == "stable";
    let mut all_releases: Vec<GitHubReleaseResponse> = Vec::new();
    let mut current_url = format!("{}/repos/{}/releases?per_page=30", github_api_base.trim_end_matches('/'), clean_repo);
    let mut page_count = 0;
    const MAX_RELEASE_PAGES: usize = 10;

    while page_count < MAX_RELEASE_PAGES {
        page_count += 1;
        let mut req = client
            .get(&current_url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "AetherFlow-Updater");

        if is_trusted_github_api_url(&current_url, github_api_base) {
            if let Ok(token) = env::var("AF_GITHUB_TOKEN").or_else(|_| env::var("GITHUB_TOKEN")) {
                let trimmed = token.trim();
                if !trimmed.is_empty() {
                    req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", trimmed));
                }
            }
        }

        let resp = req.send().await?;
        let status = resp.status();
        let status_code = status.as_u16();

        if page_count == 1 && status == reqwest::StatusCode::NOT_FOUND {
            let fb_url = format!("{}/repos/{}/releases/latest", github_api_base.trim_end_matches('/'), clean_repo);
            let mut fb_req = client
                .get(&fb_url)
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", "AetherFlow-Updater");
            if is_trusted_github_api_url(&fb_url, github_api_base) {
                if let Ok(token) = env::var("AF_GITHUB_TOKEN").or_else(|_| env::var("GITHUB_TOKEN")) {
                    let trimmed = token.trim();
                    if !trimmed.is_empty() {
                        fb_req = fb_req.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", trimmed));
                    }
                }
            }
            let fb_resp = fb_req.send().await?;
            let fb_status = fb_resp.status();
            let fb_rem_zero = fb_resp
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim() == "0")
                .unwrap_or(false);
            let fb_ra_hdr = fb_resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let fb_res_hdr = fb_resp
                .headers()
                .get("x-ratelimit-reset")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let fb_rb_hdr = fb_resp
                .headers()
                .get("x-ratelimit-resource")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            let fb_bytes = fb_resp.bytes().await?;
            let fb_str = String::from_utf8_lossy(&fb_bytes);
            let fb_lower = fb_str.to_ascii_lowercase();
            let fb_has_rate_limit = fb_lower.contains("rate limit")
                || fb_lower.contains("secondary rate limit")
                || fb_lower.contains("abuse detection")
                || fb_lower.contains("too many requests");

            let fb_is_rate_limit_resp = fb_status == reqwest::StatusCode::TOO_MANY_REQUESTS
                || (fb_status == reqwest::StatusCode::FORBIDDEN && (fb_rem_zero || fb_ra_hdr.is_some() || fb_has_rate_limit));

            if fb_is_rate_limit_resp {
                let mut cooldown = Duration::from_secs(60);
                if let Some(retry_after) = fb_ra_hdr.as_deref() {
                    if let Ok(secs) = retry_after.trim().parse::<u64>() {
                        cooldown = Duration::from_secs(secs.clamp(1, 3600));
                    }
                } else if let Some(reset) = fb_res_hdr.as_deref() {
                    if let Ok(reset_epoch) = reset.trim().parse::<i64>() {
                        let now_epoch = Utc::now().timestamp();
                        if reset_epoch > now_epoch {
                            let diff = (reset_epoch - now_epoch) as u64;
                            cooldown = Duration::from_secs(diff.clamp(1, 3600));
                        }
                    }
                }

                if let Some(ref res_b) = fb_rb_hdr {
                    record_github_api_rate_limit(github_api_base, res_b, cooldown);
                }
                record_github_api_rate_limit(github_api_base, "releases", cooldown);
                record_github_api_rate_limit(github_api_base, "tags", cooldown);
                record_github_api_rate_limit(github_api_base, "commits", cooldown);
                record_github_api_rate_limit(github_api_base, "core", cooldown);
                record_github_api_rate_limit(github_api_base, "default", cooldown);

                anyhow::bail!("GitHub API rate limit exceeded for {clean_repo} (status {})", fb_status.as_u16());
            }

            if !fb_status.is_success() {
                anyhow::bail!("GitHub API returned {}", fb_status);
            }

            if let Ok(single) = serde_json::from_slice::<GitHubReleaseResponse>(&fb_bytes) {
                all_releases.push(single);
            }
            break;
        }

        let rem_zero = resp
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim() == "0")
            .unwrap_or(false);
        let ra_hdr = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let res_hdr = resp
            .headers()
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let rb_hdr = resp
            .headers()
            .get("x-ratelimit-resource")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let link_hdr = resp
            .headers()
            .get("link")
            .or_else(|| resp.headers().get("Link"))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let body_bytes = resp.bytes().await?;
        let body_str = String::from_utf8_lossy(&body_bytes);
        let body_lower = body_str.to_ascii_lowercase();

        let body_has_rate_limit = body_lower.contains("rate limit")
            || body_lower.contains("secondary rate limit")
            || body_lower.contains("abuse detection")
            || body_lower.contains("too many requests");

        let is_rate_limit_resp = status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || (status == reqwest::StatusCode::FORBIDDEN && (rem_zero || ra_hdr.is_some() || body_has_rate_limit));

        if is_rate_limit_resp {
            let mut cooldown = Duration::from_secs(60);
            if let Some(retry_after) = ra_hdr.as_deref() {
                if let Ok(secs) = retry_after.trim().parse::<u64>() {
                    cooldown = Duration::from_secs(secs.clamp(1, 3600));
                }
            } else if let Some(reset) = res_hdr.as_deref() {
                if let Ok(reset_epoch) = reset.trim().parse::<i64>() {
                    let now_epoch = Utc::now().timestamp();
                    if reset_epoch > now_epoch {
                        let diff = (reset_epoch - now_epoch) as u64;
                        cooldown = Duration::from_secs(diff.clamp(1, 3600));
                    }
                }
            }

            if let Some(ref res_b) = rb_hdr {
                record_github_api_rate_limit(github_api_base, res_b, cooldown);
            }
            record_github_api_rate_limit(github_api_base, "releases", cooldown);
            record_github_api_rate_limit(github_api_base, "tags", cooldown);
            record_github_api_rate_limit(github_api_base, "commits", cooldown);
            record_github_api_rate_limit(github_api_base, "core", cooldown);
            record_github_api_rate_limit(github_api_base, "default", cooldown);

            anyhow::bail!("GitHub API rate limit exceeded for {clean_repo} (status {status_code})");
        }

        if !status.is_success() {
            if page_count > 1 {
                anyhow::bail!("GitHub API returned {} on page {}", status, page_count);
            }
            anyhow::bail!("GitHub API returned {}", status);
        }

        let page_releases: Vec<GitHubReleaseResponse> = match serde_json::from_slice::<Vec<GitHubReleaseResponse>>(&body_bytes) {
            Ok(list) => list,
            Err(_) => {
                let single = serde_json::from_slice::<GitHubReleaseResponse>(&body_bytes)
                    .map_err(|e| anyhow::anyhow!("decode GitHub releases: {}", e))?;
                vec![single]
            }
        };

        let page_len = page_releases.len();
        all_releases.extend(page_releases);

        let next_from_link = link_hdr.as_deref().and_then(parse_github_link_next_url);
        let has_another_page = next_from_link.is_some() || page_len >= 30;
        if page_count >= MAX_RELEASE_PAGES && has_another_page {
            anyhow::bail!(
                "GitHub release pagination exceeded maximum page limit ({}) for '{}'; refusing to cache incomplete release set",
                MAX_RELEASE_PAGES,
                clean_repo
            );
        }

        if let Some(next_url) = next_from_link {
            if validate_github_releases_next_url(&next_url, github_api_base, clean_repo) {
                current_url = next_url;
                continue;
            }
            anyhow::bail!(
                "Untrusted or cross-repository GitHub pagination Link URL '{}' for '{}'",
                sanitize_git_remote_url_for_display(&next_url),
                clean_repo
            );
        }

        if page_len >= 30 {
            current_url = format!(
                "{}/repos/{}/releases?per_page=30&page={}",
                github_api_base.trim_end_matches('/'),
                clean_repo,
                page_count + 1
            );
        } else {
            break;
        }
    }

    let mut best_candidate: Option<(String, String, bool)> = None;
    for rel in all_releases {
        if rel.draft {
            continue;
        }
        if is_stable && rel.prerelease {
            continue;
        }
        let mut version = extract_version(&rel.tag_name, "");
        if version.is_empty() {
            let normalized_tag = af_release::lifecycle::normalize_version(&rel.tag_name);
            version = extract_version(normalized_tag, "");
        }
        if version.is_empty() {
            continue;
        }

        if !tag_allowed_by_channel_for_source(&version, effective_channel, "github")
            || !tag_allowed_by_channel_for_source(&rel.tag_name, effective_channel, "github")
        {
            continue;
        }

        let is_pre = rel.prerelease || !tag_allowed_by_channel_for_source(&rel.tag_name, "stable", "github");
        match &best_candidate {
            None => {
                best_candidate = Some((version, rel.html_url, is_pre));
            }
            Some((current_ver, _, current_is_pre)) => {
                let ord = af_release::lifecycle::compare_versions(&version, current_ver);
                let should_replace = match ord {
                    std::cmp::Ordering::Greater => true,
                    std::cmp::Ordering::Equal => {
                        effective_channel == "prerelease" && is_pre && !*current_is_pre
                    }
                    std::cmp::Ordering::Less => false,
                };
                if should_replace {
                    best_candidate = Some((version, rel.html_url, is_pre));
                }
            }
        }
    }

    let Some((version, html_url, _)) = best_candidate else {
        anyhow::bail!(
            "No eligible GitHub release found for repo '{}' on channel '{}'",
            clean_repo,
            effective_channel
        );
    };

    let result = (
        af_release::lifecycle::sanitize_persisted_lifecycle_text(&version),
        sanitize_git_remote_url_for_display(&html_url),
    );
    let now_rfc3339 = Utc::now().to_rfc3339();
    if let Ok(mut cache) = GITHUB_RELEASE_CACHE.lock() {
        cache.insert(cache_key.clone(), (result.0.clone(), result.1.clone(), Instant::now(), now_rfc3339.clone()));
    }
    Ok((result.0, result.1, now_rfc3339))
}

pub fn normalize_tag_or_version_prefix(raw: &str) -> &str {
    let mut s = raw.trim();
    loop {
        if let Some(rest) = s.strip_prefix("release-v") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix("release-") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix("release/") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix('v') {
            s = rest;
        } else if let Some(rest) = s.strip_prefix('V') {
            s = rest;
        } else {
            break;
        }
    }
    s
}

pub fn is_prerelease_version_for_channel(version_or_tag: &str) -> bool {
    af_release::lifecycle::is_prerelease_version_for_channel(version_or_tag)
}

pub fn tag_allowed_by_channel_for_source(
    version_or_tag: &str,
    channel: &str,
    update_source: &str,
) -> bool {
    let effective_channel_owned = {
        let t = channel.trim().to_ascii_lowercase();
        if t.is_empty() {
            "stable".to_string()
        } else {
            t
        }
    };
    let effective_channel = effective_channel_owned.as_str();

    let is_pre = af_release::lifecycle::is_prerelease_version_for_channel_with_source(
        version_or_tag,
        if update_source.trim().is_empty() {
            None
        } else {
            Some(update_source)
        },
    );

    if effective_channel == "stable" {
        return !is_pre;
    }
    if !is_pre {
        return true;
    }
    let lower = version_or_tag.to_ascii_lowercase();
    match effective_channel {
        "rc" => lower.contains("rc"),
        "beta" => lower.contains("beta") || lower.contains("rc"),
        "alpha" => lower.contains("alpha") || lower.contains("beta") || lower.contains("rc"),
        "nightly" => true,
        "prerelease" | "edge" | "all" => true,
        _ => lower.contains(effective_channel),
    }
}

pub fn tag_allowed_by_channel(version_or_tag: &str, channel: &str) -> bool {
    tag_allowed_by_channel_for_source(version_or_tag, channel, "")
}

pub async fn detect_latest_git_tag_for_channel(
    repo_url: &str,
    repo: &str,
    channel: &str,
) -> anyhow::Result<(String, String, String)> {
    let clean_repo_url = if !repo_url.trim().is_empty() {
        repo_url.trim().to_string()
    } else if !repo.trim().is_empty() {
        format!("https://github.com/{}.git", repo.trim())
    } else {
        anyhow::bail!("missing repository URL");
    };

    let mut command = Command::new("git");
    command.args(["ls-remote", "--tags", "--refs", clean_repo_url.trim()]);
    let out = update_probe_output(command, Duration::from_secs(20)).await?;

    if !out.status.success() {
        anyhow::bail!(
            "git ls-remote failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut best_allowed = String::new();
    let mut tag_count = 0usize;
    for line in stdout.lines() {
        if !line.contains("refs/tags/") {
            continue;
        }
        let Some(idx) = line.rfind('/') else {
            continue;
        };
        let ref_name = line[idx + 1..].trim();
        let mut version = extract_version(ref_name, "");
        if version.is_empty() {
            let normalized = af_release::lifecycle::normalize_version(ref_name);
            version = extract_version(normalized, "");
        }
        if version.is_empty() {
            continue;
        }
        tag_count += 1;
        if tag_allowed_by_channel_for_source(ref_name, channel, "git")
            && tag_allowed_by_channel_for_source(&version, channel, "git")
            && (best_allowed.is_empty() || is_remote_version_newer(&best_allowed, &version))
        {
            best_allowed = version;
        }
    }

    let effective_channel = if channel.trim().is_empty() {
        "stable"
    } else {
        channel.trim()
    };

    if best_allowed.is_empty() {
        if tag_count == 0 && (repo.trim() == "ccf-2012/seedcross" || clean_repo_url.contains("ccf-2012/seedcross")) {
            return detect_latest_git_head(&clean_repo_url, repo).await;
        }
        if tag_count > 0 {
            anyhow::bail!(
                "No stable release tags found for {} on channel {}",
                repo_url,
                effective_channel
            );
        }
        anyhow::bail!("no tags discovered");
    }

    let sanitized_repo_url = sanitize_git_remote_url_for_display(&clean_repo_url);
    let mut display_url = sanitized_repo_url.trim().trim_end_matches(".git").to_string();
    if display_url.is_empty() && !repo.trim().is_empty() {
        display_url = format!("https://github.com/{}", repo.trim());
    }

    Ok((
        best_allowed,
        af_release::lifecycle::sanitize_persisted_lifecycle_text(&format!("{}/releases", display_url)),
        Utc::now().to_rfc3339(),
    ))
}

pub async fn detect_latest_git_tag(
    repo_url: &str,
    repo: &str,
) -> anyhow::Result<(String, String, String)> {
    detect_latest_git_tag_for_channel(repo_url, repo, "stable").await
}

pub fn strip_trailing_version_punctuation(s: &str) -> &str {
    let mut trimmed = s.trim_end_matches(|c: char| {
        c == '.' || c == ',' || c == ';' || c == ':' || c == ')' || c == ']' || c == '}' || c == '"' || c == '\''
    });
    if trimmed.ends_with('+') {
        trimmed = trimmed[..trimmed.len() - 1].trim_end_matches(|c: char| {
            c == '.' || c == ',' || c == ';' || c == ':' || c == ')' || c == ']' || c == '}' || c == '"' || c == '\''
        });
    }
    if trimmed.ends_with('-') {
        let prefix = &trimmed[..trimmed.len() - 1];
        if !prefix.contains('-') && !prefix.contains('+') && !prefix.contains('~') {
            trimmed = prefix.trim_end_matches(|c: char| {
                c == '.' || c == ',' || c == ';' || c == ':' || c == ')' || c == ']' || c == '}' || c == '"' || c == '\''
            });
        }
    }
    trimmed
}

pub fn extract_version_from_text(raw: &str) -> String {
    extract_version(raw, "")
}

pub fn extract_version(raw: &str, custom_expr: &str) -> String {
    let text = raw.trim();
    if text.is_empty() {
        return String::new();
    }

    for line in text.lines() {
        let line_trim = line.trim();
        if let Some(map) = parse_component_manifest(line_trim) {
            return normalize_component_manifest(&map);
        }
    }

    let norm_text = af_release::lifecycle::normalize_version(text);

    if !custom_expr.trim().is_empty() {
        if let Ok(re) = Regex::new(custom_expr) {
            if let Some(caps) = re.captures(text) {
                if let Some(m) = caps.get(1) {
                    let s = strip_trailing_version_punctuation(m.as_str().trim());
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
                if let Some(m) = caps.get(0) {
                    let s = strip_trailing_version_punctuation(m.as_str().trim());
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
            }
            if let Some(caps) = re.captures(norm_text) {
                if let Some(m) = caps.get(1) {
                    let s = strip_trailing_version_punctuation(m.as_str().trim());
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
                if let Some(m) = caps.get(0) {
                    let s = strip_trailing_version_punctuation(m.as_str().trim());
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
            }
        }
    }

    if let Some(caps) = SYNTHETIC_COMMIT_VERSION_RE.captures(text) {
        if let Some(m) = caps.get(0) {
            let s = m.as_str().trim();
            let clean = s
                .strip_prefix('v')
                .or_else(|| s.strip_prefix('V'))
                .unwrap_or(s);
            return clean.to_string();
        }
    }
    if let Some(caps) = SYNTHETIC_COMMIT_VERSION_RE.captures(norm_text) {
        if let Some(m) = caps.get(0) {
            let s = m.as_str().trim();
            let clean = s
                .strip_prefix('v')
                .or_else(|| s.strip_prefix('V'))
                .unwrap_or(s);
            return clean.to_string();
        }
    }

    let clean_text = text
        .strip_prefix('v')
        .or_else(|| text.strip_prefix('V'))
        .unwrap_or(text);
    if is_git_commit_sha(clean_text) {
        return clean_text.to_string();
    }

    let clean_norm = norm_text
        .strip_prefix('v')
        .or_else(|| norm_text.strip_prefix('V'))
        .unwrap_or(norm_text);
    if is_git_commit_sha(clean_norm) {
        return clean_norm.to_string();
    }

    if let Some(caps) = DOTTED_VERSION_RE.captures(text) {
        if let Some(m) = caps.get(1) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    if let Some(caps) = DOTTED_VERSION_RE.captures(norm_text) {
        if let Some(m) = caps.get(1) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }

    for token in text.split_whitespace().chain(norm_text.split_whitespace()) {
        let trimmed_token = token.trim_matches(|c: char| {
            c == '(' || c == ')' || c == '[' || c == ']' || c == '"' || c == '\'' || c == ','
        });
        let clean = trimmed_token
            .strip_prefix('v')
            .or_else(|| trimmed_token.strip_prefix('V'))
            .unwrap_or(trimmed_token);
        if is_git_commit_sha(clean) {
            return clean.to_string();
        }
    }

    if let Some(caps) = DEFAULT_VERSION_RE.captures(text) {
        if let Some(m) = caps.get(1) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
        if let Some(m) = caps.get(0) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    if let Some(caps) = DEFAULT_VERSION_RE.captures(norm_text) {
        if let Some(m) = caps.get(1) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
        if let Some(m) = caps.get(0) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }

    String::new()
}

fn parse_git_head(output: &str) -> anyhow::Result<String> {
    let head = output.split_whitespace().next().unwrap_or_default();
    if !is_git_commit(head) {
        anyhow::bail!("invalid Git HEAD commit");
    }
    Ok(head.to_string())
}

fn is_git_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn dpkg_char_order(c: Option<u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(b) if b.is_ascii_alphabetic() => b as i32,
        Some(b) => (b as i32) + 256,
    }
}

pub fn dpkg_verrevcmp(a: &str, b: &str) -> std::cmp::Ordering {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut i = 0;
    let mut j = 0;

    while i < ab.len() || j < bb.len() {
        while (i < ab.len() && !ab[i].is_ascii_digit())
            || (j < bb.len() && !bb[j].is_ascii_digit())
        {
            let ac = if i < ab.len() && !ab[i].is_ascii_digit() {
                Some(ab[i])
            } else {
                None
            };
            let bc = if j < bb.len() && !bb[j].is_ascii_digit() {
                Some(bb[j])
            } else {
                None
            };
            let ord = dpkg_char_order(ac).cmp(&dpkg_char_order(bc));
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
            if ac.is_some() {
                i += 1;
            }
            if bc.is_some() {
                j += 1;
            }
        }

        while i < ab.len() && ab[i] == b'0' {
            i += 1;
        }
        while j < bb.len() && bb[j] == b'0' {
            j += 1;
        }

        let i_start = i;
        while i < ab.len() && ab[i].is_ascii_digit() {
            i += 1;
        }
        let j_start = j;
        while j < bb.len() && bb[j].is_ascii_digit() {
            j += 1;
        }

        let a_len = i - i_start;
        let b_len = j - j_start;
        if a_len != b_len {
            return a_len.cmp(&b_len);
        }

        let ord = ab[i_start..i].cmp(&bb[j_start..j]);
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }

    std::cmp::Ordering::Equal
}

fn parse_debian_version(raw: &str) -> (u64, &str, &str) {
    let mut s = raw.trim();
    if !s.starts_with(|c: char| c.is_ascii_digit()) {
        s = normalize_tag_or_version_prefix(s);
    }
    let (epoch, remainder) = if let Some((ep, rem)) = s.split_once(':') {
        if !ep.is_empty() && ep.bytes().all(|b| b.is_ascii_digit()) {
            (ep.parse::<u64>().unwrap_or(0), rem)
        } else {
            (0, s)
        }
    } else {
        (0, s)
    };
    let (upstream, debian_revision) = if let Some((up, rev)) = remainder.rsplit_once('-') {
        (up, rev)
    } else {
        (remainder, "")
    };
    (epoch, upstream, debian_revision)
}

pub fn compare_debian_versions_str(a: &str, b: &str) -> std::cmp::Ordering {
    let (a_epoch, a_up, a_rev) = parse_debian_version(a);
    let (b_epoch, b_up, b_rev) = parse_debian_version(b);

    if a_epoch != b_epoch {
        return a_epoch.cmp(&b_epoch);
    }

    let up_ord = dpkg_verrevcmp(a_up, b_up);
    if up_ord != std::cmp::Ordering::Equal {
        return up_ord;
    }

    dpkg_verrevcmp(a_rev, b_rev)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SemverVersion {
    epoch: u64,
    segments: Vec<u64>,
    prerelease: Option<Vec<PrereleaseIdentifier>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrereleaseIdentifier {
    Numeric(String),
    Alpha(String),
}

fn parse_semver(raw: &str) -> Option<SemverVersion> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    // In SemVer mode, strip build metadata (+...)
    let s_no_build = match s.split_once('+') {
        Some((v, _)) => v.trim(),
        None => s,
    };
    let norm = af_release::lifecycle::normalize_version(s_no_build);
    if norm.is_empty() {
        return None;
    }

    let (epoch, rest) = if let Some((ep, rem)) = norm.split_once(':') {
        if !ep.is_empty() && ep.bytes().all(|b| b.is_ascii_digit()) {
            (ep.parse::<u64>().ok()?, rem)
        } else {
            (0, norm)
        }
    } else {
        (0, norm)
    };

    if rest.is_empty() || !rest.bytes().any(|b| b.is_ascii_digit()) {
        return None;
    }

    let (normal_str, prerelease_opt) = match rest.find(|c: char| c == '-' || c == '~') {
        Some(idx) => (&rest[..idx], Some(&rest[idx + 1..])),
        None => (rest, None),
    };

    let mut segments = Vec::new();
    for seg in normal_str.split('.') {
        let seg_trim = seg.trim();
        if seg_trim.is_empty() || !seg_trim.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        segments.push(seg_trim.parse::<u64>().ok()?);
    }
    if segments.is_empty() {
        return None;
    }

    let prerelease = match prerelease_opt {
        Some(pre) if !pre.trim().is_empty() => {
            let mut ids = Vec::new();
            for part in pre.trim().split('.') {
                let part_trim = part.trim();
                if part_trim.is_empty() {
                    continue;
                }
                if part_trim.bytes().all(|b| b.is_ascii_digit()) {
                    let canonical = part_trim.trim_start_matches('0');
                    let canonical = if canonical.is_empty() { "0" } else { canonical };
                    ids.push(PrereleaseIdentifier::Numeric(canonical.to_string()));
                } else {
                    ids.push(PrereleaseIdentifier::Alpha(part_trim.to_string()));
                }
            }
            if ids.is_empty() {
                None
            } else {
                Some(ids)
            }
        }
        _ => None,
    };

    Some(SemverVersion {
        epoch,
        segments,
        prerelease,
    })
}

fn compare_semver_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let (Some(sa), Some(sb)) = (parse_semver(a), parse_semver(b)) else {
        let a_norm = af_release::lifecycle::normalize_version(a);
        let b_norm = af_release::lifecycle::normalize_version(b);
        return dpkg_verrevcmp(a_norm, b_norm);
    };

    if sa.epoch != sb.epoch {
        return sa.epoch.cmp(&sb.epoch);
    }

    let max_len = sa.segments.len().max(sb.segments.len());
    for i in 0..max_len {
        let seg_a = sa.segments.get(i).copied().unwrap_or(0);
        let seg_b = sb.segments.get(i).copied().unwrap_or(0);
        let ord = seg_a.cmp(&seg_b);
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }

    match (&sa.prerelease, &sb.prerelease) {
        (None, None) => std::cmp::Ordering::Equal,
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(ids_a), Some(ids_b)) => {
            for (id_a, id_b) in ids_a.iter().zip(ids_b.iter()) {
                let ord = match (id_a, id_b) {
                    (PrereleaseIdentifier::Numeric(na), PrereleaseIdentifier::Numeric(nb)) => {
                        na.len().cmp(&nb.len()).then_with(|| na.cmp(nb))
                    }
                    (PrereleaseIdentifier::Numeric(_), PrereleaseIdentifier::Alpha(_)) => std::cmp::Ordering::Less,
                    (PrereleaseIdentifier::Alpha(_), PrereleaseIdentifier::Numeric(_)) => std::cmp::Ordering::Greater,
                    (PrereleaseIdentifier::Alpha(sa), PrereleaseIdentifier::Alpha(sb)) => sa.cmp(sb),
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
            ids_a.len().cmp(&ids_b.len())
        }
    }
}

pub fn is_newer_version(local: &str, remote: &str) -> bool {
    is_remote_version_newer(local, remote)
}

pub fn versions_match_target_internal(expected: &str, achieved: &str) -> bool {
    af_release::lifecycle::versions_match_target(achieved, expected)
}

/// Compares two version strings using Debian Policy (§5.6.12 `dpkg --compare-versions`),
/// SemVer prerelease ordering, git commit SHAs, synthetic commit versions, and component manifests.
pub fn is_remote_version_newer(local: &str, remote: &str) -> bool {
    is_remote_version_newer_for_source(local, remote, "")
}

pub fn is_remote_version_newer_for_source(local: &str, remote: &str, update_source: &str) -> bool {
    let l_trim = local.trim();
    let r_trim = remote.trim();

    // 1. Multi-component manifests (frontend:...,backend:...,proxy:...)
    let l_manifest = parse_component_manifest(l_trim);
    let r_manifest = parse_component_manifest(r_trim);

    if l_manifest.is_some() || r_manifest.is_some() {
        if let (Some(installed_map), Some(latest_map)) = (l_manifest.as_ref(), r_manifest.as_ref()) {
            if latest_map.len() != installed_map.len() {
                return true;
            }
            for (comp, latest_val) in latest_map {
                let Some(inst_val) = installed_map.get(comp) else {
                    return true;
                };
                let is_hex_pair = (af_release::lifecycle::is_hex_digits_7_to_40(latest_val) || af_release::lifecycle::is_hex_digits_7_to_40(af_release::lifecycle::normalize_version(latest_val)))
                    && (af_release::lifecycle::is_hex_digits_7_to_40(inst_val) || af_release::lifecycle::is_hex_digits_7_to_40(af_release::lifecycle::normalize_version(inst_val)));
                if is_hex_pair {
                    if !af_release::lifecycle::commits_match_prefix(latest_val, inst_val, true) {
                        return true;
                    }
                } else {
                    if af_release::lifecycle::commits_match_prefix(latest_val, inst_val, false) {
                        continue;
                    }
                    if af_release::lifecycle::single_version_matches(inst_val, latest_val) {
                        continue;
                    }
                    if is_newer_version_scalar_for_source(inst_val, latest_val, update_source) {
                        return true;
                    }
                }
            }
            return false;
        } else if let Some(l_map) = l_manifest.as_ref() {
            let r_clean = af_release::lifecycle::normalize_version(r_trim);
            if is_git_commit_sha(r_clean) {
                if let Some(l_frontend) = l_map.get("frontend") {
                    return !af_release::lifecycle::commits_match_prefix(l_frontend, r_clean, true);
                }
            }
            return true;
        } else if let Some(r_map) = r_manifest.as_ref() {
            let l_clean = af_release::lifecycle::normalize_version(l_trim);
            if is_git_commit_sha(l_clean) {
                if let Some(r_frontend) = r_map.get("frontend") {
                    return !af_release::lifecycle::commits_match_prefix(l_clean, r_frontend, true);
                }
            }
            return true;
        }
    }

    is_newer_version_scalar_for_source(l_trim, r_trim, update_source)
}

pub fn is_version_newer_for_source(local: &str, remote: &str, update_source: &str) -> bool {
    is_remote_version_newer_for_source(local, remote, update_source)
}

pub fn is_newer_version_scalar(local: &str, remote: &str) -> bool {
    is_newer_version_scalar_for_source(local, remote, "")
}

pub fn is_newer_version_scalar_for_source(local: &str, remote: &str, update_source: &str) -> bool {
    let l_trim = local.trim();
    let r_trim = remote.trim();

    if update_source == "apt" {
        return compare_debian_versions_str(l_trim, r_trim) == std::cmp::Ordering::Less;
    }

    let l_norm = af_release::lifecycle::normalize_version(local);
    let r_norm = af_release::lifecycle::normalize_version(remote);

    if l_norm == r_norm
        || (is_git_commit_sha(l_norm) && is_git_commit_sha(r_norm) && l_norm.eq_ignore_ascii_case(r_norm))
    {
        return false;
    }

    let is_commit_source = matches!(
        update_source.trim().to_ascii_lowercase().as_str(),
        "git" | "git_commit" | "git_head"
    );

    // 2. Synthetic commit versions (0.1.0-<sha>)
    let l_synth = parse_synthetic_commit_version(l_trim);
    let r_synth = parse_synthetic_commit_version(r_trim);

    if let Some((l_base, l_sha)) = l_synth {
        if let Some((r_base, r_sha)) = r_synth {
            if is_commit_source {
                match compare_semver_versions(l_base, r_base) {
                    std::cmp::Ordering::Less => return true,
                    std::cmp::Ordering::Greater => return false,
                    std::cmp::Ordering::Equal => {
                        return !af_release::lifecycle::commits_match_prefix(l_sha, r_sha, true);
                    }
                }
            }
        } else {
            let r_clean = af_release::lifecycle::normalize_version(r_trim);
            if !r_clean.contains('.') && is_git_commit_sha(r_clean) {
                return !af_release::lifecycle::commits_match_prefix(l_sha, r_clean, true);
            }
        }
    } else if let Some((_r_base, r_sha)) = r_synth {
        let l_clean = af_release::lifecycle::normalize_version(l_trim);
        if !l_clean.contains('.') && is_git_commit_sha(l_clean) {
            return !af_release::lifecycle::commits_match_prefix(l_clean, r_sha, true);
        }
    }

    // 3. Short & full git commit SHAs
    let l_clean = af_release::lifecycle::normalize_version(l_trim);
    let r_clean = af_release::lifecycle::normalize_version(r_trim);
    let l_is_hex_sha = af_release::lifecycle::is_hex_digits_7_to_40(l_clean) && !l_clean.contains('.');
    let r_is_hex_sha = af_release::lifecycle::is_hex_digits_7_to_40(r_clean) && !r_clean.contains('.');
    let l_is_sha = is_git_commit_sha(l_clean) && !l_clean.bytes().all(|b| b.is_ascii_digit());
    let r_is_sha = is_git_commit_sha(r_clean) && !r_clean.bytes().all(|b| b.is_ascii_digit());

    let both_all_digits = l_clean.bytes().all(|b| b.is_ascii_digit()) && r_clean.bytes().all(|b| b.is_ascii_digit());
    let unequal_digit_tags = both_all_digits && l_clean.len() != r_clean.len() && l_clean.len() != 40 && r_clean.len() != 40;

    if l_is_hex_sha && r_is_hex_sha && !unequal_digit_tags && (is_commit_source || l_is_sha || r_is_sha) {
        return !af_release::lifecycle::commits_match_prefix(l_clean, r_clean, true);
    }

    // Untagged branch SHA installed on a release-tag-tracked package
    if l_is_sha && !r_is_sha {
        if parse_semver(r_trim).is_some() {
            return true;
        }
    }

    compare_semver_versions(l_trim, r_trim) == std::cmp::Ordering::Less
}

pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    compare_versions_for_source(a, b, "")
}

pub fn compare_versions_for_source(a: &str, b: &str, update_source: &str) -> std::cmp::Ordering {
    if update_source == "apt" {
        return compare_debian_versions_str(a, b);
    }

    let a_norm = af_release::lifecycle::normalize_version(a);
    let b_norm = af_release::lifecycle::normalize_version(b);
    if a_norm == b_norm
        || (is_git_commit_sha(a_norm) && is_git_commit_sha(b_norm) && a_norm.eq_ignore_ascii_case(b_norm))
    {
        return std::cmp::Ordering::Equal;
    }

    if af_release::lifecycle::commits_match_prefix(a_norm, b_norm, false) {
        return std::cmp::Ordering::Equal;
    }
    if is_git_commit_sha(a_norm) && is_git_commit_sha(b_norm) {
        if !(a_norm.bytes().all(|b| b.is_ascii_digit()) && b_norm.bytes().all(|b| b.is_ascii_digit())) {
            return a_norm.to_ascii_lowercase().cmp(&b_norm.to_ascii_lowercase());
        }
    }

    compare_semver_versions(a, b)
}

pub fn persist_package_update_record(record: &PackageUpdateRecord) {
    ensure_app_updates_columns();
    let mut safe_record = record.clone();
    safe_record.release_url = af_release::lifecycle::sanitize_persisted_lifecycle_text(
        &sanitize_git_remote_url_for_display(&safe_record.release_url),
    );
    safe_record.error = af_release::lifecycle::sanitize_persisted_lifecycle_text(
        &public_update_error(&safe_record.error),
    );
    safe_record.source_key = sanitize_source_key_for_persistence(&safe_record.source_key);
    safe_record.latest_version = af_release::lifecycle::sanitize_persisted_lifecycle_text(&safe_record.latest_version);
    safe_record.installed_version = af_release::lifecycle::sanitize_persisted_lifecycle_text(&safe_record.installed_version);
    let record = &safe_record;

    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "INSERT INTO app_updates (package_name, installed_version, latest_version, update_available, update_url, checked_at, last_error, source_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(package_name) DO UPDATE SET
               installed_version = excluded.installed_version,
               latest_version = excluded.latest_version,
               update_available = excluded.update_available,
               update_url = excluded.update_url,
               checked_at = excluded.checked_at,
               last_error = excluded.last_error,
               source_key = excluded.source_key",
            params![
                record.package_id,
                record.installed_version,
                record.latest_version,
                record.update_available,
                record.release_url,
                record.checked_at,
                record.error,
                record.source_key,
            ],
        );
    }
}

fn persist_and_cache_package_update(record: &PackageUpdateRecord) -> bool {
    let mut prev_update_available = false;
    let mut had_existing = false;

    if let Ok(mut cache) = PACKAGE_UPDATE_CACHE.lock() {
        if let Some(prev) = cache.get(&record.package_id) {
            had_existing = true;
            prev_update_available = prev.update_available;
        }
        cache.insert(record.package_id.clone(), record.clone());
    }

    if !had_existing {
        if let Ok(conn) = af_db::get_conn() {
            if let Ok(existing_avail) = conn.query_row(
                "SELECT COALESCE(update_available, 0) FROM app_updates WHERE package_name = ?1",
                params![record.package_id],
                |r| r.get::<_, bool>(0),
            ) {
                prev_update_available = existing_avail;
            }
        }
    }

    persist_package_update_record(record);

    !prev_update_available && record.update_available
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. MediaFlow Worker Poller (`backend/services/mediaflow.go`)
// ─────────────────────────────────────────────────────────────────────────────

static MEDIAFLOW_POLLER_ACTIVE: AtomicBool = AtomicBool::new(false);
static MEDIAFLOW_PROCESSING: AtomicBool = AtomicBool::new(false);

/// Spawns the background MediaFlow worker poller (10-second interval) that picks up
/// `APPROVED` items in `mediaflow_queue`, transitions them to `PROCESSING`, invokes
/// `ffmpeg` with hardware transcode flags from [`af_hardware::get_gpu_transcode_flags()`],
/// and updates the row to `COMPLETED` or `FAILED`.
pub fn start_mediaflow_poller() {
    if MEDIAFLOW_POLLER_ACTIVE.swap(true, Ordering::SeqCst) {
        return;
    }

    tokio::spawn(async move {
        tracing::info!(
            interval_secs = 10,
            "mediaflow autonomous transcode poller initialized"
        );

        let mut ticker = tokio::time::interval(Duration::from_secs(10));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            let _ = process_next_mediaflow_job().await;
        }
    });
}

/// Processes a single `APPROVED` job from `mediaflow_queue` if one exists and no job
/// is currently running. Returns `true` if a job was picked up and processed.
pub async fn process_next_mediaflow_job() -> bool {
    if MEDIAFLOW_PROCESSING.swap(true, Ordering::SeqCst) {
        return false;
    }

    struct ProcessingGuard;
    impl Drop for ProcessingGuard {
        fn drop(&mut self) {
            MEDIAFLOW_PROCESSING.store(false, Ordering::SeqCst);
        }
    }
    let _guard = ProcessingGuard;

    let job_opt: Option<(i64, String)> = {
        let Ok(conn) = af_db::get_conn() else {
            return false;
        };
        let Ok(row) = conn.query_row(
            "SELECT id, file_path FROM mediaflow_queue WHERE status = 'APPROVED' ORDER BY created_at ASC, id ASC LIMIT 1",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
        ) else {
            return false;
        };
        let _ = conn.execute(
            "UPDATE mediaflow_queue SET status = 'PROCESSING', updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
            params![row.0],
        );
        Some(row)
    };

    let Some((job_id, file_path)) = job_opt else {
        return false;
    };

    let src_path = Path::new(&file_path);
    if !src_path.exists() {
        record_mediaflow_failure(job_id, "Source file does not exist");
        return true;
    }

    let flags = af_hardware::get_gpu_transcode_flags();
    let parent_dir = src_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = src_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let out_path = parent_dir.join(format!("{}_hevc.mkv", stem));

    let mut args: Vec<String> = vec!["-y".to_string()];
    if !flags.hw_accel.is_empty() && flags.hw_accel != "none" {
        args.push("-hwaccel".to_string());
        args.push(flags.hw_accel.clone());
        if !flags.hw_accel_device.is_empty() {
            args.push("-hwaccel_device".to_string());
            args.push(flags.hw_accel_device.clone());
        }
        if !flags.output_format.is_empty() {
            args.push("-hwaccel_output_format".to_string());
            args.push(flags.output_format.clone());
        }
    }

    let video_codec = if flags.video_codec.trim().is_empty() {
        "libx265"
    } else {
        flags.video_codec.trim()
    };

    args.extend([
        "-i".to_string(),
        file_path.clone(),
        "-c:v".to_string(),
        video_codec.to_string(),
        "-b:v".to_string(),
        "5M".to_string(),
        "-c:a".to_string(),
        "copy".to_string(),
        out_path.to_string_lossy().to_string(),
    ]);

    tracing::info!(
        job_id = job_id,
        file_path = %file_path,
        codec = %video_codec,
        "mediaflow: starting transcode job"
    );

    match Command::new("ffmpeg").args(&args).output().await {
        Ok(output) if output.status.success() => {
            let new_size = fs::metadata(&out_path)
                .map(|m| m.len() as i64)
                .unwrap_or(0);

            let trash_dir = parent_dir.join(".mediaflow_trash");
            let _ = fs::create_dir_all(&trash_dir);
            if let Some(fname) = src_path.file_name() {
                let _ = fs::rename(src_path, trash_dir.join(fname));
            }

            let out_str = out_path.to_string_lossy().to_string();
            if let Ok(conn) = af_db::get_conn() {
                let _ = conn.execute(
                    "UPDATE mediaflow_queue SET status = 'COMPLETED', file_path = ?1, new_codec = 'hevc', new_size = ?2, updated_at = CURRENT_TIMESTAMP WHERE id = ?3",
                    params![out_str, new_size, job_id],
                );
            }
            tracing::info!(
                job_id = job_id,
                output = %out_str,
                new_size = new_size,
                "mediaflow: transcode completed"
            );
        }
        Ok(output) => {
            let _ = fs::remove_file(&out_path);
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let err_log = tail_error_log(&combined, 1000);
            record_mediaflow_failure(
                job_id,
                &format!("FFmpeg error ({}): {}", output.status, err_log),
            );
        }
        Err(err) => {
            let _ = fs::remove_file(&out_path);
            record_mediaflow_failure(job_id, &format!("FFmpeg execution error: {}", err));
        }
    }

    true
}

fn tail_error_log(text: &str, max_len: usize) -> String {
    let trimmed = text.trim();
    if trimmed.len() <= max_len {
        return trimmed.to_string();
    }
    let mut start = trimmed.len() - max_len;
    while start < trimmed.len() && !trimmed.is_char_boundary(start) {
        start += 1;
    }
    trimmed[start..].to_string()
}

fn record_mediaflow_failure(job_id: i64, reason: &str) {
    tracing::error!(job_id = job_id, error = %reason, "mediaflow: transcode job failed");
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "UPDATE mediaflow_queue SET status = 'FAILED', error_log = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2",
            params![reason, job_id],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_ENV_MUTEX: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

    #[cfg(unix)]
    #[test]
    fn heal_state_survives_unknown_and_active_lifecycle_until_recovery() {
        use crate::inventory_regressions::{isolated, Fixture};
        use std::os::unix::fs::PermissionsExt;
        let name =
            "workers::tests::heal_state_survives_unknown_and_active_lifecycle_until_recovery";
        if !isolated(name) {
            return;
        }
        let fixture = Fixture::new();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let exhausted = ServiceHealState {
            failure_count: MAX_HEAL_RETRIES,
            exhausted: true,
            next_retry_at: Some(Instant::now() + Duration::from_secs(300)),
        };
        let backed_off = ServiceHealState {
            failure_count: 2,
            exhausted: false,
            next_retry_at: Some(Instant::now() + Duration::from_secs(300)),
        };
        let seeded = HashMap::from([
            ("fixture-main".to_string(), exhausted.clone()),
            ("nginx".to_string(), exhausted.clone()),
            ("smbd".to_string(), backed_off),
            ("retired-unit".to_string(), exhausted.clone()),
        ]);
        *HEAL_STATES.lock().unwrap() = seeded.clone();
        let hidden = fixture.journal.with_extension("unavailable");
        std::fs::rename(&fixture.journal, &hidden).unwrap();
        runtime.block_on(perform_heal_check());
        assert_eq!(*HEAL_STATES.lock().unwrap(), seeded);
        assert!(!fixture.calls.exists());
        std::fs::rename(&hidden, &fixture.journal).unwrap();
        let job = crate::PackageJobInfo {
            job_id: "seeded-heal-job".into(),
            package_id: "fixture".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 0,
            last_line: String::new(),
            started_at: Utc::now().to_rfc3339(),
            expected_target_version: None,
        };
        assert!(crate::try_start_package_job(job));
        runtime.block_on(perform_heal_check());
        assert_eq!(*HEAL_STATES.lock().unwrap(), seeded);
        assert!(!fixture.calls.exists());
        crate::finish_package_job("fixture", "update", true, "", "seeded-heal-job").unwrap();
        std::fs::write(&fixture.catalog, "corrupt").unwrap();
        runtime.block_on(perform_heal_check());
        assert_eq!(*HEAL_STATES.lock().unwrap(), seeded);
        fixture.write_packages(&[Fixture::package("fixture", "systemd", "fixture-main")]);
        let install = fixture.root.join("install");
        std::fs::set_permissions(&install, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(
            std::fs::symlink_metadata(install.join(".fixture.lock"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied,
        );
        runtime.block_on(perform_heal_check());
        std::fs::set_permissions(&install, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(*HEAL_STATES.lock().unwrap(), seeded);
        assert!(!fixture.calls.exists());
        fixture.command("systemctl", "printf '%s\\n' \"$*\" >> \"$AF_STATUS_CALLS\"\ncase \"$1 $2\" in 'is-active fixture-main') echo inactive; exit 3;; is-active*) echo active;; show*) printf 'LoadState=loaded\\nType=simple\\n';; *) exit 92;; esac\n");
        runtime.block_on(perform_heal_check());
        {
            let states = HEAL_STATES.lock().unwrap();
            assert_eq!(states["fixture-main"], exhausted);
            assert_eq!(states["nginx"], ServiceHealState::default());
            assert_eq!(states["smbd"], ServiceHealState::default());
            assert!(!states.contains_key("retired-unit"));
        }
        fixture.command("systemctl", "printf '%s\\n' \"$*\" >> \"$AF_STATUS_CALLS\"\ntest \"$1\" = is-active || exit 92\necho active\n");
        runtime.block_on(perform_heal_check());
        assert_eq!(
            HEAL_STATES.lock().unwrap()["fixture-main"],
            ServiceHealState::default()
        );
        let suspended = HashMap::from([
            (
                "nginx".to_string(),
                ServiceHealState {
                    failure_count: 1,
                    next_retry_at: None,
                    exhausted: false,
                },
            ),
            ("fixture-main".to_string(), exhausted),
        ]);
        *HEAL_STATES.lock().unwrap() = suspended.clone();
        fixture.command("systemctl", "printf '%s\\n' \"$*\" >> \"$AF_STATUS_CALLS\"\ncase \"$1\" in is-active) echo inactive; exit 3;; show) printf 'LoadState=loaded\\nType=simple\\n';; *) exit 92;; esac\n");
        let local_guard = crate::PACKAGE_LIFECYCLE_MUTEX.try_lock().unwrap();
        runtime.block_on(perform_heal_check());
        assert_eq!(*HEAL_STATES.lock().unwrap(), suspended);
        drop(local_guard);
        let calls = std::fs::read_to_string(&fixture.calls).unwrap();
        assert!(calls
            .lines()
            .all(|call| call.starts_with("is-active ") || call.starts_with("show ")));
        println!("seeded exhausted budgets, notification flag and retry deadlines survive journal/catalog uncertainty and active jobs; only recovered/deleted units reset");
    }

    #[cfg(unix)]
    #[test]
    fn healing_status_timeouts_kill_and_reap_both_probe_children() {
        use crate::inventory_regressions::{isolated, Fixture};
        let name = "workers::tests::healing_status_timeouts_kill_and_reap_both_probe_children";
        if !isolated(name) {
            return;
        }
        let fixture = Fixture::new();
        let fifo = fixture.root.join("blocked-health");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        std::env::set_var("AF_BLOCK_FIFO", fifo);
        std::env::set_var("AF_STATUS_PID", fixture.root.join("health.pid"));
        let runtime = tokio::runtime::Runtime::new().unwrap();
        fixture.command(
            "systemctl",
            "printf '%s' \"$$\" > \"$AF_STATUS_PID\"\nexec /bin/cat \"$AF_BLOCK_FIFO\"\n",
        );
        let start = Instant::now();
        assert_eq!(
            runtime.block_on(check_systemd_unit_healthy("fixture-main")),
            None
        );
        assert!(start.elapsed() >= Duration::from_secs(10));
        assert!(start.elapsed() < Duration::from_secs(12));
        let pid = std::fs::read_to_string(fixture.root.join("health.pid")).unwrap();
        assert!(!Path::new("/proc").join(pid).exists());
        fixture.command("systemctl", "case \"$1\" in is-active) echo inactive; exit 3;; show) printf '%s' \"$$\" > \"$AF_STATUS_PID\"; exec /bin/cat \"$AF_BLOCK_FIFO\";; *) exit 92;; esac\n");
        let start = Instant::now();
        assert_eq!(
            runtime.block_on(check_systemd_unit_healthy("fixture-main")),
            None
        );
        assert!(start.elapsed() >= Duration::from_secs(5));
        assert!(start.elapsed() < Duration::from_secs(7));
        let pid = std::fs::read_to_string(fixture.root.join("health.pid")).unwrap();
        assert!(!Path::new("/proc").join(pid).exists());
        println!("actual is-active (10s) and metadata show (5s) timeouts both return unknown and reap FIFO-blocked children");
    }

    #[cfg(unix)]
    #[test]
    fn heal_poll_is_read_only_and_unknown_snapshots_skip_controls() {
        let name = "workers::tests::heal_poll_is_read_only_and_unknown_snapshots_skip_controls";
        if std::env::var("AF_HEAL_POLL_TEST_CHILD").as_deref() != Ok(name) {
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env("AF_HEAL_POLL_TEST_CHILD", name)
                .status()
                .unwrap()
                .success());
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("af-heal-poll-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        std::env::set_var("AETHERFLOW_FS_ROOT", &root);
        std::env::set_var("AETHERFLOW_RELEASE_ROOT", &root);
        let catalog = root.join("packages.json");
        std::fs::write(
            &catalog,
            &serde_json::to_string(&[af_models::Package {
                name: "fixture".into(),
                service_name: "fixture".into(),
                service_type: "systemd".into(),
                lock_file: "/install/.fixture.lock".into(),
                ..Default::default()
            }])
            .unwrap(),
        )
        .unwrap();
        std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", catalog);
        let cfg = af_release::ReleaseConfig::for_root(&root);
        let path = af_release::config::try_resolve_db_path(&cfg, None)
            .unwrap()
            .path;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::initialize_package_jobs(rusqlite::Connection::open(&path).unwrap()).unwrap();
        let controls = root.join("bin");
        std::fs::create_dir(&controls).unwrap();
        let calls = root.join("calls");
        let ctl = controls.join("systemctl");
        std::fs::write(&ctl, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$AF_HEAL_CALLS\"\ncase \"$1\" in is-active) echo active;; *) exit 92;; esac\n").unwrap();
        std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("AF_HEAL_CALLS", &calls);
        std::env::set_var(
            "PATH",
            format!("{}:{}", controls.display(), std::env::var("PATH").unwrap()),
        );
        let runtime = tokio::runtime::Runtime::new().unwrap();
        // Healthy observations still run while genuine mutations own both locks.
        let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        let local = crate::PACKAGE_LIFECYCLE_MUTEX.try_lock().unwrap();
        runtime.block_on(perform_heal_check());
        let observed = std::fs::read_to_string(&calls).unwrap_or_default();
        assert_eq!(
            observed.lines().count(),
            3,
            "healthy polling must not take mutation locks: {observed}"
        );
        assert!(observed.lines().all(|line| line.starts_with("is-active ")));
        drop(local);
        drop(admission);
        std::fs::remove_file(&calls).unwrap();
        let info = crate::PackageJobInfo {
            job_id: "heal-poll-active".into(),
            package_id: "fixture".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 10,
            last_line: String::new(),
            started_at: chrono::Utc::now().to_rfc3339(),
            expected_target_version: None,
        };
        assert!(crate::try_start_package_job(info));
        runtime.block_on(perform_heal_check());
        assert!(!calls.exists(), "a real active job excludes heal checks");
        crate::finish_package_job("fixture", "update", true, "", "heal-poll-active").unwrap();
        // A missing journal is unknown, not an empty service inventory.
        let hidden = path.with_extension("temporarily-unavailable");
        std::fs::rename(&path, &hidden).unwrap();
        assert!(crate::get_active_services().is_err());
        runtime.block_on(perform_heal_check());
        assert!(
            !calls.exists(),
            "unknown state must not attempt service controls"
        );
        std::fs::rename(&hidden, &path).unwrap();
        runtime.block_on(perform_heal_check());
        assert_eq!(std::fs::read_to_string(&calls).unwrap().lines().count(), 3);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_health_recovery_excludes_scheduled_oneshot_jobs() {
        assert!(!unit_metadata_allows_recovery(
            "loadstate=loaded\ntype=oneshot\n"
        ));
        assert!(!unit_metadata_allows_recovery(
            "loadstate=not-found\ntype=simple\n"
        ));
        assert!(!unit_metadata_allows_recovery(""));
        assert!(unit_metadata_allows_recovery(
            "type=simple\nloadstate=loaded\n"
        ));
        assert!(unit_metadata_allows_recovery("loadstate=loaded\n")); // timers
    }

    #[test]
    fn test_metrics_columns_use_the_supplied_connection() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE metrics_history (timestamp TEXT);")
            .unwrap();
        ensure_metrics_history_columns_with_connection(&conn);
        ensure_metrics_history_columns_with_connection(&conn);
        conn.execute(
            "INSERT INTO metrics_history (timestamp, cpu_usage, memory_pct, swap_pct, disk_read_mb, disk_write_mb, net_rx_mb, net_tx_mb) VALUES ('audit', 1, 2, 3, 4, 5, 6, 7)",
            [],
        )
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    struct ProbeCleanup(std::path::PathBuf);

    #[cfg(target_os = "linux")]
    impl ProbeCleanup {
        fn processes(&self) -> Vec<u32> {
            std::fs::read_dir(&self.0)
                .unwrap()
                .flatten()
                .filter(|entry| {
                    entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "pids")
                })
                .flat_map(|entry| {
                    std::fs::read_to_string(entry.path())
                        .unwrap()
                        .split_whitespace()
                        .map(|pid| pid.parse::<u32>().unwrap())
                        .collect::<Vec<_>>()
                })
                .collect()
        }
        fn live(&self) -> Vec<u32> {
            self.processes()
                .into_iter()
                .filter(|pid| {
                    std::fs::read_to_string(format!("/proc/{pid}/stat"))
                        .ok()
                        .and_then(|stat| {
                            stat.rsplit_once(") ")
                                .map(|(_, fields)| !fields.starts_with('Z') && !fields.starts_with('X'))
                        })
                        .unwrap_or(false)
                })
                .collect()
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for ProbeCleanup {
        fn drop(&mut self) {
            for pid in self.live() {
                // Only PIDs published by this disposable fixture are eligible.
                let _ = std::process::Command::new("/bin/kill")
                    .args(["-KILL", "--", &pid.to_string()])
                    .status();
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn slow_update_helpers(fixture: &crate::inventory_regressions::Fixture) -> ProbeCleanup {
        for name in ["dpkg-query", "apt-cache", "git", "fixture-version"] {
            fixture.command(name, r#"exec /usr/bin/python3 -c 'import os,pathlib,signal,subprocess,sys
root=pathlib.Path(os.environ["AF_UPDATE_PROBE_ROOT"])
child=subprocess.Popen([sys.executable,"-c","import signal; signal.pause()"])
(root/(str(os.getpid())+".pids")).write_text(str(os.getpid())+" "+str(child.pid))
if os.environ.get("AF_UPDATE_PROBE_OVERFLOW"): sys.stdout.write("x"*(2*1024*1024)); sys.stdout.flush()
signal.pause()'
    "#);
        }
        std::env::set_var("AF_UPDATE_PROBE_ROOT", &fixture.root);
        ProbeCleanup(fixture.root.clone())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn version_probe_timeouts_reap_apt_binary_and_git_process_trees() {
        use crate::inventory_regressions::{isolated, Fixture};
        let name = "workers::tests::version_probe_timeouts_reap_apt_binary_and_git_process_trees";
        if !isolated(name) {
            return;
        }
        let fixture = Fixture::new();
        let cleanup = slow_update_helpers(&fixture);
        let mut package = Fixture::package("fixture", "systemd", "fixture");
        package["update_source"] = serde_json::json!("apt");
        package["update_package"] = serde_json::json!("fixture");
        let apt: Package = serde_json::from_value(package.clone()).unwrap();
        package["update_source"] = serde_json::json!("binary");
        package["version_command"] = serde_json::json!(["fixture-version"]);
        let binary: Package = serde_json::from_value(package.clone()).unwrap();
        package["update_source"] = serde_json::json!("git");
        package["update_repo_url"] = serde_json::json!("https://fixture.invalid/repo.git");
        let git: Package = serde_json::from_value(package).unwrap();
        let client = reqwest::Client::new();
        let started = Instant::now();
        let (installed_apt, installed_binary, latest_apt, latest_head, latest_tag) = tokio::join!(
            detect_installed_version(&apt),
            detect_installed_version(&binary),
            detect_latest_apt_version("fixture"),
            detect_latest_version(&client, "https://fixture.invalid", &git),
            detect_latest_git_tag("https://fixture.invalid/repo.git", "fixture/repo"),
        );
        assert!(
            installed_apt.is_err()
                && installed_binary.is_err()
                && latest_apt.is_err()
                && latest_head.is_err()
                && latest_tag.is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(23));
        assert_eq!(
            cleanup.processes().len(),
            10,
            "all five real detector paths must execute"
        );
        assert!(
            cleanup.live().is_empty(),
            "timed-out helpers survived: {:?}",
            cleanup.live()
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn version_probe_cancellation_and_overflow_retain_cleanup_ownership() {
        use crate::inventory_regressions::{isolated, Fixture};
        let name = "workers::tests::version_probe_cancellation_and_overflow_retain_cleanup_ownership";
        if !isolated(name) {
            return;
        }
        let fixture = Fixture::new();
        let cleanup = slow_update_helpers(&fixture);
        let task = tokio::spawn(update_probe_output(
            Command::new("fixture-version"),
            Duration::from_secs(30),
        ));
        let ready = Instant::now() + Duration::from_secs(3);
        while cleanup.processes().is_empty() && Instant::now() < ready {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(cleanup.processes().len(), 2);
        task.abort();
        let _ = task.await;
        let cleaned = Instant::now() + Duration::from_secs(2);
        while !cleanup.live().is_empty() && Instant::now() < cleaned {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(cleanup.live().is_empty(), "cancelled helper survived");
        std::env::set_var("AF_UPDATE_PROBE_OVERFLOW", "1");
        let result = update_probe_output(Command::new("fixture-version"), Duration::from_secs(5)).await;
        assert!(result.is_err());
        assert!(cleanup.live().is_empty(), "oversized helper survived");
    }

    #[test]
    fn test_version_extraction_and_comparison() {
        assert_eq!(extract_version("jellyfin 10.9.11", ""), "10.9.11");
        assert_eq!(extract_version("v2.4.0-rc1", ""), "2.4.0-rc1");
        assert_eq!(extract_version("1:1.0.0-1", ""), "1:1.0.0-1");
        assert_eq!(extract_version("1.0.0~rc1", ""), "1.0.0~rc1");
        assert!(is_remote_version_newer("10.9.10", "10.9.11"));
        assert!(!is_remote_version_newer("10.9.11", "10.9.11"));
        assert!(!is_remote_version_newer("10.10.0", "10.9.11"));
        assert!(is_remote_version_newer("1.0.0~rc1", "1.0.0"));
        assert!(is_remote_version_newer("2.4.0-rc1", "2.4.0"));
        assert!(is_remote_version_newer("1.0.0-1", "1.1.0"));
        assert!(is_remote_version_newer("1.0.0-1", "1.0.0-2"));
        assert!(!is_remote_version_newer("1:1.0.0-1", "2.0.0"));
        assert!(!is_remote_version_newer("1.0.0", "1.0.0~rc1"));
        assert!(!is_remote_version_newer("2.4.0", "2.4.0-rc1"));
    }

    #[test]
    fn test_git_head_tracking() {
        let local = "a".repeat(40);
        let remote = "b".repeat(40);
        assert_eq!(parse_git_head(&format!("{}\tHEAD\n", remote)).unwrap(), remote);
        for invalid in ["", "v1.2.3", "abc123 HEAD", &"g".repeat(40)] {
            assert!(parse_git_head(invalid).is_err());
        }
        assert!(is_remote_version_newer(&local, &remote));
        assert!(!is_remote_version_newer(&local, &local));
    }

    #[test]
    fn test_git_sha_and_synthetic_version_identities() {
        assert_eq!(extract_version("6e840ac", ""), "6e840ac");
        assert_eq!(extract_version("dd032e1d7bb2", ""), "dd032e1d7bb2");
        assert_eq!(normalize_version_token("6e840ac"), "6e840ac");
        assert_eq!(normalize_version_token("dd032e1d7bb2"), "dd032e1d7bb2");
        assert!(is_remote_version_newer("6e840ac", "0.6.27"));
        assert!(is_remote_version_newer("dd032e1", "2.18.2"));
        assert!(!is_remote_version_newer(
            "0.1.0-6e840ac",
            "6e840acbda8d1234567890abcdef1234567890ab"
        ));
        assert!(is_remote_version_newer(
            "0.1.0-6e840ac",
            "9999999bda8d1234567890abcdef1234567890ab"
        ));
        assert!(!is_git_commit_sha("20261108"));
        assert!(is_git_commit_sha("6e840ac"));
    }

    #[test]
    fn test_sanitize_update_check_error_rate_limit() {
        assert_eq!(
            sanitize_update_check_error("GitHub API rate limit exceeded (HTTP 403)"),
            "GitHub API rate limit reached; retaining last confirmed version"
        );
        assert_eq!(
            sanitize_update_check_error("GitHub API rate limit exceeded (HTTP 429)"),
            "GitHub API rate limit reached; retaining last confirmed version"
        );
        assert_eq!(
            sanitize_update_check_error("Installed version could not be confirmed"),
            "Installed version could not be confirmed"
        );
        assert_eq!(
            sanitize_update_check_error("arbitrary internal failure /etc/passwd"),
            "Update status could not be confirmed"
        );
    }

    #[test]
    fn test_parse_speed_str_to_mb_s() {
        assert!((parse_speed_str_to_mb_s("10.5 MB/s") - 10.5).abs() < 1e-6);
        assert!((parse_speed_str_to_mb_s("1024.0 KB/s") - 1.0).abs() < 1e-6);
        assert_eq!(parse_speed_str_to_mb_s("0 B/s"), 0.0);
    }

    #[test]
    fn test_installed_state_uses_lock_during_active_lifecycle_job() {
        let path = std::env::temp_dir().join(format!(
            "af-package-lock-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::write(&path, "installed").unwrap();
        let pkg = Package {
            lock_file: path.to_string_lossy().into_owned(),
            status: "installing".to_string(),
            ..Default::default()
        };
        let installed_during_job = package_is_installed(&pkg);
        std::fs::remove_file(&path).unwrap();
        assert!(installed_during_job);
        assert!(!package_is_installed(&pkg));
    }

    #[test]
    fn update_failures_never_copy_command_diagnostics_into_status() {
        let record = build_package_update_record(
            "fixture", true,
            Err(anyhow::anyhow!("SYNTHETIC_PRIVATE_DIAGNOSTIC /etc/private/config")),
            Err(anyhow::anyhow!("remote endpoint returned SYNTHETIC_PRIVATE_DIAGNOSTIC")),
            None, "2026-11-06T00:00:00Z".into(),
        );
        assert_eq!(record.error, "Installed version could not be confirmed; Latest version could not be confirmed");
        assert!(!serde_json::to_string(&record).unwrap().contains("SYNTHETIC_PRIVATE_DIAGNOSTIC"));
    }

    #[cfg(unix)]
    #[test]
    fn legacy_update_errors_are_sanitized_from_database_and_cache() {
        use crate::inventory_regressions::{isolated, Fixture};
        if !isolated("workers::tests::legacy_update_errors_are_sanitized_from_database_and_cache") { return; }
        let _fixture = Fixture::new();
        af_db::init_db().unwrap();
        af_db::get_conn().unwrap().execute(
            "INSERT INTO app_updates(package_name,installed_version,latest_version,update_available,last_error) VALUES('fixture','1.0','1.1',1,'SYNTHETIC_PRIVATE_DIAGNOSTIC')", [],
        ).unwrap();
        assert_eq!(get_package_update_map()["fixture"].error, "Update status could not be confirmed");
        let mut raw = get_package_update_map()["fixture"].clone();
        raw.error = "different SYNTHETIC_PRIVATE_DIAGNOSTIC".into();
        PACKAGE_UPDATE_CACHE.lock().unwrap().insert("fixture".into(), raw);
        let safe = get_package_update_map();
        assert_eq!(safe["fixture"].error, "Update status could not be confirmed");
        assert!(safe["fixture"].update_available);
    }

    #[test]
    fn test_build_package_update_record_preserves_previous_versions_on_failure() {
        let prev = PackageUpdateRecord {
            package_id: "radarr".to_string(),
            installed: true,
            installed_version: "5.14.0".to_string(),
            latest_version: "5.15.0".to_string(),
            update_available: true,
            checked_at: "2026-11-01T00:00:00Z".to_string(),
            release_url: "https://github.com/Radarr/Radarr/releases/tag/v5.15.0".to_string(),
            error: String::new(),
            source_key: "github:https://api.github.com|radarr/radarr|stable".to_string(),
        };

        let failed = build_package_update_record(
            "radarr",
            true,
            Err(anyhow::anyhow!("binary not found")),
            Err(anyhow::anyhow!("github rate limit exceeded")),
            Some(&prev),
            "2026-11-02T00:00:00Z".to_string(),
        );
        assert_eq!(failed.installed_version, "5.14.0");
        assert_eq!(failed.latest_version, "5.15.0");
        assert_eq!(
            failed.release_url,
            "https://github.com/Radarr/Radarr/releases/tag/v5.15.0"
        );
        assert_eq!(failed.checked_at, "2026-11-01T00:00:00Z");
        assert!(failed.update_available);
        assert_eq!(failed.error, "Installed version could not be confirmed; Latest version could not be confirmed");
    }

    #[test]
    fn test_github_token_never_sent_to_pypi_or_untrusted_host() {
        assert!(is_trusted_github_api_url(
            "https://api.github.com/repos/a/b/releases/latest",
            "https://api.github.com"
        ));
        assert!(!is_trusted_github_api_url(
            "https://pypi.org/pypi/pyload-ng/json",
            "https://api.github.com"
        ));
        assert!(!is_trusted_github_api_url(
            "https://pypi.org/pypi/pyload-ng/json",
            "https://pypi.org"
        ));
        assert!(is_trusted_github_api_url(
            "https://github.com/a/b",
            "https://api.github.com"
        ));
        assert!(!is_trusted_github_api_url(
            "http://api.github.com/repos/a/b/releases/latest",
            "https://api.github.com"
        ));
        assert!(is_trusted_github_api_url(
            "http://127.0.0.1:8080/repos/a/b/releases/latest",
            "http://127.0.0.1:8080"
        ));
        assert!(!is_trusted_github_api_url(
            "http://evil.com/repos/a/b/releases/latest",
            "http://evil.com"
        ));
    }

    #[test]
    fn test_component_manifest_requirements_and_equality() {
        assert!(parse_component_manifest("frontend:111111a,backend:222222b,proxy:333333c,frontend:444444d").is_none());
        assert!(parse_component_manifest("frontend:111111a").is_none());
        assert!(parse_component_manifest("frontend:111111a,backend:222222b").is_none());
        assert!(parse_component_manifest("backend:222222b,proxy:333333c").is_none());
        assert!(parse_component_manifest("frontend:111111a,proxy:333333c").is_none());
        assert!(parse_component_manifest("frontend:111111a,backend:222222b,proxy:333333c").is_some());
        assert!(parse_component_manifest("ui:111111a,server:222222b").is_some());

        let raw = "frontend:6e840acbda8d1234567890abcdef1234567890ab,backend:dd032e1d7bb2,proxy:1a2b3c4";
        assert_eq!(extract_version(raw, "git"), raw);

        let m1 = "frontend:111111a,backend:222222b,proxy:333333c";
        let m2 = "frontend:111111a,backend:222222b,proxy:333333c,worker:444444d";
        assert!(!versions_match_target_internal(m1, m2));
        assert!(is_remote_version_newer(m1, m2));
        assert!(is_remote_version_newer(m2, m1));
        assert!(versions_match_target_internal(m1, m1));
        assert!(is_newer_version(m1, m2));
    }

    #[test]
    fn test_installed_version_failure_preserves_checked_at_and_surfaces_warning() {
        let prev = PackageUpdateRecord {
            package_id: "qbittorrent".to_string(),
            installed: true,
            installed_version: "4.6.0".to_string(),
            latest_version: "4.6.1".to_string(),
            update_available: true,
            checked_at: "2026-11-01T12:00:00Z".to_string(),
            release_url: "https://github.com/qbittorrent/qBittorrent/releases/tag/release-4.6.1".to_string(),
            error: String::new(),
            source_key: "github:https://api.github.com|qbittorrent/qbittorrent".to_string(),
        };

        let rec = build_package_update_record(
            "qbittorrent",
            true,
            Err(anyhow::anyhow!("probe timed out")),
            Ok(("4.6.2".to_string(), "https://github.com/qbittorrent/qBittorrent/releases/tag/release-4.6.2".to_string())),
            Some(&prev),
            "2026-11-08T12:00:00Z".to_string(),
        );

        assert_eq!(rec.installed_version, "4.6.0");
        assert_eq!(rec.latest_version, "4.6.2");
        assert_eq!(rec.checked_at, "2026-11-08T12:00:00Z");
        assert_eq!(
            rec.error,
            "Installed version probe returned no output; retaining last known installed version"
        );
        assert_eq!(
            public_update_error(&rec.error),
            "Installed version probe returned no output; retaining last known installed version"
        );
    }

    #[tokio::test]
    async fn test_rate_limit_handling_and_stale_cache_fallback() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let length = socket.read(&mut request).await.unwrap();
            let _ = length;
            let response = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let client = build_github_http_client();
        let api_base = format!("http://{address}");
        let repo = "testowner/testrepo";

        let cache_key = github_release_cache_key(&api_base, repo);
        {
            let mut cache = github_release_cache();
            cache.insert(
                cache_key.clone(),
                ("1.0.0".to_string(), "https://github.com/testowner/testrepo/releases/tag/v1.0.0".to_string(), Instant::now() - Duration::from_secs(3600), "2026-11-08T11:00:00Z".to_string()),
            );
        }

        let res = detect_latest_github_release(&client, &api_base, repo).await;
        server.await.unwrap();
        assert!(res.is_err());
        let err_str = res.unwrap_err().to_string();
        assert!(err_str.contains("rate limit"));

        let rec = build_package_update_record_for_source(
            &api_base,
            "github",
            repo,
            true,
            Ok("0.9.0".to_string()),
            Err(anyhow::anyhow!("rate limit")),
            None,
            "2026-11-08T12:00:00Z".to_string(),
            "",
        );
        assert_eq!(rec.latest_version, "1.0.0");
        assert_eq!(rec.checked_at, "2026-11-08T11:00:00Z");
        assert_eq!(rec.error, "Latest version could not be confirmed");
    }

    #[test]
    fn test_component_manifest_newer_comparison() {
        let local = "frontend:6e840ac,backend:dd032e1,proxy:1a2b3c4";
        let remote_same = "frontend:6e840acbda8d1234567890abcdef1234567890ab,backend:dd032e1d7bb2,proxy:1a2b3c4";
        assert!(!is_remote_version_newer(local, remote_same));

        let remote_diff = "frontend:6e840ac,backend:ffffff1,proxy:1a2b3c4";
        assert!(is_remote_version_newer(local, remote_diff));

        let remote_missing = "frontend:6e840ac,backend:dd032e1,proxy:1a2b3c4,worker:555555a";
        assert!(is_remote_version_newer(local, remote_missing));

        // Generic component manifests comp1:1.1,comp2:2.0 vs comp1:1.10,comp2:2.0
        let gen_local = "comp1:1.1,comp2:2.0";
        let gen_remote = "comp1:1.10,comp2:2.0";
        assert!(!versions_match_target_internal(gen_local, gen_remote));
        assert!(is_remote_version_newer(gen_local, gen_remote));
        assert!(!is_remote_version_newer(gen_remote, gen_local));
    }

    #[tokio::test]
    async fn test_cache_hit_preserves_observed_at_checked_at() {
        let repo = "test-cached-owner/test-cached-repo";
        let api_base = "https://api.github.com";
        let cache_key = github_release_cache_key(api_base, repo);
        let cached_time = "2026-11-01T10:00:00Z";
        {
            let mut cache = github_release_cache();
            cache.insert(
                cache_key,
                (
                    "3.4.5".to_string(),
                    format!("https://github.com/{repo}/releases/tag/v3.4.5"),
                    Instant::now(),
                    cached_time.to_string(),
                ),
            );
        }

        let pkg = Package {
            name: "test-cached-pkg".into(),
            update_source: "github".into(),
            update_repo: repo.into(),
            version_command: vec!["printf".into(), "%s".into(), "3.4.5".into()],
            ..Default::default()
        };

        let client = build_github_http_client();
        let (record, _) = probe_package_update(&client, api_base, &pkg).await;
        assert_eq!(record.latest_version, "3.4.5");
        assert_eq!(record.checked_at, cached_time);
    }

    #[test]
    fn test_threadfin_fallback_preserves_newer_previous_and_sets_error() {
        let prev = PackageUpdateRecord {
            package_id: "threadfin".to_string(),
            installed: true,
            installed_version: "1.1.0".to_string(),
            latest_version: "1.2.0".to_string(),
            update_available: true,
            checked_at: "2026-11-01T00:00:00Z".to_string(),
            release_url: "https://github.com/Threadfin/Threadfin/releases/tag/1.2.0".to_string(),
            error: String::new(),
            source_key: "github:https://api.github.com|threadfin/threadfin|stable".to_string(),
        };

        let failed_record = build_package_update_record(
            "threadfin",
            true,
            Ok("1.1.0".to_string()),
            Err(anyhow::anyhow!("GitHub release fetch failed")),
            Some(&prev),
            "2026-11-08T12:00:00Z".to_string(),
        );

        // Newer version 1.2.0 from previous observation must NOT be overwritten by static fallback (e.g. 1.1.2)
        assert_eq!(failed_record.latest_version, "1.2.0");
        assert_eq!(failed_record.checked_at, "2026-11-01T00:00:00Z");
        assert_eq!(failed_record.error, "Latest version could not be confirmed");
    }

    #[tokio::test]
    async fn test_stale_af_version_receipt_contradicting_live_runtime_fails() {
        let _env_guard = TEST_ENV_MUTEX.lock().await;
        let temp_dir = std::env::temp_dir().join(format!("af-test-stale-ver-{}", uuid::Uuid::new_v4()));
        let opt_dir = temp_dir.join("opt/test-stale-pkg");
        std::fs::create_dir_all(&opt_dir).unwrap();
        std::fs::write(opt_dir.join(".af-version"), "1.0.0").unwrap();

        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let pkg = Package {
            name: "test-stale-pkg".into(),
            version_command: vec!["printf".into(), "%s".into(), "2.0.0".into()],
            ..Default::default()
        };

        // Live runtime says 2.0.0 but disk receipt says 1.0.0 -> must FAIL
        let res = probe_installed_package_version_strict(&pkg).await;
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("Stale or mismatched .af-version receipt"), "actual error: {err_msg}");

        // Now fix .af-version to match live runtime
        std::fs::write(opt_dir.join(".af-version"), "2.0.0").unwrap();
        let res_ok = probe_installed_package_version_strict(&pkg).await;
        assert!(res_ok.is_ok());
        assert_eq!(res_ok.unwrap(), "2.0.0");

        std::env::remove_var("AETHERFLOW_FS_ROOT");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_probe_installed_package_version_strict() {
        let pkg = Package {
            name: "test-pkg".into(),
            ..Default::default()
        };
        assert!(probe_installed_package_version_strict(&pkg).await.is_err());
    }

    #[test]
    fn test_monitored_component_policy_skips_unconfigured_optional_and_oneshots() {
        let autobrr_unconfigured = crate::resolve_service_component_policies_with("rclone", false);
        let monitored_units: Vec<String> = autobrr_unconfigured
            .into_iter()
            .filter(is_component_policy_monitored)
            .map(|p| p.unit)
            .collect();
        assert_eq!(monitored_units, vec!["rclone".to_string()]);

        let recyclarr_policies = crate::resolve_service_component_policies_with("recyclarr", false);
        let recyclarr_monitored: Vec<String> = recyclarr_policies
            .into_iter()
            .filter(is_component_policy_monitored)
            .map(|p| p.unit)
            .collect();
        assert_eq!(recyclarr_monitored, vec!["recyclarr.timer".to_string()]);
    }

    #[tokio::test]
    async fn test_piped_strict_probe_verifies_all_three_git_repos_against_receipt() {
        let _env_guard = TEST_ENV_MUTEX.lock().await;
        let temp_dir = std::env::temp_dir().join(format!("af-test-piped-git-{}", uuid::Uuid::new_v4()));
        let opt_piped = temp_dir.join("opt/piped");
        let opt_frontend = opt_piped.join("frontend");
        let opt_backend = opt_piped.join("backend");
        let opt_proxy = opt_piped.join("proxy");

        let init_repo = |dir: &Path, name: &str| -> String {
            std::fs::create_dir_all(dir).unwrap();
            assert!(std::process::Command::new("git")
                .args(["init", "-b", "main"])
                .current_dir(dir)
                .status()
                .unwrap()
                .success());
            assert!(std::process::Command::new("git")
                .args(["config", "user.email", "test@example.com"])
                .current_dir(dir)
                .status()
                .unwrap()
                .success());
            assert!(std::process::Command::new("git")
                .args(["config", "user.name", "Test"])
                .current_dir(dir)
                .status()
                .unwrap()
                .success());
            std::fs::write(dir.join("component.txt"), name).unwrap();
            assert!(std::process::Command::new("git")
                .args(["add", "component.txt"])
                .current_dir(dir)
                .status()
                .unwrap()
                .success());
            assert!(std::process::Command::new("git")
                .args(["commit", "-m", "initial commit"])
                .current_dir(dir)
                .status()
                .unwrap()
                .success());
            let out = std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(out.status.success());
            String::from_utf8_lossy(&out.stdout).trim().to_ascii_lowercase()
        };

        let fe_sha = init_repo(&opt_frontend, "piped-frontend");
        let be_sha = init_repo(&opt_backend, "piped-backend");
        let pr_sha = init_repo(&opt_proxy, "piped-proxy");

        let manifest = format!("frontend:{fe_sha},backend:{be_sha},proxy:{pr_sha}");
        std::fs::write(opt_piped.join(".af-version"), &manifest).unwrap();

        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let pkg = Package {
            name: "piped".into(),
            update_repo: "TeamPiped/Piped".into(),
            update_source: "git".into(),
            ..Default::default()
        };

        // 1. Success when .af-version matches all 3 repos in installer layout
        let res_ok = probe_installed_package_version_strict(&pkg).await;
        assert!(res_ok.is_ok(), "Expected success when .af-version matches: {:?}", res_ok.err());
        assert_eq!(res_ok.unwrap(), manifest);

        // 2. Fails when any of the 3 repos is on a different commit than .af-version
        let mismatched = format!("frontend:{fe_sha},backend:{},proxy:{pr_sha}", "0".repeat(40));
        std::fs::write(opt_piped.join(".af-version"), &mismatched).unwrap();
        let res_mismatch = probe_installed_package_version_strict(&pkg).await;
        assert!(res_mismatch.is_err());
        let err = res_mismatch.unwrap_err().to_string();
        assert!(
            err.contains("Stale or mismatched .af-version receipt"),
            "Expected mismatch error, got: {err}"
        );

        // 3. Fails when one repo has incomplete git probe
        std::fs::write(opt_piped.join(".af-version"), &manifest).unwrap();
        let proxy_git = opt_proxy.join(".git");
        let proxy_git_bak = opt_proxy.join(".git_bak");
        std::fs::rename(&proxy_git, &proxy_git_bak).unwrap();
        let res_incomplete = probe_installed_package_version_strict(&pkg).await;
        assert!(res_incomplete.is_err());

        // Restore git dir and clean up
        let _ = std::fs::rename(&proxy_git_bak, &proxy_git);
        std::env::remove_var("AETHERFLOW_FS_ROOT");
        let _ = std::fs::remove_dir_all(&temp_dir);

        // 4. Verify flat layout fallback (/opt/piped/.git, /opt/piped-backend/.git, /opt/piped-proxy/.git)
        let flat_temp_dir = std::env::temp_dir().join(format!("af-test-piped-flat-{}", uuid::Uuid::new_v4()));
        let flat_piped = flat_temp_dir.join("opt/piped");
        let flat_backend = flat_temp_dir.join("opt/piped-backend");
        let flat_proxy = flat_temp_dir.join("opt/piped-proxy");
        let fe_flat = init_repo(&flat_piped, "piped-frontend");
        let be_flat = init_repo(&flat_backend, "piped-backend");
        let pr_flat = init_repo(&flat_proxy, "piped-proxy");
        let flat_manifest = format!("frontend:{fe_flat},backend:{be_flat},proxy:{pr_flat}");
        std::fs::write(flat_piped.join(".af-version"), &flat_manifest).unwrap();
        std::env::set_var("AETHERFLOW_FS_ROOT", &flat_temp_dir);
        let res_flat = probe_installed_package_version_strict(&pkg).await;
        assert!(res_flat.is_ok(), "Expected success with flat layout fallback: {:?}", res_flat.err());
        assert_eq!(res_flat.unwrap(), flat_manifest);
        std::env::remove_var("AETHERFLOW_FS_ROOT");
        let _ = std::fs::remove_dir_all(&flat_temp_dir);
    }

    #[tokio::test]
    async fn test_cache_hit_isolation_sequential_and_concurrent() {
        let api_base = "https://api.github.com";
        let repo_a = "test-iso/repo-a";
        let repo_b = "test-iso/repo-b";
        let cached_time_a = "2026-11-01T01:00:00Z";
        let cached_time_b = "2026-11-02T02:00:00Z";

        {
            let mut cache = github_release_cache();
            cache.insert(
                github_release_cache_key(api_base, repo_a),
                ("1.0.0".to_string(), format!("https://github.com/{repo_a}/releases/tag/v1.0.0"), Instant::now(), cached_time_a.to_string()),
            );
            cache.insert(
                github_release_cache_key(api_base, repo_b),
                ("2.0.0".to_string(), format!("https://github.com/{repo_b}/releases/tag/v2.0.0"), Instant::now(), cached_time_b.to_string()),
            );
        }

        let pkg_a = Package {
            name: "test-pkg-a".into(),
            update_source: "github".into(),
            update_repo: repo_a.into(),
            version_command: vec!["printf".into(), "%s".into(), "1.0.0".into()],
            ..Default::default()
        };
        let pkg_b = Package {
            name: "test-pkg-b".into(),
            update_source: "github".into(),
            update_repo: repo_b.into(),
            version_command: vec!["printf".into(), "%s".into(), "2.0.0".into()],
            ..Default::default()
        };

        let client = build_github_http_client();

        // 1. Sequential probe: timestamps must not cross-contaminate
        let (rec_a, _) = probe_package_update(&client, api_base, &pkg_a).await;
        let (rec_b, _) = probe_package_update(&client, api_base, &pkg_b).await;
        assert_eq!(rec_a.checked_at, cached_time_a);
        assert_eq!(rec_b.checked_at, cached_time_b);

        // 2. Concurrent probe: timestamps must not cross-contaminate
        let (res_a, res_b) = tokio::join!(
            probe_package_update(&client, api_base, &pkg_a),
            probe_package_update(&client, api_base, &pkg_b),
        );
        assert_eq!(res_a.0.checked_at, cached_time_a);
        assert_eq!(res_b.0.checked_at, cached_time_b);
    }

    #[tokio::test]
    async fn test_piped_discovery_uses_oldest_constituent_observed_at() {
        let sha_fe = "1111111111111111111111111111111111111111";
        let sha_be = "2222222222222222222222222222222222222222";
        let sha_px = "3333333333333333333333333333333333333333";

        let time_fe = "2026-11-05T10:00:00+00:00";
        let time_be = "2026-11-01T08:00:00+00:00"; // oldest!
        let time_px = "2026-11-03T12:00:00+00:00";

        {
            let mut cache = git_remote_head_cache();
            cache.insert(
                git_head_cache_key("https://github.com/TeamPiped/Piped.git", "TeamPiped/Piped"),
                (sha_fe.to_string(), "https://github.com/TeamPiped/Piped/commits/HEAD".to_string(), Instant::now(), time_fe.to_string()),
            );
            cache.insert(
                git_head_cache_key("https://github.com/TeamPiped/Piped-Backend.git", "TeamPiped/Piped-Backend"),
                (sha_be.to_string(), "https://github.com/TeamPiped/Piped-Backend/commits/HEAD".to_string(), Instant::now(), time_be.to_string()),
            );
            cache.insert(
                git_head_cache_key("https://github.com/TeamPiped/Piped-Proxy.git", "TeamPiped/Piped-Proxy"),
                (sha_px.to_string(), "https://github.com/TeamPiped/Piped-Proxy/commits/HEAD".to_string(), Instant::now(), time_px.to_string()),
            );
        }

        let res = detect_latest_piped_manifest().await.unwrap();
        assert_eq!(
            res.0,
            format!("frontend:{sha_fe},backend:{sha_be},proxy:{sha_px}")
        );
        // Constituent observations hit the cache with different timestamps -> manifest MUST take oldest!
        assert_eq!(res.2, time_be);
    }

    #[test]
    fn test_semver_build_metadata_and_debian_ordering() {
        // SemVer 2.0.0 build metadata is ignored for version precedence
        assert!(!is_remote_version_newer("1.0.0", "1.0.0+build.2"));
        assert!(!is_remote_version_newer("1.0.0+build.2", "1.0.0"));
        assert_eq!(compare_versions("1.0.0", "1.0.0+build.2"), std::cmp::Ordering::Equal);
        assert_eq!(compare_versions("1.0.0+build.2", "1.0.0"), std::cmp::Ordering::Equal);

        // Prereleases with letter suffix are strictly OLDER than bare release
        assert!(is_remote_version_newer("1.0.0-foo", "1.0.0"));
        assert!(!is_remote_version_newer("1.0.0", "1.0.0-foo"));
        assert_eq!(compare_versions("1.0.0-foo", "1.0.0"), std::cmp::Ordering::Less);
        assert_eq!(compare_versions("1.0.0", "1.0.0-foo"), std::cmp::Ordering::Greater);

        assert!(is_remote_version_newer("1.0.0-alpha.1", "1.0.0"));
        assert_eq!(compare_versions("1.0.0-alpha.1", "1.0.0"), std::cmp::Ordering::Less);

        assert!(is_remote_version_newer("1.0.0-rc.1", "1.0.0"));
        assert_eq!(compare_versions("1.0.0-rc.1", "1.0.0"), std::cmp::Ordering::Less);

        // SemVer 2.0.0: numeric prereleases after hyphen (like 1.0.0-1, 1.0.0-0.3.7) are prereleases (LOWER precedence than 1.0.0)
        assert!(is_remote_version_newer("1.0.0-1", "1.0.0"));
        assert!(!is_remote_version_newer("1.0.0", "1.0.0-1"));
        assert_eq!(compare_versions("1.0.0-1", "1.0.0"), std::cmp::Ordering::Less);
        assert_eq!(compare_versions("1.0.0", "1.0.0-1"), std::cmp::Ordering::Greater);

        assert!(is_remote_version_newer("1.0.0-0.3.7", "1.0.0"));
        assert_eq!(compare_versions("1.0.0-0.3.7", "1.0.0"), std::cmp::Ordering::Less);

        // Apt mode: Debian package revisions (-1 > bare, +deb11u1 < +deb11u2, +b1 < +b2)
        assert!(is_remote_version_newer_for_source("1.0.0", "1.0.0-1", "apt"));
        assert!(!is_remote_version_newer_for_source("1.0.0-1", "1.0.0", "apt"));
        assert_eq!(compare_versions_for_source("1.0.0", "1.0.0-1", "apt"), std::cmp::Ordering::Less);
        assert_eq!(compare_versions_for_source("1.0.0-1", "1.0.0", "apt"), std::cmp::Ordering::Greater);

        assert!(is_remote_version_newer_for_source("1.2.3-1ubuntu1", "1.2.3-2ubuntu1", "apt"));
        assert_eq!(compare_versions_for_source("1.2.3-1ubuntu1", "1.2.3-2ubuntu1", "apt"), std::cmp::Ordering::Less);

        assert!(is_remote_version_newer_for_source("1.2.3+deb11u1", "1.2.3+deb11u2", "apt"));
        assert_eq!(compare_versions_for_source("1.2.3+deb11u1", "1.2.3+deb11u2", "apt"), std::cmp::Ordering::Less);
        assert!(is_remote_version_newer_for_source("1.2.3+b1", "1.2.3+b2", "apt"));
        assert_eq!(compare_versions_for_source("1.2.3+b1", "1.2.3+b2", "apt"), std::cmp::Ordering::Less);

        // Release prefixes normalized
        assert_eq!(compare_versions("release_1.0.0", "v1.0.0"), std::cmp::Ordering::Equal);
        assert_eq!(compare_versions("rel_1.0.0", "1.0.0"), std::cmp::Ordering::Equal);
        assert_eq!(compare_versions("release-1.0.0", "1.0.0+build.1"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_stacked_tag_prefixes_in_extract_version() {
        assert_eq!(extract_version("release-v1.2.3", ""), "1.2.3");
        assert_eq!(extract_version("release_v1.2.3", ""), "1.2.3");
        assert_eq!(extract_version("rel-v1.2.3", ""), "1.2.3");
        assert_eq!(extract_version("rel_v1.2.3", ""), "1.2.3");
        assert_eq!(extract_version("release_1.2.3", ""), "1.2.3");
        assert_eq!(extract_version("v1.2.3", ""), "1.2.3");
    }

    #[test]
    fn test_git_commit_sha_antisymmetry_and_newer() {
        let sha1 = "6e840acbda8d1234567890abcdef1234567890ab";
        let sha2 = "9999999bda8d1234567890abcdef1234567890ab";
        // Distinct commits: compare_versions must be antisymmetric total order
        let ord1 = compare_versions(sha1, sha2);
        let ord2 = compare_versions(sha2, sha1);
        assert_eq!(ord1, ord2.reverse());
        assert_ne!(ord1, std::cmp::Ordering::Equal);

        // Prefix-matching commits are equal
        assert_eq!(compare_versions("6e840ac", sha1), std::cmp::Ordering::Equal);
        assert_eq!(compare_versions(sha1, "6e840ac"), std::cmp::Ordering::Equal);

        // is_remote_version_newer: distinct commit on tracked branch is an update
        assert!(is_remote_version_newer(sha1, sha2));
        assert!(is_remote_version_newer(sha2, sha1));
        // Same/prefix-matching commit is NOT an update
        assert!(!is_remote_version_newer(sha1, "6e840ac"));
        assert!(!is_remote_version_newer("6e840ac", sha1));
    }

    #[tokio::test]
    async fn test_detect_installed_version_fails_closed_when_live_cmd_fails_with_af_version() {
        let _env_guard = TEST_ENV_MUTEX.lock().await;
        let temp_dir = std::env::temp_dir().join(format!("af-test-fail-closed-{}", uuid::Uuid::new_v4()));
        let opt_dir = temp_dir.join("opt/test-fail-pkg");
        std::fs::create_dir_all(&opt_dir).unwrap();
        std::fs::write(opt_dir.join(".af-version"), "1.0.0").unwrap();

        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let pkg = Package {
            name: "test-fail-pkg".into(),
            // A live command that is guaranteed to fail
            version_command: vec!["/bin/false".into()],
            ..Default::default()
        };

        // Even though .af-version exists with "1.0.0", the configured live probe failed,
        // so detect_installed_version MUST fail closed (Err)
        let res = detect_installed_version(&pkg).await;
        assert!(res.is_err(), "Expected detect_installed_version to fail closed when live cmd fails");

        let rec = build_package_update_record(
            "test-fail-pkg",
            true,
            res,
            Ok(("1.0.0".to_string(), "https://example.com".to_string())),
            None,
            "2026-11-08T12:00:00Z".to_string(),
        );
        assert_eq!(rec.error, "Installed version could not be confirmed");

        std::env::remove_var("AETHERFLOW_FS_ROOT");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_stale_cache_origin_isolation_and_observed_at_preservation() {
        let origin_a = "https://api.github.com";
        let origin_b = "https://github-enterprise.internal.net";
        let repo = "myorg/myrepo";
        let observed_time = "2026-11-08T09:30:00Z";

        // Insert into cache under origin A
        {
            let mut cache = github_release_cache();
            cache.insert(
                github_release_cache_key(origin_a, repo),
                (
                    "2.5.0".to_string(),
                    format!("https://github.com/{repo}/releases/tag/v2.5.0"),
                    Instant::now() - Duration::from_secs(3600),
                    observed_time.to_string(),
                ),
            );
        }

        // Stale lookup under origin B must return None (origin isolation!)
        assert_eq!(get_cached_github_release_stale(origin_b, repo), None);

        // Stale lookup under origin A must return the cached version, URL, and observed_at
        let cached = get_cached_github_release_stale(origin_a, repo);
        assert!(cached.is_some());
        let (v, _u, obs) = cached.unwrap();
        assert_eq!(v, "2.5.0");
        assert_eq!(obs, observed_time);

        // When used in build_package_update_record_for_source with Err and no prior DB record,
        // checked_at is set to observed_time
        let rec = build_package_update_record_for_source(
            origin_a,
            "github",
            repo,
            true,
            Ok("2.4.0".to_string()),
            Err(anyhow::anyhow!("API timeout")),
            None,
            "2026-11-08T12:00:00Z".to_string(),
            "",
        );
        assert_eq!(rec.latest_version, "2.5.0");
        assert_eq!(rec.checked_at, observed_time);

        // When static fallback is used with no prior DB record and no cache hit, checked_at is empty ("")
        let rec_static = build_package_update_record_for_source(
            origin_b,
            "github",
            "threadfin",
            true,
            Ok("1.0.0".to_string()),
            Err(anyhow::anyhow!("API timeout")),
            None,
            "2026-11-08T12:00:00Z".to_string(),
            "",
        );
        // threadfin has static fallback; since it had no cache hit under origin_b and no prior DB record,
        // checked_at must be empty string
        assert_eq!(rec_static.checked_at, "");
    }

    #[test]
    fn test_source_provenance_validation_invalidates_prev_on_mismatch_or_legacy() {
        let origin_a = "https://api.github.com";
        let origin_b = "https://internal-ghe.example.com";
        let repo_a = "owner/repo-a";
        let repo_b = "owner/repo-b";

        let matching_prev = PackageUpdateRecord {
            package_id: "testpkg".to_string(),
            installed: true,
            installed_version: "1.0.0".to_string(),
            latest_version: "1.1.0".to_string(),
            update_available: true,
            checked_at: "2026-11-01T00:00:00Z".to_string(),
            release_url: "https://github.com/owner/repo-a/releases/tag/v1.1.0".to_string(),
            error: String::new(),
            source_key: format!("github:{}|{}", normalize_api_origin(origin_a), repo_a),
        };

        // 1. Matching provenance: previous version, URL, checked_at, and update_available are preserved on error
        let expected_key_a = format!("github:{}|{}", normalize_api_origin(origin_a), repo_a);
        let rec_matching = build_package_update_record_for_source(
            origin_a,
            "github",
            "testpkg",
            true,
            Ok("1.0.0".to_string()),
            Err(anyhow::anyhow!("network unreachable")),
            Some(&matching_prev),
            "2026-11-08T12:00:00Z".to_string(),
            &expected_key_a,
        );
        assert_eq!(rec_matching.latest_version, "1.1.0");
        assert_eq!(rec_matching.release_url, "https://github.com/owner/repo-a/releases/tag/v1.1.0");
        assert_eq!(rec_matching.checked_at, "2026-11-01T00:00:00Z");
        assert!(rec_matching.update_available);

        // 2. Mismatched origin (origin changed from origin_a to origin_b):
        // prev record must be INVALIDATED (treated as None for latest_version/release_url/checked_at/update_available)
        let expected_key_b_origin = format!("github:{}|{}", normalize_api_origin(origin_b), repo_a);
        let rec_mismatched_origin = build_package_update_record_for_source(
            origin_b,
            "github",
            "testpkg",
            true,
            Ok("1.0.0".to_string()),
            Err(anyhow::anyhow!("network unreachable")),
            Some(&matching_prev),
            "2026-11-08T12:00:00Z".to_string(),
            &expected_key_b_origin,
        );
        assert_eq!(rec_mismatched_origin.latest_version, "");
        assert_eq!(rec_mismatched_origin.release_url, "");
        assert_eq!(rec_mismatched_origin.checked_at, "");
        assert!(!rec_mismatched_origin.update_available);

        // 3. Mismatched repo (repo changed from repo_a to repo_b):
        let expected_key_b_repo = format!("github:{}|{}", normalize_api_origin(origin_a), repo_b);
        let rec_mismatched_repo = build_package_update_record_for_source(
            origin_a,
            "github",
            "testpkg",
            true,
            Ok("1.0.0".to_string()),
            Err(anyhow::anyhow!("network unreachable")),
            Some(&matching_prev),
            "2026-11-08T12:00:00Z".to_string(),
            &expected_key_b_repo,
        );
        assert_eq!(rec_mismatched_repo.latest_version, "");
        assert_eq!(rec_mismatched_repo.release_url, "");
        assert_eq!(rec_mismatched_repo.checked_at, "");
        assert!(!rec_mismatched_repo.update_available);

        // 4. Legacy record without source_key (source_key is empty):
        let legacy_prev = PackageUpdateRecord {
            package_id: "testpkg".to_string(),
            installed: true,
            installed_version: "1.0.0".to_string(),
            latest_version: "1.1.0".to_string(),
            update_available: true,
            checked_at: "2026-11-01T00:00:00Z".to_string(),
            release_url: "https://github.com/owner/repo-a/releases/tag/v1.1.0".to_string(),
            error: String::new(),
            source_key: String::new(), // legacy empty
        };
        let rec_legacy = build_package_update_record_for_source(
            origin_a,
            "github",
            "testpkg",
            true,
            Ok("1.0.0".to_string()),
            Err(anyhow::anyhow!("network unreachable")),
            Some(&legacy_prev),
            "2026-11-08T12:00:00Z".to_string(),
            &expected_key_a,
        );
        assert_eq!(rec_legacy.latest_version, "");
        assert_eq!(rec_legacy.release_url, "");
        assert_eq!(rec_legacy.checked_at, "");
        assert!(!rec_legacy.update_available);
    }

    #[test]
    fn test_fallback_timestamps_for_stale_cache_and_static_fallback() {
        let origin = "https://api.github.com";
        let repo = "demo/fallback-test";
        let cache_obs = "2026-11-07T15:30:00Z";

        // Seed stale cache for repo
        {
            let mut cache = github_release_cache();
            cache.insert(
                github_release_cache_key(origin, repo),
                (
                    "3.0.0".to_string(),
                    format!("https://github.com/{repo}/releases/tag/v3.0.0"),
                    Instant::now() - Duration::from_secs(7200),
                    cache_obs.to_string(),
                ),
            );
        }

        // prev record has an old checked_at, but empty latest_version
        let prev_empty_latest = PackageUpdateRecord {
            package_id: "demo-pkg".to_string(),
            installed: true,
            installed_version: "2.9.0".to_string(),
            latest_version: "".to_string(),
            update_available: false,
            checked_at: "2026-11-01T10:00:00Z".to_string(),
            release_url: "".to_string(),
            error: "earlier error".to_string(),
            source_key: format!("github:{}|{}", normalize_api_origin(origin), repo),
        };

        // When upstream errors, but stale cache provides version 3.0.0,
        // checked_at MUST be cache_obs ("2026-11-07T15:30:00Z"), NOT prev.checked_at and NOT now!
        let rec_cache = build_package_update_record_for_source(
            origin,
            "github",
            repo,
            true,
            Ok("2.9.0".to_string()),
            Err(anyhow::anyhow!("503 Service Unavailable")),
            Some(&prev_empty_latest),
            "2026-11-08T18:00:00Z".to_string(),
            &format!("github:{}|{}", normalize_api_origin(origin), repo),
        );
        assert_eq!(rec_cache.latest_version, "3.0.0");
        assert_eq!(rec_cache.checked_at, cache_obs);

        // When upstream errors and static fallback provides version (threadfin),
        // and prev_record had empty latest_version, checked_at MUST be empty string ("")!
        let prev_threadfin_empty = PackageUpdateRecord {
            package_id: "threadfin".to_string(),
            installed: true,
            installed_version: "1.0.0".to_string(),
            latest_version: "".to_string(),
            update_available: false,
            checked_at: "2026-11-01T10:00:00Z".to_string(),
            release_url: "".to_string(),
            error: "failed previously".to_string(),
            source_key: format!("github:{}|Threadfin/Threadfin", normalize_api_origin(origin)),
        };

        let rec_static = build_package_update_record_for_source(
            origin,
            "github",
            "threadfin",
            true,
            Ok("1.0.0".to_string()),
            Err(anyhow::anyhow!("GitHub API down")),
            Some(&prev_threadfin_empty),
            "2026-11-08T18:00:00Z".to_string(),
            &format!("github:{}|Threadfin/Threadfin", normalize_api_origin(origin)),
        );
        assert!(!rec_static.latest_version.is_empty());
        assert_eq!(rec_static.checked_at, ""); // MUST NOT copy prev.checked_at!
    }

    #[tokio::test]
    async fn test_origin_scoped_rate_limit_cooldowns_isolated() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        clear_github_rate_limits();

        // Start mock origin A: always returns 429 Too Many Requests
        let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let req_count_a = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let req_count_a_server = req_count_a.clone();
        let server_a = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener_a.accept().await {
                req_count_a_server.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut buf = vec![0; 2048];
                let _ = socket.read(&mut buf).await;
                let resp = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nx-ratelimit-resource: core\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        // Start mock origin B: returns 200 OK with release JSON
        let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_b = listener_b.local_addr().unwrap();
        let server_b = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener_b.accept().await {
                let mut buf = vec![0; 2048];
                let _ = socket.read(&mut buf).await;
                let body = r#"{"tag_name":"v2.0.0","html_url":"http://mock-b/release"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let client = build_github_http_client();
        let origin_a = format!("http://{addr_a}");
        let origin_b = format!("http://{addr_b}");

        // First call to origin A gets 429 with x-ratelimit-resource: core and records rate limit cooldown
        let res_a = detect_latest_github_release(&client, &origin_a, "owner/repo").await;
        assert!(res_a.is_err());
        assert!(res_a.unwrap_err().to_string().contains("rate limit"));
        assert_eq!(req_count_a.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Subsequent release discovery request to origin A checking "releases" must be suppressed
        // WITHOUT hitting the server, because "core" cooldown is active and shared across buckets!
        let res_a2 = detect_latest_github_release(&client, &origin_a, "owner/repo").await;
        assert!(res_a2.is_err());
        assert!(res_a2.unwrap_err().to_string().contains("rate limit backoff active"));
        assert_eq!(req_count_a.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Cooldown checks across origin A buckets
        assert!(is_github_api_rate_limited(&origin_a, "core"));
        assert!(is_github_api_rate_limited(&origin_a, "releases"));
        assert!(is_github_rate_limited_for_origin(&origin_a, "releases"));
        assert!(github_rate_limit_remaining_secs_for_origin(&origin_a, "releases") > 0);

        // Origin B must be COMPLETELY UNAFFECTED!
        assert!(!is_github_api_rate_limited(&origin_b, "core"));
        assert!(!is_github_api_rate_limited(&origin_b, "releases"));
        assert!(!is_github_api_rate_limited(&origin_b, "default"));

        let res_b = detect_latest_github_release(&client, &origin_b, "owner/repo").await;
        assert!(res_b.is_ok(), "Origin B request must succeed despite Origin A rate limit: {:?}", res_b);
        let (ver_b, url_b, _) = res_b.unwrap();
        assert_eq!(ver_b, "2.0.0");
        assert_eq!(url_b, "http://mock-b/release");

        server_a.abort();
        server_b.abort();
        clear_github_rate_limits();
    }

    #[tokio::test]
    async fn test_retired_readarr_discovery_preserves_pinned_target() {
        let client = build_github_http_client();
        let pkg = Package {
            name: "readarr".into(),
            update_source: "retired".into(),
            ..Default::default()
        };

        // 1. Older Readarr installation (0.4.17.0) -> latest_version == "0.4.18.2805", update_available == true
        let mut rec_older = build_package_update_record_for_source(
            "https://api.github.com",
            "retired",
            "readarr",
            true,
            Ok("0.4.17.0".to_string()),
            Ok(("0.4.18.2805".to_string(), String::new())),
            None,
            "2026-11-09T00:00:00Z".to_string(),
            "",
        );
        if rec_older.latest_version.is_empty() {
            rec_older.latest_version = "0.4.18.2805".to_string();
        }
        rec_older.update_available = rec_older.installed
            && is_remote_version_newer_for_source(
                &rec_older.installed_version,
                &rec_older.latest_version,
                &pkg.update_source,
            );
        rec_older.error = String::new();
        assert_eq!(rec_older.latest_version, "0.4.18.2805");
        assert!(rec_older.update_available);
        assert_eq!(rec_older.error, "");

        // 2. Up-to-date Readarr installation (0.4.18.2805) -> latest_version == "0.4.18.2805", update_available == false
        let mut rec_uptodate = build_package_update_record_for_source(
            "https://api.github.com",
            "retired",
            "readarr",
            true,
            Ok("0.4.18.2805".to_string()),
            Ok(("0.4.18.2805".to_string(), String::new())),
            None,
            "2026-11-09T00:00:00Z".to_string(),
            "",
        );
        if rec_uptodate.latest_version.is_empty() {
            rec_uptodate.latest_version = "0.4.18.2805".to_string();
        }
        rec_uptodate.update_available = rec_uptodate.installed
            && is_remote_version_newer_for_source(
                &rec_uptodate.installed_version,
                &rec_uptodate.latest_version,
                &pkg.update_source,
            );
        rec_uptodate.error = String::new();
        assert_eq!(rec_uptodate.latest_version, "0.4.18.2805");
        assert!(!rec_uptodate.update_available);
        assert_eq!(rec_uptodate.error, "");

        // Pinned version returned without querying upstream GitHub
        let detected = detect_latest_version(&client, "https://invalid-host-unreachable.example.com", &pkg).await.unwrap();
        assert_eq!(detected.0, "0.4.18.2805");
    }

    #[test]
    fn test_fresh_latest_observation_keeps_own_timestamp_when_installed_probe_falls_back() {
        let prev = PackageUpdateRecord {
            package_id: "qbittorrent".to_string(),
            installed: true,
            installed_version: "4.6.0".to_string(),
            latest_version: "4.6.1".to_string(),
            update_available: true,
            checked_at: "2026-11-01T12:00:00Z".to_string(),
            release_url: "https://github.com/qbittorrent/qBittorrent/releases/tag/release-4.6.1".to_string(),
            error: String::new(),
            source_key: "github:https://api.github.com|qbittorrent/qbittorrent|stable".to_string(),
        };

        let rec = build_package_update_record(
            "qbittorrent",
            true,
            Err(anyhow::anyhow!("probe timed out")),
            Ok(("4.6.2".to_string(), "https://github.com/qbittorrent/qBittorrent/releases/tag/release-4.6.2".to_string())),
            Some(&prev),
            "2026-11-08T12:00:00Z".to_string(),
        );

        assert_eq!(rec.installed_version, "4.6.0");
        assert_eq!(rec.latest_version, "4.6.2");
        assert_eq!(rec.checked_at, "2026-11-08T12:00:00Z");
        assert_eq!(
            rec.error,
            "Installed version probe returned no output; retaining last known installed version"
        );
    }

    #[test]
    fn test_debian_version_preservation_and_comparison() {
        assert!(is_remote_version_newer_for_source("1.0.0", "1.0.0+git1", "apt"));
        assert!(!is_remote_version_newer_for_source("1.0.0+git1", "1.0.0", "apt"));
        assert_eq!(
            compare_debian_versions_str("1.0.0", "1.0.0+git1"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_debian_versions_str("1.0.0+git1", "1.0.0"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_debian_versions_str("1:1.0-1", "1.0-1"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_debian_versions_str("1.0~rc1-1", "1.0-1"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_channel_provenance_and_retained_tag_revalidation() {
        let pkg_nightly = Package {
            name: "testpkg".into(),
            update_source: "github".into(),
            update_repo: "owner/repo".into(),
            update_channel: "nightly".into(),
            ..Default::default()
        };
        let key_nightly = canonical_update_source_key("https://api.github.com", &pkg_nightly);
        assert!(key_nightly.ends_with("|nightly"));

        let pkg_stable = Package {
            name: "testpkg".into(),
            update_source: "github".into(),
            update_repo: "owner/repo".into(),
            update_channel: "stable".into(),
            ..Default::default()
        };
        let key_stable = canonical_update_source_key("https://api.github.com", &pkg_stable);
        assert!(key_stable.ends_with("|stable"));
        assert_ne!(key_nightly, key_stable);

        let prev_nightly = PackageUpdateRecord {
            package_id: "testpkg".to_string(),
            installed: true,
            installed_version: "1.0.0".to_string(),
            latest_version: "1.2.0-rc1".to_string(),
            update_available: true,
            checked_at: "2026-11-01T00:00:00Z".to_string(),
            release_url: "https://github.com/owner/repo/releases/tag/v1.2.0-rc1".to_string(),
            error: String::new(),
            source_key: key_nightly,
        };

        // When switching to stable channel and upstream fails, prev_nightly is invalidated
        let rec = build_package_update_record_for_source(
            "https://api.github.com",
            "github",
            "testpkg",
            true,
            Ok("1.0.0".to_string()),
            Err(anyhow::anyhow!("GitHub API down")),
            Some(&prev_nightly),
            "2026-11-08T12:00:00Z".to_string(),
            &key_stable,
        );
        assert_eq!(rec.latest_version, "");
        assert_eq!(rec.checked_at, "");
        assert!(!rec.update_available);

        // When channel == "stable", a prerelease latest_version (1.2.0-rc1 or 1.0.0-1) is not retained on fallback
        let prev_prerelease_on_stable = PackageUpdateRecord {
            package_id: "testpkg".to_string(),
            installed: true,
            installed_version: "1.0.0".to_string(),
            latest_version: "1.2.0-rc1".to_string(),
            update_available: true,
            checked_at: "2026-11-01T00:00:00Z".to_string(),
            release_url: "".to_string(),
            error: String::new(),
            source_key: key_stable.clone(),
        };
        let rec_filtered = build_package_update_record_for_source(
            "https://api.github.com",
            "github",
            "testpkg",
            true,
            Ok("1.0.0".to_string()),
            Err(anyhow::anyhow!("GitHub API down")),
            Some(&prev_prerelease_on_stable),
            "2026-11-08T12:00:00Z".to_string(),
            &key_stable,
        );
        assert_eq!(rec_filtered.latest_version, "");
        assert_eq!(rec_filtered.checked_at, "");
        assert!(!rec_filtered.update_available);
    }

    #[tokio::test]
    async fn test_git_tag_channel_filtering_and_prerelease_rules() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-git-channel-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let run_git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(&temp_dir)
                .output()
                .unwrap();
            assert!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
        };

        run_git(&["init", "-b", "main"]);
        run_git(&["config", "user.email", "test@example.com"]);
        run_git(&["config", "user.name", "Test"]);
        std::fs::write(temp_dir.join("README.md"), "hello").unwrap();
        run_git(&["add", "README.md"]);
        run_git(&["commit", "-m", "initial commit"]);

        // Create tags:
        // v0.9.0 (stable)
        // v1.0.0-0.1 (numeric prerelease)
        // v1.0.0-nightly (arbitrary prerelease)
        run_git(&["tag", "v0.9.0"]);
        run_git(&["tag", "v1.0.0-0.1"]);
        run_git(&["tag", "v1.0.0-nightly"]);

        let repo_url = temp_dir.to_str().unwrap();

        // 1. On "stable" (or ""), numeric prerelease v1.0.0-0.1 and v1.0.0-nightly are ignored -> selects 0.9.0!
        let res_stable = detect_latest_git_tag_for_channel(repo_url, "", "stable").await;
        assert!(res_stable.is_ok(), "Expected stable tag: {:?}", res_stable.err());
        assert_eq!(res_stable.unwrap().0, "0.9.0");

        let res_default = detect_latest_git_tag_for_channel(repo_url, "", "").await;
        assert!(res_default.is_ok());
        assert_eq!(res_default.unwrap().0, "0.9.0");

        // 2. On "prerelease" or "nightly" channel, prereleases are allowed -> selects 1.0.0-nightly
        let res_nightly = detect_latest_git_tag_for_channel(repo_url, "", "nightly").await;
        assert!(res_nightly.is_ok());
        assert_eq!(res_nightly.unwrap().0, "1.0.0-nightly");

        // 3. Repository with ONLY prereleases:
        // Delete v0.9.0
        run_git(&["tag", "-d", "v0.9.0"]);
        run_git(&["tag", "v1.0.0-rc.1"]);

        // On "stable", no stable candidate exists -> MUST RETURN Err (never fall back to prerelease!)
        let res_no_stable = detect_latest_git_tag_for_channel(repo_url, "", "stable").await;
        assert!(res_no_stable.is_err(), "Expected Err when only prerelease tags exist on stable channel");
        let err_msg = res_no_stable.unwrap_err().to_string();
        assert!(err_msg.contains("No stable release tags found"), "actual error: {err_msg}");

        // On "rc" or "beta", selects v1.0.0-rc.1
        let res_rc = detect_latest_git_tag_for_channel(repo_url, "", "rc").await;
        assert!(res_rc.is_ok());
        assert_eq!(res_rc.unwrap().0, "1.0.0-rc.1");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_rate_limit_body_only_403_activates_cooldown() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        clear_github_rate_limits();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let req_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let req_count_srv = req_count.clone();

        let server = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                req_count_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut buf = vec![0; 2048];
                let _ = socket.read(&mut buf).await;
                let body = r#"{"message": "API rate limit exceeded for 203.0.113.1."}"#;
                let resp = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let client = build_github_http_client();
        let origin = format!("http://{addr}");
        let repo = "owner/rate-limited-repo";

        // First call receives 403 with rate limit body and NO rate-limit headers
        let res1 = detect_latest_github_release(&client, &origin, repo).await;
        assert!(res1.is_err());
        let err1 = res1.unwrap_err().to_string();
        assert!(err1.contains("rate limit"), "expected rate limit error, got: {err1}");
        assert_eq!(req_count.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Cooldown must be recorded across both "releases" and "core"/"default"
        assert!(is_github_rate_limited_for_origin(&origin, "releases"));
        assert!(is_github_api_rate_limited(&origin, "core"));
        assert!(is_github_api_rate_limited(&origin, "default"));

        // Second consecutive release discovery request must be SUPPRESSED without hitting the mock server
        let res2 = detect_latest_github_release(&client, &origin, repo).await;
        assert!(res2.is_err());
        let err2 = res2.unwrap_err().to_string();
        assert!(err2.contains("rate limit backoff active"), "expected backoff error, got: {err2}");
        assert_eq!(
            req_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "Second request must be suppressed and not hit the server!"
        );

        server.abort();
        clear_github_rate_limits();
    }

    #[test]
    fn test_dpkg_differential_ordering() {
        let pairs = [
            ("1.0", "1.0.0"),
            ("1.0.0", "1.0"),
            ("1.0.0-rc1", "1.0.0"),
            ("1.0.0", "1.0.0-rc1"),
            ("1.0.0~rc1", "1.0.0"),
            ("1.0.0", "1.0.0~rc1"),
            ("1.0.0+git1", "1.0.0"),
            ("1.0.0", "1.0.0+git1"),
            ("1.0.0+b1", "1.0.0"),
            ("1.0.0", "1.0.0+b1"),
            ("1:1.0", "2.0"),
            ("2.0", "1:1.0"),
            ("1.0-1", "1.0-2"),
            ("1.0-2", "1.0-1"),
            ("1.0~beta1~svn1245", "1.0~beta1"),
            ("1.0~beta1", "1.0~beta1~svn1245"),
            ("1.0a", "1.0+a"),
            ("1.0+a", "1.0a"),
            ("1.0.0+deb11u1", "1.0.0+deb11u2"),
            ("1.2.3-1ubuntu1", "1.2.3-2ubuntu1"),
            ("0.4.17", "0.4.18.2805"),
            ("0.4.18.2805", "0.4.18.2805"),
            ("2:1.0.0", "2:1.0.0"),
            ("1.0.0-1", "1.0.0-1"),
            ("1.0~rc1", "1.0~rc2"),
            ("1.0+debug", "1.0"),
            ("1.0-0", "1.0"),
            ("1.0", "1.0-0"),
        ];

        let run_dpkg = |v1: &str, v2: &str| -> std::cmp::Ordering {
            let eq = std::process::Command::new("dpkg")
                .args(["--compare-versions", v1, "eq", v2])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if eq {
                return std::cmp::Ordering::Equal;
            }
            let lt = std::process::Command::new("dpkg")
                .args(["--compare-versions", v1, "lt", v2])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if lt {
                return std::cmp::Ordering::Less;
            }
            std::cmp::Ordering::Greater
        };

        for (v1, v2) in pairs {
            let expected = run_dpkg(v1, v2);
            let actual = compare_debian_versions_str(v1, v2);
            assert_eq!(
                actual, expected,
                "Debian comparison mismatch for '{v1}' vs '{v2}': actual={actual:?}, expected(dpkg)={expected:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_readarr_failed_installed_probe_preserves_error_and_rejects_admission() {
        use crate::inventory_regressions::{isolated, Fixture};
        if !isolated("workers::tests::test_readarr_failed_installed_probe_preserves_error_and_rejects_admission") {
            return;
        }
        let _fixture = Fixture::new();
        af_db::init_db().unwrap();
        ensure_app_updates_columns();

        // Seed previous DB record with installed_version = "0.4.17.0"
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT INTO app_updates (package_name, installed_version, latest_version, update_available, update_url, checked_at, last_error, source_key)
                 VALUES ('readarr', '0.4.17.0', '0.4.18.2805', 1, '', '2026-11-01T00:00:00Z', '', 'retired:readarr|stable')",
                [],
            ).unwrap();
        }

        let client = build_github_http_client();
        let pkg = Package {
            name: "readarr".into(),
            update_source: "retired".into(),
            // A version_command that fails:
            version_command: vec!["/bin/false".into()],
            ..Default::default()
        };

        let (rec, _notify) = probe_package_update(&client, "https://api.github.com", &pkg).await;

        // Verify last_error / error preserves the installed version check failure
        assert!(
            rec.error.to_ascii_lowercase().contains("installed version check failed")
                || rec.error.to_ascii_lowercase().contains("installed version could not be confirmed"),
            "Expected installed check failure in error, got: {}",
            rec.error
        );

        // Crucial requirement: update_available MUST BE FALSE when installed probe fails!
        assert!(!rec.update_available, "Failed installed probe must NOT allow update_available = true!");

        // Also check DB persisted state:
        let conn = af_db::get_conn().unwrap();
        let (db_avail, db_err): (bool, Option<String>) = conn.query_row(
            "SELECT update_available, last_error FROM app_updates WHERE package_name = 'readarr'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        assert!(!db_avail);
        assert!(
            db_err.unwrap_or_default().to_ascii_lowercase().contains("installed version check failed"),
            "Database last_error must preserve failure"
        );
    }

    #[test]
    fn test_rclone_declarative_discovery_uses_github_source_and_preserves_build_metadata() {
        let pkg = Package {
            name: "rclone".into(),
            update_source: "github".into(),
            update_repo: "rclone/rclone".into(),
            version_command: vec!["rclone".into(), "--version".into()],
            ..Default::default()
        };

        // 1. canonical_update_source_key with DeclarativeRust engine must NOT map to APT
        let (eff_src, _) = effective_update_source_and_apt_package(&pkg);
        assert_eq!(eff_src, "github");

        let key = canonical_update_source_key("https://api.github.com", &pkg);
        assert_eq!(key, "github:https://api.github.com|rclone/rclone|stable");
        assert!(!key.contains("apt:"));

        // 2. extract_version preserves +debug, +git1-1, etc.
        assert_eq!(extract_version("rclone v1.75.2", ""), "1.75.2");
        assert_eq!(extract_version("v1.0.0+debug", ""), "1.0.0+debug");
        assert_eq!(extract_version("release-v1.0.0+git1-1", ""), "1.0.0+git1-1");
        assert_eq!(extract_version("1.0.0+b1", ""), "1.0.0+b1");

        // 3. Exact source key requirement rejects keys missing |<channel>
        let legacy_key = "github:https://api.github.com|rclone/rclone";
        let prev_record = PackageUpdateRecord {
            package_id: "rclone".to_string(),
            installed: true,
            installed_version: "1.74.0".to_string(),
            latest_version: "1.75.2".to_string(),
            update_available: true,
            checked_at: "2026-11-01T00:00:00Z".to_string(),
            release_url: "".to_string(),
            error: "".to_string(),
            source_key: legacy_key.to_string(),
        };

        let rec = build_package_update_record_for_source(
            "https://api.github.com",
            "github",
            "rclone/rclone",
            true,
            Ok("1.74.0".to_string()),
            Err(anyhow::anyhow!("network unreachable")),
            Some(&prev_record),
            "2026-11-08T00:00:00Z".to_string(),
            &key,
        );
        // Because legacy_key is missing "|stable", exact equality fails and legacy record is rejected!
        assert_eq!(rec.latest_version, "");
        assert_eq!(rec.checked_at, "");
        assert!(!rec.update_available);
    }

    #[test]
    fn test_github_and_github_release_synonyms_and_source_key_normalization() {
        let pkg_github = Package {
            name: "rclone".into(),
            update_source: "github".into(),
            update_repo: "rclone/rclone".into(),
            update_channel: "stable".into(),
            version_command: vec!["rclone".into(), "--version".into()],
            ..Default::default()
        };
        let pkg_github_release = Package {
            name: "rclone".into(),
            update_source: "github_release".into(),
            update_repo: "rclone/rclone".into(),
            update_channel: "stable".into(),
            version_command: vec!["rclone".into(), "--version".into()],
            ..Default::default()
        };

        let key1 = canonical_update_source_key("https://api.github.com", &pkg_github);
        let key2 = canonical_update_source_key("https://api.github.com", &pkg_github_release);
        assert_eq!(key1, "github:https://api.github.com|rclone/rclone|stable");
        assert_eq!(key1, key2);

        let (src1, _) = effective_update_source_and_apt_package(&pkg_github);
        let (src2, _) = effective_update_source_and_apt_package(&pkg_github_release);
        assert_eq!(src1, "github");
        assert_eq!(src2, "github");

        assert!(should_track_package(&pkg_github));
        assert!(should_track_package(&pkg_github_release));
    }

    #[test]
    fn test_recompute_update_available_from_fresh_installed_observation_on_upstream_failure() {
        let prev = PackageUpdateRecord {
            package_id: "testpkg".to_string(),
            installed: true,
            installed_version: "1.0.0".to_string(),
            latest_version: "2.0.0".to_string(),
            update_available: true,
            checked_at: "2026-11-01T00:00:00Z".to_string(),
            release_url: "https://github.com/example/testpkg/releases/tag/v2.0.0".to_string(),
            error: String::new(),
            source_key: "github:https://api.github.com|example/testpkg|stable".to_string(),
        };

        let key = "github:https://api.github.com|example/testpkg|stable";

        // Case a: Package upgraded to 2.0.0; upstream fails -> latest_version retained as 2.0.0, update_available recomputed to false!
        let rec_upgraded = build_package_update_record_for_source(
            "https://api.github.com",
            "github",
            "testpkg",
            true,
            Ok("2.0.0".to_string()),
            Err(anyhow::anyhow!("network unreachable")),
            Some(&prev),
            "2026-11-08T12:00:00Z".to_string(),
            key,
        );
        assert_eq!(rec_upgraded.latest_version, "2.0.0");
        assert_eq!(rec_upgraded.installed_version, "2.0.0");
        assert!(!rec_upgraded.update_available);
        assert_eq!(rec_upgraded.checked_at, "2026-11-01T00:00:00Z");

        // Case b: Package at 1.5.0; upstream fails -> latest_version retained as 2.0.0, update_available recomputed to true!
        let rec_intermediate = build_package_update_record_for_source(
            "https://api.github.com",
            "github",
            "testpkg",
            true,
            Ok("1.5.0".to_string()),
            Err(anyhow::anyhow!("network unreachable")),
            Some(&prev),
            "2026-11-08T12:00:00Z".to_string(),
            key,
        );
        assert_eq!(rec_intermediate.latest_version, "2.0.0");
        assert_eq!(rec_intermediate.installed_version, "1.5.0");
        assert!(rec_intermediate.update_available);
        assert_eq!(rec_intermediate.checked_at, "2026-11-01T00:00:00Z");
    }

    #[test]
    fn test_explicit_trusted_origin_policy_for_custom_github_enterprise() {
        // 1. Configured GHE origin matches request URL
        assert!(should_attach_github_token(
            "https://ghe.internal.example/api/v3/repos/rclone/rclone/releases/latest",
            "https://ghe.internal.example/api/v3"
        ));

        // 2. Reject untrusted third-party registries even if configured as base
        assert!(!should_attach_github_token(
            "https://pypi.org/pypi/foo/json",
            "https://ghe.internal.example/api/v3"
        ));
        assert!(!should_attach_github_token(
            "https://pypi.org/pypi/foo/json",
            "https://pypi.org"
        ));
        assert!(!should_attach_github_token(
            "https://crates.io/api/v1/crates/foo",
            "https://crates.io"
        ));

        // 3. Reject plain http:// on non-loopback hosts
        assert!(!should_attach_github_token(
            "http://ghe.internal.example/api/v3/repos/a/b",
            "http://ghe.internal.example/api/v3"
        ));

        // 4. Loopback http is permitted
        assert!(should_attach_github_token(
            "http://127.0.0.1:8080/api/v3/repos/a/b",
            "http://127.0.0.1:8080"
        ));
        assert!(should_attach_github_token(
            "http://localhost:9090/repos/a/b",
            "http://localhost:9090"
        ));

        // 5. AF_TRUSTED_GITHUB_ORIGINS environment variable
        std::env::set_var("AF_TRUSTED_GITHUB_ORIGINS", "https://extra-ghe.corp.local, https://custom.github.net");
        assert!(should_attach_github_token(
            "https://extra-ghe.corp.local/api/v3/repos/a/b",
            "https://api.github.com"
        ));
        assert!(should_attach_github_token(
            "https://custom.github.net/repos/a/b",
            "https://api.github.com"
        ));
        assert!(!should_attach_github_token(
            "https://untrusted.corp.local/api/v3/repos/a/b",
            "https://api.github.com"
        ));
        std::env::remove_var("AF_TRUSTED_GITHUB_ORIGINS");
    }

    #[test]
    fn test_exact_default_https_port_for_builtin_github_origins() {
        assert_eq!(
            should_attach_github_token("https://api.github.com:8443/repos/a/b", "https://api.github.com"),
            false
        );
        assert_eq!(
            should_attach_github_token("https://api.github.com:443/repos/a/b", "https://api.github.com"),
            true
        );
        assert_eq!(
            should_attach_github_token("https://api.github.com:8443/repos/a/b", "https://api.github.com:8443"),
            true
        );
    }

    #[test]
    fn test_do_not_collapse_consecutive_hyphens_in_build_metadata() {
        let v1 = extract_version("1.0.0+build--old", "");
        let v2 = extract_version("1.0.0+build--new", "");
        assert_eq!(v1, "1.0.0+build--old");
        assert_eq!(v2, "1.0.0+build--new");
        assert_ne!(v1, v2);
        assert_eq!(extract_version_from_text("1.0.0+build--old"), "1.0.0+build--old");
        assert_eq!(extract_version_from_text("1.0.0+build--new"), "1.0.0+build--new");
        assert!(!af_release::lifecycle::versions_match_target("1.0.0+build--old", "1.0.0+build--new"));
        assert!(!versions_match_target_internal("1.0.0+build--old", "1.0.0+build--new"));
    }

    #[tokio::test]
    async fn test_probe_installed_package_version_strict_requires_independent_runtime_evidence() {
        let _env_guard = TEST_ENV_MUTEX.lock().await;
        let temp_dir = std::env::temp_dir().join(format!("af-test-isolated-receipt-{}", uuid::Uuid::new_v4()));
        let opt_dir = temp_dir.join("opt/isolated-pkg");
        std::fs::create_dir_all(&opt_dir).unwrap();
        // Only .af-version exists in isolation, no lock file, no binaries, no systemd units
        std::fs::write(opt_dir.join(".af-version"), "1.0.0").unwrap();

        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let pkg = Package {
            name: "isolated-pkg".into(),
            // Empty version_command means no live command probe
            version_command: vec![],
            ..Default::default()
        };

        let res = probe_installed_package_version_strict(&pkg).await;
        assert!(res.is_err(), "Expected probe_installed_package_version_strict to fail without runtime evidence");
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("No independent runtime evidence found alongside .af-version receipt"),
            "Expected 'No independent runtime evidence found alongside .af-version receipt', got: {err_msg}"
        );

        std::env::remove_var("AETHERFLOW_FS_ROOT");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_extract_version_preserves_trailing_hyphens_in_build_metadata() {
        assert_eq!(extract_version("1.0.0+build-", ""), "1.0.0+build-");
        assert_eq!(extract_version("1.0.0+build--", ""), "1.0.0+build--");
        assert_eq!(extract_version("1.0.0-rc1-", ""), "1.0.0-rc1-");
        assert_eq!(extract_version_from_text("1.0.0+build-"), "1.0.0+build-");
        assert_eq!(extract_version_from_text("1.0.0+build--"), "1.0.0+build--");
        assert!(!af_release::lifecycle::versions_match_target("1.0.0+build-", "1.0.0+build--"));
    }

    #[tokio::test]
    async fn test_github_release_discovery_rejects_prerelease_on_stable_channel() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 2048];
            let _ = socket.read(&mut buf).await.unwrap();
            // Upstream GitHub returns a release marked with tag "v2.0.0-rc1"
            let body = r#"{"tag_name":"v2.0.0-rc1","html_url":"http://mock/release/v2.0.0-rc1","prerelease":false}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(resp.as_bytes()).await.unwrap();
        });

        let client = build_github_http_client();
        let origin = format!("http://{addr}");
        let repo = "owner/prerelease-repo";

        // 1. Stable channel discovery must reject "v2.0.0-rc1"
        let res = detect_latest_github_release_for_channel(&client, &origin, repo, "stable").await;
        assert!(res.is_err(), "Stable channel must reject prerelease tag: {:?}", res);
        server.await.unwrap();

        // 2. Must NOT store under "stable" cache
        let stable_key = github_release_cache_key_for_channel(&origin, repo, "stable");
        let cached = github_release_cache().get(&stable_key).cloned();
        assert!(cached.is_none(), "Stable cache must not contain rejected prerelease: {:?}", cached);

        // 3. Stale cache fallback for stable channel must return None even if prerelease is in cache
        {
            let mut cache = github_release_cache();
            cache.insert(
                stable_key.clone(),
                ("2.0.0-rc1".to_string(), "http://mock/url".to_string(), Instant::now() - Duration::from_secs(3600), "2026-11-08T00:00:00Z".to_string()),
            );
        }
        assert_eq!(get_cached_github_release_stale_for_channel(&origin, repo, "stable"), None);

        // 4. Fresh cache lookup via detect_latest_github_release_for_channel must also reject cached 2.0.0-rc1
        let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let origin2 = format!("http://{addr2}");
        let stable_key2 = github_release_cache_key_for_channel(&origin2, repo, "stable");
        {
            let mut cache = github_release_cache();
            cache.insert(
                stable_key2.clone(),
                ("2.0.0-rc1".to_string(), "http://mock/url".to_string(), Instant::now(), "2026-11-08T00:00:00Z".to_string()),
            );
        }
        let res_cached = detect_latest_github_release_for_channel(&client, &origin2, repo, "stable").await;
        assert!(res_cached.is_err());
    }

    #[tokio::test]
    async fn test_mixed_case_stable_rejects_prerelease_and_does_not_pollute_cache() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0; 2048];
                let _ = socket.read(&mut buf).await.unwrap();
                let body = r#"{"tag_name":"v1.2.3","html_url":"http://mock/release/v1.2.3","prerelease":true}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(resp.as_bytes()).await.unwrap();
            }
        });

        let client = build_github_http_client();
        let origin = format!("http://{addr}");
        let repo = "owner/mixedcase-stable-repo";

        let res_mixed = detect_latest_github_release_for_channel(&client, &origin, repo, "Stable").await;
        assert!(res_mixed.is_err(), "Stable channel (mixed-case) must reject prerelease:true: {:?}", res_mixed);

        let res_upper = detect_latest_github_release_for_channel(&client, &origin, repo, "STABLE").await;
        assert!(res_upper.is_err(), "STABLE channel (upper-case) must reject prerelease:true: {:?}", res_upper);

        server.await.unwrap();

        let stable_key = github_release_cache_key_for_channel(&origin, repo, "stable");
        let cached = github_release_cache().get(&stable_key).cloned();
        assert!(cached.is_none(), "Stable cache must not contain rejected prerelease: {:?}", cached);
    }

    #[test]
    fn test_extract_version_preserves_hyphen_only_identifiers() {
        assert_eq!(extract_version("1.0.0--", ""), "1.0.0--");
        assert_eq!(extract_version("1.0.0+--", ""), "1.0.0+--");
        assert_eq!(extract_version("1.0.0+-", ""), "1.0.0+-");
        assert_eq!(extract_version("1.0.0+build-", ""), "1.0.0+build-");
        assert_eq!(extract_version("1.0.0+build--", ""), "1.0.0+build--");
        assert_eq!(extract_version("1.0.0-rc1-", ""), "1.0.0-rc1-");

        assert_eq!(extract_version("1.0.0-", ""), "1.0.0");
        assert_eq!(extract_version("1.0.0+", ""), "1.0.0");
    }

    #[tokio::test]
    async fn test_runtime_evidence_rejects_non_runtime_and_receipt_rejects_symlink_fifo() {
        let _env_guard = TEST_ENV_MUTEX.lock().await;
        let temp_dir = std::env::temp_dir().join(format!("af-test-runtime-evidence-{}", uuid::Uuid::new_v4()));
        let opt_dir = temp_dir.join("opt/evidence-pkg");
        std::fs::create_dir_all(&opt_dir).unwrap();

        let version_file = opt_dir.join(".af-version");
        std::fs::write(&version_file, "1.2.3").unwrap();
        std::fs::write(opt_dir.join("install.log"), "Installation finished").unwrap();
        std::fs::write(opt_dir.join("anything.lock"), "lock data").unwrap();

        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let pkg = Package {
            name: "evidence-pkg".into(),
            version_command: vec![],
            ..Default::default()
        };

        let res = probe_installed_package_version_strict(&pkg).await;
        assert!(res.is_err(), "Expected failure without executable runtime files");
        assert!(
            res.unwrap_err().to_string().contains("No independent runtime evidence found"),
            "Should reject non-runtime files as evidence"
        );

        use std::os::unix::fs::PermissionsExt;
        let non_exec_bin = opt_dir.join("non_exec_binary");
        std::fs::write(&non_exec_bin, "#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(&non_exec_bin, std::fs::Permissions::from_mode(0o644)).unwrap();

        let res2 = probe_installed_package_version_strict(&pkg).await;
        assert!(res2.is_err(), "Expected failure when binary is not executable (0o644)");

        let symlink_receipt = opt_dir.join("symlink_receipt");
        std::os::unix::fs::symlink(&version_file, &symlink_receipt).unwrap();
        let sym_res = read_receipt_bounded_nofollow(&symlink_receipt);
        assert!(sym_res.is_err(), "read_receipt_bounded_nofollow must reject symlinks: {:?}", sym_res);

        let fifo_receipt = opt_dir.join("fifo_receipt");
        let c_fifo = std::ffi::CString::new(fifo_receipt.to_str().unwrap()).unwrap();
        let mkfifo_ret = unsafe { af_release::lifecycle::libc::mkfifo(c_fifo.as_ptr(), 0o644) };
        assert_eq!(mkfifo_ret, 0, "mkfifo failed");
        let fifo_res = read_receipt_bounded_nofollow(&fifo_receipt);
        assert!(fifo_res.is_err(), "read_receipt_bounded_nofollow must reject FIFOs: {:?}", fifo_res);

        std::env::remove_var("AETHERFLOW_FS_ROOT");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_stale_or_empty_service_unit_file_rejected_as_runtime_evidence() {
        let _env_guard = TEST_ENV_MUTEX.lock().await;
        let temp_dir = std::env::temp_dir().join(format!("af-test-stale-unit-{}", uuid::Uuid::new_v4()));
        let opt_dir = temp_dir.join("opt/stale-service-pkg");
        let systemd_dir = temp_dir.join("etc/systemd/system");
        std::fs::create_dir_all(&opt_dir).unwrap();
        std::fs::create_dir_all(&systemd_dir).unwrap();

        let version_file = opt_dir.join(".af-version");
        std::fs::write(&version_file, "1.2.3").unwrap();

        let service_file = systemd_dir.join("stale-service-pkg.service");

        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let pkg = Package {
            name: "stale-service-pkg".into(),
            lock_file: "/opt/stale-service-pkg/.af-version".into(),
            version_command: vec![],
            ..Default::default()
        };

        // 1. Empty .service file must be rejected
        std::fs::write(&service_file, "").unwrap();
        let res_empty = probe_installed_package_version_strict(&pkg).await;
        assert!(
            res_empty.is_err(),
            "Empty .service file must NOT certify runtime"
        );
        let err_msg = res_empty.unwrap_err().to_string();
        assert!(
            err_msg.contains("No independent runtime evidence found"),
            "Expected 'No independent runtime evidence found', got: {err_msg}"
        );

        // 2. .service file with no ExecStart= must be rejected
        std::fs::write(
            &service_file,
            "[Unit]\nDescription=Stale Service\n[Service]\nRestart=always\n",
        )
        .unwrap();
        let res_no_exec = probe_installed_package_version_strict(&pkg).await;
        assert!(
            res_no_exec.is_err(),
            ".service with no ExecStart= must NOT certify runtime"
        );

        // 3. .service file with ExecStart= pointing to nonexistent binary must be rejected
        std::fs::write(
            &service_file,
            "[Unit]\nDescription=Stale Service\n[Service]\nExecStart=/usr/local/bin/nonexistent_bin_xyz --flag\n",
        )
        .unwrap();
        let res_nonexistent = probe_installed_package_version_strict(&pkg).await;
        assert!(
            res_nonexistent.is_err(),
            ".service with nonexistent binary must NOT certify runtime"
        );

        // 4. .service file with ExecStart= pointing to a non-executable file (0o644) must be rejected
        use std::os::unix::fs::PermissionsExt;
        let non_exec_script = opt_dir.join("daemon.sh");
        std::fs::write(&non_exec_script, "#!/bin/sh\necho running\n").unwrap();
        std::fs::set_permissions(&non_exec_script, std::fs::Permissions::from_mode(0o644)).unwrap();

        std::fs::write(
            &service_file,
            "[Unit]\nDescription=Stale Service\n[Service]\nExecStart=-/opt/stale-service-pkg/daemon.sh\n",
        )
        .unwrap();
        let res_non_exec = probe_installed_package_version_strict(&pkg).await;
        assert!(
            res_non_exec.is_err(),
            ".service with non-executable binary must NOT certify runtime"
        );

        // 5. Positive control: when binary becomes executable (0o755), runtime evidence is certified
        std::fs::set_permissions(&non_exec_script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let res_valid = probe_installed_package_version_strict(&pkg).await;
        assert!(
            res_valid.is_ok(),
            "Valid executable in ExecStart= should satisfy runtime evidence: {:?}",
            res_valid.err()
        );
        assert_eq!(res_valid.unwrap(), "1.2.3");

        std::env::remove_var("AETHERFLOW_FS_ROOT");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_github_release_discovery_for_prerelease_and_stable_channels() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    let (status, body) = if req.contains("/releases/latest") {
                        (
                            "200 OK",
                            r#"{"tag_name":"v1.9.0","html_url":"http://mock/release/v1.9.0","prerelease":false,"draft":false}"#.to_string(),
                        )
                    } else if req.contains("/releases?per_page=30") {
                        (
                            "200 OK",
                            r#"[
                                {"tag_name":"v3.0.0-draft","html_url":"http://mock/release/v3.0.0-draft","prerelease":true,"draft":true},
                                {"tag_name":"v2.0.0-beta.1","html_url":"http://mock/release/v2.0.0-beta.1","prerelease":true,"draft":false},
                                {"tag_name":"v1.9.0","html_url":"http://mock/release/v1.9.0","prerelease":false,"draft":false}
                            ]"#.to_string(),
                        )
                    } else {
                        ("404 Not Found", r#"{"message":"Not Found"}"#.to_string())
                    };

                    let resp = format!(
                        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                });
            }
        });

        let client = build_github_http_client();
        let origin = format!("http://{addr}");
        let repo = "owner/prerelease-discovery-repo";

        // 1. Beta channel queries /releases?per_page=30, skips draft v3.0.0-draft, discovers v2.0.0-beta.1 over v1.9.0
        let res_beta = detect_latest_github_release_for_channel(&client, &origin, repo, "beta").await;
        assert!(res_beta.is_ok(), "Beta channel discovery failed: {:?}", res_beta.err());
        let (ver_beta, url_beta, _) = res_beta.unwrap();
        assert_eq!(ver_beta, "2.0.0-beta.1");
        assert_eq!(url_beta, "http://mock/release/v2.0.0-beta.1");

        // 2. Nightly channel queries /releases?per_page=30, skips draft, discovers v2.0.0-beta.1 over v1.9.0
        let repo_nightly = "owner/prerelease-discovery-nightly";
        let res_nightly = detect_latest_github_release_for_channel(&client, &origin, repo_nightly, "nightly").await;
        assert!(res_nightly.is_ok(), "Nightly channel discovery failed: {:?}", res_nightly.err());
        let (ver_nightly, url_nightly, _) = res_nightly.unwrap();
        assert_eq!(ver_nightly, "2.0.0-beta.1");
        assert_eq!(url_nightly, "http://mock/release/v2.0.0-beta.1");

        // 3. Stable channel queries /releases/latest and selects v1.9.0
        let repo_stable = "owner/prerelease-discovery-stable";
        let res_stable = detect_latest_github_release_for_channel(&client, &origin, repo_stable, "stable").await;
        assert!(res_stable.is_ok(), "Stable channel discovery failed: {:?}", res_stable.err());
        let (ver_stable, url_stable, _) = res_stable.unwrap();
        assert_eq!(ver_stable, "1.9.0");
        assert_eq!(url_stable, "http://mock/release/v1.9.0");

        server.abort();
    }

    #[tokio::test]
    async fn test_git_head_cache_isolation_by_remote_url() {
        let repo = "org/app";
        let remote_a = "https://git.provider-a.com/org/app.git";
        let remote_b = "https://git.provider-b.com/org/app.git";

        let key_a = git_head_cache_key(remote_a, repo);
        let key_b = git_head_cache_key(remote_b, repo);
        assert_ne!(key_a, key_b, "Cache keys must be isolated across different remote URLs");

        let sha_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let sha_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let now = Instant::now();
        let ts = "2026-11-09T00:00:00Z".to_string();

        {
            let mut cache = GIT_REMOTE_HEAD_CACHE.lock().unwrap();
            cache.insert(key_a.clone(), (sha_a.to_string(), "http://remote-a/commit".to_string(), now, ts.clone()));
            cache.insert(key_b.clone(), (sha_b.to_string(), "http://remote-b/commit".to_string(), now, ts.clone()));
        }

        let cached_a = GIT_REMOTE_HEAD_CACHE.lock().unwrap().get(&key_a).cloned();
        let cached_b = GIT_REMOTE_HEAD_CACHE.lock().unwrap().get(&key_b).cloned();

        assert_eq!(cached_a.unwrap().0, sha_a);
        assert_eq!(cached_b.unwrap().0, sha_b);
    }

    #[test]
    fn test_tag_allowed_by_channel_preserves_debian_revisions_and_rejects_prereleases() {
        // Stable channel must allow valid Debian package revisions:
        assert!(tag_allowed_by_channel("1:1.2.3-1+b1", "stable"));
        assert!(tag_allowed_by_channel("2.4.5-1ubuntu1", "stable"));
        assert!(tag_allowed_by_channel("1.0.0-1deb12u1", "stable"));
        assert!(tag_allowed_by_channel("1.2.3-1", "stable"));
        assert!(tag_allowed_by_channel("0ubuntu0.22.04.1", "stable"));

        // Stable channel must reject true prereleases:
        assert!(!tag_allowed_by_channel("1.2.3-rc1", "stable"));
        assert!(!tag_allowed_by_channel("1.2.3-beta.1", "stable"));
        assert!(!tag_allowed_by_channel("1.0.0-alpha", "stable"));
        assert!(!tag_allowed_by_channel("1.0.0-nightly.20261109", "stable"));
        assert!(!tag_allowed_by_channel("1.0.0-0.1", "stable"));
        assert!(!tag_allowed_by_channel("1.0.0--", "stable"));

        // Retained APT target preservation on discovery failure:
        let prev_record = PackageUpdateRecord {
            package_id: "deb-pkg".to_string(),
            installed: true,
            installed_version: "1:1.2.3-1".to_string(),
            latest_version: "1:1.2.3-1+b1".to_string(),
            update_available: true,
            checked_at: "2026-11-01T00:00:00Z".to_string(),
            release_url: "".to_string(),
            error: "".to_string(),
            source_key: "apt:deb-pkg|stable".to_string(),
        };

        let rec = build_package_update_record_for_source(
            "",
            "apt",
            "deb-pkg",
            true,
            Ok("1:1.2.3-1".to_string()),
            Err(anyhow::anyhow!("apt repository timeout")),
            Some(&prev_record),
            "2026-11-09T00:00:00Z".to_string(),
            "apt:deb-pkg|stable",
        );

        // Retained target must NOT be cleared because "1:1.2.3-1+b1" is a valid stable revision!
        assert_eq!(rec.latest_version, "1:1.2.3-1+b1");
        assert!(rec.update_available);
        assert_eq!(rec.checked_at, "2026-11-01T00:00:00Z");

        // And check for ubuntu and debian suffixes:
        for deb_ver in ["2.4.5-1ubuntu1", "1.0.0-1deb12u1"] {
            let prev = PackageUpdateRecord {
                package_id: "deb-pkg2".to_string(),
                installed: true,
                installed_version: "1.0.0".to_string(),
                latest_version: deb_ver.to_string(),
                update_available: true,
                checked_at: "2026-11-01T00:00:00Z".to_string(),
                release_url: "".to_string(),
                error: "".to_string(),
                source_key: "apt:deb-pkg2|stable".to_string(),
            };
            let r = build_package_update_record_for_source(
                "",
                "apt",
                "deb-pkg2",
                true,
                Ok("1.0.0".to_string()),
                Err(anyhow::anyhow!("apt repository timeout")),
                Some(&prev),
                "2026-11-09T00:00:00Z".to_string(),
                "apt:deb-pkg2|stable",
            );
            assert_eq!(r.latest_version, deb_ver);
            assert!(r.update_available);
        }
    }

    #[tokio::test]
    async fn test_systemd_unit_validation_execstart_reset_and_missing_script() {
        let _env_guard = TEST_ENV_MUTEX.lock().await;
        let temp_dir = std::env::temp_dir().join(format!("af-test-systemd-reset-{}", uuid::Uuid::new_v4()));
        let opt_dir = temp_dir.join("opt/test-svc");
        let systemd_dir = temp_dir.join("etc/systemd/system");
        std::fs::create_dir_all(&opt_dir).unwrap();
        std::fs::create_dir_all(&systemd_dir).unwrap();

        std::fs::write(opt_dir.join(".af-version"), "1.0.0").unwrap();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let pkg = Package {
            name: "test-svc".into(),
            lock_file: "/opt/test-svc/.af-version".into(),
            version_command: vec![],
            ..Default::default()
        };

        let service_file = systemd_dir.join("test-svc.service");

        // 1. ExecStart=/bin/true followed by empty ExecStart= reset line must be REJECTED!
        std::fs::write(
            &service_file,
            "[Unit]\nDescription=Test Service\n[Service]\nExecStart=/bin/true\nExecStart=\n",
        )
        .unwrap();
        let res_reset = probe_installed_package_version_strict(&pkg).await;
        assert!(
            res_reset.is_err(),
            "Unit file with ExecStart=/bin/true followed by ExecStart= reset MUST be rejected!"
        );

        // 2. ExecStart=/bin/sh /nonexistent/script.sh must be REJECTED because referenced script does not exist!
        std::fs::write(
            &service_file,
            "[Unit]\nDescription=Test Service\n[Service]\nExecStart=/bin/sh /nonexistent/script.sh\n",
        )
        .unwrap();
        let res_missing_script = probe_installed_package_version_strict(&pkg).await;
        assert!(
            res_missing_script.is_err(),
            "Unit file with interpreter pointing to missing script MUST be rejected!"
        );

        std::env::remove_var("AETHERFLOW_FS_ROOT");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_detect_latest_github_release_prerelease_channel_selects_highest_version() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };
                let mut buf = vec![0; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&buf[..n]);
                let body = if req_str.contains("repo-pre-beta") {
                    r#"[
                        {"tag_name": "v1.9.0-beta", "html_url": "https://github.com/mock/repo/releases/v1.9.0-beta", "prerelease": true},
                        {"tag_name": "v2.0.0-beta.1", "html_url": "https://github.com/mock/repo/releases/v2.0.0-beta.1", "prerelease": true}
                    ]"#
                } else {
                    r#"[
                        {"tag_name": "v1.9.0-beta", "html_url": "https://github.com/mock/repo/releases/v1.9.0-beta", "prerelease": true},
                        {"tag_name": "v2.0.0", "html_url": "https://github.com/mock/repo/releases/v2.0.0", "prerelease": false}
                    ]"#
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let client = build_github_http_client();
        let origin = format!("http://{addr}");

        // 1. Channel "prerelease" with v1.9.0-beta and v2.0.0
        let res_pre = detect_latest_github_release_for_channel(&client, &origin, "test-owner/repo-pre", "prerelease").await.unwrap();
        assert_eq!(res_pre.0, "2.0.0", "prerelease channel must select higher version 2.0.0 over 1.9.0-beta");
        assert_ne!(res_pre.0, "1.9.0-beta");

        // 2. Channel "beta" with v1.9.0-beta and v2.0.0
        let res_beta = detect_latest_github_release_for_channel(&client, &origin, "test-owner/repo-beta", "beta").await.unwrap();
        assert_eq!(res_beta.0, "2.0.0", "beta channel must select higher version 2.0.0 over 1.9.0-beta");
        assert_ne!(res_beta.0, "1.9.0-beta");

        // 3. Channel "all" with v1.9.0-beta and v2.0.0
        let res_all = detect_latest_github_release_for_channel(&client, &origin, "test-owner/repo-all", "all").await.unwrap();
        assert_eq!(res_all.0, "2.0.0", "all channel must select higher version 2.0.0 over 1.9.0-beta");
        assert_ne!(res_all.0, "1.9.0-beta");

        // 4. Channel "prerelease" with v1.9.0-beta and v2.0.0-beta.1
        let res_pre_beta = detect_latest_github_release_for_channel(&client, &origin, "test-owner/repo-pre-beta", "prerelease").await.unwrap();
        assert_eq!(res_pre_beta.0, "2.0.0-beta.1", "prerelease channel must select higher version 2.0.0-beta.1 over 1.9.0-beta");

        server.abort();
    }

    #[test]
    fn test_git_remotes_case_sensitivity_and_normalization() {
        let url1 = "https://Git.Example.com/team/App.git";
        let url2 = "https://git.example.com/team/app.git";
        let url3 = "HTTPS://GIT.EXAMPLE.COM:443/team/App.git";
        let url4 = "https://git.example.com/team/App.git";

        // git_head_cache_key:
        let key1 = git_head_cache_key(url1, "team/App");
        let key2 = git_head_cache_key(url2, "team/app");
        let key3 = git_head_cache_key(url3, "team/App");
        let key4 = git_head_cache_key(url4, "team/App");

        assert_ne!(key1, key2, "team/App.git and team/app.git must produce distinct git_head_cache_key values");
        assert_eq!(key1, key3, "HTTPS://GIT.EXAMPLE.COM:443/team/App.git and https://Git.Example.com/team/App.git must normalize to same key");
        assert_eq!(key1, key4);

        // canonical_update_source_key:
        let pkg1 = Package {
            name: "app".into(),
            update_source: "git".into(),
            update_repo: "team/App".into(),
            update_repo_url: url1.into(),
            ..Default::default()
        };
        let pkg2 = Package {
            name: "app".into(),
            update_source: "git".into(),
            update_repo: "team/app".into(),
            update_repo_url: url2.into(),
            ..Default::default()
        };
        let pkg3 = Package {
            name: "app".into(),
            update_source: "git".into(),
            update_repo: "team/App".into(),
            update_repo_url: url3.into(),
            ..Default::default()
        };
        let pkg4 = Package {
            name: "app".into(),
            update_source: "git".into(),
            update_repo: "team/App".into(),
            update_repo_url: url4.into(),
            ..Default::default()
        };

        let ckey1 = canonical_update_source_key("", &pkg1);
        let ckey2 = canonical_update_source_key("", &pkg2);
        let ckey3 = canonical_update_source_key("", &pkg3);
        let ckey4 = canonical_update_source_key("", &pkg4);

        assert_ne!(ckey1, ckey2, "canonical_update_source_key must preserve path case and distinguish App vs app");
        assert_eq!(ckey1, ckey3, "canonical_update_source_key must normalize authority and default port :443");
        assert_eq!(ckey1, ckey4);
    }

    #[test]
    fn test_channel_source_debian_revisions_and_semver_rejection() {
        // 1. Rejected on stable in both tag_allowed_by_channel and is_prerelease_version_for_channel
        assert!(is_prerelease_version_for_channel("1.2.3-foo-1"));
        assert!(is_prerelease_version_for_channel("1.2.3-1.2"));
        assert!(!tag_allowed_by_channel("1.2.3-foo-1", "stable"));
        assert!(!tag_allowed_by_channel("1.2.3-1.2", "stable"));

        // Source-aware for github and git:
        assert!(!tag_allowed_by_channel_for_source("1.2.3-foo-1", "stable", "github"));
        assert!(!tag_allowed_by_channel_for_source("1.2.3-1.2", "stable", "github"));
        assert!(!tag_allowed_by_channel_for_source("1.2.3-foo-1", "stable", "git"));
        assert!(!tag_allowed_by_channel_for_source("1.2.3-1.2", "stable", "git"));

        // 2. Allowed on stable for APT / retained targets
        assert!(!is_prerelease_version_for_channel("1:1.2.3-1+b1"));
        assert!(!is_prerelease_version_for_channel("2.4.5-1ubuntu1"));
        assert!(!is_prerelease_version_for_channel("1.0.0-1deb12u1"));
        assert!(!is_prerelease_version_for_channel("1.2.3-1"));

        assert!(tag_allowed_by_channel_for_source("1:1.2.3-1+b1", "stable", "apt"));
        assert!(tag_allowed_by_channel_for_source("2.4.5-1ubuntu1", "stable", "apt"));
        assert!(tag_allowed_by_channel_for_source("1.0.0-1deb12u1", "stable", "apt"));
        assert!(tag_allowed_by_channel_for_source("1.2.3-1", "stable", "apt"));

        assert!(tag_allowed_by_channel("1:1.2.3-1+b1", "stable"));
        assert!(tag_allowed_by_channel("2.4.5-1ubuntu1", "stable"));
        assert!(tag_allowed_by_channel("1.0.0-1deb12u1", "stable"));
        assert!(tag_allowed_by_channel("1.2.3-1", "stable"));
    }

    #[test]
    fn test_systemd_unit_execstart_under_unit_rejected() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-systemd-unit-sec-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let service_file = temp_dir.join("test-invalid.service");
        std::fs::write(
            &service_file,
            "[Unit]\nDescription=Test Service\nExecStart=/bin/true\n[Service]\nTimeoutSec=30\n",
        ).unwrap();
        let pkg = Package {
            name: "test-invalid".into(),
            ..Default::default()
        };
        let is_valid = is_valid_systemd_service_unit(&service_file, &pkg);
        assert!(!is_valid, "systemd unit with ExecStart under [Unit] must be rejected by is_valid_systemd_service_unit");

        let bin_true = std::path::Path::new("/bin/true");
        if bin_true.exists() {
            let valid_file = temp_dir.join("test-valid.service");
            std::fs::write(
                &valid_file,
                "[Unit]\nDescription=Test Service\n[Service]\nExecStart=/bin/true\n",
            ).unwrap();
            let is_valid_ok = is_valid_systemd_service_unit(&valid_file, &pkg);
            assert!(is_valid_ok, "systemd unit with ExecStart under [Service] must be accepted");
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_git_remotes_credentials_and_ssh_user_case() {
        let u1 = "Deploy@Git.Example.com:Team/App.git";
        let u2 = "deploy@Git.Example.com:Team/App.git";

        let k1 = git_head_cache_key(u1, "team/App");
        let k2 = git_head_cache_key(u2, "team/App");
        assert_ne!(k1, k2, "Deploy@host and deploy@host must produce distinct git_head_cache_key values");

        let pkg1 = Package {
            name: "app".into(),
            update_source: "git".into(),
            update_repo: "team/App".into(),
            update_repo_url: u1.into(),
            ..Default::default()
        };
        let pkg2 = Package {
            name: "app".into(),
            update_source: "git".into(),
            update_repo: "team/App".into(),
            update_repo_url: u2.into(),
            ..Default::default()
        };
        let ck1 = canonical_update_source_key("", &pkg1);
        let ck2 = canonical_update_source_key("", &pkg2);
        assert_ne!(ck1, ck2, "Deploy@host and deploy@host must produce distinct canonical_update_source_key values");

        let cred_url = "https://admin:super_secret_token@git.example.com/team/App.git";
        let pkg_cred = Package {
            name: "app-cred".into(),
            update_source: "git".into(),
            update_repo: "team/App".into(),
            update_repo_url: cred_url.into(),
            ..Default::default()
        };
        let ckey_cred = canonical_update_source_key("", &pkg_cred);
        let head_key_cred = git_head_cache_key(cred_url, "team/App");
        let disp_url = sanitize_git_remote_url_for_display(cred_url);

        assert!(!ckey_cred.contains("super_secret_token"), "canonical key must not leak password");
        assert!(!ckey_cred.contains("admin:super_secret_token"));
        assert!(!head_key_cred.contains("super_secret_token"), "cache key must not leak password");
        assert!(!head_key_cred.contains("admin:super_secret_token"));
        assert!(!disp_url.contains("super_secret_token"), "display url must not leak password");
        assert!(!disp_url.contains("admin:super_secret_token"));
        assert_eq!(disp_url, "https://git.example.com/team/App.git");

        // Test persistence in SQLite
        let rec = PackageUpdateRecord {
            package_id: "test-cred-pkg".into(),
            release_url: cred_url.into(),
            error: "failed with secret: super_secret_token".into(),
            ..Default::default()
        };
        persist_package_update_record(&rec);
        if let Ok(conn) = af_db::get_conn() {
            let mut stmt = conn.prepare("SELECT update_url, last_error FROM app_updates WHERE package_name = ?1").unwrap();
            let mut rows = stmt.query(params!["test-cred-pkg"]).unwrap();
            if let Some(row) = rows.next().unwrap() {
                let saved_url: String = row.get(0).unwrap();
                let saved_err: String = row.get(1).unwrap();
                assert!(!saved_url.contains("super_secret_token"));
                assert!(!saved_url.contains("admin:super_secret_token"));
                assert!(!saved_err.contains("super_secret_token"));
            }
        }
    }

    #[test]
    fn test_systemd_unit_validation_case_sensitive_and_no_execstartpre() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-systemd-unit-pre-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let pkg = Package {
            name: "test-pre".into(),
            ..Default::default()
        };

        // 1. ExecStartPre only in [Service] -> invalid!
        let pre_only = temp_dir.join("pre-only.service");
        std::fs::write(
            &pre_only,
            "[Unit]\nDescription=Pre Only\n[Service]\nExecStartPre=/bin/true\n",
        ).unwrap();
        assert!(!is_valid_systemd_service_unit(&pre_only, &pkg), "ExecStartPre alone must not satisfy is_valid_systemd_service_unit");

        // 2. Lowercase execstart= in [Service] -> invalid!
        let lower_only = temp_dir.join("lower-only.service");
        std::fs::write(
            &lower_only,
            "[Unit]\nDescription=Lower Only\n[Service]\nexecstart=/bin/true\n",
        ).unwrap();
        assert!(!is_valid_systemd_service_unit(&lower_only, &pkg), "lowercase execstart= must not satisfy is_valid_systemd_service_unit");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_github_release_discovery_multi_page_pagination() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };
                let mut buf = vec![0; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&buf[..n]);

                let body: String = if req_str.contains("page=2") {
                    r#"[{"tag_name": "v2.1.0-beta.1", "html_url": "https://github.com/org/repo/releases/v2.1.0-beta.1", "prerelease": true, "draft": false}]"#.to_string()
                } else {
                    let mut items = Vec::new();
                    for i in 1..=30 {
                        items.push(format!(
                            r#"{{"tag_name": "v1.9.{}", "html_url": "https://github.com/org/repo/releases/v1.9.{}", "prerelease": false, "draft": false}}"#,
                            i, i
                        ));
                    }
                    format!("[{}]", items.join(","))
                };

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let client = build_github_http_client();
        let origin = format!("http://{addr}");

        let res = detect_latest_github_release_for_channel(&client, &origin, "test-owner/multi-page-repo", "prerelease").await.unwrap();
        assert_eq!(res.0, "2.1.0-beta.1", "Pagination must fetch page 2 and discover higher 2.1.0-beta.1 over page 1's v1.9.30");

        server.abort();
    }

    #[test]
    fn test_retained_git_tags_and_apt_dotted_revisions() {
        // Git tags: 1.2.3-1 is a SemVer prerelease, rejected on stable
        assert!(!tag_allowed_by_channel_for_source("1.2.3-1", "stable", "git_tags"));
        assert!(!tag_allowed_by_channel_for_source("1.0.0-0.1", "stable", "git_tags"));
        assert!(!tag_allowed_by_channel_for_source("1.2.3-1.2", "stable", "git_tags"));

        // APT: 1.0.0-0.1, 1.2.3-1.2, 1:1.2.3-1+b1, 1.2.3-1 are valid Debian NMU revisions, preserved on stable!
        assert!(tag_allowed_by_channel_for_source("1.0.0-0.1", "stable", "apt"));
        assert!(tag_allowed_by_channel_for_source("1.2.3-1.2", "stable", "apt"));
        assert!(tag_allowed_by_channel_for_source("1:1.2.3-1+b1", "stable", "apt"));
        assert!(tag_allowed_by_channel_for_source("1.2.3-1", "stable", "apt"));
        assert!(tag_allowed_by_channel_for_source("2.4.5-1ubuntu1", "stable", "apt"));

        // APT rejects prerelease tags
        assert!(!tag_allowed_by_channel_for_source("1.2.3-rc1", "stable", "apt"));
        assert!(!tag_allowed_by_channel_for_source("1.2.3-foo-1", "stable", "apt"));
    }

    #[tokio::test]
    async fn test_github_release_discovery_stable_channel_scans_pages_and_picks_highest() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };
                let mut buf = vec![0; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&buf[..n]);

                let (status, body) = if req_str.contains("/releases/latest") {
                    (
                        "HTTP/1.1 200 OK",
                        r#"{"tag_name": "v1.9.4", "html_url": "https://github.com/org/repo/releases/v1.9.4", "prerelease": false, "draft": false}"#,
                    )
                } else if req_str.contains("/releases?per_page=30") {
                    (
                        "HTTP/1.1 200 OK",
                        r#"[
                            {"tag_name": "v1.9.4", "html_url": "https://github.com/org/repo/releases/v1.9.4", "prerelease": false, "draft": false},
                            {"tag_name": "v2.0.0", "html_url": "https://github.com/org/repo/releases/v2.0.0", "prerelease": false, "draft": false}
                        ]"#,
                    )
                } else {
                    ("HTTP/1.1 404 Not Found", r#"{"message": "Not Found"}"#)
                };

                let resp = format!(
                    "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let client = build_github_http_client();
        let origin = format!("http://{addr}");

        let res = detect_latest_github_release_for_channel(&client, &origin, "test-owner/backport-repo", "stable").await.unwrap();
        assert_eq!(res.0, "2.0.0", "Stable release discovery must scan releases and select higher 2.0.0 over backport 1.9.4");
        assert_eq!(res.1, "https://github.com/org/repo/releases/v2.0.0");

        server.abort();
    }

    #[tokio::test]
    async fn test_github_release_discovery_fails_closed_on_page_2_failure() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };
                let mut buf = vec![0; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&buf[..n]);

                let (status, body) = if req_str.contains("page=2") {
                    ("HTTP/1.1 500 Internal Server Error", r#"{"message": "Server Error"}"#.to_string())
                } else {
                    let mut items = Vec::new();
                    for i in 1..=30 {
                        items.push(format!(
                            r#"{{"tag_name": "v1.0.{}", "html_url": "https://github.com/org/repo/releases/v1.0.{}", "prerelease": false, "draft": false}}"#,
                            i, i
                        ));
                    }
                    ("HTTP/1.1 200 OK", format!("[{}]", items.join(",")))
                };

                let resp = format!(
                    "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let client = build_github_http_client();
        let origin = format!("http://{addr}");
        let repo = "test-owner/fail-page2-repo";

        let res = detect_latest_github_release_for_channel(&client, &origin, repo, "stable").await;
        assert!(res.is_err(), "Must fail closed when page 2 returns HTTP 500");
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("GitHub API returned 500") || err_msg.contains("on page 2"), "error: {err_msg}");

        let cache_key = github_release_cache_key_for_channel(&origin, repo, "stable");
        let cached = github_release_cache().get(&cache_key).cloned();
        assert!(cached.is_none(), "Incomplete discovery result must NOT be cached!");

        server.abort();
    }

    #[test]
    fn test_canonical_update_source_key_and_persistence_scrub_secrets() {
        // 1. API base with userinfo and query parameters
        let dirty_api = "https://user:super_secret_pass@api.github.internal.com:443/v3?token=secret_query#anchor";
        let pkg_github = Package {
            name: "myapp".into(),
            update_source: "github".into(),
            update_repo: "myorg/myapp".into(),
            update_channel: "stable".into(),
            ..Default::default()
        };

        let key = canonical_update_source_key(dirty_api, &pkg_github);
        assert!(!key.contains("super_secret_pass"), "Key must not contain password: {key}");
        assert!(!key.contains("user:"), "Key must not contain userinfo: {key}");
        assert!(!key.contains("secret_query"), "Key must not contain query parameters: {key}");
        assert_eq!(key, "github:https://api.github.internal.com/v3|myorg/myapp|stable");

        // 2. Git remote URL with query parameters containing secret tokens
        let dirty_git_url = "https://git.example.com/team/App.git?token=secret123&access_token=xyz#frag";
        let pkg_git = Package {
            name: "myapp-git".into(),
            update_source: "git".into(),
            update_repo: "team/App".into(),
            update_repo_url: dirty_git_url.into(),
            update_channel: "stable".into(),
            ..Default::default()
        };

        let git_key = canonical_update_source_key("", &pkg_git);
        assert!(!git_key.contains("secret123"), "Git source key must not contain token: {git_key}");
        assert!(!git_key.contains("access_token"), "Git source key must not contain access_token: {git_key}");

        let disp_git = sanitize_git_remote_url_for_display(dirty_git_url);
        assert_eq!(disp_git, "https://git.example.com/team/App.git");
        assert!(!disp_git.contains("secret123"));
        assert!(!disp_git.contains("access_token"));

        // 3. Test persist_package_update_record sanitizes source_key, latest_version, installed_version
        let dirty_record = PackageUpdateRecord {
            package_id: "test-scrub-pkg".into(),
            installed: true,
            installed_version: "1.0.0-token=secret_in_version".into(),
            latest_version: "2.0.0-password=secret_in_latest".into(),
            update_available: true,
            checked_at: "2026-11-09T00:00:00Z".into(),
            release_url: "https://git.example.com/repo.git?secret=leak".into(),
            error: "curl -u admin:super_secret_curl https://example.com".into(),
            source_key: "github:https://api.github.com|myorg/myapp|stable?token=secret_in_key".into(),
        };

        persist_package_update_record(&dirty_record);
        if let Ok(conn) = af_db::get_conn() {
            let mut stmt = conn.prepare("SELECT installed_version, latest_version, update_url, last_error, source_key FROM app_updates WHERE package_name = ?1").unwrap();
            let mut rows = stmt.query(params!["test-scrub-pkg"]).unwrap();
            if let Some(row) = rows.next().unwrap() {
                let saved_inst: String = row.get(0).unwrap();
                let saved_latest: String = row.get(1).unwrap();
                let saved_url: String = row.get(2).unwrap();
                let saved_err: String = row.get(3).unwrap();
                let saved_key: String = row.get(4).unwrap();

                assert!(!saved_inst.contains("secret_in_version"), "installed_version must redact secrets");
                assert!(!saved_latest.contains("secret_in_latest"), "latest_version must redact secrets");
                assert!(!saved_url.contains("leak"), "update_url must redact secrets");
                assert!(!saved_err.contains("super_secret_curl"), "last_error must redact curl user credentials");
                assert!(!saved_key.contains("secret_in_key"), "source_key must redact secrets");
            }
        }
    }

    #[test]
    fn test_strict_semver_prerelease_rules_for_git_sources() {
        for src in &["github", "github_release", "git", "git_tags"] {
            // Numeric prerelease / hyphen after SemVer:
            assert!(
                !tag_allowed_by_channel_for_source("1.2.3-1", "stable", src),
                "Source {src} must reject 1.2.3-1 on stable"
            );
            assert!(
                !tag_allowed_by_channel_for_source("1.2.3-debug.1", "stable", src),
                "Source {src} must reject 1.2.3-debug.1 on stable"
            );
            assert!(
                !tag_allowed_by_channel_for_source("1.2.3-ubuntu1", "stable", src),
                "Source {src} must reject 1.2.3-ubuntu1 on stable"
            );
            assert!(
                !tag_allowed_by_channel_for_source("1.2.3-deb11u1", "stable", src),
                "Source {src} must reject 1.2.3-deb11u1 on stable"
            );
            assert!(
                tag_allowed_by_channel_for_source("1.2.3", "stable", src),
                "Source {src} must allow 1.2.3 on stable"
            );
        }
    }

    #[tokio::test]
    async fn test_wave19_audit_findings_workers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Finding 1: detect_latest_github_release_for_channel fails closed when 10 pages exceeded
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };
                let mut buf = vec![0; 4096];
                let _ = socket.read(&mut buf).await.unwrap_or(0);

                let mut items = Vec::new();
                for i in 1..=30 {
                    items.push(format!(
                        r#"{{"tag_name": "v1.0.{}", "html_url": "https://github.com/org/repo/releases/v1.0.{}", "prerelease": false, "draft": false}}"#,
                        i, i
                    ));
                }
                let body = format!("[{}]", items.join(","));
                let next_link = format!("<http://{addr}/repos/test-owner/overflow-repo/releases?per_page=30&page=99>; rel=\"next\"");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nLink: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    next_link,
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let client = build_github_http_client();
        let origin = format!("http://{addr}");
        let res = detect_latest_github_release_for_channel(&client, &origin, "test-owner/overflow-repo", "stable").await;
        assert!(res.is_err(), "Must fail closed when release pagination exceeds MAX_RELEASE_PAGES without exhaustion");
        let err_str = res.err().unwrap().to_string();
        assert!(
            err_str.contains("GitHub release pagination exceeded maximum page limit (10) for 'test-owner/overflow-repo'; refusing to cache incomplete release set"),
            "Error message mismatch: {err_str}"
        );

        let cache_key = github_release_cache_key_for_channel(&origin, "test-owner/overflow-repo", "stable");
        assert!(
            GITHUB_RELEASE_CACHE.lock().unwrap().get(&cache_key).is_none(),
            "Incomplete release scan must not be cached"
        );
        server.abort();

        // Finding 2: sanitize_api_base_for_source_key preserves path case
        assert_eq!(
            sanitize_api_base_for_source_key("https://Git.Example.com/TeamA/api/"),
            "https://git.example.com/TeamA/api"
        );
        assert_eq!(
            sanitize_api_base_for_source_key("https://Git.Example.com/TeamA/api?token=secret#frag"),
            "https://git.example.com/TeamA/api"
        );
        // Fallback when URL parse fails preserves path case and hashes query
        let fallback_input = "invalid url ://Git.Example.com/TeamA/api?foo=bar#frag";
        assert_eq!(
            sanitize_api_base_for_source_key(fallback_input),
            format!("invalid url ://git.example.com/TeamA/api?q#{}", sha256_hex_12(b"foo=bar"))
        );

        // Finding 4: sanitize_git_remote_url_for_display and normalize_git_remote_url_preserve_path_case
        assert_eq!(
            sanitize_git_remote_url_for_display("git@github.com:Org/Repo.git?token=secret#readme"),
            "ssh://git@github.com/Org/Repo.git"
        );
        assert_eq!(
            normalize_git_remote_url_preserve_path_case("git@github.com:Org/Repo.git?token=secret#readme"),
            format!("ssh://git@github.com/Org/Repo?q#{}", sha256_hex_12(b"token=secret"))
        );

        // Finding 3: persist_package_update_record / sanitize_source_key_for_persistence preserves ssh:// and cred#...
        let canonical_ssh_key = "git-repo:ssh://Deploy@git.example.com/Team/App.git#main";
        let canonical_cred_key = "git-repo:https://cred#0123456789ab@github.com/org/repo.git#main";
        assert_eq!(sanitize_source_key_for_persistence(canonical_ssh_key), canonical_ssh_key);
        assert_eq!(sanitize_source_key_for_persistence(canonical_cred_key), canonical_cred_key);
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(canonical_ssh_key),
            canonical_ssh_key
        );

        // Raw credentials in unnormalized source keys are scrubbed
        let dirty_ssh_key = "git-repo:ssh://Deploy:secretpass@git.example.com/Team/App.git#main";
        let cleaned_ssh = sanitize_source_key_for_persistence(dirty_ssh_key);
        assert!(!cleaned_ssh.contains("secretpass"));
        assert!(cleaned_ssh.contains("cred#"));

        // Test persist_package_update_record preserves canonical ssh and cred keys
        let rec = PackageUpdateRecord {
            package_id: "test-ssh-key-pkg".into(),
            source_key: canonical_ssh_key.into(),
            latest_version: "1.0.0".into(),
            installed_version: "1.0.0".into(),
            release_url: "ssh://Deploy@git.example.com/Team/App.git".into(),
            ..Default::default()
        };
        persist_package_update_record(&rec);
        if let Ok(conn) = af_db::get_conn() {
            let saved_key: String = conn.query_row(
                "SELECT source_key FROM app_updates WHERE package_name = ?1",
                params!["test-ssh-key-pkg"],
                |r| r.get(0),
            ).unwrap();
            assert_eq!(saved_key, canonical_ssh_key, "Persisted source_key must match canonical SSH key");
        }

        // Finding 7: compare_versions and compare_versions_for_source with 7+ digit tags
        assert_eq!(compare_versions("10000000", "9000000"), std::cmp::Ordering::Greater);
        assert_eq!(compare_versions("v10000000", "v9000000"), std::cmp::Ordering::Greater);
        assert_eq!(compare_versions_for_source("10000000", "9000000", "git"), std::cmp::Ordering::Greater);
        assert_eq!(compare_versions_for_source("v10000000", "v9000000", "git"), std::cmp::Ordering::Greater);
        assert!(is_newer_version_scalar_for_source("9000000", "10000000", "git"));
        assert!(!is_newer_version_scalar_for_source("10000000", "9000000", "git"));
    }

    #[test]
    fn test_wave20_builder_b_regressions() {
        // 1. API base cache key and rate limit isolation across base paths (/TeamA/api/v3 vs /TeamB/api/v3)
        let key_a = github_release_cache_key_for_channel("https://ghe.internal/TeamA/api/v3", "myorg/repo", "stable");
        let key_b = github_release_cache_key_for_channel("https://ghe.internal/TeamB/api/v3", "myorg/repo", "stable");
        assert_ne!(key_a, key_b, "Cache keys for /TeamA/api/v3 and /TeamB/api/v3 must be distinct!");
        assert!(key_a.contains("teama/api/v3") || key_a.contains("TeamA/api/v3"));
        assert!(key_b.contains("teamb/api/v3") || key_b.contains("TeamB/api/v3"));

        clear_github_rate_limits();
        let base_a = "https://ghe.internal/TeamA/api/v3";
        let base_b = "https://ghe.internal/TeamB/api/v3";
        record_github_api_rate_limit(base_a, "core", Duration::from_secs(60));
        assert!(is_github_rate_limited_for_origin(base_a, "core"));
        assert!(github_rate_limit_remaining_secs_for_origin(base_a, "core") > 0);
        assert!(!is_github_rate_limited_for_origin(base_b, "core"));
        assert_eq!(github_rate_limit_remaining_secs_for_origin(base_b, "core"), 0);
        clear_github_rate_limits();

        // 2. Query-bearing Git source keys (?q#<12-hex>) idempotence on persistence
        let q_key_bare = "git-repo:https://github.com/org/repo.git?q#0123456789ab";
        assert_eq!(sanitize_source_key_for_persistence(q_key_bare), q_key_bare);
        let q_key_branch = "git-repo:https://github.com/org/repo.git?q#0123456789ab#main";
        assert_eq!(sanitize_source_key_for_persistence(q_key_branch), q_key_branch);
        // Repeated persistence calls are strictly idempotent
        assert_eq!(
            sanitize_source_key_for_persistence(&sanitize_source_key_for_persistence(q_key_branch)),
            q_key_branch
        );

        // 3. Cross-repo and off-origin pagination Link validation fail-closed behavior
        let api_base = "https://api.github.com";
        let ghe_base = "https://ghe.internal/api/v3";
        // Same repo, same origin -> allowed
        assert!(validate_github_releases_next_url(
            "https://api.github.com/repos/org/repo/releases?per_page=30&page=2",
            api_base,
            "org/repo"
        ));
        assert!(validate_github_releases_next_url(
            "https://ghe.internal/api/v3/repos/org/repo/releases?per_page=30&page=2",
            ghe_base,
            "org/repo"
        ));
        // Cross-repository -> rejected
        assert!(!validate_github_releases_next_url(
            "https://api.github.com/repos/attacker/evil/releases?per_page=30&page=2",
            api_base,
            "org/repo"
        ));
        assert!(!validate_github_releases_next_url(
            "https://ghe.internal/api/v3/repos/other/repo/releases?per_page=30&page=2",
            ghe_base,
            "org/repo"
        ));
        // Off-origin -> rejected
        assert!(!validate_github_releases_next_url(
            "https://evil.attacker.com/repos/org/repo/releases?per_page=30&page=2",
            api_base,
            "org/repo"
        ));

        // 4. Numeric short Git commit IDs recognized and distinct
        let num_sha1 = "9999999";
        let full_sha = "123456abcdef0123456789abcdef0123456789a";
        let num_sha2 = "1234567";

        // "9999999" vs "123456abcdef..." on "git"
        assert!(is_newer_version_scalar_for_source(num_sha1, full_sha, "git"));
        assert!(is_newer_version_scalar_for_source(full_sha, num_sha1, "git"));

        // "9999999" vs "1234567" on "git"
        assert!(is_newer_version_scalar_for_source(num_sha1, num_sha2, "git"));
        assert!(is_newer_version_scalar_for_source(num_sha2, num_sha1, "git"));

        // Prefix match is NOT an update
        let full_matching_9 = "9999999abcdef0123456789abcdef0123456789a";
        assert!(!is_newer_version_scalar_for_source(num_sha1, full_matching_9, "git"));
        assert!(!is_newer_version_scalar_for_source(full_matching_9, num_sha1, "git"));

        // Synthetic commit version rejects pure-numeric short SHA (which are SemVer prereleases)
        assert_eq!(
            parse_synthetic_commit_version("0.1.0-1234567"),
            None
        );
        assert_eq!(
            parse_synthetic_commit_version("0.1.0-6e840ac"),
            Some(("0.1.0", "6e840ac"))
        );
    }

    #[test]
    fn test_wave21_builder_b_regressions() {
        // Finding 3: validate_github_releases_next_url path sensitivity
        let configured_base = "https://git.example.com/TeamA/api/v3";
        // Case mismatch on base path prefix -> rejected
        assert!(!validate_github_releases_next_url(
            "https://git.example.com/teama/api/v3/repos/owner/repo/releases?page=2",
            configured_base,
            "owner/repo"
        ));
        // Case mismatch on repo slug -> accepted (GitHub owner/repo slugs are case-insensitive)
        assert!(validate_github_releases_next_url(
            "https://git.example.com/TeamA/api/v3/repos/Owner/Repo/releases?page=2",
            configured_base,
            "owner/repo"
        ));
        assert!(validate_github_releases_next_url(
            "https://git.example.com/TeamA/api/v3/repos/owner/repo/releases?page=2",
            configured_base,
            "Owner/Repo"
        ));

        // Finding 8: Numeric SemVer prereleases
        assert!(is_newer_version_scalar_for_source("1.0.0-1234567", "2.0.0-1234567", ""));
        assert!(!is_newer_version_scalar_for_source("2.0.0-1234567", "1.0.0-1234567", ""));
        assert!(is_newer_version_scalar_for_source("1.0.0-1234567", "2.0.0-1234567", "false"));
        assert!(!is_newer_version_scalar_for_source("2.0.0-1234567", "1.0.0-1234567", "false"));
        assert!(is_newer_version_scalar("1.0.0-1234567", "2.0.0-1234567"));
        assert!(!is_newer_version_scalar("2.0.0-1234567", "1.0.0-1234567"));

        // Finding 8: Synthetic commit versions comparing differing version bases
        assert!(is_newer_version_scalar_for_source("1.0.0-6e840ac", "2.0.0-6e840ac", ""));
        assert!(!is_newer_version_scalar_for_source("2.0.0-6e840ac", "1.0.0-deadbeef", ""));
        assert!(is_newer_version_scalar_for_source("1.0.0-6e840ac", "2.0.0-6e840ac", "false"));
        assert!(!is_newer_version_scalar_for_source("2.0.0-6e840ac", "1.0.0-deadbeef", "false"));
        assert!(is_newer_version_scalar("1.0.0-6e840ac", "2.0.0-6e840ac"));
        assert!(!is_newer_version_scalar("2.0.0-6e840ac", "1.0.0-deadbeef"));

        // Finding 8: Same version base compares commit SHAs on git provenance
        assert!(!is_newer_version_scalar_for_source("1.0.0-6e840ac", "1.0.0-6e840ac", "git"));
        assert!(is_newer_version_scalar_for_source("1.0.0-6e840ac", "1.0.0-deadbeef", "git"));
        assert!(!is_newer_version_scalar_for_source("1.0.0-abcdef1", "1.0.0-abcdef0", "github"));
        assert!(is_newer_version_scalar_for_source("1.0.0-abcdef0", "1.0.0-abcdef1", "github"));
        assert!(!is_newer_version_scalar_for_source("1.0.0-abcdef1", "1.0.0-abcdef0", ""));
        assert!(is_newer_version_scalar_for_source("1.0.0-abcdef0", "1.0.0-abcdef1", ""));
    }

    #[tokio::test]
    async fn test_wave22_filebot_version_detection_and_update_check() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-filebot-{}", uuid::Uuid::new_v4()));
        let opt_filebot_node = temp_dir.join("opt/filebot-node");
        let server_dir = opt_filebot_node.join("server");
        let opt_filebot = temp_dir.join("opt/filebot");

        std::fs::create_dir_all(&server_dir).unwrap();
        std::fs::create_dir_all(&opt_filebot).unwrap();

        // Node component files
        std::fs::write(server_dir.join("app.js"), "console.log('filebot-node');").unwrap();
        std::fs::write(server_dir.join("package.json"), r#"{"name":"filebot-node","version":"0.4.7.0"}"#).unwrap();
        std::fs::write(opt_filebot_node.join(".af-version"), "0.4.7.0").unwrap();

        // Separate CLI files in /opt/filebot with version 5.1.6
        std::fs::write(opt_filebot.join("filebot.sh"), "#!/bin/sh\nexit 0").unwrap();
        std::fs::write(opt_filebot.join(".af-version"), "5.1.6").unwrap();

        let install_dir = temp_dir.join("install");
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(install_dir.join(".filebot.lock"), "").unwrap();

        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let pkg = Package {
            name: "filebot".into(),
            lock_file: "/install/.filebot.lock".into(),
            update_source: "github".into(),
            update_repo: "filebot/filebot-node".into(),
            version_command: vec![
                "python3".into(),
                "-c".into(),
                "import json, os, pathlib, sys; root = pathlib.Path((os.environ.get('AETHERFLOW_FS_ROOT') or os.environ.get('AETHERFLOW_INSTALL_ROOT') or '/').strip() or '/'); base = root / 'opt/filebot-node'; sys.exit(1) if not (base / 'server/app.js').is_file() else None; vers = [json.loads(p.read_text(encoding='utf-8')).get('version', '').strip() for p in (base / 'package.json', base / 'server/package.json', base / 'client/package.json') if p.is_file()]; v = next((x for x in vers if x), ''); sys.exit(1) if not v else print(v)".into(),
            ],
            ..Default::default()
        };

        // 1. Receipt verification: must find 0.4.7.0 and NEVER 5.1.6
        let receipt = read_af_version_receipt(&pkg);
        assert_eq!(receipt, Some("0.4.7.0".to_string()));

        // 2. Runtime evidence verification: app.js satisfies runtime evidence
        assert!(has_independent_runtime_evidence(&pkg));

        // 3. Strict installed version probe detects 0.4.7.0
        let installed = probe_installed_package_version_strict(&pkg).await;
        assert!(installed.is_ok(), "Failed to probe installed version: {:?}", installed.err());
        assert_eq!(installed.unwrap(), "0.4.7.0");

        // 4. Live version command executes python probe with active fs_root
        let live_ver = run_live_version_command(&pkg, Duration::from_secs(5)).await;
        assert!(live_ver.is_ok(), "Live version probe failed: {:?}", live_ver.err());
        assert_eq!(live_ver.unwrap().trim(), "0.4.7.0");

        // 5. Update availability: 0.4.8.1 is newer than 0.4.7.0
        assert!(is_remote_version_newer_for_source("0.4.7.0", "0.4.8.1", "github"));

        // 6. Certification match for 0.4.8.1 target
        assert!(af_release::lifecycle::versions_match_target("0.4.8.1", "0.4.8.1"));

        // 7. Update to 0.4.8.1
        std::fs::write(server_dir.join("package.json"), r#"{"name":"filebot-node","version":"0.4.8.1"}"#).unwrap();
        std::fs::write(opt_filebot_node.join(".af-version"), "0.4.8.1").unwrap();

        let updated_installed = probe_installed_package_version_strict(&pkg).await.unwrap();
        assert_eq!(updated_installed, "0.4.8.1");
        assert!(!is_remote_version_newer_for_source("0.4.8.1", "0.4.8.1", "github"));

        std::env::remove_var("AETHERFLOW_FS_ROOT");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_wave22_semver_prerelease_provenance_and_numeric() {
        // GitHub release source: SemVer ordering is enforced (downgrades are false)
        assert!(!is_newer_version_scalar_for_source("1.0.0-abcdef1", "1.0.0-abcdef0", "github"));
        assert!(is_newer_version_scalar_for_source("1.0.0-abcdef0", "1.0.0-abcdef1", "github"));
        assert!(!is_newer_version_scalar_for_source("1.0.0-abcdef1", "1.0.0-abcdef0", ""));
        assert!(is_newer_version_scalar_for_source("1.0.0-abcdef0", "1.0.0-abcdef1", ""));

        // Explicit git source: different commit hashes are treated as newer
        assert!(is_newer_version_scalar_for_source("1.0.0-abcdef1", "1.0.0-abcdef0", "git"));

        // 40-digit numeric prereleases: must not be treated as commit SHAs and must not overflow
        let num40_hi = "1.0.0-1234567890123456789012345678901234567899";
        let num40_lo = "1.0.0-1234567890123456789012345678901234567898";
        assert!(!is_newer_version_scalar_for_source(num40_hi, num40_lo, "github"));
        assert!(is_newer_version_scalar_for_source(num40_lo, num40_hi, "github"));
        assert!(!is_newer_version_scalar_for_source(num40_hi, num40_lo, ""));
        assert!(is_newer_version_scalar_for_source(num40_lo, num40_hi, ""));

        // 39-digit vs 40-digit numeric prereleases: numerical comparison
        let num39 = "1.0.0-999999999999999999999999999999999999999";
        let num40 = "1.0.0-1000000000000000000000000000000000000000";
        assert!(is_newer_version_scalar_for_source(num39, num40, ""));
        assert!(!is_newer_version_scalar_for_source(num40, num39, ""));

        // is_git_commit_sha rejects pure decimal strings of length 40
        assert!(!is_git_commit_sha("1234567890123456789012345678901234567890"));
        assert!(is_git_commit_sha("123456789012345678901234567890123456789a"));
        assert!(!is_git_commit_sha("1234567"));
        assert!(is_git_commit_sha("6e840ac"));

        // parse_synthetic_commit_version rejects pure numeric suffixes
        assert_eq!(parse_synthetic_commit_version("1.0.0-1234567890123456789012345678901234567890"), None);
        assert_eq!(parse_synthetic_commit_version("1.0.0-1234567"), None);
        assert_eq!(parse_synthetic_commit_version("1.0.0-6e840ac"), Some(("1.0.0", "6e840ac")));
    }

}
