//! Background Orchestration Workers (`metrics_recorder.go`, `af_heal.go`, `smart_backup.go`, `app_updates.go`).
//!
//! Provides four background tasks and on-demand package update utilities:
//! 1. [`start_metrics_recorder`] — 60-second system metrics snapshotter & hourly 7-day retention pruner.
//! 2. [`start_heal_worker`] — `af-heal` systemd service watchdog with exponential backoff (`10s * 2^attempt`, max 3 retries) and notifications.
//! 3. [`start_smart_backup_scheduler`] — 30-minute scheduled SQLite online backup (`VACUUM INTO` + `.sha256` sidecar).
//! 4. [`start_app_update_watcher`] & [`refresh_all_package_updates`] / [`refresh_package_update_by_id`] / [`get_package_update_map`] —
//!    upstream GitHub / apt / git-tag release checker and thread-safe update cache.

use af_models::Package;
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
    if let Ok(root) = env::var("AETHERFLOW_FS_ROOT") {
        let trimmed = root.trim();
        if !trimmed.is_empty() {
            let rel = path_str.trim_start_matches('/');
            return Path::new(trimmed).join(rel);
        }
    }
    PathBuf::from(path_str)
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
}

/// Thread-safe in-memory cache of package update records keyed by `package_id`.
pub static PACKAGE_UPDATE_CACHE: Lazy<Mutex<HashMap<String, PackageUpdateRecord>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static APP_UPDATE_WATCHER_ACTIVE: AtomicBool = AtomicBool::new(false);

static DOTTED_VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bv?(\d+\.\d+(?:\.\d+)*(?:[._:+~-][0-9A-Za-z]+)*)\b").unwrap());
static DEFAULT_VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bv?([0-9]+(?:[._:+~-][0-9A-Za-z]+)*)\b").unwrap());
static NUMERIC_TOKEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\d+").unwrap());

#[derive(Debug, Deserialize)]
struct GitHubReleaseResponse {
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    html_url: String,
}

/// Status text is public (Marketplace) and visible to ordinary Services viewers.
/// Only fixed summaries may cross this boundary, including historical DB/cache rows.
pub fn public_update_error(error: &str) -> String {
    match error {
        "" => String::new(),
        "Installed version could not be confirmed"
        | "Latest version could not be confirmed"
        | "Installed version could not be confirmed; Latest version could not be confirmed" => error.to_string(),
        _ => "Update status could not be confirmed".to_string(),
    }
}

fn serialize_update_error<S: serde::Serializer>(error: &str, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&public_update_error(error))
}

/// Returns persisted and cached update records with safe status summaries.
pub fn get_package_update_map() -> HashMap<String, PackageUpdateRecord> {
    let mut result = HashMap::new();

    if let Ok(conn) = af_db::get_conn() {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT package_name, COALESCE(installed_version, ''), COALESCE(latest_version, ''),
                    COALESCE(update_available, 0), COALESCE(update_url, ''),
                    COALESCE(CAST(checked_at AS TEXT), ''), COALESCE(last_error, '')
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
                })
            }) {
                for row in rows.flatten() {
                    result.insert(row.package_id.clone(), row);
                }
            }
        }
    }

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

fn build_github_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("AetherFlow-Updater")
        .build()
        .unwrap_or_default()
}

fn should_track_package(pkg: &Package) -> bool {
    if pkg.update_source.is_empty() {
        return false;
    }
    match pkg.update_source.as_str() {
        "apt" => !pkg.update_package.is_empty(),
        "github" | "git_tags" | "git" => {
            !pkg.version_command.is_empty()
                && (!pkg.update_repo.is_empty() || !pkg.update_repo_url.is_empty())
        }
        _ => !pkg.version_command.is_empty(),
    }
}

fn package_is_installed(pkg: &Package) -> bool {
    !pkg.lock_file.is_empty() && resolve_fs_path(&pkg.lock_file).exists()
}

async fn check_single_package(
    client: &reqwest::Client,
    github_api_base: &str,
    pkg: &Package,
) -> (PackageUpdateRecord, bool) {
    let is_installed = package_is_installed(&pkg);

    let installed_res = detect_installed_version(pkg).await;
    let latest_res = detect_latest_version(client, github_api_base, pkg).await;

    let prev_record = get_package_update_map().get(&pkg.name).cloned();
    let record = build_package_update_record(
        &pkg.name,
        is_installed,
        installed_res,
        latest_res,
        prev_record.as_ref(),
        Utc::now().to_rfc3339(),
    );

    let notify = persist_and_cache_package_update(&record);
    (record, notify)
}

fn build_package_update_record(
    pkg_name: &str,
    is_installed: bool,
    installed_res: anyhow::Result<String>,
    latest_res: anyhow::Result<(String, String)>,
    prev_record: Option<&PackageUpdateRecord>,
    checked_at: String,
) -> PackageUpdateRecord {
    let mut err_parts = Vec::new();
    let installed_version = match &installed_res {
        Ok(v) => v.clone(),
        Err(e) => {
            tracing::warn!(package = pkg_name, error = %e, "installed version observation failed");
            err_parts.push("Installed version could not be confirmed");
            prev_record
                .map(|r| r.installed_version.clone())
                .unwrap_or_default()
        }
    };

    let (latest_version, release_url) = match &latest_res {
        Ok((v, u)) => (v.clone(), u.clone()),
        Err(e) => {
            tracing::warn!(package = pkg_name, error = %e, "latest version observation failed");
            err_parts.push("Latest version could not be confirmed");
            (
                prev_record
                    .map(|r| r.latest_version.clone())
                    .unwrap_or_default(),
                prev_record
                    .map(|r| r.release_url.clone())
                    .unwrap_or_default(),
            )
        }
    };

    let update_available = if installed_res.is_ok() && latest_res.is_ok() {
        is_installed && is_remote_version_newer(&installed_version, &latest_version)
    } else {
        is_installed
            && prev_record
                .map(|record| record.update_available)
                .unwrap_or(false)
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

async fn detect_installed_version(pkg: &Package) -> anyhow::Result<String> {
    match pkg.update_source.as_str() {
        "apt" => {
            if pkg.update_package.is_empty() {
                anyhow::bail!("no apt package configured for {}", pkg.name);
            }
            let mut command = Command::new("dpkg-query");
            command.args(["-W", "-f=${Version}", &pkg.update_package]);
            let out = update_probe_output(command, Duration::from_secs(15)).await?;

            if !out.status.success() {
                anyhow::bail!(
                    "dpkg-query exited with {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }

            if pkg.update_source == "git" {
                return parse_git_head(&String::from_utf8_lossy(&out.stdout));
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
            let prog = &pkg.version_command[0];
            let args = &pkg.version_command[1..];
            let mut command = Command::new(prog);
            command.args(args);
            let out = update_probe_output(command, Duration::from_secs(15)).await?;

            if !out.status.success() {
                anyhow::bail!(
                    "version command exited with {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }

            if pkg.update_source == "git" {
                return parse_git_head(&String::from_utf8_lossy(&out.stdout));
            }

            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let version = extract_version(&combined, &pkg.version_regex);
            if version.is_empty() {
                anyhow::bail!("unable to parse version output");
            }
            Ok(version)
        }
    }
}

async fn detect_latest_version(
    client: &reqwest::Client,
    github_api_base: &str,
    pkg: &Package,
) -> anyhow::Result<(String, String)> {
    match pkg.update_source.as_str() {
        "apt" => detect_latest_apt_version(&pkg.update_package).await,
        "github" => detect_latest_github_release(client, github_api_base, &pkg.update_repo).await,
        "git_tags" | "git" => {
            let repo_url = if !pkg.update_repo_url.is_empty() {
                pkg.update_repo_url.clone()
            } else if !pkg.update_repo.is_empty() {
                format!("https://github.com/{}.git", pkg.update_repo)
            } else {
                String::new()
            };
            if pkg.update_source == "git" {
                if repo_url.is_empty() {
                    anyhow::bail!("missing repository URL");
                }
                let mut command = Command::new("git");
                command.args(["ls-remote", "--exit-code", &repo_url, "HEAD"]);
                let output = update_probe_output(command, Duration::from_secs(20)).await?;
                if !output.status.success() {
                    anyhow::bail!("git ls-remote HEAD failed: {}", output.status);
                }
                let head = parse_git_head(&String::from_utf8_lossy(&output.stdout))?;
                Ok((
                    head,
                    format!("{}/commits/HEAD", repo_url.trim_end_matches(".git")),
                ))
            } else {
                detect_latest_git_tag(&repo_url, &pkg.update_repo).await
            }
        }
        other => anyhow::bail!("unsupported update source {:?}", other),
    }
}

async fn detect_latest_apt_version(package_name: &str) -> anyhow::Result<(String, String)> {
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
            let version = extract_version(rest.trim(), "");
            if !version.is_empty() {
                return Ok((version, String::new()));
            }
            break;
        }
    }

    anyhow::bail!("candidate version not found")
}

async fn detect_latest_github_release(
    client: &reqwest::Client,
    github_api_base: &str,
    repo: &str,
) -> anyhow::Result<(String, String)> {
    if repo.trim().is_empty() {
        anyhow::bail!("missing GitHub repo");
    }

    let url = format!("{}/repos/{}/releases/latest", github_api_base, repo.trim());
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "AetherFlow-Updater")
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("GitHub API returned {}", resp.status());
    }

    let release: GitHubReleaseResponse = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("decode GitHub release: {}", e))?;

    let version = extract_version(&release.tag_name, "");
    if version.is_empty() {
        anyhow::bail!("unable to parse GitHub release tag {:?}", release.tag_name);
    }

    Ok((version, release.html_url))
}

async fn detect_latest_git_tag(repo_url: &str, repo: &str) -> anyhow::Result<(String, String)> {
    if repo_url.trim().is_empty() {
        anyhow::bail!("missing repository URL");
    }

    let mut command = Command::new("git");
    command.args(["ls-remote", "--tags", "--refs", repo_url.trim()]);
    let out = update_probe_output(command, Duration::from_secs(20)).await?;

    if !out.status.success() {
        anyhow::bail!(
            "git ls-remote failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut best = String::new();
    for line in stdout.lines() {
        if !line.contains("refs/tags/") {
            continue;
        }
        let Some(idx) = line.rfind('/') else {
            continue;
        };
        let ref_name = line[idx + 1..].trim();
        let version = extract_version(ref_name, "");
        if version.is_empty() {
            continue;
        }
        if best.is_empty() || is_remote_version_newer(&best, &version) {
            best = version;
        }
    }

    if best.is_empty() {
        anyhow::bail!("no tags discovered");
    }

    let mut clean_repo_url = repo_url.trim().trim_end_matches(".git").to_string();
    if clean_repo_url.is_empty() && !repo.trim().is_empty() {
        clean_repo_url = format!("https://github.com/{}", repo.trim());
    }

    Ok((best, format!("{}/releases", clean_repo_url)))
}

fn extract_version(raw: &str, custom_expr: &str) -> String {
    let text = raw.trim();
    if text.is_empty() {
        return String::new();
    }

    if !custom_expr.trim().is_empty() {
        if let Ok(re) = Regex::new(custom_expr) {
            if let Some(caps) = re.captures(text) {
                if let Some(m) = caps.get(1) {
                    return m.as_str().trim().to_string();
                }
                if let Some(m) = caps.get(0) {
                    return m.as_str().trim().to_string();
                }
            }
        }
    }

    if let Some(caps) = DOTTED_VERSION_RE.captures(text) {
        if let Some(m) = caps.get(1) {
            return m.as_str().trim().to_string();
        }
    }

    if let Some(caps) = DEFAULT_VERSION_RE.captures(text) {
        if let Some(m) = caps.get(1) {
            return m.as_str().trim().to_string();
        }
        if let Some(m) = caps.get(0) {
            return m.as_str().trim().to_string();
        }
    }

    String::new()
}

fn normalize_version_tokens(raw: &str) -> Vec<u64> {
    NUMERIC_TOKEN_RE
        .find_iter(raw)
        .filter_map(|m| m.as_str().parse::<u64>().ok())
        .collect()
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

/// Compares two version strings by numeric segments matching Go's `IsRemoteVersionNewer`.
pub fn is_remote_version_newer(local: &str, remote: &str) -> bool {
    if is_git_commit(local) && is_git_commit(remote) {
        return local != remote;
    }
    let local_tokens = normalize_version_tokens(local);
    let remote_tokens = normalize_version_tokens(remote);
    if local_tokens.is_empty() || remote_tokens.is_empty() {
        return false;
    }

    let max_len = local_tokens.len().max(remote_tokens.len());
    for i in 0..max_len {
        let l = local_tokens.get(i).copied().unwrap_or(0);
        let r = remote_tokens.get(i).copied().unwrap_or(0);
        if l == r {
            continue;
        }
        return r > l;
    }

    false
}

fn persist_and_cache_package_update(record: &PackageUpdateRecord) -> bool {
    let mut safe_record = record.clone();
    safe_record.error = public_update_error(&safe_record.error);
    let record = &safe_record;
    let mut prev_update_available = false;
    let mut had_existing = false;

    if let Ok(mut cache) = PACKAGE_UPDATE_CACHE.lock() {
        if let Some(prev) = cache.get(&record.package_id) {
            had_existing = true;
            prev_update_available = prev.update_available;
        }
        cache.insert(record.package_id.clone(), record.clone());
    }

    if let Ok(conn) = af_db::get_conn() {
        if !had_existing {
            if let Ok(existing_avail) = conn.query_row(
                "SELECT COALESCE(update_available, 0) FROM app_updates WHERE package_name = ?1",
                params![record.package_id],
                |r| r.get::<_, bool>(0),
            ) {
                prev_update_available = existing_avail;
            }
        }

        let _ = conn.execute(
            "INSERT INTO app_updates (package_name, installed_version, latest_version, update_available, update_url, checked_at, last_error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(package_name) DO UPDATE SET
               installed_version = excluded.installed_version,
               latest_version = excluded.latest_version,
               update_available = excluded.update_available,
               update_url = excluded.update_url,
               checked_at = excluded.checked_at,
               last_error = excluded.last_error",
            params![
                record.package_id,
                record.installed_version,
                record.latest_version,
                record.update_available,
                record.release_url,
                record.checked_at,
                record.error,
            ],
        );
    }

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
        assert!(is_remote_version_newer("10.9.10", "10.9.11"));
        assert!(!is_remote_version_newer("10.9.11", "10.9.11"));
        assert!(!is_remote_version_newer("10.10.0", "10.9.11"));
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
        assert!(failed.update_available);
        assert_eq!(failed.error, "Installed version could not be confirmed; Latest version could not be confirmed");
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
}
