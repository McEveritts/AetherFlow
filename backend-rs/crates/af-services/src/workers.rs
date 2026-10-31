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
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Read;
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

    let alter_stmts = [
        "ALTER TABLE metrics_history ADD COLUMN cpu_usage REAL DEFAULT 0;",
        "ALTER TABLE metrics_history ADD COLUMN memory_pct REAL DEFAULT 0;",
        "ALTER TABLE metrics_history ADD COLUMN swap_pct REAL DEFAULT 0;",
        "ALTER TABLE metrics_history ADD COLUMN disk_read_mb REAL DEFAULT 0;",
        "ALTER TABLE metrics_history ADD COLUMN disk_write_mb REAL DEFAULT 0;",
        "ALTER TABLE metrics_history ADD COLUMN net_rx_mb REAL DEFAULT 0;",
        "ALTER TABLE metrics_history ADD COLUMN net_tx_mb REAL DEFAULT 0;",
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
    let timestamp = Utc::now().to_rfc3339();

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

    ensure_metrics_history_columns();

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

#[derive(Debug, Clone)]
struct ServiceHealState {
    failure_count: u32,
    next_retry_at: Option<Instant>,
    exhausted: bool,
}

impl Default for ServiceHealState {
    fn default() -> Self {
        Self {
            failure_count: 0,
            next_retry_at: None,
            exhausted: false,
        }
    }
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
fn collect_monitored_systemd_units() -> Vec<(String, String)> {
    let mut units: Vec<(String, String)> = vec![
        ("nginx".to_string(), "Nginx".to_string()),
        ("smbd".to_string(), "Samba (smbd)".to_string()),
        ("wsdd".to_string(), "WSDD".to_string()),
    ];
    let mut seen: HashSet<String> = units.iter().map(|(u, _)| u.clone()).collect();

    if let Ok(pkgs) = crate::get_package_catalog() {
        for pkg in pkgs {
            if pkg.service_type == "pm2" || pkg.service_type == "docker" {
                continue;
            }
            if pkg.lock_file.is_empty() || !pkg.lock_file.starts_with("/install/") {
                continue;
            }
            if !resolve_fs_path(&pkg.lock_file).exists() {
                continue;
            }

            let unit = if pkg.service_name.trim().is_empty() {
                pkg.name.clone()
            } else {
                pkg.service_name.trim().to_string()
            };
            if unit.is_empty() || unit.contains('@') {
                continue;
            }
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

    units
}

/// Checks if a systemd unit is healthy (`active`) or if `systemctl` is unavailable
/// (e.g. non-systemd dev/test hosts). Returns `Some(false)` only when systemd reports
/// a failed/inactive state for an installed unit.
async fn check_systemd_unit_healthy(unit: &str) -> Option<bool> {
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new("systemctl").args(["is-active", unit]).output(),
    )
    .await
    .ok()?
    .ok()?;

    let status_text = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
    match status_text.as_str() {
        "active" | "activating" | "reloading" => Some(true),
        "failed" | "inactive" | "deactivating" => {
            // Verify unit actually exists on the system before treating "inactive" as crashed
            if status_text == "inactive" {
                if let Ok(Ok(load_out)) = tokio::time::timeout(
                    Duration::from_secs(5),
                    Command::new("systemctl")
                        .args(["show", "-p", "LoadState", "--value", unit])
                        .output(),
                )
                .await
                {
                    let load_state = String::from_utf8_lossy(&load_out.stdout)
                        .trim()
                        .to_lowercase();
                    if load_state == "not-found" || load_state.is_empty() {
                        return None;
                    }
                }
            }
            Some(false)
        }
        _ => None,
    }
}

async fn perform_heal_check() {
    let units = collect_monitored_systemd_units();
    let now = Instant::now();

    for (unit, display_name) in units {
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
                    let attempt = st.failure_count;
                    st.failure_count += 1;
                    let backoff_secs = BASE_BACKOFF_SECS.saturating_mul(1u64 << attempt);
                    st.next_retry_at = Some(now + Duration::from_secs(backoff_secs));
                    (true, st.failure_count, false)
                }
            } else {
                let attempt = st.failure_count;
                st.failure_count += 1;
                let backoff_secs = BASE_BACKOFF_SECS.saturating_mul(1u64 << attempt);
                st.next_retry_at = Some(now + Duration::from_secs(backoff_secs));
                (true, st.failure_count, false)
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

        tracing::warn!(
            unit = %unit,
            service = %display_name,
            attempt = attempt_num,
            max_retries = MAX_HEAL_RETRIES,
            "af-heal: attempting automatic service restart"
        );

        match crate::control_service(&unit, "restart").await {
            Ok(()) => {
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
            check_and_run_smart_backup();
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
    let db_path = Path::new(&db_path_str);
    if db_path_str != ":memory:" && !db_path_str.starts_with("file:") {
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                return parent.join("backups");
            }
        }
    }
    PathBuf::from("data/backups")
}

fn execute_online_sqlite_backup() -> anyhow::Result<PathBuf> {
    let backup_dir = resolve_backups_directory();
    fs::create_dir_all(&backup_dir)?;

    let ts = Utc::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let filename = format!("aetherflow_{}.sqlite", ts);
    let backup_file = backup_dir.join(&filename);
    let escaped_path = backup_file.to_string_lossy().replace('\'', "''");

    {
        let conn = af_db::get_conn()?;
        conn.execute_batch(&format!("VACUUM INTO '{}';", escaped_path))?;
    }

    let checksum = compute_sha256_hex(&backup_file)?;
    let sidecar_path = PathBuf::from(format!("{}.sha256", backup_file.display()));
    fs::write(&sidecar_path, format!("{}\n", checksum))?;

    Ok(backup_file)
}

fn compute_sha256_hex(path: &Path) -> anyhow::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
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
    #[serde(alias = "last_error", default)]
    pub error: String,
}

/// Thread-safe in-memory cache of package update records keyed by `package_id`.
pub static PACKAGE_UPDATE_CACHE: Lazy<Mutex<HashMap<String, PackageUpdateRecord>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static APP_UPDATE_WATCHER_ACTIVE: AtomicBool = AtomicBool::new(false);

static DOTTED_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bv?(\d+\.\d+(?:\.\d+)*(?:[._:+~-][0-9A-Za-z]+)*)\b").unwrap()
});
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

/// Returns a snapshot of all known [`PackageUpdateRecord`] entries, merging persisted
/// rows from `app_updates` in SQLite with the in-memory [`PACKAGE_UPDATE_CACHE`].
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
pub async fn refresh_all_package_updates() -> Vec<PackageUpdateRecord> {
    let Ok(pkgs) = crate::get_packages() else {
        return Vec::new();
    };

    let client = build_github_http_client();
    let base_url = resolve_github_api_base_url();
    let mut records = Vec::new();

    for pkg in pkgs {
        let is_installed = pkg.status == "installed" || pkg.status == "running";
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

    records
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
        let _ = refresh_all_package_updates().await;

        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Consume immediate first tick
        ticker.tick().await;

        loop {
            ticker.tick().await;
            let _ = refresh_all_package_updates().await;
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

async fn check_single_package(
    client: &reqwest::Client,
    github_api_base: &str,
    pkg: &Package,
) -> (PackageUpdateRecord, bool) {
    let is_installed = pkg.status == "installed" || pkg.status == "running";

    let installed_res = detect_installed_version(pkg).await;
    let latest_res = detect_latest_version(client, github_api_base, pkg).await;

    let mut err_parts = Vec::new();
    let installed_version = match &installed_res {
        Ok(v) => v.clone(),
        Err(e) => {
            err_parts.push(format!("installed version: {}", e));
            String::new()
        }
    };

    let (latest_version, release_url) = match &latest_res {
        Ok((v, u)) => (v.clone(), u.clone()),
        Err(e) => {
            err_parts.push(format!("latest version: {}", e));
            (String::new(), String::new())
        }
    };

    let update_available = installed_res.is_ok()
        && latest_res.is_ok()
        && is_remote_version_newer(&installed_version, &latest_version);

    let record = PackageUpdateRecord {
        package_id: pkg.name.clone(),
        installed: is_installed,
        installed_version,
        latest_version,
        update_available,
        checked_at: Utc::now().to_rfc3339(),
        release_url,
        error: err_parts.join("; "),
    };

    let notify = persist_and_cache_package_update(&record);
    (record, notify)
}

async fn detect_installed_version(pkg: &Package) -> anyhow::Result<String> {
    match pkg.update_source.as_str() {
        "apt" => {
            if pkg.update_package.is_empty() {
                anyhow::bail!("no apt package configured for {}", pkg.name);
            }
            let out = tokio::time::timeout(
                Duration::from_secs(15),
                Command::new("dpkg-query")
                    .args(["-W", "-f=${Version}", &pkg.update_package])
                    .output(),
            )
            .await
            .map_err(|_| anyhow::anyhow!("dpkg-query timed out"))?
            .map_err(|e| anyhow::anyhow!("dpkg-query failed: {}", e))?;

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
            let prog = &pkg.version_command[0];
            let args = &pkg.version_command[1..];
            let out = tokio::time::timeout(
                Duration::from_secs(15),
                Command::new(prog).args(args).output(),
            )
            .await
            .map_err(|_| anyhow::anyhow!("version command timed out"))?
            .map_err(|e| anyhow::anyhow!("version command failed: {}", e))?;

            if !out.status.success() {
                anyhow::bail!(
                    "version command exited with {}: {}",
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
            detect_latest_git_tag(&repo_url, &pkg.update_repo).await
        }
        other => anyhow::bail!("unsupported update source {:?}", other),
    }
}

async fn detect_latest_apt_version(package_name: &str) -> anyhow::Result<(String, String)> {
    let out = tokio::time::timeout(
        Duration::from_secs(15),
        Command::new("apt-cache")
            .args(["policy", package_name])
            .output(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("apt-cache timed out"))?
    .map_err(|e| anyhow::anyhow!("apt-cache failed: {}", e))?;

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

    let out = tokio::time::timeout(
        Duration::from_secs(20),
        Command::new("git")
            .args(["ls-remote", "--tags", "--refs", repo_url.trim()])
            .output(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("git ls-remote timed out"))?
    .map_err(|e| anyhow::anyhow!("git ls-remote failed: {}", e))?;

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

/// Compares two version strings by numeric segments matching Go's `IsRemoteVersionNewer`.
pub fn is_remote_version_newer(local: &str, remote: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_extraction_and_comparison() {
        assert_eq!(extract_version("jellyfin 10.9.11", ""), "10.9.11");
        assert_eq!(extract_version("v2.4.0-rc1", ""), "2.4.0-rc1");
        assert!(is_remote_version_newer("10.9.10", "10.9.11"));
        assert!(!is_remote_version_newer("10.9.11", "10.9.11"));
        assert!(!is_remote_version_newer("10.10.0", "10.9.11"));
    }

    #[test]
    fn test_parse_speed_str_to_mb_s() {
        assert!((parse_speed_str_to_mb_s("10.5 MB/s") - 10.5).abs() < 1e-6);
        assert!((parse_speed_str_to_mb_s("1024.0 KB/s") - 1.0).abs() < 1e-6);
        assert_eq!(parse_speed_str_to_mb_s("0 B/s"), 0.0);
    }
}
