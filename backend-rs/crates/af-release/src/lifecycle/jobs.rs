use super::lease::{owner_is_alive, retire_finished_owners, OwnerLease};
use super::sanitize_persisted_lifecycle_text;
use super::units::{package_resources, ReservationTarget};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const RECOVERY_STATE_PRIOR_VERIFIED: &str = "prior_state_verified";
pub const RECOVERY_STATE_UNVERIFIED: &str = "unverified";
pub const RETENTION_STATE_RETAINED: &str = "retained";
pub const RETENTION_STATE_PURGED: &str = "purged";

/// Enforces the persistence invariant for package removal retention outcomes:
/// only a completed `remove` job may persist `"retained"` (ordinary remove
/// leaving managed config/data behind) or `"purged"` (explicit destructive
/// purge). All other actions and failed removals record `""`.
pub fn normalize_retention_state(
    success: bool,
    action: &str,
    retention_state: Option<&str>,
) -> &'static str {
    if !success || action != "remove" {
        return "";
    }
    match retention_state.map(str::trim) {
        Some(RETENTION_STATE_RETAINED) => RETENTION_STATE_RETAINED,
        Some(RETENTION_STATE_PURGED) => RETENTION_STATE_PURGED,
        _ => "",
    }
}

/// Enforces the persistence invariant for failed-operation recovery receipts:
/// only a failed in-place operation (`install`, `reinstall`, `update`) that did
/// not fail in removal/retention or interruption may persist
/// [`RECOVERY_STATE_PRIOR_VERIFIED`]. Failed updates without that evidence
/// record `unverified` to distinguish them from rows written before this field.
pub fn normalize_recovery_state(
    success: bool,
    action: &str,
    failure_category: &str,
    recovery_state: Option<&str>,
) -> &'static str {
    if !success
        && matches!(action, "install" | "reinstall" | "update")
        && !matches!(failure_category, "retention" | "interrupted")
        && recovery_state.map(str::trim) == Some(RECOVERY_STATE_PRIOR_VERIFIED)
    {
        RECOVERY_STATE_PRIOR_VERIFIED
    } else if !success && action == "update" {
        RECOVERY_STATE_UNVERIFIED
    } else {
        ""
    }
}

pub fn initialize_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS package_lifecycle_jobs (
        package_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, action TEXT NOT NULL,
        status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL DEFAULT '',
        owner_id TEXT NOT NULL DEFAULT '', service_units TEXT NOT NULL DEFAULT '[]',
        failure_category TEXT NOT NULL DEFAULT '', failed_stage TEXT NOT NULL DEFAULT '',
        exit_code INTEGER, sanitized_summary TEXT NOT NULL DEFAULT '',
        expected_target_version TEXT NOT NULL DEFAULT '', achieved_version TEXT NOT NULL DEFAULT '',
        recovery_state TEXT NOT NULL DEFAULT '',
        retention_state TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS package_lifecycle_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_id TEXT NOT NULL, job_id TEXT NOT NULL, action TEXT NOT NULL,
        status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL DEFAULT '',
        owner_id TEXT NOT NULL DEFAULT '', service_units TEXT NOT NULL DEFAULT '[]',
        failure_category TEXT NOT NULL DEFAULT '', failed_stage TEXT NOT NULL DEFAULT '',
        exit_code INTEGER, sanitized_summary TEXT NOT NULL DEFAULT '',
        expected_target_version TEXT NOT NULL DEFAULT '', achieved_version TEXT NOT NULL DEFAULT '',
        recovery_state TEXT NOT NULL DEFAULT '',
        retention_state TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_lifecycle_history_pkg ON package_lifecycle_history(package_id, started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_lifecycle_history_job ON package_lifecycle_history(job_id);
    CREATE VIEW IF NOT EXISTS package_lifecycle_journal AS SELECT * FROM package_lifecycle_history;",
    )?;
    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(package_lifecycle_jobs)")?
        .query_map([], |row| row.get(1))?
        .collect::<rusqlite::Result<_>>()?;
    for (name, definition) in [
        ("owner_id", "TEXT NOT NULL DEFAULT ''"),
        ("service_units", "TEXT NOT NULL DEFAULT '[]'"),
        ("failure_category", "TEXT NOT NULL DEFAULT ''"),
        ("failed_stage", "TEXT NOT NULL DEFAULT ''"),
        ("exit_code", "INTEGER"),
        ("sanitized_summary", "TEXT NOT NULL DEFAULT ''"),
        ("expected_target_version", "TEXT NOT NULL DEFAULT ''"),
        ("achieved_version", "TEXT NOT NULL DEFAULT ''"),
        ("recovery_state", "TEXT NOT NULL DEFAULT ''"),
        ("retention_state", "TEXT NOT NULL DEFAULT ''"),
    ] {
        if !columns.iter().any(|column| column == name) {
            conn.execute_batch(&format!(
                "ALTER TABLE package_lifecycle_jobs ADD COLUMN {name} {definition}"
            ))?;
        }
    }
    let hist_columns: Vec<String> = conn
        .prepare("PRAGMA table_info(package_lifecycle_history)")?
        .query_map([], |row| row.get(1))?
        .collect::<rusqlite::Result<_>>()?;
    for (name, definition) in [
        ("owner_id", "TEXT NOT NULL DEFAULT ''"),
        ("service_units", "TEXT NOT NULL DEFAULT '[]'"),
        ("failure_category", "TEXT NOT NULL DEFAULT ''"),
        ("failed_stage", "TEXT NOT NULL DEFAULT ''"),
        ("exit_code", "INTEGER"),
        ("sanitized_summary", "TEXT NOT NULL DEFAULT ''"),
        ("expected_target_version", "TEXT NOT NULL DEFAULT ''"),
        ("achieved_version", "TEXT NOT NULL DEFAULT ''"),
        ("recovery_state", "TEXT NOT NULL DEFAULT ''"),
        ("retention_state", "TEXT NOT NULL DEFAULT ''"),
    ] {
        if !hist_columns.iter().any(|column| column == name) {
            conn.execute_batch(&format!(
                "ALTER TABLE package_lifecycle_history ADD COLUMN {name} {definition}"
            ))?;
        }
    }
    Ok(())
}

pub fn reconcile_jobs_with_options(
    conn: &Connection,
    database: &Path,
    retire_leases: bool,
) -> Result<()> {
    let has_owner: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_jobs') WHERE name='owner_id')",
        [], |row| row.get(0),
    )?;
    if !has_owner {
        return Ok(());
    }
    let has_recovery: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_jobs') WHERE name='recovery_state')",
        [], |row| row.get(0),
    )?;
    let has_hist_recovery: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_history') WHERE name='recovery_state')",
        [], |row| row.get(0),
    )?;
    struct OrphanedJobRow {
        package: String,
        job: String,
        owner: String,
        action: String,
        started_at: String,
        service_units: String,
        expected_target_version: String,
        sanitized_summary: String,
    }
    let jobs: Vec<OrphanedJobRow> = conn
        .prepare(
            "SELECT package_id,job_id,owner_id,action,started_at,service_units,expected_target_version,sanitized_summary
             FROM package_lifecycle_jobs
             WHERE status IN ('installing','updating','uninstalling')",
        )?
        .query_map([], |row| {
            Ok(OrphanedJobRow {
                package: row.get(0)?,
                job: row.get(1)?,
                owner: row.get(2)?,
                action: row.get(3)?,
                started_at: row.get(4)?,
                service_units: row.get(5)?,
                expected_target_version: row.get(6)?,
                sanitized_summary: row.get(7)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    let interrupt_orphaned_row = |row: &OrphanedJobRow| -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let pkg_san = sanitize_persisted_text(&row.package);
        let job_san = sanitize_persisted_text(&row.job);
        let owner_san = sanitize_persisted_text(&row.owner);
        let action_san = sanitize_persisted_text(&row.action);
        let started_san = sanitize_persisted_text(&row.started_at);
        let units_san = sanitize_service_units_json(&row.service_units);
        let expected_san = sanitize_persisted_text(&row.expected_target_version);
        let summary_san = sanitize_persisted_text(&row.sanitized_summary);
        if row.package != pkg_san {
            let _ = conn.execute(
                "DELETE FROM package_lifecycle_jobs
                 WHERE package_id=?1 AND status NOT IN ('installing','updating','uninstalling')",
                params![pkg_san],
            );
        }
        let target_pkg = if row.package == pkg_san
            || !conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM package_lifecycle_jobs WHERE package_id=?1)",
                params![pkg_san],
                |r| r.get::<_, bool>(0),
            )? {
            pkg_san.as_str()
        } else {
            row.package.as_str()
        };
        if has_recovery {
            conn.execute(
                "UPDATE package_lifecycle_jobs
                 SET package_id=?1,job_id=?2,action=?3,status='interrupted',started_at=?4,finished_at=?5,owner_id=?6,service_units=?7,failure_category='interrupted',sanitized_summary=?8,expected_target_version=?9,recovery_state=''
                 WHERE package_id=?10 AND job_id=?11 AND owner_id=?12 AND status IN ('installing','updating','uninstalling')",
                params![
                    target_pkg, job_san, action_san, started_san, now, owner_san, units_san,
                    summary_san, expected_san, row.package, row.job, row.owner
                ],
            )?;
        } else {
            conn.execute(
                "UPDATE package_lifecycle_jobs
                 SET package_id=?1,job_id=?2,action=?3,status='interrupted',started_at=?4,finished_at=?5,owner_id=?6,service_units=?7,failure_category='interrupted',sanitized_summary=?8,expected_target_version=?9
                 WHERE package_id=?10 AND job_id=?11 AND owner_id=?12 AND status IN ('installing','updating','uninstalling')",
                params![
                    target_pkg, job_san, action_san, started_san, now, owner_san, units_san,
                    summary_san, expected_san, row.package, row.job, row.owner
                ],
            )?;
        }
        if has_hist_recovery {
            let _ = conn.execute(
                "UPDATE package_lifecycle_history
                 SET package_id=?1,job_id=?2,action=?3,status='interrupted',started_at=?4,finished_at=?5,owner_id=?6,service_units=?7,failure_category='interrupted',sanitized_summary=?8,expected_target_version=?9,recovery_state=''
                 WHERE package_id=?10 AND job_id=?11 AND owner_id=?12 AND status IN ('installing','updating','uninstalling')",
                params![
                    pkg_san, job_san, action_san, started_san, now, owner_san, units_san,
                    summary_san, expected_san, row.package, row.job, row.owner
                ],
            );
        } else {
            let _ = conn.execute(
                "UPDATE package_lifecycle_history
                 SET package_id=?1,job_id=?2,action=?3,status='interrupted',started_at=?4,finished_at=?5,owner_id=?6,service_units=?7,failure_category='interrupted',sanitized_summary=?8,expected_target_version=?9
                 WHERE package_id=?10 AND job_id=?11 AND owner_id=?12 AND status IN ('installing','updating','uninstalling')",
                params![
                    pkg_san, job_san, action_san, started_san, now, owner_san, units_san,
                    summary_san, expected_san, row.package, row.job, row.owner
                ],
            );
        }
        Ok(())
    };
    for row in &jobs {
        if row.owner.is_empty() || !matches!(owner_is_alive(database, &row.owner), Ok(false)) {
            continue;
        }
        interrupt_orphaned_row(row)?;
    }
    if retire_leases {
        let _ = retire_finished_owners(conn, database);
    }
    Ok(())
}

pub fn reconcile_jobs(conn: &Connection, database: &Path) -> Result<()> {
    reconcile_jobs_with_options(conn, database, true)
}

pub fn check_package_reservation(
    conn: &Connection,
    package: &str,
    units: &[String],
    job_id: &str,
    action: Option<&str>,
) -> Result<()> {
    let package_sanitized = sanitize_persisted_text(package);
    let job_id_sanitized = sanitize_persisted_text(job_id);
    let action_sanitized = action.map(sanitize_persisted_text);
    let sanitized_units: Vec<String> = units
        .iter()
        .map(|unit| sanitize_persisted_text(unit))
        .collect();
    check_resources(
        conn,
        Some(package_resources(&package_sanitized, &sanitized_units)),
        &job_id_sanitized,
        action_sanitized.as_deref(),
    )?;
    if !job_id_sanitized.is_empty() {
        let exact: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM package_lifecycle_jobs WHERE (package_id=?1 OR package_id=?2) AND (job_id=?3 OR job_id=?4) AND status IN ('installing','updating','uninstalling'))",
            params![package_sanitized, package, job_id_sanitized, job_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(exact, "Lifecycle owner does not match requested package");
    }
    Ok(())
}

pub fn admit_job(
    conn: &mut Connection,
    package: &str,
    job_id: &str,
    action: &str,
    started_at: &str,
    units: &[String],
) -> Result<OwnerLease> {
    admit_job_with_target(conn, package, job_id, action, started_at, units, None)
}

pub fn admit_job_with_target(
    conn: &mut Connection,
    package: &str,
    job_id: &str,
    action: &str,
    started_at: &str,
    units: &[String],
    expected_target_version: Option<&str>,
) -> Result<OwnerLease> {
    anyhow::ensure!(
        !package.is_empty() && !job_id.is_empty(),
        "lifecycle identity is required"
    );
    let package_sanitized = sanitize_persisted_text(package);
    let job_id_sanitized = sanitize_persisted_text(job_id);
    let action_sanitized = sanitize_persisted_text(action);
    anyhow::ensure!(
        !package_sanitized.is_empty() && !job_id_sanitized.is_empty(),
        "lifecycle identity is required"
    );
    let status = match action_sanitized.as_str() {
        "install" | "reinstall" => "installing",
        "update" => "updating",
        "remove" => "uninstalling",
        _ => anyhow::bail!("invalid lifecycle action"),
    };
    let database = PathBuf::from(conn.path().context("lifecycle database path missing")?);
    anyhow::ensure!(
        !database.as_os_str().is_empty(),
        "durable lifecycle database is required"
    );
    let _ = retire_finished_owners(conn, &database);
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    check_package_reservation(&tx, &package_sanitized, units, "", Some(&action_sanitized))?;
    let lease = OwnerLease::create(&database)?;
    let sanitized_units: Vec<String> = units
        .iter()
        .map(|unit| sanitize_persisted_text(unit))
        .collect();
    let normalized: Vec<String> = package_resources(&package_sanitized, &sanitized_units)
        .into_iter()
        .map(|unit| sanitize_persisted_text(&unit))
        .collect();
    let normalized_json = serde_json::to_string(&normalized)?;
    let started_at_sanitized = sanitize_persisted_text(started_at);
    let owner_id_sanitized = sanitize_persisted_text(&lease.id);
    let target_ver_raw = expected_target_version.unwrap_or("");
    let target_ver = sanitize_persisted_text(target_ver_raw);
    let has_jobs_retention: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_jobs') WHERE name='retention_state')",
        [],
        |row| row.get(0),
    )?;
    let has_hist_retention: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_history') WHERE name='retention_state')",
        [],
        |row| row.get(0),
    )?;
    if has_jobs_retention {
        tx.execute(
            "INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category,failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,recovery_state,retention_state)
            VALUES (?1,?2,?3,?4,?5,'',?6,?7,'','',NULL,'',?8,'','','') ON CONFLICT(package_id) DO UPDATE SET
            job_id=excluded.job_id,action=excluded.action,status=excluded.status,started_at=excluded.started_at,finished_at='',owner_id=excluded.owner_id,service_units=excluded.service_units,failure_category='',failed_stage='',exit_code=NULL,sanitized_summary='',expected_target_version=excluded.expected_target_version,achieved_version='',recovery_state='',retention_state=''",
            params![package_sanitized, job_id_sanitized, action_sanitized, status, started_at_sanitized, owner_id_sanitized, normalized_json, target_ver],
        )?;
    } else {
        tx.execute(
            "INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category,failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,recovery_state)
            VALUES (?1,?2,?3,?4,?5,'',?6,?7,'','',NULL,'',?8,'','') ON CONFLICT(package_id) DO UPDATE SET
            job_id=excluded.job_id,action=excluded.action,status=excluded.status,started_at=excluded.started_at,finished_at='',owner_id=excluded.owner_id,service_units=excluded.service_units,failure_category='',failed_stage='',exit_code=NULL,sanitized_summary='',expected_target_version=excluded.expected_target_version,achieved_version='',recovery_state=''",
            params![package_sanitized, job_id_sanitized, action_sanitized, status, started_at_sanitized, owner_id_sanitized, normalized_json, target_ver],
        )?;
    }
    if has_hist_retention {
        tx.execute(
            "INSERT INTO package_lifecycle_history (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category,failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,recovery_state,retention_state)
            VALUES (?1,?2,?3,?4,?5,'',?6,?7,'','',NULL,'',?8,'','','')",
            params![package_sanitized, job_id_sanitized, action_sanitized, status, started_at_sanitized, owner_id_sanitized, normalized_json, target_ver],
        )?;
    } else {
        tx.execute(
            "INSERT INTO package_lifecycle_history (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category,failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,recovery_state)
            VALUES (?1,?2,?3,?4,?5,'',?6,?7,'','',NULL,'',?8,'','')",
            params![package_sanitized, job_id_sanitized, action_sanitized, status, started_at_sanitized, owner_id_sanitized, normalized_json, target_ver],
        )?;
    }
    tx.commit()?;
    Ok(lease)
}

pub fn finish_job(
    conn: &Connection,
    package: &str,
    job_id: &str,
    action: &str,
    success: bool,
    failure_category: &str,
) -> Result<()> {
    finish_job_with_diagnostics(
        conn,
        package,
        job_id,
        action,
        success,
        LifecycleJobDiagnostics {
            failure_category,
            ..Default::default()
        },
    )
}

#[derive(Default)]
pub struct LifecycleJobDiagnostics<'a> {
    pub failure_category: &'a str,
    pub failed_stage: Option<&'a str>,
    pub exit_code: Option<i32>,
    pub sanitized_summary: Option<&'a str>,
    pub expected_target_version: Option<&'a str>,
    pub achieved_version: Option<&'a str>,
    pub finished_at: Option<&'a str>,
    pub recovery_state: Option<&'a str>,
    pub retention_state: Option<&'a str>,
}

impl LifecycleJobDiagnostics<'_> {
    /// Canonical write/read lifecycle sanitizer shared across `af-release` and
    /// `af-services` so in-memory `JobRegistry` identities match persisted SQLite rows.
    pub fn sanitize_persisted_text(raw: &str) -> String {
        sanitize_persisted_text(raw)
    }
}

pub fn finish_job_with_diagnostics(
    conn: &Connection,
    package: &str,
    job_id: &str,
    action: &str,
    success: bool,
    diagnostics: LifecycleJobDiagnostics<'_>,
) -> Result<()> {
    let LifecycleJobDiagnostics {
        failure_category,
        failed_stage,
        exit_code,
        sanitized_summary,
        expected_target_version,
        achieved_version,
        finished_at,
        recovery_state,
        retention_state,
    } = diagnostics;
    let package_sanitized = sanitize_persisted_text(package);
    let job_id_sanitized = sanitize_persisted_text(job_id);
    let action_sanitized = sanitize_persisted_text(action);
    let status = if success { "completed" } else { "failed" };
    let finished_at_owned = finished_at
        .map(sanitize_persisted_text)
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let finished_at = finished_at_owned.as_str();
    let cat = if success || failure_category.is_empty() {
        String::new()
    } else {
        sanitize_persisted_text(failure_category)
    };
    let recovery = normalize_recovery_state(success, &action_sanitized, &cat, recovery_state);
    let retention = normalize_retention_state(success, &action_sanitized, retention_state);
    let stage = sanitize_persisted_text(failed_stage.unwrap_or(""));
    let summary = sanitize_persisted_text(sanitized_summary.unwrap_or(""));
    let achieved = sanitize_persisted_text(achieved_version.unwrap_or(""));
    let expected = sanitize_persisted_text(expected_target_version.unwrap_or(""));

    let in_tx = !conn.is_autocommit();
    if !in_tx {
        conn.execute_batch("BEGIN IMMEDIATE;")?;
    }
    let run = || -> Result<()> {
        let has_jobs_retention: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_jobs') WHERE name='retention_state')",
            [],
            |row| row.get(0),
        )?;
        let has_hist_retention: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_history') WHERE name='retention_state')",
            [],
            |row| row.get(0),
        )?;
        let existing_active: Option<(String, String, String, String, String, String, String)> = conn
            .query_row(
                "SELECT package_id, job_id, action, started_at, owner_id, service_units, expected_target_version
                 FROM package_lifecycle_jobs
                 WHERE ((package_id=?1 AND job_id=?2 AND action=?3)
                        OR (package_id=?4 AND job_id=?5 AND action=?6))
                   AND status IN ('installing','updating','uninstalling')
                 LIMIT 1",
                params![
                    package_sanitized,
                    job_id_sanitized,
                    action_sanitized,
                    package,
                    job_id,
                    action,
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            matched_pkg,
            matched_job_id,
            matched_action,
            existing_jobs_started_at,
            existing_jobs_owner_id,
            existing_jobs_service_units,
            existing_jobs_expected,
        )) = existing_active
        else {
            anyhow::bail!("lifecycle receipt identity changed");
        };
        let jobs_started_at = sanitize_persisted_text(&existing_jobs_started_at);
        let jobs_owner_id = sanitize_persisted_text(&existing_jobs_owner_id);
        let jobs_service_units = sanitize_service_units_json(&existing_jobs_service_units);
        let resolved_jobs_expected = if expected.is_empty() {
            sanitize_persisted_text(&existing_jobs_expected)
        } else {
            expected.clone()
        };
        if matched_pkg != package_sanitized {
            let _ = conn.execute(
                "DELETE FROM package_lifecycle_jobs
                 WHERE package_id=?1 AND status NOT IN ('installing','updating','uninstalling')",
                params![package_sanitized],
            );
        }
        let can_update_jobs_pkg = matched_pkg == package_sanitized
            || !conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM package_lifecycle_jobs WHERE package_id=?1)",
                params![package_sanitized],
                |row| row.get::<_, bool>(0),
            )?;
        let target_jobs_pkg = if can_update_jobs_pkg {
            package_sanitized.as_str()
        } else {
            matched_pkg.as_str()
        };
        let existing_hist_row: Option<(String, String, String, String)> = conn
            .query_row(
                "SELECT started_at, owner_id, service_units, expected_target_version
                 FROM package_lifecycle_history
                 WHERE ((package_id=?1 AND job_id=?2 AND action=?3)
                        OR (package_id=?4 AND job_id=?5 AND action=?6))
                   AND status IN ('installing','updating','uninstalling')
                 ORDER BY id DESC LIMIT 1",
                params![
                    matched_pkg,
                    matched_job_id,
                    matched_action,
                    package_sanitized,
                    job_id_sanitized,
                    action_sanitized,
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let (hist_started_at, hist_owner_id, hist_service_units, resolved_hist_expected) =
            match existing_hist_row {
                Some((raw_started, raw_owner, raw_units, raw_expected)) => {
                    let s_started = sanitize_persisted_text(&raw_started);
                    let s_owner = sanitize_persisted_text(&raw_owner);
                    let s_units = sanitize_service_units_json(&raw_units);
                    let s_expected = if expected.is_empty() {
                        if !raw_expected.is_empty() {
                            sanitize_persisted_text(&raw_expected)
                        } else {
                            resolved_jobs_expected.clone()
                        }
                    } else {
                        expected.clone()
                    };
                    (s_started, s_owner, s_units, s_expected)
                }
                None => (
                    jobs_started_at.clone(),
                    jobs_owner_id.clone(),
                    jobs_service_units.clone(),
                    resolved_jobs_expected.clone(),
                ),
            };
        let updated = if has_jobs_retention {
            conn.execute(
                "UPDATE package_lifecycle_jobs SET package_id=?1,job_id=?2,action=?3,status=?4,started_at=?5,finished_at=?6,owner_id=?7,service_units=?8,failure_category=?9,failed_stage=?10,exit_code=?11,sanitized_summary=?12,expected_target_version=?13,achieved_version=?14,recovery_state=?15,retention_state=?16
                 WHERE package_id=?17 AND job_id=?18 AND action=?19 AND status IN ('installing','updating','uninstalling')",
                params![target_jobs_pkg, job_id_sanitized, action_sanitized, status, jobs_started_at, finished_at, jobs_owner_id, jobs_service_units, cat, stage, exit_code, summary, resolved_jobs_expected, achieved, recovery, retention, matched_pkg, matched_job_id, matched_action],
            )?
        } else {
            conn.execute(
                "UPDATE package_lifecycle_jobs SET package_id=?1,job_id=?2,action=?3,status=?4,started_at=?5,finished_at=?6,owner_id=?7,service_units=?8,failure_category=?9,failed_stage=?10,exit_code=?11,sanitized_summary=?12,expected_target_version=?13,achieved_version=?14,recovery_state=?15
                 WHERE package_id=?16 AND job_id=?17 AND action=?18 AND status IN ('installing','updating','uninstalling')",
                params![target_jobs_pkg, job_id_sanitized, action_sanitized, status, jobs_started_at, finished_at, jobs_owner_id, jobs_service_units, cat, stage, exit_code, summary, resolved_jobs_expected, achieved, recovery, matched_pkg, matched_job_id, matched_action],
            )?
        };
        anyhow::ensure!(updated == 1, "lifecycle receipt identity changed");
        let hist_updated = if has_hist_retention {
            conn.execute(
                "UPDATE package_lifecycle_history SET package_id=?1,job_id=?2,action=?3,status=?4,started_at=?5,finished_at=?6,owner_id=?7,service_units=?8,failure_category=?9,failed_stage=?10,exit_code=?11,sanitized_summary=?12,expected_target_version=?13,achieved_version=?14,recovery_state=?15,retention_state=?16
                 WHERE ((package_id=?17 AND job_id=?18 AND action=?19)
                        OR (package_id=?20 AND job_id=?21 AND action=?22))
                   AND status IN ('installing','updating','uninstalling')",
                params![package_sanitized, job_id_sanitized, action_sanitized, status, hist_started_at, finished_at, hist_owner_id, hist_service_units, cat, stage, exit_code, summary, resolved_hist_expected, achieved, recovery, retention, matched_pkg, matched_job_id, matched_action, package_sanitized, job_id_sanitized, action_sanitized],
            )?
        } else {
            conn.execute(
                "UPDATE package_lifecycle_history SET package_id=?1,job_id=?2,action=?3,status=?4,started_at=?5,finished_at=?6,owner_id=?7,service_units=?8,failure_category=?9,failed_stage=?10,exit_code=?11,sanitized_summary=?12,expected_target_version=?13,achieved_version=?14,recovery_state=?15
                 WHERE ((package_id=?16 AND job_id=?17 AND action=?18)
                        OR (package_id=?19 AND job_id=?20 AND action=?21))
                   AND status IN ('installing','updating','uninstalling')",
                params![package_sanitized, job_id_sanitized, action_sanitized, status, hist_started_at, finished_at, hist_owner_id, hist_service_units, cat, stage, exit_code, summary, resolved_hist_expected, achieved, recovery, matched_pkg, matched_job_id, matched_action, package_sanitized, job_id_sanitized, action_sanitized],
            )?
        };
        if hist_updated == 0 {
            if has_hist_retention {
                conn.execute(
                    "INSERT INTO package_lifecycle_history (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category,failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,recovery_state,retention_state)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                    params![package_sanitized, job_id_sanitized, action_sanitized, status, jobs_started_at, finished_at, jobs_owner_id, jobs_service_units, cat, stage, exit_code, summary, resolved_jobs_expected, achieved, recovery, retention],
                )?;
            } else {
                conn.execute(
                    "INSERT INTO package_lifecycle_history (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category,failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,recovery_state)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                    params![package_sanitized, job_id_sanitized, action_sanitized, status, jobs_started_at, finished_at, jobs_owner_id, jobs_service_units, cat, stage, exit_code, summary, resolved_jobs_expected, achieved, recovery],
                )?;
            }
        }
        Ok(())
    };
    match run() {
        Ok(()) => {
            if !in_tx {
                conn.execute_batch("COMMIT;")?;
            }
            Ok(())
        }
        Err(e) => {
            if !in_tx {
                let _ = conn.execute_batch("ROLLBACK;");
            }
            Err(e)
        }
    }
}

/// Summary of the most recently completed lifecycle job for a package, used to
/// prove retained-removal provenance and survive failed retry attempts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageLifecycleRetentionRecord {
    pub package_id: String,
    pub job_id: String,
    pub action: String,
    pub status: String,
    pub retention_state: String,
    pub finished_at: String,
}

/// Queries the most recently completed lifecycle record for `package_id` (or its
/// canonical lock alias) across `package_lifecycle_jobs` and
/// `package_lifecycle_history`, tolerating older databases that predate the
/// `retention_state` column or `package_lifecycle_history` table.
pub fn query_package_retention_history(
    conn: &Connection,
    package_id: &str,
) -> Result<Option<PackageLifecycleRetentionRecord>> {
    let trimmed = package_id.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let lock_alias = af_models::resolve_package_lock_name(trimmed);
    let sanitized_trimmed = sanitize_persisted_text(trimmed);
    let sanitized_lock_alias = af_models::resolve_package_lock_name(&sanitized_trimmed);

    let jobs_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='package_lifecycle_jobs')",
        [],
        |row| row.get(0),
    )?;
    if jobs_exists {
        let has_retention: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_jobs') WHERE name='retention_state')",
            [],
            |row| row.get(0),
        )?;
        let has_finished: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_jobs') WHERE name='finished_at')",
            [],
            |row| row.get(0),
        )?;
        let sql = format!(
            "SELECT package_id, job_id, action, status, {}, {} \
             FROM package_lifecycle_jobs \
             WHERE (LOWER(package_id)=LOWER(?1) OR LOWER(package_id)=LOWER(?2) \
                    OR LOWER(package_id)=LOWER(?3) OR LOWER(package_id)=LOWER(?4)) \
               AND status='completed' \
             LIMIT 1",
            if has_retention {
                "retention_state"
            } else {
                "''"
            },
            if has_finished { "finished_at" } else { "''" },
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(params![
            trimmed,
            lock_alias,
            sanitized_trimmed,
            sanitized_lock_alias
        ])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(PackageLifecycleRetentionRecord {
                package_id: sanitize_persisted_text(&row.get::<_, String>(0)?),
                job_id: sanitize_persisted_text(&row.get::<_, String>(1)?),
                action: sanitize_persisted_text(&row.get::<_, String>(2)?),
                status: sanitize_history_text_field(row.get(3)?),
                retention_state: sanitize_history_text_field(row.get(4)?),
                finished_at: sanitize_history_text_field(row.get(5)?),
            }));
        }
    }

    let hist_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='package_lifecycle_history')",
        [],
        |row| row.get(0),
    )?;
    if !hist_exists {
        return Ok(None);
    }
    let has_hist_retention: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_history') WHERE name='retention_state')",
        [],
        |row| row.get(0),
    )?;
    let has_hist_finished: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_history') WHERE name='finished_at')",
        [],
        |row| row.get(0),
    )?;
    let sql = format!(
        "SELECT package_id, job_id, action, status, {}, {} \
         FROM package_lifecycle_history \
         WHERE (LOWER(package_id)=LOWER(?1) OR LOWER(package_id)=LOWER(?2) \
                OR LOWER(package_id)=LOWER(?3) OR LOWER(package_id)=LOWER(?4)) \
           AND status='completed' \
         ORDER BY id DESC \
         LIMIT 1",
        if has_hist_retention {
            "retention_state"
        } else {
            "''"
        },
        if has_hist_finished {
            "finished_at"
        } else {
            "''"
        },
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params![
        trimmed,
        lock_alias,
        sanitized_trimmed,
        sanitized_lock_alias
    ])?;
    if let Some(row) = rows.next()? {
        return Ok(Some(PackageLifecycleRetentionRecord {
            package_id: sanitize_persisted_text(&row.get::<_, String>(0)?),
            job_id: sanitize_persisted_text(&row.get::<_, String>(1)?),
            action: sanitize_persisted_text(&row.get::<_, String>(2)?),
            status: sanitize_history_text_field(row.get(3)?),
            retention_state: sanitize_history_text_field(row.get(4)?),
            finished_at: sanitize_history_text_field(row.get(5)?),
        }));
    }
    Ok(None)
}

/// Returns the set of canonical lowercase package lock stems whose most
/// recently completed lifecycle record across `package_lifecycle_jobs` and
/// `package_lifecycle_history` is an ordinary retained removal
/// (`action='remove'`, `status='completed'`, `retention_state='retained'`).
///
/// Tolerates older schemas without `retention_state` or
/// `package_lifecycle_history`, failing closed for records without positive
/// retained provenance.
pub fn query_retained_lifecycle_packages(
    conn: &Connection,
) -> Result<std::collections::HashSet<String>> {
    let mut resolved = std::collections::HashSet::new();
    let mut retained = std::collections::HashSet::new();
    for table in ["package_lifecycle_jobs", "package_lifecycle_history"] {
        let columns: std::collections::HashSet<String> = conn
            .prepare("SELECT name FROM pragma_table_info(?1)")?
            .query_map([table], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        if columns.is_empty() {
            continue;
        }
        let retention = if columns.contains("retention_state") {
            "COALESCE(retention_state, '')"
        } else {
            "''"
        };
        let order = if table == "package_lifecycle_history" {
            "id DESC"
        } else if columns.contains("finished_at") {
            "finished_at DESC, started_at DESC"
        } else {
            "started_at DESC"
        };
        let sql = format!(
            "SELECT package_id, action, {retention} FROM {table}
             WHERE status = 'completed' ORDER BY {order}"
        );
        let mut statement = conn.prepare(&sql)?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let package_id = sanitize_persisted_text(&row.get::<_, String>(0)?);
            let action: String = row.get(1)?;
            let retention_state: String = row.get(2)?;
            let key =
                af_models::resolve_package_lock_name(&package_id.to_ascii_lowercase()).to_string();
            if !key.is_empty()
                && resolved.insert(key.clone())
                && action == "remove"
                && retention_state == RETENTION_STATE_RETAINED
            {
                retained.insert(key);
            }
        }
    }
    Ok(retained)
}

pub fn record_completed_lifecycle_job(
    conn: &Connection,
    package: &str,
    job_id: &str,
    action: &str,
    sanitized_summary: Option<&str>,
    expected_target_version: Option<&str>,
    achieved_version: Option<&str>,
) -> Result<()> {
    finish_job_with_diagnostics(
        conn,
        package,
        job_id,
        action,
        true,
        LifecycleJobDiagnostics {
            exit_code: Some(0),
            sanitized_summary,
            expected_target_version,
            achieved_version,
            ..Default::default()
        },
    )
}

pub fn sanitize_persisted_text(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let trimmed = raw.trim();
    if trimmed.starts_with(['{', '[']) {
        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(_) => return super::diagnostic_projection::redact_secrets(raw),
            Err(err) if err.to_string().contains("recursion limit") => {
                return super::diagnostic_projection::redact_balanced_structured_secrets(raw);
            }
            Err(_) => {}
        }
    }
    if raw.as_bytes().iter().any(|&b| b == b'{' || b == b'[') {
        let with_embedded = super::diagnostic_projection::redact_embedded_json_spans(raw);
        sanitize_persisted_lifecycle_text(&with_embedded)
    } else {
        sanitize_persisted_lifecycle_text(raw)
    }
}

fn parse_service_units_json_safe(raw: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_default()
}

fn sanitize_service_units_json(raw: &str) -> String {
    let sanitized: Vec<String> = parse_service_units_json_safe(raw)
        .into_iter()
        .map(|unit| sanitize_persisted_text(&unit))
        .collect();
    serde_json::to_string(&sanitized).unwrap_or_else(|_| "[]".to_string())
}

fn sanitize_history_text_field(raw: String) -> String {
    if raw.is_empty() {
        raw
    } else {
        super::diagnostic_projection::redact_secrets(&raw)
    }
}

fn sanitize_optional_history_field(raw: Option<String>) -> Option<String> {
    let value = raw?;
    if value.is_empty() {
        None
    } else {
        Some(super::diagnostic_projection::redact_secrets(&value))
    }
}

pub fn get_lifecycle_history(
    conn: &Connection,
    package_id: &str,
    limit: usize,
) -> Result<Vec<af_models::PackageLifecycleRecord>> {
    let sanitized_pkg = sanitize_persisted_text(package_id);
    let projected_pkg = sanitize_history_text_field(package_id.to_string());
    let mut stmt = conn.prepare(
        "SELECT package_id, job_id, action, status, started_at, finished_at, owner_id, service_units,
                failure_category, failed_stage, exit_code, sanitized_summary, expected_target_version, achieved_version
         FROM package_lifecycle_history
         WHERE package_id = ?1 OR package_id = ?2 OR package_id = ?3
         ORDER BY id DESC LIMIT ?4",
    )?;
    let records = stmt
        .query_map(
            params![package_id, sanitized_pkg, projected_pkg, limit as i64],
            |row| {
                let started_at = sanitize_history_text_field(row.get(4)?);
                let finished_at = sanitize_history_text_field(row.get(5)?);
                let owner_id = sanitize_history_text_field(row.get(6)?);
                let service_units_raw: String = row.get(7)?;
                let service_units = parse_service_units_json_safe(&service_units_raw)
                    .into_iter()
                    .map(sanitize_history_text_field)
                    .collect();
                let failure_category = sanitize_history_text_field(row.get(8)?);
                let failed_stage = sanitize_optional_history_field(row.get(9)?);
                let sanitized_summary = sanitize_optional_history_field(row.get(11)?);
                let expected_target_version = sanitize_optional_history_field(row.get(12)?);
                let achieved_version = sanitize_optional_history_field(row.get(13)?);
                Ok(af_models::PackageLifecycleRecord {
                    package_id: sanitize_persisted_text(&row.get::<_, String>(0)?),
                    job_id: sanitize_persisted_text(&row.get::<_, String>(1)?),
                    action: sanitize_persisted_text(&row.get::<_, String>(2)?),
                    status: sanitize_history_text_field(row.get(3)?),
                    started_at,
                    finished_at,
                    owner_id,
                    service_units,
                    failure_category,
                    failed_stage,
                    exit_code: row.get(10)?,
                    sanitized_summary,
                    expected_target_version,
                    achieved_version,
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(records)
}

pub fn check_reservation(
    conn: &Connection,
    target: ReservationTarget<'_>,
    job_id: &str,
    action: Option<&str>,
) -> Result<()> {
    let job_id_sanitized = sanitize_persisted_text(job_id);
    let action_sanitized = action.map(sanitize_persisted_text);
    let resources = match target {
        ReservationTarget::Package(package) => {
            let package_sanitized = sanitize_persisted_text(package);
            let mut units = Vec::new();
            if !job_id_sanitized.is_empty() {
                let table: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='package_lifecycle_jobs')",
                    [], |row| row.get(0),
                )?;
                if table {
                    let mut statement = conn.prepare("SELECT service_units FROM package_lifecycle_jobs WHERE (package_id=?1 OR package_id=?2) AND (job_id=?3 OR job_id=?4)")?;
                    for raw in statement.query_map(
                        params![package_sanitized, package, job_id_sanitized, job_id],
                        |row| row.get::<_, String>(0),
                    )? {
                        units.extend(parse_service_units_json_safe(&raw?));
                    }
                }
            }
            return check_package_reservation(
                conn,
                package,
                &units,
                job_id,
                action_sanitized.as_deref(),
            );
        }
        ReservationTarget::Service(service) => {
            let service_sanitized = sanitize_persisted_text(service);
            Some(package_resources(&service_sanitized, &[]))
        }
        ReservationTarget::System => None,
    };
    check_resources(
        conn,
        resources,
        &job_id_sanitized,
        action_sanitized.as_deref(),
    )
}

fn check_resources(
    conn: &Connection,
    resources: Option<BTreeSet<String>>,
    job_id: &str,
    action: Option<&str>,
) -> Result<()> {
    let table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='package_lifecycle_jobs')",
        [], |row| row.get(0),
    )?;
    if !table {
        anyhow::ensure!(job_id.is_empty(), "lifecycle reservation not found");
        return Ok(());
    }
    let jobs: Vec<(String, String, String, String, String)> = conn
        .prepare(
            "SELECT package_id,job_id,action,service_units,status FROM package_lifecycle_jobs
         WHERE status NOT IN ('completed','failed','interrupted')",
        )?
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut matched_owner = false;
    for (package, reserved_job, reserved_action, units, status) in jobs {
        let sanitized_pkg = sanitize_persisted_text(&package);
        let display_package = sanitized_pkg.as_str();
        anyhow::ensure!(
            resources.is_some(),
            "Application lifecycle reservation is active for {display_package}; core service control is unavailable"
        );
        let parsed_units = parse_service_units_json_safe(&units);
        let sanitized_units: Vec<String> = parsed_units
            .iter()
            .map(|unit| sanitize_persisted_text(unit))
            .collect();
        let mut reserved_resources = package_resources(&sanitized_pkg, &sanitized_units);
        if sanitized_pkg != package
            || sanitized_units
                .iter()
                .zip(parsed_units.iter())
                .any(|(sanitized, raw)| sanitized != raw)
        {
            reserved_resources.extend(package_resources(&package, &parsed_units));
        }
        let matches_target = !resources.as_ref().unwrap().is_disjoint(&reserved_resources);
        if matches_target {
            let expected_status = match reserved_action.as_str() {
                "install" | "reinstall" => "installing",
                "update" => "updating",
                "remove" => "uninstalling",
                _ => anyhow::bail!("Lifecycle reservation action is unknown for {display_package}"),
            };
            anyhow::ensure!(
                status == expected_status,
                "Lifecycle reservation phase is unknown for {display_package}"
            );
            anyhow::ensure!(
                !job_id.is_empty()
                    && (reserved_job == job_id || sanitize_persisted_text(&reserved_job) == job_id),
                "Application lifecycle reservation is active for {display_package}"
            );
            anyhow::ensure!(
                action.is_none_or(|value| value == reserved_action),
                "Lifecycle reservation action does not match"
            );
            matched_owner = true;
        }
    }
    anyhow::ensure!(
        job_id.is_empty() || matched_owner,
        "Lifecycle reservation is missing or no longer active"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_lifecycle_history_resanitizes_tampered_and_legacy_rows_on_read() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let pw_key = concat!("pass", "word");
        let pa_key = concat!("pa", "ss");
        let tok_key = concat!("tok", "en");
        let api_key = concat!("api_", "key");
        let cat_raw = format!("https://admin:CAT_URL_R15@example.com {pw_key}=CAT_PW_R15");
        let stage_raw = format!(r#"{{"{pw_key}": "STAGE_CANARY_R14"}}"#);
        let summary_raw = format!(
            "Bearer SUMMARY_BEARER_R14; café_{pa_key}=SUMMARY_CAFE_R14; {pw_key}=\\u0022part1 SUMMARY_U22_R14\\u0022"
        );
        let expected_raw =
            format!("https://admin:EXPECTED_URL_R14@example.com/pkg --{tok_key}=EXPECTED_TOK_R14");
        let achieved_raw = r#"{"user (primary)": "admin:ACHIEVED_USER_R14"}"#;

        // Simulate a legacy or out-of-band SQLite row inserted without write-side sanitization.
        conn.execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, finished_at, owner_id,
                service_units, failure_category, failed_stage, exit_code, sanitized_summary,
                expected_target_version, achieved_version, recovery_state, retention_state
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, '', '[]', ?7, ?8, 1, ?9, ?10, ?11, '', '')",
            params![
                "legacy-pkg",
                "job-legacy-1",
                "update",
                "failed",
                "2026-11-27T00:00:00Z",
                "2026-11-27T00:01:00Z",
                cat_raw,
                stage_raw,
                summary_raw,
                expected_raw,
                achieved_raw,
            ],
        )
        .unwrap();

        // Insert a second row with benign empty / clean fields to ensure non-secrets stay intact.
        conn.execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, finished_at, owner_id,
                service_units, failure_category, failed_stage, exit_code, sanitized_summary,
                expected_target_version, achieved_version, recovery_state, retention_state
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, '', '[]', '', '', 0, ?7, '2.4.1', '2.4.1', '', '')",
            params![
                "legacy-pkg",
                "job-benign-2",
                "update",
                "completed",
                "2026-11-27T00:02:00Z",
                "2026-11-27T00:03:00Z",
                r#"{"path": "C:\\t-u benign_arg"}"#,
            ],
        )
        .unwrap();

        // Insert a third tampered row carrying duplicate-key JSON secrets (Carbon W1A-R14-02)
        // in failure_category and sanitized_summary, plus a benign static failure_category row.
        let dup_cat_raw = r#"{"msg": "Authorization: Bearer DUP_CAT_R15", "msg": "ok"}"#;
        let dup_sum_raw =
            format!(r#"{{"config": {{"{api_key}": "DUP_SUM_R15"}}, "config": {{}}}}"#);
        conn.execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, finished_at, owner_id,
                service_units, failure_category, failed_stage, exit_code, sanitized_summary,
                expected_target_version, achieved_version, recovery_state, retention_state
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, '', '[]', ?7, 'installer', 1, ?8, '2.5.0', '', '', '')",
            params![
                "legacy-pkg",
                "job-dup-3",
                "update",
                "failed",
                "2026-11-27T00:04:00Z",
                "2026-11-27T00:05:00Z",
                dup_cat_raw,
                dup_sum_raw,
            ],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, finished_at, owner_id,
                service_units, failure_category, failed_stage, exit_code, sanitized_summary,
                expected_target_version, achieved_version, recovery_state, retention_state
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, '', '[]', 'install_failed', 'installer', 1, 'exit code 1', '2.5.1', '', '', '')",
            params![
                "legacy-pkg",
                "job-static-4",
                "install",
                "failed",
                "2026-11-27T00:06:00Z",
                "2026-11-27T00:07:00Z",
            ],
        )
        .unwrap();

        let history = get_lifecycle_history(&conn, "legacy-pkg", 10).unwrap();
        assert_eq!(history.len(), 4);

        // Newest row first (ORDER BY id DESC): benign static category preserved identically.
        let static_row = &history[0];
        assert_eq!(static_row.job_id, "job-static-4");
        assert_eq!(static_row.failure_category, "install_failed");

        // Duplicate-key JSON row: overwritten secrets scrubbed on read, valid JSON preserved.
        let dup_row = &history[1];
        assert_eq!(dup_row.job_id, "job-dup-3");
        assert!(
            !dup_row.failure_category.contains("DUP_CAT_R15"),
            "duplicate-key failure_category leaked: {}",
            dup_row.failure_category
        );
        serde_json::from_str::<serde_json::Value>(&dup_row.failure_category).unwrap();
        let dup_sum = dup_row.sanitized_summary.as_deref().unwrap();
        assert!(
            !dup_sum.contains("DUP_SUM_R15"),
            "duplicate-key summary leaked: {dup_sum}"
        );
        serde_json::from_str::<serde_json::Value>(dup_sum).unwrap();

        // Benign empty / clean row: empty failure_category stays empty & empty optionals -> None.
        let benign = &history[2];
        assert_eq!(benign.job_id, "job-benign-2");
        assert_eq!(benign.failure_category, "");
        assert_eq!(benign.failed_stage, None);
        assert_eq!(
            benign.sanitized_summary.as_deref(),
            Some(r#"{"path": "C:\\t-u benign_arg"}"#)
        );
        assert_eq!(benign.expected_target_version.as_deref(), Some("2.4.1"));
        assert_eq!(benign.achieved_version.as_deref(), Some("2.4.1"));

        // Legacy/tampered row: every secret (including failure_category) re-sanitized on read.
        let legacy = &history[3];
        assert_eq!(legacy.job_id, "job-legacy-1");
        assert!(
            !legacy.failure_category.contains("CAT_URL_R15"),
            "failure_category leaked URL secret: {}",
            legacy.failure_category
        );
        assert!(
            !legacy.failure_category.contains("CAT_PW_R15"),
            "failure_category leaked pw secret: {}",
            legacy.failure_category
        );
        assert!(legacy
            .failure_category
            .contains("https://[REDACTED]@example.com"));

        let stage = legacy.failed_stage.as_deref().unwrap();
        assert!(!stage.contains("STAGE_CANARY_R14"), "stage leaked: {stage}");
        assert!(stage.contains("[REDACTED]"), "stage unredacted: {stage}");
        serde_json::from_str::<serde_json::Value>(stage).unwrap();

        let summary = legacy.sanitized_summary.as_deref().unwrap();
        for leaked in ["SUMMARY_BEARER_R14", "SUMMARY_CAFE_R14", "SUMMARY_U22_R14"] {
            assert!(
                !summary.contains(leaked),
                "summary leaked {leaked}: {summary}"
            );
        }
        assert!(summary.contains("[REDACTED]"));

        let expected = legacy.expected_target_version.as_deref().unwrap();
        assert!(
            !expected.contains("EXPECTED_URL_R14"),
            "expected leaked: {expected}"
        );
        assert!(
            !expected.contains("EXPECTED_TOK_R14"),
            "expected leaked: {expected}"
        );
        assert!(expected.contains("https://[REDACTED]@example.com/pkg"));

        let achieved = legacy.achieved_version.as_deref().unwrap();
        assert!(
            !achieved.contains("ACHIEVED_USER_R14"),
            "achieved leaked: {achieved}"
        );
        assert!(achieved.contains("[REDACTED]"));
        serde_json::from_str::<serde_json::Value>(achieved).unwrap();

        // Write-side sanitization verification (Team 8 F-07 = Neon AUD-10):
        // finish_job_with_diagnostics must sanitize failure_category before persisting to SQLite,
        // preserve static categories like "install_failed", and store "" on success.
        let seed_and_finish =
            |pkg: &str, job_id: &str, success: bool, raw_cat: &str, raw_summary: Option<&str>| {
                conn.execute(
                "INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at)
                 VALUES (?1,?2,'install','installing','2026-11-27T01:00:00Z')",
                params![pkg, job_id],
            )
            .unwrap();
                conn.execute(
                "INSERT INTO package_lifecycle_history (package_id,job_id,action,status,started_at)
                 VALUES (?1,?2,'install','installing','2026-11-27T01:00:00Z')",
                params![pkg, job_id],
            )
            .unwrap();
                finish_job_with_diagnostics(
                    &conn,
                    pkg,
                    job_id,
                    "install",
                    success,
                    LifecycleJobDiagnostics {
                        failure_category: raw_cat,
                        failed_stage: Some("installer"),
                        exit_code: Some(if success { 0 } else { 1 }),
                        sanitized_summary: raw_summary,
                        finished_at: Some("2026-11-27T01:01:00Z"),
                        ..Default::default()
                    },
                )
                .unwrap();
            };
        seed_and_finish(
            "write-secret-pkg",
            "job-write-secret",
            false,
            "https://admin:WRITE_CAT_URL_R15@example.com",
            Some(r#"{"err": "Digest username=\"alice\",\n  response=\"WRITE_DIGEST_R15\""}"#),
        );
        seed_and_finish(
            "write-static-pkg",
            "job-write-static",
            false,
            "install_failed",
            Some("installer exited with code 1"),
        );
        seed_and_finish(
            "write-ok-pkg",
            "job-write-ok",
            true,
            "https://admin:IGNORED_SUCCESS_CAT_R15@example.com",
            Some("completed"),
        );

        let assert_table_rows = |table: &str| {
            let (secret_cat, secret_sum): (String, String) = conn
                .query_row(
                    &format!(
                        "SELECT failure_category, sanitized_summary FROM {table} WHERE job_id='job-write-secret'"
                    ),
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert!(
                !secret_cat.contains("WRITE_CAT_URL_R15"),
                "{table} persisted unsanitized failure_category: {secret_cat}"
            );
            assert_eq!(secret_cat, "https://[REDACTED]@example.com");
            assert!(
                !secret_sum.contains("WRITE_DIGEST_R15"),
                "{table} persisted unsanitized folded Digest summary: {secret_sum}"
            );

            let static_cat: String = conn
                .query_row(
                    &format!(
                        "SELECT failure_category FROM {table} WHERE job_id='job-write-static'"
                    ),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(static_cat, "install_failed");

            let ok_cat: String = conn
                .query_row(
                    &format!("SELECT failure_category FROM {table} WHERE job_id='job-write-ok'"),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(ok_cat, "");
        };
        assert_table_rows("package_lifecycle_jobs");
        assert_table_rows("package_lifecycle_history");

        let secret_hist = get_lifecycle_history(&conn, "write-secret-pkg", 5).unwrap();
        assert_eq!(secret_hist.len(), 1);
        assert_eq!(
            secret_hist[0].failure_category,
            "https://[REDACTED]@example.com"
        );
        assert!(!secret_hist[0]
            .sanitized_summary
            .as_deref()
            .unwrap()
            .contains("WRITE_DIGEST_R15"));

        let static_hist = get_lifecycle_history(&conn, "write-static-pkg", 5).unwrap();
        assert_eq!(static_hist.len(), 1);
        assert_eq!(static_hist[0].failure_category, "install_failed");

        let ok_hist = get_lifecycle_history(&conn, "write-ok-pkg", 5).unwrap();
        assert_eq!(ok_hist.len(), 1);
        assert_eq!(ok_hist[0].failure_category, "");
    }

    #[test]
    fn wave1a_r16_sqlite_write_read_metadata_json_and_two_stage_sanitization() {
        let root = std::env::temp_dir().join(format!("af-jobs-r16-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let db_path = root.join("lifecycle.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        initialize_schema(&conn).unwrap();

        let pw_k = concat!("pass", "word");
        let pa_k = concat!("pa", "ss");
        let tok_k = concat!("tok", "en");

        // 1. Carbon W1A-AUD-06 + Neon AUD-02 write-side sanitization & JSON preservation
        let dirty_started = "2026-11-27T00:00:00Z https://admin:START_AT_SECRET_R16@example.com";
        let dirty_unit = format!("app --{pw_k}=UNIT_SECRET_R16");
        let target_json = format!(r#"{{"\t{pa_k}": "TARGET_TAB_SECRET_R16"}}"#);
        let lease = admit_job_with_target(
            &mut conn,
            "r16-pkg",
            "job-r16-write",
            "update",
            dirty_started,
            &[dirty_unit, "sonarr.service".to_string()],
            Some(&target_json),
        )
        .unwrap();

        let stage_json = format!(r#"{{"{pw_k}": "STAGE_JSON_SECRET_R16"}}"#);
        let two_stage_summary = r#"{"msg": "X-Api-Key: \nTWO_STAGE_SUM_SECRET_R16"}"#;
        let dirty_finished = "2026-11-27T00:01:00Z Authorization: Bearer FIN_AT_SECRET_R16";
        finish_job_with_diagnostics(
            &conn,
            "r16-pkg",
            "job-r16-write",
            "update",
            false,
            LifecycleJobDiagnostics {
                failure_category: "installer",
                failed_stage: Some(&stage_json),
                exit_code: Some(1),
                sanitized_summary: Some(two_stage_summary),
                expected_target_version: None,
                achieved_version: Some(r#"{"msg": "Cookie:\nHost: example.com"}"#),
                finished_at: Some(dirty_finished),
                ..Default::default()
            },
        )
        .unwrap();

        let assert_written_row = |table: &str| {
            let (s_at, f_at, owner, units, stage, sum, exp, ach): (
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                String,
            ) = conn
                .query_row(
                    &format!(
                        "SELECT started_at, finished_at, owner_id, service_units, failed_stage, sanitized_summary, expected_target_version, achieved_version FROM {table} WHERE job_id='job-r16-write'"
                    ),
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                            row.get(7)?,
                        ))
                    },
                )
                .unwrap();
            assert!(!s_at.contains("START_AT_SECRET_R16"), "{table}: {s_at}");
            assert!(s_at.contains("2026-11-27T00:00:00Z"), "{table}: {s_at}");
            assert!(!f_at.contains("FIN_AT_SECRET_R16"), "{table}: {f_at}");
            assert!(f_at.contains("2026-11-27T00:01:00Z"), "{table}: {f_at}");
            assert_eq!(
                owner, lease.id,
                "{table} must preserve normal UUID owner_id"
            );
            assert!(
                !units.to_ascii_lowercase().contains("unit_secret_r16"),
                "{table}: {units}"
            );
            assert!(units.contains("sonarr"), "{table}: {units}");
            assert!(!stage.contains("STAGE_JSON_SECRET_R16"), "{table}: {stage}");
            let stage_val: serde_json::Value = serde_json::from_str(&stage).unwrap_or_else(|e| {
                panic!("{table} failed_stage must remain valid JSON ({e}): {stage}")
            });
            assert_eq!(stage_val[pw_k], "[REDACTED]");
            assert!(!sum.contains("TWO_STAGE_SUM_SECRET_R16"), "{table}: {sum}");
            let sum_val: serde_json::Value = serde_json::from_str(&sum)
                .unwrap_or_else(|e| panic!("{table} summary must remain valid JSON ({e}): {sum}"));
            assert!(
                sum_val["msg"].as_str().unwrap().contains("[REDACTED]"),
                "{table}: {sum}"
            );
            assert!(!exp.contains("TARGET_TAB_SECRET_R16"), "{table}: {exp}");
            serde_json::from_str::<serde_json::Value>(&exp).unwrap_or_else(|e| {
                panic!("{table} expected_target_version must remain valid JSON ({e}): {exp}")
            });
            assert_eq!(
                ach, r#"{"msg": "Cookie:\nHost: example.com"}"#,
                "{table} must not inject spurious [REDACTED] on benign empty header"
            );
        };
        assert_written_row("package_lifecycle_jobs");
        assert_written_row("package_lifecycle_history");

        // Two-stage read-back via get_lifecycle_history must keep valid JSON and zero leaks.
        let write_hist = get_lifecycle_history(&conn, "r16-pkg", 5).unwrap();
        assert_eq!(write_hist.len(), 1);
        assert!(!write_hist[0].started_at.contains("START_AT_SECRET_R16"));
        assert!(!write_hist[0].finished_at.contains("FIN_AT_SECRET_R16"));
        assert_eq!(write_hist[0].owner_id, lease.id);
        assert!(write_hist[0]
            .service_units
            .iter()
            .all(|u| !u.to_ascii_lowercase().contains("unit_secret_r16")));
        assert!(write_hist[0].service_units.iter().any(|u| u == "sonarr"));
        let read_stage = write_hist[0].failed_stage.as_deref().unwrap();
        assert!(!read_stage.contains("STAGE_JSON_SECRET_R16"));
        serde_json::from_str::<serde_json::Value>(read_stage).unwrap();
        let read_sum = write_hist[0].sanitized_summary.as_deref().unwrap();
        assert!(!read_sum.contains("TWO_STAGE_SUM_SECRET_R16"));
        serde_json::from_str::<serde_json::Value>(read_sum).unwrap();

        // 2. Normal ISO timestamps, normal service units, and benign retention states stay untouched
        let benign_lease = admit_job_with_target(
            &mut conn,
            "benign-r16",
            "job-benign-r16",
            "remove",
            "2026-11-27T02:00:00Z",
            &["sonarr.service".to_string()],
            Some("2.0.0"),
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "benign-r16",
            "job-benign-r16",
            "remove",
            true,
            LifecycleJobDiagnostics {
                finished_at: Some("2026-11-27T02:01:00Z"),
                retention_state: Some(RETENTION_STATE_RETAINED),
                ..Default::default()
            },
        )
        .unwrap();
        let benign_hist = get_lifecycle_history(&conn, "benign-r16", 5).unwrap();
        assert_eq!(benign_hist.len(), 1);
        assert_eq!(benign_hist[0].started_at, "2026-11-27T02:00:00Z");
        assert_eq!(benign_hist[0].finished_at, "2026-11-27T02:01:00Z");
        assert_eq!(benign_hist[0].owner_id, benign_lease.id);
        assert_eq!(benign_hist[0].service_units, vec!["benign-r16", "sonarr"]);
        let benign_ret = query_package_retention_history(&conn, "benign-r16")
            .unwrap()
            .expect("benign retention record");
        assert_eq!(benign_ret.retention_state, RETENTION_STATE_RETAINED);
        assert_eq!(benign_ret.finished_at, "2026-11-27T02:01:00Z");

        // 3. Tampered/legacy SQLite rows: read-side sanitization in get_lifecycle_history &
        // query_package_retention_history (both package_lifecycle_jobs and package_lifecycle_history)
        let tamper_started = format!("2026-11-27 --{pw_k}=START_TAMPER_R16");
        let tamper_finished = format!("2026-11-27 --{tok_k}=RET_FIN_SECRET_R16");
        let tamper_owner = format!("owner --{pw_k}=OWNER_SECRET_R16");
        let tamper_units = serde_json::to_string(&vec![
            format!("app --{pw_k}=UNIT_TAMPER_R16"),
            "sonarr.service".to_string(),
        ])
        .unwrap();
        let tamper_retention = "retained Authorization: Bearer RET_STATE_SECRET_R16";
        let tamper_summary =
            format!(r#"[info: 5" disk] {{"\t{pa_k}": "AUD03_SQLITE_SECRET_R16"}}"#);

        conn.execute(
            "INSERT INTO package_lifecycle_jobs (
                package_id, job_id, action, status, started_at, finished_at, owner_id,
                service_units, failure_category, failed_stage, exit_code, sanitized_summary,
                expected_target_version, achieved_version, recovery_state, retention_state
            ) VALUES (?1, ?2, 'remove', 'completed', ?3, ?4, ?5, ?6, '', '', 0, ?7, '', '', '', ?8)",
            params![
                "tamper-jobs-pkg",
                "job-tamper-jobs",
                tamper_started,
                tamper_finished,
                tamper_owner,
                tamper_units,
                tamper_summary,
                tamper_retention,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, finished_at, owner_id,
                service_units, failure_category, failed_stage, exit_code, sanitized_summary,
                expected_target_version, achieved_version, recovery_state, retention_state
            ) VALUES (?1, ?2, 'remove', 'completed', ?3, ?4, ?5, ?6, '', '', 0, ?7, '', '', '', ?8)",
            params![
                "tamper-hist-pkg",
                "job-tamper-hist",
                tamper_started,
                tamper_finished,
                tamper_owner,
                tamper_units,
                tamper_summary,
                tamper_retention,
            ],
        )
        .unwrap();

        let jobs_ret = query_package_retention_history(&conn, "tamper-jobs-pkg")
            .unwrap()
            .expect("jobs retention record");
        assert!(!jobs_ret.retention_state.contains("RET_STATE_SECRET_R16"));
        assert!(jobs_ret.retention_state.contains("[REDACTED]"));
        assert!(!jobs_ret.finished_at.contains("RET_FIN_SECRET_R16"));
        assert!(jobs_ret.finished_at.contains("[REDACTED]"));

        let hist_ret = query_package_retention_history(&conn, "tamper-hist-pkg")
            .unwrap()
            .expect("history retention record");
        assert!(!hist_ret.retention_state.contains("RET_STATE_SECRET_R16"));
        assert!(hist_ret.retention_state.contains("[REDACTED]"));
        assert!(!hist_ret.finished_at.contains("RET_FIN_SECRET_R16"));
        assert!(hist_ret.finished_at.contains("[REDACTED]"));

        let tamper_hist = get_lifecycle_history(&conn, "tamper-hist-pkg", 5).unwrap();
        assert_eq!(tamper_hist.len(), 1);
        assert!(!tamper_hist[0].started_at.contains("START_TAMPER_R16"));
        assert!(!tamper_hist[0].finished_at.contains("RET_FIN_SECRET_R16"));
        assert!(!tamper_hist[0].owner_id.contains("OWNER_SECRET_R16"));
        assert!(tamper_hist[0]
            .service_units
            .iter()
            .all(|u| !u.contains("UNIT_TAMPER_R16")));
        assert!(tamper_hist[0]
            .service_units
            .iter()
            .any(|u| u == "sonarr.service"));
        assert!(!tamper_hist[0]
            .sanitized_summary
            .as_deref()
            .unwrap()
            .contains("AUD03_SQLITE_SECRET_R16"));

        drop(benign_lease);
        drop(lease);
        drop(conn);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn wave1a_r17_deep_json_fallback_target_and_tampered_identity_sanitization() {
        let root = std::env::temp_dir().join(format!("af-jobs-r17-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let db_path = root.join("lifecycle.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        initialize_schema(&conn).unwrap();

        let pw_k = concat!("pass", "word");
        let tok_k = concat!("tok", "en");

        // 1. Neon F-10 part 1: deep valid RFC 8259 JSON (>128 depth) must preserve quoted
        //    `"[REDACTED]"` in SQLite instead of emitting unquoted `[REDACTED]`.
        let deep_json = format!(
            "{{\"{pw_k}\":\"SECRET_DEEP_SQL_R17\",\"deep\":{}1{}}}",
            "{\"a\":".repeat(130),
            "}".repeat(130)
        );
        let deep_lease = admit_job_with_target(
            &mut conn,
            "deep-r17-pkg",
            "job-deep-r17",
            "update",
            "2026-11-27T04:00:00Z",
            &["sonarr.service".to_string()],
            Some("3.1.0"),
        )
        .unwrap();
        record_completed_lifecycle_job(
            &conn,
            "deep-r17-pkg",
            "job-deep-r17",
            "update",
            Some(&deep_json),
            None,
            Some("3.1.0"),
        )
        .unwrap();

        let expected_quoted_pair = format!("\"{pw_k}\":\"[REDACTED]\"");
        let forbidden_unquoted_pair = format!("\"{pw_k}\":[REDACTED]");
        let assert_deep_row = |table: &str| {
            let stored: String = conn
                .query_row(
                    &format!(
                        "SELECT sanitized_summary FROM {table} WHERE package_id='deep-r17-pkg' AND job_id='job-deep-r17'"
                    ),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                !stored.contains("SECRET_DEEP_SQL_R17"),
                "{table} leaked deep JSON secret: {stored}"
            );
            assert!(
                stored.contains(&expected_quoted_pair),
                "{table} must quote [REDACTED] in >128-deep JSON: {}",
                &stored[..stored.len().min(96)]
            );
            assert!(
                !stored.contains(&forbidden_unquoted_pair),
                "{table} emitted invalid unquoted JSON token: {}",
                &stored[..stored.len().min(96)]
            );
            assert_eq!(sanitize_persisted_text(&stored), stored);
        };
        assert_deep_row("package_lifecycle_jobs");
        assert_deep_row("package_lifecycle_history");

        let deep_hist = get_lifecycle_history(&conn, "deep-r17-pkg", 5).unwrap();
        assert_eq!(deep_hist.len(), 1);
        let read_deep = deep_hist[0].sanitized_summary.as_deref().unwrap();
        assert!(!read_deep.contains("SECRET_DEEP_SQL_R17"));
        assert!(read_deep.contains(&expected_quoted_pair));
        assert!(!read_deep.contains(&forbidden_unquoted_pair));

        // 2. Team 8 F-08: finish_job_with_diagnostics fallback (hist_updated == 0) preserves
        //    expected_target_version stored on package_lifecycle_jobs when diagnostics omits it,
        //    sanitizes legacy tampered values, and still honors an explicit override.
        let fb_lease = admit_job_with_target(
            &mut conn,
            "fallback-r17-pkg",
            "job-fb-r17",
            "update",
            "2026-11-27T04:05:00Z",
            &["sonarr.service".to_string()],
            Some("4.2.0"),
        )
        .unwrap();
        conn.execute(
            "DELETE FROM package_lifecycle_history WHERE package_id='fallback-r17-pkg' AND job_id='job-fb-r17'",
            [],
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "fallback-r17-pkg",
            "job-fb-r17",
            "update",
            true,
            LifecycleJobDiagnostics {
                expected_target_version: None,
                achieved_version: Some("4.2.0"),
                finished_at: Some("2026-11-27T04:06:00Z"),
                ..Default::default()
            },
        )
        .unwrap();
        let fb_hist = get_lifecycle_history(&conn, "fallback-r17-pkg", 5).unwrap();
        assert_eq!(fb_hist.len(), 1);
        assert_eq!(fb_hist[0].expected_target_version.as_deref(), Some("4.2.0"));
        assert_eq!(fb_hist[0].achieved_version.as_deref(), Some("4.2.0"));

        // Explicit diagnostics override still wins in fallback insert.
        let fb_override_lease = admit_job_with_target(
            &mut conn,
            "fallback-override-r17",
            "job-fb-ovr-r17",
            "update",
            "2026-11-27T04:07:00Z",
            &[],
            Some("4.2.0"),
        )
        .unwrap();
        conn.execute(
            "DELETE FROM package_lifecycle_history WHERE package_id='fallback-override-r17' AND job_id='job-fb-ovr-r17'",
            [],
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "fallback-override-r17",
            "job-fb-ovr-r17",
            "update",
            true,
            LifecycleJobDiagnostics {
                expected_target_version: Some("4.3.0"),
                achieved_version: Some("4.3.0"),
                finished_at: Some("2026-11-27T04:08:00Z"),
                ..Default::default()
            },
        )
        .unwrap();
        let fb_ovr_hist = get_lifecycle_history(&conn, "fallback-override-r17", 5).unwrap();
        assert_eq!(fb_ovr_hist.len(), 1);
        assert_eq!(
            fb_ovr_hist[0].expected_target_version.as_deref(),
            Some("4.3.0")
        );

        // Tampered expected_target_version on legacy package_lifecycle_jobs is sanitized on fallback.
        let legacy_dirty_target = format!("4.2.0 --{pw_k}=LEGACY_FB_SECRET_R17");
        conn.execute(
            "INSERT INTO package_lifecycle_jobs (
                package_id, job_id, action, status, started_at, expected_target_version
            ) VALUES ('fallback-dirty-r17', 'job-fb-dirty-r17', 'update', 'updating', '2026-11-27T04:09:00Z', ?1)",
            params![legacy_dirty_target],
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "fallback-dirty-r17",
            "job-fb-dirty-r17",
            "update",
            true,
            LifecycleJobDiagnostics {
                expected_target_version: None,
                achieved_version: Some("4.2.0"),
                finished_at: Some("2026-11-27T04:10:00Z"),
                ..Default::default()
            },
        )
        .unwrap();
        let fb_dirty_raw: String = conn
            .query_row(
                "SELECT expected_target_version FROM package_lifecycle_history WHERE package_id='fallback-dirty-r17' AND job_id='job-fb-dirty-r17'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !fb_dirty_raw.contains("LEGACY_FB_SECRET_R17"),
            "{fb_dirty_raw}"
        );
        assert!(fb_dirty_raw.contains("[REDACTED]"), "{fb_dirty_raw}");

        // 3. Neon F-11: tampered job_id, action, and status scrubbed on read in
        //    get_lifecycle_history and query_package_retention_history (while clean values stay intact).
        let tamper_job_id = "job Bearer TAMPER_JOBID_R17";
        let tamper_action = format!("update {pw_k}=TAMPER_ACTION_R17");
        let tamper_status = format!("failed {tok_k}=TAMPER_STATUS_R17");
        conn.execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, finished_at
            ) VALUES ('tamper-id-hist-r17', ?1, ?2, ?3, '2026-11-27T04:11:00Z', '2026-11-27T04:12:00Z')",
            params![tamper_job_id, tamper_action, tamper_status],
        )
        .unwrap();
        let id_hist = get_lifecycle_history(&conn, "tamper-id-hist-r17", 5).unwrap();
        assert_eq!(id_hist.len(), 1);
        assert!(!id_hist[0].job_id.contains("TAMPER_JOBID_R17"));
        assert!(id_hist[0].job_id.contains("[REDACTED]"));
        assert!(!id_hist[0].action.contains("TAMPER_ACTION_R17"));
        assert!(id_hist[0].action.contains("[REDACTED]"));
        assert!(!id_hist[0].status.contains("TAMPER_STATUS_R17"));
        assert!(id_hist[0].status.contains("[REDACTED]"));

        // Tampered completed rows in both package_lifecycle_jobs and package_lifecycle_history
        // for query_package_retention_history.
        conn.execute(
            "INSERT INTO package_lifecycle_jobs (
                package_id, job_id, action, status, started_at, finished_at, retention_state
            ) VALUES ('tamper-ret-jobs-r17', ?1, ?2, 'completed', '2026-11-27T04:13:00Z', '2026-11-27T04:14:00Z', 'retained')",
            params![tamper_job_id, tamper_action],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, finished_at, retention_state
            ) VALUES ('tamper-ret-hist-r17', ?1, ?2, 'completed', '2026-11-27T04:13:00Z', '2026-11-27T04:14:00Z', 'retained')",
            params![tamper_job_id, tamper_action],
        )
        .unwrap();

        let ret_jobs = query_package_retention_history(&conn, "tamper-ret-jobs-r17")
            .unwrap()
            .expect("retention from jobs");
        assert!(!ret_jobs.job_id.contains("TAMPER_JOBID_R17"));
        assert!(ret_jobs.job_id.contains("[REDACTED]"));
        assert!(!ret_jobs.action.contains("TAMPER_ACTION_R17"));
        assert!(ret_jobs.action.contains("[REDACTED]"));
        assert_eq!(ret_jobs.status, "completed");

        let ret_hist = query_package_retention_history(&conn, "tamper-ret-hist-r17")
            .unwrap()
            .expect("retention from history");
        assert!(!ret_hist.job_id.contains("TAMPER_JOBID_R17"));
        assert!(ret_hist.job_id.contains("[REDACTED]"));
        assert!(!ret_hist.action.contains("TAMPER_ACTION_R17"));
        assert!(ret_hist.action.contains("[REDACTED]"));
        assert_eq!(ret_hist.status, "completed");

        // Normal job_id / action / status remain untouched.
        assert_eq!(deep_hist[0].job_id, "job-deep-r17");
        assert_eq!(deep_hist[0].action, "update");
        assert_eq!(deep_hist[0].status, "completed");

        drop(fb_override_lease);
        drop(fb_lease);
        drop(deep_lease);
        drop(conn);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn wave1a_r18_write_read_identity_expected_target_and_embedded_json_sanitization() {
        let root = std::env::temp_dir().join(format!("af-jobs-r18-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let db_path = root.join("lifecycle.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        initialize_schema(&conn).unwrap();

        let pw_k = concat!("pass", "word");
        let tok_k = concat!("tok", "en");

        // 1. Carbon W1A-R17-05: admit_job_with_target + finish_job_with_diagnostics sanitize
        //    package_id, job_id, action, and service_units consistently on write.
        let tainted_pkg = format!("sonarr --{pw_k}=CANARY_SQL_PKG_R18");
        let tainted_jid = format!("job-1 --{pw_k}=CANARY_SQL_JID_R18");
        let lease_tainted = admit_job_with_target(
            &mut conn,
            &tainted_pkg,
            &tainted_jid,
            "update",
            "2026-11-27T12:00:00Z",
            &["sonarr.service".to_string()],
            Some("1.0.0"),
        )
        .unwrap();

        let (stored_job_pkg, stored_job_jid, stored_units): (String, String, String) = conn
            .query_row(
                "SELECT package_id, job_id, service_units FROM package_lifecycle_jobs WHERE action='update'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(
            !stored_job_pkg.contains("CANARY_SQL_PKG_R18"),
            "{stored_job_pkg}"
        );
        assert!(stored_job_pkg.contains("[REDACTED]"), "{stored_job_pkg}");
        assert!(
            !stored_job_jid.contains("CANARY_SQL_JID_R18"),
            "{stored_job_jid}"
        );
        assert!(stored_job_jid.contains("[REDACTED]"), "{stored_job_jid}");
        assert!(
            !stored_units
                .to_ascii_lowercase()
                .contains("canary_sql_pkg_r18"),
            "{stored_units}"
        );

        let (stored_hist_pkg, stored_hist_jid): (String, String) = conn
            .query_row(
                "SELECT package_id, job_id FROM package_lifecycle_history WHERE action='update'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored_hist_pkg, stored_job_pkg);
        assert_eq!(stored_hist_jid, stored_job_jid);

        // Reservation check and finish_job_with_diagnostics match identically using caller inputs.
        check_package_reservation(
            &conn,
            &tainted_pkg,
            &["sonarr.service".to_string()],
            &tainted_jid,
            Some("update"),
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            &tainted_pkg,
            &tainted_jid,
            "update",
            true,
            LifecycleJobDiagnostics {
                achieved_version: Some("1.0.0"),
                finished_at: Some("2026-11-27T12:01:00Z"),
                ..Default::default()
            },
        )
        .unwrap();

        let tainted_hist = get_lifecycle_history(&conn, &tainted_pkg, 5).unwrap();
        assert_eq!(tainted_hist.len(), 1);
        assert!(!tainted_hist[0].package_id.contains("CANARY_SQL_PKG_R18"));
        assert!(!tainted_hist[0].job_id.contains("CANARY_SQL_JID_R18"));
        assert_eq!(tainted_hist[0].status, "completed");

        // Fallback hist_updated == 0 INSERT also writes sanitized package_id & job_id.
        let fb_pkg = format!("radarr --{tok_k}=CANARY_FB_PKG_R18");
        let fb_jid = format!("job-fb --{tok_k}=CANARY_FB_JID_R18");
        let lease_fb = admit_job_with_target(
            &mut conn,
            &fb_pkg,
            &fb_jid,
            "remove",
            "2026-11-27T12:02:00Z",
            &[],
            None,
        )
        .unwrap();
        conn.execute(
            "DELETE FROM package_lifecycle_history WHERE package_id=?1",
            params![sanitize_persisted_text(&fb_pkg)],
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            &fb_pkg,
            &fb_jid,
            "remove",
            true,
            LifecycleJobDiagnostics {
                finished_at: Some("2026-11-27T12:03:00Z"),
                retention_state: Some(RETENTION_STATE_RETAINED),
                ..Default::default()
            },
        )
        .unwrap();
        let (fb_hist_pkg, fb_hist_jid): (String, String) = conn
            .query_row(
                "SELECT package_id, job_id FROM package_lifecycle_history WHERE action='remove'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(!fb_hist_pkg.contains("CANARY_FB_PKG_R18"), "{fb_hist_pkg}");
        assert!(!fb_hist_jid.contains("CANARY_FB_JID_R18"), "{fb_hist_jid}");

        // 2. Neon AUD-07 #1: normal hist_updated == 1 UPDATE path scrubs legacy dirty
        //    expected_target_version on both tables when diagnostics.expected_target_version is None.
        let legacy_target = "1.0 Bearer SECRET_LEGACY_TARGET_R18";
        conn.execute(
            "INSERT INTO package_lifecycle_jobs (
                package_id, job_id, action, status, started_at, expected_target_version
            ) VALUES ('legacy-target-r18', 'job-leg-tgt-r18', 'update', 'updating', '2026-11-27T12:04:00Z', ?1)",
            params![legacy_target],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, expected_target_version
            ) VALUES ('legacy-target-r18', 'job-leg-tgt-r18', 'update', 'updating', '2026-11-27T12:04:00Z', ?1)",
            params![legacy_target],
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "legacy-target-r18",
            "job-leg-tgt-r18",
            "update",
            true,
            LifecycleJobDiagnostics {
                expected_target_version: None,
                achieved_version: Some("1.0"),
                finished_at: Some("2026-11-27T12:05:00Z"),
                ..Default::default()
            },
        )
        .unwrap();
        let jobs_legacy_exp: String = conn
            .query_row(
                "SELECT expected_target_version FROM package_lifecycle_jobs WHERE package_id='legacy-target-r18'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let hist_legacy_exp: String = conn
            .query_row(
                "SELECT expected_target_version FROM package_lifecycle_history WHERE package_id='legacy-target-r18'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !jobs_legacy_exp.contains("SECRET_LEGACY_TARGET_R18"),
            "jobs table retained legacy dirty expected_target_version: {jobs_legacy_exp}"
        );
        assert!(jobs_legacy_exp.contains("[REDACTED]"), "{jobs_legacy_exp}");
        assert!(
            !hist_legacy_exp.contains("SECRET_LEGACY_TARGET_R18"),
            "history table retained legacy dirty expected_target_version: {hist_legacy_exp}"
        );
        assert!(hist_legacy_exp.contains("[REDACTED]"), "{hist_legacy_exp}");

        // 3. Carbon W1A-R17-04 / Neon AUD-07 #3: out-of-band tampered package_id scrubbed on read
        //    in get_lifecycle_history, query_package_retention_history, and query_retained_lifecycle_packages.
        let tamper_jobs_pkg = format!("sonarr --{pw_k}=CANARY_READ_JOBS_PKG_R18");
        let tamper_hist_pkg = "prowlarr Bearer CANARY_READ_HIST_PKG_R18";
        conn.execute(
            "INSERT INTO package_lifecycle_jobs (
                package_id, job_id, action, status, started_at, finished_at, retention_state
            ) VALUES (?1, 'job-tamper-pkg-1', 'remove', 'completed', '2026-11-27T12:06:00Z', '2026-11-27T12:07:00Z', 'retained')",
            params![tamper_jobs_pkg],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, finished_at, retention_state
            ) VALUES (?1, 'job-tamper-pkg-2', 'remove', 'completed', '2026-11-27T12:06:00Z', '2026-11-27T12:07:00Z', 'retained')",
            params![tamper_hist_pkg],
        )
        .unwrap();

        let ret_jobs = query_package_retention_history(&conn, &tamper_jobs_pkg)
            .unwrap()
            .expect("retention from tampered jobs row");
        assert!(!ret_jobs.package_id.contains("CANARY_READ_JOBS_PKG_R18"));
        assert!(ret_jobs.package_id.contains("[REDACTED]"));

        let ret_hist = query_package_retention_history(&conn, tamper_hist_pkg)
            .unwrap()
            .expect("retention from tampered history row");
        assert!(!ret_hist.package_id.contains("CANARY_READ_HIST_PKG_R18"));
        assert!(ret_hist.package_id.contains("[REDACTED]"));

        let read_hist = get_lifecycle_history(&conn, tamper_hist_pkg, 5).unwrap();
        assert_eq!(read_hist.len(), 1);
        assert!(!read_hist[0].package_id.contains("CANARY_READ_HIST_PKG_R18"));
        assert!(read_hist[0].package_id.contains("[REDACTED]"));

        let retained_set = query_retained_lifecycle_packages(&conn).unwrap();
        assert!(retained_set.iter().all(|k| {
            !k.contains("canary_read_jobs_pkg_r18") && !k.contains("canary_read_hist_pkg_r18")
        }));

        // 4. Team 8 F11 #2: sanitize_persisted_text scrubs embedded JSON spans cleanly.
        let emb_cookie = r#"installer error: {"hdr": "Cookie: sid='line1\nSUPER_SECRET_F11_R18'"}"#;
        let emb_out = sanitize_persisted_text(emb_cookie);
        assert!(
            !emb_out.contains("SUPER_SECRET_F11_R18"),
            "embedded JSON cookie leaked: {emb_out}"
        );
        assert!(emb_out.contains("[REDACTED]"), "{emb_out}");
        assert_eq!(sanitize_persisted_text(&emb_out), emb_out);

        let emb_dup =
            format!(r#"installer err: {{"{pw_k}": "DUP_EMB_R18", "{pw_k}": "ok"}} tail=ok"#);
        let emb_dup_out = sanitize_persisted_text(&emb_dup);
        assert!(!emb_dup_out.contains("DUP_EMB_R18"), "{emb_dup_out}");
        assert!(emb_dup_out.contains("tail=ok"), "{emb_dup_out}");
        assert_eq!(sanitize_persisted_text(&emb_dup_out), emb_dup_out);

        let emb_benign = r#"installer info: {"msg": "Cookie:\nHost: example.com"}"#;
        assert_eq!(sanitize_persisted_text(emb_benign), emb_benign);

        // Normal clean slugs/UUIDs stay 100% unchanged through admit + finish + read.
        let clean_lease = admit_job_with_target(
            &mut conn,
            "radarr",
            "job-clean-r18",
            "install",
            "2026-11-27T12:10:00Z",
            &["radarr.service".to_string()],
            Some("5.0.0"),
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "radarr",
            "job-clean-r18",
            "install",
            true,
            LifecycleJobDiagnostics {
                sanitized_summary: Some(emb_cookie),
                achieved_version: Some("5.0.0"),
                finished_at: Some("2026-11-27T12:11:00Z"),
                ..Default::default()
            },
        )
        .unwrap();
        let clean_hist = get_lifecycle_history(&conn, "radarr", 5).unwrap();
        assert_eq!(clean_hist.len(), 1);
        assert_eq!(clean_hist[0].package_id, "radarr");
        assert_eq!(clean_hist[0].job_id, "job-clean-r18");
        assert_eq!(clean_hist[0].action, "install");
        assert!(!clean_hist[0]
            .sanitized_summary
            .as_deref()
            .unwrap()
            .contains("SUPER_SECRET_F11_R18"));

        drop(clean_lease);
        drop(lease_fb);
        drop(lease_tainted);
        drop(conn);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn wave1a_r19_dirty_reservation_tampered_units_and_inplace_hist_scrub() {
        let root = std::env::temp_dir().join(format!("af-jobs-r19-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let db_path = root.join("lifecycle.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();
        initialize_schema(&conn).unwrap();

        let pw_k = concat!("pass", "word");
        let tok_k = concat!("tok", "en");

        // Canonical identity helper parity check (Carbon F4)
        let auth_jid = "job Authorization: Bearer CANARY_AUTH_PARITY_R19";
        let malformed_pkg = format!(r#"err {{"{pw_k}": "CANARY_MALFORMED_PARITY_R19""#);
        assert_eq!(
            LifecycleJobDiagnostics::sanitize_persisted_text(auth_jid),
            sanitize_persisted_text(auth_jid)
        );
        assert_eq!(
            LifecycleJobDiagnostics::sanitize_persisted_text(&malformed_pkg),
            sanitize_persisted_text(&malformed_pkg)
        );

        // 1. Team 8 F7 part 1: legacy dirty active row blocks overlapping admit & Service checks
        let dirty_pkg = format!("app --{tok_k}=DIRTY_RES_PKG_R19");
        let dirty_jid = format!("job --{tok_k}=DIRTY_RES_JID_R19");
        let dirty_unit = format!("app --{tok_k}=DIRTY_RES_UNIT_R19.service");
        let dirty_units_json = serde_json::to_string(&vec![dirty_unit.clone()]).unwrap();
        let dirty_started = format!("2026-11-27T14:00:00Z --{pw_k}=DIRTY_START_R19");
        let dirty_owner = format!("owner --{tok_k}=DIRTY_OWNER_R19");
        let dirty_target = format!("2.0.0 --{pw_k}=DIRTY_TARGET_R19");

        conn.execute(
            "INSERT INTO package_lifecycle_jobs (
                package_id, job_id, action, status, started_at, owner_id, service_units, expected_target_version
            ) VALUES (?1, ?2, 'update', 'updating', ?3, ?4, ?5, ?6)",
            params![
                dirty_pkg,
                dirty_jid,
                dirty_started,
                dirty_owner,
                dirty_units_json,
                dirty_target,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, owner_id, service_units, expected_target_version
            ) VALUES (?1, ?2, 'update', 'updating', ?3, ?4, ?5, ?6)",
            params![
                dirty_pkg,
                dirty_jid,
                dirty_started,
                dirty_owner,
                dirty_units_json,
                dirty_target,
            ],
        )
        .unwrap();

        // Overlapping admit by package or by service unit must be rejected without echoing secrets.
        let overlap_pkg_err = admit_job_with_target(
            &mut conn,
            &dirty_pkg,
            "job-overlap-1",
            "update",
            "2026-11-27T14:01:00Z",
            &[],
            None,
        )
        .err()
        .expect("overlapping package admit must fail")
        .to_string();
        assert!(
            !overlap_pkg_err.contains("DIRTY_RES_PKG_R19"),
            "overlap error leaked secret: {overlap_pkg_err}"
        );

        let overlap_unit_err = admit_job_with_target(
            &mut conn,
            "different-pkg",
            "job-overlap-2",
            "update",
            "2026-11-27T14:01:00Z",
            std::slice::from_ref(&dirty_unit),
            None,
        )
        .err()
        .expect("overlapping unit admit must fail")
        .to_string();
        assert!(
            !overlap_unit_err.contains("DIRTY_RES_PKG_R19")
                && !overlap_unit_err.contains("DIRTY_RES_UNIT_R19"),
            "unit overlap error leaked secret: {overlap_unit_err}"
        );

        // ReservationTarget::Service sanitizes target before matching dirty or clean active rows.
        let svc_err = check_reservation(&conn, ReservationTarget::Service(&dirty_unit), "", None)
            .unwrap_err()
            .to_string();
        assert!(
            !svc_err.contains("DIRTY_RES_PKG_R19") && !svc_err.contains("DIRTY_RES_UNIT_R19"),
            "service reservation error leaked secret: {svc_err}"
        );

        // Rightful owner check matches legacy dirty row cleanly.
        check_reservation(
            &conn,
            ReservationTarget::Package(&dirty_pkg),
            &dirty_jid,
            Some("update"),
        )
        .unwrap();

        // 2. Team 8 F7 part 3: finish_job_with_diagnostics hist_updated == 1 UPDATE scrubs ALL
        //    legacy dirty columns in place on BOTH package_lifecycle_jobs and package_lifecycle_history.
        finish_job_with_diagnostics(
            &conn,
            &dirty_pkg,
            &dirty_jid,
            "update",
            true,
            LifecycleJobDiagnostics {
                achieved_version: Some("2.0.0"),
                finished_at: Some("2026-11-27T14:02:00Z"),
                ..Default::default()
            },
        )
        .unwrap();

        let assert_scrubbed_table = |table: &str| {
            let row: (String, String, String, String, String, String) = conn
                .query_row(
                    &format!(
                        "SELECT package_id, job_id, started_at, owner_id, service_units, expected_target_version FROM {table}"
                    ),
                    [],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                        ))
                    },
                )
                .unwrap();
            let joined = format!(
                "{} | {} | {} | {} | {} | {}",
                row.0, row.1, row.2, row.3, row.4, row.5
            );
            for canary in [
                "DIRTY_RES_PKG_R19",
                "DIRTY_RES_JID_R19",
                "DIRTY_RES_UNIT_R19",
                "DIRTY_START_R19",
                "DIRTY_OWNER_R19",
                "DIRTY_TARGET_R19",
            ] {
                assert!(
                    !joined.contains(canary),
                    "{table} retained dirty legacy {canary} after hist_updated==1 scrub: {joined}"
                );
            }
            assert!(
                row.0.contains("[REDACTED]"),
                "{table} package_id: {}",
                row.0
            );
            assert!(row.1.contains("[REDACTED]"), "{table} job_id: {}", row.1);
            assert!(
                row.2.contains("[REDACTED]"),
                "{table} started_at: {}",
                row.2
            );
            assert!(row.3.contains("[REDACTED]"), "{table} owner_id: {}", row.3);
            assert!(
                row.4.contains("[REDACTED]"),
                "{table} service_units: {}",
                row.4
            );
            assert!(
                row.5.contains("[REDACTED]"),
                "{table} expected_target: {}",
                row.5
            );
        };
        assert_scrubbed_table("package_lifecycle_jobs");
        assert_scrubbed_table("package_lifecycle_history");

        // 3. Carbon F5: tampered non-array JSON service_units never leaks via serde_json::Error
        let tampered_units_str = r#""Bearer TAMPERED_UNITS_SECRET_R19""#;
        conn.execute(
            "INSERT INTO package_lifecycle_jobs (
                package_id, job_id, action, status, started_at, service_units
            ) VALUES ('tampered-units-pkg', 'job-tu-r19', 'install', 'installing', '2026-11-27T14:05:00Z', ?1)",
            params![tampered_units_str],
        )
        .unwrap();

        check_reservation(
            &conn,
            ReservationTarget::Service("unrelated.service"),
            "",
            None,
        )
        .unwrap();
        check_reservation(
            &conn,
            ReservationTarget::Package("tampered-units-pkg"),
            "job-tu-r19",
            Some("install"),
        )
        .unwrap();
        let blocked_err = admit_job_with_target(
            &mut conn,
            "tampered-units-pkg",
            "job-tu-overlap",
            "install",
            "2026-11-27T14:06:00Z",
            &[],
            None,
        )
        .err()
        .expect("overlapping tampered-units-pkg admit must fail")
        .to_string();
        assert!(
            !blocked_err.contains("TAMPERED_UNITS_SECRET_R19"),
            "admit error echoed tampered service_units secret: {blocked_err}"
        );

        drop(conn);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
