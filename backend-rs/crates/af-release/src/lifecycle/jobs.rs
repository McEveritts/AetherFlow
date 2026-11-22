use super::lease::{owner_is_alive, retire_finished_owners, OwnerLease};
use super::sanitize_persisted_lifecycle_text;
use super::units::{package_resources, ReservationTarget};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, TransactionBehavior};
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

pub fn reconcile_jobs(conn: &Connection, database: &Path) -> Result<()> {
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
    let jobs: Vec<(String, String, String)> = conn.prepare(
        "SELECT package_id,job_id,owner_id FROM package_lifecycle_jobs WHERE status IN ('installing','updating','uninstalling')",
    )?.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (package, job, owner) in jobs {
        if owner.is_empty() || !matches!(owner_is_alive(database, &owner), Ok(false)) {
            continue;
        }
        let now = chrono::Utc::now().to_rfc3339();
        if has_recovery {
            conn.execute(
                "UPDATE package_lifecycle_jobs SET status='interrupted',finished_at=?1,failure_category='interrupted',recovery_state=''
                 WHERE package_id=?2 AND job_id=?3 AND owner_id=?4 AND status IN ('installing','updating','uninstalling')",
                params![now, package, job, owner],
            )?;
        } else {
            conn.execute(
                "UPDATE package_lifecycle_jobs SET status='interrupted',finished_at=?1,failure_category='interrupted'
                 WHERE package_id=?2 AND job_id=?3 AND owner_id=?4 AND status IN ('installing','updating','uninstalling')",
                params![now, package, job, owner],
            )?;
        }
        if has_hist_recovery {
            let _ = conn.execute(
                "UPDATE package_lifecycle_history SET status='interrupted',finished_at=?1,failure_category='interrupted',recovery_state=''
                 WHERE package_id=?2 AND job_id=?3 AND owner_id=?4 AND status IN ('installing','updating','uninstalling')",
                params![now, package, job, owner],
            );
        } else {
            let _ = conn.execute(
                "UPDATE package_lifecycle_history SET status='interrupted',finished_at=?1,failure_category='interrupted'
                 WHERE package_id=?2 AND job_id=?3 AND owner_id=?4 AND status IN ('installing','updating','uninstalling')",
                params![now, package, job, owner],
            );
        }
    }
    let _ = retire_finished_owners(conn, database);
    Ok(())
}

pub fn check_package_reservation(
    conn: &Connection,
    package: &str,
    units: &[String],
    job_id: &str,
    action: Option<&str>,
) -> Result<()> {
    check_resources(
        conn,
        Some(package_resources(package, units)),
        job_id,
        action,
    )?;
    if !job_id.is_empty() {
        let exact: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2 AND status IN ('installing','updating','uninstalling'))",
            params![package,job_id], |row| row.get(0),
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
    let status = match action {
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
    check_package_reservation(&tx, package, units, "", Some(action))?;
    let lease = OwnerLease::create(&database)?;
    let normalized: Vec<_> = package_resources(package, units).into_iter().collect();
    let normalized_json = serde_json::to_string(&normalized)?;
    let target_ver_raw = expected_target_version.unwrap_or("");
    let target_ver = sanitize_persisted_lifecycle_text(target_ver_raw);
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
            params![package, job_id, action, status, started_at, lease.id, normalized_json, target_ver],
        )?;
    } else {
        tx.execute(
            "INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category,failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,recovery_state)
            VALUES (?1,?2,?3,?4,?5,'',?6,?7,'','',NULL,'',?8,'','') ON CONFLICT(package_id) DO UPDATE SET
            job_id=excluded.job_id,action=excluded.action,status=excluded.status,started_at=excluded.started_at,finished_at='',owner_id=excluded.owner_id,service_units=excluded.service_units,failure_category='',failed_stage='',exit_code=NULL,sanitized_summary='',expected_target_version=excluded.expected_target_version,achieved_version='',recovery_state=''",
            params![package, job_id, action, status, started_at, lease.id, normalized_json, target_ver],
        )?;
    }
    if has_hist_retention {
        tx.execute(
            "INSERT INTO package_lifecycle_history (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category,failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,recovery_state,retention_state)
            VALUES (?1,?2,?3,?4,?5,'',?6,?7,'','',NULL,'',?8,'','','')",
            params![package, job_id, action, status, started_at, lease.id, normalized_json, target_ver],
        )?;
    } else {
        tx.execute(
            "INSERT INTO package_lifecycle_history (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category,failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,recovery_state)
            VALUES (?1,?2,?3,?4,?5,'',?6,?7,'','',NULL,'',?8,'','')",
            params![package, job_id, action, status, started_at, lease.id, normalized_json, target_ver],
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
    let status = if success { "completed" } else { "failed" };
    let finished_at_owned = finished_at
        .map(ToString::to_string)
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let finished_at = finished_at_owned.as_str();
    let cat = if success { "" } else { failure_category };
    let recovery = normalize_recovery_state(success, action, cat, recovery_state);
    let retention = normalize_retention_state(success, action, retention_state);
    let stage = sanitize_persisted_lifecycle_text(failed_stage.unwrap_or(""));
    let summary = sanitize_persisted_lifecycle_text(sanitized_summary.unwrap_or(""));
    let achieved = sanitize_persisted_lifecycle_text(achieved_version.unwrap_or(""));
    let expected = sanitize_persisted_lifecycle_text(expected_target_version.unwrap_or(""));

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
        let updated = if has_jobs_retention {
            conn.execute(
                "UPDATE package_lifecycle_jobs SET status=?1,finished_at=?2,failure_category=?3,failed_stage=?4,exit_code=?5,sanitized_summary=?6,expected_target_version=CASE WHEN ?7 != '' THEN ?7 ELSE expected_target_version END,achieved_version=?8,recovery_state=?9,retention_state=?10
                 WHERE package_id=?11 AND job_id=?12 AND action=?13 AND status IN ('installing','updating','uninstalling')",
                params![status, finished_at, cat, stage, exit_code, summary, expected, achieved, recovery, retention, package, job_id, action],
            )?
        } else {
            conn.execute(
                "UPDATE package_lifecycle_jobs SET status=?1,finished_at=?2,failure_category=?3,failed_stage=?4,exit_code=?5,sanitized_summary=?6,expected_target_version=CASE WHEN ?7 != '' THEN ?7 ELSE expected_target_version END,achieved_version=?8,recovery_state=?9
                 WHERE package_id=?10 AND job_id=?11 AND action=?12 AND status IN ('installing','updating','uninstalling')",
                params![status, finished_at, cat, stage, exit_code, summary, expected, achieved, recovery, package, job_id, action],
            )?
        };
        anyhow::ensure!(updated == 1, "lifecycle receipt identity changed");
        let hist_updated = if has_hist_retention {
            conn.execute(
                "UPDATE package_lifecycle_history SET status=?1,finished_at=?2,failure_category=?3,failed_stage=?4,exit_code=?5,sanitized_summary=?6,expected_target_version=CASE WHEN ?7 != '' THEN ?7 ELSE expected_target_version END,achieved_version=?8,recovery_state=?9,retention_state=?10
                 WHERE package_id=?11 AND job_id=?12 AND action=?13 AND status IN ('installing','updating','uninstalling')",
                params![status, finished_at, cat, stage, exit_code, summary, expected, achieved, recovery, retention, package, job_id, action],
            )?
        } else {
            conn.execute(
                "UPDATE package_lifecycle_history SET status=?1,finished_at=?2,failure_category=?3,failed_stage=?4,exit_code=?5,sanitized_summary=?6,expected_target_version=CASE WHEN ?7 != '' THEN ?7 ELSE expected_target_version END,achieved_version=?8,recovery_state=?9
                 WHERE package_id=?10 AND job_id=?11 AND action=?12 AND status IN ('installing','updating','uninstalling')",
                params![status, finished_at, cat, stage, exit_code, summary, expected, achieved, recovery, package, job_id, action],
            )?
        };
        if hist_updated == 0 {
            let (started_at, owner_id, service_units): (String, String, String) = conn
                .query_row(
                    "SELECT started_at, owner_id, service_units FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2",
                    params![package, job_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap_or_else(|_| (finished_at.to_string(), String::new(), "[]".to_string()));
            if has_hist_retention {
                conn.execute(
                    "INSERT INTO package_lifecycle_history (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category,failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,recovery_state,retention_state)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                    params![package, job_id, action, status, started_at, finished_at, owner_id, service_units, cat, stage, exit_code, summary, expected, achieved, recovery, retention],
                )?;
            } else {
                conn.execute(
                    "INSERT INTO package_lifecycle_history (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category,failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,recovery_state)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                    params![package, job_id, action, status, started_at, finished_at, owner_id, service_units, cat, stage, exit_code, summary, expected, achieved, recovery],
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
             WHERE (LOWER(package_id)=LOWER(?1) OR LOWER(package_id)=LOWER(?2)) \
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
        let mut rows = stmt.query(params![trimmed, lock_alias])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(PackageLifecycleRetentionRecord {
                package_id: row.get(0)?,
                job_id: row.get(1)?,
                action: row.get(2)?,
                status: row.get(3)?,
                retention_state: row.get(4)?,
                finished_at: row.get(5)?,
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
         WHERE (LOWER(package_id)=LOWER(?1) OR LOWER(package_id)=LOWER(?2)) \
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
    let mut rows = stmt.query(params![trimmed, lock_alias])?;
    if let Some(row) = rows.next()? {
        return Ok(Some(PackageLifecycleRetentionRecord {
            package_id: row.get(0)?,
            job_id: row.get(1)?,
            action: row.get(2)?,
            status: row.get(3)?,
            retention_state: row.get(4)?,
            finished_at: row.get(5)?,
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
            let package_id: String = row.get(0)?;
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

pub fn get_lifecycle_history(
    conn: &Connection,
    package_id: &str,
    limit: usize,
) -> Result<Vec<af_models::PackageLifecycleRecord>> {
    let mut stmt = conn.prepare(
        "SELECT package_id, job_id, action, status, started_at, finished_at, owner_id, service_units,
                failure_category, failed_stage, exit_code, sanitized_summary, expected_target_version, achieved_version
         FROM package_lifecycle_history
         WHERE package_id = ?1
         ORDER BY id DESC LIMIT ?2",
    )?;
    let records = stmt
        .query_map(params![package_id, limit as i64], |row| {
            let service_units_raw: String = row.get(7)?;
            let service_units =
                serde_json::from_str::<Vec<String>>(&service_units_raw).unwrap_or_default();
            let failed_stage: String = row.get(9)?;
            let sanitized_summary: String = row.get(11)?;
            let expected_target_version: String = row.get(12)?;
            let achieved_version: String = row.get(13)?;
            Ok(af_models::PackageLifecycleRecord {
                package_id: row.get(0)?,
                job_id: row.get(1)?,
                action: row.get(2)?,
                status: row.get(3)?,
                started_at: row.get(4)?,
                finished_at: row.get(5)?,
                owner_id: row.get(6)?,
                service_units,
                failure_category: row.get(8)?,
                failed_stage: if failed_stage.is_empty() {
                    None
                } else {
                    Some(failed_stage)
                },
                exit_code: row.get(10)?,
                sanitized_summary: if sanitized_summary.is_empty() {
                    None
                } else {
                    Some(sanitized_summary)
                },
                expected_target_version: if expected_target_version.is_empty() {
                    None
                } else {
                    Some(expected_target_version)
                },
                achieved_version: if achieved_version.is_empty() {
                    None
                } else {
                    Some(achieved_version)
                },
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(records)
}

pub fn check_reservation(
    conn: &Connection,
    target: ReservationTarget<'_>,
    job_id: &str,
    action: Option<&str>,
) -> Result<()> {
    let resources = match target {
        ReservationTarget::Package(package) => {
            let mut units = Vec::new();
            if !job_id.is_empty() {
                let table: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='package_lifecycle_jobs')",
                    [], |row| row.get(0),
                )?;
                if table {
                    let mut statement = conn.prepare("SELECT service_units FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2")?;
                    for raw in statement
                        .query_map(params![package, job_id], |row| row.get::<_, String>(0))?
                    {
                        units.extend(serde_json::from_str::<Vec<String>>(&raw?)?);
                    }
                }
            }
            return check_package_reservation(conn, package, &units, job_id, action);
        }
        ReservationTarget::Service(service) => Some(package_resources(service, &[])),
        ReservationTarget::System => None,
    };
    check_resources(conn, resources, job_id, action)
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
        anyhow::ensure!(resources.is_some(), "Application lifecycle reservation is active for {package}; core service control is unavailable");
        let reserved_resources =
            package_resources(&package, &serde_json::from_str::<Vec<String>>(&units)?);
        let matches_target = !resources.as_ref().unwrap().is_disjoint(&reserved_resources);
        if matches_target {
            let expected_status = match reserved_action.as_str() {
                "install" | "reinstall" => "installing",
                "update" => "updating",
                "remove" => "uninstalling",
                _ => anyhow::bail!("Lifecycle reservation action is unknown for {package}"),
            };
            anyhow::ensure!(
                status == expected_status,
                "Lifecycle reservation phase is unknown for {package}"
            );
            anyhow::ensure!(
                !job_id.is_empty() && reserved_job == job_id,
                "Application lifecycle reservation is active for {package}"
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
