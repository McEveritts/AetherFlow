use anyhow::{Context, Result};
pub use libc;
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{params, Connection, TransactionBehavior};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

af_models::define_package_diagnostic_redaction!();

pub struct OwnerLease {
    pub id: String,
    database: PathBuf,
    _file: File,
}

fn lease_path(database: &Path, owner: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        uuid::Uuid::parse_str(owner).is_ok(),
        "invalid lifecycle owner identity"
    );
    Ok(database.with_extension("lifecycle-owners").join(owner))
}

impl OwnerLease {
    pub fn create(database: &Path) -> Result<Self> {
        let id = uuid::Uuid::new_v4().to_string();
        let path = lease_path(database, &id)?;
        let parent = path.parent().context("missing lifecycle lease directory")?;
        crate::fs_security::create_dir_all_no_symlinks(parent, 0o755)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(&path)?;
        anyhow::ensure!(
            lock_exclusive(&file)?,
            "new lifecycle owner lease already locked"
        );
        let lease = Self {
            id,
            database: database.to_owned(),
            _file: file,
        };
        lease._file.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(lease)
    }
}

impl Drop for OwnerLease {
    fn drop(&mut self) {
        let cleanup = || -> Result<()> {
            let conn = Connection::open_with_flags(
                &self.database,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            conn.busy_timeout(std::time::Duration::ZERO)?;
            retire_owner(&conn, &self.database, &self.id, &self._file)
        };
        let _ = cleanup();
    }
}

#[cfg(unix)]
fn lock_exclusive(file: &File) -> Result<bool> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error.into())
    }
}

#[cfg(not(unix))]
fn lock_exclusive(_file: &File) -> Result<bool> {
    anyhow::bail!("lifecycle owner leases require advisory lock support")
}

fn open_owner_file(database: &Path, owner: &str) -> Result<File> {
    let path = lease_path(database, owner)?;
    crate::fs_security::ensure_no_symlink_ancestors(&path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .context("cannot inspect lifecycle owner lease")?;
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_file(), "invalid lifecycle owner lease file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(metadata.nlink() == 1, "linked lifecycle owner lease file");
    }
    Ok(file)
}

pub fn owner_is_alive(database: &Path, owner: &str) -> Result<bool> {
    let file = open_owner_file(database, owner)?;
    Ok(!lock_exclusive(&file)?)
}

#[cfg(unix)]
fn retire_owner(conn: &Connection, database: &Path, owner: &str, file: &File) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    anyhow::ensure!(
        conn.is_autocommit(),
        "lifecycle cleanup requires committed receipts"
    );
    let active: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM package_lifecycle_jobs WHERE owner_id=?1 AND status NOT IN ('completed','failed','interrupted'))",
        [owner], |row| row.get(0),
    )?;
    anyhow::ensure!(!active, "lifecycle owner still has a reservation");
    let path = lease_path(database, owner)?;
    let parent = path.parent().context("missing lifecycle lease directory")?;
    crate::fs_security::ensure_no_symlink_ancestors(parent)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    anyhow::ensure!(
        directory.metadata()?.mode() & 0o022 == 0,
        "lifecycle lease directory is writable by other users"
    );
    let expected = file.metadata()?;
    anyhow::ensure!(
        expected.is_file() && expected.nlink() == 1,
        "invalid lifecycle owner lease inode"
    );
    let name = std::ffi::CString::new(owner)?;
    let mut observed = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            observed.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let observed = unsafe { observed.assume_init() };
    anyhow::ensure!(
        observed.st_mode & libc::S_IFMT == libc::S_IFREG
            && observed.st_nlink == 1
            && observed.st_dev == expected.dev()
            && observed.st_ino == expected.ino(),
        "lifecycle owner lease inode changed"
    );
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn retire_owner(_conn: &Connection, _database: &Path, _owner: &str, _file: &File) -> Result<()> {
    anyhow::bail!("lifecycle owner cleanup requires advisory lock support")
}

fn retire_finished_owners(conn: &Connection, database: &Path) -> Result<()> {
    if !conn.is_autocommit() {
        return Ok(());
    }
    let owners: Vec<String> = conn
        .prepare("SELECT DISTINCT owner_id FROM package_lifecycle_jobs WHERE status IN ('completed','failed','interrupted') AND owner_id!=''")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for owner in owners {
        if let Ok(file) = open_owner_file(database, &owner) {
            if matches!(lock_exclusive(&file), Ok(true)) {
                let _ = retire_owner(conn, database, &owner, &file);
            }
        }
    }
    Ok(())
}

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

pub enum ReservationTarget<'a> {
    Package(&'a str),
    Service(&'a str),
    System,
}

pub fn port_resource(port: i32) -> Option<String> {
    if (1..=65535).contains(&port) {
        Some(format!("port:{port}"))
    } else {
        None
    }
}

pub fn package_resources(package: &str, units: &[String]) -> BTreeSet<String> {
    std::iter::once(package)
        .chain(units.iter().map(String::as_str))
        .map(|unit| unit.trim().to_ascii_lowercase())
        .map(|unit| unit.trim_end_matches(".service").to_owned())
        .filter(|unit| !unit.is_empty())
        .collect()
}

pub fn is_timer_unit(unit: &str) -> bool {
    unit.trim().to_ascii_lowercase().ends_with(".timer")
}

pub fn is_socket_unit(unit: &str) -> bool {
    unit.trim().to_ascii_lowercase().ends_with(".socket")
}

pub fn is_activation_unit(unit: &str) -> bool {
    is_timer_unit(unit) || is_socket_unit(unit)
}

/// Companion units added in newer AetherFlow releases that may legitimately be
/// `LoadState=not-found` on pre-socket LibreSpeed or pre-companion noVNC hosts.
pub fn is_legacy_optional_companion_unit(unit: &str) -> bool {
    let lower = unit.trim().to_ascii_lowercase();
    lower == "librespeed.socket" || lower.trim_end_matches(".service") == "novnc-session"
}

/// Shared stop / quiesce priority tier (lower values stop FIRST).
///
/// 0: socket and timer activation units (`*.socket`, `*.timer`) stop before app
///    workers so incoming requests or timer ticks cannot reactivate a partially
///    replaced or removed service.
/// 1: frontend proxies that require companion services (`novnc`).
/// 2: standard application daemons and intermediate session units (`novnc-session`).
/// 3: underlying display/backend servers (`novnc-xvnc`).
pub fn unit_stop_order_key(unit: &str) -> u8 {
    let lower = unit.trim().to_ascii_lowercase();
    if lower.ends_with(".timer") || lower.ends_with(".socket") {
        0
    } else {
        match lower.trim_end_matches(".service") {
            "novnc" => 1,
            "novnc-session" => 2,
            "novnc-xvnc" => 3,
            _ => 2,
        }
    }
}

/// Shared start / restore / restart priority tier (lower values start FIRST).
///
/// 0: socket units (`*.socket`) and base display servers (`novnc-xvnc`) start
///    before workers that depend on them (`Requires=` / `BindsTo=`).
/// 1: intermediate companion units (`novnc-session`).
/// 2: standard application daemons and frontend proxies (`librespeed`, `novnc`).
/// 3: scheduled timer units (`*.timer`) start after daemons are running.
pub fn unit_start_order_key(unit: &str) -> u8 {
    let lower = unit.trim().to_ascii_lowercase();
    if lower.ends_with(".socket") {
        0
    } else if lower.ends_with(".timer") {
        3
    } else {
        match lower.trim_end_matches(".service") {
            "novnc-xvnc" => 0,
            "novnc-session" => 1,
            "novnc" => 2,
            _ => 2,
        }
    }
}

pub fn sort_units_for_stop(units: &mut [String]) {
    units.sort_by_key(|unit| unit_stop_order_key(unit));
}

pub fn sort_units_for_start(units: &mut [String]) {
    units.sort_by_key(|unit| unit_start_order_key(unit));
}

/// Orders a stop-ordered unit list for restoration/startup: reverses generic
/// ordering first, then applies dependency-aware start tiers so sockets and
/// base servers start before workers while timers start last.
pub fn ordered_units_for_start(stopped_order: &[String]) -> Vec<String> {
    let mut ordered: Vec<String> = stopped_order.iter().rev().cloned().collect();
    sort_units_for_start(&mut ordered);
    ordered
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
            "SELECT package_id, action, {} \
             FROM package_lifecycle_jobs \
             WHERE status='completed' \
             ORDER BY {}",
            if has_retention {
                "retention_state"
            } else {
                "''"
            },
            if has_finished {
                "finished_at DESC, started_at DESC"
            } else {
                "started_at DESC"
            },
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let pkg: String = row.get(0)?;
            let action: String = row.get(1)?;
            let retention_state: String = row.get(2)?;
            let key =
                af_models::resolve_package_lock_name(&pkg.trim().to_ascii_lowercase()).to_string();
            if !key.is_empty()
                && resolved.insert(key.clone())
                && action == "remove"
                && retention_state == RETENTION_STATE_RETAINED
            {
                retained.insert(key);
            }
        }
    }

    let hist_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='package_lifecycle_history')",
        [],
        |row| row.get(0),
    )?;
    if !hist_exists {
        return Ok(retained);
    }
    let has_hist_retention: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_history') WHERE name='retention_state')",
        [],
        |row| row.get(0),
    )?;
    let sql = format!(
        "SELECT package_id, action, {} \
         FROM package_lifecycle_history \
         WHERE status='completed' \
         ORDER BY id DESC",
        if has_hist_retention {
            "retention_state"
        } else {
            "''"
        },
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let pkg: String = row.get(0)?;
        let action: String = row.get(1)?;
        let retention_state: String = row.get(2)?;
        let key =
            af_models::resolve_package_lock_name(&pkg.trim().to_ascii_lowercase()).to_string();
        if !key.is_empty()
            && resolved.insert(key.clone())
            && action == "remove"
            && retention_state == RETENTION_STATE_RETAINED
        {
            retained.insert(key);
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

pub fn is_hex_commit(s: &str) -> bool {
    let len = s.len();
    (7..=40).contains(&len)
        && s.bytes().all(|b| b.is_ascii_hexdigit())
        && (len == 40 || s.bytes().any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F')))
}

pub fn is_hex_digits_7_to_40(s: &str) -> bool {
    s.len() >= 7 && s.len() <= 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn commits_match_prefix(a: &str, b: &str, known_git_context: bool) -> bool {
    if !is_hex_digits_7_to_40(a) || !is_hex_digits_7_to_40(b) {
        return false;
    }
    if !known_git_context && !is_hex_commit(a) && !is_hex_commit(b) {
        return false;
    }
    let al = a.to_ascii_lowercase();
    let bl = b.to_ascii_lowercase();
    al.starts_with(&bl) || bl.starts_with(&al)
}

pub fn is_debian_plus_revision(suffix_after_plus: &str) -> bool {
    let lower = suffix_after_plus.to_ascii_lowercase();
    let trimmed = lower.trim_start_matches(['+', '~']);
    if trimmed.is_empty() {
        return false;
    }

    // 1. deb\d+ (e.g. +deb11u1, +deb12u2 — "deb" followed immediately by an ASCII digit!)
    if let Some(rest) = trimmed.strip_prefix("deb") {
        if rest.starts_with(|c: char| c.is_ascii_digit()) {
            return true;
        }
    }

    // 2. dfsg(\.\d+|\d+|-|$) (e.g. +dfsg, +dfsg1, +dfsg.1, +dfsg-1)
    if let Some(rest) = trimmed.strip_prefix("dfsg") {
        if rest.is_empty()
            || rest.starts_with('-')
            || rest.starts_with(|c: char| c.is_ascii_digit())
            || (rest.starts_with('.') && rest[1..].starts_with(|c: char| c.is_ascii_digit()))
        {
            return true;
        }
    }

    // 3. ds(\.\d+|\d+|-|$) (e.g. +ds, +ds1, +ds.1, +ds-1)
    if let Some(rest) = trimmed.strip_prefix("ds") {
        if rest.is_empty()
            || rest.starts_with('-')
            || rest.starts_with(|c: char| c.is_ascii_digit())
            || (rest.starts_with('.') && rest[1..].starts_with(|c: char| c.is_ascii_digit()))
        {
            return true;
        }
    }

    // 4. really[0-9.] (e.g. +really1.0)
    if let Some(rest) = trimmed.strip_prefix("really") {
        if rest.starts_with(|c: char| c.is_ascii_digit() || c == '.') {
            return true;
        }
    }

    // 5. nmu\d+ (e.g. +nmu1)
    if let Some(rest) = trimmed.strip_prefix("nmu") {
        if rest.starts_with(|c: char| c.is_ascii_digit()) {
            return true;
        }
    }

    // 6. b\d+$ (e.g. +b1, +b2 — 'b' followed ONLY by ASCII digits!)
    if let Some(rest) = trimmed.strip_prefix('b') {
        if !rest.is_empty() && rest.bytes().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }

    // 7. u\d+$ (e.g. +u1 — 'u' followed ONLY by ASCII digits!)
    if let Some(rest) = trimmed.strip_prefix('u') {
        if !rest.is_empty() && rest.bytes().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }

    false
}

pub fn strip_semver_build_metadata(s: &str) -> &str {
    if let Some(idx) = s.find('+') {
        let suffix = &s[idx + 1..];
        if !is_debian_plus_revision(suffix) {
            return &s[..idx];
        }
    }
    s
}

pub fn is_debian_revision_suffix(suffix: &str) -> bool {
    let s = suffix.trim();
    if s.is_empty() || s.starts_with('-') || s.starts_with("0.") {
        return false;
    }
    let starts_valid = s.starts_with(|c: char| c.is_ascii_digit())
        || ((s.starts_with('r') || s.starts_with('R'))
            && s.len() > 1
            && s[1..].starts_with(|c: char| c.is_ascii_digit()));
    if !starts_valid {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    const PRERELEASE_KEYWORDS: &[&str] = &[
        "alpha",
        "beta",
        "rc",
        "dev",
        "devel",
        "nightly",
        "edge",
        "pre",
        "preview",
        "canary",
        "snapshot",
        "git",
        "svn",
        "test",
        "unstable",
        "experimental",
        "debug",
    ];
    for kw in PRERELEASE_KEYWORDS {
        if lower.contains(kw) {
            return false;
        }
    }

    let has_debian_marker = lower.contains("ubuntu")
        || lower.contains("deb")
        || lower.contains("dfsg")
        || lower.contains("build")
        || lower.contains("+b")
        || (lower.contains('b') && lower.contains('+'))
        || lower.contains(':');

    let is_numeric_dots = s.chars().all(|c| c.is_ascii_digit() || c == '.') && s.contains('.');
    !is_numeric_dots || has_debian_marker
}

pub fn is_valid_apt_debian_revision_suffix(suffix: &str) -> bool {
    let s = suffix.trim();
    if s.is_empty() || s.starts_with('-') {
        return false;
    }
    let starts_valid = s.starts_with(|c: char| c.is_ascii_digit())
        || ((s.starts_with('r') || s.starts_with('R'))
            && s.len() > 1
            && s[1..].starts_with(|c: char| c.is_ascii_digit()));
    if !starts_valid {
        return false;
    }
    if s.contains('~') {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    const PRERELEASE_KEYWORDS: &[&str] = &[
        "alpha",
        "beta",
        "rc",
        "dev",
        "devel",
        "nightly",
        "edge",
        "pre",
        "preview",
        "canary",
        "snapshot",
        "git",
        "svn",
        "test",
        "unstable",
        "experimental",
        "debug",
    ];
    for kw in PRERELEASE_KEYWORDS {
        if lower.contains(kw) {
            return false;
        }
    }
    true
}

pub fn is_prerelease_version_for_channel_with_source(
    version_or_tag: &str,
    update_source: Option<&str>,
) -> bool {
    let clean = strip_version_prefix(version_or_tag);
    let src = update_source.map(|s| s.trim().to_ascii_lowercase());
    let is_apt = matches!(src.as_deref(), Some("apt" | "deb" | "dpkg"));
    let effective_clean = if !is_apt {
        clean.split_once('+').map(|(v, _)| v).unwrap_or(clean)
    } else {
        clean
    };
    let lower = effective_clean.to_ascii_lowercase();

    if lower.contains('~') {
        return true;
    }

    const PRERELEASE_KEYWORDS: &[&str] = &[
        "alpha",
        "beta",
        "rc",
        "dev",
        "devel",
        "nightly",
        "edge",
        "pre",
        "preview",
        "canary",
        "snapshot",
        "unstable",
        "experimental",
        "debug",
        "dirty",
        "wip",
    ];
    for word in PRERELEASE_KEYWORDS {
        if lower.contains(word) {
            return true;
        }
    }

    match src.as_deref() {
        Some("apt") | Some("deb") | Some("dpkg") => {
            let without_epoch = if let Some((_, rem)) = clean.split_once(':') {
                rem
            } else {
                clean
            };
            if let Some((upstream, deb_rev)) = without_epoch.rsplit_once('-') {
                if upstream.contains('~') {
                    return true;
                }
                let segments_numeric = if upstream.contains('-') {
                    upstream
                        .split('-')
                        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                } else {
                    true
                };
                return !(segments_numeric && is_valid_apt_debian_revision_suffix(deb_rev));
            }
            false
        }
        Some("github")
        | Some("github_release")
        | Some("github_releases")
        | Some("github_tags")
        | Some("git")
        | Some("git_tags")
        | Some("git_tag")
        | Some("git_commit")
        | Some("git_head")
        | Some("gitlab")
        | Some("gitea") => {
            let semver_core_and_pre = clean.split_once('+').map(|(v, _)| v).unwrap_or(clean);
            if semver_core_and_pre.contains('-') {
                return true;
            }
            if let Some(sv) = parse_semver(semver_core_and_pre) {
                if let Some(ref pre) = sv.prerelease {
                    if !pre.is_empty() {
                        return true;
                    }
                }
            }
            false
        }
        _ => {
            let semver_core_and_pre = clean.split_once('+').map(|(v, _)| v).unwrap_or(clean);
            if let Some((_upstream, rest)) =
                semver_core_and_pre.to_ascii_lowercase().split_once('-')
            {
                let is_plain_debian_rev = if rest.contains('-') {
                    let parts: Vec<&str> = rest.split('-').collect();
                    let earlier_numeric = parts[..parts.len() - 1]
                        .iter()
                        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
                    earlier_numeric && is_debian_revision_suffix(parts[parts.len() - 1])
                } else {
                    is_debian_revision_suffix(rest)
                };

                if is_plain_debian_rev {
                    return false;
                }
                if !rest.trim().is_empty() {
                    return true;
                }
            }

            if let Some(sv) = parse_semver(semver_core_and_pre) {
                if let Some(ref pre) = sv.prerelease {
                    if !pre.is_empty() {
                        return true;
                    }
                }
            }

            false
        }
    }
}

pub fn is_prerelease_version_for_channel(version_or_tag: &str) -> bool {
    is_prerelease_version_for_channel_with_source(version_or_tag, None)
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
        while (i < ab.len() && !ab[i].is_ascii_digit()) || (j < bb.len() && !bb[j].is_ascii_digit())
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
        s = strip_version_prefix(s);
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
    let s_no_build = match s.split_once('+') {
        Some((v, _)) => v.trim(),
        None => s,
    };
    let norm = normalize_version(s_no_build);
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

    let (normal_str, prerelease_opt) = match rest.find(['-', '~']) {
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
                    let digits = if canonical.is_empty() {
                        "0".to_string()
                    } else {
                        canonical.to_string()
                    };
                    ids.push(PrereleaseIdentifier::Numeric(digits));
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
        let a_norm = normalize_version(a);
        let b_norm = normalize_version(b);
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
                    (PrereleaseIdentifier::Numeric(_), PrereleaseIdentifier::Alpha(_)) => {
                        std::cmp::Ordering::Less
                    }
                    (PrereleaseIdentifier::Alpha(_), PrereleaseIdentifier::Numeric(_)) => {
                        std::cmp::Ordering::Greater
                    }
                    (PrereleaseIdentifier::Alpha(sa), PrereleaseIdentifier::Alpha(sb)) => {
                        sa.cmp(sb)
                    }
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
            ids_a.len().cmp(&ids_b.len())
        }
    }
}

pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let an = normalize_version(a);
    let bn = normalize_version(b);
    if an == bn || an.eq_ignore_ascii_case(bn) {
        return std::cmp::Ordering::Equal;
    }
    if commits_match_prefix(an, bn, false) {
        return std::cmp::Ordering::Equal;
    }
    if is_hex_digits_7_to_40(an)
        && is_hex_digits_7_to_40(bn)
        && !(an.bytes().all(|byte| byte.is_ascii_digit())
            && bn.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return an.to_ascii_lowercase().cmp(&bn.to_ascii_lowercase());
    }
    compare_semver_versions(a, b)
}

pub fn strip_version_prefix(s: &str) -> &str {
    let mut trimmed = s.trim();
    loop {
        let prev = trimmed;
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("release-")
            || lower.starts_with("release_")
            || lower.starts_with("release/")
        {
            trimmed = trimmed[8..].trim();
        } else if lower.starts_with("rel-")
            || lower.starts_with("rel_")
            || lower.starts_with("rel/")
        {
            trimmed = trimmed[4..].trim();
        } else if lower.starts_with("version-")
            || lower.starts_with("version_")
            || lower.starts_with("version/")
        {
            trimmed = trimmed[8..].trim();
        } else if lower.starts_with("ver-")
            || lower.starts_with("ver_")
            || lower.starts_with("ver/")
        {
            trimmed = trimmed[4..].trim();
        } else if let Some(idx) = trimmed.find(['-', '/', '_']) {
            let prefix = &trimmed[..idx];
            if prefix.eq_ignore_ascii_case("release")
                || prefix.eq_ignore_ascii_case("rel")
                || prefix.eq_ignore_ascii_case("version")
                || prefix.eq_ignore_ascii_case("ver")
            {
                trimmed = trimmed[idx + 1..].trim();
            }
        }
        if let Some(rest) = trimmed.strip_prefix(|c: char| c == 'v' || c == 'V') {
            if rest.starts_with(|c: char| c.is_ascii_digit()) || rest.is_empty() {
                trimmed = rest.trim();
            }
        }
        if trimmed == prev {
            break;
        }
    }
    trimmed
}

pub fn normalize_version(s: &str) -> &str {
    strip_version_prefix(s)
}

pub fn normalize_version_str(s: &str) -> &str {
    normalize_version(s)
}

/// Extracts the raw candidate version token from `apt-cache policy` stdout.
/// Returns `None` when no `Candidate:` line is present or the first candidate is empty / `(none)`.
pub fn parse_apt_policy_candidate(stdout: &str) -> Option<&str> {
    let candidate = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("Candidate:"))?
        .trim();
    (!candidate.is_empty() && candidate != "(none)").then_some(candidate)
}

/// Validates an exact Debian/APT package version token per Debian Policy §5.6.12
/// (`[epoch:]upstream_version[-debian_revision]`), rejecting floating tags, globs,
/// release selectors, `v`-prefixed tags, Git SHAs, component manifests, and unsafe characters.
pub fn validate_exact_apt_version(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return false;
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
        return false;
    }
    let rest = if let Some((epoch, rem)) = trimmed.split_once(':') {
        if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        rem
    } else {
        trimmed
    };
    if rest.is_empty() || !rest.starts_with(|c: char| c.is_ascii_digit()) || rest.contains(':') {
        return false;
    }
    if let Some((upstream, rev)) = rest.rsplit_once('-') {
        if upstream.is_empty() || rev.is_empty() {
            return false;
        }
        return upstream
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'~' | b'-'))
            && rev
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'~'));
    }
    rest.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'~'))
}

/// Parses `dpkg-query -W -f=${db:Status-Status} ${Version}\n <pkg>` output, returning
/// the exact full Debian version only when status is strictly `installed` and the version
/// token is a valid Debian version.
pub fn parse_installed_dpkg_status_version(stdout: &str) -> Option<&str> {
    let mut parts = stdout.trim().split_whitespace();
    let status = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || status != "installed" {
        return None;
    }
    validate_exact_apt_version(version).then_some(version)
}

/// Returns whether a legacy stripped `.af-version` receipt (e.g. `0.14.0` or `1.9.1`)
/// is compatible with a live full Debian version (`1:0.14.0-1+deb12u1` or `1.9.1-2+deb13u1`).
/// Exact target certification still requires full-version equality via `versions_match_target`.
pub fn apt_receipt_matches_live_debian_revision(
    update_source: &str,
    receipt_ver: &str,
    live_ver: &str,
) -> bool {
    if !matches!(
        update_source.trim().to_ascii_lowercase().as_str(),
        "apt" | "deb" | "dpkg"
    ) {
        return false;
    }
    let live_trimmed = live_ver.trim();
    let without_epoch = match live_trimmed.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
            rest
        }
        _ => live_trimmed,
    };
    let Some((live_upstream, deb_rev)) = without_epoch.rsplit_once('-') else {
        return false;
    };
    !live_upstream.contains('~')
        && is_valid_apt_debian_revision_suffix(deb_rev)
        && (versions_match_target(receipt_ver, live_upstream)
            || versions_match_target(live_upstream, receipt_ver))
}

pub fn single_version_matches(achieved: &str, expected: &str) -> bool {
    let exp = expected.trim();
    let ach = achieved.trim();
    if exp.is_empty() || ach.is_empty() {
        return false;
    }
    if !validate_target_version(ach) || !validate_target_version(exp) {
        return false;
    }
    let ach_lower = ach.to_ascii_lowercase();
    let exp_lower = exp.to_ascii_lowercase();
    let is_manifest = ach.contains(',')
        || exp.contains(',')
        || ach.contains('=')
        || exp.contains('=')
        || ach_lower.contains("frontend:")
        || exp_lower.contains("frontend:")
        || ach_lower.contains("backend:")
        || exp_lower.contains("backend:")
        || ach_lower.contains("proxy:")
        || exp_lower.contains("proxy:");

    if is_manifest {
        return matches_component_manifest(ach, exp);
    }
    if exp.eq_ignore_ascii_case(ach) {
        return true;
    }
    let norm_exp = normalize_version(exp);
    let norm_ach = normalize_version(ach);
    if norm_exp.eq_ignore_ascii_case(norm_ach) {
        return true;
    }
    let sem_exp = strip_semver_build_metadata(norm_exp);
    let sem_ach = strip_semver_build_metadata(norm_ach);
    if sem_exp.eq_ignore_ascii_case(sem_ach) {
        return true;
    }
    commits_match_prefix(norm_exp, norm_ach, false)
}

pub fn single_version_matches_target(achieved: &str, expected: &str) -> bool {
    let exp = expected.trim();
    let ach = achieved.trim();
    if exp.is_empty() || ach.is_empty() {
        return false;
    }
    let norm_exp = strip_version_prefix(exp);
    let norm_ach = strip_version_prefix(ach);

    // Exact case-sensitive equality of normalized strings
    if norm_ach == norm_exp {
        return true;
    }

    // Only compare case-insensitively when BOTH normalized tokens are pure hexadecimal Git commit SHAs
    let ach_is_hex = is_hex_digits_7_to_40(norm_ach);
    let exp_is_hex = is_hex_digits_7_to_40(norm_exp);

    if ach_is_hex && exp_is_hex {
        if norm_ach.eq_ignore_ascii_case(norm_exp) {
            return true;
        }
        if commits_match_prefix(norm_exp, norm_ach, false) {
            return true;
        }
    }

    false
}

pub fn is_hex_sha_7_to_64(s: &str) -> bool {
    let len = s.len();
    (7..=64).contains(&len) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn is_hex_digits_7_to_64(s: &str) -> bool {
    is_hex_sha_7_to_64(s)
}

fn is_sensitive_key_name(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("api-key")
        || lower.contains("access_key")
        || lower.contains("access-key")
        || lower.contains("private_key")
        || lower.contains("private-key")
        || lower.contains("client_secret")
        || lower.contains("credential")
        || lower.contains("passphrase")
        || lower.contains("auth")
}

fn check_numeric_semver_debian(s: &str) -> bool {
    if s.contains(':') {
        let colon_count = s.matches(':').count();
        if colon_count != 1 {
            return false;
        }
        let (epoch, rest) = match s.split_once(':') {
            Some(pair) => pair,
            None => return false,
        };
        if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if !rest.starts_with(|c: char| c.is_ascii_digit()) {
            return false;
        }
        return rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '~'));
    }

    let rest = if (s.starts_with('v') || s.starts_with('V'))
        && s.len() > 1
        && s[1..]
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
    {
        &s[1..]
    } else {
        s
    };

    if !rest.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }

    rest.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '~'))
}

pub fn validate_single_version_token(ver: &str) -> bool {
    let trimmed = ver.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return false;
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
        return false;
    }
    if trimmed.chars().any(|c| {
        matches!(
            c,
            ';' | '&'
                | '|'
                | '`'
                | '$'
                | '('
                | ')'
                | '<'
                | '>'
                | '"'
                | '\''
                | '*'
                | '?'
                | '!'
                | '{'
                | '}'
        )
    }) {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    const FORBIDDEN_TOKENS: &[&str] = &[
        "latest",
        "unknown",
        "none",
        "null",
        "undefined",
        "error",
        "n/a",
        "na",
        "current",
        "installed",
        "pending",
        "default",
        "auto",
        "true",
        "false",
        "head",
        "main",
        "master",
        "stable",
        "beta",
        "nightly",
        "edge",
        "dev",
        "devel",
        "alpha",
        "rc",
        "release",
    ];
    if FORBIDDEN_TOKENS.contains(&lower.as_str()) {
        return false;
    }

    if is_sensitive_key_name(&lower) {
        return false;
    }

    // b) Valid Git commit SHA (7..=64 hex)
    if is_hex_sha_7_to_64(trimmed) {
        return true;
    }

    // a) Concrete numeric/SemVer/Debian version starting with ASCII digit (0-9)
    if check_numeric_semver_debian(trimmed) {
        return true;
    }

    // Standard release/version prefixes (e.g. Release-v1.0.0, ver-1.0.0)
    let stripped = strip_version_prefix(trimmed);
    if !stripped.is_empty() && stripped != trimmed {
        let stripped_lower = stripped.to_ascii_lowercase();
        if !FORBIDDEN_TOKENS.contains(&stripped_lower.as_str())
            && !is_sensitive_key_name(&stripped_lower)
            && (is_hex_sha_7_to_64(stripped) || check_numeric_semver_debian(stripped))
        {
            return true;
        }
    }

    // c) Valid <prefix>-<sha> where <prefix> is [A-Za-z0-9._-]+ (not sensitive key)
    // and <sha> is 7..=64 hex characters or <prefix> starts with a digit.
    if let Some(idx) = trimmed.rfind('-') {
        let prefix = &trimmed[..idx];
        let sha = &trimmed[idx + 1..];
        if is_hex_sha_7_to_64(sha) && !prefix.is_empty() {
            let prefix_lower = prefix.to_ascii_lowercase();
            if prefix.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
            }) && (prefix.starts_with(|character: char| character.is_ascii_digit())
                || (!FORBIDDEN_TOKENS.contains(&prefix_lower.as_str())
                    && !is_sensitive_key_name(&prefix_lower)))
            {
                return true;
            }
        }
    }

    false
}

pub fn is_valid_component_version(s: &str) -> bool {
    validate_single_version_token(s)
}

pub fn parse_piped_component_manifest(
    s: &str,
) -> Option<std::collections::HashMap<String, String>> {
    parse_component_manifest(s)
}

pub fn parse_component_manifest(s: &str) -> Option<std::collections::HashMap<String, String>> {
    if !s.contains(':') && !s.contains('=') {
        return None;
    }
    let parts: Vec<&str> = s.split(',').collect();
    let mut map = std::collections::HashMap::new();
    for raw_part in &parts {
        let item = raw_part.trim();
        if item.is_empty() {
            return None;
        }
        let delimiter_index = item.find(['=', ':'])?;
        let key = item[..delimiter_index].trim().to_lowercase();
        let val = item[delimiter_index + 1..].trim().to_string();
        if key.is_empty() || val.is_empty() {
            return None;
        }
        if !validate_single_version_token(&val) {
            return None;
        }
        if map.insert(key, val).is_some() {
            return None;
        }
    }
    if map.len() < 2 {
        return None;
    }
    let has_frontend = map.contains_key("frontend");
    let has_backend = map.contains_key("backend");
    let has_proxy = map.contains_key("proxy");
    if has_frontend || has_backend || has_proxy {
        if !has_frontend || !has_backend || !has_proxy || map.len() != 3 || parts.len() != 3 {
            return None;
        }
        for k in ["frontend", "backend", "proxy"] {
            let val = map.get_mut(k)?;
            let norm = normalize_version(val);
            let val_clean = if is_hex_sha_7_to_64(norm) {
                norm.to_ascii_lowercase()
            } else if is_hex_sha_7_to_64(val) {
                val.to_ascii_lowercase()
            } else {
                val.trim().to_string()
            };
            *val = val_clean;
        }
    }
    Some(map)
}

pub fn matches_component_manifest(achieved: &str, expected: &str) -> bool {
    let exp_map = match parse_component_manifest(expected) {
        Some(m) => m,
        None => return false,
    };
    let ach_map = match parse_component_manifest(achieved) {
        Some(m) => m,
        None => return false,
    };
    if exp_map.len() != ach_map.len() {
        return false;
    }
    for (k, exp_val) in &exp_map {
        match ach_map.get(k) {
            Some(ach_val) => {
                let is_hex_pair = (is_hex_digits_7_to_40(exp_val)
                    || is_hex_digits_7_to_40(normalize_version(exp_val)))
                    && (is_hex_digits_7_to_40(ach_val)
                        || is_hex_digits_7_to_40(normalize_version(ach_val)));
                if is_hex_pair {
                    if !commits_match_prefix(exp_val, ach_val, true) {
                        return false;
                    }
                } else if !single_version_matches_target(ach_val, exp_val) {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}

pub fn validate_target_version(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return false;
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
        return false;
    }
    if trimmed.chars().any(|c| {
        matches!(
            c,
            ';' | '&'
                | '|'
                | '`'
                | '$'
                | '('
                | ')'
                | '<'
                | '>'
                | '"'
                | '\''
                | '*'
                | '?'
                | '!'
                | '{'
                | '}'
        )
    }) {
        return false;
    }
    if matches!(
        trimmed.to_ascii_lowercase().as_str(),
        "unknown" | "none" | "null" | "latest"
    ) {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    let is_manifest_candidate = trimmed.contains(',')
        || trimmed.contains('=')
        || lower.contains("frontend:")
        || lower.contains("backend:")
        || lower.contains("proxy:")
        || lower.contains("frontend=")
        || lower.contains("backend=")
        || lower.contains("proxy=");

    if is_manifest_candidate {
        return parse_component_manifest(trimmed).is_some();
    }

    validate_single_version_token(trimmed)
}

pub fn is_valid_target_version_token(s: &str) -> bool {
    validate_target_version(s)
}

pub fn versions_match_target(achieved: &str, expected: &str) -> bool {
    let exp = expected.trim();
    let ach = achieved.trim();
    if exp.is_empty() || ach.is_empty() {
        return false;
    }
    if !validate_target_version(ach) || !validate_target_version(exp) {
        return false;
    }

    let ach_lower = ach.to_ascii_lowercase();
    let exp_lower = exp.to_ascii_lowercase();
    let is_manifest = ach.contains(',')
        || exp.contains(',')
        || ach.contains('=')
        || exp.contains('=')
        || ach_lower.contains("frontend:")
        || exp_lower.contains("frontend:")
        || ach_lower.contains("backend:")
        || exp_lower.contains("backend:")
        || ach_lower.contains("proxy:")
        || exp_lower.contains("proxy:");

    if is_manifest {
        return matches_component_manifest(ach, exp);
    }

    if ach == exp {
        return true;
    }

    single_version_matches_target(ach, exp)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReleaseCommand, ReleaseConfig, ReleaseLockGuard};
    use std::io::{BufRead, Read, Write};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[test]
    fn shared_companion_allows_only_matching_owner_not_unrelated_admin() {
        let (root, _, database, conn) = fixture();
        let owner = OwnerLease::create(&database).unwrap();
        insert(&conn, &owner.id);
        conn.execute(
            "UPDATE package_lifecycle_jobs SET service_units='[\"apache2.service\"]'",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id,service_units) VALUES ('queued','other','update','updating','now',?1,'[\"apache2.service\"]')", [&owner.id]).unwrap();
        assert!(
            check_reservation(&conn, ReservationTarget::Service("apache2"), "job", None).is_err()
        );
        assert!(check_reservation(&conn, ReservationTarget::Service("apache2"), "", None).is_err());
        assert!(check_reservation(
            &conn,
            ReservationTarget::Service("apache2"),
            "foreign",
            None
        )
        .is_err());
        assert!(check_reservation(&conn, ReservationTarget::System, "job", None).is_err());
        conn.execute(
            "UPDATE package_lifecycle_jobs SET status='unknown' WHERE package_id='queued'",
            [],
        )
        .unwrap();
        assert!(
            check_reservation(&conn, ReservationTarget::Service("apache2"), "job", None).is_err()
        );
        drop((conn, owner));
        std::fs::remove_dir_all(root).unwrap();
    }

    fn fixture() -> (PathBuf, ReleaseConfig, PathBuf, Connection) {
        let root = std::env::temp_dir().join(format!("af-owner-{}", uuid::Uuid::new_v4()));
        let cfg = ReleaseConfig::for_root(&root);
        let database = crate::config::try_resolve_db_path(&cfg, None).unwrap().path;
        std::fs::create_dir_all(database.parent().unwrap()).unwrap();
        let conn = Connection::open(&database).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        initialize_schema(&conn).unwrap();
        (root, cfg, database, conn)
    }

    fn insert(conn: &Connection, owner: &str) {
        conn.execute("INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at,owner_id,service_units)
            VALUES ('fixture','job','update','updating','now',?1,'[\"fixture.service\",\"fixture.timer\"]')", [owner]).unwrap();
    }

    fn state(conn: &Connection) -> String {
        conn.query_row("SELECT status FROM package_lifecycle_jobs", [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    fn admission(cfg: &ReleaseConfig) -> crate::ReleaseResult<()> {
        let path = crate::ensure_interoperable_maintenance_lock_file(cfg)?;
        let _guard = ReleaseLockGuard::acquire(path, Duration::ZERO)?;
        crate::admin::ensure_no_active_package_lifecycle_jobs(cfg, ReleaseCommand::Deploy)
    }

    #[test]
    fn finished_jobs_retire_owner_files_without_changing_receipts() {
        let (root, _, database, mut conn) = fixture();
        let directory = database.with_extension("lifecycle-owners");
        for success in [true, false] {
            for index in 0..64 {
                let job = format!("finished-{success}-{index}");
                let lease = admit_job(&mut conn, "fixture", &job, "update", "now", &[]).unwrap();
                assert!(owner_is_alive(&database, &lease.id).unwrap());
                finish_job(&conn, "fixture", &job, "update", success, "configuration").unwrap();
                let receipt: (String, String, String, String, String) = conn
                    .query_row(
                        "SELECT owner_id,job_id,action,status,failure_category FROM package_lifecycle_jobs",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                    )
                    .unwrap();
                assert_eq!(receipt.0, lease.id);
                assert_eq!(receipt.1, job);
                assert_eq!(receipt.2, "update");
                assert_eq!(receipt.3, if success { "completed" } else { "failed" });
                assert_eq!(receipt.4, if success { "" } else { "configuration" });
                assert!(owner_is_alive(&database, &lease.id).unwrap());
                drop(lease);
                assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
            }
        }
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_preserves_shared_active_owner_and_direct_sql_receipts() {
        let (root, _, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        let owner = lease.id.clone();
        insert(&conn, &owner);
        conn.execute("INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id) VALUES ('other','other-job','remove','uninstalling','now',?1)", [&owner]).unwrap();
        conn.execute("UPDATE package_lifecycle_jobs SET status='failed',finished_at='finished',failure_category='configuration' WHERE package_id='fixture'", []).unwrap();
        drop(lease);
        assert!(lease_path(&database, &owner).unwrap().exists());
        assert!(!owner_is_alive(&database, &owner).unwrap());
        check_reservation(
            &conn,
            ReservationTarget::Package("other"),
            "other-job",
            Some("remove"),
        )
        .unwrap();
        assert!(check_reservation(
            &conn,
            ReservationTarget::Package("other"),
            "job",
            Some("remove")
        )
        .is_err());
        reconcile_jobs(&conn, &database).unwrap();
        assert!(!lease_path(&database, &owner).unwrap().exists());
        let receipts: Vec<(String, String, String, String, String)> = conn
            .prepare("SELECT package_id,job_id,action,status,owner_id FROM package_lifecycle_jobs ORDER BY package_id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            receipts,
            vec![
                (
                    "fixture".into(),
                    "job".into(),
                    "update".into(),
                    "failed".into(),
                    owner.clone()
                ),
                (
                    "other".into(),
                    "other-job".into(),
                    "remove".into(),
                    "interrupted".into(),
                    owner
                ),
            ]
        );
        let finished: String = conn
            .query_row(
                "SELECT finished_at FROM package_lifecycle_jobs WHERE package_id='fixture'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(finished, "finished");
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn terminal_cleanup_preserves_live_and_successor_owner_identities() {
        let (root, _, database, mut conn) = fixture();
        let lease = admit_job(&mut conn, "fixture", "first", "update", "now", &[]).unwrap();
        let first_path = lease_path(&database, &lease.id).unwrap();
        finish_job(&conn, "fixture", "first", "update", true, "").unwrap();
        reconcile_jobs(&conn, &database).unwrap();
        assert!(owner_is_alive(&database, &lease.id).unwrap());
        let successor = admit_job(&mut conn, "fixture", "second", "remove", "later", &[]).unwrap();
        let successor_path = lease_path(&database, &successor.id).unwrap();
        assert_ne!(lease.id, successor.id);
        drop(lease);
        assert!(!first_path.exists());
        assert!(owner_is_alive(&database, &successor.id).unwrap());
        for (package, job, action) in [
            ("fixture", "first", "update"),
            ("other", "second", "remove"),
            ("fixture", "second", "update"),
        ] {
            assert!(finish_job(&conn, package, job, action, true, "").is_err());
        }
        let identity: (String, String, String, String) = conn
            .query_row(
                "SELECT job_id,action,status,owner_id FROM package_lifecycle_jobs",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            identity,
            (
                "second".into(),
                "remove".into(),
                "uninstalling".into(),
                successor.id.clone()
            )
        );
        drop(successor);
        assert!(successor_path.exists());
        reconcile_jobs(&conn, &database).unwrap();
        assert_eq!(state(&conn), "interrupted");
        assert!(!successor_path.exists());
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uncommitted_receipts_never_remove_recovery_evidence() {
        let (root, _, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        insert(&conn, &lease.id);
        let path = lease_path(&database, &lease.id).unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        finish_job(&conn, "fixture", "job", "update", true, "").unwrap();
        drop(lease);
        retire_finished_owners(&conn, &database).unwrap();
        assert!(path.exists());
        conn.execute_batch("ROLLBACK").unwrap();
        assert_eq!(state(&conn), "updating");
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        reconcile_jobs(&conn, &database).unwrap();
        assert_eq!(state(&conn), "interrupted");
        assert!(path.exists());
        conn.execute_batch("ROLLBACK").unwrap();
        assert_eq!(state(&conn), "updating");
        reconcile_jobs(&conn, &database).unwrap();
        assert_eq!(state(&conn), "interrupted");
        assert!(!path.exists());
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn cleanup_failures_preserve_receipts_and_retry_without_weakening_locks() {
        use std::os::unix::fs::PermissionsExt;

        let (root, _, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        insert(&conn, &lease.id);
        let path = lease_path(&database, &lease.id).unwrap();
        let directory = path.parent().unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o777)).unwrap();
        finish_job(&conn, "fixture", "job", "update", false, "configuration").unwrap();
        drop(lease);
        assert!(path.exists());
        reconcile_jobs(&conn, &database).unwrap();
        assert!(path.exists());
        assert_eq!(state(&conn), "failed");
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        reconcile_jobs(&conn, &database).unwrap();
        assert!(!path.exists());
        assert_eq!(state(&conn), "failed");
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn link_substitutions_never_unlink_executor_locks_or_owner_evidence() {
        use std::os::unix::fs::{symlink, MetadataExt};

        for hard_link in [false, true] {
            let (root, _, database, conn) = fixture();
            let lease = OwnerLease::create(&database).unwrap();
            insert(&conn, &lease.id);
            let path = lease_path(&database, &lease.id).unwrap();
            let evidence = root.join("original-owner");
            std::fs::rename(&path, &evidence).unwrap();
            let executor_path = root.join("package-executor.lock");
            let executor = ReleaseLockGuard::acquire(&executor_path, Duration::ZERO).unwrap();
            let executor_identity = executor.file_identity().unwrap();
            let executor_contents = std::fs::read(&executor_path).unwrap();
            if hard_link {
                std::fs::hard_link(&executor_path, &path).unwrap();
            } else {
                symlink(&executor_path, &path).unwrap();
            }
            assert!(owner_is_alive(&database, &lease.id).is_err());
            reconcile_jobs(&conn, &database).unwrap();
            assert_eq!(state(&conn), "updating");
            finish_job(&conn, "fixture", "job", "update", true, "").unwrap();
            drop(lease);
            reconcile_jobs(&conn, &database).unwrap();
            assert!(std::fs::symlink_metadata(&path).is_ok());
            assert!(evidence.exists());
            assert_eq!(std::fs::read(&executor_path).unwrap(), executor_contents);
            let metadata = std::fs::metadata(&executor_path).unwrap();
            assert_eq!((metadata.dev(), metadata.ino()), executor_identity);
            assert!(ReleaseLockGuard::acquire(&executor_path, Duration::ZERO).is_err());
            assert_eq!(state(&conn), "completed");
            drop((conn, executor));
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    #[cfg(unix)]
    fn owner_directory_symlink_substitution_is_not_followed_during_cleanup() {
        use std::os::unix::fs::symlink;

        let (root, _, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        insert(&conn, &lease.id);
        finish_job(&conn, "fixture", "job", "update", true, "").unwrap();
        let directory = database.with_extension("lifecycle-owners");
        let saved = root.join("saved-owners");
        let substituted = root.join("unrelated-owners");
        std::fs::create_dir(&substituted).unwrap();
        let sentinel = substituted.join(&lease.id);
        std::fs::write(&sentinel, b"unrelated executor evidence").unwrap();
        std::fs::rename(&directory, &saved).unwrap();
        symlink(&substituted, &directory).unwrap();
        drop(lease);
        reconcile_jobs(&conn, &database).unwrap();
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"unrelated executor evidence"
        );
        assert_eq!(std::fs::read_dir(&saved).unwrap().count(), 1);
        std::fs::remove_file(&directory).unwrap();
        std::fs::rename(&saved, &directory).unwrap();
        reconcile_jobs(&conn, &database).unwrap();
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        assert!(sentinel.exists());
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn live_owner_survives_same_process_reopen_and_dead_owner_is_interrupted() {
        let (root, cfg, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        let path = lease_path(&database, &lease.id).unwrap();
        insert(&conn, &lease.id);
        let replacement_instance = OwnerLease::create(&database).unwrap();
        assert_ne!(replacement_instance.id, lease.id);
        drop(replacement_instance);
        assert!(admission(&cfg).is_err());
        assert_eq!(state(&conn), "updating");
        check_reservation(
            &conn,
            ReservationTarget::Service("fixture.timer"),
            "job",
            None,
        )
        .unwrap();
        assert!(check_reservation(
            &conn,
            ReservationTarget::Package("fixture"),
            "job",
            Some("remove")
        )
        .is_err());
        check_reservation(
            &conn,
            ReservationTarget::Package("other"),
            "",
            Some("remove"),
        )
        .unwrap();
        drop(lease);
        assert!(path.exists());
        admission(&cfg).unwrap();
        assert_eq!(state(&conn), "interrupted");
        assert!(!path.exists());
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn inherited_maintenance_survives_guard_drop_until_child_exits() {
        let (root, cfg, _database, conn) = fixture();
        let path = crate::ensure_interoperable_maintenance_lock_file(&cfg).unwrap();
        let guard = ReleaseLockGuard::acquire(&path, Duration::ZERO).unwrap();
        let mut command = Command::new("/bin/cat");
        command.stdin(Stdio::piped()).stdout(Stdio::null());
        guard.preserve_in_child(&mut command).unwrap();
        let mut child = command.spawn().unwrap();
        drop(command);
        drop(guard);
        assert!(admission(&cfg).is_err());
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        admission(&cfg).unwrap();
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_lifecycle_table_preserves_explicit_rollback_admission() {
        use std::io::{Seek, SeekFrom};
        let (root, cfg, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        insert(&conn, &lease.id);
        let page: u64 = conn
            .query_row(
                "SELECT rootpage FROM sqlite_master WHERE name='package_lifecycle_jobs'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let size: u64 = conn
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .unwrap();
        drop(conn);
        let mut file = OpenOptions::new().write(true).open(&database).unwrap();
        file.seek(SeekFrom::Start((page - 1) * size)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let lock = crate::ensure_interoperable_maintenance_lock_file(&cfg).unwrap();
        let _guard = ReleaseLockGuard::acquire(lock, Duration::ZERO).unwrap();
        assert!(crate::admin::ensure_no_active_package_lifecycle_jobs(
            &cfg,
            ReleaseCommand::Deploy
        )
        .is_err());
        crate::admin::ensure_no_active_package_lifecycle_jobs(&cfg, ReleaseCommand::Rollback)
            .unwrap();
        drop(lease);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_owners_fail_closed_and_runner_lock_prevents_premature_reconciliation() {
        let (root, cfg, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        insert(&conn, &lease.id);
        let lock = crate::ensure_interoperable_maintenance_lock_file(&cfg).unwrap();
        let runner = ReleaseLockGuard::acquire(&lock, Duration::ZERO).unwrap();
        drop(lease);
        assert!(admission(&cfg).is_err());
        assert_eq!(state(&conn), "updating");
        drop(runner);
        admission(&cfg).unwrap();
        assert_eq!(state(&conn), "interrupted");
        for unknown in ["", "bad-identity", "c37209aa-a27b-4812-b2ae-cbb605d04135"] {
            conn.execute(
                "UPDATE package_lifecycle_jobs SET status='updating',owner_id=?1",
                [unknown],
            )
            .unwrap();
            assert!(admission(&cfg).is_err());
            assert_eq!(state(&conn), "updating");
        }
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn standalone_recovers_crashed_api_without_starting_api_or_erasing_release_recovery() {
        const WORKER: &str = "AF_OWNER_CRASH_FIXTURE";
        if let Some(database) = std::env::var_os(WORKER) {
            let database = PathBuf::from(database);
            let conn = Connection::open(&database).unwrap();
            let lease = OwnerLease::create(&database).unwrap();
            insert(&conn, &lease.id);
            println!("OWNER_READY");
            std::io::stdout().flush().unwrap();
            let mut release = [0u8];
            std::io::stdin().read_exact(&mut release).unwrap();
            drop(lease);
            return;
        }
        let (root, cfg, database, conn) = fixture();
        std::fs::create_dir_all(&cfg.releases_dir).unwrap();
        let recovery = cfg.releases_dir.join(".recovery_state.json");
        std::fs::write(&recovery, b"release-recovery-sentinel").unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "lifecycle::tests::standalone_recovers_crashed_api_without_starting_api_or_erasing_release_recovery", "--nocapture"])
            .env(WORKER, &database).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(output.read_line(&mut line).unwrap(), 0);
            if line.contains("OWNER_READY") {
                break;
            }
        }
        assert!(admission(&cfg).is_err());
        let owner: String = conn
            .query_row("SELECT owner_id FROM package_lifecycle_jobs", [], |row| {
                row.get(0)
            })
            .unwrap();
        let path = lease_path(&database, &owner).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(path.exists());
        assert!(!owner_is_alive(&database, &owner).unwrap());
        admission(&cfg).unwrap();
        assert_eq!(state(&conn), "interrupted");
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(&recovery).unwrap(),
            b"release-recovery-sentinel"
        );
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_package_lifecycle_history_and_diagnostics() {
        let (root, _, _database, mut conn) = fixture();
        let lease = admit_job_with_target(
            &mut conn,
            "radarr",
            "job-history-1",
            "update",
            "2026-11-08T12:00:00Z",
            &[],
            Some("5.3.6"),
        )
        .unwrap();

        finish_job_with_diagnostics(
            &conn,
            "radarr",
            "job-history-1",
            "update",
            false,
            LifecycleJobDiagnostics {
                failure_category: "target_verification",
                failed_stage: Some("target_verification"),
                exit_code: Some(1),
                sanitized_summary: Some("version did not advance"),
                expected_target_version: Some("5.3.6"),
                achieved_version: Some("5.3.5"),
                ..Default::default()
            },
        )
        .unwrap();

        let history = get_lifecycle_history(&conn, "radarr", 10).unwrap();
        assert_eq!(history.len(), 1);
        let item = &history[0];
        assert_eq!(item.job_id, "job-history-1");
        assert_eq!(item.status, "failed");
        assert_eq!(item.expected_target_version.as_deref(), Some("5.3.6"));
        assert_eq!(item.achieved_version.as_deref(), Some("5.3.5"));
        assert_eq!(item.failed_stage.as_deref(), Some("target_verification"));
        assert_eq!(item.exit_code, Some(1));

        // Start a second job
        let lease2 = admit_job_with_target(
            &mut conn,
            "radarr",
            "job-history-2",
            "update",
            "2026-11-08T12:05:00Z",
            &[],
            Some("5.3.6"),
        )
        .unwrap();

        finish_job_with_diagnostics(
            &conn,
            "radarr",
            "job-history-2",
            "update",
            true,
            LifecycleJobDiagnostics {
                exit_code: Some(0),
                expected_target_version: Some("5.3.6"),
                achieved_version: Some("5.3.6"),
                ..Default::default()
            },
        )
        .unwrap();

        let history_updated = get_lifecycle_history(&conn, "radarr", 10).unwrap();
        assert_eq!(history_updated.len(), 2);
        assert_eq!(history_updated[0].job_id, "job-history-2");
        assert_eq!(history_updated[0].status, "completed");
        assert_eq!(
            history_updated[0].achieved_version.as_deref(),
            Some("5.3.6")
        );
        assert_eq!(history_updated[1].job_id, "job-history-1");

        drop(lease);
        drop(lease2);
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_strict_hex_commit_and_tokens() {
        // 8-digit decimal date must NOT be treated as hex commit
        assert!(!is_hex_commit("20261108"));
        assert!(!is_hex_commit("1234567"));
        assert!(!is_hex_commit("123456")); // too short

        // Valid short hex with letters
        assert!(is_hex_commit("202611a"));
        assert!(is_hex_commit("abcdef0"));
        assert!(is_hex_commit("0123456789abcdef"));

        // 40-char commit
        assert!(is_hex_commit("0000000000000000000000000000000000000000"));
        assert!(is_hex_commit("4b825dc642cb6eb9a060e54bf8d69288fbee4904"));

        // is_valid_target_version_token
        assert!(!is_valid_target_version_token(""));
        assert!(!is_valid_target_version_token("   "));
        assert!(!is_valid_target_version_token("latest"));
        assert!(!is_valid_target_version_token("LATEST"));
        assert!(!is_valid_target_version_token("unknown"));
        assert!(!is_valid_target_version_token("none"));
        assert!(!is_valid_target_version_token("null"));
        assert!(!is_valid_target_version_token("v1.0 with space"));

        assert!(is_valid_target_version_token("v1.2.3"));
        assert!(is_valid_target_version_token("1.2.3"));
        assert!(is_valid_target_version_token("release-1.0.0"));
        assert!(is_valid_target_version_token("1234567")); // 7-digit short hex
        assert!(is_valid_target_version_token(
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        ));
        assert!(is_valid_target_version_token(
            "frontend:4b825dc,backend:012345a,proxy:abcdef1"
        ));
    }

    #[test]
    fn test_parse_manifest_and_version_match() {
        // Duplicate keys rejected
        assert!(parse_component_manifest("frontend:4b825dc,frontend:012345a").is_none());
        // Fewer than 2 components rejected
        assert!(parse_component_manifest("frontend:4b825dc").is_none());
        // Frontend/backend/proxy requires all 3
        assert!(parse_component_manifest("frontend:4b825dc,backend:012345a").is_none());
        assert!(parse_component_manifest("backend:012345a,proxy:abcdef1").is_none());
        // All 3 with hex commits valid (including all-digit short SHAs)
        let m = parse_component_manifest("frontend:4b825dc,backend:012345a,proxy:abcdef1");
        assert!(m.is_some());
        assert!(
            parse_component_manifest("frontend:20261108,backend:012345a,proxy:abcdef1").is_some()
        );
        // All 3 but non-hex commit rejected
        assert!(
            parse_component_manifest("frontend:nothex12,backend:012345a,proxy:abcdef1").is_none()
        );

        // versions_match_target with manifests
        let exp = "frontend:4b825dc642cb,backend:012345abcdef,proxy:abcdef123456";
        let ach = "frontend:4b825dc,backend:012345a,proxy:abcdef1";
        assert!(versions_match_target(ach, exp));

        // Different length manifest must fail
        let ach_extra = "frontend:4b825dc,backend:012345a,proxy:abcdef1,extra:v1.0";
        assert!(!versions_match_target(ach_extra, exp));
    }

    #[test]
    fn test_case_insensitive_and_all_digit_git_shas() {
        // 1. Case-insensitive SHA prefix matching
        let full_lower = "abcdef1234567890abcdef1234567890abcdef12";
        let short_upper = "ABCDEF12";
        assert!(single_version_matches(short_upper, full_lower));
        assert!(single_version_matches(full_lower, short_upper));
        assert!(versions_match_target(short_upper, full_lower));
        assert!(versions_match_target(full_lower, short_upper));

        // 2. All-digit short Git SHA matching 40-char SHA
        let all_digit_short = "1234567";
        let full_with_hex = "1234567abcdef0123456789abcdef0123456789a"; // 40 chars
        assert_eq!(full_with_hex.len(), 40);
        assert!(single_version_matches(all_digit_short, full_with_hex));
        assert!(single_version_matches(full_with_hex, all_digit_short));
        assert!(versions_match_target(all_digit_short, full_with_hex));

        // Inside frontend,backend,proxy Git manifest, even two all-digit short SHAs match
        let exp_git_manifest = "frontend:1234567890,backend:0123456789,proxy:9876543210";
        let ach_git_manifest = "frontend:1234567,backend:0123456,proxy:9876543";
        assert!(versions_match_target(ach_git_manifest, exp_git_manifest));

        // But 8/9 digit decimal release dates without 40-char context do NOT prefix-match
        assert!(!single_version_matches("20261108", "202611080"));
        assert!(!versions_match_target("20261108", "202611080"));

        // 3. Generic component manifests comp1:1.1,comp2:2.0 vs comp1:1.10,comp2:2.0 do NOT match
        let gen1 = "comp1:1.1,comp2:2.0";
        let gen2 = "comp1:1.10,comp2:2.0";
        assert!(!versions_match_target(gen1, gen2));
        assert!(!versions_match_target(gen2, gen1));

        let gen_same = "comp1:1.1,comp2:2.0";
        assert!(versions_match_target(gen1, gen_same));
    }

    #[test]
    fn test_finish_job_inserts_history_if_0_rows_updated() {
        let (root, _, _database, mut conn) = fixture();
        let lease = admit_job_with_target(
            &mut conn,
            "prowlarr",
            "job-zero-row-1",
            "update",
            "2026-11-08T12:00:00Z",
            &[],
            Some("1.0.0"),
        )
        .unwrap();

        // Delete history row to simulate 0-row update
        conn.execute(
            "DELETE FROM package_lifecycle_history WHERE job_id='job-zero-row-1'",
            [],
        )
        .unwrap();

        // Finish should insert new history row
        finish_job_with_diagnostics(
            &conn,
            "prowlarr",
            "job-zero-row-1",
            "update",
            true,
            LifecycleJobDiagnostics {
                exit_code: Some(0),
                expected_target_version: Some("1.0.0"),
                achieved_version: Some("1.0.0"),
                ..Default::default()
            },
        )
        .unwrap();

        let history = get_lifecycle_history(&conn, "prowlarr", 10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].job_id, "job-zero-row-1");
        assert_eq!(history[0].status, "completed");

        drop(lease);
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_normalize_version_and_semver_build_metadata() {
        assert_eq!(normalize_version("v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("V1.2.3"), "1.2.3");
        assert_eq!(normalize_version("release-1.2.3"), "1.2.3");
        assert_eq!(normalize_version("release_1.2.3"), "1.2.3");
        assert_eq!(normalize_version("release/1.2.3"), "1.2.3");
        assert_eq!(normalize_version("rel-1.2.3"), "1.2.3");
        assert_eq!(normalize_version("rel_1.2.3"), "1.2.3");
        assert_eq!(normalize_version("release-v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("rel_v1.2.3"), "1.2.3");

        // Build metadata identity preserved across normalization (+debug, +git1, +b1, +20260101, etc.)
        assert_eq!(normalize_version("1.0.0+build.2"), "1.0.0+build.2");
        assert_eq!(normalize_version("1.0.0+debug"), "1.0.0+debug");
        assert_eq!(normalize_version("1.0.0+beta"), "1.0.0+beta");
        assert_eq!(normalize_version("1.0.0+upstream"), "1.0.0+upstream");
        assert_eq!(normalize_version("v1.0.0+20241108"), "1.0.0+20241108");
        assert_eq!(
            normalize_version("1.0.0-rc.1+build.42"),
            "1.0.0-rc.1+build.42"
        );

        // Stacked prefixes stripped
        assert_eq!(normalize_version("release-v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("release_v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("rel-v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("rel_v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("release/v1.2.3"), "1.2.3");

        // Debian + revisions preserved
        assert_eq!(normalize_version("1.2.3+deb11u1"), "1.2.3+deb11u1");
        assert_eq!(normalize_version("1.2.3+deb12u2"), "1.2.3+deb12u2");
        assert_eq!(normalize_version("1.0.0+dfsg"), "1.0.0+dfsg");
        assert_eq!(normalize_version("1.0.0+dfsg1"), "1.0.0+dfsg1");
        assert_eq!(normalize_version("1.0.0+dfsg.1"), "1.0.0+dfsg.1");
        assert_eq!(normalize_version("1.0.0+dfsg-1"), "1.0.0+dfsg-1");
        assert_eq!(normalize_version("1.0.0+ds1"), "1.0.0+ds1");
        assert_eq!(normalize_version("1.0.0+really2.0"), "1.0.0+really2.0");
        assert_eq!(normalize_version("1.0.0+nmu1"), "1.0.0+nmu1");
        assert_eq!(normalize_version("1.0.0+b1"), "1.0.0+b1");
        assert_eq!(normalize_version("1.0.0+b2"), "1.0.0+b2");
        assert_eq!(normalize_version("1.0.0+u2"), "1.0.0+u2");

        // normalize_version_str alias preserves build metadata
        assert_eq!(
            normalize_version_str("release_2.0.0+build.1"),
            "2.0.0+build.1"
        );

        // single_version_matches works with build metadata & release prefixes (SemVer equivalence)
        assert!(single_version_matches("1.0.0+build.2", "1.0.0"));
        assert!(single_version_matches("1.0.0", "1.0.0+build.2"));
        assert!(single_version_matches("1.0.0+debug", "1.0.0"));
        assert!(single_version_matches("release-v1.0.0", "1.0.0"));
        assert!(single_version_matches("release_1.0.0", "v1.0.0"));

        // Target certification distinguishes build metadata (+debug, +build.2, etc.)
        assert!(!versions_match_target("1.0.0", "1.0.0+debug"));
        assert!(!versions_match_target("1.0.0+debug", "1.0.0"));
        assert!(!versions_match_target("1.0.0+build.2", "1.0.0"));
        assert!(versions_match_target("1.0.0+debug", "v1.0.0+debug"));
        assert!(versions_match_target("1.0.0+debug", "release-v1.0.0+debug"));
    }

    #[test]
    fn test_piped_manifest_delimiters_and_component_versions() {
        // Both '=' and ':' delimiters are accepted for 3-component piped manifests
        assert!(matches_component_manifest(
            "frontend=1.0,backend=2.0,proxy=3.0",
            "frontend:1.0,backend:2.0,proxy:3.0"
        ));
        assert!(matches_component_manifest(
            "frontend:1.0,backend:2.0,proxy:3.0",
            "frontend=1.0,backend=2.0,proxy:3.0"
        ));
        assert!(matches_component_manifest(
            "frontend=v1.0,backend=v2.0,proxy=v3.0",
            "frontend=1.0,backend=2.0,proxy:3.0"
        ));
        assert!(versions_match_target(
            "frontend=1.0,backend=2.0,proxy=3.0",
            "frontend:1.0,backend:2.0,proxy:3.0"
        ));
        assert!(versions_match_target(
            "frontend=v1.0,backend=v2.0,proxy=v3.0",
            "frontend:1.0,backend:2.0,proxy:3.0"
        ));
    }

    #[test]
    fn test_source_aware_target_validation_debian_and_manifest() {
        assert!(validate_target_version("1.0~rc1-1"));
        assert!(validate_target_version("1:1.0-1"));
        assert!(validate_target_version("1.0.0+git1"));
        assert!(validate_target_version(
            "frontend=1.0,backend=2.0,proxy=3.0"
        ));
        assert!(validate_target_version(
            "frontend:1.0,backend:2.0,proxy:3.0"
        ));

        // Dangerous characters rejected
        assert!(!validate_target_version("../etc/passwd"));
        assert!(!validate_target_version("1.0.0; rm -rf /"));
        assert!(!validate_target_version("1.0.0 && whoami"));
        assert!(!validate_target_version("latest"));
        assert!(!validate_target_version("unknown"));
        assert!(!validate_target_version(""));
    }

    #[test]
    fn test_case_preservation_for_target_certification() {
        assert!(!versions_match_target("1.0.0+Debug", "1.0.0+debug"));
        assert!(!versions_match_target("1.0.0+debug", "1.0.0+Debug"));
        assert!(versions_match_target("1.0.0+Debug", "v1.0.0+Debug"));
        assert!(versions_match_target("Release-v1.0.0+Debug", "1.0.0+Debug"));
        assert!(versions_match_target("version-v1.0.0+Debug", "1.0.0+Debug"));
        assert!(versions_match_target("ver-1.0.0+Debug", "1.0.0+Debug"));
        assert!(versions_match_target("deadbeef1234", "DEADBEEF1234"));
        assert!(versions_match_target("DEADBEEF1234", "deadbeef1234"));
    }

    #[test]
    fn test_reject_incomplete_or_malformed_component_manifests() {
        assert!(!validate_target_version("frontend=1.0,backend=2.0"));
        assert!(!validate_target_version("frontend:1.0,backend:2.0"));
        assert!(!validate_target_version("frontend=1.0,backend=2.0,proxy="));
        assert!(!validate_target_version(
            "frontend=1.0,backend=2.0,proxy=3.0,extra=4.0"
        ));

        assert!(validate_target_version(
            "frontend=1.0,backend=2.0,proxy=3.0"
        ));
        assert!(validate_target_version(
            "frontend:1.0,backend:2.0,proxy:3.0"
        ));
        assert!(validate_target_version("1:1.0.0~rc1-1+b1"));
    }

    #[test]
    fn test_parse_component_manifest_rejects_empty_and_duplicate_entries() {
        // Empty segments (leading, trailing, double comma, whitespace-padded)
        assert!(parse_component_manifest("frontend=1.0,,backend=2.0,proxy=3.0").is_none());
        assert!(parse_component_manifest("frontend=1.0,backend=2.0,proxy=3.0,").is_none());
        assert!(parse_component_manifest(",frontend=1.0,backend=2.0,proxy=3.0").is_none());
        assert!(parse_component_manifest("frontend=1.0,  ,backend=2.0,proxy=3.0").is_none());
        assert!(!validate_target_version(
            "frontend=1.0,,backend=2.0,proxy=3.0"
        ));
        assert!(!validate_target_version(
            "frontend=1.0,backend=2.0,proxy=3.0,"
        ));
        assert!(!validate_target_version(
            ",frontend=1.0,backend=2.0,proxy=3.0"
        ));
        assert!(!validate_target_version(
            "frontend=1.0,  ,backend=2.0,proxy=3.0"
        ));

        // Duplicate component keys
        assert!(
            parse_component_manifest("frontend=1.0,frontend=2.0,backend=2.0,proxy=3.0").is_none()
        );
        assert!(
            parse_component_manifest("frontend:1.0,backend:2.0,proxy:3.0,backend:2.0").is_none()
        );
        assert!(parse_component_manifest("frontend:1.0,backend:2.0,proxy:3.0,proxy:3.0").is_none());
        assert!(!validate_target_version(
            "frontend=1.0,frontend=2.0,backend=2.0,proxy=3.0"
        ));
        assert!(!validate_target_version(
            "frontend:1.0,backend:2.0,proxy:3.0,backend:2.0"
        ));
    }

    #[test]
    fn test_malformed_manifest_never_matches_itself() {
        assert!(!versions_match_target(
            "frontend=1.0,,backend=2.0,proxy=3.0",
            "frontend=1.0,,backend=2.0,proxy=3.0"
        ));
        assert!(!single_version_matches(
            "frontend=1.0,,backend=2.0,proxy=3.0",
            "frontend=1.0,,backend=2.0,proxy=3.0"
        ));
    }

    #[test]
    fn test_target_validator_rejects_credential_tokens_and_preserves_debian_epoch() {
        assert!(!validate_target_version("password:secret"));
        assert!(!validate_target_version("token:abc"));
        assert!(!validate_target_version("user:pass"));
        assert!(validate_target_version("1:1.0.0~rc1-1+b1"));
        assert!(validate_target_version("0:1.0.0"));
        assert!(validate_target_version("1.0.0+build-"));
        assert!(validate_target_version("1.0.0+build--"));
    }

    #[test]
    fn test_persisting_lifecycle_outcome_sanitizes_credentials_and_secrets() {
        let (root, _, _database, mut conn) = fixture();
        let lease = admit_job_with_target(
            &mut conn,
            "testpkg",
            "job-secret-1",
            "update",
            "2026-11-08T12:00:00Z",
            &[],
            Some("password:secret"),
        )
        .unwrap();

        finish_job_with_diagnostics(
            &conn,
            "testpkg",
            "job-secret-1",
            "update",
            false,
            LifecycleJobDiagnostics {
                failure_category: "configuration",
                failed_stage: Some("install_stage"),
                exit_code: Some(1),
                sanitized_summary: Some("password='prefix\nPERSISTED_QUOTE_CANARY' curl -u operator:\" PERSISTED_QUOTE_CANARY\" --verbose; failed connecting with Bearer supersecret and curl -u admin:hunter2 https://example.com"),
                expected_target_version: Some("password:secret"),
                achieved_version: Some("0.9.0"),
                ..Default::default()
            },
        )
        .unwrap();

        let history = get_lifecycle_history(&conn, "testpkg", 10).unwrap();
        assert_eq!(history.len(), 1);
        let record = &history[0];

        let summary = record.sanitized_summary.as_deref().unwrap();
        assert!(summary.contains("[REDACTED]"));
        assert!(!summary.contains("supersecret"));
        assert!(!summary.contains("hunter2"));
        assert!(!summary.contains("PERSISTED_QUOTE_CANARY"));

        let expected = record.expected_target_version.as_deref().unwrap();
        assert!(expected.contains("[REDACTED]"));
        assert!(!expected.contains("password:secret"));

        drop(lease);
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_sanitize_persisted_lifecycle_text_quoted_credentials() {
        assert_eq!(
            sanitize_persisted_lifecycle_text("password=\"first SECRET_TAIL\""),
            "password=[REDACTED]"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("secret='multi word secret'"),
            "secret=[REDACTED]"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("\"password\": \"first SECRET_TAIL\""),
            "\"password\": [REDACTED]"
        );
        let sample = "config with password=\"first SECRET_TAIL\" and secret='multi word secret' and \"password\": \"first SECRET_TAIL\" done";
        let sanitized = sanitize_persisted_lifecycle_text(sample);
        assert!(!sanitized.contains("SECRET_TAIL"));
        assert!(!sanitized.contains("multi word secret"));
        assert!(sanitized.contains("password=[REDACTED]"));
        assert!(sanitized.contains("secret=[REDACTED]"));
        assert!(sanitized.contains("\"password\": [REDACTED]"));
    }

    #[test]
    fn test_invalid_placeholder_and_channel_manifests_rejected() {
        assert!(!validate_target_version(
            "frontend:latest,backend:latest,proxy:latest"
        ));
        assert!(!validate_target_version("comp1:latest,comp2:unknown"));
        assert!(!validate_target_version(
            "frontend=unknown,backend=1.0.0,proxy=1.0.0"
        ));

        assert!(!versions_match_target(
            "frontend:latest,backend:latest,proxy:latest",
            "frontend:latest,backend:latest,proxy:latest"
        ));
        assert!(!versions_match_target(
            "comp1:latest,comp2:unknown",
            "comp1:latest,comp2:unknown"
        ));
        assert!(!versions_match_target(
            "frontend=unknown,backend=1.0.0,proxy=1.0.0",
            "frontend=unknown,backend=1.0.0,proxy=1.0.0"
        ));
        assert!(parse_component_manifest("frontend:latest,backend:latest,proxy:latest").is_none());
        assert!(
            parse_piped_component_manifest("frontend:latest,backend:latest,proxy:latest").is_none()
        );
        assert!(parse_component_manifest("comp1:latest,comp2:unknown").is_none());
    }

    #[test]
    fn test_sensitive_credentials_redaction_and_job_recording() {
        let sample1 = r#"{"db_password": "my_super_secret_db_pw"}"#;
        let sanitized1 = sanitize_persisted_lifecycle_text(sample1);
        assert!(!sanitized1.contains("my_super_secret_db_pw"));
        assert!(sanitized1.contains(r#"{"db_password": [REDACTED]}"#));

        let sample2 = "db_password=my_super_secret_db_pw";
        let sanitized2 = sanitize_persisted_lifecycle_text(sample2);
        assert!(!sanitized2.contains("my_super_secret_db_pw"));
        assert_eq!(sanitized2, "db_password=[REDACTED]");

        let sample3 = r#"admin_secret="first \"escaped_quote_secret\" tail_secret""#;
        let sanitized3 = sanitize_persisted_lifecycle_text(sample3);
        assert!(!sanitized3.contains("escaped_quote_secret"));
        assert!(!sanitized3.contains("tail_secret"));
        assert_eq!(sanitized3, "admin_secret=[REDACTED]");

        let sample4 = r#"{"secret": "first \"escaped_quote_secret\" tail_secret"}"#;
        let sanitized4 = sanitize_persisted_lifecycle_text(sample4);
        assert!(!sanitized4.contains("escaped_quote_secret"));
        assert!(!sanitized4.contains("tail_secret"));
        assert!(sanitized4.contains(r#"{"secret": [REDACTED]}"#));

        let (root, _, _database, mut conn) = fixture();
        let lease = admit_job_with_target(
            &mut conn,
            "testpkg-creds",
            "job-cred-1",
            "update",
            "2026-11-09T08:00:00Z",
            &[],
            Some("1.0.0"),
        )
        .unwrap();

        let diagnostic_summary =
            format!("failure with {sample1} and {sample2} and {sample3} and {sample4}");
        record_completed_lifecycle_job(
            &conn,
            "testpkg-creds",
            "job-cred-1",
            "update",
            Some(&diagnostic_summary),
            Some("1.0.0"),
            Some("1.0.0"),
        )
        .unwrap();

        let history = get_lifecycle_history(&conn, "testpkg-creds", 10).unwrap();
        assert_eq!(history.len(), 1);
        let record = &history[0];
        let summary = record.sanitized_summary.as_deref().unwrap();
        assert!(!summary.contains("my_super_secret_db_pw"));
        assert!(!summary.contains("escaped_quote_secret"));
        assert!(!summary.contains("tail_secret"));
        assert!(summary.contains("[REDACTED]"));

        drop(lease);
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_sanitize_curl_credentials_with_intervening_flags_and_quotes() {
        let cmd1 = "curl -s -u admin:synthetic-secret http://127.0.0.1:5572/core/version";
        let sanitized1 = sanitize_persisted_lifecycle_text(cmd1);
        assert!(!sanitized1.contains("synthetic-secret"));
        assert_eq!(
            sanitized1,
            "curl -s -u [REDACTED] http://127.0.0.1:5572/core/version"
        );

        let cmd2 = r#"curl -fsSL --user "admin:my secret" http://localhost"#;
        let sanitized2 = sanitize_persisted_lifecycle_text(cmd2);
        assert!(!sanitized2.contains("my secret"));
        assert_eq!(sanitized2, "curl -fsSL --user [REDACTED] http://localhost");

        let cmd3 = "curl --user=admin:secret_pass http://localhost";
        let sanitized3 = sanitize_persisted_lifecycle_text(cmd3);
        assert!(!sanitized3.contains("secret_pass"));
        assert_eq!(sanitized3, "curl --user=[REDACTED] http://localhost");

        let cmd4 = "curl -u=admin:secret_pass http://localhost";
        let sanitized4 = sanitize_persisted_lifecycle_text(cmd4);
        assert!(!sanitized4.contains("secret_pass"));
        assert_eq!(sanitized4, "curl -u=[REDACTED] http://localhost");
    }

    #[test]
    fn test_prerelease_version_for_channel_debian_and_semver() {
        assert!(is_prerelease_version_for_channel("1.2.3-foo-1"));
        assert!(is_prerelease_version_for_channel("1.2.3-1.2"));
        assert!(is_prerelease_version_for_channel("1.2.3-rc1"));
        assert!(is_prerelease_version_for_channel("1.2.3~rc1"));
        assert!(is_prerelease_version_for_channel("1.2.3-beta.1"));
        assert!(is_prerelease_version_for_channel("1.0.0-0.1"));

        assert!(!is_prerelease_version_for_channel("1:1.2.3-1+b1"));
        assert!(!is_prerelease_version_for_channel("2.4.5-1ubuntu1"));
        assert!(!is_prerelease_version_for_channel("1.0.0-1deb12u1"));
        assert!(!is_prerelease_version_for_channel("1.2.3-1"));
        assert!(!is_prerelease_version_for_channel("1.2.3"));
    }

    #[test]
    fn test_sanitize_curl_attached_credentials_and_commas() {
        let cmd1 = "curl -uadmin:synthetic-secret http://localhost";
        let sanitized1 = sanitize_persisted_lifecycle_text(cmd1);
        assert!(!sanitized1.contains("synthetic-secret"));
        assert_eq!(sanitized1, "curl -u[REDACTED] http://localhost");

        let cmd2 = "curl -s -uadmin:part1,part2 http://localhost";
        let sanitized2 = sanitize_persisted_lifecycle_text(cmd2);
        assert!(!sanitized2.contains("part1"));
        assert!(!sanitized2.contains("part2"));
        assert_eq!(sanitized2, "curl -s -u[REDACTED] http://localhost");

        let cmd3 = "curl --user=admin:part1,part2 http://localhost";
        let sanitized3 = sanitize_persisted_lifecycle_text(cmd3);
        assert!(!sanitized3.contains("part1"));
        assert!(!sanitized3.contains("part2"));
        assert_eq!(sanitized3, "curl --user=[REDACTED] http://localhost");

        let cmd4 = "curl -u admin:sec1,sec2 http://localhost";
        let sanitized4 = sanitize_persisted_lifecycle_text(cmd4);
        assert!(!sanitized4.contains("sec1"));
        assert!(!sanitized4.contains("sec2"));
        assert_eq!(sanitized4, "curl -u [REDACTED] http://localhost");

        let cmd5 = "curl -fsSL -uadmin:secret http://localhost";
        let sanitized5 = sanitize_persisted_lifecycle_text(cmd5);
        assert!(!sanitized5.contains("secret"));
        assert_eq!(sanitized5, "curl -fsSL -u[REDACTED] http://localhost");
    }

    #[test]
    fn test_source_aware_prerelease_version_rules() {
        // is_valid_apt_debian_revision_suffix
        assert!(is_valid_apt_debian_revision_suffix("0.1"));
        assert!(is_valid_apt_debian_revision_suffix("1.2"));
        assert!(is_valid_apt_debian_revision_suffix("1+b1"));
        assert!(is_valid_apt_debian_revision_suffix("1deb12u1"));
        assert!(is_valid_apt_debian_revision_suffix("2ubuntu1"));
        assert!(is_valid_apt_debian_revision_suffix("1"));
        assert!(!is_valid_apt_debian_revision_suffix("rc1"));
        assert!(!is_valid_apt_debian_revision_suffix("beta.1"));
        assert!(!is_valid_apt_debian_revision_suffix("foo-1"));
        assert!(!is_valid_apt_debian_revision_suffix("0.1~rc1"));

        // APT source
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.0.0-0.1",
            Some("apt")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3-1.2",
            Some("apt")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1:1.2.3-1+b1",
            Some("apt")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3-1",
            Some("apt")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "2.4.5-1ubuntu1",
            Some("apt")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-rc1",
            Some("apt")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-foo-1",
            Some("apt")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3~rc1",
            Some("apt")
        ));

        // Git / git_tags source
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-1",
            Some("git_tags")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.0.0-0.1",
            Some("git_tags")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-1.2",
            Some("git_tags")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-foo-1",
            Some("git_tags")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1:1.2.3-1+b1",
            Some("git_tags")
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "2.4.5-1ubuntu1",
            Some("git_tags")
        ));

        // Strict SemVer prerelease rejection for git / github sources including debug and revisions
        for src in ["github", "github_release", "git", "git_tags"] {
            assert!(is_prerelease_version_for_channel_with_source(
                "1.2.3-debug.1",
                Some(src)
            ));
            assert!(is_prerelease_version_for_channel_with_source(
                "1.2.3-1",
                Some(src)
            ));
            assert!(is_prerelease_version_for_channel_with_source(
                "1.2.3-ubuntu1",
                Some(src)
            ));
            assert!(!is_prerelease_version_for_channel_with_source(
                "1.2.3",
                Some(src)
            ));
        }

        // Default / None source
        assert!(is_prerelease_version_for_channel_with_source(
            "1.0.0-0.1",
            None
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-1.2",
            None
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-foo-1",
            None
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-debug.1",
            None
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3-1", None
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1:1.2.3-1+b1",
            None
        ));
    }

    #[test]
    fn test_sanitize_curl_and_kv_edge_cases() {
        assert_eq!(
            sanitize_persisted_lifecycle_text("curl -uadmin https://example.com"),
            "curl -u[REDACTED] https://example.com"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("curl -uadmin:secret https://example.com"),
            "curl -u[REDACTED] https://example.com"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("curl -u admin:part1,part2 https://example.com"),
            "curl -u [REDACTED] https://example.com"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("password=part1,part2"),
            "password=[REDACTED]"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("password: part1,part2"),
            "password: [REDACTED]"
        );
    }

    #[test]
    fn test_wave19_audit_findings_lifecycle_sanitization_and_ordering() {
        // Finding 5: continuation tokens with '=' and ':'
        assert_eq!(
            sanitize_persisted_lifecycle_text("password: part1,part2=SECRET"),
            "password: [REDACTED]"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("token=part1,part2=SECRET; next=ok"),
            "token=[REDACTED]; next=ok"
        );

        // Finding 3: passwordless ssh:// and cred#... preserved, while other credentials redacted
        assert_eq!(
            sanitize_persisted_lifecycle_text(
                "git-repo:ssh://Deploy@git.example.com/Team/App.git#main"
            ),
            "git-repo:ssh://Deploy@git.example.com/Team/App.git#main"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("git-repo:ssh://git@github.com/org/repo.git#main"),
            "git-repo:ssh://git@github.com/org/repo.git#main"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text(
                "git-repo:https://cred#0123456789ab@github.com/org/repo.git#main"
            ),
            "git-repo:https://cred#0123456789ab@github.com/org/repo.git#main"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("ssh://user:pass@host/repo.git"),
            "ssh://[REDACTED]@host/repo.git"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("https://user:pass@host/repo.git"),
            "https://[REDACTED]@host/repo.git"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text("https://token@host/repo.git"),
            "https://[REDACTED]@host/repo.git"
        );

        // Finding 6: Build metadata with +dfsg-1 is not classified as prerelease on Git / GitHub
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+dfsg-1",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+dfsg-1",
            Some("github")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+20130313144700",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+build-4",
            Some("git")
        ));
        // Build metadata (+...) does NOT affect prerelease classification on non-APT sources
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+dev.1",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+debug",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+dirty",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+wip",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "v1.2.3+rc.1",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "v1.2.3+rc.1",
            None
        ));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-1",
            Some("git")
        ));

        // Finding 7: 7+ digit numeric version tags compared numerically, not as hex commit hashes
        assert_eq!(
            compare_versions("10000000", "9000000"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_versions("v10000000", "v9000000"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_versions("20261109", "9999999"),
            std::cmp::Ordering::Greater
        );
        // Real hex commit hashes still compared lexically
        assert_eq!(
            compare_versions("deadbeef", "cafebabe"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_versions("09abcdef", "10000000"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_nested_secret_redaction() {
        assert_eq!(
            sanitize_persisted_lifecycle_text(r#"password: {"value":"CANARY_SECRET"}"#),
            "password: [REDACTED]"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text(r#""password": {"value":"CANARY_SECRET"}"#),
            "\"password\": [REDACTED]"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text(r#"secret=["CANARY_SECRET"]"#),
            "secret=[REDACTED]"
        );
        assert_eq!(
            sanitize_persisted_lifecycle_text(r#"password={"nested":{"secret":"CANARY_SECRET"}}"#),
            "password=[REDACTED]"
        );
        let sample =
            r#"diagnostics: {"auth": {"token": "CANARY_SECRET"}, "password": ["NESTED_SECRET"]}"#;
        let sanitized = sanitize_persisted_lifecycle_text(sample);
        assert!(!sanitized.contains("CANARY_SECRET"));
        assert!(!sanitized.contains("NESTED_SECRET"));
    }

    #[test]
    fn test_build_metadata_stable_classification() {
        assert!(!is_prerelease_version_for_channel("v1.2.3+rc.1"));
        assert!(!is_prerelease_version_for_channel_with_source(
            "v1.2.3+rc.1",
            None
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "v1.2.3+rc.1",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "v1.2.3+rc.1",
            Some("github")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+dev.1",
            Some("git")
        ));
        assert!(!is_prerelease_version_for_channel_with_source(
            "1.2.3+debug",
            Some("github")
        ));

        // True prereleases must still be classified as prereleases
        assert!(is_prerelease_version_for_channel("1.2.3-rc.1"));
        assert!(is_prerelease_version_for_channel("1.2.3~rc.1"));
        assert!(is_prerelease_version_for_channel_with_source(
            "1.2.3-rc.1",
            Some("git")
        ));
    }

    #[test]
    fn test_wave21_nested_containers_and_multiline_redaction() {
        // 3-level nested object
        let sample_3level = r#"{"secret": {"level1": {"level2": {"level3": "CANARY_LEVEL3"}}}}"#;
        let sanitized_3level = sanitize_persisted_lifecycle_text(sample_3level);
        assert!(!sanitized_3level.contains("CANARY_LEVEL3"));
        assert_eq!(sanitized_3level, r#"{"secret": [REDACTED]}"#);

        // 4-level nested object
        let sample_4level =
            r#"{"password": {"level1": {"level2": {"level3": {"level4": "CANARY_LEVEL4"}}}}}"#;
        let sanitized_4level = sanitize_persisted_lifecycle_text(sample_4level);
        assert!(!sanitized_4level.contains("CANARY_LEVEL4"));
        assert_eq!(sanitized_4level, r#"{"password": [REDACTED]}"#);

        // Multiline pretty-printed JSON object
        let sample_multiline = "{\n  \"api_key\": {\n    \"level1\": {\n      \"level2\": {\n        \"key\": \"CANARY_MULTILINE\"\n      }\n    }\n  }\n}";
        let sanitized_multiline = sanitize_persisted_lifecycle_text(sample_multiline);
        assert!(!sanitized_multiline.contains("CANARY_MULTILINE"));
        assert!(sanitized_multiline.contains("\"api_key\": [REDACTED]"));

        // Multiline scalar value after sensitive key
        let sample_scalar_multiline = "{\n  \"api_key\":\n    \"CANARY_SCALAR\"\n}";
        let sanitized_scalar_multiline = sanitize_persisted_lifecycle_text(sample_scalar_multiline);
        assert!(!sanitized_scalar_multiline.contains("CANARY_SCALAR"));
        assert!(sanitized_scalar_multiline.contains("[REDACTED]"));

        // Truncated / unclosed container
        let sample_truncated =
            "diagnostics: password: {\"level1\": {\"level2\": \"CANARY_TRUNCATED\"";
        let sanitized_truncated = sanitize_persisted_lifecycle_text(sample_truncated);
        assert!(!sanitized_truncated.contains("CANARY_TRUNCATED"));
        assert!(sanitized_truncated.contains("password: [REDACTED]"));

        // redact_sensitive_nested_containers direct invocation
        let direct_redacted = redact_sensitive_nested_containers(sample_3level);
        assert!(!direct_redacted.contains("CANARY_LEVEL3"));
        assert_eq!(direct_redacted, r#"{"secret": [REDACTED]}"#);
    }

    #[test]
    fn test_wave22_scalar_redaction() {
        let cases = [
            "Cookie: session=CANARY_COOKIE",
            "Set-Cookie: sid=CANARY_COOKIE; HttpOnly",
            "session=CANARY_SESSION",
            "session_id=CANARY_SESSION",
            "cookie=CANARY_COOKIE",
            r#"{"webhook_url":"https://example.test/CANARY_HOOK"}"#,
            r#"{"webhook":"CANARY_WEBHOOK"}"#,
            "webhook_secret=CANARY_HOOK",
            "pass=CANARY_PASSWORD",
            r#"{"pass":"CANARY_PASSWORD"}"#,
            "db_pass=CANARY_PASSWORD",
            "Proxy-Authorization: Basic CANARY_PROXY",
            "X-Api-Key: CANARY_API_KEY",
            "X-Auth-Token: CANARY_AUTH_TOKEN",
            "Authorization: Bearer CANARY_AUTH",
            "\"Cookie: session=CANARY_COOKIE\"",
        ];

        for c in cases {
            let redacted = sanitize_persisted_lifecycle_text(c);
            assert!(
                !redacted.contains("CANARY_"),
                "Redacted output for '{c}' still contains CANARY_: '{redacted}'"
            );
            assert!(
                redacted.contains("[REDACTED]"),
                "Redacted output for '{c}' must contain [REDACTED]: '{redacted}'"
            );
        }

        // Verify preservation of non-secret prose/keys
        let preserved = r#"{"bypass": true, "status": "passed"}"#;
        assert_eq!(sanitize_persisted_lifecycle_text(preserved), preserved);

        let prose = "compass heading is north and bypass compression";
        assert_eq!(sanitize_persisted_lifecycle_text(prose), prose);
    }

    #[test]
    fn test_w22_s01_escaped_quote_and_multi_header_sanitization() {
        // 1. Escaped double-quotes inside header value
        let cmd1 = r#"curl -H "Cookie: sid=\"COOKIE_CANARY\"" https://example.invalid"#;
        let out1 = sanitize_persisted_lifecycle_text(cmd1);
        assert!(!out1.contains("COOKIE_CANARY"));
        assert!(out1.contains("https://example.invalid"));
        assert_eq!(
            out1,
            r#"curl -H "Cookie: [REDACTED]" https://example.invalid"#
        );

        // 2. Set-Cookie with attributes and inner escaped quote
        let cmd2 = r#"curl -H "Set-Cookie: sid=\"COOKIE_CANARY\"; Secure" https://example.invalid"#;
        let out2 = sanitize_persisted_lifecycle_text(cmd2);
        assert!(!out2.contains("COOKIE_CANARY"));
        assert!(out2.contains("https://example.invalid"));
        assert_eq!(
            out2,
            r#"curl -H "Set-Cookie: [REDACTED]" https://example.invalid"#
        );

        // 3. Single-quoted header value with double quotes and escaped single quotes
        let cmd3a = "curl -H 'Cookie: sid=\"COOKIE_CANARY\"' https://example.invalid";
        let out3a = sanitize_persisted_lifecycle_text(cmd3a);
        assert!(!out3a.contains("COOKIE_CANARY"));
        assert!(out3a.contains("https://example.invalid"));
        assert_eq!(
            out3a,
            "curl -H 'Cookie: [REDACTED]' https://example.invalid"
        );

        let cmd3b = r"curl -H 'Cookie: sid=\'COOKIE_CANARY\'' https://example.invalid";
        let out3b = sanitize_persisted_lifecycle_text(cmd3b);
        assert!(!out3b.contains("COOKIE_CANARY"));
        assert!(out3b.contains("https://example.invalid"));
        assert_eq!(
            out3b,
            "curl -H 'Cookie: [REDACTED]' https://example.invalid"
        );

        // 4. JSON-serialized string with escaped inner quotes
        let cmd4 =
            r#"{"cmd":"curl -H \"Cookie: sid=\\\"COOKIE_CANARY\\\"\" https://example.invalid"}"#;
        let out4 = sanitize_persisted_lifecycle_text(cmd4);
        assert!(!out4.contains("COOKIE_CANARY"));
        assert!(out4.contains("https://example.invalid"), "{out4}");
        assert_eq!(
            out4,
            r#"{"cmd":"curl -H \"Cookie: [REDACTED]\" https://example.invalid"}"#
        );

        // 5. Multiple headers on the same line
        let cmd5 = r#"curl -H "Cookie: sid=\"CANARY_1\"" -H "X-Api-Key: \"CANARY_2\"" https://example.invalid"#;
        let out5 = sanitize_persisted_lifecycle_text(cmd5);
        assert!(!out5.contains("CANARY_1"));
        assert!(!out5.contains("CANARY_2"));
        assert!(out5.contains("https://example.invalid"));
        assert_eq!(
            out5,
            r#"curl -H "Cookie: [REDACTED]" -H "X-Api-Key: [REDACTED]" https://example.invalid"#
        );

        // Multiple headers without inner escaped quotes on same line
        let cmd5b =
            r#"curl -H "Cookie: sid=CANARY_1" -H "X-Api-Key: CANARY_2" https://example.invalid"#;
        let out5b = sanitize_persisted_lifecycle_text(cmd5b);
        assert!(!out5b.contains("CANARY_1"));
        assert!(!out5b.contains("CANARY_2"));
        assert!(out5b.contains("https://example.invalid"));
        assert_eq!(
            out5b,
            r#"curl -H "Cookie: [REDACTED]" -H "X-Api-Key: [REDACTED]" https://example.invalid"#
        );
    }

    #[test]
    fn test_w24_structured_masking_grammar() {
        let scalars = [
            r#"password=\"SECRET words\""#,
            r#"api_key=\"SECRET words\""#,
            r#"client_secret=\"SECRET words\""#,
            r#"session=\"SECRET words\""#,
            r#"webhook=\"SECRET words\""#,
            r#"rclone_rc_pass=\"SECRET words\""#,
        ];
        for sample in scalars {
            let out = sanitize_persisted_lifecycle_text(sample);
            assert!(!out.contains("SECRET"), "scalar leaked: {sample} -> {out}");
            assert!(
                out.contains("[REDACTED]"),
                "scalar missing mask: {sample} -> {out}"
            );
            assert_eq!(sanitize_persisted_lifecycle_text(&out), out);
        }

        let flags = [
            "--password SECRET word",
            "--token SECRET word",
            "--api-key SECRET word",
            "--cookie SECRET word",
            "--session SECRET word",
            "--webhook SECRET word",
            r#"--password=\"SECRET words\""#,
            "--password=SECRET",
            "--token=SECRET",
        ];
        for sample in flags {
            let out = sanitize_persisted_lifecycle_text(sample);
            assert!(!out.contains("SECRET"), "flag leaked: {sample} -> {out}");
            assert!(
                out.contains("[REDACTED]"),
                "flag missing mask: {sample} -> {out}"
            );
            assert_eq!(sanitize_persisted_lifecycle_text(&out), out);
        }

        let raw_user = r#"curl --user=\"admin:SECRET words\" https://example.invalid"#;
        let raw_out = sanitize_persisted_lifecycle_text(raw_user);
        assert!(!raw_out.contains("SECRET"), "curl user leaked: {raw_out}");
        assert!(raw_out.contains("https://example.invalid"), "{raw_out}");
        assert_eq!(raw_out, "curl --user=[REDACTED] https://example.invalid");

        let mut encoded = r#"curl --user="admin:SECRET words" https://example.invalid"#.to_string();
        for depth in 1..=4 {
            encoded = serde_json::to_string(&encoded).unwrap();
            let wrapped = format!(r#"{{"command":{encoded}}}"#);
            let out = sanitize_persisted_lifecycle_text(&wrapped);
            assert!(
                !out.contains("SECRET"),
                "depth {depth} leaked: {wrapped} -> {out}"
            );
            assert!(
                out.contains("https://example.invalid"),
                "depth {depth}: {out}"
            );
            let parsed: serde_json::Value = serde_json::from_str(&out)
                .unwrap_or_else(|err| panic!("depth {depth} json: {err}: {out}"));
            assert!(parsed.get("command").is_some(), "{out}");
            assert_eq!(sanitize_persisted_lifecycle_text(&out), out);
        }

        let diag = r#"AF_DIAG_FAILURE={"stage": "password=[REDACTED]\"SECRET words\\\"", "exit_code": 17, "category": "installer", "summary": "--user [REDACTED]\"user:SECRET words\\\""}"#;
        let diag_out = sanitize_persisted_lifecycle_text(diag);
        assert!(!diag_out.contains("SECRET"), "diag leaked: {diag_out}");
        let json = diag_out
            .split_once("AF_DIAG_FAILURE=")
            .map(|(_, rest)| rest)
            .unwrap_or("");
        let parsed: serde_json::Value =
            serde_json::from_str(json).unwrap_or_else(|err| panic!("diag json: {err}: {json}"));
        assert_eq!(parsed["exit_code"], 17);
        assert_eq!(parsed["category"], "installer");
        assert!(!parsed.to_string().contains("SECRET"));
        assert_eq!(sanitize_persisted_lifecycle_text(&diag_out), diag_out);

        let preserved = "bypass=visible passed=true monkey=1";
        assert_eq!(sanitize_persisted_lifecycle_text(preserved), preserved);
    }

    #[test]
    fn test_w25_escape_aware_scalar_and_unicode_keys() {
        let exact = [
            ("password=SENTINEL", "password=[REDACTED]"),
            ("password=[REDACTED]SENTINEL", "password=[REDACTED]"),
            (
                "curl --password [REDACTED]SENTINEL --verbose",
                "curl --password [REDACTED] --verbose",
            ),
            (
                "curl -uoperator:SENTINEL https://example.invalid",
                "curl -u[REDACTED] https://example.invalid",
            ),
            (r#"{"password":123456789}"#, r#"{"password":"[REDACTED]"}"#),
            ("password:'SENTINEL'", "password:[REDACTED]"),
            (
                r"curl --password prefix\ SENTINEL --verbose",
                "curl --password [REDACTED] --verbose",
            ),
            ("password=already,SENTINEL", "password=[REDACTED]"),
            (
                r"curl --password $'SENTINEL' https://example.invalid",
                "curl --password [REDACTED] https://example.invalid",
            ),
            (
                r#"curl --password $"SENTINEL" https://example.invalid"#,
                "curl --password [REDACTED] https://example.invalid",
            ),
            (
                r#"curl --password prefix"SENTINEL" https://example.invalid"#,
                "curl --password [REDACTED] https://example.invalid",
            ),
            (
                r"curl --password prefix'SENTINEL' https://example.invalid",
                "curl --password [REDACTED] https://example.invalid",
            ),
            (
                r"curl --user operator:prefix\ SENTINEL https://example.invalid",
                "curl --user [REDACTED] https://example.invalid",
            ),
            (r"password=prefix\;SENTINEL", "password=[REDACTED]"),
            (r"password=prefix\\;SENTINEL", "password=[REDACTED]"),
            (
                r#"{"command":"curl --password prefix\\ SENTINEL --verbose"}"#,
                r#"{"command":"curl --password [REDACTED] --verbose"}"#,
            ),
            (
                r#"{"command":"curl --password prefix\ SENTINEL --verbose"}"#,
                r#"{"command":"curl --password [REDACTED] --verbose"}"#,
            ),
            (
                r#"{"pass\u0077ord":"SENTINEL"}"#,
                r#"{"password":[REDACTED]}"#,
            ),
            (
                r#"{"pass\\u0077ord":"SENTINEL"}"#,
                r#"{"password":[REDACTED]}"#,
            ),
        ];
        for (sample, expected) in exact {
            let out = sanitize_persisted_lifecycle_text(sample);
            assert_eq!(out, expected, "sample={sample}");
            assert!(!out.contains("SENTINEL"), "{out}");
            assert!(!out.contains("123456789"), "{out}");
            assert_eq!(
                sanitize_persisted_lifecycle_text(&out),
                out,
                "idempotent: {sample}"
            );
            if sample.contains("--verbose") {
                assert!(out.contains("--verbose"), "{out}");
            }
            if sample.contains("https://example.invalid") {
                assert!(out.contains("https://example.invalid"), "{out}");
            }
            if expected.starts_with(r#"{"command""#) || expected.starts_with(r#"{"password":""#) {
                serde_json::from_str::<serde_json::Value>(&out)
                    .unwrap_or_else(|err| panic!("json {err}: {out}"));
            }
        }

        let containers = [
            r#"{"Credentials":{"plain":"SENTINEL"}}"#,
            r#"{"credentials":{"a":{"b":{"c":{"plain":"SENTINEL"}}}}}"#,
            r#"{"credentials":[{"a":[{"plain":"SENTINEL"}]}]}"#,
        ];
        for sample in containers {
            let out = sanitize_persisted_lifecycle_text(sample);
            assert!(!out.contains("SENTINEL"), "{sample} -> {out}");
            assert!(!out.contains("plain"), "{sample} -> {out}");
            assert!(out.contains("[REDACTED]"), "{out}");
            assert_eq!(sanitize_persisted_lifecycle_text(&out), out, "{out}");
        }

        let header = r#"curl -H \"Cookie: sid=\"SENTINEL\"\" https://example.invalid"#;
        let header_out = sanitize_persisted_lifecycle_text(header);
        assert!(!header_out.contains("SENTINEL"), "{header_out}");
        assert!(
            header_out.contains("https://example.invalid"),
            "{header_out}"
        );
        assert!(header_out.contains("[REDACTED]"), "{header_out}");
        assert_eq!(sanitize_persisted_lifecycle_text(&header_out), header_out);

        let kept = r#"{"na\u006de":"visible"}"#;
        assert_eq!(sanitize_persisted_lifecycle_text(kept), kept);
    }

    #[test]
    fn recovery_state_persistence_invariants_and_reset_on_readmit_or_interrupt() {
        assert_eq!(
            normalize_recovery_state(
                false,
                "reinstall",
                "installer",
                Some(RECOVERY_STATE_PRIOR_VERIFIED)
            ),
            RECOVERY_STATE_PRIOR_VERIFIED
        );
        assert_eq!(
            normalize_recovery_state(
                false,
                "update",
                "target_verification",
                Some(RECOVERY_STATE_PRIOR_VERIFIED)
            ),
            RECOVERY_STATE_PRIOR_VERIFIED
        );
        assert_eq!(
            normalize_recovery_state(
                false,
                "install",
                "installer",
                Some(RECOVERY_STATE_PRIOR_VERIFIED)
            ),
            RECOVERY_STATE_PRIOR_VERIFIED
        );
        // Never allowed for completed, remove, retention, interrupted, or arbitrary values.
        assert_eq!(
            normalize_recovery_state(true, "reinstall", "", Some(RECOVERY_STATE_PRIOR_VERIFIED)),
            ""
        );
        assert_eq!(
            normalize_recovery_state(
                false,
                "remove",
                "installer",
                Some(RECOVERY_STATE_PRIOR_VERIFIED)
            ),
            ""
        );
        assert_eq!(
            normalize_recovery_state(
                false,
                "reinstall",
                "retention",
                Some(RECOVERY_STATE_PRIOR_VERIFIED)
            ),
            ""
        );
        assert_eq!(
            normalize_recovery_state(
                false,
                "reinstall",
                "interrupted",
                Some(RECOVERY_STATE_PRIOR_VERIFIED)
            ),
            ""
        );
        assert_eq!(
            normalize_recovery_state(false, "reinstall", "installer", Some("partial")),
            ""
        );
        assert_eq!(
            normalize_recovery_state(false, "update", "installer", None),
            RECOVERY_STATE_UNVERIFIED
        );

        let root = std::env::temp_dir().join(format!("af-recovery-inv-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let db = root.join("aetherflow.sqlite");
        let mut conn = Connection::open(&db).unwrap();
        initialize_schema(&conn).unwrap();

        let lease1 = admit_job(
            &mut conn,
            "syncthing",
            "job-1",
            "reinstall",
            "t1",
            &["syncthing".into()],
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "syncthing",
            "job-1",
            "reinstall",
            false,
            LifecycleJobDiagnostics {
                failure_category: "installer",
                recovery_state: Some(RECOVERY_STATE_PRIOR_VERIFIED),
                ..Default::default()
            },
        )
        .unwrap();
        drop(lease1);

        let (status, rec): (String, String) = conn
            .query_row(
                "SELECT status, recovery_state FROM package_lifecycle_jobs WHERE package_id='syncthing'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "failed");
        assert_eq!(rec, RECOVERY_STATE_PRIOR_VERIFIED);
        let hist_rec: String = conn
            .query_row(
                "SELECT recovery_state FROM package_lifecycle_history WHERE job_id='job-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(hist_rec, RECOVERY_STATE_PRIOR_VERIFIED);

        // Re-admitting resets recovery_state to empty and abandoning marks interrupted with empty recovery_state.
        let lease2 = admit_job(
            &mut conn,
            "syncthing",
            "job-2",
            "reinstall",
            "t2",
            &["syncthing".into()],
        )
        .unwrap();
        let active_rec: String = conn
            .query_row(
                "SELECT recovery_state FROM package_lifecycle_jobs WHERE package_id='syncthing'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active_rec, "");
        drop(lease2);
        reconcile_jobs(&conn, &db).unwrap();
        let (int_status, int_rec): (String, String) = conn
            .query_row(
                "SELECT status, recovery_state FROM package_lifecycle_jobs WHERE package_id='syncthing'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(int_status, "interrupted");
        assert_eq!(int_rec, "");

        // Remove failure cannot persist prior_state_verified even if passed.
        let lease3 = admit_job(
            &mut conn,
            "syncthing",
            "job-3",
            "remove",
            "t3",
            &["syncthing".into()],
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "syncthing",
            "job-3",
            "remove",
            false,
            LifecycleJobDiagnostics {
                failure_category: "installer",
                recovery_state: Some(RECOVERY_STATE_PRIOR_VERIFIED),
                ..Default::default()
            },
        )
        .unwrap();
        drop(lease3);
        let rm_rec: String = conn
            .query_row(
                "SELECT recovery_state FROM package_lifecycle_jobs WHERE package_id='syncthing'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rm_rec, "");

        drop(conn);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn test_service_activation_and_companion_ordering_rules() {
        assert!(is_socket_unit("librespeed.socket"));
        assert!(is_activation_unit("librespeed.socket"));
        assert!(is_timer_unit("recyclarr.timer"));
        assert!(is_activation_unit("recyclarr.timer"));
        assert!(!is_activation_unit("librespeed.service"));

        assert!(is_legacy_optional_companion_unit("librespeed.socket"));
        assert!(is_legacy_optional_companion_unit("LIBRESPEED.SOCKET"));
        assert!(is_legacy_optional_companion_unit("novnc-session"));
        assert!(is_legacy_optional_companion_unit("novnc-session.service"));
        assert!(!is_legacy_optional_companion_unit("librespeed.service"));
        assert!(!is_legacy_optional_companion_unit("novnc-xvnc.service"));

        let mut librespeed = vec![
            "librespeed.service".to_string(),
            "librespeed.socket".to_string(),
        ];
        sort_units_for_stop(&mut librespeed);
        assert_eq!(librespeed, vec!["librespeed.socket", "librespeed.service"]);
        assert_eq!(
            ordered_units_for_start(&librespeed),
            vec!["librespeed.socket", "librespeed.service"]
        );

        let mut novnc = vec![
            "novnc-xvnc.service".to_string(),
            "novnc-session.service".to_string(),
            "novnc.service".to_string(),
        ];
        sort_units_for_stop(&mut novnc);
        assert_eq!(
            novnc,
            vec![
                "novnc.service",
                "novnc-session.service",
                "novnc-xvnc.service"
            ]
        );
        assert_eq!(
            ordered_units_for_start(&novnc),
            vec![
                "novnc-xvnc.service",
                "novnc-session.service",
                "novnc.service"
            ]
        );

        let mut mixed = vec![
            "app.service".to_string(),
            "app.timer".to_string(),
            "app.socket".to_string(),
        ];
        sort_units_for_stop(&mut mixed);
        assert_eq!(mixed[2], "app.service");
        assert!(is_activation_unit(&mixed[0]) && is_activation_unit(&mixed[1]));
        assert_eq!(
            ordered_units_for_start(&mixed),
            vec!["app.socket", "app.service", "app.timer"]
        );

        let generic_stopped = vec!["web.service".to_string(), "db.service".to_string()];
        assert_eq!(
            ordered_units_for_start(&generic_stopped),
            vec!["db.service", "web.service"]
        );

        let ls_res = package_resources(
            "librespeed",
            &["librespeed.service".into(), "librespeed.socket".into()],
        );
        assert!(ls_res.contains("librespeed"));
        assert!(ls_res.contains("librespeed.socket"));
        let novnc_res = package_resources(
            "novnc",
            &[
                "novnc.service".into(),
                "novnc-xvnc.service".into(),
                "novnc-session.service".into(),
            ],
        );
        assert!(novnc_res.contains("novnc"));
        assert!(novnc_res.contains("novnc-xvnc"));
        assert!(novnc_res.contains("novnc-session"));
    }

    #[test]
    fn parse_apt_policy_candidate_handles_revisions_none_and_first_entry() {
        assert_eq!(
            parse_apt_policy_candidate(
                "plexmediaserver:\n  Installed: 1.40.0\n  Candidate: 2:2.53.0+ds-1~deb12u1\n  Version table:\n"
            ),
            Some("2:2.53.0+ds-1~deb12u1")
        );
        assert_eq!(
            parse_apt_policy_candidate("pkg:\n  Installed: (none)\n  Candidate: (none)\n"),
            None
        );
        assert_eq!(parse_apt_policy_candidate("pkg:\n  Candidate:   \n"), None);
        assert_eq!(parse_apt_policy_candidate("pkg:\n  Installed: 1.0\n"), None);
        assert_eq!(
            parse_apt_policy_candidate("pkg:\n  Candidate: (none)\n  Candidate: 1.2.3\n"),
            None
        );
    }

    #[test]
    fn retention_state_persists_survives_failed_purge_and_clears_on_purge_or_reinstall() {
        let root =
            std::env::temp_dir().join(format!("af-lifecycle-retention-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let db = root.join("aetherflow.db");
        let mut conn = Connection::open(&db).unwrap();
        initialize_schema(&conn).unwrap();

        // 1. Retained remove records retention_state='retained'
        let lease1 = admit_job(
            &mut conn,
            "rclone",
            "job-remove-retained",
            "remove",
            "2026-11-22T00:00:01Z",
            &[],
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "rclone",
            "job-remove-retained",
            "remove",
            true,
            LifecycleJobDiagnostics {
                retention_state: Some(RETENTION_STATE_RETAINED),
                ..Default::default()
            },
        )
        .unwrap();
        drop(lease1);

        let rec = query_package_retention_history(&conn, "rclone")
            .unwrap()
            .expect("retained removal record");
        assert_eq!(rec.action, "remove");
        assert_eq!(rec.retention_state, RETENTION_STATE_RETAINED);
        assert!(query_retained_lifecycle_packages(&conn)
            .unwrap()
            .contains("rclone"));

        // 2. A subsequent failed purge overwrites package_lifecycle_jobs with status='failed',
        //    but history query still recovers the prior completed retained removal.
        let lease2 = admit_job(
            &mut conn,
            "rclone",
            "job-purge-failed",
            "remove",
            "2026-11-22T00:01:00Z",
            &[],
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "rclone",
            "job-purge-failed",
            "remove",
            false,
            LifecycleJobDiagnostics {
                failure_category: "runtime",
                retention_state: Some(RETENTION_STATE_PURGED),
                ..Default::default()
            },
        )
        .unwrap();
        drop(lease2);

        let after_failed = query_package_retention_history(&conn, "rclone")
            .unwrap()
            .expect("prior completed retained removal preserved in history");
        assert_eq!(after_failed.job_id, "job-remove-retained");
        assert_eq!(after_failed.retention_state, RETENTION_STATE_RETAINED);
        assert!(query_retained_lifecycle_packages(&conn)
            .unwrap()
            .contains("rclone"));

        // 3. A successful purge records retention_state='purged'.
        let lease3 = admit_job(
            &mut conn,
            "rclone",
            "job-purge-ok",
            "remove",
            "2026-11-22T00:02:00Z",
            &[],
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "rclone",
            "job-purge-ok",
            "remove",
            true,
            LifecycleJobDiagnostics {
                retention_state: Some(RETENTION_STATE_PURGED),
                ..Default::default()
            },
        )
        .unwrap();
        drop(lease3);

        let after_purge = query_package_retention_history(&conn, "rclone")
            .unwrap()
            .expect("completed purge record");
        assert_eq!(after_purge.job_id, "job-purge-ok");
        assert_eq!(after_purge.retention_state, RETENTION_STATE_PURGED);
        assert!(!query_retained_lifecycle_packages(&conn)
            .unwrap()
            .contains("rclone"));

        // 4. Older schema without retention_state column is tolerated gracefully.
        let legacy_conn = Connection::open_in_memory().unwrap();
        legacy_conn
            .execute_batch(
                "CREATE TABLE package_lifecycle_jobs (
                    package_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL
                );
                INSERT INTO package_lifecycle_jobs VALUES ('rclone','old-rm','remove','completed','2026-01-01T00:00:00Z');",
            )
            .unwrap();
        let legacy_rec = query_package_retention_history(&legacy_conn, "rclone")
            .unwrap()
            .expect("legacy remove record");
        assert_eq!(legacy_rec.action, "remove");
        assert_eq!(legacy_rec.retention_state, "");
        assert!(query_retained_lifecycle_packages(&legacy_conn)
            .unwrap()
            .is_empty());

        drop(conn);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn test_exact_apt_version_validation_and_dpkg_status_parsing() {
        for valid in [
            "1:0.14.0-1+deb12u1",
            "4.0.6+dfsg-3+deb13u1",
            "1.0.20210914-1.1+b1",
            "10.10.3+deb12",
            "0.9.21.1-1~bpo12+1",
            "2.0.3-4",
            "11.0.0",
        ] {
            assert!(
                validate_exact_apt_version(valid),
                "valid Debian version {valid:?} must be accepted"
            );
        }

        for invalid in [
            "",
            "latest",
            "v1.2.3",
            "V1.2.3",
            "1.2.*",
            "1.2.3-",
            "1.2_3",
            "deadbeef",
            "quassel-core=1:0.14.0-1",
            "1:0.14.0-1/bookworm",
            "1::0.14.0-1",
            "epoch:1.0-1",
            "1.0..2",
            "1.0 2",
        ] {
            assert!(
                !validate_exact_apt_version(invalid),
                "invalid APT target {invalid:?} must be rejected"
            );
        }

        assert_eq!(
            parse_installed_dpkg_status_version("installed 4.0.6+dfsg-3+deb13u1\n"),
            Some("4.0.6+dfsg-3+deb13u1")
        );
        assert_eq!(
            parse_installed_dpkg_status_version("installed 1:0.14.0-1+deb12u1\n"),
            Some("1:0.14.0-1+deb12u1")
        );
        for bad_dpkg in [
            "config-files 4.0.6+dfsg-3+deb13u1\n",
            "half-installed 1:0.14.0-1+deb12u1\n",
            "unpacked 1:0.14.0-1+deb12u1\n",
            "not-installed \n",
            "installed 1:0.14.0-1 extra\n",
            "installed v1.2.3\n",
            "",
        ] {
            assert_eq!(
                parse_installed_dpkg_status_version(bad_dpkg),
                None,
                "non-installed or malformed dpkg output {bad_dpkg:?} must fail closed"
            );
        }

        assert!(apt_receipt_matches_live_debian_revision(
            "apt",
            "0.14.0",
            "1:0.14.0-1+deb12u1"
        ));
        assert!(!apt_receipt_matches_live_debian_revision(
            "apt",
            "0.14.1",
            "1:0.14.0-1+deb12u1"
        ));
        assert!(!apt_receipt_matches_live_debian_revision(
            "apt",
            "0.14.0",
            "1:0.14.0~rc1-1"
        ));
    }
}
