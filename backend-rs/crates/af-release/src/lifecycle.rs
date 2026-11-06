use anyhow::{Context, Result};
use rusqlite::{params, Connection, TransactionBehavior};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

pub struct OwnerLease {
    pub id: String,
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
        file.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(Self { id, _file: file })
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

pub fn owner_is_alive(database: &Path, owner: &str) -> Result<bool> {
    let path = lease_path(database, owner)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .context("cannot inspect lifecycle owner lease")?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "invalid lifecycle owner lease file"
    );
    Ok(!lock_exclusive(&file)?)
}

pub fn initialize_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS package_lifecycle_jobs (
        package_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, action TEXT NOT NULL,
        status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL DEFAULT '',
        owner_id TEXT NOT NULL DEFAULT '', service_units TEXT NOT NULL DEFAULT '[]'
    );",
    )?;
    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(package_lifecycle_jobs)")?
        .query_map([], |row| row.get(1))?
        .collect::<rusqlite::Result<_>>()?;
    for (name, definition) in [
        ("owner_id", "TEXT NOT NULL DEFAULT ''"),
        ("service_units", "TEXT NOT NULL DEFAULT '[]'"),
        ("failure_category", "TEXT NOT NULL DEFAULT ''"),
    ] {
        if !columns.iter().any(|column| column == name) {
            conn.execute_batch(&format!(
                "ALTER TABLE package_lifecycle_jobs ADD COLUMN {name} {definition}"
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
    let jobs: Vec<(String, String, String)> = conn.prepare(
        "SELECT package_id,job_id,owner_id FROM package_lifecycle_jobs WHERE status IN ('installing','updating','uninstalling')",
    )?.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (package, job, owner) in jobs {
        if owner.is_empty() || !matches!(owner_is_alive(database, &owner), Ok(false)) {
            continue;
        }
        conn.execute(
            "UPDATE package_lifecycle_jobs SET status='interrupted',finished_at=?1
             WHERE package_id=?2 AND job_id=?3 AND owner_id=?4 AND status IN ('installing','updating','uninstalling')",
            params![chrono::Utc::now().to_rfc3339(), package, job, owner],
        )?;
    }
    Ok(())
}

pub enum ReservationTarget<'a> {
    Package(&'a str),
    Service(&'a str),
    System,
}

pub fn package_resources(package: &str, units: &[String]) -> BTreeSet<String> {
    std::iter::once(package)
        .chain(units.iter().map(String::as_str))
        .map(|unit| unit.trim().to_ascii_lowercase())
        .map(|unit| unit.trim_end_matches(".service").to_owned())
        .filter(|unit| !unit.is_empty())
        .collect()
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
    anyhow::ensure!(
        !package.is_empty() && !job_id.is_empty(),
        "lifecycle identity is required"
    );
    let status = match action {
        "install" => "installing",
        "update" => "updating",
        "remove" => "uninstalling",
        _ => anyhow::bail!("invalid lifecycle action"),
    };
    let database = PathBuf::from(conn.path().context("lifecycle database path missing")?);
    anyhow::ensure!(
        !database.as_os_str().is_empty(),
        "durable lifecycle database is required"
    );
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    check_package_reservation(&tx, package, units, "", Some(action))?;
    let lease = OwnerLease::create(&database)?;
    let normalized: Vec<_> = package_resources(package, units).into_iter().collect();
    tx.execute("INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at,finished_at,owner_id,service_units,failure_category)
        VALUES (?1,?2,?3,?4,?5,'',?6,?7,'') ON CONFLICT(package_id) DO UPDATE SET
        job_id=excluded.job_id,action=excluded.action,status=excluded.status,started_at=excluded.started_at,finished_at='',owner_id=excluded.owner_id,service_units=excluded.service_units,failure_category=''",
        params![package,job_id,action,status,started_at,lease.id,serde_json::to_string(&normalized)?])?;
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
    let status = if success { "completed" } else { "failed" };
    anyhow::ensure!(conn.execute(
        "UPDATE package_lifecycle_jobs SET status=?1,finished_at=?2,failure_category=?3
         WHERE package_id=?4 AND job_id=?5 AND action=?6 AND status IN ('installing','updating','uninstalling')",
        params![status,chrono::Utc::now().to_rfc3339(),if success { "" } else { failure_category },package,job_id,action],
    )? == 1, "lifecycle receipt identity changed");
    Ok(())
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
                "install" => "installing",
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
    fn live_owner_survives_same_process_reopen_and_dead_owner_is_interrupted() {
        let (root, cfg, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
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
        admission(&cfg).unwrap();
        assert_eq!(state(&conn), "interrupted");
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
        child.kill().unwrap();
        child.wait().unwrap();
        admission(&cfg).unwrap();
        assert_eq!(state(&conn), "interrupted");
        assert_eq!(
            std::fs::read(&recovery).unwrap(),
            b"release-recovery-sentinel"
        );
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }
}
