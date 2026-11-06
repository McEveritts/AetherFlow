//! Durable API lifecycle receipts. Only identity and outcome are persisted;
//! installer output can contain credentials and must never enter this journal.
use chrono::Utc;
use once_cell::sync::Lazy;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::{collections::HashMap, sync::Mutex, time::Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageJobInfo {
    pub job_id: String,
    pub package_id: String,
    pub action: String,
    pub status: String,
    pub progress: i32,
    pub last_line: String,
    pub started_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageJobOutcome {
    pub job_id: String,
    pub package_id: String,
    pub action: String,
    /// completed, failed, or interrupted (completion could not be confirmed).
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub message: String,
    pub started_at: String,
    pub finished_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageJobFailure {
    Preparation,
    Installer,
    Configuration,
    ServiceRestore,
    Retention,
    ConfigurationAndServiceRestore,
}

impl PackageJobFailure {
    fn category(self) -> &'static str {
        match self {
            Self::Preparation => "preparation",
            Self::Installer => "installer",
            Self::Configuration => "configuration",
            Self::ServiceRestore => "service_restore",
            Self::Retention => "retention",
            Self::ConfigurationAndServiceRestore => "configuration_and_service_restore",
        }
    }

    fn from_category(category: &str) -> Option<Self> {
        match category {
            "preparation" => Some(Self::Preparation),
            "installer" => Some(Self::Installer),
            "configuration" => Some(Self::Configuration),
            "service_restore" => Some(Self::ServiceRestore),
            "retention" => Some(Self::Retention),
            "configuration_and_service_restore" => Some(Self::ConfigurationAndServiceRestore),
            _ => None,
        }
    }

    pub fn summary(self) -> &'static str {
        match self {
            Self::Preparation => "Application preparation failed before installer execution. Check application state before retrying.",
            Self::Installer => "The package installer failed. Rollback and data recovery are not confirmed; check application state before retrying.",
            Self::Configuration => "The installer finished, but required application configuration could not be synchronized.",
            Self::ServiceRestore => "The installer finished, but a stopped application service could not be restored. Check service state before retrying.",
            Self::Retention => "Package removal finished, but reinstall settings could not be retained. Data recovery is not confirmed.",
            Self::ConfigurationAndServiceRestore => "The installer finished, but required application configuration and service restoration failed. Check service state before retrying.",
        }
    }
}

pub fn package_job_progress_summary(status: &str) -> &'static str {
    match status {
        "installing" => "Installing application.",
        "updating" => "Updating application.",
        "uninstalling" => "Removing application.",
        "completed" => "Operation completed.",
        "failed" => "Operation failed. Contact an administrator for details.",
        "interrupted" => "Operation interrupted. Contact an administrator before retrying.",
        _ => "Operation completion is not yet confirmed.",
    }
}

#[derive(Default)]
struct JobRegistry {
    active: HashMap<String, PackageJobInfo>,
    outcomes: HashMap<String, PackageJobOutcome>,
    db: Option<Connection>,
    leases: HashMap<String, af_release::lifecycle::OwnerLease>,
}

impl JobRegistry {
    fn open(conn: Connection, reconcile: bool) -> anyhow::Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        af_release::lifecycle::initialize_schema(&conn)?;
        let has_category: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_jobs') WHERE name='failure_category')",
            [], |row| row.get(0),
        )?;
        if !has_category {
            conn.execute_batch("ALTER TABLE package_lifecycle_jobs ADD COLUMN failure_category TEXT NOT NULL DEFAULT ''")?;
        }
        if reconcile {
            af_release::lifecycle::reconcile_jobs(&conn, Path::new(conn.path().unwrap_or("")))?;
        }
        let mut registry = Self {
            db: Some(conn),
            outcomes: HashMap::new(),
            active: HashMap::new(),
            leases: HashMap::new(),
        };
        registry.refresh()?;
        Ok(registry)
    }

    fn refresh(&mut self) -> anyhow::Result<()> {
        let Some(conn) = &self.db else { return Ok(()) };
        let rows: Vec<PackageJobOutcome> = conn.prepare(
            "SELECT package_id,job_id,action,status,started_at,finished_at,failure_category FROM package_lifecycle_jobs",
        )?.query_map([], |row| {
            let status: String = row.get(3)?;
            Ok(PackageJobOutcome {
                package_id: row.get(0)?, job_id: row.get(1)?, action: row.get(2)?,
                message: outcome_summary(&status, &row.get::<_, String>(6)?).into(), status,
                started_at: row.get(4)?, finished_at: row.get(5)?,
            })
        })?.collect::<rusqlite::Result<_>>()?;
        for row in rows {
            if !matches!(row.status.as_str(), "completed" | "failed" | "interrupted") {
                if self
                    .active
                    .get(&row.package_id)
                    .is_none_or(|active| active.job_id != row.job_id || active.status != row.status)
                {
                    self.active.insert(
                        row.package_id.clone(),
                        PackageJobInfo {
                            job_id: row.job_id,
                            package_id: row.package_id.clone(),
                            action: row.action,
                            status: row.status,
                            started_at: row.started_at,
                            progress: 5,
                            last_line: "Operation completion is not yet confirmed.".into(),
                        },
                    );
                }
                self.outcomes.remove(&row.package_id);
            } else {
                self.active.remove(&row.package_id);
                self.leases.remove(&row.package_id);
                if self
                    .outcomes
                    .get(&row.package_id)
                    .is_none_or(|old| old.job_id != row.job_id || old.status != row.status)
                {
                    self.outcomes.insert(row.package_id.clone(), row);
                }
            }
        }
        Ok(())
    }

    fn start(&mut self, mut info: PackageJobInfo) -> anyhow::Result<bool> {
        if let Some(conn) = &self.db {
            af_release::lifecycle::reconcile_jobs(conn, Path::new(conn.path().unwrap_or("")))?;
        }
        self.refresh()?;
        if self.active.contains_key(&info.package_id) {
            return Ok(false);
        }
        if info.job_id.is_empty() {
            info.job_id = uuid::Uuid::new_v4().to_string();
        }
        let catalog = crate::get_package_catalog()?;
        anyhow::ensure!(
            catalog
                .iter()
                .any(|package| package.name == info.package_id),
            "Package catalog entry is unavailable"
        );
        let units = crate::resolve_service_units_with_catalog(&info.package_id, &catalog);
        if let Some(conn) = &mut self.db {
            let lease = af_release::lifecycle::admit_job(
                conn,
                &info.package_id,
                &info.job_id,
                &info.action,
                &info.started_at,
                &units,
            )?;
            self.leases.insert(info.package_id.clone(), lease);
        }
        self.outcomes.remove(&info.package_id);
        self.active.insert(info.package_id.clone(), info);
        Ok(true)
    }

    fn finish(
        &mut self,
        pkg: &str,
        action: &str,
        success: bool,
        _message: &str,
        job_id: &str,
    ) -> anyhow::Result<Option<PackageJobOutcome>> {
        self.finish_with_failure(pkg, action, success, None, job_id)
    }

    fn finish_with_failure(
        &mut self,
        pkg: &str,
        action: &str,
        success: bool,
        failure: Option<PackageJobFailure>,
        job_id: &str,
    ) -> anyhow::Result<Option<PackageJobOutcome>> {
        let Some(job) = self
            .active
            .get(pkg)
            .filter(|j| j.job_id == job_id && j.action == action)
        else {
            return Ok(None);
        };
        let status = if success { "completed" } else { "failed" };
        let category = if success {
            ""
        } else {
            failure.map_or("", PackageJobFailure::category)
        };
        let outcome = PackageJobOutcome {
            job_id: job.job_id.clone(),
            package_id: pkg.to_string(),
            action: action.to_string(),
            status: status.to_string(),
            message: outcome_summary(status, category).to_string(),
            started_at: job.started_at.clone(),
            finished_at: Utc::now().to_rfc3339(),
        };
        if let Some(conn) = &self.db {
            anyhow::ensure!(conn.execute("UPDATE package_lifecycle_jobs SET status=?1,finished_at=?2,failure_category=?3 WHERE package_id=?4 AND job_id=?5 AND action=?6 AND status IN ('installing','updating','uninstalling')",
                params![outcome.status,outcome.finished_at,category,pkg,outcome.job_id,action])? == 1, "lifecycle receipt identity changed");
        }
        self.outcomes.insert(pkg.to_string(), outcome.clone());
        self.active.remove(pkg);
        self.leases.remove(pkg);
        Ok(Some(outcome))
    }
}

fn outcome_summary(status: &str, category: &str) -> &'static str {
    match status {
        "completed" => "Operation completed.",
        "interrupted" => "The API restarted before completion was confirmed. Check application state and logs before retrying; rollback and data recovery are not confirmed.",
        _ => PackageJobFailure::from_category(category).map_or(
            "Operation failed. Check authenticated service logs for details; rollback and data recovery are not confirmed.",
            PackageJobFailure::summary,
        ),
    }
}

static JOBS: Lazy<Mutex<JobRegistry>> = Lazy::new(|| Mutex::new(JobRegistry::default()));

/// Called after database initialization, before routes or background workers start.
pub fn initialize_package_jobs(conn: Connection) -> anyhow::Result<()> {
    let admission = af_runner::acquire_lifecycle_admission_lock(None).ok();
    *JOBS
        .lock()
        .map_err(|_| anyhow::anyhow!("lifecycle registry unavailable"))? =
        JobRegistry::open(conn, admission.is_some())?;
    Ok(())
}

#[derive(Clone, Default)]
pub struct PackageJobSnapshot {
    pub active: HashMap<String, PackageJobInfo>,
    pub outcomes: HashMap<String, PackageJobOutcome>,
}

pub fn package_job_snapshot() -> anyhow::Result<PackageJobSnapshot> {
    let (mut snapshot, path) = {
        let jobs = JOBS
            .lock()
            .map_err(|_| anyhow::anyhow!("lifecycle registry unavailable"))?;
        (
            PackageJobSnapshot {
                active: jobs.active.clone(),
                outcomes: jobs.outcomes.clone(),
            },
            jobs.db
                .as_ref()
                .and_then(|conn| conn.path())
                .map(str::to_owned),
        )
    };
    let Some(path) = path else {
        return Ok(snapshot);
    };
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(Duration::from_millis(150))?;
    let mut refreshed = JobRegistry {
        db: Some(conn),
        ..Default::default()
    };
    refreshed.refresh()?;
    for (package, current) in &mut refreshed.active {
        if let Some(local) = snapshot
            .active
            .get(package)
            .filter(|local| local.job_id == current.job_id && local.status == current.status)
        {
            *current = local.clone();
        }
    }
    snapshot.active = refreshed.active;
    snapshot.outcomes = refreshed.outcomes;
    Ok(snapshot)
}

pub fn take_package_job_lease(
    pkg: &str,
    job_id: &str,
) -> Option<af_release::lifecycle::OwnerLease> {
    let mut jobs = JOBS.lock().ok()?;
    if jobs.active.get(pkg)?.job_id != job_id {
        return None;
    }
    jobs.leases.remove(pkg)
}

pub fn has_active_package_jobs() -> bool {
    let Ok(_admission) = af_runner::acquire_lifecycle_admission_lock(None) else {
        return true;
    };
    let Ok(mut jobs) = JOBS.lock() else {
        return true;
    };
    if let Some(conn) = &jobs.db {
        if af_release::lifecycle::reconcile_jobs(conn, Path::new(conn.path().unwrap_or("")))
            .is_err()
        {
            return true;
        }
    }
    jobs.refresh().is_err() || !jobs.active.is_empty()
}

pub fn reconcile_package_jobs_under_admission() -> anyhow::Result<()> {
    let mut jobs = JOBS
        .lock()
        .map_err(|_| anyhow::anyhow!("lifecycle registry unavailable"))?;
    let Some(conn) = &jobs.db else {
        return Ok(());
    };
    af_release::lifecycle::reconcile_jobs(conn, Path::new(conn.path().unwrap_or("")))?;
    jobs.refresh()?;
    Ok(())
}

pub fn reconcile_package_jobs() -> anyhow::Result<()> {
    let Ok(_admission) = af_runner::acquire_lifecycle_admission_lock(None) else {
        return Ok(());
    };
    reconcile_package_jobs_under_admission()
}

pub fn get_package_job_info(pkg: &str) -> Option<PackageJobInfo> {
    match package_job_snapshot() {
        Ok(jobs) => jobs.active.get(pkg).cloned(),
        Err(_) => JOBS.lock().ok()?.active.get(pkg).cloned(),
    }
}
pub fn get_package_job_outcome(pkg: &str) -> Option<PackageJobOutcome> {
    package_job_snapshot().ok()?.outcomes.get(pkg).cloned()
}
pub fn set_package_job_info(mut info: PackageJobInfo) -> Option<PackageJobInfo> {
    let mut jobs = JOBS.lock().ok()?;
    let current = jobs
        .active
        .get(&info.package_id)
        .filter(|j| j.job_id == info.job_id)?;
    info.progress = info
        .progress
        .clamp(0, 95)
        .max(current.progress.clamp(0, 95));
    jobs.active.insert(info.package_id.clone(), info.clone());
    Some(info)
}

pub fn try_start_package_job(info: PackageJobInfo) -> bool {
    match JOBS.lock().map(|mut j| j.start(info)) {
        Ok(Ok(started)) => started,
        error => {
            tracing::error!(?error, "Failed to persist lifecycle admission");
            false
        }
    }
}
pub fn clear_package_job_info(pkg: &str) {
    if let Ok(mut j) = JOBS.lock() {
        j.active.remove(pkg);
    }
}
pub fn finish_package_job(
    pkg: &str,
    action: &str,
    success: bool,
    message: &str,
    job_id: &str,
) -> Option<PackageJobOutcome> {
    match JOBS
        .lock()
        .map(|mut j| j.finish(pkg, action, success, message, job_id))
    {
        Ok(Ok(outcome)) => outcome,
        error => {
            tracing::error!(
                ?error,
                "Failed to persist lifecycle outcome; leaving operation unresolved"
            );
            None
        }
    }
}

pub fn fail_package_job(
    pkg: &str,
    action: &str,
    failure: PackageJobFailure,
    job_id: &str,
) -> Option<PackageJobOutcome> {
    match JOBS
        .lock()
        .map(|mut jobs| jobs.finish_with_failure(pkg, action, false, Some(failure), job_id))
    {
        Ok(Ok(outcome)) => outcome,
        error => {
            tracing::error!(
                ?error,
                "Failed to persist lifecycle failure; leaving operation unresolved"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_http_registry_and_direct_runner_reject_shared_companion_owners() {
        let name = "package_jobs::tests::real_http_registry_and_direct_runner_reject_shared_companion_owners";
        if isolated_recovery_test(name) {
            return;
        }
        let (root, path) = recovery_fixture();
        initialize_package_jobs(Connection::open(&path).unwrap()).unwrap();
        let mut http = job("http-nextcloud");
        http.package_id = "nextcloud".into();
        let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        assert!(try_start_package_job(http));
        let mut http_remove = job("http-rutorrent");
        http_remove.package_id = "rutorrent".into();
        assert!(!try_start_package_job(http_remove.clone()));
        drop(admission);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            use futures::StreamExt;
            let request = af_models::PackageRunnerRequest {
                action: "update".into(),
                package_id: "organizr".into(),
                script_name: "updatepackage-organizr".into(),
                ..Default::default()
            };
            let stream = af_runner::package_lifecycle::execute_coordinated_package_stream(request);
            tokio::pin!(stream);
            let mut rejected = false;
            while let Some(line) = stream.next().await {
                rejected |= line.unwrap().starts_with("__RUNNER_EXIT_ERROR__:");
            }
            assert!(rejected);
        });
        let mut conn = Connection::open(&path).unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM package_lifecycle_jobs", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert!(af_release::lifecycle::check_package_reservation(
            &conn,
            "rutorrent",
            &af_runner::package_lifecycle::package_service_units("rutorrent").unwrap(),
            "http-nextcloud",
            Some("update")
        )
        .is_err());
        assert!(
            finish_package_job("nextcloud", "update", true, "done", "http-nextcloud").is_some()
        );
        let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        let direct = af_release::lifecycle::admit_job(
            &mut conn,
            "organizr",
            "direct-organizr",
            "remove",
            "now",
            &af_runner::package_lifecycle::package_service_units("organizr").unwrap(),
        )
        .unwrap();
        assert!(!try_start_package_job(http_remove.clone()));
        drop(admission);
        assert_eq!(
            package_job_snapshot().unwrap().active["organizr"].job_id,
            "direct-organizr"
        );
        drop(direct);
        reconcile_package_jobs().unwrap();
        assert_eq!(
            package_job_snapshot().unwrap().outcomes["organizr"].status,
            "interrupted"
        );
        let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        assert!(try_start_package_job(http_remove));
        drop(admission);
        finish_package_job("rutorrent", "update", true, "done", "http-rutorrent").unwrap();
        std::fs::write(root.join("packages.json"), b"not-json").unwrap();
        assert!(!try_start_package_job(job("catalog-unavailable")));
        assert!(af_runner::package_lifecycle::package_service_units("nextcloud").is_err());
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn isolated_recovery_test(name: &str) -> bool {
        if std::env::var("AF_RECOVERY_TEST_CHILD").as_deref() == Ok(name) {
            return false;
        }
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_RECOVERY_TEST_CHILD", name)
            .status()
            .unwrap()
            .success());
        true
    }

    fn recovery_fixture() -> (std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("af-recovery-{}", uuid::Uuid::new_v4()));
        std::env::set_var("AETHERFLOW_FS_ROOT", &root);
        std::env::set_var("AETHERFLOW_RELEASE_ROOT", &root);
        let cfg = af_release::ReleaseConfig::for_root(&root);
        let path = af_release::config::try_resolve_db_path(&cfg, None)
            .unwrap()
            .path;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut packages: Vec<af_models::Package> =
            serde_json::from_str(include_str!("../../../../config/packages.json")).unwrap();
        packages.push(af_models::Package {
            name: "fixture".into(),
            service_name: "fixture".into(),
            ..Default::default()
        });
        let catalog = root.join("packages.json");
        std::fs::write(&catalog, serde_json::to_vec(&packages).unwrap()).unwrap();
        std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", catalog);
        (root, path)
    }

    fn lock_holder(path: &Path) -> std::process::Child {
        use std::io::BufRead;
        let mut child = std::process::Command::new("python3")
            .args(["-c", "import fcntl,sys; lock=open(sys.argv[1], 'r'); fcntl.flock(lock, fcntl.LOCK_EX); print('locked', flush=True); sys.stdin.readline()"])
            .arg(path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready.trim(), "locked");
        child
    }

    #[test]
    fn recovery_tick_waits_for_owner_and_maintenance_child_then_allows_retry() {
        use std::io::Write;
        let name = "package_jobs::tests::recovery_tick_waits_for_owner_and_maintenance_child_then_allows_retry";
        if isolated_recovery_test(name) {
            return;
        }
        let (root, path) = recovery_fixture();
        let mut original = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
        assert!(original.start(job("dead-owner-job")).unwrap());
        let lease = original.leases.remove("fixture").unwrap();
        let owner_path = path.with_extension("lifecycle-owners").join(&lease.id);
        drop((lease, original));
        let mut owner = lock_holder(&owner_path);
        initialize_package_jobs(Connection::open(&path).unwrap()).unwrap();
        reconcile_package_jobs().unwrap();
        assert_eq!(
            package_job_snapshot().unwrap().active["fixture"].job_id,
            "dead-owner-job"
        );
        assert!(!try_start_package_job(job("must-not-steal-owner")));
        let cfg = af_release::ReleaseConfig::for_root(&root);
        let maintenance_path =
            af_release::ensure_interoperable_maintenance_lock_file(&cfg).unwrap();
        let mut child = lock_holder(&maintenance_path);
        initialize_package_jobs(Connection::open(&path).unwrap()).unwrap();
        owner.kill().unwrap();
        owner.wait().unwrap();
        reconcile_package_jobs().unwrap();
        assert_eq!(
            package_job_snapshot().unwrap().active["fixture"].status,
            "updating"
        );
        assert!(af_runner::acquire_lifecycle_admission_lock(Some(&root)).is_err());
        child.stdin.take().unwrap().write_all(b"release\n").unwrap();
        assert!(child.wait().unwrap().success());
        let changes = Connection::open(&path).unwrap();
        changes.pragma_update(None, "query_only", true).unwrap();
        assert_eq!(
            package_job_snapshot().unwrap().active["fixture"].status,
            "updating"
        );
        reconcile_package_jobs().unwrap();
        let snapshot = package_job_snapshot().unwrap();
        assert!(snapshot.active.is_empty());
        assert_eq!(snapshot.outcomes["fixture"].status, "interrupted");
        assert_eq!(snapshot.outcomes["fixture"].job_id, "dead-owner-job");
        assert!(finish_package_job("fixture", "update", true, "late", "dead-owner-job").is_none());
        let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        assert!(try_start_package_job(job("retry-after-recovery")));
        drop(admission);
        assert_eq!(
            package_job_snapshot().unwrap().active["fixture"].job_id,
            "retry-after-recovery"
        );
        assert!(finish_package_job(
            "fixture",
            "remove",
            true,
            "wrong-action",
            "retry-after-recovery"
        )
        .is_none());
        finish_package_job("fixture", "update", true, "done", "retry-after-recovery").unwrap();
        drop(changes);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn safe_failure_categories_survive_readonly_snapshots_and_restart() {
        let name =
            "package_jobs::tests::safe_failure_categories_survive_readonly_snapshots_and_restart";
        if isolated_recovery_test(name) {
            return;
        }
        let (root, path) = recovery_fixture();
        initialize_package_jobs(Connection::open(&path).unwrap()).unwrap();
        for failure in [
            PackageJobFailure::Preparation,
            PackageJobFailure::Installer,
            PackageJobFailure::Configuration,
            PackageJobFailure::ServiceRestore,
            PackageJobFailure::Retention,
            PackageJobFailure::ConfigurationAndServiceRestore,
        ] {
            let identity = failure.category();
            let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
            assert!(try_start_package_job(job(identity)));
            drop(admission);
            let failed = fail_package_job("fixture", "update", failure, identity).unwrap();
            assert_eq!(failed.message, failure.summary());
            assert!(failed.message.len() < 256);
            assert_eq!(package_job_snapshot().unwrap().outcomes["fixture"], failed);
            initialize_package_jobs(Connection::open(&path).unwrap()).unwrap();
            assert_eq!(package_job_snapshot().unwrap().outcomes["fixture"], failed);
            assert!(fail_package_job("fixture", "remove", failure, identity).is_none());
        }
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE package_lifecycle_jobs SET failure_category=?1",
            ["password=must-never-be-output"],
        )
        .unwrap();
        assert!(!package_job_snapshot().unwrap().outcomes["fixture"]
            .message
            .contains("password"));
        let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        assert!(try_start_package_job(job("fresh-identity")));
        drop(admission);
        let category: String = conn
            .query_row(
                "SELECT failure_category FROM package_lifecycle_jobs",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(category, "");
        let outcome = finish_package_job(
            "fixture",
            "update",
            false,
            "credential-do-not-persist",
            "fresh-identity",
        )
        .unwrap();
        assert!(!outcome.message.contains("credential"));
        assert_eq!(package_job_snapshot().unwrap().outcomes["fixture"], outcome);
        assert!(!String::from_utf8_lossy(&std::fs::read(&path).unwrap())
            .contains("credential-do-not-persist"));
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn polling_does_not_own_maintenance_or_block_admission_registry() {
        let name =
            "package_jobs::tests::polling_does_not_own_maintenance_or_block_admission_registry";
        if std::env::var("AF_POLLING_TEST_CHILD").as_deref() != Ok(name) {
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env("AF_POLLING_TEST_CHILD", name)
                .status()
                .unwrap()
                .success());
            return;
        }
        let (root, path) = recovery_fixture();
        initialize_package_jobs(Connection::open(&path).unwrap()).unwrap();
        let blocker = Connection::open(&path).unwrap();
        blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let _ = get_package_job_info("fixture");
            sender.send(()).unwrap();
        });
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root));
        let registry_available = JOBS.try_lock().is_ok();
        blocker.execute_batch("ROLLBACK").unwrap();
        receiver.recv_timeout(Duration::from_secs(6)).unwrap();
        reader.join().unwrap();
        assert!(
            admission.is_ok(),
            "status polling must never acquire the maintenance flock"
        );
        assert!(
            registry_available,
            "slow status reads must not hold the mutation registry mutex"
        );
        drop(admission);
        blocker.execute_batch("PRAGMA journal_mode=WAL").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let scripts = root.join("packages/package/install");
        std::fs::create_dir_all(&scripts).unwrap();
        let script = format!("installpackage-polling-{}", uuid::Uuid::new_v4());
        std::fs::write(
            scripts.join(&script),
            "#!/bin/sh\nprintf 'isolated installer completed\\n'\n",
        )
        .unwrap();
        let controls = root.join("fake-bin");
        std::fs::create_dir_all(&controls).unwrap();
        for program in ["systemctl", "sudo"] {
            let command = controls.join(program);
            std::fs::write(&command, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::env::set_var(
            "PATH",
            format!("{}:{}", controls.display(), std::env::var("PATH").unwrap()),
        );
        std::env::set_var("AETHERFLOW_RUNNER_SOCK", root.join("absent-runner.sock"));
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(&root).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reading = stop.clone();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let started = barrier.clone();
        let poller = std::thread::spawn(move || {
            started.wait();
            let mut snapshots = 0;
            while !reading.load(std::sync::atomic::Ordering::Acquire) {
                package_job_snapshot().unwrap();
                snapshots += 1;
            }
            snapshots
        });
        barrier.wait();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for iteration in 0..8 {
                let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
                let identity = format!("parallel-{iteration}");
                assert!(try_start_package_job(job(&identity)));
                drop(admission);
                af_runner::PACKAGE_JOB_ID
                    .scope(identity.clone(), async {
                        af_runner::execute_package_local("update", "fixture", &script, 0, |_| {})
                            .await
                            .unwrap();
                        crate::control_service_with_manager(
                            "fixture.service",
                            "start",
                            "systemd-unit",
                        )
                        .await
                        .unwrap();
                    })
                    .await;
                assert!(finish_package_job("fixture", "update", true, "done", &identity).is_some());
            }
        });
        stop.store(true, std::sync::atomic::Ordering::Release);
        let snapshots = poller.join().unwrap();
        assert!(snapshots > 0);
        println!("{snapshots} real read-only snapshots overlapped 8 admissions, legacy executions and owned service controls");
        assert!(try_start_package_job(job("abandoned")));
        drop(take_package_job_lease("fixture", "abandoned").unwrap());
        assert_eq!(
            package_job_snapshot().unwrap().active["fixture"].status,
            "updating"
        );
        assert!(!has_active_package_jobs());
        assert_eq!(
            get_package_job_outcome("fixture").unwrap().status,
            "interrupted"
        );
        std::env::set_current_dir(previous).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    fn job(id: &str) -> PackageJobInfo {
        PackageJobInfo {
            job_id: id.into(),
            package_id: "fixture".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 5,
            last_line: "credential-do-not-persist".into(),
            started_at: id.into(),
        }
    }
    #[test]
    fn restart_retains_failure_and_interrupts_unconfirmed_work_without_persisting_output() {
        let name = "package_jobs::tests::restart_retains_failure_and_interrupts_unconfirmed_work_without_persisting_output";
        if isolated_recovery_test(name) {
            return;
        }
        let (root, path) = recovery_fixture();
        {
            let mut store = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
            assert!(store.start(job("first")).unwrap());
            assert!(!store.start(job("duplicate")).unwrap());
            store
                .finish("fixture", "update", false, "secret-output", "first")
                .unwrap();
        }
        {
            let mut store = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
            assert_eq!(store.outcomes["fixture"].status, "failed");
            assert!(!store.outcomes["fixture"].message.contains("secret-output"));
            assert!(store.start(job("second")).unwrap());
            assert!(store
                .finish("fixture", "update", true, "late", "first")
                .unwrap()
                .is_none());
        }
        {
            let mut store = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
            assert_eq!(store.outcomes["fixture"].status, "interrupted");
            assert_eq!(store.outcomes["fixture"].job_id, "second");
            assert!(store
                .finish("fixture", "update", true, "late", "second")
                .unwrap()
                .is_none());
            assert!(store.start(job("third")).unwrap());
            store
                .finish("fixture", "update", true, "done", "third")
                .unwrap();
            assert!(store
                .finish("fixture", "update", false, "stale", "first")
                .unwrap()
                .is_none());
        }
        let store = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
        assert_eq!(store.outcomes["fixture"].status, "completed");
        assert_eq!(store.outcomes["fixture"].job_id, "third");
        let raw = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("credential-do-not-persist"));
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn another_api_cannot_claim_live_work_and_dropped_task_is_not_completed() {
        let name = "package_jobs::tests::another_api_cannot_claim_live_work_and_dropped_task_is_not_completed";
        if isolated_recovery_test(name) {
            return;
        }
        let (root, path) = recovery_fixture();
        let _admission =
            af_release::ReleaseLockGuard::acquire(root.join("maintenance.lock"), Duration::ZERO)
                .unwrap();
        let mut first = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
        assert!(first.start(job("original")).unwrap());
        let task_lease = first.leases.remove("fixture").unwrap();
        let mut restarted = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
        assert_eq!(restarted.active["fixture"].job_id, "original");
        assert!(!restarted.start(job("replacement")).unwrap());
        drop(task_lease);
        af_release::lifecycle::reconcile_jobs(first.db.as_ref().unwrap(), &path).unwrap();
        first.refresh().unwrap();
        assert_eq!(first.outcomes["fixture"].status, "interrupted");
        assert!(first
            .finish("fixture", "update", true, "late", "original")
            .unwrap()
            .is_none());
        assert!(restarted.start(job("replacement")).unwrap());
        drop((first, restarted));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_durable_state_cannot_be_replaced_by_new_admission() {
        let name = "package_jobs::tests::unknown_durable_state_cannot_be_replaced_by_new_admission";
        if isolated_recovery_test(name) {
            return;
        }
        let (root, path) = recovery_fixture();
        let mut registry = JobRegistry::open(Connection::open(&path).unwrap(), true).unwrap();
        assert!(registry.start(job("original")).unwrap());
        registry.db.as_ref().unwrap().execute(
            "UPDATE package_lifecycle_jobs SET status='unknown-worker-phase' WHERE package_id='fixture'", [],
        ).unwrap();
        registry.leases.clear();
        assert!(!registry.start(job("replacement")).unwrap());
        assert_eq!(registry.active["fixture"].job_id, "original");
        assert_eq!(registry.active["fixture"].status, "unknown-worker-phase");
        assert!(registry
            .finish("fixture", "update", true, "late", "original")
            .is_err());
        let status: String = registry
            .db
            .as_ref()
            .unwrap()
            .query_row(
                "SELECT status FROM package_lifecycle_jobs WHERE package_id='fixture'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "unknown-worker-phase");
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }
}
