//! Durable API lifecycle receipts. Only identity and outcome are persisted;
//! installer output can contain credentials and must never enter this journal.
use chrono::Utc;
use once_cell::sync::Lazy;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::{collections::HashMap, sync::Mutex, time::Duration};

pub use af_models::{PackageJobOutcomeRecord, PackageLifecycleRecord};

pub type PackageJobOutcome = af_models::PackageJobOutcomeRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageJobInfo {
    pub job_id: String,
    pub package_id: String,
    pub action: String,
    pub status: String,
    pub progress: i32,
    pub last_line: String,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_target_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageJobFailure {
    Preparation,
    Installer,
    Configuration,
    ServiceRestore,
    Retention,
    ConfigurationAndServiceRestore,
    TargetVerification,
}

impl PackageJobFailure {
    pub fn category(self) -> &'static str {
        match self {
            Self::Preparation => "preparation",
            Self::Installer => "installer",
            Self::Configuration => "configuration",
            Self::ServiceRestore => "service_restore",
            Self::Retention => "retention",
            Self::ConfigurationAndServiceRestore => "configuration_and_service_restore",
            Self::TargetVerification => "target_verification",
        }
    }

    pub fn from_category(category: &str) -> Option<Self> {
        match category {
            "preparation" => Some(Self::Preparation),
            "installer" => Some(Self::Installer),
            "configuration" => Some(Self::Configuration),
            "service_restore" => Some(Self::ServiceRestore),
            "retention" => Some(Self::Retention),
            "configuration_and_service_restore" => Some(Self::ConfigurationAndServiceRestore),
            "target_verification" => Some(Self::TargetVerification),
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
            Self::TargetVerification => "The installed version could not be confirmed or did not advance to the expected target version. Check application state before retrying.",
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

#[cfg(test)]
use af_release::lifecycle::diagnostic_projection::is_already_redacted;
pub use af_release::lifecycle::diagnostic_projection::{
    is_sensitive_secret_key, redact_balanced_structured_secrets, redact_embedded_json_fragments,
    redact_embedded_json_spans, redact_json_value, redact_secrets, redact_sensitive_http_headers,
};

pub fn sanitize_diagnostic_summary(input: &str, max_len: usize) -> String {
    let redacted = redact_secrets(input);
    let trimmed = redacted.trim();
    if trimmed.chars().count() <= max_len {
        trimmed.to_string()
    } else {
        let mut truncated: String = trimmed.chars().take(max_len).collect();
        truncated.push_str("...");
        truncated
    }
}

pub fn parse_diagnostic_markers(text: &str) -> (Option<String>, Option<i32>, Option<String>) {
    static STAGE_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"(?i)(?:\[STAGE:|stage[:=]\s*|stage\s+['`]?)([a-zA-Z0-9_.-]+)").unwrap()
    });
    static EXIT_CODE_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r"(?i)(?:exit status|exit code|exited with code|failed with code)[:=]?\s*(-?\d+)",
        )
        .unwrap()
    });

    let failed_stage = STAGE_RE
        .captures(text)
        .and_then(|c| c.get(1))
        .map(|m| redact_secrets(m.as_str()));
    let exit_code = EXIT_CODE_RE
        .captures(text)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<i32>().ok());
    let summary = if !text.trim().is_empty() {
        Some(sanitize_diagnostic_summary(text, 280))
    } else {
        None
    };

    (failed_stage, exit_code, summary)
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
        let has_recovery: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_jobs') WHERE name='recovery_state')",
            [],
            |row| row.get(0),
        )?;
        let query = if has_recovery {
            "SELECT package_id,job_id,action,status,started_at,finished_at,failure_category,
                    failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,
                    recovery_state
             FROM package_lifecycle_jobs"
        } else {
            "SELECT package_id,job_id,action,status,started_at,finished_at,failure_category,
                    failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,
                    ''
             FROM package_lifecycle_jobs"
        };
        let rows: Vec<PackageJobOutcome> = conn
            .prepare(query)?
            .query_map([], read_outcome)?
            .collect::<rusqlite::Result<_>>()?;
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
                            expected_target_version: row.expected_target_version,
                        },
                    );
                }
                self.outcomes.remove(&row.package_id);
            } else {
                self.active.remove(&row.package_id);
                self.leases.remove(&row.package_id);
                if self.outcomes.get(&row.package_id).is_none_or(|old| {
                    old.job_id != row.job_id
                        || old.status != row.status
                        || old.recovery_state != row.recovery_state
                }) {
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
            let lease = af_release::lifecycle::admit_job_with_target(
                conn,
                &info.package_id,
                &info.job_id,
                &info.action,
                &info.started_at,
                &units,
                info.expected_target_version.as_deref(),
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
        self.finish_with_diagnostics(
            pkg, action, success, failure, job_id, None, None, None, None, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_with_diagnostics(
        &mut self,
        pkg: &str,
        action: &str,
        success: bool,
        failure: Option<PackageJobFailure>,
        job_id: &str,
        failed_stage: Option<String>,
        exit_code: Option<i32>,
        sanitized_summary: Option<String>,
        expected_target_version: Option<String>,
        achieved_version: Option<String>,
    ) -> anyhow::Result<Option<PackageJobOutcome>> {
        self.finish_with_diagnostics_and_recovery(
            pkg,
            action,
            success,
            failure,
            job_id,
            failed_stage,
            exit_code,
            sanitized_summary,
            expected_target_version,
            achieved_version,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_with_diagnostics_and_recovery(
        &mut self,
        pkg: &str,
        action: &str,
        success: bool,
        failure: Option<PackageJobFailure>,
        job_id: &str,
        failed_stage: Option<String>,
        exit_code: Option<i32>,
        sanitized_summary: Option<String>,
        expected_target_version: Option<String>,
        achieved_version: Option<String>,
        recovery_state: Option<String>,
        retention_state: Option<String>,
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
        let normalized_recovery = af_release::lifecycle::normalize_recovery_state(
            success,
            action,
            category,
            recovery_state.as_deref(),
        );
        let recovery_state_opt = if normalized_recovery.is_empty() {
            None
        } else {
            Some(normalized_recovery.to_string())
        };
        let sanitized_summary = sanitized_summary.map(|s| redact_secrets(&s));
        let failed_stage = failed_stage.map(|s| redact_secrets(&s));
        let expected_target =
            expected_target_version.or_else(|| job.expected_target_version.clone());
        let outcome = PackageJobOutcome {
            job_id: job.job_id.clone(),
            package_id: pkg.to_string(),
            action: action.to_string(),
            status: status.to_string(),
            message: outcome_summary(status, category).to_string(),
            started_at: job.started_at.clone(),
            finished_at: Utc::now().to_rfc3339(),
            failed_stage: failed_stage.clone(),
            exit_code,
            sanitized_summary: sanitized_summary.clone(),
            expected_target_version: expected_target,
            achieved_version,
            recovery_state: recovery_state_opt.clone(),
        };
        if let Some(conn) = &self.db {
            af_release::lifecycle::finish_job_with_diagnostics(
                conn,
                pkg,
                &outcome.job_id,
                action,
                success,
                af_release::lifecycle::LifecycleJobDiagnostics {
                    failure_category: category,
                    failed_stage: failed_stage.as_deref(),
                    exit_code,
                    sanitized_summary: sanitized_summary.as_deref(),
                    expected_target_version: outcome.expected_target_version.as_deref(),
                    achieved_version: outcome.achieved_version.as_deref(),
                    finished_at: Some(outcome.finished_at.as_str()),
                    recovery_state: recovery_state_opt.as_deref(),
                    retention_state: retention_state.as_deref(),
                },
            )?;
        }
        self.outcomes.insert(pkg.to_string(), outcome.clone());
        self.active.remove(pkg);
        self.leases.remove(pkg);
        Ok(Some(outcome))
    }
}

fn read_outcome(row: &Row<'_>) -> rusqlite::Result<PackageJobOutcome> {
    let status: String = row.get(3)?;
    let failed_stage: String = row.get::<_, Option<String>>(7)?.unwrap_or_default();
    let exit_code: Option<i32> = row.get(8)?;
    let sanitized_summary: String = row.get::<_, Option<String>>(9)?.unwrap_or_default();
    let expected_target_version: String = row.get::<_, Option<String>>(10)?.unwrap_or_default();
    let achieved_version: String = row.get::<_, Option<String>>(11)?.unwrap_or_default();
    let recovery_state: String = row.get::<_, Option<String>>(12)?.unwrap_or_default();
    Ok(PackageJobOutcome {
        package_id: row.get(0)?,
        job_id: row.get(1)?,
        action: row.get(2)?,
        message: outcome_summary(&status, &row.get::<_, String>(6)?).into(),
        status,
        started_at: row.get(4)?,
        finished_at: row.get(5)?,
        failed_stage: if failed_stage.is_empty() {
            None
        } else {
            Some(failed_stage)
        },
        exit_code,
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
        recovery_state: if recovery_state.is_empty() {
            None
        } else {
            Some(recovery_state)
        },
    })
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

pub fn retained_lifecycle_packages() -> anyhow::Result<std::collections::HashSet<String>> {
    let conn = af_db::get_read_conn()?;
    af_release::lifecycle::query_retained_lifecycle_packages(&conn)
}

/// Look up an exact terminal receipt after a later job supersedes it in the live registry.
pub fn get_package_job_history_outcome(
    package_id: &str,
    job_id: &str,
) -> anyhow::Result<Option<PackageJobOutcome>> {
    let path = JOBS
        .lock()
        .map_err(|_| anyhow::anyhow!("lifecycle registry unavailable"))?
        .db
        .as_ref()
        .and_then(|conn| conn.path())
        .map(str::to_owned);
    let Some(path) = path else {
        return Ok(None);
    };
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(Duration::from_millis(150))?;
    let has_recovery: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('package_lifecycle_history') WHERE name='recovery_state')",
        [],
        |row| row.get(0),
    )?;
    let query = if has_recovery {
        "SELECT package_id,job_id,action,status,started_at,finished_at,failure_category,
                failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,
                recovery_state
         FROM package_lifecycle_history
         WHERE package_id = ?1 AND job_id = ?2
           AND status IN ('completed', 'failed', 'interrupted')
         ORDER BY id DESC LIMIT 1"
    } else {
        "SELECT package_id,job_id,action,status,started_at,finished_at,failure_category,
                failed_stage,exit_code,sanitized_summary,expected_target_version,achieved_version,
                ''
         FROM package_lifecycle_history
         WHERE package_id = ?1 AND job_id = ?2
           AND status IN ('completed', 'failed', 'interrupted')
         ORDER BY id DESC LIMIT 1"
    };
    Ok(conn
        .query_row(query, params![package_id, job_id], read_outcome)
        .optional()?)
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
    info.last_line = redact_secrets(&info.last_line);
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

pub fn try_start_package_job(mut info: PackageJobInfo) -> bool {
    info.last_line = redact_secrets(&info.last_line);
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

#[allow(clippy::too_many_arguments)]
pub fn finish_package_job_with_diagnostics(
    pkg: &str,
    action: &str,
    success: bool,
    failure: Option<PackageJobFailure>,
    job_id: &str,
    failed_stage: Option<String>,
    exit_code: Option<i32>,
    sanitized_summary: Option<String>,
    expected_target_version: Option<String>,
    achieved_version: Option<String>,
) -> Option<PackageJobOutcome> {
    finish_package_job_with_recovery(
        pkg,
        action,
        success,
        failure,
        job_id,
        failed_stage,
        exit_code,
        sanitized_summary,
        expected_target_version,
        achieved_version,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn finish_package_job_with_recovery(
    pkg: &str,
    action: &str,
    success: bool,
    failure: Option<PackageJobFailure>,
    job_id: &str,
    failed_stage: Option<String>,
    exit_code: Option<i32>,
    sanitized_summary: Option<String>,
    expected_target_version: Option<String>,
    achieved_version: Option<String>,
    recovery_state: Option<String>,
) -> Option<PackageJobOutcome> {
    finish_package_job_with_recovery_and_retention(
        pkg,
        action,
        success,
        failure,
        job_id,
        failed_stage,
        exit_code,
        sanitized_summary,
        expected_target_version,
        achieved_version,
        recovery_state,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn finish_package_job_with_recovery_and_retention(
    pkg: &str,
    action: &str,
    success: bool,
    failure: Option<PackageJobFailure>,
    job_id: &str,
    failed_stage: Option<String>,
    exit_code: Option<i32>,
    sanitized_summary: Option<String>,
    expected_target_version: Option<String>,
    achieved_version: Option<String>,
    recovery_state: Option<String>,
    retention_state: Option<String>,
) -> Option<PackageJobOutcome> {
    match JOBS.lock().map(|mut jobs| {
        jobs.finish_with_diagnostics_and_recovery(
            pkg,
            action,
            success,
            failure,
            job_id,
            failed_stage,
            exit_code,
            sanitized_summary,
            expected_target_version,
            achieved_version,
            recovery_state,
            retention_state,
        )
    }) {
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

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;
