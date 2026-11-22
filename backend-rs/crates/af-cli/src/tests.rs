//! Comprehensive unit and integration tests for `af-cli` in isolated temporary directories.
//!
//! Covers:
//! 1. Legacy `packages/system/af` CLI compatibility (`install`, `remove`, `list`, `update`, `upgrade`, `-h`, `autodl` alias)
//!    and rejection of no-arg interactive TUI invocation.
//! 2. Typed request generation & validation (`PackageRunnerRequest`, `SystemctlRequest`, `QuotaRunnerRequest`,
//!    `SandboxRunnerRequest`, `SelfUpdateRequest`) with injection/traversal rejection.
//! 3. Runner socket streaming protocol (`[PROGRESS:<pct>]` parsing and `__RUNNER_EXIT_ERROR__:` propagation)
//!    and mock transport dispatch across `package`, `service`, `quota`, `sandbox`, `release`, and `health`.
//! 4. Release `status`, `deploy`, `rollback`, `cleanup`, and `migrate-systemd` integration with `af-release`.
//! 5. Host backup `create`, `list`, `verify`, `chunk`, `assemble`, `delete`, `prune`, `ownership`,
//!    non-destructive `restore-preflight`, and fail-closed `restore` (`DestructiveRestoreUnsupported`) via `af-host`.
//! 6. Resumable provisioning foundation (`STATE_VERSION=2` `/install/.aetherflow.state`, `.aetherflow.conf`,
//!    `os-release` preflight, PID lockfile, `--repair`, `--resume`, `--fresh`, `--dry-run`, and `.aetherflow-sha256`
//!    safe config overlays preserving `.user-backup.<ts>`).

use super::*;
use af_models::{
    PackageRunnerRequest, QuotaRunnerRequest, RunnerResponse, SandboxRunnerRequest,
    SelfUpdateRequest, SystemctlRequest,
};
use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

mod cli_and_transport_tests;
mod package_purge_tests;
mod package_update_tests;
mod provision_maintenance_tests;
mod release_backup_tests;

pub(super) static ENV_TEST_LOCK: once_cell::sync::Lazy<Mutex<()>> =
    once_cell::sync::Lazy::new(|| Mutex::new(()));

/// RAII temporary directory guard under `std::env::temp_dir()` so tests never touch real system paths.
pub(super) struct TempTestDir {
    path: PathBuf,
}

impl TempTestDir {
    pub(super) fn new(prefix: &str) -> Self {
        let unique = format!(
            "af-cli-test-{}-{}-{}",
            prefix,
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).expect("create isolated temp dir");
        Self { path }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Recording mock implementation of [`RunnerClientTransport`] for testing Unix-socket-mediated
/// commands without a live root daemon.
#[derive(Default, Clone)]
pub(super) struct MockRunnerTransport {
    pub(super) package_calls: Arc<Mutex<Vec<PackageRunnerRequest>>>,
    pub(super) cancel_calls: Arc<Mutex<Vec<SandboxRunnerRequest>>>,
    pub(super) systemctl_calls: Arc<Mutex<Vec<SystemctlRequest>>>,
    pub(super) quota_calls: Arc<Mutex<Vec<QuotaRunnerRequest>>>,
    pub(super) sandbox_calls: Arc<Mutex<Vec<SandboxRunnerRequest>>>,
    pub(super) self_update_calls: Arc<Mutex<Vec<SelfUpdateRequest>>>,
    pub(super) hosts_calls: Arc<Mutex<Vec<af_runner::HostsUpdateRequest>>>,
    pub(super) probed_versions: Arc<Mutex<std::collections::HashMap<String, String>>>,
    pub(super) simulated_package_body: Arc<Mutex<Option<String>>>,
}

impl RunnerClientTransport for MockRunnerTransport {
    fn check_health(&self) -> CliResult<RunnerResponse> {
        Ok(RunnerResponse {
            success: true,
            output: "ready".to_string(),
            error: String::new(),
        })
    }

    fn execute_package(&self, req: &PackageRunnerRequest) -> CliResult<PackageExecutionReceipt> {
        self.package_calls.lock().unwrap().push(req.clone());
        let body = self
            .simulated_package_body
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| {
                format!(
                    "[PROGRESS:10] Validating {}\n[PROGRESS:60] Configuring systemd unit\n[PROGRESS:100] Completed {}\n",
                    req.package_id, req.script_name
                )
            });
        let (receipt, _) = parse_package_stream_body(req, &body)?;
        Ok(receipt)
    }

    fn cancel_package(&self, req: &SandboxRunnerRequest) -> CliResult<RunnerResponse> {
        self.cancel_calls.lock().unwrap().push(req.clone());
        Ok(RunnerResponse {
            success: true,
            output: format!("cancellation signalled for {}", req.package_id),
            error: String::new(),
        })
    }

    fn execute_systemctl(&self, req: &SystemctlRequest) -> CliResult<RunnerResponse> {
        self.systemctl_calls.lock().unwrap().push(req.clone());
        Ok(RunnerResponse {
            success: true,
            output: format!("active ({} {})", req.action, req.service),
            error: String::new(),
        })
    }

    fn execute_quota(&self, req: &QuotaRunnerRequest) -> CliResult<RunnerResponse> {
        self.quota_calls.lock().unwrap().push(req.clone());
        Ok(RunnerResponse {
            success: true,
            output: serde_json::to_string(&serde_json::json!({
                "username": req.username,
                "quota": req.size,
                "status": "applied"
            }))
            .unwrap(),
            error: String::new(),
        })
    }

    fn execute_sandbox(&self, req: &SandboxRunnerRequest) -> CliResult<RunnerResponse> {
        self.sandbox_calls.lock().unwrap().push(req.clone());
        Ok(RunnerResponse {
            success: true,
            output: "sandbox applied".to_string(),
            error: String::new(),
        })
    }

    fn execute_self_update(&self, req: &SelfUpdateRequest) -> CliResult<RunnerResponse> {
        self.self_update_calls.lock().unwrap().push(req.clone());
        Ok(RunnerResponse {
            success: true,
            output: "Release manager initiated in root runner cgroup".to_string(),
            error: String::new(),
        })
    }

    fn execute_hosts(&self, req: &af_runner::HostsUpdateRequest) -> CliResult<RunnerResponse> {
        self.hosts_calls.lock().unwrap().push(req.clone());
        Ok(RunnerResponse {
            success: true,
            output: format!("hosts {}", req.action),
            error: String::new(),
        })
    }

    fn probe_package_version(&self, package_id: &str) -> CliResult<Option<String>> {
        Ok(self
            .probed_versions
            .lock()
            .unwrap()
            .get(package_id)
            .cloned())
    }
}

pub(super) fn create_sample_sqlite_db(db_path: &Path) {
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let conn = Connection::open(db_path).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA user_version = 14;
         CREATE TABLE settings (id INTEGER PRIMARY KEY, domain TEXT NOT NULL);
         INSERT INTO settings (id, domain) VALUES (1, 'aetherflow.local');",
    )
    .unwrap();
}
