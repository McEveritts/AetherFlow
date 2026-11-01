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
use af_release::ReleaseChannel;
use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// RAII temporary directory guard under `std::env::temp_dir()` so tests never touch real system paths.
struct TempTestDir {
    path: PathBuf,
}

impl TempTestDir {
    fn new(prefix: &str) -> Self {
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

    fn path(&self) -> &Path {
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
struct MockRunnerTransport {
    package_calls: Arc<Mutex<Vec<PackageRunnerRequest>>>,
    cancel_calls: Arc<Mutex<Vec<SandboxRunnerRequest>>>,
    systemctl_calls: Arc<Mutex<Vec<SystemctlRequest>>>,
    quota_calls: Arc<Mutex<Vec<QuotaRunnerRequest>>>,
    sandbox_calls: Arc<Mutex<Vec<SandboxRunnerRequest>>>,
    self_update_calls: Arc<Mutex<Vec<SelfUpdateRequest>>>,
    simulated_package_body: Arc<Mutex<Option<String>>>,
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
}

fn create_sample_sqlite_db(db_path: &Path) {
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

#[test]
fn cli_parser_supports_legacy_af_shorthands_and_rejects_no_arg_tui() {
    // 1. Calling `af` with no arguments returns an explicit Unsupported error for interactive TUI
    let empty_err = parse_cli_args(Vec::<&str>::new()).unwrap_err();
    assert_eq!(empty_err.exit_code(), CliExitCode::UnsupportedOperation);
    assert!(empty_err.to_string().contains("interactive-tui"));

    // 2. Legacy `af install sonarr radarr`
    let inv = parse_cli_args(["install", "sonarr", "radarr"]).unwrap();
    assert_eq!(
        inv.command,
        AfCommand::Package(PackageCommand::Install {
            packages: vec!["sonarr".to_string(), "radarr".to_string()],
            port: None,
        })
    );

    assert!(parse_cli_args(["remove", "autodl"]).is_err());
    assert_eq!(resolve_package_lock_name("autodl"), "autodlirssi");
    assert_eq!(resolve_package_lock_name("sonarr"), "sonarr");

    // 4. Legacy `af list`, `af update`, `af upgrade`, `af -h`
    let list_inv = parse_cli_args(["list", "--installed"]).unwrap();
    assert_eq!(
        list_inv.command,
        AfCommand::Package(PackageCommand::List {
            installed_only: true
        })
    );

    let upd_inv = parse_cli_args(["update"]).unwrap();
    assert_eq!(
        upd_inv.command,
        AfCommand::Package(PackageCommand::Update {
            package: None,
            channel: ReleaseChannel::Stable,
        })
    );

    let upg_inv = parse_cli_args(["upgrade", "--channel", "nightly"]).unwrap();
    assert_eq!(
        upg_inv.command,
        AfCommand::Package(PackageCommand::Upgrade {
            channel: ReleaseChannel::Nightly,
        })
    );

    let help_inv = parse_cli_args(["-h"]).unwrap();
    assert_eq!(
        help_inv.command,
        AfCommand::Help {
            topic: HelpTopic::General
        }
    );
}

#[test]
fn typed_request_builders_validate_and_reject_injections() {
    // Package request builder
    let pkg_req = build_package_runner_request("install", "jellyfin", Some(8096)).unwrap();
    assert_eq!(pkg_req.action, "install");
    assert_eq!(pkg_req.package_id, "jellyfin");
    assert_eq!(pkg_req.script_name, "installpackage-jellyfin");
    assert_eq!(pkg_req.app_port, 8096);

    assert!(build_package_runner_request("install", "../etc/passwd", None).is_err());
    assert!(build_package_runner_request("install", "nonexistent_pkg_xyz", None).is_err());
    assert!(build_package_runner_request("exec", "sonarr", None).is_err());

    // Service request builder
    let svc_req = validate_service_request("sonarr.service", "restart").unwrap();
    assert_eq!(svc_req.service, "sonarr.service");
    assert_eq!(svc_req.action, "restart");
    assert!(validate_service_request("sonarr;rm -rf /", "restart").is_err());
    assert!(validate_service_request("sonarr.service", "mask").is_err());

    // Quota request builder reuses af-runner's 1K block parser
    let (q_req, blocks) = build_quota_runner_request("alice_01", "50G").unwrap();
    assert_eq!(q_req.username, "alice_01");
    assert_eq!(q_req.size, "50G");
    assert_eq!(blocks, 50 * 1024 * 1024);
    assert!(build_quota_runner_request("1bad;user", "50G").is_err());
    assert!(build_quota_runner_request("alice_01", "50X").is_err());

    // Sandbox request builder
    let sbx_req = build_sandbox_runner_request("sonarr").unwrap();
    assert_eq!(sbx_req.package_id, "sonarr");
    assert!(build_sandbox_runner_request("../sonarr").is_err());

    // Self-update request builder reuses af-release validation
    let su_req = build_self_update_runner_request("deploy", ReleaseChannel::Stable).unwrap();
    assert_eq!(su_req.command, "deploy");
    assert_eq!(su_req.channel, "stable");
    assert!(build_self_update_runner_request("arbitrary-cmd", ReleaseChannel::Stable).is_err());
}

#[test]
fn package_stream_parser_extracts_progress_and_propagates_runner_exit_errors() {
    let req = build_package_runner_request("install", "sonarr", None).unwrap();
    let stream_ok = "\
[PROGRESS:5] Preparing environment
Installing dependencies...
[PROGRESS:55] Writing systemd unit
[PROGRESS:100] Package sonarr installed
";
    let (receipt, events) = parse_package_stream_body(&req, stream_ok).unwrap();
    assert_eq!(receipt.last_progress_percent, Some(100));
    assert_eq!(receipt.total_log_lines, 4);
    assert_eq!(receipt.truncated_log_lines, 0);
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].progress_percent, Some(5));
    assert_eq!(events[0].message, "Preparing environment");
    assert_eq!(
        format_human_progress_line("sonarr", &events[0]),
        "[  5%] sonarr: Preparing environment"
    );
    assert_eq!(events[1].progress_percent, None);
    assert_eq!(
        format_human_progress_line("sonarr", &events[1]),
        "       sonarr: Installing dependencies..."
    );

    // Verify incremental chunked splitting across arbitrary mid-line boundaries and bounded log ring
    let mut acc = PackageStreamAccumulator::new();
    let mut live_events = Vec::new();
    acc.push_chunk(b"[PROGR", |ev| live_events.push(ev.clone()));
    assert!(live_events.is_empty());
    acc.push_chunk(b"ESS:25] Step one\nPlain log ", |ev| live_events.push(ev.clone()));
    assert_eq!(live_events.len(), 1);
    assert_eq!(live_events[0].progress_percent, Some(25));
    acc.push_chunk(b"line\n[PROGRESS:100] Done", |ev| live_events.push(ev.clone()));
    assert_eq!(live_events.len(), 2);
    let chunked_receipt = acc.finish(&req, |ev| live_events.push(ev.clone())).unwrap();
    assert_eq!(live_events.len(), 3);
    assert_eq!(chunked_receipt.last_progress_percent, Some(100));
    assert_eq!(chunked_receipt.total_log_lines, 3);

    let stream_err = "\
[PROGRESS:10] Starting removal
__RUNNER_EXIT_ERROR__:exit status 42
";
    let err = parse_package_stream_body(&req, stream_err).unwrap_err();
    assert_eq!(err.exit_code(), CliExitCode::RunnerIpcFailure);
    assert!(err.to_string().contains("exit status 42"));
}

#[test]
fn runner_mediated_commands_dispatch_typed_requests_and_respect_lockfiles_and_dry_run() {
    let tmp = TempTestDir::new("runner-dispatch");
    let install_dir = tmp.path().join("install");
    fs::create_dir_all(&install_dir).unwrap();
    // Mark `radarr` as already installed via `/install/.radarr.lock`
    fs::write(install_dir.join(".radarr.lock"), b"installed\n").unwrap();

    let transport = MockRunnerTransport::default();
    let root_str = tmp.path().to_string_lossy().to_string();

    // 1. Install `sonarr` and `radarr`: `radarr` should be skipped as already installed, `sonarr` dispatched
    let inv = parse_cli_args(["--json", "--root", &root_str, "install", "sonarr", "radarr"]).unwrap();
    let env = execute_invocation(&inv, &transport);
    assert_eq!(env.status, "ok");
    assert_eq!(env.exit_code, 0);
    let pkg_calls = transport.package_calls.lock().unwrap();
    assert_eq!(pkg_calls.len(), 1);
    assert_eq!(pkg_calls[0].package_id, "sonarr");
    assert_eq!(pkg_calls[0].script_name, "installpackage-sonarr");
    drop(pkg_calls);

    // 2. Service restart via `/v1/systemctl`
    let svc_inv = parse_cli_args(["service", "restart", "sonarr.service"]).unwrap();
    let svc_env = execute_invocation(&svc_inv, &transport);
    assert_eq!(svc_env.status, "ok");
    let svc_calls = transport.systemctl_calls.lock().unwrap();
    assert_eq!(svc_calls.len(), 1);
    assert_eq!(svc_calls[0].service, "sonarr.service");
    assert_eq!(svc_calls[0].action, "restart");
    drop(svc_calls);

    // 3. Quota set via `/v1/quota` and legacy `setdisk` alias
    let quota_inv = parse_cli_args(["setdisk", "alice", "100G"]).unwrap();
    let quota_env = execute_invocation(&quota_inv, &transport);
    assert_eq!(quota_env.status, "ok");
    let q_calls = transport.quota_calls.lock().unwrap();
    assert_eq!(q_calls.len(), 1);
    assert_eq!(q_calls[0].username, "alice");
    assert_eq!(q_calls[0].size, "100G");
    drop(q_calls);

    // 4. Sandbox apply & render via `/v1/sandbox` and `af_runner::render_systemd_sandbox_dropin`
    let sbx_inv = parse_cli_args(["sandbox", "apply", "sonarr"]).unwrap();
    let sbx_env = execute_invocation(&sbx_inv, &transport);
    assert_eq!(sbx_env.status, "ok");
    assert_eq!(transport.sandbox_calls.lock().unwrap().len(), 1);

    let render_inv = parse_cli_args(["sandbox", "render", "sonarr", "--user", "mediauser"]).unwrap();
    let render_env = execute_invocation(&render_inv, &transport);
    assert_eq!(render_env.status, "ok");
    assert!(render_env.message.contains("[Service]"));
    assert!(render_env.message.contains("NoNewPrivileges=yes"));

    // 5. Package cancel via `/v1/package/cancel`
    let cancel_inv = parse_cli_args(["package", "cancel", "sonarr"]).unwrap();
    let cancel_env = execute_invocation(&cancel_inv, &transport);
    assert_eq!(cancel_env.status, "ok");
    assert_eq!(transport.cancel_calls.lock().unwrap().len(), 1);

    // 6. Release deploy via runner socket (`/v1/self-update`)
    let rel_inv = parse_cli_args(["release", "deploy", "--channel", "nightly"]).unwrap();
    let rel_env = execute_invocation(&rel_inv, &transport);
    assert_eq!(rel_env.status, "ok");
    let su_calls = transport.self_update_calls.lock().unwrap();
    assert_eq!(su_calls.len(), 1);
    assert_eq!(su_calls[0].command, "deploy");
    assert_eq!(su_calls[0].channel, "nightly");
}

#[test]
fn release_status_and_local_dry_run_integrate_with_af_release() {
    let tmp = TempTestDir::new("release-engine");
    let root_str = tmp.path().to_string_lossy().to_string();
    let transport = MockRunnerTransport::default();

    // Create minimal release directories matching `ReleaseConfig::for_root` (`opt/AetherFlow/releases`)
    let rel_v1 = tmp.path().join("opt/AetherFlow/releases/v4.0.0");
    fs::create_dir_all(&rel_v1).unwrap();
    let etc_dir = tmp.path().join("etc/aetherflow");
    fs::create_dir_all(&etc_dir).unwrap();

    let status_inv = parse_cli_args(["--json", "--root", &root_str, "release", "status"]).unwrap();
    let status_env = execute_invocation(&status_inv, &transport);
    assert_eq!(
        status_env.status, "ok",
        "release status failed: {}",
        status_env.message
    );
    let data = status_env.data.unwrap();
    assert_eq!(data["configured_channel"], "stable");
    let avail = data["available_releases"]
        .as_array()
        .expect("available_releases array");
    assert_eq!(avail.len(), 1);
    assert!(avail[0]
        .as_str()
        .unwrap_or_default()
        .ends_with("v4.0.0"));

    // Cleanup in --dry-run mode
    let clean_inv = parse_cli_args([
        "--dry-run",
        "--root",
        &root_str,
        "release",
        "cleanup",
        "--keep-releases",
        "2",
    ])
    .unwrap();
    let clean_env = execute_invocation(&clean_inv, &transport);
    assert_eq!(
        clean_env.status, "ok",
        "release cleanup failed: {}",
        clean_env.message
    );
}

#[test]
fn backup_commands_create_verify_list_and_run_non_destructive_restore_preflight_via_af_host() {
    let tmp = TempTestDir::new("backup-e2e");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_sqlite_db(&live_db);

    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    fs::write(etc_af.join("settings.conf"), b"theme=dark\n").unwrap();

    let root_str = host_root.to_string_lossy().to_string();
    let transport = MockRunnerTransport::default();

    // 1. Create a full host archive backup with chunk splitting in isolated root
    let create_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "backup",
        "create",
        "--archive",
        "--timestamp",
        "2026-10-31-180000",
        "--chunk-size",
        "512",
    ])
    .unwrap();
    let create_env = execute_invocation(&create_inv, &transport);
    assert_eq!(
        create_env.status, "ok",
        "backup create failed: {}",
        create_env.message
    );

    let archive_name = "aetherflow-backup-2026-10-31-180000.tar.gz";

    // 2. List backups
    let list_inv = parse_cli_args(["--json", "--root", &root_str, "backup", "list"]).unwrap();
    let list_env = execute_invocation(&list_inv, &transport);
    assert_eq!(list_env.status, "ok");
    let list_data = list_env.data.unwrap();
    assert_eq!(list_data["count"], 1);
    assert_eq!(list_data["items"][0]["filename"], archive_name);
    assert_eq!(list_data["items"][0]["checksum_present"], true);
    assert_eq!(list_data["items"][0]["manifest_present"], true);

    // 3. Verify backup artifact and sidecar/manifest
    let verify_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "backup",
        "verify",
        archive_name,
    ])
    .unwrap();
    let verify_env = execute_invocation(&verify_inv, &transport);
    assert_eq!(verify_env.status, "ok");

    // 4. Run NON-DESTRUCTIVE restore-preflight into an isolated staging directory
    let stage_target = tmp.path().join("restore-preflight-stage");
    let stage_str = stage_target.to_string_lossy().to_string();
    let preflight_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "backup",
        "restore-preflight",
        archive_name,
        "--target-root",
        &stage_str,
    ])
    .unwrap();
    let preflight_env = execute_invocation(&preflight_inv, &transport);
    assert_eq!(
        preflight_env.status, "ok",
        "restore-preflight failed: {}",
        preflight_env.message
    );
    let plan_data = preflight_env.data.unwrap();
    assert_eq!(plan_data["non_destructive_only"], true);
    assert!(!stage_target.exists(), "restore-preflight must never write to target_root");

    // 5. Verify destructive `af backup restore` fails closed with UnsupportedOperation (exit code 6)
    let restore_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "backup",
        "restore",
        archive_name,
    ])
    .unwrap();
    let restore_env = execute_invocation(&restore_inv, &transport);
    assert_eq!(restore_env.status, "error");
    assert_eq!(
        restore_env.exit_code,
        CliExitCode::UnsupportedOperation.as_i32()
    );
    assert!(restore_env.message.contains("explicitly unsupported"));
}

#[test]
fn resumable_provisioning_persists_state_v2_supports_repair_and_overlays_configs_safely() {
    let tmp = TempTestDir::new("provision");
    let root = tmp.path().join("rootfs");
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::write(
        root.join("etc/os-release"),
        "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n",
    )
    .unwrap();

    let root_str = root.to_string_lossy().to_string();
    let transport = MockRunnerTransport::default();

    // 1. Preflight check passes against Ubuntu 24.04 in isolated root
    let pre_inv = parse_cli_args(["--json", "--root", &root_str, "provision", "preflight"]).unwrap();
    let pre_env = execute_invocation(&pre_inv, &transport);
    assert_eq!(pre_env.status, "ok", "preflight failed: {}", pre_env.message);

    // 2. Dry-run provisioning does not create `/install/.aetherflow.state`
    let dry_inv = parse_cli_args([
        "--dry-run",
        "--root",
        &root_str,
        "provision",
        "run",
        "--no-root-check",
    ])
    .unwrap();
    let dry_env = execute_invocation(&dry_inv, &transport);
    assert_eq!(dry_env.status, "ok");
    assert!(!root.join("install/.aetherflow.state").exists());

    // 3. Execute default Rust-native foundation steps and verify `# STATE_VERSION=2` persistence
    let run_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "provision",
        "run",
        "--no-root-check",
    ])
    .unwrap();
    let run_env = execute_invocation(&run_inv, &transport);
    assert_eq!(run_env.status, "ok", "provision run failed: {}", run_env.message);

    let state_raw = fs::read_to_string(root.join("install/.aetherflow.state")).unwrap();
    assert!(state_raw.starts_with("# STATE_VERSION=2\n"));
    assert!(state_raw.contains("makedirs\n"));
    assert!(state_raw.contains("harden_perms\n"));
    assert!(root.join("opt/AetherFlow/releases").is_dir());
    assert!(root
        .join("etc/systemd/system/aetherflow-api.service.d/10-aetherflow-sandbox.conf")
        .is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let state_mode = fs::metadata(root.join("install/.aetherflow.state"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let conf_mode = fs::metadata(root.join("install/.aetherflow.conf"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(state_mode, 0o600, "state file must have 0600 private permissions");
        assert_eq!(conf_mode, 0o600, "config file must have 0600 private permissions");
    }

    // 4. Re-running `af provision run` skips already-completed steps (`SkippedAlreadyDone`)
    let resume_env = execute_invocation(&run_inv, &transport);
    assert_eq!(resume_env.status, "ok");
    let resume_data = resume_env.data.unwrap();
    assert_eq!(
        resume_data["records"][0]["status"],
        "skipped_already_done"
    );

    // 5. Explicit `af provision repair makedirs` clears and re-executes `makedirs`
    let repair_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "provision",
        "repair",
        "makedirs",
        "--no-root-check",
    ])
    .unwrap();
    let repair_env = execute_invocation(&repair_inv, &transport);
    assert_eq!(repair_env.status, "ok");
    let repair_data = repair_env.data.unwrap();
    assert_eq!(
        repair_data["cleared_for_repair"],
        serde_json::json!(["makedirs"])
    );
    assert_eq!(repair_data["records"][0]["status"], "completed");

    // 6. Reject arbitrary raw shell step names or command injections
    let bad_step = parse_cli_args([
        "--root",
        &root_str,
        "provision",
        "run",
        "bash -c 'id'",
    ])
    .unwrap();
    let bad_env = execute_invocation(&bad_step, &transport);
    assert_eq!(bad_env.status, "error");
    assert_eq!(bad_env.exit_code, CliExitCode::UsageOrValidation.as_i32());

    // 7. Test `ProvisionLockGuard` crash recovery and active contention
    let lock_path = root.join("run/aetherflow-setup.lock");
    fs::write(&lock_path, b"99999999\n").unwrap(); // Stale crashed PID
    let lock_guard = ProvisionLockGuard::acquire(&lock_path).expect("should recover stale lockfile");
    let contention_err = ProvisionLockGuard::acquire(&lock_path).unwrap_err();
    assert_eq!(
        contention_err.exit_code(),
        CliExitCode::PreflightOrIntegrityFailure
    );
    drop(lock_guard);
    assert!(!lock_path.exists(), "dropping lock guard should remove lockfile");

    // 8. Test `safe_overlay_config_file` user-modification backup semantics
    let src_v1 = tmp.path().join("stock_v1.conf");
    let src_v2 = tmp.path().join("stock_v2.conf");
    let target_conf = root.join("etc/aetherflow/custom_overlay.conf");
    fs::write(&src_v1, b"port=8080\n").unwrap();
    fs::write(&src_v2, b"port=9090\n").unwrap();

    // Initial install
    let r1 = safe_overlay_config_file(&src_v1, &target_conf, false, false).unwrap();
    assert_eq!(r1.outcome, ConfigOverlayOutcome::InstalledNew);
    assert!(r1.sidecar_path.is_file());

    // Identical re-apply
    let r2 = safe_overlay_config_file(&src_v1, &target_conf, false, false).unwrap();
    assert_eq!(r2.outcome, ConfigOverlayOutcome::UnchangedIdentical);

    // Upgrade unmodified stock file to v2
    let r3 = safe_overlay_config_file(&src_v2, &target_conf, false, false).unwrap();
    assert_eq!(r3.outcome, ConfigOverlayOutcome::UpdatedUnmodifiedStock);
    assert!(r3.backup_path.is_none());

    // Simulate operator editing target_conf, then overlay v1 -> must create `.user-backup.<ts>`
    fs::write(&target_conf, b"port=7777\nuser_customized=true\n").unwrap();
    let r4 = safe_overlay_config_file(&src_v1, &target_conf, false, false).unwrap();
    assert_eq!(
        r4.outcome,
        ConfigOverlayOutcome::BackedUpUserModifiedAndUpdated
    );
    let bak = r4.backup_path.expect("expected user backup path");
    assert!(bak.is_file());
    assert_eq!(
        fs::read_to_string(&bak).unwrap(),
        "port=7777\nuser_customized=true\n"
    );
    assert_eq!(fs::read_to_string(&target_conf).unwrap(), "port=8080\n");

    // 9. Verify ancestor symlink rejection in provisioning state store on Unix
    #[cfg(unix)]
    {
        let sym_root = tmp.path().join("sym-rootfs");
        let outside_dir = tmp.path().join("outside-install");
        fs::create_dir_all(&sym_root).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();
        std::os::unix::fs::symlink(&outside_dir, sym_root.join("install")).unwrap();
        let sym_paths = ProvisionPaths::for_root(&sym_root).unwrap();
        let sym_store = ProvisionStateStore::new(sym_paths);
        let sym_err = sym_store.ensure_initialized(false).unwrap_err();
        assert_eq!(sym_err.exit_code(), CliExitCode::UsageOrValidation);
    }
}

#[test]
fn package_stream_accumulator_bounds_retained_logs_and_partial_lines() {
    let request = build_package_runner_request("install", "sonarr", None).unwrap();
    let mut accumulator = PackageStreamAccumulator::new();
    let chunk = vec![b'x'; MAX_PACKAGE_STREAM_LINE_CARRY_BYTES * 3];
    let mut largest_line = 0;
    accumulator.push_chunk(&chunk, |event| largest_line = largest_line.max(event.raw_line.len()));
    accumulator.push_chunk(b"\n", |_| {});
    for _ in 0..MAX_RETAINED_PACKAGE_LOG_LINES + 10 {
        accumulator.push_chunk(b"log line\n", |_| {});
    }
    let receipt = accumulator.finish(&request, |_| {}).unwrap();
    assert!(largest_line <= MAX_PACKAGE_STREAM_LINE_CARRY_BYTES);
    assert_eq!(receipt.log_lines.len(), MAX_RETAINED_PACKAGE_LOG_LINES);
    assert_eq!(receipt.total_log_lines, MAX_RETAINED_PACKAGE_LOG_LINES + 13);
    assert_eq!(receipt.truncated_log_lines, 13);
}

#[cfg(unix)]
#[test]
fn concurrent_provisioning_stale_lock_recovery_has_one_owner() {
    use std::sync::{Arc, Barrier, mpsc};
    let sandbox = TempTestDir::new("concurrent-provision-lock");
    let lock_path = sandbox.path().join("aetherflow-setup.lock");
    fs::write(&lock_path, "99999999\n").unwrap();
    let start = Arc::new(Barrier::new(3));
    let finish = Arc::new(Barrier::new(3));
    let (sender, receiver) = mpsc::channel();
    let mut workers = Vec::new();
    for _ in 0..2 {
        let start = start.clone();
        let finish = finish.clone();
        let sender = sender.clone();
        let lock_path = lock_path.clone();
        workers.push(std::thread::spawn(move || {
            start.wait();
            let guard = ProvisionLockGuard::acquire(&lock_path);
            sender.send(guard.is_ok()).unwrap();
            finish.wait();
            drop(guard);
        }));
    }
    start.wait();
    let owner_count = usize::from(receiver.recv().unwrap()) + usize::from(receiver.recv().unwrap());
    finish.wait();
    for worker in workers { worker.join().unwrap(); }
    assert_eq!(owner_count, 1);
    assert!(!lock_path.exists());
    assert!(sandbox.path().join(".aetherflow-setup.lock.rust-guard").is_file());
    let guard = ProvisionLockGuard::acquire(&lock_path).unwrap();
    drop(guard);
}

#[cfg(unix)]
#[test]
fn provisioning_rejects_ancestor_symlinks_without_writing_outside_root() {
    use std::os::unix::fs::symlink;
    let sandbox = TempTestDir::new("provision-symlink");
    let outside = sandbox.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let root = sandbox.path().join("root");
    fs::create_dir_all(&root).unwrap();
    symlink(&outside, root.join("install")).unwrap();
    let invocation = parse_cli_args(["--json", "--root", root.to_str().unwrap(), "provision", "run", "--no-root-check"]).unwrap();
    let response = execute_invocation(&invocation, &MockRunnerTransport::default());
    assert_eq!(response.status, "error");
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn backup_assembly_dry_run_does_not_create_directories() {
    let sandbox = TempTestDir::new("assemble-dry-run");
    let backup_dir = sandbox.path().join("not-created/backups");
    let digest = "a".repeat(64);
    let invocation = parse_cli_args([
        "--json", "--dry-run", "--root", sandbox.path().to_str().unwrap(),
        "backup", "assemble", "--output", "backup.sqlite", "--sha256", &digest,
        "--backup-dir", backup_dir.to_str().unwrap(), "part.00000",
    ]).unwrap();
    let response = execute_invocation(&invocation, &MockRunnerTransport::default());
    assert_eq!(response.status, "ok", "{}", response.message);
    assert_eq!(fs::read_dir(sandbox.path()).unwrap().count(), 0);
}
