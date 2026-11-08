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

#[test]
fn direct_cli_requires_matching_durable_terminal_not_progress_or_eof() {
    let request = build_package_runner_request("remove", "syncthing", None).unwrap();
    let identity = uuid::Uuid::new_v4().to_string();
    let admitted = format!("{}{}\n", af_runner::package_lifecycle::JOB_MARKER,
        serde_json::json!({"job_id":identity,"package_id":"syncthing","action":"remove"}));
    let terminal = af_runner::package_lifecycle::LifecycleReceipt {
        job_id: identity.clone(), package_id: "syncthing".into(), action: "remove".into(),
        status: "completed".into(), started_at: "2026-11-06T00:00:00Z".into(),
        finished_at: "2026-11-06T00:01:00Z".into(), app_port: 0,
    };
    let receipt_line = |receipt: &af_runner::package_lifecycle::LifecycleReceipt| {
        format!("{}{}\n", af_runner::package_lifecycle::RECEIPT_MARKER, serde_json::to_string(receipt).unwrap())
    };
    let mut progress_only = PackageStreamAccumulator::new();
    progress_only.push_chunk(format!("{admitted}[PROGRESS:100] Installer finished\n").as_bytes(), |_| {});
    assert!(matches!(progress_only.finish_verified(&request, |_| {}), Err(CliError::RunnerIpc { message, .. }) if message.contains("unconfirmed")));
    let mut success = PackageStreamAccumulator::new();
    success.push_chunk(format!("{admitted}[PROGRESS:100] Script finished\n{}", receipt_line(&terminal)).as_bytes(), |_| {});
    assert_eq!(success.finish_verified(&request, |_| {}).unwrap().lifecycle.unwrap(), terminal);
    let mut failed_terminal = terminal.clone();
    failed_terminal.status = "failed".into();
    let mut failed = PackageStreamAccumulator::new();
    failed.push_chunk(format!("{admitted}{}", receipt_line(&failed_terminal)).as_bytes(), |_| {});
    assert!(matches!(failed.finish_verified(&request, |_| {}), Err(CliError::Execution(message)) if message.contains(&identity)));
    let mut wrong_identity = terminal.clone();
    wrong_identity.job_id = uuid::Uuid::new_v4().to_string();
    let mut wrong = PackageStreamAccumulator::new();
    wrong.push_chunk(format!("{admitted}{}", receipt_line(&wrong_identity)).as_bytes(), |_| {});
    assert!(matches!(wrong.finish_verified(&request, |_| {}), Err(CliError::RunnerIpc { .. })));
}

#[test]
fn direct_cli_purge_is_explicit_and_ordinary_removal_retains_data() {
    for (args, purge) in [(vec!["remove", "syncthing"], false),
        (vec!["package", "remove", "syncthing", "--purge"], true)] {
        let invocation = parse_cli_args(args.into_iter().map(String::from).collect::<Vec<_>>()).unwrap();
        assert!(matches!(invocation.command, AfCommand::Package(PackageCommand::Remove { purge: actual, .. }) if actual == purge));
    }
}

#[cfg(unix)]
#[test]
fn actual_unix_transport_rejects_eof_after_script_success_without_durable_receipt() {
    use std::io::{Read, Write};
    let dir_name = format!("s-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let tmpdir_base = std::env::var_os("TMPDIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let candidate_root = tmpdir_base.join(&dir_name);
    let root = TempTestDir {
        path: if candidate_root.join("runner.sock").as_os_str().len() < 95 {
            candidate_root
        } else {
            PathBuf::from("/tmp").join(dir_name)
        },
    };
    fs::create_dir_all(root.path()).unwrap();
    let socket = root.path().join("runner.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let mut request = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&chunk[..count]);
            if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..end]);
                let length = headers.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
                }).unwrap();
                if request.len() >= end + 4 + length { break; }
            }
        }
        let body = "[PROGRESS:100] Installer script succeeded\n";
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
    });
    let client = UnixSocketRunnerClient::new(socket);
    let request = build_package_runner_request("remove", "syncthing", None).unwrap();
    assert!(matches!(client.execute_package(&request), Err(CliError::RunnerIpc { message, .. }) if message.contains("unconfirmed")));
    server.join().unwrap();
}

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

    // 2. Legacy `af install sonarr radarr` and `af reinstall sonarr --port 18989`
    let inv = parse_cli_args(["install", "sonarr", "radarr"]).unwrap();
    assert_eq!(
        inv.command,
        AfCommand::Package(PackageCommand::Install {
            packages: vec!["sonarr".to_string(), "radarr".to_string()],
            port: None,
        })
    );

    let reinv = parse_cli_args(["reinstall", "sonarr", "--port", "18989"]).unwrap();
    assert_eq!(
        reinv.command,
        AfCommand::Package(PackageCommand::Reinstall {
            packages: vec!["sonarr".to_string()],
            port: Some(18989),
        })
    );

    let pkg_reinv = parse_cli_args(["package", "reinstall", "radarr", "sonarr"]).unwrap();
    assert_eq!(
        pkg_reinv.command,
        AfCommand::Package(PackageCommand::Reinstall {
            packages: vec!["radarr".to_string(), "sonarr".to_string()],
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

    // 1b. Reinstall `radarr` and `sonarr` even when `/install/.radarr.lock` and `/etc/Swizzin/.sonarr.lock` exist
    let swizzin_dir = tmp.path().join("etc/Swizzin");
    fs::create_dir_all(&swizzin_dir).unwrap();
    fs::write(swizzin_dir.join(".sonarr.lock"), b"PORT=18989\n").unwrap();

    // Verify `af install sonarr` skips when `/etc/Swizzin/.sonarr.lock` exists
    let skip_inv = parse_cli_args(["--json", "--root", &root_str, "install", "sonarr"]).unwrap();
    let skip_env = execute_invocation(&skip_inv, &transport);
    assert_eq!(skip_env.status, "ok");
    assert_eq!(transport.package_calls.lock().unwrap().len(), 1);

    // Verify `af reinstall radarr sonarr` executes both in-place with action="reinstall" and delete_data=false
    let reinv = parse_cli_args(["--json", "--root", &root_str, "reinstall", "radarr", "sonarr"]).unwrap();
    let reenv = execute_invocation(&reinv, &transport);
    assert_eq!(reenv.status, "ok");
    assert_eq!(reenv.exit_code, 0);
    assert_eq!(reenv.action, "reinstall");
    let pkg_calls = transport.package_calls.lock().unwrap();
    assert_eq!(pkg_calls.len(), 3);
    assert_eq!(pkg_calls[1].package_id, "radarr");
    assert_eq!(pkg_calls[1].action, "reinstall");
    assert_eq!(pkg_calls[1].script_name, "installpackage-radarr");
    assert!(!pkg_calls[1].delete_data);
    assert_eq!(pkg_calls[2].package_id, "sonarr");
    assert_eq!(pkg_calls[2].action, "reinstall");
    assert_eq!(pkg_calls[2].script_name, "installpackage-sonarr");
    assert_eq!(pkg_calls[2].app_port, 18989);
    assert!(!pkg_calls[2].delete_data);
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

    // 5. Verify destructive `af backup restore` without confirmation fails closed with UnsupportedOperation (exit code 6)
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

    // 6. Verify confirmed `af backup restore --confirm-destructive-restore` succeeds into isolated staging target
    let confirmed_restore_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "backup",
        "restore",
        archive_name,
        "--target-root",
        &stage_str,
        "--confirm-destructive-restore",
        "--allow-overwrite",
    ])
    .unwrap();
    let confirmed_env = execute_invocation(&confirmed_restore_inv, &transport);
    assert_eq!(
        confirmed_env.status, "ok",
        "confirmed restore failed: {}",
        confirmed_env.message
    );
    assert!(stage_target
        .join("var/lib/aetherflow/aetherflow.sqlite")
        .is_file());
    assert!(stage_target.join("etc/AetherFlow/settings.conf").is_file());
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

#[test]
fn maintenance_cli_commands_and_aliases_work_correctly() {
    let tmp = TempTestDir::new("maint-cli");
    let root = tmp.path().join("rootfs");
    fs::create_dir_all(&root).unwrap();
    let root_str = root.to_string_lossy().to_string();
    let transport = MockRunnerTransport::default();

    // 1. Test `af maintenance tune` (and shorthand `af tune`)
    // Dry-run
    let tune_dry_inv = parse_cli_args(["--json", "--root", &root_str, "maintenance", "tune", "--dry-run"]).unwrap();
    let resp = execute_invocation(&tune_dry_inv, &transport);
    assert_eq!(resp.status, "ok");
    assert!(resp.message.contains("[DRY-RUN]"));
    assert!(!root.join("etc/sysctl.d/99-aetherflow-tune.conf").exists());

    // Live apply via shorthand `af tune`
    let tune_live_inv = parse_cli_args(["--json", "--root", &root_str, "tune"]).unwrap();
    let resp = execute_invocation(&tune_live_inv, &transport);
    assert_eq!(resp.status, "ok");
    let conf_path = root.join("etc/sysctl.d/99-aetherflow-tune.conf");
    assert!(conf_path.is_file());
    let content = fs::read_to_string(&conf_path).unwrap();
    assert!(content.contains("net.ipv4.tcp_congestion_control = bbr"));
    assert!(content.contains("net.core.default_qdisc = fq"));

    // 2. Test `af maintenance sentinel` (and shorthand `af sentinel`)
    let auth_log = root.join("var/log/auth.log");
    fs::create_dir_all(auth_log.parent().unwrap()).unwrap();
    fs::write(
        &auth_log,
        b"Oct 25 10:00:00 srv sshd[123]: Failed password for root from 192.168.1.100 port 22 ssh2\n\
          Oct 25 10:00:01 srv sshd[124]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2\n\
          Oct 25 10:00:02 srv sshd[125]: Failed password for test from 10.0.0.1 port 22 ssh2\n",
    )
    .unwrap();
    let auth_str = auth_log.to_string_lossy().to_string();

    let sent_inv = parse_cli_args([
        "--json",
        "maintenance",
        "sentinel",
        "--log-path",
        &auth_str,
        "--threshold",
        "2",
    ])
    .unwrap();
    let resp = execute_invocation(&sent_inv, &transport);
    assert_eq!(resp.status, "ok");
    let data = resp.data.expect("sentinel report data");
    assert_eq!(data["failed_event_count"], 3);
    assert_eq!(data["offending_ips"].as_array().unwrap().len(), 1);
    assert_eq!(data["offending_ips"][0], "192.168.1.100");

    // Shorthand `af sentinel <path> --threshold 2`
    let sent_short_inv = parse_cli_args([
        "--json",
        "sentinel",
        &auth_str,
        "--threshold",
        "2",
    ])
    .unwrap();
    let resp = execute_invocation(&sent_short_inv, &transport);
    assert_eq!(resp.status, "ok");

    // 3. Test `af maintenance clean-logs` (and shorthand `af clean-logs`)
    let big_log = root.join("var/log/aetherflow-test.log");
    let small_log = root.join("var/log/normal.log");
    fs::write(&big_log, vec![b'A'; 2000]).unwrap();
    fs::write(&small_log, vec![b'B'; 100]).unwrap();

    // Dry-run clean
    let clean_dry_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "maintenance",
        "clean-logs",
        "--max-size",
        "1KB",
        "--dry-run",
    ])
    .unwrap();
    let resp = execute_invocation(&clean_dry_inv, &transport);
    assert_eq!(resp.status, "ok");
    assert_eq!(fs::metadata(&big_log).unwrap().len(), 2000);

    // Live clean via shorthand `af clean-logs`
    let clean_live_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "clean-logs",
        "--max-size",
        "1KB",
    ])
    .unwrap();
    let resp = execute_invocation(&clean_live_inv, &transport);
    assert_eq!(resp.status, "ok");
    assert_eq!(fs::metadata(&big_log).unwrap().len(), 0);
    assert_eq!(fs::metadata(&small_log).unwrap().len(), 100);

    // 4. Test `af maintenance showspace` (and shorthand `af showspace`)
    let alice_home = root.join("home/alice");
    let bob_home = root.join("home/bob");
    fs::create_dir_all(&alice_home).unwrap();
    fs::create_dir_all(&bob_home).unwrap();
    fs::write(alice_home.join("data.bin"), vec![0u8; 1024]).unwrap();
    fs::write(bob_home.join("data.bin"), vec![0u8; 2048]).unwrap();

    let show_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "maintenance",
        "showspace",
    ])
    .unwrap();
    let resp = execute_invocation(&show_inv, &transport);
    assert_eq!(resp.status, "ok");
    let entries = resp.data.expect("showspace entries");
    assert!(entries.as_array().unwrap().len() >= 2);

    // Shorthand with `--user alice`
    let show_user_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "showspace",
        "--user",
        "alice",
    ])
    .unwrap();
    let resp = execute_invocation(&show_user_inv, &transport);
    assert_eq!(resp.status, "ok");
    let user_entries = resp.data.expect("user entries");
    assert_eq!(user_entries.as_array().unwrap().len(), 1);
    assert_eq!(user_entries[0]["user"], "alice");

    // 5. Test `af maintenance ownership`
    let owner_inv = parse_cli_args(["--json", "maintenance", "ownership"]).unwrap();
    let resp = execute_invocation(&owner_inv, &transport);
    assert_eq!(resp.status, "ok");
    let items = resp.data.expect("ownership items");
    let arr = items.as_array().unwrap();
    assert!(arr.iter().any(|e| e["script_path"] == "packages/system/af-tune"));
    assert!(arr.iter().any(|e| e["script_path"] == "packages/system/af-sentinel.py"));
    assert!(arr.iter().any(|e| e["script_path"] == "packages/system/clean_log"));
    assert!(arr.iter().any(|e| e["script_path"] == "packages/system/showspace"));
}

#[test]
fn newly_promoted_rust_native_provisioning_steps_execute_safely_in_isolated_root() {
    let tmp = TempTestDir::new("promoted-provision");
    let root = tmp.path().join("rootfs");
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::write(
        root.join("etc/os-release"),
        "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n",
    )
    .unwrap();

    // Create a legacy sudoers file to verify apachesudo purges it
    let sudoers_d = root.join("etc/sudoers.d");
    fs::create_dir_all(&sudoers_d).unwrap();
    fs::write(sudoers_d.join("aether-legacy"), b"www-data ALL=(ALL) NOPASSWD: ALL\n").unwrap();
    assert!(sudoers_d.join("aether-legacy").exists());

    let root_str = root.to_string_lossy().to_string();
    let transport = MockRunnerTransport::default();

    // 1. Run the promoted Rust-native steps explicitly
    let steps_to_run = [
        "bashrc",
        "hostname",
        "locale",
        "skel",
        "apachesudo",
        "build_modern",
        "bbr",
        "perms",
    ];

    for step in &steps_to_run {
        let inv = parse_cli_args([
            "--json",
            "--root",
            &root_str,
            "provision",
            "run",
            step,
            "--no-root-check",
        ])
        .unwrap();
        let env = execute_invocation(&inv, &transport);
        assert_eq!(
            env.status, "ok",
            "provision step '{}' failed: {}",
            step, env.message
        );
        let data = env.data.unwrap();
        assert_eq!(
            data["records"][0]["status"], "completed",
            "step '{}' record status should be completed",
            step
        );
    }

    // 2. Verify all steps are recorded in `.aetherflow.state`
    let state_raw = fs::read_to_string(root.join("install/.aetherflow.state")).unwrap();
    assert!(state_raw.starts_with("# STATE_VERSION=2\n"));
    for step in &steps_to_run {
        assert!(
            state_raw.contains(&format!("{}\n", step)),
            "state file missing step '{}'",
            step
        );
    }

    // 3. Verify .aetherflow.conf has HOSTNAME_CONFIGURED and SUDOERS_HARDENED
    let conf_raw = fs::read_to_string(root.join("install/.aetherflow.conf")).unwrap();
    assert!(conf_raw.contains("HOSTNAME_CONFIGURED=true"));
    assert!(conf_raw.contains("SUDOERS_HARDENED=true"));

    // 4. Verify bashrc
    let bashrc_path = root.join("root/.bashrc");
    assert!(bashrc_path.is_file(), "root/.bashrc must exist");
    let bashrc_content = fs::read_to_string(&bashrc_path).unwrap();
    assert!(bashrc_content.contains("/usr/local/bin"));

    // 5. Verify hostname
    let etc_hostname = root.join("etc/hostname");
    assert!(etc_hostname.is_file(), "etc/hostname must exist");
    assert_eq!(fs::read_to_string(&etc_hostname).unwrap().trim(), "localhost");

    // 6. Verify locale
    let locale_path = root.join("etc/default/locale");
    assert!(locale_path.is_file(), "etc/default/locale must exist");
    let locale_content = fs::read_to_string(&locale_path).unwrap();
    assert!(locale_content.contains("LANG=en_US.UTF-8"));
    assert!(locale_content.contains("LC_ALL=en_US.UTF-8"));

    // 7. Verify skel
    assert!(root.join("etc/skel/Media").is_dir());
    assert!(root.join("etc/skel/torrents/rtorrent").is_dir());
    assert!(root.join("etc/skel/torrents/deluge").is_dir());
    assert!(root.join("etc/skel/torrents/qbittorrent").is_dir());

    // 8. Verify apachesudo purged legacy sudoers file
    assert!(!sudoers_d.join("aether-legacy").exists(), "legacy sudoers file must be purged");

    // 9. Verify build_modern created /etc/aetherflow/aetherflow.env with 0600 mode
    let env_path = root.join("etc/aetherflow/aetherflow.env");
    assert!(env_path.is_file(), "aetherflow.env must exist");
    let env_content = fs::read_to_string(&env_path).unwrap();
    assert!(env_content.contains("AES_MASTER_KEY="));
    assert!(env_content.contains("JWT_SECRET="));
    assert!(env_content.contains("AF_DB_PATH=/var/lib/aetherflow/aetherflow.sqlite"));
    assert!(env_content.contains("AETHERFLOW_RUNNER_SOCK=/run/aetherflow/runner.sock"));

    // 10. Verify bbr network tuning config exists
    let sysctl_path = root.join("etc/sysctl.d/99-aetherflow-tune.conf");
    assert!(sysctl_path.is_file(), "99-aetherflow-tune.conf must exist");
    let sysctl_content = fs::read_to_string(&sysctl_path).unwrap();
    assert!(sysctl_content.contains("net.core.default_qdisc = fq"));
    assert!(sysctl_content.contains("net.ipv4.tcp_congestion_control = bbr"));

    // 11. Verify permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bashrc_mode = fs::metadata(&bashrc_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(bashrc_mode, 0o640, "root/.bashrc must have 0640 permissions");

        let locale_mode = fs::metadata(&locale_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(locale_mode, 0o644, "etc/default/locale must have 0644 permissions");

        let env_mode = fs::metadata(&env_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(env_mode, 0o600, "aetherflow.env must have 0600 permissions");

        let var_lib_mode = fs::metadata(root.join("var/lib/aetherflow")).unwrap().permissions().mode() & 0o777;
        assert_eq!(var_lib_mode, 0o700, "var/lib/aetherflow must have 0700 permissions");

        let skel_media_mode = fs::metadata(root.join("etc/skel/Media")).unwrap().permissions().mode() & 0o777;
        assert_eq!(skel_media_mode, 0o750, "etc/skel/Media must have 0750 permissions");
    }

    // 12. Verify re-running build_modern preserves existing .env content
    let original_env = fs::read_to_string(&env_path).unwrap();
    let rerun_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "provision",
        "repair",
        "build_modern",
        "--no-root-check",
    ])
    .unwrap();
    let rerun_env = execute_invocation(&rerun_inv, &transport);
    assert_eq!(rerun_env.status, "ok");
    let preserved_env = fs::read_to_string(&env_path).unwrap();
    assert_eq!(original_env, preserved_env, "existing aetherflow.env must be preserved across runs");
}

#[test]
fn backup_restore_failures_have_nonzero_execution_exit_codes() {
    let failures = [
        af_host::HostBackupError::ServiceQuiescenceFailed {
            unit: "fixture-writer.service".to_string(),
            phase: "stop".to_string(),
            reason: "fixture stop failure".to_string(),
        },
        af_host::HostBackupError::RestoreRolledBack {
            reason: "fixture restore failure".to_string(),
            rollback_summary: "original files recovered".to_string(),
        },
        af_host::HostBackupError::RestoreRollbackFailed {
            reason: "fixture restore failure".to_string(),
            rollback_errors: "fixture rollback failure".to_string(),
            recovery_dir: PathBuf::from("/fixture/recovery"),
            failure_journal_path: PathBuf::from("/fixture/recovery/journal.json"),
            services_left_stopped: true,
        },
    ];
    for failure in failures {
        let error = CliError::Backup(failure);
        assert_eq!(error.exit_code(), CliExitCode::ExecutionFailure);
        let envelope = error.to_error_envelope("backup", "restore");
        assert_eq!(envelope.status, "error");
        assert_ne!(envelope.exit_code, 0);
    }
}

#[test]
fn release_local_deploy_and_rollback_write_status_receipts_and_honor_root_conf() {
    let tmp = TempTestDir::new("release-status-receipt");
    let root_str = tmp.path().to_string_lossy().to_string();
    let transport = MockRunnerTransport::default();

    let rel_v1 = tmp.path().join("opt/AetherFlow/releases/v4.0.0");
    let rel_v2 = tmp.path().join("opt/AetherFlow/releases/v4.0.1");
    fs::create_dir_all(&rel_v1).unwrap();
    fs::create_dir_all(&rel_v2).unwrap();
    let etc_dir = tmp.path().join("etc/aetherflow");
    fs::create_dir_all(&etc_dir).unwrap();
    fs::write(
        etc_dir.join("release-manager.conf"),
        "RELEASE_CHANNEL=\"nightly\"\nMAX_RELEASES=4\n",
    )
    .unwrap();

    // 1. `af --root <root> release status` loads `<root>/etc/aetherflow/release-manager.conf`
    let status_inv = parse_cli_args(["--json", "--root", &root_str, "release", "status"]).unwrap();
    let status_env = execute_invocation(&status_inv, &transport);
    assert_eq!(status_env.status, "ok", "{}", status_env.message);
    let data = status_env.data.unwrap();
    assert_eq!(data["configured_channel"], "nightly");

    // 2. Local rollback fails when no `previous` slot exists and writes a `failed` receipt
    let fail_receipt_path = tmp.path().join("var/lib/aetherflow/.self-update-jobs/job-fail.json");
    let fail_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "release",
        "rollback",
        "--local",
        "--job-status-file",
        fail_receipt_path.to_str().unwrap(),
        "--job-unit",
        "aetherflow-self-update-rollback-nightly-12345678.service",
    ])
    .unwrap();
    let fail_env = execute_invocation(&fail_inv, &transport);
    assert_eq!(fail_env.status, "error");
    let fail_receipt: SelfUpdateJobStatus =
        serde_json::from_str(&fs::read_to_string(&fail_receipt_path).unwrap()).unwrap();
    assert_eq!(fail_receipt.status, "failed");
    assert!(fail_receipt.completed);
    assert!(!fail_receipt.success);
    assert_ne!(fail_receipt.exit_code, Some(0));
    assert!(!fail_receipt.error.is_empty());
    let retry_closed_receipt = execute_invocation(&fail_inv, &transport);
    assert_eq!(retry_closed_receipt.status, "error");
    assert!(retry_closed_receipt
        .message
        .contains("admission was closed"));

    // 3. Dry-run local rollback with `.previous_release` in dry_run_root succeeds and writes a `succeeded` receipt
    #[cfg(unix)]
    {
        let dry_releases = tmp.path().join("tmp/aetherflow-dryrun/releases");
        fs::create_dir_all(&dry_releases).unwrap();
        fs::write(
            dry_releases.join(".previous_release"),
            format!("{}\n", rel_v1.display()),
        )
        .unwrap();
        let ok_receipt_path = tmp.path().join("var/lib/aetherflow/.self-update-jobs/job-ok.json");
        let ok_inv = parse_cli_args([
            "--json",
            "--dry-run",
            "--root",
            &root_str,
            "release",
            "rollback",
            "--local",
            "--job-status-file",
            ok_receipt_path.to_str().unwrap(),
            "--job-unit",
            "aetherflow-self-update-rollback-nightly-87654321.service",
        ])
        .unwrap();
        let ok_env = execute_invocation(&ok_inv, &transport);
        assert_eq!(ok_env.status, "ok", "{}", ok_env.message);
        let ok_receipt: SelfUpdateJobStatus =
            serde_json::from_str(&fs::read_to_string(&ok_receipt_path).unwrap()).unwrap();
        assert_eq!(ok_receipt.status, "succeeded");
        assert!(ok_receipt.completed);
        assert!(ok_receipt.success);
        assert_eq!(ok_receipt.exit_code, Some(0));
    }
}

#[test]
fn standalone_cleanup_reconciles_dead_api_owner_without_api_startup() {
    let root = TempTestDir::new("standalone-owner-recovery");
    let cfg = af_release::ReleaseConfig::for_root(root.path());
    let database = af_release::config::try_resolve_db_path(&cfg, None)
        .unwrap()
        .path;
    fs::create_dir_all(database.parent().unwrap()).unwrap();
    let conn = Connection::open(&database).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
    af_release::lifecycle::initialize_schema(&conn).unwrap();
    let owner = af_release::lifecycle::OwnerLease::create(&database).unwrap();
    conn.execute(
        "INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id)
        VALUES ('fixture','original-job','update','updating','now',?1)",
        [&owner.id],
    )
    .unwrap();
    let invocation = parse_cli_args([
        "--json",
        "--root",
        root.path().to_str().unwrap(),
        "release",
        "cleanup",
    ])
    .unwrap();
    let transport = MockRunnerTransport::default();
    let blocked = execute_invocation(&invocation, &transport);
    assert_eq!(blocked.status, "error");
    assert!(blocked
        .message
        .contains("lifecycle orchestration is active"));
    drop(owner);
    let recovered = execute_invocation(&invocation, &transport);
    assert_eq!(recovered.status, "ok", "{}", recovered.message);
    let status: String = conn
        .query_row("SELECT status FROM package_lifecycle_jobs", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(status, "interrupted");
}

#[test]
fn runner_dispatched_release_and_update_commands_reject_local_root_and_config_overrides() {
    let sandbox = TempTestDir::new("runner-release-override-reject");
    let root_str = sandbox.path().to_string_lossy().to_string();
    let conf_path = sandbox.path().join("custom.conf");
    fs::write(&conf_path, "RELEASE_CHANNEL=\"nightly\"\n").unwrap();
    let conf_str = conf_path.to_string_lossy().to_string();
    let status_file = sandbox.path().join("job.json");
    let status_str = status_file.to_string_lossy().to_string();

    let rejected_arg_sets: Vec<Vec<&str>> = vec![
        vec!["--json", "--root", &root_str, "release", "deploy"],
        vec!["--json", "--root", &root_str, "release", "rollback"],
        vec!["--json", "release", "deploy", "--config", &conf_str],
        vec!["--json", "release", "deploy", "--keep-releases", "3"],
        vec!["--json", "release", "deploy", "--job-status-file", &status_str],
        vec![
            "--json",
            "release",
            "deploy",
            "--job-unit",
            "aetherflow-self-update-deploy-stable-12345678.service",
        ],
        vec!["--json", "--root", &root_str, "update"],
        vec!["--json", "--root", &root_str, "upgrade"],
    ];

    for raw_args in rejected_arg_sets {
        let transport = MockRunnerTransport::default();
        let invocation = parse_cli_args(raw_args.clone()).unwrap();
        let envelope = execute_invocation(&invocation, &transport);
        assert_eq!(
            envelope.status, "error",
            "expected error for {:?}",
            raw_args
        );
        assert_eq!(
            envelope.exit_code,
            CliExitCode::UsageOrValidation.as_i32(),
            "expected validation exit code for {:?}: {}",
            raw_args,
            envelope.message
        );
        assert!(
            transport.self_update_calls.lock().unwrap().is_empty(),
            "runner socket must not be invoked when local overrides are rejected: {:?}",
            raw_args
        );
    }
}

#[test]
fn isolated_root_backup_cli_rejects_out_of_root_backup_dir_and_contains_staging_sqlite_override() {
    let sandbox = TempTestDir::new("backup-cli-containment");
    let root_dir = sandbox.path().join("iso-root");
    let outside_dir = sandbox.path().join("outside-backups");
    fs::create_dir_all(&root_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    let bad_inv = parse_cli_args([
        "--json",
        "--root",
        root_dir.to_str().unwrap(),
        "backup",
        "create",
        "--backup-dir",
        outside_dir.to_str().unwrap(),
    ])
    .unwrap();
    let bad_env = execute_invocation(&bad_inv, &MockRunnerTransport::default());
    assert_eq!(bad_env.status, "error");
    assert_eq!(bad_env.exit_code, CliExitCode::UsageOrValidation.as_i32());
    assert!(bad_env.message.contains("outside active isolated root"));

    let db_path = root_dir.join("srv/custom-af/aetherflow.sqlite");
    let backup_dir = root_dir.join("var/lib/aetherflow/backups");
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    fs::create_dir_all(&backup_dir).unwrap();
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA user_version = 7;
         CREATE TABLE sample (id INTEGER PRIMARY KEY, label TEXT NOT NULL);
         INSERT INTO sample (id, label) VALUES (1, 'contained');",
    )
    .unwrap();
    drop(conn);

    let mut backup_cfg = af_host::HostBackupConfig::for_isolated_root(&root_dir, "v4.0.0");
    backup_cfg.backup_dir = backup_dir.clone();
    backup_cfg.sqlite_db_path = Some(db_path.clone());
    let receipt = af_host::create_sqlite_snapshot_backup(&backup_cfg, Some("20261103_110000")).unwrap();
    let backup_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let stage_target = root_dir.join("var/lib/aetherflow/restore-staging/stage-one");
    let preflight_inv = parse_cli_args([
        "--json",
        "--root",
        root_dir.to_str().unwrap(),
        "backup",
        "restore-preflight",
        &backup_filename,
        "--backup-dir",
        backup_dir.to_str().unwrap(),
        "--target-root",
        stage_target.to_str().unwrap(),
    ])
    .unwrap();
    let preflight_env = execute_invocation(&preflight_inv, &MockRunnerTransport::default());
    assert_eq!(preflight_env.status, "ok", "{}", preflight_env.message);
    let plan_items = preflight_env.data.unwrap()["items"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(plan_items.len(), 1);
    let destination_str = plan_items[0]["destination_path"].as_str().unwrap();
    assert!(
        Path::new(destination_str).starts_with(&stage_target),
        "staging restore destination '{}' escaped staging target '{}'",
        destination_str,
        stage_target.display()
    );

    let recover_inv = parse_cli_args([
        "--json",
        "--root",
        root_dir.to_str().unwrap(),
        "backup",
        "recover",
        "--backup-dir",
        backup_dir.to_str().unwrap(),
    ])
    .unwrap();
    let recover_env = execute_invocation(&recover_inv, &MockRunnerTransport::default());
    assert_eq!(recover_env.status, "ok", "{}", recover_env.message);
}
