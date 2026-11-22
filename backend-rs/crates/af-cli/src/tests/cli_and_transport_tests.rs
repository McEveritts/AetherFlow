use super::{MockRunnerTransport, TempTestDir};
use crate::*;
use af_release::ReleaseChannel;
use std::fs;

#[test]
fn direct_cli_requires_matching_durable_terminal_not_progress_or_eof() {
    let request = build_package_runner_request("remove", "syncthing", None).unwrap();
    let identity = uuid::Uuid::new_v4().to_string();
    let admitted = format!(
        "{}{}\n",
        af_runner::package_lifecycle::JOB_MARKER,
        serde_json::json!({"job_id":identity,"package_id":"syncthing","action":"remove"})
    );
    let terminal = af_runner::package_lifecycle::LifecycleReceipt {
        job_id: identity.clone(),
        package_id: "syncthing".into(),
        action: "remove".into(),
        status: "completed".into(),
        started_at: "2026-11-06T00:00:00Z".into(),
        finished_at: "2026-11-06T00:01:00Z".into(),
        app_port: 0,
    };
    let receipt_line = |receipt: &af_runner::package_lifecycle::LifecycleReceipt| {
        format!(
            "{}{}\n",
            af_runner::package_lifecycle::RECEIPT_MARKER,
            serde_json::to_string(receipt).unwrap()
        )
    };
    let mut progress_only = PackageStreamAccumulator::new();
    progress_only.push_chunk(
        format!("{admitted}[PROGRESS:100] Installer finished\n").as_bytes(),
        |_| {},
    );
    assert!(
        matches!(progress_only.finish_verified(&request, |_| {}), Err(CliError::RunnerIpc { message, .. }) if message.contains("unconfirmed"))
    );
    let mut success = PackageStreamAccumulator::new();
    success.push_chunk(
        format!(
            "{admitted}[PROGRESS:100] Script finished\n{}",
            receipt_line(&terminal)
        )
        .as_bytes(),
        |_| {},
    );
    assert_eq!(
        success
            .finish_verified(&request, |_| {})
            .unwrap()
            .lifecycle
            .unwrap(),
        terminal
    );
    let mut failed_terminal = terminal.clone();
    failed_terminal.status = "failed".into();
    let mut failed = PackageStreamAccumulator::new();
    failed.push_chunk(
        format!("{admitted}{}", receipt_line(&failed_terminal)).as_bytes(),
        |_| {},
    );
    assert!(
        matches!(failed.finish_verified(&request, |_| {}), Err(CliError::Execution(message)) if message.contains(&identity))
    );
    let mut wrong_identity = terminal.clone();
    wrong_identity.job_id = uuid::Uuid::new_v4().to_string();
    let mut wrong = PackageStreamAccumulator::new();
    wrong.push_chunk(
        format!("{admitted}{}", receipt_line(&wrong_identity)).as_bytes(),
        |_| {},
    );
    assert!(matches!(
        wrong.finish_verified(&request, |_| {}),
        Err(CliError::RunnerIpc { .. })
    ));
}

#[test]
fn direct_cli_purge_is_explicit_and_ordinary_removal_retains_data() {
    for (args, purge) in [
        (vec!["remove", "syncthing"], false),
        (vec!["package", "remove", "syncthing", "--purge"], true),
    ] {
        let invocation =
            parse_cli_args(args.into_iter().map(String::from).collect::<Vec<_>>()).unwrap();
        assert!(
            matches!(invocation.command, AfCommand::Package(PackageCommand::Remove { purge: actual, .. }) if actual == purge)
        );
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
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&chunk[..count]);
            if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                if request.len() >= end + 4 + length {
                    break;
                }
            }
        }
        let body = "[PROGRESS:100] Installer script succeeded\n";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    });
    let client = UnixSocketRunnerClient::new(socket);
    let request = build_package_runner_request("remove", "syncthing", None).unwrap();
    assert!(
        matches!(client.execute_package(&request), Err(CliError::RunnerIpc { message, .. }) if message.contains("unconfirmed"))
    );
    server.join().unwrap();
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
            target_version: None,
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
    acc.push_chunk(b"ESS:25] Step one\nPlain log ", |ev| {
        live_events.push(ev.clone())
    });
    assert_eq!(live_events.len(), 1);
    assert_eq!(live_events[0].progress_percent, Some(25));
    acc.push_chunk(b"line\n[PROGRESS:100] Done", |ev| {
        live_events.push(ev.clone())
    });
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
    let inv =
        parse_cli_args(["--json", "--root", &root_str, "install", "sonarr", "radarr"]).unwrap();
    let env = execute_invocation(&inv, &transport);
    assert_eq!(env.status, "ok");
    assert_eq!(env.exit_code, 0);
    let pkg_calls = transport.package_calls.lock().unwrap();
    assert_eq!(pkg_calls.len(), 1);
    assert_eq!(pkg_calls[0].package_id, "sonarr");
    assert_eq!(pkg_calls[0].script_name, "installpackage-sonarr");
    drop(pkg_calls);

    // 1b. Legacy `/etc/Swizzin/.sonarr.lock` is upgrade input, not a canonical install receipt.
    let swizzin_dir = tmp.path().join("etc/Swizzin");
    fs::create_dir_all(&swizzin_dir).unwrap();
    fs::write(swizzin_dir.join(".sonarr.lock"), b"PORT=18989\n").unwrap();

    // `af info sonarr` and `af list --installed` agree with canonical services/API status (`installed: false`)
    // while surfacing the legacy receipt as upgrade input.
    let info_inv =
        parse_cli_args(["--json", "--root", &root_str, "package", "info", "sonarr"]).unwrap();
    let info_env = execute_invocation(&info_inv, &transport);
    assert_eq!(info_env.status, "ok");
    let info_data = info_env.data.as_ref().unwrap();
    assert_eq!(info_data["installed"], false);
    assert_eq!(info_data["legacy_receipt_present"], true);
    assert_eq!(
        info_data["lock_path"],
        install_dir.join(".sonarr.lock").to_string_lossy().as_ref()
    );
    assert_eq!(
        info_data["legacy_lock_path"],
        swizzin_dir.join(".sonarr.lock").to_string_lossy().as_ref()
    );

    // `af install radarr` still skips canonical `/install/.radarr.lock`, whereas `af install sonarr`
    // upgrades the legacy `/etc/Swizzin/.sonarr.lock` in-place via `reinstall` preserving PORT=18989.
    let upgrade_inv =
        parse_cli_args(["--json", "--root", &root_str, "install", "radarr", "sonarr"]).unwrap();
    let upgrade_env = execute_invocation(&upgrade_inv, &transport);
    assert_eq!(upgrade_env.status, "ok");
    {
        let pkg_calls = transport.package_calls.lock().unwrap();
        assert_eq!(pkg_calls.len(), 2);
        assert_eq!(pkg_calls[1].package_id, "sonarr");
        assert_eq!(pkg_calls[1].action, "reinstall");
        assert_eq!(pkg_calls[1].script_name, "installpackage-sonarr");
        assert_eq!(pkg_calls[1].app_port, 18989);
        assert!(!pkg_calls[1].delete_data);
    }

    // Verify `af reinstall radarr sonarr` executes both in-place with action="reinstall" and delete_data=false
    let reinv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "reinstall",
        "radarr",
        "sonarr",
    ])
    .unwrap();
    let reenv = execute_invocation(&reinv, &transport);
    assert_eq!(reenv.status, "ok");
    assert_eq!(reenv.exit_code, 0);
    assert_eq!(reenv.action, "reinstall");
    let pkg_calls = transport.package_calls.lock().unwrap();
    assert_eq!(pkg_calls.len(), 4);
    assert_eq!(pkg_calls[2].package_id, "radarr");
    assert_eq!(pkg_calls[2].action, "reinstall");
    assert_eq!(pkg_calls[2].script_name, "installpackage-radarr");
    assert!(!pkg_calls[2].delete_data);
    assert_eq!(pkg_calls[3].package_id, "sonarr");
    assert_eq!(pkg_calls[3].action, "reinstall");
    assert_eq!(pkg_calls[3].script_name, "installpackage-sonarr");
    assert_eq!(pkg_calls[3].app_port, 18989);
    assert!(!pkg_calls[3].delete_data);
    drop(pkg_calls);

    // Verify `af remove sonarr` still dispatches removal for a legacy-only receipt so cleanup can run.
    let remove_inv = parse_cli_args(["--json", "--root", &root_str, "remove", "sonarr"]).unwrap();
    let remove_env = execute_invocation(&remove_inv, &transport);
    assert_eq!(remove_env.status, "ok");
    let pkg_calls = transport.package_calls.lock().unwrap();
    assert_eq!(pkg_calls.len(), 5);
    assert_eq!(pkg_calls[4].package_id, "sonarr");
    assert_eq!(pkg_calls[4].action, "remove");
    assert_eq!(pkg_calls[4].script_name, "removepackage-sonarr");
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

    let render_inv =
        parse_cli_args(["sandbox", "render", "sonarr", "--user", "mediauser"]).unwrap();
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
fn package_stream_accumulator_bounds_retained_logs_and_partial_lines() {
    let request = build_package_runner_request("install", "sonarr", None).unwrap();
    let mut accumulator = PackageStreamAccumulator::new();
    let chunk = vec![b'x'; MAX_PACKAGE_STREAM_LINE_CARRY_BYTES * 3];
    let mut largest_line = 0;
    accumulator.push_chunk(&chunk, |event| {
        largest_line = largest_line.max(event.raw_line.len())
    });
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

#[test]
fn help_update_documents_package_update_and_release_deploy() {
    let inv = parse_cli_args(["help", "update"]).unwrap();
    assert_eq!(
        inv.command,
        AfCommand::Help {
            topic: HelpTopic::Update
        }
    );
    let resp = execute_invocation(&inv, &MockRunnerTransport::default());
    assert_eq!(resp.status, "ok");
    assert!(resp
        .message
        .contains("af update <package> [--target-version <ver>]"));
    assert!(resp.message.contains("af release deploy"));
}

#[test]
fn hosts_cli_commands_validate_and_dispatch_to_runner() {
    let transport = MockRunnerTransport::default();

    // Dry-run `af hosts update`
    let dry_inv = parse_cli_args([
        "--json",
        "--dry-run",
        "hosts",
        "update",
        "127.0.0.1",
        "sonarr.aether.local",
    ])
    .unwrap();
    let dry_env = execute_invocation(&dry_inv, &transport);
    assert_eq!(dry_env.status, "ok", "{}", dry_env.message);
    assert!(dry_env.message.contains("[DRY-RUN]"));
    assert!(transport.hosts_calls.lock().unwrap().is_empty());

    // Live `af hosts update`, `remove`, and `reconcile`
    let upd_inv = parse_cli_args([
        "--json",
        "hosts",
        "update",
        "10.0.0.5",
        "radarr.aether.local",
        "sonarr.aether.local",
    ])
    .unwrap();
    let upd_env = execute_invocation(&upd_inv, &transport);
    assert_eq!(upd_env.status, "ok", "{}", upd_env.message);

    let rem_inv = parse_cli_args(["--json", "hosts", "remove", "radarr.aether.local"]).unwrap();
    let rem_env = execute_invocation(&rem_inv, &transport);
    assert_eq!(rem_env.status, "ok", "{}", rem_env.message);

    let rec_inv = parse_cli_args([
        "--json",
        "hosts",
        "reconcile",
        "127.0.0.1",
        "plex.aether.local",
    ])
    .unwrap();
    let rec_env = execute_invocation(&rec_inv, &transport);
    assert_eq!(rec_env.status, "ok", "{}", rec_env.message);

    let calls = transport.hosts_calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].action, "update");
    assert_eq!(calls[0].ip, "10.0.0.5");
    assert_eq!(
        calls[0].domains,
        vec![
            "radarr.aether.local".to_string(),
            "sonarr.aether.local".to_string()
        ]
    );
    assert_eq!(calls[1].action, "remove");
    assert_eq!(calls[1].domains, vec!["radarr.aether.local".to_string()]);
    assert_eq!(calls[2].action, "reconcile");
    assert_eq!(calls[2].ip, "127.0.0.1");

    // Validation rejections
    assert!(parse_cli_args(["hosts", "update", "not-an-ip", "app.aether.local"]).is_err());
    assert!(parse_cli_args(["hosts", "remove", "bad;domain"]).is_err());
}
