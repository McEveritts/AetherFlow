use super::{MockRunnerTransport, TempTestDir};
use crate::*;
use std::fs;

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
    let pre_inv =
        parse_cli_args(["--json", "--root", &root_str, "provision", "preflight"]).unwrap();
    let pre_env = execute_invocation(&pre_inv, &transport);
    assert_eq!(
        pre_env.status, "ok",
        "preflight failed: {}",
        pre_env.message
    );

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
    assert_eq!(
        run_env.status, "ok",
        "provision run failed: {}",
        run_env.message
    );

    let state_raw = fs::read_to_string(root.join("install/.aetherflow.state")).unwrap();
    assert!(state_raw.starts_with("# STATE_VERSION=2\n"));
    assert!(state_raw.contains("makedirs\n"));
    assert!(state_raw.contains("harden_perms\n"));
    assert!(root.join("opt/AetherFlow/releases").is_dir());
    assert!(root.join("etc/systemd/system").is_dir());
    assert!(!root
        .join("etc/systemd/system/aetherflow-api.service.d/10-aetherflow-sandbox.conf")
        .exists());

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
        assert_eq!(
            state_mode, 0o600,
            "state file must have 0600 private permissions"
        );
        assert_eq!(
            conf_mode, 0o600,
            "config file must have 0600 private permissions"
        );
    }

    // 4. Re-running `af provision run` skips already-completed steps (`SkippedAlreadyDone`)
    let resume_env = execute_invocation(&run_inv, &transport);
    assert_eq!(resume_env.status, "ok");
    let resume_data = resume_env.data.unwrap();
    assert_eq!(resume_data["records"][0]["status"], "skipped_already_done");

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
    let bad_step =
        parse_cli_args(["--root", &root_str, "provision", "run", "bash -c 'id'"]).unwrap();
    let bad_env = execute_invocation(&bad_step, &transport);
    assert_eq!(bad_env.status, "error");
    assert_eq!(bad_env.exit_code, CliExitCode::UsageOrValidation.as_i32());

    // 7. Test `ProvisionLockGuard` crash recovery and active contention
    let lock_path = root.join("run/aetherflow-setup.lock");
    fs::write(&lock_path, b"99999999\n").unwrap(); // Stale crashed PID
    let lock_guard =
        ProvisionLockGuard::acquire(&lock_path).expect("should recover stale lockfile");
    let contention_err = ProvisionLockGuard::acquire(&lock_path).unwrap_err();
    assert_eq!(
        contention_err.exit_code(),
        CliExitCode::PreflightOrIntegrityFailure
    );
    drop(lock_guard);
    assert!(
        !lock_path.exists(),
        "dropping lock guard should remove lockfile"
    );

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

#[cfg(unix)]
#[test]
fn concurrent_provisioning_stale_lock_recovery_has_one_owner() {
    use std::sync::{mpsc, Arc, Barrier};
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
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(owner_count, 1);
    assert!(!lock_path.exists());
    assert!(sandbox
        .path()
        .join(".aetherflow-setup.lock.rust-guard")
        .is_file());
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
    let invocation = parse_cli_args([
        "--json",
        "--root",
        root.to_str().unwrap(),
        "provision",
        "run",
        "--no-root-check",
    ])
    .unwrap();
    let response = execute_invocation(&invocation, &MockRunnerTransport::default());
    assert_eq!(response.status, "error");
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
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
    let tune_dry_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "maintenance",
        "tune",
        "--dry-run",
    ])
    .unwrap();
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
    let sent_short_inv =
        parse_cli_args(["--json", "sentinel", &auth_str, "--threshold", "2"]).unwrap();
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

    let show_inv =
        parse_cli_args(["--json", "--root", &root_str, "maintenance", "showspace"]).unwrap();
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
    assert!(arr
        .iter()
        .any(|e| e["script_path"] == "packages/system/af-tune"));
    assert!(arr
        .iter()
        .any(|e| e["script_path"] == "packages/system/af-sentinel.py"));
    assert!(arr
        .iter()
        .any(|e| e["script_path"] == "packages/system/clean_log"));
    assert!(arr
        .iter()
        .any(|e| e["script_path"] == "packages/system/showspace"));
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
    fs::write(
        sudoers_d.join("aether-legacy"),
        b"www-data ALL=(ALL) NOPASSWD: ALL\n",
    )
    .unwrap();
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

    // 3. Verify .aetherflow.conf has HOSTNAME_CONFIGURED and SUDOERS_HARDENED (POSIX single-quoted)
    let conf_raw = fs::read_to_string(root.join("install/.aetherflow.conf")).unwrap();
    assert!(conf_raw.contains("HOSTNAME_CONFIGURED='true'"));
    assert!(conf_raw.contains("SUDOERS_HARDENED='true'"));

    // 4. Verify bashrc
    let bashrc_path = root.join("root/.bashrc");
    assert!(bashrc_path.is_file(), "root/.bashrc must exist");
    let bashrc_content = fs::read_to_string(&bashrc_path).unwrap();
    assert!(bashrc_content.contains("/usr/local/bin"));

    // 5. Verify hostname
    let etc_hostname = root.join("etc/hostname");
    assert!(etc_hostname.is_file(), "etc/hostname must exist");
    assert_eq!(
        fs::read_to_string(&etc_hostname).unwrap().trim(),
        "localhost"
    );

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
    assert!(
        !sudoers_d.join("aether-legacy").exists(),
        "legacy sudoers file must be purged"
    );

    // 9. Verify build_modern created /etc/aetherflow/aetherflow.env with 0600 mode
    let env_path = root.join("etc/aetherflow/aetherflow.env");
    assert!(env_path.is_file(), "aetherflow.env must exist");
    let env_content = fs::read_to_string(&env_path).unwrap();
    assert!(env_content.contains("AES_MASTER_KEY="));
    assert!(env_content.contains("JWT_SECRET="));
    assert!(env_content.contains("AF_DB_PATH=/var/lib/aetherflow/aetherflow.sqlite"));
    assert!(env_content.contains("AETHERFLOW_RUNNER_SOCK=/run/aetherflow/runner.sock"));
    assert!(!env_content.contains("GIN_MODE="));

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
        assert_eq!(
            bashrc_mode, 0o640,
            "root/.bashrc must have 0640 permissions"
        );

        let locale_mode = fs::metadata(&locale_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            locale_mode, 0o644,
            "etc/default/locale must have 0644 permissions"
        );

        let env_mode = fs::metadata(&env_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(env_mode, 0o600, "aetherflow.env must have 0600 permissions");

        let var_lib_mode = fs::metadata(root.join("var/lib/aetherflow"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            var_lib_mode, 0o700,
            "var/lib/aetherflow must have 0700 permissions"
        );

        let skel_media_mode = fs::metadata(root.join("etc/skel/Media"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            skel_media_mode, 0o750,
            "etc/skel/Media must have 0750 permissions"
        );
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
    assert_eq!(
        original_env, preserved_env,
        "existing aetherflow.env must be preserved across runs"
    );
}

#[test]
fn provision_conf_uses_posix_single_quoting_unquotes_variants_and_blocks_passwd() {
    let tmp = TempTestDir::new("conf-quoting");
    let paths = ProvisionPaths::for_root(tmp.path()).unwrap();
    let store = ProvisionStateStore::new(paths.clone());

    store
        .save_config_value("SPECIAL_VAL", "it's $(id) & `uname`; a \"b\"")
        .unwrap();
    let raw = fs::read_to_string(&paths.config_file).unwrap();
    assert!(
        raw.contains("SPECIAL_VAL='it'\\''s $(id) & `uname`; a \"b\"'\n"),
        "unexpected serialized conf: {raw}"
    );
    let parsed = store.read_config_map().unwrap();
    assert_eq!(
        parsed.get("SPECIAL_VAL").map(String::as_str),
        Some("it's $(id) & `uname`; a \"b\"")
    );

    // Rejects plaintext `passwd`
    assert!(store.save_config_value("passwd", "hunter2").is_err());

    // Reader unquotes single-quoted, double-quoted, bash %q backslash-escaped, and $'...' values,
    // and strips/ignores any legacy `passwd` entry.
    let legacy_sample = "\
SINGLE='hello'\\''world'\n\
DOUBLE=\"quoted \\\"val\\\" \\$ok\"\n\
ESCAPED=foo\\ bar\\&baz\n\
ANSIC=$'tab\\there'\n\
PLAIN=simple\n\
passwd='legacy-plaintext'\n";
    let decoded = crate::provision::parse_config_map(legacy_sample);
    assert_eq!(
        decoded.get("SINGLE").map(String::as_str),
        Some("hello'world")
    );
    assert_eq!(
        decoded.get("DOUBLE").map(String::as_str),
        Some("quoted \"val\" $ok")
    );
    assert_eq!(
        decoded.get("ESCAPED").map(String::as_str),
        Some("foo bar&baz")
    );
    assert_eq!(decoded.get("ANSIC").map(String::as_str), Some("tab\there"));
    assert_eq!(decoded.get("PLAIN").map(String::as_str), Some("simple"));
    assert!(!decoded.contains_key("passwd"));
}

#[test]
fn provision_boot_removes_stale_api_sandbox_dropin_and_provisions_apache_htpasswd() {
    let tmp = TempTestDir::new("provision-boot-apache");
    let root = tmp.path().join("rootfs");
    let dropin_dir = root.join("etc/systemd/system/aetherflow-api.service.d");
    fs::create_dir_all(&dropin_dir).unwrap();
    let stale_sandbox = dropin_dir.join("10-aetherflow-sandbox.conf");
    let stale_sidecar = dropin_dir.join("10-aetherflow-sandbox.conf.aetherflow-sha256");
    let hardening_dropin = dropin_dir.join("10-aetherflow-hardening.conf");
    fs::write(&stale_sandbox, b"[Service]\nProtectProc=invisible\n").unwrap();
    fs::write(&stale_sidecar, b"deadbeef\n").unwrap();
    fs::write(&hardening_dropin, b"[Service]\nUMask=0027\n").unwrap();

    // Configure /etc/apache2/AetherFlow and seed username + unencrypted .master.creds
    let apache_af_dir = root.join("etc/apache2/AetherFlow");
    fs::create_dir_all(&apache_af_dir).unwrap();
    let var_lib = root.join("var/lib/aetherflow");
    fs::create_dir_all(&var_lib).unwrap();
    fs::write(
        var_lib.join(".master.creds"),
        br#"{"username":"operator","password":"SuperSecretPassword123!","ha1":"00"}"#,
    )
    .unwrap();

    let root_str = root.to_string_lossy().to_string();
    let transport = MockRunnerTransport::default();

    let boot_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "provision",
        "run",
        "boot",
        "harden_perms",
        "--no-root-check",
    ])
    .unwrap();
    let boot_env = execute_invocation(&boot_inv, &transport);
    assert_eq!(boot_env.status, "ok", "{}", boot_env.message);

    assert!(
        !stale_sandbox.exists(),
        "boot must remove stale 10-aetherflow-sandbox.conf for aetherflow-api.service"
    );
    assert!(
        !stale_sidecar.exists(),
        "boot must remove stale 10-aetherflow-sandbox.conf.aetherflow-sha256 sidecar"
    );
    assert!(
        hardening_dropin.is_file(),
        "boot must preserve 10-aetherflow-hardening.conf"
    );

    let htpasswd_path = apache_af_dir.join("htpasswd");
    assert!(
        htpasswd_path.is_file(),
        "harden_perms must provision /etc/apache2/AetherFlow/htpasswd when configured"
    );
    let htpasswd_raw = fs::read_to_string(&htpasswd_path).unwrap();
    assert!(
        htpasswd_raw.starts_with("operator:$2y$"),
        "expected operator:$2y$ bcrypt entry, got {htpasswd_raw:?}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&htpasswd_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "htpasswd must have 0640 permissions");
    }
}
