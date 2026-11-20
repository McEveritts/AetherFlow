use super::*;
use std::sync::Arc;

static ENV_TEST_MUTEX: once_cell::sync::Lazy<std::sync::Mutex<()>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(()));

#[test]
fn test_stale_af_version_receipt_against_older_live_runtime_fails_certification() {
    let env_cfg = crate::PackageExecutionEnv::default();
    let target = "2.5.0";

    // Scenario 1: Stale .af-version receipt was written with "2.5.0" (matching target),
    // but the live runtime probe still returns older "2.4.0".
    // Certification MUST fail because live runtime and receipt disagree.
    let live_probe = |_pkg: &str, _env: &crate::PackageExecutionEnv| {
        LiveRuntimeProbeOutcome::Verified("2.4.0".to_string())
    };
    let receipt_probe = |_pkg: &str, _env: &crate::PackageExecutionEnv| Some("2.5.0".to_string());

    let resolved = resolve_verified_installed_version_with_prober(
        "sonarr",
        &env_cfg,
        live_probe,
        receipt_probe,
    );
    assert_eq!(
        resolved, None,
        "Disagreement between live probe (2.4.0) and receipt (2.5.0) must reject receipt as stale"
    );

    let matches_target = resolved
        .as_deref()
        .map(|ver| af_release::lifecycle::versions_match_target(ver, target))
        .unwrap_or(false);
    assert!(!matches_target, "Certification must fail on stale receipt!");

    // Scenario 2: Live git rev-parse HEAD returns older commit while receipt claims new commit
    let live_git = |_pkg: &str, _env: &crate::PackageExecutionEnv| {
        LiveRuntimeProbeOutcome::Verified("1111111111111111".to_string())
    };
    let receipt_git =
        |_pkg: &str, _env: &crate::PackageExecutionEnv| Some("2222222222222222".to_string());
    let resolved_git =
        resolve_verified_installed_version_with_prober("lidarr", &env_cfg, live_git, receipt_git);
    assert_eq!(
        resolved_git, None,
        "Disagreement between live git commit and receipt must reject certification"
    );

    // Scenario 3: When live probe and receipt agree on "2.5.0", certification passes
    let live_ok = |_pkg: &str, _env: &crate::PackageExecutionEnv| {
        LiveRuntimeProbeOutcome::Verified("2.5.0".to_string())
    };
    let receipt_ok = |_pkg: &str, _env: &crate::PackageExecutionEnv| Some("2.5.0".to_string());
    let resolved_ok =
        resolve_verified_installed_version_with_prober("sonarr", &env_cfg, live_ok, receipt_ok);
    assert_eq!(resolved_ok, Some("2.5.0".to_string()));
    assert!(af_release::lifecycle::versions_match_target(
        resolved_ok.as_deref().unwrap(),
        target
    ));

    // Scenario 4: When no live runtime probe is available, .af-version alone is rejected without independent runtime evidence, and accepted with evidence
    let live_none =
        |_pkg: &str, _env: &crate::PackageExecutionEnv| LiveRuntimeProbeOutcome::NotConfigured;
    let receipt_only = |_pkg: &str, _env: &crate::PackageExecutionEnv| Some("2.5.0".to_string());
    let resolved_none = resolve_verified_installed_version_with_prober(
        "custompkg",
        &env_cfg,
        live_none,
        receipt_only,
    );
    assert_eq!(
        resolved_none, None,
        "Without independent runtime evidence on disk, receipt-only certification must be rejected"
    );

    let temp_dir_sc4 =
        std::env::temp_dir().join(format!("af-test-sc4-evidence-{}", uuid::Uuid::new_v4()));
    let mut env_cfg_sc4 = crate::PackageExecutionEnv::default();
    env_cfg_sc4.fs_root = Some(temp_dir_sc4.clone());
    let payload_file = temp_dir_sc4.join("opt/custompkg/app.bin");
    std::fs::create_dir_all(payload_file.parent().unwrap()).unwrap();
    std::fs::write(&payload_file, b"runtime-payload").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&payload_file, std::fs::Permissions::from_mode(0o755));
    }

    let resolved_with_evidence = resolve_verified_installed_version_with_prober(
        "custompkg",
        &env_cfg_sc4,
        live_none,
        receipt_only,
    );
    assert_eq!(
        resolved_with_evidence,
        Some("2.5.0".to_string()),
        "With independent runtime evidence on disk, receipt is accepted"
    );
    let _ = std::fs::remove_dir_all(&temp_dir_sc4);

    // Scenario 5: Configured live probe fails -> certification MUST fail even if .af-version matches target
    let live_failed = |_pkg: &str, _env: &crate::PackageExecutionEnv| {
        LiveRuntimeProbeOutcome::Failed("Probe timeout or binary missing".to_string())
    };
    let receipt_matches = |_pkg: &str, _env: &crate::PackageExecutionEnv| Some("2.5.0".to_string());
    let resolved_failed = resolve_verified_installed_version_with_prober(
        "invidious",
        &env_cfg,
        live_failed,
        receipt_matches,
    );
    assert_eq!(
        resolved_failed, None,
        "Failed live probe must fail-closed and NEVER fall back to receipt"
    );
}

#[test]
fn test_piped_live_probe_three_components() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-piped-runner-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let init_repo = |dir: &Path| -> String {
        std::fs::create_dir_all(dir).unwrap();
        let _ = std::process::Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(dir)
            .output();
        let _ = std::process::Command::new("git")
            .args(["config", "user.email", "t@e.com"])
            .current_dir(dir)
            .output();
        let _ = std::process::Command::new("git")
            .args(["config", "user.name", "T"])
            .current_dir(dir)
            .output();
        std::fs::write(dir.join("f"), "c").unwrap();
        let _ = std::process::Command::new("git")
            .args(["add", "f"])
            .current_dir(dir)
            .output();
        let _ = std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(dir)
            .output();
        let out = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(dir)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .to_ascii_lowercase()
    };

    let fe = init_repo(&temp_dir.join("opt/piped/frontend"));
    let be = init_repo(&temp_dir.join("opt/piped/backend"));
    let pr = init_repo(&temp_dir.join("opt/piped/proxy"));

    let live = probe_live_runtime_version("piped", &env_cfg);
    assert_eq!(
        live,
        LiveRuntimeProbeOutcome::Verified(format!("frontend:{fe},backend:{be},proxy:{pr}"))
    );

    let receipt_path = temp_dir.join("opt/piped/.af-version");
    std::fs::write(
        &receipt_path,
        format!("frontend:{fe},backend:{be},proxy:{pr}"),
    )
    .unwrap();
    let verified = resolve_verified_installed_version("piped", &env_cfg);
    assert_eq!(
        verified,
        Some(format!("frontend:{fe},backend:{be},proxy:{pr}"))
    );

    // Mismatched receipt
    std::fs::write(
        &receipt_path,
        format!("frontend:{fe},backend:0000000000000000000000000000000000000000,proxy:{pr}"),
    )
    .unwrap();
    let verified_mismatch = resolve_verified_installed_version("piped", &env_cfg);
    assert_eq!(verified_mismatch, None);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_direct_runner_extract_version_token_from_rclone_output() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!(
        "af-test-rclone-version-token-{}",
        uuid::Uuid::new_v4()
    ));
    let bin_dir = temp_dir.join("usr/local/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();

    // Create a mock rclone script that prints prose like "rclone v1.75.2\n- os/version: linux"
    let script_path = bin_dir.join("rclone");
    std::fs::write(
        &script_path,
        "#!/bin/sh\necho 'rclone v1.75.2'\necho '- os/version: linux'\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    // Keep the production regex, but execute the fixture rather than the
    // catalog's shell command, which names the host's /usr/bin/rclone.
    let packages_path = temp_dir.join("packages.json");
    std::fs::write(&packages_path, crate::EMBEDDED_PACKAGES_JSON).unwrap();
    let mut automation: serde_json::Value =
        serde_json::from_str(crate::EMBEDDED_AUTOMATION_JSON).unwrap();
    automation["rclone"]["version_command"] =
        serde_json::json!(["/usr/local/bin/rclone", "version"]);
    let automation_path = temp_dir.join("package_automation.json");
    std::fs::write(&automation_path, serde_json::to_vec(&automation).unwrap()).unwrap();
    let previous_packages = std::env::var_os("AETHERFLOW_PACKAGES_CONFIG");
    let previous_automation = std::env::var_os("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG");
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &packages_path);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation_path);

    // Probe live runtime version for "rclone"
    let outcome = probe_live_runtime_version("rclone", &env_cfg);
    for (key, previous) in [
        ("AETHERFLOW_PACKAGES_CONFIG", previous_packages),
        ("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", previous_automation),
    ] {
        match previous {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }
    assert_eq!(
        outcome,
        LiveRuntimeProbeOutcome::Verified("1.75.2".to_string()),
        "probe_live_runtime_version must extract bare token '1.75.2' from 'rclone v1.75.2'"
    );

    // Also test receipt matching target "1.75.2"
    let receipt_probe = |_pkg: &str, _env: &crate::PackageExecutionEnv| Some("1.75.2".to_string());
    let certified = resolve_verified_installed_version_with_prober(
        "rclone",
        &env_cfg,
        |_pkg, _env| outcome.clone(),
        receipt_probe,
    );
    assert_eq!(certified, Some("1.75.2".to_string()));
    assert!(af_release::lifecycle::versions_match_target(
        certified.as_deref().unwrap(),
        "1.75.2"
    ));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_catalog_loading_failure_fails_closed_without_certifying_af_version() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-catalog-fail-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let malformed_cfg = temp_dir.join("bad_packages.json");
    std::fs::write(&malformed_cfg, "{ this is not valid json }").unwrap();

    // Point AF_PACKAGES_CONFIG to the malformed file
    std::env::set_var("AF_PACKAGES_CONFIG", &malformed_cfg);

    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    // Probe live runtime version: must return Failed(...)
    let outcome = probe_live_runtime_version("sonarr", &env_cfg);
    match &outcome {
        LiveRuntimeProbeOutcome::Failed(reason) => {
            assert!(
                reason.contains("Failed to load package definition"),
                "Expected failure reason about package definition, got: {}",
                reason
            );
        }
        other => panic!("Expected LiveRuntimeProbeOutcome::Failed, got: {:?}", other),
    }

    // Even if .af-version receipt is present with target version "3.0.0", certification MUST fail (return None)
    let receipt_probe = |_pkg: &str, _env: &crate::PackageExecutionEnv| Some("3.0.0".to_string());
    let certified = resolve_verified_installed_version_with_prober(
        "sonarr",
        &env_cfg,
        |_pkg, _env| outcome.clone(),
        receipt_probe,
    );
    assert_eq!(
        certified, None,
        "Catalog failure must fail closed and refuse to certify .af-version"
    );

    std::env::remove_var("AF_PACKAGES_CONFIG");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_probe_live_runtime_version_descendant_pipe_drain_does_not_hang() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-pipe-drain-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let mut packages: Vec<serde_json::Value> =
        serde_json::from_str(crate::EMBEDDED_PACKAGES_JSON).unwrap();
    packages.push(serde_json::json!({
        "name": "probe-pipe-test",
        "label": "Probe Pipe Test",
        "description": "Test package",
        "lock_file": "/install/.probe-pipe-test.lock",
        "category": "Test",
        "service_type": "systemd",
        "service_name": "probe-pipe-test"
    }));
    let pkg_path = temp_dir.join("packages.json");
    std::fs::write(&pkg_path, serde_json::to_string(&packages).unwrap()).unwrap();

    let mut automation: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(crate::EMBEDDED_AUTOMATION_JSON).unwrap();
    automation.insert(
        "probe-pipe-test".to_string(),
        serde_json::json!({
            "version_command": ["sh", "-c", "echo 1.75.2; sleep 30 &"]
        }),
    );
    let auto_path = temp_dir.join("package_automation.json");
    std::fs::write(&auto_path, serde_json::to_string(&automation).unwrap()).unwrap();

    std::env::set_var("AF_PACKAGES_CONFIG", &pkg_path);
    std::env::set_var("AF_PACKAGE_AUTOMATION_CONFIG", &auto_path);

    let env_cfg = crate::PackageExecutionEnv::default();
    let start = std::time::Instant::now();
    let outcome = probe_live_runtime_version("probe-pipe-test", &env_cfg);
    let elapsed = start.elapsed();

    std::env::remove_var("AF_PACKAGES_CONFIG");
    std::env::remove_var("AF_PACKAGE_AUTOMATION_CONFIG");
    let _ = std::fs::remove_dir_all(&temp_dir);

    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "probe_live_runtime_version took {:?}, expected < 2s without hanging on descendant",
        elapsed
    );
    assert_eq!(
        outcome,
        Confirmed("1.75.2".to_string()),
        "probe_live_runtime_version must return Confirmed(\"1.75.2\")"
    );
}

#[test]
fn test_preserve_complete_prerelease_and_build_identities() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();
    // 1. extract_version_token preserves complete identities
    let old_token = extract_version_token("my-tool 1.0.0+build--old (x86_64-linux)");
    let new_token = extract_version_token("my-tool 1.0.0+build--new (x86_64-linux)");
    let debug_token = extract_version_token("my-tool 1.0.0+Debug (x86_64-linux)");
    let alpha_token = extract_version_token("my-tool 1.0.0-alpha--1 (x86_64-linux)");
    let debian_epoch = extract_version_token("Package: 2:1.18.2-1ubuntu1 (amd64)");
    let tilde_rc = extract_version_token("my-tool 1.0.0~rc1-1");

    assert_eq!(old_token, "1.0.0+build--old");
    assert_eq!(new_token, "1.0.0+build--new");
    assert_eq!(debug_token, "1.0.0+Debug");
    assert_eq!(alpha_token, "1.0.0-alpha--1");
    assert_eq!(debian_epoch, "2:1.18.2-1ubuntu1");
    assert_eq!(tilde_rc, "1.0.0~rc1-1");

    assert_ne!(
        old_token, new_token,
        "1.0.0+build--old and 1.0.0+build--new must not collapse"
    );
    assert_ne!(
        debug_token, "1.0.0",
        "1.0.0+Debug must retain build metadata"
    );
    assert_ne!(
        old_token, "1.0.0+build",
        "1.0.0+build--old must not be truncated at --"
    );

    // 2. Generic binary-probe fallback in probe_live_runtime_version
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-build-meta-{}", uuid::Uuid::new_v4()));
    let bin_dir = temp_dir.join("usr/local/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();

    let mut packages: Vec<serde_json::Value> =
        serde_json::from_str(crate::EMBEDDED_PACKAGES_JSON).unwrap();
    packages.push(serde_json::json!({
        "name": "buildmetaapp",
        "label": "Build Meta App",
        "description": "Test package",
        "lock_file": "/install/.buildmetaapp.lock",
        "category": "Test",
        "service_type": "systemd",
        "service_name": "buildmetaapp"
    }));
    let pkg_path = temp_dir.join("packages.json");
    std::fs::write(&pkg_path, serde_json::to_string(&packages).unwrap()).unwrap();
    std::env::set_var("AF_PACKAGES_CONFIG", &pkg_path);

    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    for (ver, expected) in [
        ("1.0.0+build--old", "1.0.0+build--old"),
        ("1.0.0+build--new", "1.0.0+build--new"),
        ("1.0.0+Debug", "1.0.0+Debug"),
    ] {
        let prog_path = bin_dir.join("buildmetaapp");
        std::fs::write(
            &prog_path,
            format!("#!/bin/sh\necho 'buildmetaapp {}'\n", ver),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&prog_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let outcome = probe_live_runtime_version("buildmetaapp", &env_cfg);
        assert_eq!(
            outcome,
            LiveRuntimeProbeOutcome::Verified(expected.to_string()),
            "Generic binary probe must preserve complete version '{}'",
            ver
        );
    }

    std::env::remove_var("AF_PACKAGES_CONFIG");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_candidate_receipt_snapshot_and_restore_on_failed_certification() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-receipt-snap-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    // Setup pre-existing receipt at /opt/mockpkg/.af-version
    let pre_existing = temp_dir.join("opt/mockpkg/.af-version");
    std::fs::create_dir_all(pre_existing.parent().unwrap()).unwrap();
    std::fs::write(&pre_existing, b"1.0.0\n").unwrap();

    // Snapshot candidate receipts before operation
    let snapshots = snapshot_candidate_receipts_with_env("mockpkg", &env_cfg).unwrap();
    assert!(!snapshots.is_empty(), "Must find candidate paths");

    // Verify pre-existing receipt has Some(b"1.0.0\n")
    let pre_snap = snapshots
        .iter()
        .find(|s| s.path == pre_existing)
        .expect("pre-existing must be tracked");
    assert_eq!(pre_snap.bytes(), Some(b"1.0.0\n".as_slice()));

    // Verify non-existent candidate path (e.g. /var/lib/mockpkg/.af-version) has None
    let var_lib_path = temp_dir.join("var/lib/mockpkg/.af-version");
    let non_exist_snap = snapshots
        .iter()
        .find(|s| s.path == var_lib_path)
        .expect("var/lib candidate must be tracked");
    assert_eq!(non_exist_snap.state, None);

    // Mutate pre-existing receipt (installer writes new version)
    std::fs::write(&pre_existing, b"2.0.0-uncertified\n").unwrap();

    // Also write a newly created receipt at var/lib
    std::fs::create_dir_all(var_lib_path.parent().unwrap()).unwrap();
    std::fs::write(&var_lib_path, b"2.0.0-uncertified\n").unwrap();

    // Target certification fails -> restore candidate receipts!
    let restore_res = restore_candidate_receipts(&snapshots);
    assert!(
        restore_res.is_ok(),
        "Restoration must succeed: {:?}",
        restore_res
    );

    // Pre-existing receipt must be rolled back to 1.0.0
    assert_eq!(std::fs::read(&pre_existing).unwrap(), b"1.0.0\n");

    // Newly created receipt at var/lib must be completely removed
    assert!(
        !var_lib_path.exists(),
        "Newly created receipt must be removed after failed certification"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_run_bounded_probe_command_kills_descendants_and_times_out() {
    let mut cmd = std::process::Command::new("sh");
    cmd.args(["-c", "sleep 30"]);

    let start = std::time::Instant::now();
    let res = run_bounded_probe_command(&mut cmd, Duration::from_millis(150));
    let elapsed = start.elapsed();

    assert!(res.is_err(), "Hanging command must time out");
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("timed out"),
        "Error must mention timeout: {}",
        err_msg
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "Command timeout took {:?}, expected < 2s",
        elapsed
    );

    let mut echo_cmd = std::process::Command::new("echo");
    echo_cmd.arg("hello-probe");
    let echo_res = run_bounded_probe_command(&mut echo_cmd, Duration::from_secs(2));
    assert!(echo_res.is_ok());
    let output = echo_res.unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello-probe"
    );
}

#[test]
fn test_restore_candidate_receipts_symlink_swap_does_not_modify_victim() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-symlink-restore-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let receipt_path = temp_dir.join("opt/vulnpkg/.af-version");
    std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
    std::fs::write(&receipt_path, b"1.0.0\n").unwrap();

    // Snapshot original receipt (1.0.0)
    let snapshots = snapshot_candidate_receipts_with_env("vulnpkg", &env_cfg).unwrap();

    // Attacker creates a victim file outside
    let victim_file = temp_dir.join("victim_file.txt");
    std::fs::write(&victim_file, b"VICTIM_INTACT_CONTENT").unwrap();

    // Attacker replaces .af-version with a symlink pointing to victim_file
    std::fs::remove_file(&receipt_path).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&victim_file, &receipt_path).unwrap();

    // Now restore candidate receipts!
    let restore_res = restore_candidate_receipts(&snapshots);
    assert!(
        restore_res.is_ok(),
        "Restoration must succeed: {:?}",
        restore_res
    );

    // Victim file MUST NOT have been modified!
    assert_eq!(
        std::fs::read(&victim_file).unwrap(),
        b"VICTIM_INTACT_CONTENT"
    );

    // .af-version MUST now be a regular file with b"1.0.0\n", NOT a symlink!
    let meta = std::fs::symlink_metadata(&receipt_path).unwrap();
    assert!(
        !meta.file_type().is_symlink(),
        ".af-version must not be a symlink after restoration"
    );
    assert!(
        meta.file_type().is_file(),
        ".af-version must be a regular file"
    );
    assert_eq!(std::fs::read(&receipt_path).unwrap(), b"1.0.0\n");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_snapshot_symlink_or_fifo_fails_closed_and_marks_job_failed() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-symlink-snap-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let receipt_path = temp_dir.join("opt/symlinkpkg/.af-version");
    std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
    let target_file = temp_dir.join("target.txt");
    std::fs::write(&target_file, b"target").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target_file, &receipt_path).unwrap();

    // 1. snapshot_candidate_receipts_with_env must fail closed with Err
    let snap_res = snapshot_candidate_receipts_with_env("symlinkpkg", &env_cfg);
    assert!(
        snap_res.is_err(),
        "Snapshotting a symlink must fail closed: {:?}",
        snap_res
    );
    let err_msg = snap_res.unwrap_err();
    assert!(
        err_msg.to_ascii_lowercase().contains("symlink"),
        "Error must mention symlink: {}",
        err_msg
    );

    // Also verify FIFO fails closed with non-regular file error
    #[cfg(unix)]
    {
        let fifo_path = temp_dir.join("opt/fifopkg/.af-version");
        std::fs::create_dir_all(fifo_path.parent().unwrap()).unwrap();
        let fifo_cstr = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
        let _ = unsafe { libc::mkfifo(fifo_cstr.as_ptr(), 0o644) };
        let fifo_snap = snapshot_candidate_receipts_with_env("fifopkg", &env_cfg);
        assert!(fifo_snap.is_err(), "Snapshotting a FIFO must fail closed");
        let fifo_err = fifo_snap.unwrap_err();
        assert!(
            fifo_err.contains("non-regular file") || fifo_err.contains("symlink"),
            "FIFO error must mention non-regular file: {}",
            fifo_err
        );
    }

    // 2. CoordinatedOperation::execute must mark job as terminal "failed"
    let db_path = temp_dir.join("var/lib/aetherflow/aetherflow.sqlite");
    std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
        CREATE TABLE settings(id INTEGER PRIMARY KEY,base_domain TEXT);
        INSERT INTO settings VALUES(1,'default.example.test');
        CREATE TABLE app_updates(package_name TEXT PRIMARY KEY);
        CREATE TABLE app_ingress_configs(app_name TEXT PRIMARY KEY,public_domain TEXT,
            external_access_enabled BOOLEAN,listen_port INTEGER,tls_enabled BOOLEAN,
            created_at TEXT,updated_at TEXT);",
    )
    .unwrap();

    let req = PackageRunnerRequest {
        package_id: "symlinkpkg".to_string(),
        action: "install".to_string(),
        script_name: "installpackage-symlinkpkg".to_string(),
        app_port: 8080,
        delete_data: false,
        expected_target_version: Some("1.0.0".to_string()),
        ..Default::default()
    };
    let package = Package {
        name: "symlinkpkg".into(),
        service_name: "symlinkpkg".into(),
        service_type: "systemd".into(),
        default_port: 8080,
        ..Default::default()
    };

    struct DummyBackend;
    impl LifecycleBackend for DummyBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8080
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(false) })
        }
        fn control<'a>(&'a self, _: &'a str, _: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let mut coord =
        CoordinatedOperation::admit(conn, req, package, vec!["symlinkpkg".into()]).unwrap();
    let (tx, _rx) = mpsc::channel(10);
    let exec_res = coord.execute(&DummyBackend, &tx).await;
    assert!(
        exec_res.is_err(),
        "Execute must fail due to symlink receipt snapshot"
    );

    let (status, failure_category, failed_stage): (String, Option<String>, Option<String>) = coord.conn.query_row(
        "SELECT status, failure_category, failed_stage FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2",
        rusqlite::params![coord.request.package_id, coord.request.lifecycle_job_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap();

    assert_eq!(status, "failed", "Job status must be terminal 'failed'");
    assert_eq!(
        failure_category.as_deref(),
        Some("preflight"),
        "failure_category must be preflight"
    );
    assert_eq!(
        failed_stage.as_deref(),
        Some("preflight_receipt_snapshot"),
        "failed_stage must be preflight_receipt_snapshot"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_has_independent_runtime_evidence_rejects_only_lockfile() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-lock-evidence-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    // Create directory /opt/lockpkg with only .af-version and anything.lock
    let opt_dir = temp_dir.join("opt/lockpkg");
    std::fs::create_dir_all(&opt_dir).unwrap();
    std::fs::write(opt_dir.join(".af-version"), b"1.0.0\n").unwrap();
    std::fs::write(opt_dir.join("anything.lock"), b"lockfile").unwrap();
    std::fs::write(opt_dir.join("install.log"), b"logs").unwrap();
    std::fs::write(opt_dir.join("data.tmp"), b"temporary").unwrap();

    let has_evidence = has_independent_runtime_evidence("lockpkg", &env_cfg);
    assert!(
        !has_evidence,
        "has_independent_runtime_evidence must reject directory containing only .af-version, anything.lock, and data files"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_extract_version_token_preserves_trailing_hyphens_in_prerelease_and_build() {
    assert_eq!(
        extract_version_token("tool 1.0.0+build- (linux)"),
        "1.0.0+build-"
    );
    assert_eq!(
        extract_version_token("tool 1.0.0+build-- (linux)"),
        "1.0.0+build--"
    );
    assert_eq!(
        extract_version_token("tool 1.0.0-alpha- (linux)"),
        "1.0.0-alpha-"
    );
    assert_eq!(
        extract_version_token("tool 1.0.0-alpha-- (linux)"),
        "1.0.0-alpha--"
    );
    assert_eq!(extract_version_token("tool 1.0.0-- (linux)"), "1.0.0--");
    assert_eq!(extract_version_token("tool 1.0.0+-- (linux)"), "1.0.0+--");
    assert_eq!(extract_version_token("tool 1.0.0+- (linux)"), "1.0.0+-");

    // Dangling trailing hyphen without identifier must be trimmed
    assert_eq!(extract_version_token("tool 1.0.0- (linux)"), "1.0.0");
    assert_eq!(extract_version_token("tool 1.0.0+ (linux)"), "1.0.0");

    // Trailing punctuation should be trimmed while preserving valid hyphens
    assert_eq!(extract_version_token("tool 1.0.0+build-."), "1.0.0+build-");
    assert_eq!(extract_version_token("tool 1.0.0+build-,"), "1.0.0+build-");
    assert_eq!(extract_version_token("tool 1.0.0+build-:"), "1.0.0+build-");
    assert_eq!(extract_version_token("tool 1.0.0+build-;"), "1.0.0+build-");
}

#[test]
fn test_sanitize_lifecycle_field_redacts_credentials_and_tokens() {
    let input = "Failed to fetch: password=supersecret, token: mytoken123, Bearer eyJhbGciOi..., Basic dXNlcjpwYXNz; url=https://example.com";
    let sanitized = sanitize_lifecycle_field(input);
    assert!(
        !sanitized.contains("supersecret"),
        "Password must be redacted"
    );
    assert!(!sanitized.contains("mytoken123"), "Token must be redacted");
    assert!(
        !sanitized.contains("eyJhbGciOi"),
        "Bearer token must be redacted"
    );
    assert!(
        !sanitized.contains("dXNlcjpwYXNz"),
        "Basic auth must be redacted"
    );
    assert!(sanitized.contains("password=[REDACTED]"));
    assert!(sanitized.contains("token: [REDACTED]"));
    assert!(sanitized.contains("Bearer [REDACTED]"));
    assert!(sanitized.contains("Basic [REDACTED]"));

    // Quoted and multi-word credential values
    let multiword_input = r#"Encountered error with password="first SECRET_TAIL" and "secret": "alpha beta gamma" and 'token': 'delta epsilon'"#;
    let sanitized_multi = sanitize_lifecycle_field(multiword_input);
    assert!(
        !sanitized_multi.contains("SECRET_TAIL"),
        "Must not leak SECRET_TAIL"
    );
    assert!(
        !sanitized_multi.contains("alpha beta gamma"),
        "Must not leak alpha beta gamma"
    );
    assert!(
        !sanitized_multi.contains("beta gamma"),
        "Must not leak beta gamma"
    );
    assert!(
        !sanitized_multi.contains("delta epsilon"),
        "Must not leak delta epsilon"
    );
    assert!(sanitized_multi.contains("password=[REDACTED]"));
    assert!(sanitized_multi.contains(r#""secret": [REDACTED]"#));

    // Verify db_password and escaped quotes are completely redacted
    let db_pw_input = r#"db_password="secret_val""#;
    let sanitized_db_pw = sanitize_lifecycle_field(db_pw_input);
    assert!(
        !sanitized_db_pw.contains("secret_val"),
        "db_password value must be redacted"
    );
    assert_eq!(sanitized_db_pw, "db_password=[REDACTED]");

    let json_db_pw = r#"{"db_password": "secret_val"}"#;
    let sanitized_json_db = sanitize_lifecycle_field(json_db_pw);
    assert!(
        !sanitized_json_db.contains("secret_val"),
        "JSON db_password must be redacted"
    );
    assert_eq!(sanitized_json_db, r#"{"db_password": [REDACTED]}"#);

    let escaped_quotes_input = r#"secret="part1 \"quoted\" tail_secret""#;
    let sanitized_escaped = sanitize_lifecycle_field(escaped_quotes_input);
    assert!(!sanitized_escaped.contains("part1"), "Must not leak part1");
    assert!(
        !sanitized_escaped.contains("quoted"),
        "Must not leak quoted"
    );
    assert!(
        !sanitized_escaped.contains("tail_secret"),
        "Must not leak tail_secret"
    );
    assert_eq!(sanitized_escaped, "secret=[REDACTED]");
}

#[test]
fn test_run_bounded_probe_command_cancellable_cancels_promptly() {
    let mut cmd = std::process::Command::new("sleep");
    cmd.arg("10");
    let start = std::time::Instant::now();
    let mut checks = 0;
    let res = run_bounded_probe_command_cancellable(&mut cmd, Duration::from_secs(5), || {
        checks += 1;
        checks >= 2
    });
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), "probe command cancelled");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "Cancellation must terminate immediately"
    );
}

#[test]
fn test_has_independent_runtime_evidence_systemd_unit_exec_start() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-unit-evidence-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let systemd_dir = temp_dir.join("etc/systemd/system");
    std::fs::create_dir_all(&systemd_dir).unwrap();
    let unit_file = systemd_dir.join("unitpkg.service");

    // Case 1: Empty service file -> false
    std::fs::write(&unit_file, b"").unwrap();
    assert!(
        !has_independent_runtime_evidence("unitpkg", &env_cfg),
        "Empty .service file must not count as independent runtime evidence"
    );

    // Case 2: Stale service file with nonexistent binary -> false
    std::fs::write(
        &unit_file,
        b"[Service]\nExecStart=/opt/unitpkg/bin/nonexistent\n",
    )
    .unwrap();
    assert!(
        !has_independent_runtime_evidence("unitpkg", &env_cfg),
        "Service pointing to nonexistent binary must not count as independent runtime evidence"
    );

    // Case 3: Binary exists but is not executable (0o644) -> false
    let bin_path = temp_dir.join("opt/unitpkg/bin/mybin");
    std::fs::create_dir_all(bin_path.parent().unwrap()).unwrap();
    std::fs::write(&bin_path, b"not executable").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o644));
    }
    std::fs::write(&unit_file, b"[Service]\nExecStart=/opt/unitpkg/bin/mybin\n").unwrap();
    assert!(
        !has_independent_runtime_evidence("unitpkg", &env_cfg),
        "Service pointing to non-executable binary must not count as independent runtime evidence"
    );

    // Case 4: Binary is executable with systemd modifiers and quotes -> true
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::write(
        &unit_file,
        b"[Service]\nExecStart=-@!\"/opt/unitpkg/bin/mybin\" --daemon\n",
    )
    .unwrap();
    assert!(
        has_independent_runtime_evidence("unitpkg", &env_cfg),
        "Service pointing to valid executable binary must count as independent runtime evidence"
    );

    // Case 5: Valid symlink to executable binary -> true
    let symlink_path = temp_dir.join("usr/local/bin/unitpkg-link");
    std::fs::create_dir_all(symlink_path.parent().unwrap()).unwrap();
    #[cfg(unix)]
    {
        let _ = std::os::unix::fs::symlink(&bin_path, &symlink_path);
        std::fs::write(
            &unit_file,
            b"[Service]\nExecStart=/usr/local/bin/unitpkg-link\n",
        )
        .unwrap();
        assert!(
            has_independent_runtime_evidence("unitpkg", &env_cfg),
            "Service pointing to symlink to valid executable must count as independent runtime evidence"
        );
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_run_bounded_probe_command_cancellable_grandchild_pipe_does_not_hang() {
    // Child spawns detached/background grandchild that holds stdout/stderr open
    let mut cmd = std::process::Command::new("sh");
    cmd.args(["-c", "(sleep 30) & echo finished-parent"]);

    let start = std::time::Instant::now();
    let res = run_bounded_probe_command_cancellable(&mut cmd, Duration::from_millis(500), || false);
    let elapsed = start.elapsed();

    assert!(res.is_ok(), "Command should succeed: {:?}", res);
    let output = res.unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("finished-parent"));
    assert!(
        elapsed < Duration::from_millis(1000),
        "Probe with open grandchild pipe must return in < 1s without hanging on pipe join, took {:?}",
        elapsed
    );

    // Test timeout case with grandchild holding pipes
    let mut hang_cmd = std::process::Command::new("sh");
    hang_cmd.args(["-c", "(sleep 30) & sleep 10"]);
    let start2 = std::time::Instant::now();
    let hang_res =
        run_bounded_probe_command_cancellable(&mut hang_cmd, Duration::from_millis(200), || false);
    let elapsed2 = start2.elapsed();
    assert!(hang_res.is_err());
    assert!(hang_res.unwrap_err().contains("timed out"));
    assert!(
        elapsed2 < Duration::from_millis(1000),
        "Timeout probe with grandchild pipe must return in < 1s, took {:?}",
        elapsed2
    );

    // Test cancellation case with grandchild holding pipes
    let mut cancel_cmd = std::process::Command::new("sh");
    cancel_cmd.args(["-c", "(sleep 30) & sleep 10"]);
    let start3 = std::time::Instant::now();
    let cancel_res =
        run_bounded_probe_command_cancellable(&mut cancel_cmd, Duration::from_secs(5), || true);
    let elapsed3 = start3.elapsed();
    assert!(cancel_res.is_err());
    assert_eq!(cancel_res.unwrap_err(), "probe command cancelled");
    assert!(
        elapsed3 < Duration::from_millis(1000),
        "Cancelled probe with grandchild pipe must return in < 1s, took {:?}",
        elapsed3
    );
}

#[test]
fn test_run_bounded_probe_command_cancellable_process_group_cleanup_before_reap() {
    let mut cmd = std::process::Command::new("sh");
    cmd.args(["-c", "(sleep 30) & exit 0"]);

    let start = std::time::Instant::now();
    let res = run_bounded_probe_command_cancellable(&mut cmd, Duration::from_secs(5), || false);
    assert!(res.is_ok(), "Probe command should succeed: {:?}", res);
    let out = res.unwrap();
    assert!(out.status.success());
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "Process group cleanup and reap must complete promptly"
    );
}

#[test]
fn test_restore_candidate_receipts_parent_enotdir_fails_closed() {
    let temp_dir = std::env::temp_dir().join(format!("af-test-enotdir-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let parent_file = temp_dir.join("parent_regular_file");
    std::fs::write(&parent_file, b"regular file content").unwrap();
    let receipt_path = parent_file.join(".af-version");

    let snapshots = vec![FileSnapshot::absent(receipt_path)];
    let res = restore_candidate_receipts(&snapshots);
    assert!(
        res.is_err(),
        "restore_candidate_receipts must return Err when parent is a regular file (ENOTDIR), got: {:?}",
        res
    );
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.to_lowercase().contains("not a directory")
            || err_msg.contains("ENOTDIR")
            || err_msg.contains("stepwise"),
        "Error must indicate stepwise open failure on non-directory: {}",
        err_msg
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_has_independent_runtime_evidence_systemd_reset_and_interpreter_checks() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-systemd-audit-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let systemd_dir = temp_dir.join("etc/systemd/system");
    std::fs::create_dir_all(&systemd_dir).unwrap();
    let unit_file = systemd_dir.join("testpkg.service");

    // Finding 4a: ExecStart=/bin/true followed by empty ExecStart= reset must be REJECTED
    std::fs::write(&unit_file, b"[Service]\nExecStart=/bin/true\nExecStart=\n").unwrap();
    assert!(
        !has_independent_runtime_evidence("testpkg", &env_cfg),
        "Service with ExecStart reset by empty ExecStart= must be rejected"
    );

    // Finding 4b: ExecStart=/bin/sh with nonexistent script must be REJECTED
    std::fs::write(
        &unit_file,
        b"[Service]\nExecStart=/bin/sh /opt/testpkg/missing_script.sh\n",
    )
    .unwrap();
    assert!(
        !has_independent_runtime_evidence("testpkg", &env_cfg),
        "Service using shell interpreter with nonexistent script path must be rejected"
    );

    // Finding 4c: Shell interpreter with EXISTING regular script file must be ACCEPTED
    let script_path = temp_dir.join("opt/testpkg/real_script.sh");
    std::fs::create_dir_all(script_path.parent().unwrap()).unwrap();
    std::fs::write(&script_path, b"#!/bin/sh\necho ok\n").unwrap();
    std::fs::write(
        &unit_file,
        b"[Service]\nExecStart=/bin/sh /opt/testpkg/real_script.sh\n",
    )
    .unwrap();
    assert!(
        has_independent_runtime_evidence("testpkg", &env_cfg),
        "Service using shell interpreter with existing regular script file must be accepted"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

fn test_fixture() -> (PathBuf, PathBuf, Connection, Package) {
    let root = std::env::temp_dir().join(format!("af-coordinator-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let cfg = af_release::ReleaseConfig::for_root(&root);
    let path = af_release::config::try_resolve_db_path(&cfg, None)
        .unwrap()
        .path;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL;
        CREATE TABLE settings(id INTEGER PRIMARY KEY,base_domain TEXT);
        INSERT INTO settings VALUES(1,'default.example.test');
        CREATE TABLE app_updates(package_name TEXT PRIMARY KEY);
        INSERT INTO app_updates VALUES('syncthing');
        CREATE TABLE app_ingress_configs(app_name TEXT PRIMARY KEY,public_domain TEXT,
            external_access_enabled BOOLEAN,listen_port INTEGER,tls_enabled BOOLEAN,
            created_at TEXT,updated_at TEXT);
        INSERT INTO app_ingress_configs VALUES('syncthing','custom.example.test',1,18384,0,'now','now');").unwrap();
    let package = Package {
        name: "syncthing".into(),
        service_name: "syncthing".into(),
        service_type: "systemd".into(),
        default_port: 8384,
        ..Default::default()
    };
    (root, path, conn, package)
}

#[test]
fn test_run_bounded_probe_command_waitid_eperm_zombie_fallback_kills_descendants() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();
    super::INJECT_WAITID_EPERM.store(true, std::sync::atomic::Ordering::SeqCst);

    let mut cmd = std::process::Command::new("sh");
    cmd.args(["-c", "(sleep 30) & exit 0"]);

    let start = std::time::Instant::now();
    let res = run_bounded_probe_command_cancellable(&mut cmd, Duration::from_secs(5), || false);
    super::INJECT_WAITID_EPERM.store(false, std::sync::atomic::Ordering::SeqCst);

    assert!(
        res.is_ok(),
        "Probe command should succeed under injected waitid EPERM: {:?}",
        res
    );
    let out = res.unwrap();
    assert!(out.status.success());
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "Zombie fallback and PG cleanup must complete promptly without hanging on descendant"
    );
}

#[tokio::test]
async fn test_script_failure_triggers_receipt_and_blueprint_rollback_when_services_restart_cleanly()
{
    let (root, _path, conn, _) = test_fixture();
    let sonarr_dir = root.join("var/lib/sonarr");
    std::fs::create_dir_all(&sonarr_dir).unwrap();
    let opt_sonarr = root.join("opt/sonarr");
    std::fs::create_dir_all(&opt_sonarr).unwrap();

    let receipt_file = opt_sonarr.join(".af-version");
    std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

    let config_file = sonarr_dir.join("config.xml");
    std::fs::write(&config_file, b"<Config><Port>8989</Port></Config>\n").unwrap();

    let uncommitted_receipt = root.join("var/lib/sonarr/.af-version");

    let package = Package {
        name: "sonarr".into(),
        service_name: "sonarr".into(),
        service_type: "systemd".into(),
        default_port: 8989,
        ..Default::default()
    };

    struct FailScriptBackend {
        receipt_file: PathBuf,
        uncommitted_receipt: PathBuf,
        config_file: PathBuf,
    }
    impl LifecycleBackend for FailScriptBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8989
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(false) })
        }
        fn control<'a>(&'a self, _: &'a str, _: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            let receipt_path = self.receipt_file.clone();
            let uncommitted_path = self.uncommitted_receipt.clone();
            let config_path = self.config_file.clone();
            Box::pin(async move {
                std::fs::write(&receipt_path, b"2.0.0-uncommitted\n").unwrap();
                std::fs::create_dir_all(uncommitted_path.parent().unwrap()).unwrap();
                std::fs::write(&uncommitted_path, b"2.0.0-uncommitted\n").unwrap();
                std::fs::write(&config_path, b"<Config><Port>9999</Port></Config>\n").unwrap();
                anyhow::bail!("installer script failed deliberately")
            })
        }
    }

    let backend = FailScriptBackend {
        receipt_file: receipt_file.clone(),
        uncommitted_receipt: uncommitted_receipt.clone(),
        config_file: config_file.clone(),
    };

    let req = PackageRunnerRequest {
        package_id: "sonarr".into(),
        action: "install".into(),
        script_name: "installpackage-sonarr".into(),
        app_port: 8989,
        ..Default::default()
    };

    let mut op = CoordinatedOperation::admit(conn, req, package, vec!["sonarr".into()]).unwrap();
    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(
        receipt.status, "failed",
        "Execute must return failed receipt when installer script fails"
    );

    // Verify receipt and blueprint files were restored
    assert_eq!(
        std::fs::read_to_string(&receipt_file).unwrap(),
        "1.0.0\n",
        "Pre-existing receipt must be restored on script failure"
    );
    assert!(
        !uncommitted_receipt.exists(),
        "Newly created receipt must be deleted on script failure"
    );
    assert_eq!(
        std::fs::read_to_string(&config_file).unwrap(),
        "<Config><Port>8989</Port></Config>\n",
        "Pre-existing blueprint config must be restored on script failure"
    );

    let (status, failure_category, sanitized_summary): (String, String, Option<String>) = op
        .conn
        .query_row(
            "SELECT status, failure_category, sanitized_summary FROM package_lifecycle_jobs WHERE package_id='sonarr'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(failure_category, "installer");
    assert!(
        sanitized_summary
            .as_deref()
            .unwrap_or("")
            .contains("installer script failed deliberately"),
        "Diagnostics must retain script failure: {:?}",
        sanitized_summary
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn test_snapshot_blueprint_targets_symlink_or_oversized_fails_closed() {
    let temp_dir = std::env::temp_dir().join(format!("af-test-bp-snap-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let sonarr_dir = temp_dir.join("var/lib/sonarr");
    std::fs::create_dir_all(&sonarr_dir).unwrap();
    let config_target = sonarr_dir.join("config.xml");

    // 1. Symlink target
    let victim_file = temp_dir.join("victim.txt");
    std::fs::write(&victim_file, b"victim content").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&victim_file, &config_target).unwrap();

    let snap_res = snapshot_blueprint_targets("sonarr", &env_cfg);
    assert!(
        snap_res.is_err(),
        "Snapshotting a symlink blueprint target must fail closed: {:?}",
        snap_res
    );
    let err_msg = snap_res.unwrap_err();
    assert!(
        err_msg.to_ascii_lowercase().contains("symlink"),
        "Error must mention symlink: {}",
        err_msg
    );
    // Verify victim file and symlink were NOT deleted
    assert!(victim_file.is_file(), "Victim file must not be deleted");
    assert!(
        std::fs::symlink_metadata(&config_target)
            .unwrap()
            .file_type()
            .is_symlink(),
        "Symlink must not be unlinked"
    );

    // 2. Oversized file (> 1 MiB)
    let _ = std::fs::remove_file(&config_target);
    let oversized_buf = vec![0x41u8; 2 * 1024 * 1024];
    std::fs::write(&config_target, &oversized_buf).unwrap();

    let snap_res_over = snapshot_blueprint_targets("sonarr", &env_cfg);
    assert!(
        snap_res_over.is_err(),
        "Snapshotting an oversized blueprint target must fail closed: {:?}",
        snap_res_over
    );
    let over_err = snap_res_over.unwrap_err();
    assert!(
        over_err.contains("exceeds") && over_err.contains("byte limit"),
        "Error must mention length cap: {}",
        over_err
    );
    assert!(
        config_target.is_file(),
        "Oversized file must not be deleted"
    );
    assert_eq!(
        std::fs::metadata(&config_target).unwrap().len(),
        2 * 1024 * 1024
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_restore_preserves_exact_permissions_and_ownership() {
    let temp_dir = std::env::temp_dir().join(format!("af-test-perms-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let secret_file = temp_dir.join("secret.conf");
    std::fs::write(&secret_file, b"SECRET_KEY=confidential_data_12345").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let state = read_file_entry_bounded_nofollow(&secret_file, 1024 * 1024)
        .expect("read_file_entry_bounded_nofollow must succeed")
        .expect("file must be present");
    assert_eq!(state.mode & 0o7777, 0o600);
    let expected_uid = state.uid;
    let expected_gid = state.gid;

    let snap = FileSnapshot {
        path: secret_file.clone(),
        state: Some(state),
    };

    // Mutate file to 0o644 with altered content
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    std::fs::write(&secret_file, b"LEAKED_AND_MUTATED").unwrap();

    // Restore file
    let restore_res = restore_candidate_receipts(&[snap]);
    assert!(
        restore_res.is_ok(),
        "Restoration must succeed: {:?}",
        restore_res
    );

    // Verify content
    assert_eq!(
        std::fs::read(&secret_file).unwrap(),
        b"SECRET_KEY=confidential_data_12345"
    );

    // Verify permissions are exactly 0o600, NEVER 0o644!
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&secret_file).unwrap();
        let mode = meta.permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600, "Restored file must have 0o600 mode, not 0o644");
        assert_eq!(meta.uid(), expected_uid, "Restored file must preserve UID");
        assert_eq!(meta.gid(), expected_gid, "Restored file must preserve GID");
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_systemd_unit_exec_start_outside_service_section_rejected() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-unit-section-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let systemd_dir = temp_dir.join("etc/systemd/system");
    std::fs::create_dir_all(&systemd_dir).unwrap();
    let unit_file = systemd_dir.join("badsection.service");

    // ExecStart placed inside [Unit] section
    let unit_placement = "[Unit]\nDescription=Bad Unit Section Placement\nExecStart=/bin/true\n\n[Install]\nWantedBy=multi-user.target\n";
    std::fs::write(&unit_file, unit_placement.as_bytes()).unwrap();
    assert!(
        !validate_systemd_unit_runtime_evidence(unit_placement, "badsection", &env_cfg),
        "validate_systemd_unit_runtime_evidence must reject ExecStart placed in [Unit]"
    );
    assert!(
        !has_independent_runtime_evidence("badsection", &env_cfg),
        "has_independent_runtime_evidence must reject service with ExecStart placed in [Unit]"
    );

    // ExecStart placed inside [Install] section
    let install_placement = "[Unit]\nDescription=Bad Unit Section Placement\n\n[Install]\nWantedBy=multi-user.target\nExecStart=/bin/true\n";
    std::fs::write(&unit_file, install_placement.as_bytes()).unwrap();
    assert!(
        !validate_systemd_unit_runtime_evidence(install_placement, "badsection", &env_cfg),
        "validate_systemd_unit_runtime_evidence must reject ExecStart placed in [Install]"
    );

    // ExecStart properly placed inside [Service] section
    let service_placement = "[Unit]\nDescription=Good Unit\n\n[Service]\nExecStart=/bin/true\n\n[Install]\nWantedBy=multi-user.target\n";
    std::fs::write(&unit_file, service_placement.as_bytes()).unwrap();
    assert!(
        validate_systemd_unit_runtime_evidence(service_placement, "badsection", &env_cfg),
        "validate_systemd_unit_runtime_evidence must accept ExecStart placed in [Service]"
    );
    assert!(
        has_independent_runtime_evidence("badsection", &env_cfg),
        "has_independent_runtime_evidence must accept service with ExecStart placed in [Service]"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_post_commit_rollback_error_persisted_in_diagnostics() {
    let (root, _path, conn, package) = test_fixture();
    let req = PackageRunnerRequest {
        package_id: "syncthing".into(),
        action: "install".into(),
        script_name: "installpackage-syncthing".into(),
        app_port: 8384,
        ..Default::default()
    };

    struct PostCommitFailBackend {
        root: PathBuf,
    }
    impl LifecycleBackend for PostCommitFailBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8384
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(false) })
        }
        fn control<'a>(&'a self, _: &'a str, _: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            let r = self.root.clone();
            Box::pin(async move {
                // Create var/lib as directory with syncthing as regular file (causing ENOTDIR on rollback)
                let var_lib = r.join("var/lib");
                std::fs::create_dir_all(&var_lib).unwrap();
                let syncthing_file = var_lib.join("syncthing");
                let _ = std::fs::remove_dir_all(&syncthing_file);
                std::fs::write(&syncthing_file, b"blocking regular file").unwrap();
                Ok(())
            })
        }
    }

    let backend = PostCommitFailBackend { root: root.clone() };
    let mut op = CoordinatedOperation::admit(conn, req, package, vec!["syncthing".into()]).unwrap();

    // Drop the settings table so post_commit fails when trying to synchronize ingress
    op.conn.execute("DROP TABLE settings", []).unwrap();

    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(
        receipt.status, "failed",
        "Execute must mark receipt as failed when post-commit sync fails"
    );

    let (status, category, diag): (String, String, Option<String>) = op
        .conn
        .query_row(
            "SELECT status, failure_category, sanitized_summary FROM package_lifecycle_jobs WHERE package_id='syncthing'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(category, "configuration");
    let summary = diag.expect("sanitized_summary must be persisted");
    assert!(
        summary.contains("receipt restoration error:"),
        "Diagnostic summary must preserve post-commit rollback error: {}",
        summary
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn test_validate_systemd_unit_runtime_evidence_exact_key_matching() {
    let env_cfg = crate::PackageExecutionEnv::default();

    // 1. ExecStartPre must NEVER be accepted as ExecStart
    let unit_pre = "[Service]\nExecStartPre=/bin/true\n";
    assert!(
        !validate_systemd_unit_runtime_evidence(unit_pre, "testpkg", &env_cfg),
        "ExecStartPre must not be accepted as ExecStart"
    );

    // 2. ExecStartPost must NEVER be accepted as ExecStart
    let unit_post = "[Service]\nExecStartPost=/bin/true\n";
    assert!(
        !validate_systemd_unit_runtime_evidence(unit_post, "testpkg", &env_cfg),
        "ExecStartPost must not be accepted as ExecStart"
    );

    // 3. Lowercase execstart must be rejected (exact case-sensitive matching required)
    let unit_lower = "[Service]\nexecstart=/bin/true\n";
    assert!(
        !validate_systemd_unit_runtime_evidence(unit_lower, "testpkg", &env_cfg),
        "Lowercase execstart must be rejected"
    );

    // 4. Lowercase execstartpre must be rejected
    let unit_lower_pre = "[Service]\nexecstartpre=/bin/true\n";
    assert!(
        !validate_systemd_unit_runtime_evidence(unit_lower_pre, "testpkg", &env_cfg),
        "Lowercase execstartpre must be rejected"
    );

    // 5. Valid ExecStart in [Service] with valid executable is accepted
    let unit_valid = "[Service]\nExecStart=/bin/true\n";
    assert!(
        validate_systemd_unit_runtime_evidence(unit_valid, "testpkg", &env_cfg),
        "Exact ExecStart in [Service] must be accepted"
    );
}

#[test]
fn test_sanitize_lifecycle_field_attached_curl_and_comma_credentials() {
    // Attached curl -u credentials
    let curl_attached = "curl -uadmin:supersecret https://example.com/api";
    let sanitized_attached = sanitize_lifecycle_field(curl_attached);
    assert!(
        !sanitized_attached.contains("supersecret"),
        "Attached curl password must be redacted"
    );
    assert!(
        !sanitized_attached.contains("admin:supersecret"),
        "Attached curl credentials must be redacted"
    );
    assert_eq!(
        sanitized_attached,
        "curl -u[REDACTED] https://example.com/api"
    );

    // Attached curl -u credentials with quotes
    let curl_quoted = "curl -u\"admin:supersecret\" https://example.com/api";
    let sanitized_quoted = sanitize_lifecycle_field(curl_quoted);
    assert!(
        !sanitized_quoted.contains("supersecret"),
        "Quoted curl password must be redacted"
    );
    assert_eq!(
        sanitized_quoted,
        "curl -u[REDACTED] https://example.com/api"
    );

    // Attached curl -u at end of command or line
    let curl_bare = "curl -uadmin:supersecret";
    let sanitized_bare = sanitize_lifecycle_field(curl_bare);
    assert_eq!(sanitized_bare, "curl -u[REDACTED]");

    // Attached curl with comma in credentials
    let curl_comma = "curl -uadmin:pass,word https://example.com";
    let sanitized_curl_comma = sanitize_lifecycle_field(curl_comma);
    assert!(
        !sanitized_curl_comma.contains("pass,word"),
        "Comma-containing curl credential must be redacted"
    );
    assert_eq!(
        sanitized_curl_comma,
        "curl -u[REDACTED] https://example.com"
    );

    // Unquoted credentials containing commas
    let input_comma = "Failed: password=part1,part2, status=500";
    let sanitized_comma = sanitize_lifecycle_field(input_comma);
    assert!(!sanitized_comma.contains("part1"), "part1 must be redacted");
    assert!(!sanitized_comma.contains("part2"), "part2 must be redacted");
    assert!(sanitized_comma.contains("password=[REDACTED]"));
    assert!(sanitized_comma.contains("status=500"));

    // Comma-separated key-value credentials: both password and token redacted cleanly
    let input_multi = "error: password=part1,part2, token: secret_token_xyz; details";
    let sanitized_multi = sanitize_lifecycle_field(input_multi);
    assert!(!sanitized_multi.contains("part1"));
    assert!(!sanitized_multi.contains("part2"));
    assert!(!sanitized_multi.contains("secret_token_xyz"));
    assert_eq!(
        sanitized_multi,
        "error: password=[REDACTED], token: [REDACTED]; details"
    );

    // Semicolon-delimited unquoted credentials with commas
    let input_semi = "password=part1,part2; token=token1,token2; url=https://example.com";
    let sanitized_semi = sanitize_lifecycle_field(input_semi);
    assert!(!sanitized_semi.contains("part1"));
    assert!(!sanitized_semi.contains("part2"));
    assert!(!sanitized_semi.contains("token1"));
    assert!(!sanitized_semi.contains("token2"));
    assert_eq!(
        sanitized_semi,
        "password=[REDACTED]; token=[REDACTED]; url=https://example.com"
    );
}

#[tokio::test]
async fn test_coordinated_operation_quiesce_restore_restart_order() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    // Sub-scenario A: Script failure order
    // Expected: stop -> script -> stop -> rollback -> start -> active
    {
        let (root, _path, conn, _) = test_fixture();
        let opt_dir = root.join("opt/syncthing-order-script-fail");
        std::fs::create_dir_all(&opt_dir).unwrap();
        let receipt_file = opt_dir.join(".af-version");
        std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

        let package = Package {
            name: "syncthing-order-script-fail".into(),
            service_name: "syncthing-order-script-fail".into(),
            service_type: "systemd".into(),
            default_port: 8384,
            ..Default::default()
        };

        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let events_for_hook = events.clone();

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |snaps| {
            if snaps.iter().any(|s| {
                s.path
                    .to_string_lossy()
                    .contains("syncthing-order-script-fail")
            }) {
                events_for_hook.lock().unwrap().push("rollback".to_string());
            }
        }));

        struct OrderScriptFailBackend {
            events: Arc<std::sync::Mutex<Vec<String>>>,
            receipt_file: PathBuf,
            receipt_at_start: Arc<std::sync::Mutex<Option<String>>>,
        }
        impl LifecycleBackend for OrderScriptFailBackend {
            fn runtime_port(&self, _: &str) -> i32 {
                8384
            }
            fn available_port(&self, _: i32) -> bool {
                true
            }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                let rolled_back = self
                    .events
                    .lock()
                    .unwrap()
                    .contains(&"rollback".to_string());
                if rolled_back {
                    self.events.lock().unwrap().push("active".to_string());
                }
                Box::pin(async { Ok(true) })
            }
            fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                let events = self.events.lock().unwrap();
                let last_stop = events.iter().rposition(|e| e == "stop");
                let last_start = events.iter().rposition(|e| e == "start");
                let is_q = match (last_stop, last_start) {
                    (Some(s), Some(st)) => s > st,
                    (Some(_), None) => true,
                    _ => false,
                };
                Box::pin(async move { Ok(is_q) })
            }
            fn control<'a>(
                &'a self,
                _: &'a str,
                action: &'a str,
                _: &'a str,
            ) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push(action.to_string());
                if action == "start" {
                    let content = std::fs::read_to_string(&self.receipt_file).ok();
                    *self.receipt_at_start.lock().unwrap() = content;
                }
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(
                &'a self,
                _: &'a PackageRunnerRequest,
                _: &'a mpsc::Sender<String>,
            ) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push("script".to_string());
                let rf = self.receipt_file.clone();
                Box::pin(async move {
                    std::fs::write(&rf, b"2.0.0-broken\n").unwrap();
                    anyhow::bail!("simulated installer failure")
                })
            }
        }

        let receipt_at_start = Arc::new(std::sync::Mutex::new(None));
        let backend = OrderScriptFailBackend {
            events: events.clone(),
            receipt_file: receipt_file.clone(),
            receipt_at_start: receipt_at_start.clone(),
        };

        let req = PackageRunnerRequest {
            package_id: "syncthing-order-script-fail".into(),
            action: "update".into(),
            script_name: "updatepackage-syncthing".into(),
            app_port: 8384,
            expected_target_version: Some("2.0.0".into()),
            ..Default::default()
        };

        let mut op = CoordinatedOperation::admit(
            conn,
            req,
            package,
            vec!["syncthing-order-script-fail".into()],
        )
        .unwrap();
        let (sender, _receiver) = mpsc::channel(32);
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed");

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

        let recorded = events.lock().unwrap().clone();
        assert_eq!(
            recorded,
            vec!["stop", "script", "stop", "rollback", "start", "active"],
            "Script failure must follow exact order: stop -> script -> stop -> rollback -> start -> active"
        );

        // Assert rollback_operation_state ALWAYS happens before final service restart and verification
        let rollback_pos = recorded.iter().position(|e| e == "rollback").unwrap();
        let final_start_pos = recorded.iter().rposition(|e| e == "start").unwrap();
        let final_active_pos = recorded.iter().rposition(|e| e == "active").unwrap();
        assert!(
            rollback_pos < final_start_pos,
            "rollback_operation_state MUST occur before final service restart"
        );
        assert!(
            final_start_pos < final_active_pos,
            "Final service restart MUST occur before active verification"
        );

        // Verify receipt was restored on disk BEFORE start was called!
        assert_eq!(
            receipt_at_start.lock().unwrap().as_deref(),
            Some("1.0.0\n"),
            "Receipt on disk must be restored before service restart executes"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    // Sub-scenario B: Certification failure order
    // Expected: stop -> script -> start -> certify_fail -> stop -> rollback -> start -> active
    {
        let (root, _path, conn, _) = test_fixture();
        let opt_dir = root.join("opt/syncthing-order-cert-fail");
        std::fs::create_dir_all(&opt_dir).unwrap();
        let receipt_file = opt_dir.join(".af-version");
        std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let events_for_rb = events.clone();
        let events_for_cf = events.clone();

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |snaps| {
            if snaps.iter().any(|s| {
                s.path
                    .to_string_lossy()
                    .contains("syncthing-order-cert-fail")
            }) {
                events_for_rb.lock().unwrap().push("rollback".to_string());
            }
        }));
        *super::TEST_CERTIFY_FAIL_HOOK.lock().unwrap() = Some(Box::new(move |pkg| {
            if pkg == "syncthing-order-cert-fail" {
                events_for_cf
                    .lock()
                    .unwrap()
                    .push("certify_fail".to_string());
            }
        }));

        struct OrderCertFailBackend {
            events: Arc<std::sync::Mutex<Vec<String>>>,
            receipt_file: PathBuf,
            receipts_at_start: Arc<std::sync::Mutex<Vec<String>>>,
        }
        impl LifecycleBackend for OrderCertFailBackend {
            fn runtime_port(&self, _: &str) -> i32 {
                8384
            }
            fn available_port(&self, _: i32) -> bool {
                true
            }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                let rolled_back = self
                    .events
                    .lock()
                    .unwrap()
                    .contains(&"rollback".to_string());
                if rolled_back {
                    self.events.lock().unwrap().push("active".to_string());
                }
                Box::pin(async { Ok(true) })
            }
            fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                let events = self.events.lock().unwrap();
                let last_stop = events.iter().rposition(|e| e == "stop");
                let last_start = events.iter().rposition(|e| e == "start");
                let is_q = match (last_stop, last_start) {
                    (Some(s), Some(st)) => s > st,
                    (Some(_), None) => true,
                    _ => false,
                };
                Box::pin(async move { Ok(is_q) })
            }
            fn control<'a>(
                &'a self,
                _: &'a str,
                action: &'a str,
                _: &'a str,
            ) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push(action.to_string());
                if action == "start" {
                    let content = std::fs::read_to_string(&self.receipt_file).unwrap_or_default();
                    self.receipts_at_start.lock().unwrap().push(content);
                }
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(
                &'a self,
                _: &'a PackageRunnerRequest,
                _: &'a mpsc::Sender<String>,
            ) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push("script".to_string());
                let rf = self.receipt_file.clone();
                Box::pin(async move {
                    // Installer succeeds but writes version 1.5.0 which mismatches expected target 2.0.0
                    std::fs::write(&rf, b"1.5.0\n").unwrap();
                    Ok(())
                })
            }
        }

        let receipts_at_start = Arc::new(std::sync::Mutex::new(Vec::new()));
        let backend = OrderCertFailBackend {
            events: events.clone(),
            receipt_file: receipt_file.clone(),
            receipts_at_start: receipts_at_start.clone(),
        };

        let syncthing_package = Package {
            name: "syncthing-order-cert-fail".into(),
            service_name: "syncthing-order-cert-fail".into(),
            service_type: "systemd".into(),
            default_port: 8384,
            ..Default::default()
        };

        let req = PackageRunnerRequest {
            package_id: "syncthing-order-cert-fail".into(),
            action: "update".into(),
            script_name: "updatepackage-syncthing".into(),
            app_port: 8384,
            expected_target_version: Some("2.0.0".into()),
            ..Default::default()
        };

        let mut op = CoordinatedOperation::admit(
            conn,
            req,
            syncthing_package,
            vec!["syncthing-order-cert-fail".into()],
        )
        .unwrap();
        let (sender, _receiver) = mpsc::channel(32);
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed");

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;
        *super::TEST_CERTIFY_FAIL_HOOK.lock().unwrap() = None;

        let recorded = events.lock().unwrap().clone();
        assert_eq!(
            recorded,
            vec!["stop", "script", "start", "certify_fail", "stop", "rollback", "start", "active"],
            "Certification failure must follow exact order: stop -> script -> start -> certify_fail -> stop -> rollback -> start -> active"
        );

        // Assert rollback_operation_state ALWAYS happens before final service restart and verification
        let rollback_pos = recorded.iter().position(|e| e == "rollback").unwrap();
        let final_start_pos = recorded.iter().rposition(|e| e == "start").unwrap();
        let final_active_pos = recorded.iter().rposition(|e| e == "active").unwrap();
        assert!(
            rollback_pos < final_start_pos,
            "rollback_operation_state MUST occur before final service restart"
        );
        assert!(
            final_start_pos < final_active_pos,
            "Final service restart MUST occur before active verification"
        );

        // First start saw installer version 1.5.0, but final restart saw restored version 1.0.0!
        let starts = receipts_at_start.lock().unwrap().clone();
        assert_eq!(starts.len(), 2);
        assert_eq!(starts[0], "1.5.0\n");
        assert_eq!(
            starts[1], "1.0.0\n",
            "Final service restart must see restored pre-op receipt"
        );

        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn test_parse_systemd_active_state_only_active_is_true() {
    // "active" must be confirmed active
    assert!(super::parse_systemd_active_state("active").unwrap());
    assert!(super::parse_systemd_active_state("  active  \n").unwrap());

    // Transitional and stopped states must return Ok(false)
    assert!(!super::parse_systemd_active_state("activating").unwrap());
    assert!(!super::parse_systemd_active_state("deactivating").unwrap());
    assert!(!super::parse_systemd_active_state("reloading").unwrap());
    assert!(!super::parse_systemd_active_state("inactive").unwrap());
    assert!(!super::parse_systemd_active_state("failed").unwrap());

    // Unknown states must return Err
    assert!(super::parse_systemd_active_state("unknown").is_err());
    assert!(super::parse_systemd_active_state("maintenance").is_err());
    assert!(super::parse_systemd_active_state("").is_err());
}

#[test]
fn test_parse_systemd_quiesced_state_inactive_and_failed_are_true() {
    // Genuinely quiescent states must return Ok(true)
    assert!(super::parse_systemd_quiesced_state("inactive").unwrap());
    assert!(super::parse_systemd_quiesced_state("  inactive  \n").unwrap());
    assert!(super::parse_systemd_quiesced_state("failed").unwrap());

    // Live and transitional states must return Ok(false)
    assert!(!super::parse_systemd_quiesced_state("active").unwrap());
    assert!(!super::parse_systemd_quiesced_state("activating").unwrap());
    assert!(!super::parse_systemd_quiesced_state("deactivating").unwrap());
    assert!(!super::parse_systemd_quiesced_state("reloading").unwrap());

    // Unknown states must return Err
    assert!(super::parse_systemd_quiesced_state("unknown").is_err());
    assert!(super::parse_systemd_quiesced_state("maintenance").is_err());
    assert!(super::parse_systemd_quiesced_state("").is_err());
}

#[test]
fn test_is_incomplete_rollback_error_hyphenated_and_diagnostics() {
    assert!(is_incomplete_rollback_error("incomplete-rollback"));
    assert!(is_incomplete_rollback_error("incomplete rollback"));
    assert!(is_incomplete_rollback_error("incomplete_rollback"));
    assert!(is_incomplete_rollback_error("Rclone rollback aborted because service quiescence failed; preserving recovery archive ... (incomplete-rollback)"));
    assert!(is_incomplete_rollback_error(
        "Application recovery is incomplete; recovery backup preserved"
    ));
    assert!(is_incomplete_rollback_error(
        "Rollback incomplete; recovery backup preserved"
    ));
    assert!(is_incomplete_rollback_error(
        "Failed to stop unit sonarr.service"
    ));

    // Unrelated errors must return false
    assert!(!is_incomplete_rollback_error("connection reset by peer"));
    assert!(!is_incomplete_rollback_error("file not found"));
}

#[tokio::test]
async fn test_restore_and_restart_units_quiesce_failure_gates_restoration_and_restart() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    struct QuiesceFailBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
    }
    impl LifecycleBackend for QuiesceFailBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8080
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            self.events.lock().unwrap().push("active".to_string());
            Box::pin(async { Ok(true) })
        }
        fn control<'a>(
            &'a self,
            _: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push(action.to_string());
            if action == "stop" {
                Box::pin(async { anyhow::bail!("systemctl stop failed deliberately") })
            } else {
                Box::pin(async { Ok(()) })
            }
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let backend = QuiesceFailBackend {
        events: events.clone(),
    };

    let rollback_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let rb_called_hook = rollback_called.clone();
    *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |_| {
        rb_called_hook.store(true, std::sync::atomic::Ordering::SeqCst);
    }));

    let stopped = vec!["mock-unit.service".to_string()];
    let mut receipt_restore_error = None;
    let mut restart_failures = Vec::new();

    CoordinatedOperation::restore_and_restart_units(
        &backend,
        "job-quiesce-fail",
        "mockpkg",
        &stopped,
        &stopped,
        &[],
        &[],
        &mut receipt_restore_error,
        &mut restart_failures,
        false,
        true,
    )
    .await;

    *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

    // 1. rollback_operation_state must NOT have been called!
    assert!(
        !rollback_called.load(std::sync::atomic::Ordering::SeqCst),
        "Rollback must be gated on successful quiescence"
    );

    // 2. Services must NOT have been restarted!
    let recorded = events.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["stop"],
        "Backend must only receive stop, never start or active verification"
    );

    // 3. receipt_restore_error must indicate quiescence failure
    let r_err =
        receipt_restore_error.expect("receipt_restore_error must be set on quiesce failure");
    assert!(r_err.contains(
        "Skipped snapshot restoration because service quiescence failed (incomplete-rollback)"
    ));

    // 4. restart_failures must contain the stop failure
    assert!(!restart_failures.is_empty());
    assert!(restart_failures[0].contains("stop before restoration failed"));
}

#[tokio::test]
async fn test_restore_and_restart_units_snapshot_restore_failure_gates_restart() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    struct SnapshotFailBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
    }
    impl LifecycleBackend for SnapshotFailBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8080
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            self.events.lock().unwrap().push("active".to_string());
            Box::pin(async { Ok(true) })
        }
        fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
        }
        fn control<'a>(
            &'a self,
            _: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push(action.to_string());
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let temp_dir =
        std::env::temp_dir().join(format!("af-test-snap-fail-gate-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let blocking_file = temp_dir.join("block");
    std::fs::write(&blocking_file, b"file").unwrap();
    // Path whose parent is a regular file will fail stepwise directory traversal during restoration!
    let bad_snap = FileSnapshot::absent(blocking_file.join(".af-version"));

    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let backend = SnapshotFailBackend {
        events: events.clone(),
    };

    let stopped = vec!["mock-unit.service".to_string()];
    let mut receipt_restore_error = None;
    let mut restart_failures = Vec::new();

    CoordinatedOperation::restore_and_restart_units(
        &backend,
        "job-snap-fail",
        "mockpkg",
        &stopped,
        &stopped,
        &[bad_snap],
        &[],
        &mut receipt_restore_error,
        &mut restart_failures,
        false,
        true,
    )
    .await;

    let _ = std::fs::remove_dir_all(&temp_dir);

    // 1. Backend must have stopped the unit, but NEVER called start or active
    let recorded = events.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["stop"],
        "Backend must not call start after snapshot restoration failure"
    );

    // 2. receipt_restore_error must be populated
    assert!(receipt_restore_error.is_some());

    // 3. restart_failures must record refusal to restart
    assert!(restart_failures.iter().any(|f| f
        .contains("Refusing to restart pre-stopped service after snapshot restoration failure")));
}

#[tokio::test]
async fn test_restore_and_restart_units_incomplete_rollback_gates_restart() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    struct IncRollbackBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
    }
    impl LifecycleBackend for IncRollbackBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8080
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            self.events.lock().unwrap().push("active".to_string());
            Box::pin(async { Ok(true) })
        }
        fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
        }
        fn control<'a>(
            &'a self,
            _: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push(action.to_string());
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let backend = IncRollbackBackend {
        events: events.clone(),
    };

    let stopped = vec!["mock-unit.service".to_string()];
    let mut receipt_restore_error = None;
    let mut restart_failures = Vec::new();

    CoordinatedOperation::restore_and_restart_units(
        &backend,
        "job-inc-rb",
        "mockpkg",
        &stopped,
        &stopped,
        &[],
        &[],
        &mut receipt_restore_error,
        &mut restart_failures,
        true, // incomplete_rollback = true
        true,
    )
    .await;

    // 1. Backend must have stopped the unit, but NEVER called start or active
    let recorded = events.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["stop"],
        "Backend must not call start after incomplete rollback"
    );

    // 2. restart_failures must record refusal to restart
    assert!(restart_failures
        .iter()
        .any(|f| f.contains("Refusing to restart pre-stopped service after incomplete rollback")));
}

#[tokio::test]
async fn test_skipped_runtime_restoration_preserves_recovery_snapshot() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    struct RecoveryBlockedBackend {
        quiescent: bool,
        events: std::sync::Mutex<Vec<String>>,
    }
    impl LifecycleBackend for RecoveryBlockedBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8080
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            self.events.lock().unwrap().push("active".to_string());
            Box::pin(async { Ok(true) })
        }
        fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async move { Ok(self.quiescent) })
        }
        fn control<'a>(
            &'a self,
            _: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push(action.to_string());
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    for (quiescent, incomplete_rollback) in [(false, false), (true, true)] {
        let root =
            std::env::temp_dir().join(format!("af-test-blocked-recovery-{}", uuid::Uuid::new_v4()));
        let runtime = root.join("opt/sonarr");
        std::fs::create_dir_all(&runtime).unwrap();
        let live_file = runtime.join("database.db");
        std::fs::write(&live_file, b"original-database").unwrap();
        let env_cfg = crate::PackageExecutionEnv::isolated(&root);
        let snapshot = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false).unwrap();
        let backup_root = snapshot.backup_root.clone();
        let backup_file = snapshot
            .entries
            .iter()
            .find_map(|entry| match entry {
                RuntimeSnapshotEntry::Directory {
                    target_path,
                    backup_path,
                    ..
                } if target_path == &runtime => Some(backup_path.join("database.db")),
                _ => None,
            })
            .expect("runtime directory must be captured");
        std::fs::write(&live_file, b"installer-modified-database").unwrap();
        let backend = RecoveryBlockedBackend {
            quiescent,
            events: std::sync::Mutex::new(Vec::new()),
        };
        let units = vec!["sonarr.service".to_string()];
        let mut receipt_restore_error = None;
        let mut restart_failures = Vec::new();

        CoordinatedOperation::restore_and_restart_units_with_runtime(
            &backend,
            "job-blocked-recovery",
            "sonarr",
            &units,
            &units,
            &[],
            &[],
            &mut receipt_restore_error,
            &mut restart_failures,
            incomplete_rollback,
            true,
            Some(snapshot),
        )
        .await;

        assert_eq!(*backend.events.lock().unwrap(), vec!["stop"]);
        assert_eq!(
            std::fs::read(&live_file).unwrap(),
            b"installer-modified-database"
        );
        assert!(!restart_failures.is_empty());
        if quiescent {
            assert!(receipt_restore_error.is_none());
            assert!(restart_failures
                .iter()
                .any(|failure| failure.contains("incomplete rollback")));
        } else {
            assert!(receipt_restore_error.unwrap().contains("quiescence failed"));
        }
        assert!(backup_root.is_dir());
        assert_eq!(std::fs::read(&backup_file).unwrap(), b"original-database");
        force_remove_backup_tree(&root);
    }
}

#[tokio::test]
async fn test_rollback_quiesces_initially_inactive_unit_started_during_install() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    let (root, _path, conn, _) = test_fixture();
    let opt_dir = root.join("opt/test-multi-unit");
    std::fs::create_dir_all(&opt_dir).unwrap();
    let receipt_file = opt_dir.join(".af-version");
    std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

    let package = Package {
        name: "test-multi-unit".into(),
        service_name: "unit-a.service".into(),
        service_type: "systemd".into(),
        default_port: 8384,
        ..Default::default()
    };

    let unit_a_active = Arc::new(std::sync::Mutex::new(true));
    let unit_b_active = Arc::new(std::sync::Mutex::new(false));
    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    let hook_events = events.clone();
    let hook_a = unit_a_active.clone();
    let hook_b = unit_b_active.clone();

    *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |snaps| {
        if snaps
            .iter()
            .any(|s| s.path.to_string_lossy().contains("test-multi-unit"))
        {
            let a_is_active = *hook_a.lock().unwrap();
            let b_is_active = *hook_b.lock().unwrap();
            assert!(
                !a_is_active,
                "unit-a.service must be inactive BEFORE rollback_operation_state"
            );
            assert!(
                !b_is_active,
                "unit-b.service must be inactive BEFORE rollback_operation_state"
            );
            hook_events.lock().unwrap().push("rollback".to_string());
        }
    }));

    struct MultiUnitBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
        unit_a_active: Arc<std::sync::Mutex<bool>>,
        unit_b_active: Arc<std::sync::Mutex<bool>>,
    }

    impl LifecycleBackend for MultiUnitBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8384
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            let is_act = match unit {
                "unit-a.service" => *self.unit_a_active.lock().unwrap(),
                "unit-b.service" => *self.unit_b_active.lock().unwrap(),
                _ => false,
            };
            self.events
                .lock()
                .unwrap()
                .push(format!("active:{}:{}", unit, is_act));
            Box::pin(async move { Ok(is_act) })
        }
        fn control<'a>(
            &'a self,
            unit: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}:{}", action, unit));
            match action {
                "stop" => {
                    if unit == "unit-a.service" {
                        *self.unit_a_active.lock().unwrap() = false;
                    } else if unit == "unit-b.service" {
                        *self.unit_b_active.lock().unwrap() = false;
                    }
                }
                "start" => {
                    if unit == "unit-a.service" {
                        *self.unit_a_active.lock().unwrap() = true;
                    } else if unit == "unit-b.service" {
                        *self.unit_b_active.lock().unwrap() = true;
                    }
                }
                _ => {}
            }
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push("script".to_string());
            // Installer script starts initially-inactive unit-b.service
            *self.unit_b_active.lock().unwrap() = true;
            self.events
                .lock()
                .unwrap()
                .push("script_started:unit-b.service".to_string());
            // Then script fails
            Box::pin(async { anyhow::bail!("installer failed deliberately") })
        }
    }

    let backend = MultiUnitBackend {
        events: events.clone(),
        unit_a_active: unit_a_active.clone(),
        unit_b_active: unit_b_active.clone(),
    };

    let req = PackageRunnerRequest {
        package_id: "test-multi-unit".into(),
        action: "update".into(),
        script_name: "updatepackage-test-multi".into(),
        app_port: 8384,
        expected_target_version: Some("2.0.0".into()),
        ..Default::default()
    };

    let mut op = CoordinatedOperation::admit(
        conn,
        req,
        package,
        vec!["unit-a.service".into(), "unit-b.service".into()],
    )
    .unwrap();

    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "failed");

    *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

    let recorded = events.lock().unwrap().clone();

    // 1. Rollback must have occurred
    let rollback_pos = recorded
        .iter()
        .position(|e| e == "rollback")
        .expect("Rollback must be recorded");

    // 2. Both unit-a and unit-b must have been stopped BEFORE rollback
    let stop_a_quiesce = recorded[..rollback_pos]
        .iter()
        .rposition(|e| e == "stop:unit-a.service")
        .expect("unit-a must be stopped before rollback");
    let stop_b_quiesce = recorded[..rollback_pos]
        .iter()
        .rposition(|e| e == "stop:unit-b.service")
        .expect("unit-b must be stopped before rollback");
    assert!(stop_a_quiesce < rollback_pos);
    assert!(stop_b_quiesce < rollback_pos);

    // 3. ONLY unit-a.service must be restarted after rollback
    let starts_after_rollback: Vec<_> = recorded[rollback_pos..]
        .iter()
        .filter(|e| e.starts_with("start:"))
        .cloned()
        .collect();
    assert_eq!(
        starts_after_rollback,
        vec!["start:unit-a.service"],
        "Only initially-active unit-a must be restarted"
    );

    // 4. Verify final active states: unit-a is active, unit-b remains inactive
    assert!(
        *unit_a_active.lock().unwrap(),
        "unit-a must be active after restoration"
    );
    assert!(
        !*unit_b_active.lock().unwrap(),
        "unit-b must remain inactive after restoration"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_fresh_install_script_fail_quiesces_installer_started_unit() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    let (root, _path, conn, _) = test_fixture();
    // Genuine fresh install: no /opt/<package> directory or receipt on disk!

    let package = Package {
        name: "test-fresh-pkg".into(),
        service_name: "fresh-unit.service".into(),
        service_type: "systemd".into(),
        default_port: 8484,
        ..Default::default()
    };

    let fresh_unit_active = Arc::new(std::sync::Mutex::new(false));
    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    let hook_events = events.clone();
    let hook_unit = fresh_unit_active.clone();

    *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |snaps| {
        if snaps
            .iter()
            .any(|s| s.path.to_string_lossy().contains("test-fresh-pkg"))
        {
            let unit_is_active = *hook_unit.lock().unwrap();
            assert!(
                !unit_is_active,
                "fresh-unit.service must be quiesced/inactive BEFORE rollback_operation_state"
            );
            hook_events.lock().unwrap().push("rollback".to_string());
        }
    }));

    struct FreshInstallBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
        fresh_unit_active: Arc<std::sync::Mutex<bool>>,
    }

    impl LifecycleBackend for FreshInstallBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8484
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            let is_act = if unit == "fresh-unit.service" {
                *self.fresh_unit_active.lock().unwrap()
            } else {
                false
            };
            self.events
                .lock()
                .unwrap()
                .push(format!("active:{}:{}", unit, is_act));
            Box::pin(async move { Ok(is_act) })
        }
        fn control<'a>(
            &'a self,
            unit: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}:{}", action, unit));
            if action == "stop" && unit == "fresh-unit.service" {
                *self.fresh_unit_active.lock().unwrap() = false;
            } else if action == "start" && unit == "fresh-unit.service" {
                *self.fresh_unit_active.lock().unwrap() = true;
            }
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push("script".to_string());
            // Fresh installer starts fresh-unit.service during installation
            *self.fresh_unit_active.lock().unwrap() = true;
            self.events
                .lock()
                .unwrap()
                .push("installer_started:fresh-unit.service".to_string());
            // Then installer fails
            Box::pin(async { anyhow::bail!("fresh installer failed deliberately") })
        }
    }

    let backend = FreshInstallBackend {
        events: events.clone(),
        fresh_unit_active: fresh_unit_active.clone(),
    };

    let req = PackageRunnerRequest {
        package_id: "test-fresh-pkg".into(),
        action: "install".into(),
        script_name: "installpackage-test-fresh".into(),
        app_port: 8484,
        expected_target_version: Some("1.0.0".into()),
        ..Default::default()
    };

    let mut op =
        CoordinatedOperation::admit(conn, req, package, vec!["fresh-unit.service".into()]).unwrap();

    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "failed");

    *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

    let recorded = events.lock().unwrap().clone();

    // 1. Rollback must have occurred
    let rollback_pos = recorded
        .iter()
        .position(|e| e == "rollback")
        .expect("Rollback must be recorded");

    // 2. fresh-unit.service must have been stopped during rollback quiescence (before rollback hook)
    let stop_quiesce = recorded[..rollback_pos]
        .iter()
        .rposition(|e| e == "stop:fresh-unit.service")
        .expect("fresh-unit.service must be stopped during rollback quiescence");
    assert!(stop_quiesce < rollback_pos);

    // 3. fresh-unit.service must NOT have been started after rollback (it was not initially active)
    let starts_after_rollback: Vec<_> = recorded[rollback_pos..]
        .iter()
        .filter(|e| e.starts_with("start:"))
        .cloned()
        .collect();
    assert!(
        starts_after_rollback.is_empty(),
        "Fresh installer started unit must not be restarted after rollback"
    );

    // 4. Verify final active state: fresh-unit is inactive
    assert!(
        !*fresh_unit_active.lock().unwrap(),
        "fresh-unit.service must remain inactive"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_running_oneshot_quiesced_on_rollback_and_not_restarted() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    let (root, _path, conn, _) = test_fixture();
    let opt_dir = root.join("opt/test-oneshot");
    std::fs::create_dir_all(&opt_dir).unwrap();
    let receipt_file = opt_dir.join(".af-version");
    std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

    let package = Package {
        name: "test-oneshot".into(),
        service_name: "recyclarr.timer".into(),
        service_type: "systemd".into(),
        default_port: 8585,
        ..Default::default()
    };

    let timer_active = Arc::new(std::sync::Mutex::new(true));
    let oneshot_active = Arc::new(std::sync::Mutex::new(true)); // oneshot is currently running!
    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    let hook_events = events.clone();
    let hook_timer = timer_active.clone();
    let hook_oneshot = oneshot_active.clone();

    *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |snaps| {
        if snaps
            .iter()
            .any(|s| s.path.to_string_lossy().contains("test-oneshot"))
        {
            let timer_is_active = *hook_timer.lock().unwrap();
            let oneshot_is_active = *hook_oneshot.lock().unwrap();
            assert!(
                !timer_is_active,
                "recyclarr.timer must be inactive BEFORE rollback"
            );
            assert!(
                !oneshot_is_active,
                "recyclarr oneshot must be inactive BEFORE rollback"
            );
            hook_events.lock().unwrap().push("rollback".to_string());
        }
    }));

    struct OneshotBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
        timer_active: Arc<std::sync::Mutex<bool>>,
        oneshot_active: Arc<std::sync::Mutex<bool>>,
    }

    impl LifecycleBackend for OneshotBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8585
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            let is_act = match unit {
                "recyclarr.timer" => *self.timer_active.lock().unwrap(),
                "recyclarr" => *self.oneshot_active.lock().unwrap(),
                _ => false,
            };
            self.events
                .lock()
                .unwrap()
                .push(format!("active:{}:{}", unit, is_act));
            Box::pin(async move { Ok(is_act) })
        }
        fn control<'a>(
            &'a self,
            unit: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}:{}", action, unit));
            match action {
                "stop" => {
                    if unit == "recyclarr.timer" {
                        *self.timer_active.lock().unwrap() = false;
                    } else if unit == "recyclarr" {
                        *self.oneshot_active.lock().unwrap() = false;
                    }
                }
                "start" => {
                    if unit == "recyclarr.timer" {
                        *self.timer_active.lock().unwrap() = true;
                    } else if unit == "recyclarr" {
                        *self.oneshot_active.lock().unwrap() = true;
                    }
                }
                _ => {}
            }
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push("script".to_string());
            // Installer script starts running oneshot again
            *self.oneshot_active.lock().unwrap() = true;
            self.events
                .lock()
                .unwrap()
                .push("script_started:recyclarr".to_string());
            // Then fails
            Box::pin(async { anyhow::bail!("installer failed deliberately") })
        }
    }

    let backend = OneshotBackend {
        events: events.clone(),
        timer_active: timer_active.clone(),
        oneshot_active: oneshot_active.clone(),
    };

    let req = PackageRunnerRequest {
        package_id: "test-oneshot".into(),
        action: "update".into(),
        script_name: "updatepackage-test-oneshot".into(),
        app_port: 8585,
        expected_target_version: Some("2.0.0".into()),
        ..Default::default()
    };

    let mut op = CoordinatedOperation::admit(
        conn,
        req,
        package,
        vec!["recyclarr.timer".into(), "recyclarr".into()],
    )
    .unwrap();

    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "failed");

    *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

    let recorded = events.lock().unwrap().clone();

    // 1. Both timer and running oneshot must be stopped before script execution (pre-operation)
    let script_pos = recorded
        .iter()
        .position(|e| e == "script")
        .expect("Script must run");
    assert!(recorded[..script_pos].contains(&"stop:recyclarr.timer".to_string()));
    assert!(recorded[..script_pos].contains(&"stop:recyclarr".to_string()));

    // 2. Rollback must have occurred
    let rollback_pos = recorded
        .iter()
        .position(|e| e == "rollback")
        .expect("Rollback must be recorded");

    // 3. During rollback quiescence, running oneshot is stopped
    let stop_oneshot_quiesce = recorded[script_pos..rollback_pos]
        .iter()
        .rposition(|e| e == "stop:recyclarr");
    assert!(
        stop_oneshot_quiesce.is_some(),
        "Running oneshot recyclarr must be stopped during rollback quiescence"
    );

    // 4. ONLY recyclarr.timer is restarted after rollback; recyclarr oneshot is NOT restarted!
    let starts_after_rollback: Vec<_> = recorded[rollback_pos..]
        .iter()
        .filter(|e| e.starts_with("start:"))
        .cloned()
        .collect();
    assert_eq!(
        starts_after_rollback,
        vec!["start:recyclarr.timer".to_string()],
        "Only recyclarr.timer should be restarted, not oneshot"
    );

    // 5. Final states
    assert!(
        *timer_active.lock().unwrap(),
        "recyclarr.timer must be active"
    );
    assert!(
        !*oneshot_active.lock().unwrap(),
        "recyclarr oneshot must be inactive"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_unit_in_transitional_state_stopped_before_op_and_restarted_on_rollback() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    // Verify parse_systemd_active_state directly: only "active" is true
    assert!(parse_systemd_active_state("active").unwrap());
    assert!(!parse_systemd_active_state("activating").unwrap());
    assert!(!parse_systemd_active_state("reloading").unwrap());
    assert!(!parse_systemd_active_state("deactivating").unwrap());
    assert!(!parse_systemd_active_state("inactive").unwrap());
    assert!(!parse_systemd_active_state("failed").unwrap());

    // Verify parse_systemd_quiesced_state directly: only inactive/failed are true
    assert!(!parse_systemd_quiesced_state("active").unwrap());
    assert!(!parse_systemd_quiesced_state("activating").unwrap());
    assert!(!parse_systemd_quiesced_state("reloading").unwrap());
    assert!(!parse_systemd_quiesced_state("deactivating").unwrap());
    assert!(parse_systemd_quiesced_state("inactive").unwrap());
    assert!(parse_systemd_quiesced_state("failed").unwrap());

    let (root, _path, conn, _) = test_fixture();
    let opt_dir = root.join("opt/test-trans");
    std::fs::create_dir_all(&opt_dir).unwrap();
    let receipt_file = opt_dir.join(".af-version");
    std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

    let package = Package {
        name: "test-trans".into(),
        service_name: "trans-unit.service".into(),
        service_type: "systemd".into(),
        default_port: 8686,
        ..Default::default()
    };

    // Initially in transitional state: !quiescent() reports true because parse_systemd_quiesced_state treats activating as false
    let unit_state = Arc::new(std::sync::Mutex::new("activating".to_string()));
    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    struct TransBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
        unit_state: Arc<std::sync::Mutex<String>>,
    }

    impl LifecycleBackend for TransBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8686
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            let st = self.unit_state.lock().unwrap().clone();
            let is_act = parse_systemd_active_state(&st).unwrap();
            self.events
                .lock()
                .unwrap()
                .push(format!("active:{}:{}", unit, is_act));
            Box::pin(async move { Ok(is_act) })
        }
        fn quiescent<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            let st = self.unit_state.lock().unwrap().clone();
            let is_q = parse_systemd_quiesced_state(&st).unwrap();
            self.events
                .lock()
                .unwrap()
                .push(format!("quiescent:{}:{}", unit, is_q));
            Box::pin(async move { Ok(is_q) })
        }
        fn control<'a>(
            &'a self,
            unit: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}:{}", action, unit));
            match action {
                "stop" => {
                    *self.unit_state.lock().unwrap() = "inactive".to_string();
                }
                "start" => {
                    *self.unit_state.lock().unwrap() = "active".to_string();
                }
                _ => {}
            }
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push("script".to_string());
            Box::pin(async { anyhow::bail!("script failed deliberately") })
        }
    }

    let backend = TransBackend {
        events: events.clone(),
        unit_state: unit_state.clone(),
    };

    let req = PackageRunnerRequest {
        package_id: "test-trans".into(),
        action: "update".into(),
        script_name: "updatepackage-test-trans".into(),
        app_port: 8686,
        expected_target_version: Some("2.0.0".into()),
        ..Default::default()
    };

    let mut op =
        CoordinatedOperation::admit(conn, req, package, vec!["trans-unit.service".into()]).unwrap();

    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "failed");

    let recorded = events.lock().unwrap().clone();

    // 1. Pre-operation stopped trans-unit.service because !backend.quiescent returned true for "activating"
    let script_pos = recorded
        .iter()
        .position(|e| e == "script")
        .expect("Script must run");
    assert!(recorded[..script_pos].contains(&"stop:trans-unit.service".to_string()));

    // 2. Rollback restarts trans-unit.service because it was included in stopped
    assert!(recorded[script_pos..].contains(&"start:trans-unit.service".to_string()));
    assert_eq!(*unit_state.lock().unwrap(), "active");

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_transitional_unit_fails_post_start_health_certification() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    let (root, _path, conn, _) = test_fixture();
    let opt_dir = root.join("opt/test-trans-cert");
    std::fs::create_dir_all(&opt_dir).unwrap();
    let receipt_file = opt_dir.join(".af-version");
    std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

    let package = Package {
        name: "test-trans-cert".into(),
        service_name: "trans-cert.service".into(),
        service_type: "systemd".into(),
        default_port: 8787,
        ..Default::default()
    };

    // Initially in transitional state: "activating"
    let unit_state = Arc::new(std::sync::Mutex::new("activating".to_string()));
    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    struct TransCertBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
        unit_state: Arc<std::sync::Mutex<String>>,
    }

    impl LifecycleBackend for TransCertBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8787
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            let st = self.unit_state.lock().unwrap().clone();
            let is_act = parse_systemd_active_state(&st).unwrap();
            self.events
                .lock()
                .unwrap()
                .push(format!("active:{}:{}:{}", unit, st, is_act));
            Box::pin(async move { Ok(is_act) })
        }
        fn quiescent<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            let st = self.unit_state.lock().unwrap().clone();
            let is_q = parse_systemd_quiesced_state(&st).unwrap();
            self.events
                .lock()
                .unwrap()
                .push(format!("quiescent:{}:{}:{}", unit, st, is_q));
            Box::pin(async move { Ok(is_q) })
        }
        fn control<'a>(
            &'a self,
            unit: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}:{}", action, unit));
            match action {
                "stop" => {
                    *self.unit_state.lock().unwrap() = "inactive".to_string();
                }
                "start" => {
                    // Remains stuck in transitional "activating" state instead of reaching "active"
                    *self.unit_state.lock().unwrap() = "activating".to_string();
                }
                _ => {}
            }
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push("script".to_string());
            Box::pin(async { Ok(()) })
        }
    }

    let backend = TransCertBackend {
        events: events.clone(),
        unit_state: unit_state.clone(),
    };

    let req = PackageRunnerRequest {
        package_id: "test-trans-cert".into(),
        action: "update".into(),
        script_name: "updatepackage-test-trans-cert".into(),
        app_port: 8787,
        expected_target_version: Some("2.0.0".into()),
        ..Default::default()
    };

    let mut op =
        CoordinatedOperation::admit(conn, req, package, vec!["trans-cert.service".into()]).unwrap();

    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(
        receipt.status, "failed",
        "Operation must fail when service remains in activating state after start"
    );

    let recorded = events.lock().unwrap().clone();

    // 1. Pre-operation stopped trans-cert.service because !backend.quiescent returned true for activating
    let script_pos = recorded
        .iter()
        .position(|e| e == "script")
        .expect("Script must run");
    assert!(recorded[..script_pos].contains(&"stop:trans-cert.service".to_string()));

    // 2. Start was attempted after installer script
    let start_pos = recorded
        .iter()
        .position(|e| e == "start:trans-cert.service")
        .expect("Start must be called");
    assert!(start_pos > script_pos);

    // 3. Post-start active check saw "activating" and returned false, failing certification
    assert!(recorded.contains(&"active:trans-cert.service:activating:false".to_string()));

    // 4. Job diagnostic records that unit is not active after start
    let (diag,): (Option<String>,) = op
        .conn
        .query_row(
            "SELECT sanitized_summary FROM package_lifecycle_jobs WHERE package_id='test-trans-cert'",
            [],
            |row| Ok((row.get(0)?,)),
        )
        .unwrap();
    assert!(diag
        .as_deref()
        .unwrap_or("")
        .contains("is not active after start"));

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_absent_unit_rollback_allows_snapshot_restoration_whereas_active_stop_failure_gates_restoration(
) {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    struct AbsentRollbackBackend {
        fail_as_absent: bool,
        quiescent_result: bool,
        events: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl LifecycleBackend for AbsentRollbackBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8080
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(false) })
        }
        fn quiescent<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("quiescent:{unit}"));
            let res = self.quiescent_result;
            Box::pin(async move { Ok(res) })
        }
        fn control<'a>(
            &'a self,
            unit: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push(format!("{action}:{unit}"));
            if action == "stop" {
                if self.fail_as_absent {
                    Box::pin(async {
                        anyhow::bail!("Unit radarr.service not loaded (exit status: 5)")
                    })
                } else {
                    Box::pin(async {
                        anyhow::bail!("Failed to stop radarr.service: unit is active and locked")
                    })
                }
            } else {
                Box::pin(async { Ok(()) })
            }
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // Scenario 1: Absent unit on fresh install rollback
    // control("stop") fails with "Unit radarr.service not loaded (exit status: 5)"
    // but quiescent returns Ok(true).
    // Rollback restoration MUST proceed!
    {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let backend = AbsentRollbackBackend {
            fail_as_absent: true,
            quiescent_result: true,
            events: events.clone(),
        };

        let rollback_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rb_hook = rollback_called.clone();
        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |_| {
            rb_hook.store(true, std::sync::atomic::Ordering::SeqCst);
        }));

        let units = vec!["radarr.service".to_string()];
        let mut receipt_restore_error = None;
        let mut restart_failures = Vec::new();

        CoordinatedOperation::restore_and_restart_units(
            &backend,
            "job-absent-unit",
            "radarr",
            &units,
            &[], // fresh install: no restart units
            &[],
            &[],
            &mut receipt_restore_error,
            &mut restart_failures,
            false,
            true,
        )
        .await;

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

        // Rollback restoration must NOT be gated because the unit is absent and quiescent!
        assert!(
            rollback_called.load(std::sync::atomic::Ordering::SeqCst),
            "Rollback must proceed for absent quiescent unit"
        );
        assert!(
            receipt_restore_error.is_none(),
            "receipt_restore_error must not be set on benign absent stop"
        );
        assert!(
            restart_failures.is_empty(),
            "restart_failures must be empty for absent quiescent unit"
        );
    }

    // Scenario 2: Active unit where stop fails
    // control("stop") fails on active unit and quiescent returns false (or error is not absent).
    // Rollback restoration MUST be gated!
    {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let backend = AbsentRollbackBackend {
            fail_as_absent: false,
            quiescent_result: false,
            events: events.clone(),
        };

        let rollback_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rb_hook = rollback_called.clone();
        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |_| {
            rb_hook.store(true, std::sync::atomic::Ordering::SeqCst);
        }));

        let units = vec!["radarr.service".to_string()];
        let mut receipt_restore_error = None;
        let mut restart_failures = Vec::new();

        CoordinatedOperation::restore_and_restart_units(
            &backend,
            "job-active-stop-fail",
            "radarr",
            &units,
            &[],
            &[],
            &[],
            &mut receipt_restore_error,
            &mut restart_failures,
            false,
            true,
        )
        .await;

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

        // Rollback restoration MUST be gated on non-absent quiesce failure!
        assert!(
            !rollback_called.load(std::sync::atomic::Ordering::SeqCst),
            "Rollback must be gated when active unit stop fails"
        );
        assert!(
            receipt_restore_error.is_some(),
            "receipt_restore_error must indicate quiescence failure"
        );
        assert!(receipt_restore_error.as_ref().unwrap().contains(
            "Skipped snapshot restoration because service quiescence failed (incomplete-rollback)"
        ));
        assert!(!restart_failures.is_empty());
        assert!(restart_failures[0].contains("radarr.service: stop before restoration failed"));
    }
}

#[test]
fn test_sanitize_lifecycle_field_redacts_nested_json_object_and_array_secrets() {
    // Raw key-value with nested object
    let raw_obj = sanitize_lifecycle_field("failed with password: {\"value\":\"CANARY_SECRET\"}");
    assert!(
        !raw_obj.contains("CANARY_SECRET"),
        "Secret must be redacted: {}",
        raw_obj
    );
    assert!(
        raw_obj.contains("password: [REDACTED]"),
        "Must redact raw object: {}",
        raw_obj
    );

    // JSON key-value with nested object
    let json_obj = sanitize_lifecycle_field("{\"password\":{\"value\":\"CANARY_SECRET\"}}");
    assert!(
        !json_obj.contains("CANARY_SECRET"),
        "Secret must be redacted: {}",
        json_obj
    );
    assert!(
        json_obj.contains("\"password\":[REDACTED]"),
        "Must redact JSON object: {}",
        json_obj
    );

    // Raw key-value with JSON array
    let raw_arr = sanitize_lifecycle_field("secret: [\"CANARY_SECRET_1\", \"CANARY_SECRET_2\"]");
    assert!(
        !raw_arr.contains("CANARY_SECRET"),
        "Secrets in array must be redacted: {}",
        raw_arr
    );
    assert!(
        raw_arr.contains("secret: [REDACTED]"),
        "Must redact raw array: {}",
        raw_arr
    );

    // JSON key-value with array
    let json_arr = sanitize_lifecycle_field("{\"token\":[\"SECRET_A\",\"SECRET_B\"]}");
    assert!(
        !json_arr.contains("SECRET"),
        "Secrets in JSON array must be redacted: {}",
        json_arr
    );
    assert!(
        json_arr.contains("\"token\":[REDACTED]"),
        "Must redact JSON array: {}",
        json_arr
    );

    // 2 levels of nested braces
    let nested_2_lvl =
        sanitize_lifecycle_field("api_key: {\"outer\": {\"inner\": \"SECRET_KEY\"}}");
    assert!(
        !nested_2_lvl.contains("SECRET_KEY"),
        "2-level nested secret must be redacted: {}",
        nested_2_lvl
    );
    assert!(nested_2_lvl.contains("api_key: [REDACTED]"));

    // 3-level and 4-level nested JSON objects
    let nested_3_lvl =
        sanitize_lifecycle_field("{\"password\": {\"l1\": {\"l2\": {\"l3\": \"CANARY_3LVL\"}}}}");
    assert!(
        !nested_3_lvl.contains("CANARY_3LVL"),
        "3-level nested secret must be redacted: {}",
        nested_3_lvl
    );
    assert!(
        nested_3_lvl.contains("\"password\": [REDACTED]")
            || nested_3_lvl.contains("\"password\":[REDACTED]")
    );

    let nested_4_lvl = sanitize_lifecycle_field(
        "api_key: {\"l1\": {\"l2\": {\"l3\": {\"l4\": \"CANARY_4LVL\"}}}}",
    );
    assert!(
        !nested_4_lvl.contains("CANARY_4LVL"),
        "4-level nested secret must be redacted: {}",
        nested_4_lvl
    );
    assert!(nested_4_lvl.contains("api_key: [REDACTED]"));

    // Multiline nested JSON objects
    let nested_multiline = sanitize_lifecycle_field(
        "\"secret\": {\n  \"l1\": {\n    \"l2\": \"CANARY_MULTILINE\"\n  }\n}",
    );
    assert!(
        !nested_multiline.contains("CANARY_MULTILINE"),
        "Multiline nested secret must be redacted: {}",
        nested_multiline
    );
    assert!(nested_multiline.contains("\"secret\": [REDACTED]"));

    // Already redacted strings should not be corrupted
    let already_redacted_raw = sanitize_lifecycle_field("password: [REDACTED]");
    assert_eq!(already_redacted_raw, "password: [REDACTED]");

    let already_redacted_json = sanitize_lifecycle_field("{\"password\":[REDACTED]}");
    assert_eq!(already_redacted_json, "{\"password\":[REDACTED]}");
}

#[tokio::test]
async fn test_post_certification_failure_restores_runtime_state_and_receipt() {
    let (root, _path, conn, package) = test_fixture();

    let opt_syncthing = root.join("opt/syncthing");
    std::fs::create_dir_all(&opt_syncthing).unwrap();
    let bin_file = opt_syncthing.join("syncthing");
    std::fs::write(&bin_file, b"bin-1.22.0").unwrap();

    let usr_bin = root.join("usr/local/bin");
    std::fs::create_dir_all(&usr_bin).unwrap();
    let usr_bin_file = usr_bin.join("syncthing");
    std::fs::write(&usr_bin_file, b"bin-1.22.0").unwrap();

    let var_lib_syncthing = root.join("var/lib/syncthing");
    std::fs::create_dir_all(&var_lib_syncthing).unwrap();
    let config_txt = var_lib_syncthing.join("config.txt");
    std::fs::write(&config_txt, b"state-1.22.0").unwrap();
    let receipt_file = var_lib_syncthing.join(".af-version");
    std::fs::write(&receipt_file, b"1.22.0\n").unwrap();

    struct PostCertFailBackend {
        root: PathBuf,
        actions: Arc<std::sync::Mutex<Vec<String>>>,
        files_before_final_start: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }
    impl LifecycleBackend for PostCertFailBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8384
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
        }
        fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            let acts = self.actions.lock().unwrap();
            let last_stop = acts.iter().rposition(|e| e == "stop");
            let last_start = acts.iter().rposition(|e| e == "start");
            let is_q = match (last_stop, last_start) {
                (Some(s), Some(st)) => s > st,
                (Some(_), None) => true,
                _ => false,
            };
            Box::pin(async move { Ok(is_q) })
        }
        fn control<'a>(
            &'a self,
            _: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            let r = self.root.clone();
            let acts = self.actions.clone();
            let files_rec = self.files_before_final_start.clone();
            let action_str = action.to_string();
            Box::pin(async move {
                acts.lock().unwrap().push(action_str.clone());
                if action_str == "start" {
                    let total_starts = acts
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|a| a.as_str() == "start")
                        .count();
                    if total_starts >= 2 {
                        // This is the post-rollback restart!
                        let bin = std::fs::read_to_string(r.join("opt/syncthing/syncthing"))
                            .unwrap_or_default();
                        let usr_bin = std::fs::read_to_string(r.join("usr/local/bin/syncthing"))
                            .unwrap_or_default();
                        let cfg = std::fs::read_to_string(r.join("var/lib/syncthing/config.txt"))
                            .unwrap_or_default();
                        let ver = std::fs::read_to_string(r.join("var/lib/syncthing/.af-version"))
                            .unwrap_or_default();
                        let mut lock = files_rec.lock().unwrap();
                        *lock = vec![
                            ("bin".into(), bin),
                            ("usr_bin".into(), usr_bin),
                            ("cfg".into(), cfg),
                            ("ver".into(), ver),
                        ];
                    }
                }
                Ok(())
            })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            let r = self.root.clone();
            Box::pin(async move {
                std::fs::write(r.join("opt/syncthing/syncthing"), b"bin-1.23.4").unwrap();
                std::fs::write(r.join("usr/local/bin/syncthing"), b"bin-1.23.4").unwrap();
                std::fs::write(r.join("var/lib/syncthing/config.txt"), b"state-1.23.4").unwrap();
                std::fs::write(r.join("var/lib/syncthing/.af-version"), b"1.23.4\n").unwrap();
                Ok(())
            })
        }
    }

    let actions = Arc::new(std::sync::Mutex::new(Vec::new()));
    let files_before_final_start = Arc::new(std::sync::Mutex::new(Vec::new()));
    let backend = PostCertFailBackend {
        root: root.clone(),
        actions: actions.clone(),
        files_before_final_start: files_before_final_start.clone(),
    };

    let req = PackageRunnerRequest {
        package_id: "syncthing".into(),
        action: "update".into(),
        script_name: "updatepackage-syncthing".into(),
        app_port: 8384,
        expected_target_version: Some("1.24.0".into()), // forces target certification failure
        ..Default::default()
    };

    let mut op = CoordinatedOperation::admit(conn, req, package, vec!["syncthing".into()]).unwrap();
    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(
        receipt.status, "failed",
        "Execute must mark receipt as failed when certification fails"
    );

    // Verify BEFORE final restart:
    let recorded = files_before_final_start.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec![
            ("bin".into(), "bin-1.22.0".into()),
            ("usr_bin".into(), "bin-1.22.0".into()),
            ("cfg".into(), "state-1.22.0".into()),
            ("ver".into(), "1.22.0\n".into()),
        ],
        "Files BEFORE final restart must be restored to 1.22.0"
    );

    // Verify on disk afterward:
    assert_eq!(std::fs::read_to_string(&bin_file).unwrap(), "bin-1.22.0");
    assert_eq!(
        std::fs::read_to_string(&usr_bin_file).unwrap(),
        "bin-1.22.0"
    );
    assert_eq!(
        std::fs::read_to_string(&config_txt).unwrap(),
        "state-1.22.0"
    );
    assert_eq!(
        std::fs::read_to_string(&receipt_file).unwrap().trim(),
        "1.22.0"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn test_filebot_receipt_resolution_prefers_filebot_node_over_cli() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-filebot-receipt-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let opt_filebot = temp_dir.join("opt/filebot");
    std::fs::create_dir_all(&opt_filebot).unwrap();
    std::fs::write(opt_filebot.join(".af-version"), b"5.1.6\n").unwrap();

    // When /opt/filebot-node/.af-version is absent while /opt/filebot/.af-version = 5.1.6
    // read_af_version_receipt must return None (never 5.1.6!)
    assert_eq!(
        read_af_version_receipt("filebot", &env_cfg),
        None,
        "read_af_version_receipt must never read /opt/filebot/.af-version CLI receipt"
    );

    // Now create /opt/filebot-node/.af-version = 0.4.8.1
    let opt_filebot_node = temp_dir.join("opt/filebot-node");
    std::fs::create_dir_all(&opt_filebot_node).unwrap();
    std::fs::write(opt_filebot_node.join(".af-version"), b"0.4.8.1\n").unwrap();

    assert_eq!(
        read_af_version_receipt("filebot", &env_cfg),
        Some("0.4.8.1".to_string()),
        "read_af_version_receipt must prefer /opt/filebot-node/.af-version"
    );

    // Verify candidate_version_marker_paths_with_env includes both receipts with filebot-node first
    let paths = candidate_version_marker_paths_with_env("filebot", &env_cfg).unwrap();
    let node_path = temp_dir.join("opt/filebot-node/.af-version");
    let cli_path = temp_dir.join("opt/filebot/.af-version");
    assert!(
        paths.contains(&node_path),
        "Must contain /opt/filebot-node/.af-version"
    );
    assert!(
        paths.contains(&cli_path),
        "Must contain /opt/filebot/.af-version"
    );

    let node_idx = paths.iter().position(|p| p == &node_path).unwrap();
    let cli_idx = paths.iter().position(|p| p == &cli_path).unwrap();
    assert!(
        node_idx < cli_idx,
        "/opt/filebot-node/.af-version must appear before /opt/filebot/.af-version"
    );

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_wave22_sanitize_lifecycle_field_scalar_credentials() {
    let test_cases = [
        "Cookie: session=CANARY_COOKIE",
        "Set-Cookie: theme=\"CANARY_COOKIE\"; HttpOnly",
        "session=CANARY_SESSION",
        "{\"webhook_url\":\"https://example.test/CANARY_HOOK\"}",
        "pass=CANARY_PASSWORD",
    ];

    for tc in test_cases {
        let sanitized = sanitize_lifecycle_field(tc);
        assert!(
            !sanitized.contains("CANARY_"),
            "Sanitized text must contain zero CANARY_ substrings for input {:?}, got {:?}",
            tc,
            sanitized
        );
    }

    // Idempotency check:
    assert_eq!(
        sanitize_lifecycle_field("password: [REDACTED]"),
        "password: [REDACTED]"
    );
    assert_eq!(
        sanitize_lifecycle_field("{\"password\":[REDACTED]}"),
        "{\"password\":[REDACTED]}"
    );
}

#[test]
fn test_wave23_large_sparse_mutable_database_restored_on_mutation_and_deletion() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-w23-sparse-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let sonarr_db_dir = temp_dir.join("var/lib/sonarr");
    std::fs::create_dir_all(&sonarr_db_dir).unwrap();
    let db_file = sonarr_db_dir.join("sonarr.db");

    let file_len: u64 = 268_435_457; // 256 MiB + 1
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::File::create(&db_file).unwrap();
        f.write_all(b"OLD_DB01").unwrap();
        f.seek(SeekFrom::Start(file_len - 8)).unwrap();
        f.write_all(b"TRAIL001").unwrap();
        f.set_len(file_len).unwrap();
    }

    // Test part (a): Mutation
    {
        let mut snap = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false).unwrap();
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&db_file)
                .unwrap();
            f.write_all(b"NEW_DB02").unwrap();
            f.seek(SeekFrom::Start(file_len - 8)).unwrap();
            f.write_all(b"TRAILNEW").unwrap();
        }
        assert_eq!(&std::fs::read(&db_file).unwrap()[..8], b"NEW_DB02");

        snap.restore().expect("restore must succeed");

        let restored_meta = std::fs::metadata(&db_file).unwrap();
        assert_eq!(restored_meta.len(), file_len);
        let mut f = std::fs::File::open(&db_file).unwrap();
        let mut head = [0u8; 8];
        use std::io::{Read, Seek, SeekFrom};
        f.read_exact(&mut head).unwrap();
        assert_eq!(&head, b"OLD_DB01");
        f.seek(SeekFrom::Start(file_len - 8)).unwrap();
        let mut tail = [0u8; 8];
        f.read_exact(&mut tail).unwrap();
        assert_eq!(&tail, b"TRAIL001");
    }

    // Test part (b): Deletion
    {
        let mut snap = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false).unwrap();
        std::fs::remove_file(&db_file).unwrap();
        assert!(!db_file.exists());

        snap.restore().expect("restore must succeed");

        assert!(db_file.exists(), "Deleted sonarr.db must be restored");
        let restored_meta = std::fs::metadata(&db_file).unwrap();
        assert_eq!(restored_meta.len(), file_len);
        let mut f = std::fs::File::open(&db_file).unwrap();
        let mut head = [0u8; 8];
        use std::io::{Read, Seek, SeekFrom};
        f.read_exact(&mut head).unwrap();
        assert_eq!(&head, b"OLD_DB01");
        f.seek(SeekFrom::Start(file_len - 8)).unwrap();
        let mut tail = [0u8; 8];
        f.read_exact(&mut tail).unwrap();
        assert_eq!(&tail, b"TRAIL001");
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave23_catalog_footprint_plex_and_mcvnc_unit_restoration() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-w23-footprint-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    // Plex footprint: /usr/lib/plexmediaserver/Plex Media Server and /var/lib/plexmediaserver/library.db
    let plex_lib = temp_dir.join("usr/lib/plexmediaserver");
    let plex_var = temp_dir.join("var/lib/plexmediaserver");
    std::fs::create_dir_all(&plex_lib).unwrap();
    std::fs::create_dir_all(&plex_var).unwrap();
    let plex_bin = plex_lib.join("Plex Media Server");
    let plex_db = plex_var.join("library.db");
    std::fs::write(&plex_bin, b"OLD_PLEX_BIN").unwrap();
    std::fs::write(&plex_db, b"OLD_PLEX_DB").unwrap();

    let mut plex_snap = PackageRuntimeSnapshot::capture(
        "plex",
        &["plexmediaserver.service".into()],
        &env_cfg,
        false,
    )
    .unwrap();

    std::fs::write(&plex_bin, b"NEW_PLEX_BIN").unwrap();
    std::fs::write(&plex_db, b"NEW_PLEX_DB").unwrap();
    plex_snap.restore().expect("plex restore must succeed");

    assert_eq!(std::fs::read(&plex_bin).unwrap(), b"OLD_PLEX_BIN");
    assert_eq!(std::fs::read(&plex_db).unwrap(), b"OLD_PLEX_DB");

    // Mcvnc footprint: aliased unit /etc/systemd/system/af-mcvnc.service
    let sysd_dir = temp_dir.join("etc/systemd/system");
    std::fs::create_dir_all(&sysd_dir).unwrap();
    let mcvnc_unit = sysd_dir.join("af-mcvnc.service");
    std::fs::write(&mcvnc_unit, b"OLD_UNIT").unwrap();

    // Capture with &[] units (catalog expands mcvnc -> af-mcvnc.service)
    let mut mcvnc_snap = PackageRuntimeSnapshot::capture("mcvnc", &[], &env_cfg, false).unwrap();
    std::fs::write(&mcvnc_unit, b"NEW_UNIT").unwrap();
    mcvnc_snap.restore().expect("mcvnc restore must succeed");
    assert_eq!(std::fs::read(&mcvnc_unit).unwrap(), b"OLD_UNIT");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave23_escaped_cookie_header_quotes_redacted() {
    let input1 = r#"curl -H "Cookie: sid=\"COOKIE_CANARY\"" https://example.invalid"#;
    let sanitized1 = sanitize_lifecycle_field(input1);
    assert!(
        !sanitized1.contains("COOKIE_CANARY"),
        "Escaped cookie canary must be redacted: {}",
        sanitized1
    );
    assert!(
        sanitized1.contains("Cookie: [REDACTED]"),
        "Must contain redacted cookie header: {}",
        sanitized1
    );

    let input2 = r#"curl -H "Set-Cookie: token=\"COOKIE_CANARY\"; Path=/" https://example.invalid"#;
    let sanitized2 = sanitize_lifecycle_field(input2);
    assert!(
        !sanitized2.contains("COOKIE_CANARY"),
        "Set-Cookie canary must be redacted: {}",
        sanitized2
    );

    let input3 = r#"{"args": ["curl", "-H", "Cookie: sid=\"COOKIE_CANARY\""]}"#;
    let sanitized3 = sanitize_lifecycle_field(input3);
    assert!(
        !sanitized3.contains("COOKIE_CANARY"),
        "JSON escaped cookie must be redacted: {}",
        sanitized3
    );
}

#[test]
fn test_wave23_runtime_restore_failure_never_rewinds_embedded_receipt() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-w23-receipt-gate-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let opt_sonarr = temp_dir.join("opt/sonarr");
    let var_lib_sonarr = temp_dir.join("var/lib/sonarr");
    std::fs::create_dir_all(&opt_sonarr).unwrap();
    std::fs::create_dir_all(&var_lib_sonarr).unwrap();

    let receipt_file = opt_sonarr.join(".af-version");
    let bin_file = opt_sonarr.join("Sonarr");
    std::fs::write(&receipt_file, b"1.0.0\n").unwrap();
    std::fs::write(&bin_file, b"old").unwrap();

    let mut rt = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false).unwrap();

    // Mutate receipt to 2.0.0 and binary to "new"
    std::fs::write(&receipt_file, b"2.0.0\n").unwrap();
    std::fs::write(&bin_file, b"new").unwrap();

    // Replace var/lib with a regular file blocker to cause Phase 1 preflight failure
    let var_dir = temp_dir.join("var");
    let var_lib = var_dir.join("lib");
    std::fs::remove_dir_all(&var_lib).unwrap();
    std::fs::write(&var_lib, b"blocking regular file").unwrap();

    // Direct rt.restore() must fail
    let res = rt.restore();
    assert!(
        res.is_err(),
        "rt.restore must fail when ancestor is blocked"
    );

    // .af-version MUST still be "2.0.0\n" (never rewound to 1.0.0!)
    let current_receipt = std::fs::read_to_string(&receipt_file).unwrap();
    assert_eq!(
        current_receipt, "2.0.0\n",
        "Receipt must NOT be rewound when runtime restore fails!"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

fn merged_usr_aliases(root: &std::path::Path) {
    for alias in ["bin", "sbin", "lib", "lib32", "lib64", "libx32"] {
        let real_dir = root.join("usr").join(alias);
        std::fs::create_dir_all(&real_dir).unwrap();
        std::os::unix::fs::symlink(format!("usr/{alias}"), root.join(alias)).unwrap();
    }
}

#[test]
fn test_wave24_merged_usr_catalog_capture_and_restore() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-w24-merged-usr-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    merged_usr_aliases(&temp_dir);
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let packages_json = manifest_dir.join("../../../config/packages.json");
    let raw = std::fs::read_to_string(&packages_json)
        .unwrap_or_else(|e| panic!("read {}: {e}", packages_json.display()));
    let catalog: Vec<serde_json::Value> = serde_json::from_str(&raw).unwrap();
    let names: Vec<String> = catalog
        .iter()
        .filter_map(|pkg| {
            pkg.get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    assert!(
        names.len() >= 70,
        "expected the full catalog, found {}",
        names.len()
    );

    let mut failures = Vec::new();
    for name in &names {
        if let Err(err) = PackageRuntimeSnapshot::capture(name, &[], &env_cfg, false) {
            failures.push(format!("{name}: {err}"));
        }
    }
    assert!(
        failures.is_empty(),
        "merged-/usr capture failures ({}): {failures:?}",
        failures.len()
    );

    let unit_dir = temp_dir.join("usr/lib/systemd/system");
    std::fs::create_dir_all(&unit_dir).unwrap();
    let unit = unit_dir.join("sonarr.service");
    std::fs::write(&unit, b"OLD_UNIT").unwrap();
    let opt_bin = temp_dir.join("opt/sonarr/Sonarr");
    std::fs::create_dir_all(opt_bin.parent().unwrap()).unwrap();
    std::fs::write(&opt_bin, b"OLD_BIN").unwrap();

    let mut snap =
        PackageRuntimeSnapshot::capture("sonarr", &["sonarr.service".into()], &env_cfg, false)
            .expect("sonarr capture on merged-/usr");
    let lib_prefix = temp_dir.join("lib");
    for entry in &snap.entries {
        let target = match entry {
            RuntimeSnapshotEntry::Absent { target_path, .. }
            | RuntimeSnapshotEntry::File { target_path, .. }
            | RuntimeSnapshotEntry::Symlink { target_path, .. }
            | RuntimeSnapshotEntry::Directory { target_path, .. } => target_path,
        };
        assert!(
            !target.starts_with(&lib_prefix),
            "merged-/usr target was not rewritten onto /usr: {}",
            target.display()
        );
    }
    std::fs::write(&unit, b"NEW_UNIT").unwrap();
    std::fs::write(&opt_bin, b"NEW_BIN").unwrap();
    snap.restore().expect("merged-/usr restore");
    assert_eq!(std::fs::read(&unit).unwrap(), b"OLD_UNIT");
    assert_eq!(std::fs::read(&opt_bin).unwrap(), b"OLD_BIN");

    let untrusted = temp_dir.join("untrusted-opt");
    std::fs::create_dir_all(untrusted.join("usr/opt")).unwrap();
    std::os::unix::fs::symlink("usr/opt", untrusted.join("opt")).unwrap();
    let mut bad_env = crate::PackageExecutionEnv::default();
    bad_env.fs_root = Some(untrusted);
    let bad = PackageRuntimeSnapshot::capture("sonarr", &[], &bad_env, false);
    assert!(
        bad.unwrap_err().contains("is a symlink"),
        "non-merged-usr symlinks must still fail closed"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave24_installer_footprint_round_trip() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-w24-footprint-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let files = [
        (
            "grafana",
            "usr/share/grafana/public/build/app.js",
            "OLD_GRAFANA",
        ),
        (
            "jellyfin",
            "usr/share/jellyfin/web/index.html",
            "OLD_JELLYFIN",
        ),
        ("netdata", "usr/sbin/netdata", "OLD_NETDATA_BIN"),
        (
            "netdata",
            "usr/libexec/netdata/plugins.d/apps.plugin",
            "OLD_NETDATA_PLUGIN",
        ),
        ("kasmvnc", "usr/share/kasmvnc/www/vnc.html", "OLD_KASM_WWW"),
        ("kasmvnc", "usr/bin/Xvnc", "OLD_XVNC"),
    ];
    for (_, rel, body) in files {
        let path = temp_dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, body.as_bytes()).unwrap();
    }

    let mut snaps = Vec::new();
    for pkg in ["grafana", "jellyfin", "netdata", "kasmvnc"] {
        snaps.push((
            pkg,
            PackageRuntimeSnapshot::capture(pkg, &[], &env_cfg, false)
                .unwrap_or_else(|e| panic!("{pkg} capture failed: {e}")),
        ));
    }
    for (_, rel, _) in files {
        let path = temp_dir.join(rel);
        std::fs::write(&path, b"NEW").unwrap();
    }
    for (pkg, mut snap) in snaps {
        snap.restore()
            .unwrap_or_else(|e| panic!("{pkg} restore failed: {e}"));
    }
    for (_, rel, body) in files {
        let path = temp_dir.join(rel);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            body.as_bytes(),
            "round-trip failed for {}",
            path.display()
        );
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave24_unreadable_database_never_yields_partial_snapshot() {
    let temp_dir = std::env::temp_dir().join(format!("af-test-w24-perm-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());
    let db_dir = temp_dir.join("var/lib/sonarr");
    std::fs::create_dir_all(&db_dir).unwrap();
    let protected = db_dir.join("protected.db");
    std::fs::write(&protected, b"SECRETDB").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o000)).unwrap();

    let euid = unsafe { libc::geteuid() };
    for ignore in [true, false] {
        let captured = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, ignore);
        if euid != 0 {
            let err = captured.expect_err("unreadable database must fail capture");
            assert!(
                err.to_ascii_lowercase().contains("permission"),
                "ignore={ignore} error should be permission denied, got {err}"
            );
            let meta = std::fs::symlink_metadata(&protected)
                .expect("unreadable database must remain on disk");
            assert!(meta.is_file());
            assert_eq!(meta.len(), b"SECRETDB".len() as u64);
            std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(std::fs::read(&protected).unwrap(), b"SECRETDB");
            std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o000)).unwrap();
        } else {
            let mut snap = captured.expect("root can read mode 000");
            std::fs::remove_file(&protected).unwrap();
            snap.restore().expect("root restore keeps the database");
            assert_eq!(std::fs::read(&protected).unwrap(), b"SECRETDB");
            std::fs::write(&protected, b"SECRETDB").unwrap();
            std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
    }
    let _ = std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o644));
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave24_sanitize_escaped_quotes_cli_flags_and_redacted_suffix() {
    let cases = [
        r#"password=\"SECRET words\""#,
        r#"api_key=\"SECRET words\""#,
        r#"client_secret=\"SECRET words\""#,
        r#"session=\"SECRET words\""#,
        r#"webhook=\"SECRET words\""#,
        r#"rclone_rc_pass=\"SECRET words\""#,
        "--password SECRET words",
        "--passwd SECRET words",
        "--pwd SECRET words",
        "--pass SECRET words",
        "--secret SECRET words",
        "--token SECRET words",
        "--api-key SECRET words",
        "--apikey SECRET words",
        "--cookie SECRET words",
        "--cookies SECRET words",
        "--session SECRET words",
        "--webhook SECRET words",
        "--password=SECRET words",
        r#"--password=\"SECRET words\""#,
        r#"--token=\"SECRET words\""#,
        r#"curl --user=\"admin:SECRET words\" https://example.invalid"#,
        r#"curl -u \"admin:SECRET words\" https://example.invalid"#,
        "bypass=visible passed=true monkey=1",
    ];
    for input in cases {
        let sanitized = sanitize_lifecycle_field(input);
        assert!(
            !sanitized.contains("SECRET"),
            "secret leaked for {input:?} -> {sanitized:?}"
        );
    }

    let boundary = sanitize_lifecycle_field("bypass=visible passed=true monkey=1");
    assert!(boundary.contains("bypass=visible"), "{boundary}");
    assert!(boundary.contains("passed=true"), "{boundary}");
    assert!(boundary.contains("monkey=1"), "{boundary}");

    let json_password = "AF_DIAG_FAILURE={\"stage\": \"password=[REDACTED]\\\"SECRET words\\\\\\\"\", \"status\": \"ok\"}";
    let sanitized_password = sanitize_lifecycle_field(json_password);
    assert!(
        !sanitized_password.contains("SECRET"),
        "{sanitized_password}"
    );
    let payload = sanitized_password.trim_start_matches("AF_DIAG_FAILURE=");
    serde_json::from_str::<serde_json::Value>(payload)
        .unwrap_or_else(|e| panic!("password diagnostic is not JSON ({e}): {sanitized_password}"));

    let json_user = "AF_DIAG_FAILURE={\"stage\": \"--user [REDACTED]\\\"user:SECRET words\\\\\\\"\", \"status\": \"ok\"}";
    let sanitized_user = sanitize_lifecycle_field(json_user);
    assert!(!sanitized_user.contains("SECRET"), "{sanitized_user}");
    let payload = sanitized_user.trim_start_matches("AF_DIAG_FAILURE=");
    serde_json::from_str::<serde_json::Value>(payload)
        .unwrap_or_else(|e| panic!("user diagnostic is not JSON ({e}): {sanitized_user}"));

    let token_json = sanitize_lifecycle_field(r#"{"note":"token=SECRET\""}"#);
    assert!(!token_json.contains("SECRET"), "{token_json}");
    serde_json::from_str::<serde_json::Value>(&token_json)
        .unwrap_or_else(|e| panic!("token JSON broken ({e}): {token_json}"));
}

fn sonarr_runtime_snap_dirs_in(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    if let Ok(rd) = std::fs::read_dir(root) {
        for ent in rd.flatten() {
            if ent
                .file_name()
                .to_string_lossy()
                .starts_with(".af-rt-snap-sonarr-")
            {
                found.push(ent.path());
            }
        }
    }
    found.sort();
    found
}

#[test]
fn test_wave25_capture_failure_drops_orphan_backup_root() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-w25-orphan-{}", uuid::Uuid::new_v4()));
    let snap_recovery = temp_dir.join("var/backups/aetherflow-recovery");
    let snap_staging = temp_dir.join("snap-tmp");
    std::fs::create_dir_all(&snap_staging).unwrap();
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());
    env_cfg.temp_dir = snap_staging.clone();
    env_cfg.recovery_root = Some(snap_recovery.clone());
    let opt = temp_dir.join("opt/sonarr");
    let ro_sub = opt.join("ro-bin");
    let etc = temp_dir.join("etc/sonarr");
    std::fs::create_dir_all(&ro_sub).unwrap();
    std::fs::create_dir_all(&etc).unwrap();
    let readable = opt.join("readable.db");
    let ro_nested = ro_sub.join("helper.bin");
    let unreadable = etc.join("unreadable.db");
    {
        let file = std::fs::File::create(&readable).unwrap();
        file.set_len(1024 * 1024).unwrap();
    }
    std::fs::write(&ro_nested, b"RO_HELPER").unwrap();
    std::fs::write(&unreadable, b"SECRETDB").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&ro_sub, std::fs::Permissions::from_mode(0o500)).unwrap();
    let etc_parent = temp_dir.join("etc");
    let etc_real = temp_dir.join("etc-real");
    std::fs::rename(&etc_parent, &etc_real).unwrap();
    std::os::unix::fs::symlink(&etc_real, &etc_parent).unwrap();
    let err = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false)
        .expect_err("symlink ancestor must fail capture even as root");
    assert!(
        err.to_ascii_lowercase().contains("symlink"),
        "unexpected capture failure: {err}"
    );
    assert!(
        err.contains("/etc"),
        "failure must follow capture of /opt/sonarr: {err}"
    );
    let after = sonarr_runtime_snap_dirs_in(&snap_recovery);
    assert!(
        after.is_empty(),
        "capture failure left orphaned snapshot directories: {after:?}"
    );
    assert!(
        sonarr_runtime_snap_dirs_in(&snap_staging).is_empty(),
        "capture must not place snapshots under disposable temp_dir"
    );

    std::fs::remove_file(&etc_parent).unwrap();
    std::fs::rename(&etc_real, &etc_parent).unwrap();
    let mut snap = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false)
        .expect("readable tree captures");
    let preserved = snap.backup_root.clone();
    assert!(preserved.is_dir(), "backup_root must exist before restore");
    assert!(
        preserved.starts_with(&snap_recovery),
        "capture must honor env_cfg.recovery_root ({}) -> got {}",
        snap_recovery.display(),
        preserved.display()
    );
    std::fs::set_permissions(&ro_sub, std::fs::Permissions::from_mode(0o700)).unwrap();
    let opt_parent = temp_dir.join("opt");
    std::fs::remove_dir_all(&opt).unwrap();
    std::fs::remove_dir_all(&opt_parent).unwrap();
    std::fs::write(&opt_parent, b"not-a-directory").unwrap();
    let restore_err = snap
        .restore()
        .expect_err("non-directory ancestor must fail restore");
    assert!(
        snap.preserve_on_drop,
        "incomplete restore must preserve backup_root, err={restore_err}"
    );
    drop(snap);
    assert!(
        preserved.is_dir(),
        "preserve_on_drop must keep {} after Drop",
        preserved.display()
    );
    force_remove_backup_tree(&preserved);
    let _ = std::fs::remove_file(&opt_parent);
    let _ = std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644));
    force_remove_backup_tree(&temp_dir);
}

#[test]
fn test_wave25_sanitize_shell_escapes_glued_suffixes_and_unicode_keys() {
    let cases = [
        r#"curl --password prefix\ SENTINEL --verbose"#,
        "curl --user operator:prefix\\ SENTINEL https://example.invalid",
        r#"{"command":"curl --password prefix\ SENTINEL --verbose"}"#,
        r#"{"command":"curl --password prefix\\ SENTINEL --verbose"}"#,
        r#"password=prefix\;SENTINEL"#,
        r#"password=prefix\&SENTINEL"#,
        r#"password=prefix\,SENTINEL"#,
        "curl --password $'SENTINEL' https://example.invalid",
        "curl --password $\"SENTINEL\" https://example.invalid",
        "curl --password prefix\"SENTINEL\" https://example.invalid",
        "curl --password prefix'SENTINEL' https://example.invalid",
        "password=[REDACTED]SENTINEL",
        "curl --password [REDACTED]SENTINEL --verbose",
        "curl --password [REDACTED]'SENTINEL'",
        "curl --password [REDACTED]\"SENTINEL\" --verbose",
        "curl --password [REDACTED]$'SENTINEL' --verbose",
        r#"{"pass\u0077ord":"SENTINEL"}"#,
        r#"{"pass\\u0077ord":"SENTINEL"}"#,
    ];
    assert_eq!(cases.len(), 18, "wave 25 sanitizer scenario count");
    for input in cases {
        let once = sanitize_lifecycle_field(input);
        let twice = sanitize_lifecycle_field(&once);
        assert!(
            !once.contains("SENTINEL"),
            "secret leaked for {input:?} -> {once:?}"
        );
        assert_eq!(once, twice, "not idempotent for {input:?} -> {once:?}");
    }

    assert_eq!(
        sanitize_lifecycle_field(r#"curl --password prefix\ SENTINEL --verbose"#),
        "curl --password [REDACTED] --verbose"
    );
    assert_eq!(
        sanitize_lifecycle_field("curl --user operator:prefix\\ SENTINEL https://example.invalid"),
        "curl --user [REDACTED] https://example.invalid"
    );
    assert_eq!(
        sanitize_lifecycle_field(r#"password=prefix\;SENTINEL"#),
        "password=[REDACTED]"
    );
    assert_eq!(
        sanitize_lifecycle_field("curl --password $'SENTINEL' https://example.invalid"),
        "curl --password [REDACTED] https://example.invalid"
    );
    assert_eq!(
        sanitize_lifecycle_field("curl --password prefix\"SENTINEL\" https://example.invalid"),
        "curl --password [REDACTED] https://example.invalid"
    );
    assert_eq!(
        sanitize_lifecycle_field("password=[REDACTED]SENTINEL"),
        "password=[REDACTED]"
    );

    let json_cmd =
        sanitize_lifecycle_field(r#"{"command":"curl --password prefix\\ SENTINEL --verbose"}"#);
    assert!(!json_cmd.contains("SENTINEL"), "{json_cmd}");
    serde_json::from_str::<serde_json::Value>(&json_cmd)
        .unwrap_or_else(|e| panic!("command JSON broken ({e}): {json_cmd}"));

    let unicode_key = sanitize_lifecycle_field(r#"{"pass\u0077ord":"SENTINEL"}"#);
    assert!(!unicode_key.contains("SENTINEL"), "{unicode_key}");
    assert!(
        unicode_key.contains("password") || unicode_key.contains("pass\\u0077ord"),
        "{unicode_key}"
    );
    let double_escaped = sanitize_lifecycle_field(r#"{"pass\\u0077ord":"SENTINEL"}"#);
    assert!(!double_escaped.contains("SENTINEL"), "{double_escaped}");

    let untouched = r#"{"na\u006de":"VISIBLE"}"#;
    assert_eq!(sanitize_lifecycle_field(untouched), untouched);

    assert_eq!(
        sanitize_lifecycle_field("webhook_url=[REDACTED_URL]"),
        "webhook_url=[REDACTED_URL]"
    );
    assert_eq!(
        sanitize_lifecycle_field("webhook_url=[REDACTED_url]"),
        "webhook_url=[REDACTED_url]"
    );

    let enclosing = r#"{"stage":"password=[REDACTED]","ok":true}"#;
    let enclosing_out = sanitize_lifecycle_field(enclosing);
    assert_eq!(enclosing_out, enclosing, "{enclosing_out}");
    serde_json::from_str::<serde_json::Value>(&enclosing_out)
        .unwrap_or_else(|e| panic!("enclosing JSON broken ({e}): {enclosing_out}"));

    let closer = r#"{"note":"--password [REDACTED]\" https://example.invalid"}"#;
    let closer_out = sanitize_lifecycle_field(closer);
    assert!(
        closer_out.contains("https://example.invalid"),
        "{closer_out}"
    );
    assert!(!closer_out.contains("SENTINEL"), "{closer_out}");
    serde_json::from_str::<serde_json::Value>(&closer_out)
        .unwrap_or_else(|e| panic!("closer JSON broken ({e}): {closer_out}"));
}

#[cfg(unix)]
#[test]
fn test_durable_recovery_storage_privileged_policy_validation() {
    use std::os::unix::fs::PermissionsExt;

    let current_uid = unsafe { libc::geteuid() };
    let base = std::env::temp_dir().join(format!(
        "af-durable-recovery-policy-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&base).unwrap();
    let fixture = base.join("fixture");
    std::fs::create_dir_all(&fixture).unwrap();
    let staging = base.join("disposable-staging");
    std::fs::create_dir_all(&staging).unwrap();

    let priv_policy = RecoveryStoragePolicy {
        privileged: true,
        expected_uid: current_uid,
    };

    // 1. Isolated fixture with default recovery_root creates private 0700 dirs under
    //    <fixture>/var/backups/aetherflow-recovery and leaves disposable temp_dir untouched.
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(fixture.clone());
    env_cfg.temp_dir = staging.clone();
    env_cfg.recovery_root = None;
    let created = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-policy1",
        &env_cfg,
        priv_policy,
        None,
    )
    .expect("isolated fixture privileged recovery root should succeed");
    let expected_recovery_root = fixture.join("var/backups/aetherflow-recovery");
    assert_eq!(created.parent(), Some(expected_recovery_root.as_path()));
    assert_eq!(
        std::fs::symlink_metadata(&expected_recovery_root)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    assert_eq!(
        std::fs::symlink_metadata(&created)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    assert_eq!(
        std::fs::read_dir(&staging).unwrap().count(),
        0,
        "disposable temp_dir must stay untouched"
    );

    // 2. Reject ephemeral tmp/run roots, protected roots, relative paths, and parent traversal.
    for bad_root in [
        fixture.join("tmp/af-snap"),
        fixture.join("var/tmp/af-snap"),
        fixture.join("var/tmp/aetherflow-scratch"),
        fixture.join("dev/shm/af-snap"),
        fixture.join("run/af-snap"),
        fixture.join("var/run/af-snap"),
        fixture.join("var/backups"),
        fixture.join("var"),
        fixture.join("var/backups/../tmp/af-snap"),
        PathBuf::from("relative/recovery"),
    ] {
        let mut bad_env = env_cfg.clone();
        bad_env.recovery_root = Some(bad_root.clone());
        let err = prepare_runtime_snapshot_backup_root_with_policy(
            ".af-rt-snap-sonarr-bad",
            &bad_env,
            priv_policy,
            None,
        )
        .expect_err(&format!("expected rejection for {}", bad_root.display()));
        assert!(!err.is_empty());
    }

    // 3. Real-host privileged policy rejects ephemeral /tmp, /var/tmp, /var/backups and never
    //    falls back to temp_dir when default /var/backups/aetherflow-recovery fails.
    let real_root_policy = RecoveryStoragePolicy {
        privileged: true,
        expected_uid: 0,
    };
    for bad_host_root in [
        "/tmp/af-priv-snap",
        "/var/tmp/af-priv-snap",
        "/var/tmp/aetherflow-scratch",
        "/dev/shm/af-priv-snap",
        "/run/af-priv-snap",
        "/var/backups",
    ] {
        let mut host_env = crate::PackageExecutionEnv::default();
        host_env.fs_root = None;
        host_env.temp_dir = staging.clone();
        host_env.recovery_root = Some(PathBuf::from(bad_host_root));
        let err = prepare_runtime_snapshot_backup_root_with_policy(
            ".af-rt-snap-sonarr-hostbad",
            &host_env,
            real_root_policy,
            None,
        )
        .expect_err(&format!("expected host rejection for {bad_host_root}"));
        assert!(
            err.contains("persistent storage") || err.contains("protected directory"),
            "unexpected host rejection for {bad_host_root}: {err}"
        );
    }
    if current_uid != 0 {
        let mut host_default_env = crate::PackageExecutionEnv::default();
        host_default_env.fs_root = None;
        host_default_env.temp_dir = staging.clone();
        host_default_env.recovery_root = None;
        let err = prepare_runtime_snapshot_backup_root_with_policy(
            ".af-rt-snap-sonarr-nofallback",
            &host_default_env,
            real_root_policy,
            None,
        )
        .expect_err("privileged real-host mode must fail closed without falling back to temp_dir");
        assert!(!err.is_empty());
        assert_eq!(
            std::fs::read_dir(&staging).unwrap().count(),
            0,
            "privileged real-host failure must not create fallback snapshots in temp_dir"
        );
    }

    // 4. Reject insecure recovery root permissions (0o755 / 0o777) and wrong expected_uid.
    std::fs::set_permissions(
        &expected_recovery_root,
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let mode_err = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-mode",
        &env_cfg,
        priv_policy,
        None,
    )
    .expect_err("0o755 recovery root must be rejected");
    assert!(
        mode_err.contains("0o700"),
        "unexpected mode error: {mode_err}"
    );
    std::fs::set_permissions(
        &expected_recovery_root,
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();

    let uid_err = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-uid",
        &env_cfg,
        RecoveryStoragePolicy {
            privileged: true,
            expected_uid: current_uid.saturating_add(1),
        },
        None,
    )
    .expect_err("wrong owner uid must be rejected");
    assert!(
        uid_err.contains("owned by uid"),
        "unexpected uid error: {uid_err}"
    );

    // 5. Reject group-writable ancestor under privileged policy.
    let var_backups = fixture.join("var/backups");
    std::fs::set_permissions(&var_backups, std::fs::Permissions::from_mode(0o775)).unwrap();
    let ancestor_err = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-ancestor",
        &env_cfg,
        priv_policy,
        None,
    )
    .expect_err("group-writable ancestor must be rejected under privileged policy");
    assert!(
        ancestor_err.contains("unsafe writable permissions"),
        "unexpected ancestor error: {ancestor_err}"
    );
    std::fs::set_permissions(&var_backups, std::fs::Permissions::from_mode(0o755)).unwrap();

    // 6. Reject symlinked recovery leaf and symlinked ancestor.
    let decoy = base.join("decoy");
    std::fs::create_dir_all(&decoy).unwrap();
    std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(&expected_recovery_root).unwrap();
    std::os::unix::fs::symlink(&decoy, &expected_recovery_root).unwrap();
    let sym_leaf_err = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-symleaf",
        &env_cfg,
        priv_policy,
        None,
    )
    .expect_err("symlinked recovery root must be rejected");
    assert!(
        sym_leaf_err.to_ascii_lowercase().contains("symlink"),
        "unexpected symlink leaf error: {sym_leaf_err}"
    );

    std::fs::remove_file(&expected_recovery_root).unwrap();
    std::fs::remove_dir(&var_backups).unwrap();
    std::os::unix::fs::symlink(&decoy, &var_backups).unwrap();
    let sym_anc_err = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-symanc",
        &env_cfg,
        priv_policy,
        None,
    )
    .expect_err("symlinked recovery ancestor must be rejected");
    assert!(
        sym_anc_err.to_ascii_lowercase().contains("symlink"),
        "unexpected symlink ancestor error: {sym_anc_err}"
    );

    force_remove_backup_tree(&base);
}

#[cfg(unix)]
#[test]
fn test_durable_recovery_storage_unprivileged_api_fallback_prefers_data_dir() {
    use std::os::unix::fs::PermissionsExt;

    let current_uid = unsafe { libc::geteuid() };
    let unpriv_policy = RecoveryStoragePolicy {
        privileged: false,
        expected_uid: current_uid,
    };

    // Place synthetic DATA_DIR beside test binary (non-ephemeral persistent path) to exercise Mode 4.
    let target_dir = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join(format!("af-unpriv-dd-{}", uuid::Uuid::new_v4()));
    let data_dir = target_dir.join("data");
    let fallback_tmp =
        std::env::temp_dir().join(format!("af-unpriv-fallback-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::create_dir_all(&fallback_tmp).unwrap();

    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = None;
    env_cfg.recovery_root = None;
    env_cfg.temp_dir = fallback_tmp.clone();

    let persistent_snap = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-unpriv1",
        &env_cfg,
        unpriv_policy,
        Some(&data_dir),
    )
    .expect("unprivileged Mode 4 should prefer persistent DATA_DIR/recovery");
    assert_eq!(
        persistent_snap.parent(),
        Some(data_dir.join("recovery").as_path())
    );
    assert_eq!(
        std::fs::symlink_metadata(data_dir.join("recovery"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::symlink_metadata(&persistent_snap)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    // Without DATA_DIR, unprivileged API fallback still succeeds with private 0o700 dir in temp_dir.
    let fallback_snap = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-unpriv2",
        &env_cfg,
        unpriv_policy,
        None,
    )
    .expect("unprivileged Mode 4 without DATA_DIR should fall back to temp_dir");
    assert_eq!(fallback_snap.parent(), Some(fallback_tmp.as_path()));
    assert_eq!(
        std::fs::symlink_metadata(&fallback_snap)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    force_remove_backup_tree(&target_dir);
    force_remove_backup_tree(&fallback_tmp);
}

#[cfg(unix)]
#[test]
fn test_runtime_snapshot_ordinary_cleanup_and_incomplete_rollback_preservation() {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!(
        "af-durable-cleanup-preserve-{}",
        uuid::Uuid::new_v4()
    ));
    let env_cfg = crate::PackageExecutionEnv::isolated(&root);
    let live_dir = root.join("var/lib/sonarr");
    std::fs::create_dir_all(&live_dir).unwrap();
    let config = live_dir.join("config.xml");
    std::fs::write(&config, b"<Config>v1</Config>").unwrap();

    // 1. Ordinary capture + drop cleans up the snapshot directory.
    let snap_clean = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false)
        .expect("capture in isolated root should succeed");
    let clean_backup = snap_clean.backup_root.clone();
    let expected_recovery_root = root.join("var/backups/aetherflow-recovery");
    assert_eq!(
        clean_backup.parent(),
        Some(expected_recovery_root.as_path())
    );
    assert_eq!(
        std::fs::symlink_metadata(&expected_recovery_root)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::symlink_metadata(&clean_backup)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(
        !root.join("tmp").exists() || sonarr_runtime_snap_dirs_in(&root.join("tmp")).is_empty(),
        "isolated capture must never place snapshots under tmp"
    );
    drop(snap_clean);
    assert!(
        !clean_backup.exists(),
        "ordinary drop must remove snapshot backup directory"
    );

    // 2. Capture + mutate + restore restores live data and cleans up snapshot on drop.
    let mut snap_restore = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false)
        .expect("second capture should succeed");
    let restore_backup = snap_restore.backup_root.clone();
    std::fs::write(&config, b"<Config>v2-broken</Config>").unwrap();
    snap_restore.restore().expect("restore should succeed");
    assert_eq!(std::fs::read(&config).unwrap(), b"<Config>v1</Config>");
    drop(snap_restore);
    assert!(
        !restore_backup.exists(),
        "clean restore drop must remove snapshot backup directory"
    );

    // 3. Preserved snapshot (e.g. quiesce failure / incomplete rollback) stays intact on drop.
    let mut snap_preserve = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false)
        .expect("third capture should succeed");
    let preserved_backup = snap_preserve.backup_root.clone();
    snap_preserve.preserve_on_drop = true;
    drop(snap_preserve);
    assert!(
        preserved_backup.is_dir(),
        "preserve_on_drop must keep backup under persistent recovery root"
    );
    assert_eq!(
        preserved_backup.parent(),
        Some(expected_recovery_root.as_path())
    );

    force_remove_backup_tree(&root);
}

#[test]
fn test_apply_legacy_package_environment_sets_persistent_recovery_root_distinct_from_scratch() {
    let _guard = ENV_TEST_MUTEX.lock().unwrap();
    let saved_fs = std::env::var_os("AETHERFLOW_FS_ROOT");
    let saved_install = std::env::var_os("AETHERFLOW_INSTALL_ROOT");
    let saved_recovery = std::env::var_os("AETHERFLOW_RECOVERY_ROOT");
    let saved_af_recovery = std::env::var_os("AF_RECOVERY_ROOT");

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    std::env::remove_var("AETHERFLOW_INSTALL_ROOT");
    std::env::remove_var("AETHERFLOW_RECOVERY_ROOT");
    std::env::remove_var("AF_RECOVERY_ROOT");

    let req = crate::PackageRunnerRequest {
        action: "update".to_string(),
        package_id: "n8n".to_string(),
        script_name: "installpackage-n8n".to_string(),
        app_port: 5678,
        delete_data: false,
        expected_target_version: Some("1.90.0".to_string()),
        achieved_version: None,
        lifecycle_job_id: "job-env-check".to_string(),
    };

    let mut host_cmd = tokio::process::Command::new("/bin/true");
    crate::package_executor::apply_legacy_package_environment(&mut host_cmd, &req);
    let host_envs: std::collections::HashMap<_, _> = host_cmd
        .as_std()
        .get_envs()
        .map(|(k, v)| (k.to_os_string(), v.map(|val| val.to_os_string())))
        .collect();
    assert_eq!(
        host_envs.get(std::ffi::OsStr::new("AF_RECOVERY_ROOT")),
        Some(&Some(std::ffi::OsString::from(
            crate::package_executor::DEFAULT_PRIVILEGED_RECOVERY_ROOT
        )))
    );
    assert_eq!(
        host_envs.get(std::ffi::OsStr::new("AF_TRANSACTION_ROOT")),
        Some(&Some(std::ffi::OsString::from(
            crate::package_executor::DEFAULT_PRIVILEGED_RECOVERY_ROOT
        )))
    );
    assert_eq!(
        host_envs.get(std::ffi::OsStr::new("AF_JOB_SCRATCH_ROOT")),
        Some(&Some(std::ffi::OsString::from(
            "/var/tmp/aetherflow-scratch"
        )))
    );
    assert_eq!(
        host_envs.get(std::ffi::OsStr::new("AF_FIXTURE_ROOT")),
        Some(&None),
        "real host runner must strip ambient AF_FIXTURE_ROOT"
    );
    assert_eq!(
        host_envs.get(std::ffi::OsStr::new("TEST_ROOT")),
        Some(&None),
        "real host runner must strip ambient TEST_ROOT"
    );

    let fixture_root = std::env::temp_dir().join("af-legacy-env-fixture");
    std::env::set_var("AETHERFLOW_FS_ROOT", &fixture_root);
    let mut iso_cmd = tokio::process::Command::new("/bin/true");
    crate::package_executor::apply_legacy_package_environment(&mut iso_cmd, &req);
    let iso_envs: std::collections::HashMap<_, _> = iso_cmd
        .as_std()
        .get_envs()
        .map(|(k, v)| (k.to_os_string(), v.map(|val| val.to_os_string())))
        .collect();
    let expected_iso = fixture_root
        .join("var/backups/aetherflow-recovery")
        .into_os_string();
    assert_eq!(
        iso_envs.get(std::ffi::OsStr::new("AF_RECOVERY_ROOT")),
        Some(&Some(expected_iso.clone()))
    );
    assert_eq!(
        iso_envs.get(std::ffi::OsStr::new("AF_TRANSACTION_ROOT")),
        Some(&Some(expected_iso))
    );

    for (key, prev) in [
        ("AETHERFLOW_FS_ROOT", saved_fs),
        ("AETHERFLOW_INSTALL_ROOT", saved_install),
        ("AETHERFLOW_RECOVERY_ROOT", saved_recovery),
        ("AF_RECOVERY_ROOT", saved_af_recovery),
    ] {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
}
