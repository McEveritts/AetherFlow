use super::*;

#[test]
fn test_cloudplow_version_probe_reads_the_deployed_git_commit() {
    const FIXTURE_CHILD: &str = "AF_CLOUDPLOW_PROBE_TEST_CHILD";
    if std::env::var_os(FIXTURE_CHILD).is_none() {
        let config = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .unwrap()
            .join("config");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "package_lifecycle::version_verification_tests::version_probing::test_cloudplow_version_probe_reads_the_deployed_git_commit",
            ])
            .env(FIXTURE_CHILD, "1")
            .env("AETHERFLOW_PACKAGES_CONFIG", config.join("packages.json"))
            .env(
                "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
                config.join("package_automation.json"),
            )
            .status()
            .unwrap();
        assert!(status.success(), "isolated Cloudplow probe test failed");
        return;
    }

    let installed = std::env::temp_dir().join(format!("af-cloudplow-{}", uuid::Uuid::new_v4()));
    let checkout = installed.join("opt/cloudplow");
    std::fs::create_dir_all(checkout.join(".git")).unwrap();
    let live_commit = "b".repeat(40);
    std::fs::write(checkout.join(".git/HEAD"), format!("{live_commit}\n")).unwrap();
    let env = crate::PackageExecutionEnv {
        fs_root: Some(installed.clone()),
        ..Default::default()
    };

    std::fs::write(checkout.join(".af-version"), "a".repeat(40)).unwrap();
    assert!(matches!(
        probe_live_runtime_version("cloudplow", &env),
        LiveRuntimeProbeOutcome::Verified(version) if version == live_commit
    ));
    assert!(resolve_verified_installed_version("cloudplow", &env).is_none());

    std::fs::write(checkout.join(".af-version"), &live_commit).unwrap();
    assert_eq!(
        resolve_verified_installed_version("cloudplow", &env),
        Some(live_commit)
    );
    std::fs::remove_dir_all(installed).unwrap();
}

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
    let bin_dir = temp_dir.join("opt/AetherFlow/apps/rclone");
    std::fs::create_dir_all(&bin_dir).unwrap();

    std::fs::write(bin_dir.join(".af-owner"), b"rclone\n").unwrap();

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

    // Exercise the production executable path and regex inside the fixture root.
    let packages_path = temp_dir.join("packages.json");
    std::fs::write(&packages_path, crate::EMBEDDED_PACKAGES_JSON).unwrap();
    let automation_path = temp_dir.join("package_automation.json");
    std::fs::write(&automation_path, crate::EMBEDDED_AUTOMATION_JSON).unwrap();
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
fn rclone_legacy_version_probe_and_snapshot_have_distinct_ownership() {
    let scratch =
        std::env::temp_dir().join(format!("af-test-rclone-paths-{}", uuid::Uuid::new_v4()));
    let root = scratch.as_path();
    let distro = root.join("usr/bin/rclone");
    let operator = root.join("usr/local/bin/rclone");
    let managed = root.join("opt/AetherFlow/apps/rclone/rclone");
    let unit = root.join("etc/systemd/system/rclone.service");
    for path in [&distro, &operator, &unit] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    }
    std::fs::write(&distro, b"distro").unwrap();
    std::fs::write(&operator, b"operator").unwrap();
    assert!(crate::probe_metadata::rclone_version_program(Some(root)).is_err());

    std::fs::write(
        &unit,
        b"[Service]\nUser=rclone\nEnvironmentFile=/etc/aetherflow/rclone.env\nExecStart=/usr/bin/rclone rcd --rc-web-gui\n",
    ).unwrap();
    assert_eq!(
        crate::probe_metadata::rclone_version_program(Some(root)).unwrap(),
        distro
    );
    std::fs::create_dir_all(managed.parent().unwrap()).unwrap();
    std::fs::write(&managed, b"managed").unwrap();
    assert_eq!(
        crate::probe_metadata::rclone_version_program(Some(root)).unwrap(),
        distro
    );
    std::fs::write(managed.with_file_name(".af-owner"), b"rclone\n").unwrap();
    assert_eq!(
        crate::probe_metadata::rclone_version_program(Some(root)).unwrap(),
        managed
    );

    let env_cfg = crate::PackageExecutionEnv::isolated(root);
    let targets = candidate_runtime_targets("rclone", &["rclone.service".into()], &env_cfg);
    assert!(targets.iter().any(|(path, _)| path == &managed));
    assert!(targets
        .iter()
        .any(|(path, _)| path == &root.join("etc/aetherflow/rclone.env")));
    assert!(!targets
        .iter()
        .any(|(path, _)| path == &distro || path == &operator));
    assert!(!targets
        .iter()
        .any(|(path, _)| path == &root.join("usr/lib/systemd/system/rclone.service")));
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn listenarr_receipt_paths_and_runtime_evidence_recognize_capitalized_opt_dir() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = std::env::temp_dir().join(format!(
        "af-test-listenarr-receipt-{}",
        uuid::Uuid::new_v4()
    ));
    let root = scratch.as_path();
    let opt_dir = root.join("opt/Listenarr");
    std::fs::create_dir_all(&opt_dir).unwrap();
    let receipt = opt_dir.join(".af-version");
    std::fs::write(&receipt, "1.10.6-canary\n").unwrap();

    let env_cfg = crate::PackageExecutionEnv::isolated(root);
    let candidates = candidate_version_marker_paths_with_env("listenarr", &env_cfg).unwrap();
    assert!(
        candidates.contains(&receipt),
        "expected {:?} in {candidates:?}",
        receipt
    );
    assert_eq!(
        read_af_version_receipt("listenarr", &env_cfg).as_deref(),
        Some("1.10.6-canary")
    );
    // Receipt alone does not count as independent runtime evidence
    assert!(!has_independent_runtime_evidence("listenarr", &env_cfg));

    // Adding executable self-contained Listenarr.Api (without Listenarr.Api.dll) satisfies independent runtime evidence
    let binary = opt_dir.join("Listenarr.Api");
    std::fs::write(&binary, b"\x7fELF").unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(has_independent_runtime_evidence("listenarr", &env_cfg));

    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn test_probe_live_runtime_version_apt_uses_dpkg_status_and_update_package() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();
    use std::os::unix::fs::PermissionsExt;

    let scratch =
        std::env::temp_dir().join(format!("af-test-apt-live-probe-{}", uuid::Uuid::new_v4()));
    let bin_dir = scratch.join("usr/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(scratch.join("var/lib/quassel")).unwrap();

    // Decoy quasselcore binary returning bare upstream version without Debian epoch/revision
    let decoy = bin_dir.join("quasselcore");
    std::fs::write(&decoy, "#!/bin/sh\necho 'Quassel IRC: 0.14.0'\n").unwrap();
    std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Synthetic dpkg-query reporting full Debian versions for update_package targets
    let dpkg_shim = bin_dir.join("dpkg-query");
    std::fs::write(
        &dpkg_shim,
        r#"#!/bin/sh
pkg=""
for a in "$@"; do pkg="$a"; done
case "$pkg" in
    quassel-core) echo "installed 1:0.14.0-1+deb12u1" ;;
    wireguard-tools) echo "installed 1.0.20210914-1.1+b1" ;;
    wireguard) echo "installed 1.0.20210914-1" ;;
    jellyfin) echo "config-files 10.10.3+deb12" ;;
    *) exit 1 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&dpkg_shim, std::fs::Permissions::from_mode(0o755)).unwrap();

    let env_cfg = crate::PackageExecutionEnv::isolated(&scratch);

    // 1. quassel queries quassel-core via dpkg-query (NOT decoy quasselcore binary)
    assert_eq!(
        probe_live_runtime_version("quassel", &env_cfg),
        LiveRuntimeProbeOutcome::Verified("1:0.14.0-1+deb12u1".to_string())
    );

    // 2. Legacy stripped receipt ("0.14.0") stays compatible while returning live full Debian version
    std::fs::write(scratch.join("var/lib/quassel/.af-version"), "0.14.0\n").unwrap();
    assert_eq!(
        resolve_verified_installed_version("quassel", &env_cfg).as_deref(),
        Some("1:0.14.0-1+deb12u1")
    );

    // 3. wireguard queries wireguard-tools (NOT wireguard metapackage)
    assert_eq!(
        probe_live_runtime_version("wireguard", &env_cfg),
        LiveRuntimeProbeOutcome::Verified("1.0.20210914-1.1+b1".to_string())
    );

    // 4. Non-installed dpkg state (config-files) fails closed
    assert!(matches!(
        probe_live_runtime_version("jellyfin", &env_cfg),
        LiveRuntimeProbeOutcome::Failed(_)
    ));

    let _ = std::fs::remove_dir_all(&scratch);
}
