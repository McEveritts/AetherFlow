use super::*;

#[test]
fn test_preflight_rejects_tmpfs_staging() {
    let _env_guard = crate::ENV_TEST_MUTEX.blocking_lock();
    let shm_dir = Path::new("/dev/shm");
    if !shm_dir.exists() {
        return;
    }
    let test_root = shm_dir.join(format!("af-test-tmpfs-{}", uuid::Uuid::new_v4()));
    let var_tmp_dir = test_root.join("var/tmp");
    fs::create_dir_all(&var_tmp_dir).unwrap();

    // 1. Direct check_filesystem_capacity_and_inodes on /dev/shm/.../var/tmp must reject tmpfs
    let direct_res = check_filesystem_capacity_and_inodes(&var_tmp_dir, 512 * 1024 * 1024, 1024);
    assert!(
        direct_res.is_err(),
        "check_filesystem_capacity_and_inodes on tmpfs /var/tmp must fail"
    );
    let err_msg = direct_res.unwrap_err();
    assert!(
        err_msg.contains("tmpfs"),
        "Error message must specify tmpfs rejection: {}",
        err_msg
    );

    // 2. preflight_check_disk_and_inodes with fs_root in /dev/shm must reject tmpfs /var/tmp
    let preflight_res = preflight_check_disk_and_inodes(Some(&test_root));
    assert!(
        preflight_res.is_err(),
        "preflight_check_disk_and_inodes must reject tmpfs staging root"
    );

    // 3. AF_REJECT_TMPFS_STAGING=1 must also reject tmpfs on any check path
    {
        let _reject_guard = EnvVarGuard::new(&[("AF_REJECT_TMPFS_STAGING", Some("1"))]);
        let env_res = check_filesystem_capacity_and_inodes(&test_root, 512 * 1024 * 1024, 1024);
        assert!(
            env_res.is_err(),
            "AF_REJECT_TMPFS_STAGING=1 must reject tmpfs mount"
        );
    }

    let _ = fs::remove_dir_all(&test_root);
}

#[tokio::test]
async fn test_threadfin_execute_recipe_staging_preflight_allows_disk_var_tmp_and_blocks_symlinks_and_tmpfs(
) {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let _env_guard = EnvVarGuard::new(&[("AF_REJECT_TMPFS_STAGING", Some("1"))]);

    // Managed mutable path boundaries must NOT be widened to include /var/tmp.
    assert!(
        validate_managed_path("/var/tmp").is_err(),
        "/var/tmp must remain outside ALLOWED_MANAGED_PREFIXES"
    );

    let elf_bytes = create_mock_elf_payload_for_arch(4096, 62);
    let mut recipe =
        get_declarative_recipe("threadfin").expect("threadfin recipe must be registered");
    for step in recipe
        .install_steps
        .iter_mut()
        .chain(recipe.update_steps.iter_mut())
    {
        if let DeclarativeStep::DownloadBinary { verification, .. } = step {
            verification.expected_sha256 = Some(hex::encode(Sha256::digest(&elf_bytes)));
        }
    }

    // 1. Disk-backed staging root under /var/tmp must pass preflight instead of
    // tripping ALLOWED_MANAGED_PREFIXES SecurityViolation on "/var/tmp".
    let disk_base = Path::new("/var/tmp");
    if disk_base.is_dir()
        && ensure_sufficient_disk_space(disk_base, 512 * 1024 * 1024, 1024).is_ok()
    {
        let root = disk_base.join(format!("af-threadfin-staging-ok-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("var/tmp")).unwrap();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(
            root.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nthreadfin:x:995:987::/var/lib/threadfin:/usr/sbin/nologin\n",
        )
        .unwrap();
        let env_cfg = PackageExecutionEnv::isolated(&root);
        let cache_dir = env_cfg.artifact_cache_dir.clone().unwrap();
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(
            cache_dir.join("Threadfin_linux_amd64_glibc_2.31_compat"),
            &elf_bytes,
        )
        .unwrap();

        let executor =
            DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
        let outcome = executor
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("threadfin install must pass /var/tmp staging preflight on disk-backed root");
        assert!(outcome.lock_present);
        assert!(root.join("install/.threadfin.lock").is_file());
        assert!(root.join("usr/local/bin/threadfin").is_file());
        assert_eq!(
            fs::read_to_string(root.join("var/lib/threadfin/.af-version"))
                .unwrap()
                .trim(),
            THREADFIN_PINNED_VERSION
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(root.join("var/lib/threadfin"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
            assert_eq!(
                fs::metadata(root.join("var/lib/threadfin/conf"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o750
            );
            assert_eq!(
                fs::metadata(root.join("var/lib/threadfin/conf/settings.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let dropin_dir = root.join("etc/systemd/system/threadfin.service.d");
        assert!(
            !dropin_dir.join("aetherflow-sandbox.conf").exists(),
            "legacy unnumbered aetherflow-sandbox.conf must not be written"
        );
        let dropin_text =
            fs::read_to_string(dropin_dir.join("10-aetherflow-sandbox.conf")).unwrap();
        assert!(
            dropin_text.contains("ReadWritePaths=/var/lib/threadfin ")
                || dropin_text.contains("ReadWritePaths=-/var/lib/threadfin "),
            "10-aetherflow-sandbox.conf must refresh ReadWritePaths after WriteSystemdUnit, got:\n{dropin_text}"
        );
        assert!(
            !dropin_text.contains("/var/lib/threadfin /var/lib/threadfin")
                && !dropin_text.contains("-/var/lib/threadfin -/var/lib/threadfin"),
            "10-aetherflow-sandbox.conf must deduplicate {{SERVICE_HOME}} against /var/lib/threadfin, got:\n{dropin_text}"
        );
        assert!(
            !dropin_text.contains("/root"),
            "10-aetherflow-sandbox.conf must not leak /root into ReadWritePaths, got:\n{dropin_text}"
        );
        let _ = fs::remove_dir_all(&root);

        // 2. Symlinked <root>/var/tmp must be rejected by validate_filesystem_path.
        #[cfg(unix)]
        {
            let sym_root =
                disk_base.join(format!("af-threadfin-staging-sym-{}", uuid::Uuid::new_v4()));
            let real_dir = sym_root.join("real-tmp");
            fs::create_dir_all(&real_dir).unwrap();
            fs::create_dir_all(sym_root.join("var")).unwrap();
            std::os::unix::fs::symlink(&real_dir, sym_root.join("var/tmp")).unwrap();

            let sym_env = PackageExecutionEnv::isolated(&sym_root);
            let sym_cache = sym_env.artifact_cache_dir.clone().unwrap();
            fs::create_dir_all(&sym_cache).unwrap();
            fs::write(
                sym_cache.join("Threadfin_linux_amd64_glibc_2.31_compat"),
                &elf_bytes,
            )
            .unwrap();

            let sym_exec =
                DeclarativePackageExecutor::with_runner(sym_env, MockCommandRunner::default());
            let err = sym_exec
                .execute_recipe(
                    &recipe,
                    PackageAction::Install,
                    CancellationToken::new(),
                    |_| {},
                )
                .await
                .expect_err("symlinked /var/tmp staging root must be rejected");
            assert!(
                matches!(err, PackageExecutorError::SecurityViolation(_))
                    && err.to_string().contains("symlink"),
                "expected symlink SecurityViolation, got: {err}"
            );
            assert!(!sym_root.join("install/.threadfin.lock").exists());
            let _ = fs::remove_dir_all(&sym_root);
        }
    }

    // 3. tmpfs staging root (/dev/shm) must still be rejected by staging preflight.
    let shm_dir = Path::new("/dev/shm");
    if shm_dir.is_dir() {
        let shm_root = shm_dir.join(format!("af-threadfin-staging-shm-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(shm_root.join("var/tmp")).unwrap();
        let shm_env = PackageExecutionEnv::isolated(&shm_root);
        let shm_cache = shm_env.artifact_cache_dir.clone().unwrap();
        fs::create_dir_all(&shm_cache).unwrap();
        fs::write(
            shm_cache.join("Threadfin_linux_amd64_glibc_2.31_compat"),
            &elf_bytes,
        )
        .unwrap();

        let shm_exec =
            DeclarativePackageExecutor::with_runner(shm_env, MockCommandRunner::default());
        let err = shm_exec
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect_err("tmpfs /var/tmp staging root must be rejected");
        assert!(
            err.to_string().contains("tmpfs"),
            "expected tmpfs staging rejection, got: {err}"
        );
        assert!(!shm_root.join("install/.threadfin.lock").exists());
        let _ = fs::remove_dir_all(&shm_root);
    }
}

#[test]
fn test_incomplete_rollback_line_detection_and_formatting() {
    let lines = [
            "Rclone rollback aborted because service quiescence failed; preserving recovery archive /var/backups/rclone (incomplete-rollback)",
            "Application recovery is incomplete; recovery backup preserved",
            "Rollback incomplete; recovery backup preserved",
            "Failed to stop unit sonarr.service",
        ];

    for line in lines {
        let lower = line.to_ascii_lowercase();
        assert!(
            crate::package_lifecycle::is_incomplete_rollback_error(line)
                || lower.contains("incomplete-rollback")
                || lower.contains("incomplete rollback")
                || lower.contains("recovery backup preserved"),
            "Line must match incomplete rollback criteria: {line}"
        );

        let sanitized = crate::package_lifecycle::sanitize_lifecycle_field(line.trim());
        let exit_err = format!(
                "__RUNNER_EXIT_ERROR__:exit status 1 [STAGE:rollback] [CATEGORY:incomplete_rollback] [SUMMARY:{}] | incomplete-rollback\n",
                sanitized
            );

        assert!(
            crate::package_lifecycle::is_incomplete_rollback_error(&exit_err),
            "Formatted exit error must be identified by is_incomplete_rollback_error: {exit_err}"
        );
    }
}

#[test]
fn test_format_exit_failure_diagnostics_overrides_stage_and_diag_json_on_incomplete_rollback() {
    let raw_diag = serde_json::json!({
        "stage": "installer",
        "category": "installer_failure",
        "summary": "install boom",
    });

    let inc_line = "Failed to stop unit test.service (incomplete-rollback)";
    let exit_msg = format_exit_failure_diagnostics(1, Some(&raw_diag), Some(inc_line))
        .expect("Must format diagnostic exit message");

    // 1. Message must have [STAGE:rollback] [CATEGORY:incomplete_rollback]
    assert!(
        exit_msg.contains("[STAGE:rollback]"),
        "Must override stage to rollback: {exit_msg}"
    );
    assert!(
        exit_msg.contains("[CATEGORY:incomplete_rollback]"),
        "Must set category to incomplete_rollback: {exit_msg}"
    );
    assert!(
        exit_msg.contains("install boom; Failed to stop unit test.service (incomplete-rollback)"),
        "Summary must combine: {exit_msg}"
    );

    // 2. Trailing AF_DIAG_FAILURE={...} must have stage: rollback, category: incomplete_rollback, and updated summary
    let marker = "AF_DIAG_FAILURE=";
    let pos = exit_msg
        .find(marker)
        .expect("Must contain AF_DIAG_FAILURE marker");
    let json_part = exit_msg[pos + marker.len()..].trim();
    let parsed: serde_json::Value =
        serde_json::from_str(json_part).expect("Trailing JSON must be valid");

    assert_eq!(
        parsed.get("stage").and_then(|v| v.as_str()),
        Some("rollback")
    );
    assert_eq!(
        parsed.get("category").and_then(|v| v.as_str()),
        Some("incomplete_rollback")
    );
    assert_eq!(
        parsed.get("summary").and_then(|v| v.as_str()),
        Some("install boom; Failed to stop unit test.service (incomplete-rollback)")
    );
}
