use super::*;

#[cfg(unix)]
#[test]
fn heal_state_survives_unknown_and_active_lifecycle_until_recovery() {
    use crate::inventory_regressions::{isolated, Fixture};
    use std::os::unix::fs::PermissionsExt;
    let name = "workers::tests::health_and_probes::heal_state_survives_unknown_and_active_lifecycle_until_recovery";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let exhausted = ServiceHealState {
        failure_count: MAX_HEAL_RETRIES,
        exhausted: true,
        next_retry_at: Some(Instant::now() + Duration::from_secs(300)),
    };
    let backed_off = ServiceHealState {
        failure_count: 2,
        exhausted: false,
        next_retry_at: Some(Instant::now() + Duration::from_secs(300)),
    };
    let seeded = HashMap::from([
        ("fixture-main".to_string(), exhausted.clone()),
        ("apache2".to_string(), exhausted.clone()),
        ("aetherflow-runner".to_string(), backed_off),
        ("retired-unit".to_string(), exhausted.clone()),
    ]);
    *HEAL_STATES.lock().unwrap() = seeded.clone();
    let hidden = fixture.journal.with_extension("unavailable");
    std::fs::rename(&fixture.journal, &hidden).unwrap();
    runtime.block_on(perform_heal_check());
    assert_eq!(*HEAL_STATES.lock().unwrap(), seeded);
    assert!(!fixture.calls.exists());
    std::fs::rename(&hidden, &fixture.journal).unwrap();
    let job = crate::PackageJobInfo {
        job_id: "seeded-heal-job".into(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 0,
        last_line: String::new(),
        started_at: Utc::now().to_rfc3339(),
        expected_target_version: None,
    };
    assert!(crate::try_start_package_job(job));
    runtime.block_on(perform_heal_check());
    assert_eq!(*HEAL_STATES.lock().unwrap(), seeded);
    assert!(!fixture.calls.exists());
    crate::finish_package_job("fixture", "update", true, "", "seeded-heal-job").unwrap();
    std::fs::write(&fixture.catalog, "corrupt").unwrap();
    runtime.block_on(perform_heal_check());
    assert_eq!(*HEAL_STATES.lock().unwrap(), seeded);
    fixture.write_packages(&[Fixture::package("fixture", "systemd", "fixture-main")]);
    let install = fixture.root.join("install");
    std::fs::set_permissions(&install, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert_eq!(
        std::fs::symlink_metadata(install.join(".fixture.lock"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied,
    );
    runtime.block_on(perform_heal_check());
    std::fs::set_permissions(&install, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(*HEAL_STATES.lock().unwrap(), seeded);
    assert!(!fixture.calls.exists());
    fixture.command("systemctl", "printf '%s\\n' \"$*\" >> \"$AF_STATUS_CALLS\"\ncase \"$1 $2\" in 'is-active fixture-main') echo inactive; exit 3;; is-active*) echo active;; show*) printf 'LoadState=loaded\\nType=simple\\n';; *) exit 92;; esac\n");
    runtime.block_on(perform_heal_check());
    {
        let states = HEAL_STATES.lock().unwrap();
        assert_eq!(states["fixture-main"], exhausted);
        assert_eq!(states["apache2"], ServiceHealState::default());
        assert_eq!(states["aetherflow-runner"], ServiceHealState::default());
        assert!(!states.contains_key("retired-unit"));
    }
    fixture.command("systemctl", "printf '%s\\n' \"$*\" >> \"$AF_STATUS_CALLS\"\ntest \"$1\" = is-active || exit 92\necho active\n");
    runtime.block_on(perform_heal_check());
    assert_eq!(
        HEAL_STATES.lock().unwrap()["fixture-main"],
        ServiceHealState::default()
    );
    let suspended = HashMap::from([
        (
            "apache2".to_string(),
            ServiceHealState {
                failure_count: 1,
                next_retry_at: None,
                exhausted: false,
            },
        ),
        ("fixture-main".to_string(), exhausted),
    ]);
    *HEAL_STATES.lock().unwrap() = suspended.clone();
    fixture.command("systemctl", "printf '%s\\n' \"$*\" >> \"$AF_STATUS_CALLS\"\ncase \"$1\" in is-active) echo inactive; exit 3;; show) printf 'LoadState=loaded\\nType=simple\\n';; *) exit 92;; esac\n");
    let local_guard = crate::PACKAGE_LIFECYCLE_MUTEX.try_lock().unwrap();
    runtime.block_on(perform_heal_check());
    assert_eq!(*HEAL_STATES.lock().unwrap(), suspended);
    drop(local_guard);
    let calls = std::fs::read_to_string(&fixture.calls).unwrap();
    assert!(calls
        .lines()
        .all(|call| call.starts_with("is-active ") || call.starts_with("show ")));
    println!("seeded exhausted budgets, notification flag and retry deadlines survive journal/catalog uncertainty and active jobs; only recovered/deleted units reset");
}

#[cfg(unix)]
#[test]
fn healing_status_timeouts_kill_and_reap_both_probe_children() {
    use crate::inventory_regressions::{isolated, Fixture};
    let name = "workers::tests::health_and_probes::healing_status_timeouts_kill_and_reap_both_probe_children";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    let fifo = fixture.root.join("blocked-health");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    std::env::set_var("AF_BLOCK_FIFO", fifo);
    std::env::set_var("AF_STATUS_PID", fixture.root.join("health.pid"));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    fixture.command(
        "systemctl",
        "printf '%s' \"$$\" > \"$AF_STATUS_PID\"\nexec /bin/cat \"$AF_BLOCK_FIFO\"\n",
    );
    let start = Instant::now();
    assert_eq!(
        runtime.block_on(check_systemd_unit_healthy("fixture-main")),
        None
    );
    assert!(start.elapsed() >= Duration::from_secs(10));
    assert!(start.elapsed() < Duration::from_secs(12));
    let pid = std::fs::read_to_string(fixture.root.join("health.pid")).unwrap();
    assert!(!Path::new("/proc").join(pid).exists());
    fixture.command("systemctl", "case \"$1\" in is-active) echo inactive; exit 3;; show) printf '%s' \"$$\" > \"$AF_STATUS_PID\"; exec /bin/cat \"$AF_BLOCK_FIFO\";; *) exit 92;; esac\n");
    let start = Instant::now();
    assert_eq!(
        runtime.block_on(check_systemd_unit_healthy("fixture-main")),
        None
    );
    assert!(start.elapsed() >= Duration::from_secs(5));
    assert!(start.elapsed() < Duration::from_secs(7));
    let pid = std::fs::read_to_string(fixture.root.join("health.pid")).unwrap();
    assert!(!Path::new("/proc").join(pid).exists());
    println!("actual is-active (10s) and metadata show (5s) timeouts both return unknown and reap FIFO-blocked children");
}

#[cfg(unix)]
#[test]
fn heal_poll_is_read_only_and_unknown_snapshots_skip_controls() {
    let name = "workers::tests::health_and_probes::heal_poll_is_read_only_and_unknown_snapshots_skip_controls";
    if std::env::var("AF_HEAL_POLL_TEST_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_HEAL_POLL_TEST_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("af-heal-poll-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    std::env::set_var("AETHERFLOW_FS_ROOT", &root);
    std::env::set_var("AETHERFLOW_RELEASE_ROOT", &root);
    let catalog = root.join("packages.json");
    std::fs::write(
        &catalog,
        serde_json::to_string(&[af_models::Package {
            name: "fixture".into(),
            service_name: "fixture".into(),
            service_type: "systemd".into(),
            lock_file: "/install/.fixture.lock".into(),
            ..Default::default()
        }])
        .unwrap(),
    )
    .unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", catalog);
    let cfg = af_release::ReleaseConfig::for_root(&root);
    let path = af_release::config::try_resolve_db_path(&cfg, None)
        .unwrap()
        .path;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    crate::initialize_package_jobs(rusqlite::Connection::open(&path).unwrap()).unwrap();
    let controls = root.join("bin");
    std::fs::create_dir(&controls).unwrap();
    let calls = root.join("calls");
    let ctl = controls.join("systemctl");
    std::fs::write(&ctl, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$AF_HEAL_CALLS\"\ncase \"$1\" in is-active) echo active;; *) exit 92;; esac\n").unwrap();
    std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::env::set_var("AF_HEAL_CALLS", &calls);
    std::env::set_var(
        "PATH",
        format!("{}:{}", controls.display(), std::env::var("PATH").unwrap()),
    );
    let runtime = tokio::runtime::Runtime::new().unwrap();
    // Healthy observations still run while genuine mutations own both locks.
    let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    let local = crate::PACKAGE_LIFECYCLE_MUTEX.try_lock().unwrap();
    runtime.block_on(perform_heal_check());
    let observed = std::fs::read_to_string(&calls).unwrap_or_default();
    assert_eq!(
        observed.lines().count(),
        2,
        "healthy polling must not take mutation locks: {observed}"
    );
    assert!(observed.lines().all(|line| line.starts_with("is-active ")));
    drop(local);
    drop(admission);
    std::fs::remove_file(&calls).unwrap();
    let info = crate::PackageJobInfo {
        job_id: "heal-poll-active".into(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 10,
        last_line: String::new(),
        started_at: chrono::Utc::now().to_rfc3339(),
        expected_target_version: None,
    };
    assert!(crate::try_start_package_job(info));
    runtime.block_on(perform_heal_check());
    assert!(!calls.exists(), "a real active job excludes heal checks");
    crate::finish_package_job("fixture", "update", true, "", "heal-poll-active").unwrap();
    // A missing journal is unknown, not an empty service inventory.
    let hidden = path.with_extension("temporarily-unavailable");
    std::fs::rename(&path, &hidden).unwrap();
    assert!(crate::get_active_services().is_err());
    runtime.block_on(perform_heal_check());
    assert!(
        !calls.exists(),
        "unknown state must not attempt service controls"
    );
    std::fs::rename(&hidden, &path).unwrap();
    runtime.block_on(perform_heal_check());
    assert_eq!(std::fs::read_to_string(&calls).unwrap().lines().count(), 2);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_health_recovery_excludes_scheduled_oneshot_jobs() {
    assert!(!unit_metadata_allows_recovery(
        "loadstate=loaded\ntype=oneshot\n"
    ));
    assert!(!unit_metadata_allows_recovery(
        "loadstate=not-found\ntype=simple\n"
    ));
    assert!(!unit_metadata_allows_recovery(""));
    assert!(unit_metadata_allows_recovery(
        "type=simple\nloadstate=loaded\n"
    ));
    assert!(unit_metadata_allows_recovery("loadstate=loaded\n")); // timers
}

#[test]
fn test_metrics_columns_use_the_supplied_connection() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE metrics_history (timestamp TEXT);")
        .unwrap();
    ensure_metrics_history_columns_with_connection(&conn);
    ensure_metrics_history_columns_with_connection(&conn);
    conn.execute(
        "INSERT INTO metrics_history (timestamp, cpu_usage, memory_pct, swap_pct, disk_read_mb, disk_write_mb, net_rx_mb, net_tx_mb) VALUES ('audit', 1, 2, 3, 4, 5, 6, 7)",
        [],
    )
    .unwrap();
}

#[cfg(target_os = "linux")]
struct ProbeCleanup(std::path::PathBuf);

#[cfg(target_os = "linux")]
impl ProbeCleanup {
    fn processes(&self) -> Vec<u32> {
        std::fs::read_dir(&self.0)
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "pids")
            })
            .flat_map(|entry| {
                std::fs::read_to_string(entry.path())
                    .unwrap()
                    .split_whitespace()
                    .map(|pid| pid.parse::<u32>().unwrap())
                    .collect::<Vec<_>>()
            })
            .collect()
    }
    fn live(&self) -> Vec<u32> {
        self.processes()
            .into_iter()
            .filter(|pid| {
                std::fs::read_to_string(format!("/proc/{pid}/stat"))
                    .ok()
                    .and_then(|stat| {
                        stat.rsplit_once(") ")
                            .map(|(_, fields)| !fields.starts_with('Z') && !fields.starts_with('X'))
                    })
                    .unwrap_or(false)
            })
            .collect()
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProbeCleanup {
    fn drop(&mut self) {
        for pid in self.live() {
            // Only PIDs published by this disposable fixture are eligible.
            let _ = std::process::Command::new("/bin/kill")
                .args(["-KILL", "--", &pid.to_string()])
                .status();
        }
    }
}

#[cfg(target_os = "linux")]
fn slow_update_helpers(fixture: &crate::inventory_regressions::Fixture) -> ProbeCleanup {
    for name in ["dpkg-query", "apt-cache", "git", "fixture-version"] {
        fixture.command(name, r#"exec /usr/bin/python3 -c 'import os,pathlib,signal,subprocess,sys
root=pathlib.Path(os.environ.get("AF_UPDATE_PROBE_ROOT") or os.environ["AETHERFLOW_FS_ROOT"])
child=subprocess.Popen([sys.executable,"-c","import signal; signal.pause()"])
(root/(str(os.getpid())+".pids")).write_text(str(os.getpid())+" "+str(child.pid))
if os.environ.get("AF_UPDATE_PROBE_OVERFLOW"): sys.stdout.write("x"*(2*1024*1024)); sys.stdout.flush()
signal.pause()'
"#);
    }
    std::env::set_var("AF_UPDATE_PROBE_ROOT", &fixture.root);
    ProbeCleanup(fixture.root.clone())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn version_probe_timeouts_reap_apt_binary_and_git_process_trees() {
    use crate::inventory_regressions::{isolated, Fixture};
    let name = "workers::tests::health_and_probes::version_probe_timeouts_reap_apt_binary_and_git_process_trees";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    let cleanup = slow_update_helpers(&fixture);
    let mut package = Fixture::package("fixture", "systemd", "fixture");
    package["update_source"] = serde_json::json!("apt");
    package["update_package"] = serde_json::json!("fixture");
    let apt: Package = serde_json::from_value(package.clone()).unwrap();
    package["update_source"] = serde_json::json!("binary");
    package["version_command"] = serde_json::json!(["fixture-version"]);
    let binary: Package = serde_json::from_value(package.clone()).unwrap();
    package["update_source"] = serde_json::json!("git");
    package["update_repo_url"] = serde_json::json!("https://fixture.invalid/repo.git");
    let git: Package = serde_json::from_value(package).unwrap();
    let client = reqwest::Client::new();
    let started = Instant::now();
    let (installed_apt, installed_binary, latest_apt, latest_head, latest_tag) = tokio::join!(
        detect_installed_version(&apt),
        detect_installed_version(&binary),
        detect_latest_apt_version("fixture"),
        detect_latest_version(&client, "https://fixture.invalid", &git),
        detect_latest_git_tag("https://fixture.invalid/repo.git", "fixture/repo"),
    );
    assert!(
        installed_apt.is_err()
            && installed_binary.is_err()
            && latest_apt.is_err()
            && latest_head.is_err()
            && latest_tag.is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(23));
    assert_eq!(
        cleanup.processes().len(),
        10,
        "all five real detector paths must execute"
    );
    assert!(
        cleanup.live().is_empty(),
        "timed-out helpers survived: {:?}",
        cleanup.live()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn version_probe_cancellation_and_overflow_retain_cleanup_ownership() {
    use crate::inventory_regressions::{isolated, Fixture};
    let name = "workers::tests::health_and_probes::version_probe_cancellation_and_overflow_retain_cleanup_ownership";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    let cleanup = slow_update_helpers(&fixture);
    let task = tokio::spawn(update_probe_output(
        Command::new("fixture-version"),
        Duration::from_secs(30),
    ));
    let ready = Instant::now() + Duration::from_secs(3);
    while cleanup.processes().is_empty() && Instant::now() < ready {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(cleanup.processes().len(), 2);
    task.abort();
    let _ = task.await;
    let cleaned = Instant::now() + Duration::from_secs(2);
    while !cleanup.live().is_empty() && Instant::now() < cleaned {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(cleanup.live().is_empty(), "cancelled helper survived");
    std::env::set_var("AF_UPDATE_PROBE_OVERFLOW", "1");
    let result = update_probe_output(Command::new("fixture-version"), Duration::from_secs(5)).await;
    assert!(result.is_err());
    assert!(cleanup.live().is_empty(), "oversized helper survived");
}

#[test]
fn test_version_extraction_and_comparison() {
    assert_eq!(extract_version("jellyfin 10.9.11", ""), "10.9.11");
    assert_eq!(extract_version("v2.4.0-rc1", ""), "2.4.0-rc1");
    assert_eq!(extract_version("1:1.0.0-1", ""), "1:1.0.0-1");
    assert_eq!(extract_version("1.0.0~rc1", ""), "1.0.0~rc1");
    assert!(is_remote_version_newer("10.9.10", "10.9.11"));
    assert!(!is_remote_version_newer("10.9.11", "10.9.11"));
    assert!(!is_remote_version_newer("10.10.0", "10.9.11"));
    assert!(is_remote_version_newer("1.0.0~rc1", "1.0.0"));
    assert!(is_remote_version_newer("2.4.0-rc1", "2.4.0"));
    assert!(is_remote_version_newer("1.0.0-1", "1.1.0"));
    assert!(is_remote_version_newer("1.0.0-1", "1.0.0-2"));
    assert!(!is_remote_version_newer("1:1.0.0-1", "2.0.0"));
    assert!(!is_remote_version_newer("1.0.0", "1.0.0~rc1"));
    assert!(!is_remote_version_newer("2.4.0", "2.4.0-rc1"));
}

#[test]
fn test_git_head_tracking() {
    let local = "a".repeat(40);
    let remote = "b".repeat(40);
    assert_eq!(
        parse_git_head(&format!("{}\tHEAD\n", remote)).unwrap(),
        remote
    );
    for invalid in ["", "v1.2.3", "abc123 HEAD", &"g".repeat(40)] {
        assert!(parse_git_head(invalid).is_err());
    }
    assert!(is_remote_version_newer(&local, &remote));
    assert!(!is_remote_version_newer(&local, &local));
}

#[test]
fn test_git_sha_and_synthetic_version_identities() {
    assert_eq!(extract_version("6e840ac", ""), "6e840ac");
    assert_eq!(extract_version("dd032e1d7bb2", ""), "dd032e1d7bb2");
    assert_eq!(normalize_version_token("6e840ac"), "6e840ac");
    assert_eq!(normalize_version_token("dd032e1d7bb2"), "dd032e1d7bb2");
    assert!(is_remote_version_newer("6e840ac", "0.6.27"));
    assert!(is_remote_version_newer("dd032e1", "2.18.2"));
    assert!(!is_remote_version_newer(
        "0.1.0-6e840ac",
        "6e840acbda8d1234567890abcdef1234567890ab"
    ));
    assert!(is_remote_version_newer(
        "0.1.0-6e840ac",
        "9999999bda8d1234567890abcdef1234567890ab"
    ));
    assert!(!is_git_commit_sha("20261108"));
    assert!(is_git_commit_sha("6e840ac"));
}

#[test]
fn test_sanitize_update_check_error_rate_limit() {
    assert_eq!(
        sanitize_update_check_error("GitHub API rate limit exceeded (HTTP 403)"),
        "GitHub API rate limit reached; retaining last confirmed version"
    );
    assert_eq!(
        sanitize_update_check_error("GitHub API rate limit exceeded (HTTP 429)"),
        "GitHub API rate limit reached; retaining last confirmed version"
    );
    assert_eq!(
        sanitize_update_check_error("Installed version could not be confirmed"),
        "Installed version could not be confirmed"
    );
    assert_eq!(
        sanitize_update_check_error("arbitrary internal failure /etc/passwd"),
        "Update status could not be confirmed"
    );
}

#[test]
fn test_parse_speed_str_to_mb_s() {
    assert!((parse_speed_str_to_mb_s("10.5 MB/s") - 10.5).abs() < 1e-6);
    assert!((parse_speed_str_to_mb_s("1024.0 KB/s") - 1.0).abs() < 1e-6);
    assert_eq!(parse_speed_str_to_mb_s("0 B/s"), 0.0);
}

#[test]
fn test_installed_state_uses_lock_during_active_lifecycle_job() {
    let path = std::env::temp_dir().join(format!(
        "af-package-lock-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap()
    ));
    std::fs::write(&path, "installed").unwrap();
    let pkg = Package {
        lock_file: path.to_string_lossy().into_owned(),
        status: "installing".to_string(),
        ..Default::default()
    };
    let installed_during_job = package_is_installed(&pkg);
    std::fs::remove_file(&path).unwrap();
    assert!(installed_during_job);
    assert!(!package_is_installed(&pkg));
}

#[test]
fn update_failures_never_copy_command_diagnostics_into_status() {
    let record = build_package_update_record(
        "fixture",
        true,
        Err(anyhow::anyhow!(
            "SYNTHETIC_PRIVATE_DIAGNOSTIC /etc/private/config"
        )),
        Err(anyhow::anyhow!(
            "remote endpoint returned SYNTHETIC_PRIVATE_DIAGNOSTIC"
        )),
        None,
        "2026-11-06T00:00:00Z".into(),
    );
    assert_eq!(
        record.error,
        "Installed version could not be confirmed; Latest version could not be confirmed"
    );
    assert!(!serde_json::to_string(&record)
        .unwrap()
        .contains("SYNTHETIC_PRIVATE_DIAGNOSTIC"));
}

#[cfg(unix)]
#[test]
fn legacy_update_errors_are_sanitized_from_database_and_cache() {
    use crate::inventory_regressions::{isolated, Fixture};
    if !isolated("workers::tests::health_and_probes::legacy_update_errors_are_sanitized_from_database_and_cache") {
        return;
    }
    let _fixture = Fixture::new();
    af_db::init_db().unwrap();
    af_db::get_conn().unwrap().execute(
        "INSERT INTO app_updates(package_name,installed_version,latest_version,update_available,last_error) VALUES('fixture','1.0','1.1',1,'SYNTHETIC_PRIVATE_DIAGNOSTIC')", [],
    ).unwrap();
    assert_eq!(
        get_package_update_map()["fixture"].error,
        "Update status could not be confirmed"
    );
    let mut raw = get_package_update_map()["fixture"].clone();
    raw.error = "different SYNTHETIC_PRIVATE_DIAGNOSTIC".into();
    PACKAGE_UPDATE_CACHE
        .lock()
        .unwrap()
        .insert("fixture".into(), raw);
    let safe = get_package_update_map();
    assert_eq!(
        safe["fixture"].error,
        "Update status could not be confirmed"
    );
    assert!(safe["fixture"].update_available);
}

#[test]
fn test_build_package_update_record_preserves_previous_versions_on_failure() {
    let prev = PackageUpdateRecord {
        package_id: "radarr".to_string(),
        installed: true,
        installed_version: "5.14.0".to_string(),
        latest_version: "5.15.0".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "https://github.com/Radarr/Radarr/releases/tag/v5.15.0".to_string(),
        error: String::new(),
        source_key: "github:https://api.github.com|radarr/radarr|stable".to_string(),
    };

    let failed = build_package_update_record(
        "radarr",
        true,
        Err(anyhow::anyhow!("binary not found")),
        Err(anyhow::anyhow!("github rate limit exceeded")),
        Some(&prev),
        "2026-11-02T00:00:00Z".to_string(),
    );
    assert_eq!(failed.installed_version, "5.14.0");
    assert_eq!(failed.latest_version, "5.15.0");
    assert_eq!(
        failed.release_url,
        "https://github.com/Radarr/Radarr/releases/tag/v5.15.0"
    );
    assert_eq!(failed.checked_at, "2026-11-01T00:00:00Z");
    assert!(failed.update_available);
    assert_eq!(
        failed.error,
        "Installed version could not be confirmed; Latest version could not be confirmed"
    );
}

#[test]
fn test_github_token_never_sent_to_pypi_or_untrusted_host() {
    assert!(is_trusted_github_api_url(
        "https://api.github.com/repos/a/b/releases/latest",
        "https://api.github.com"
    ));
    assert!(!is_trusted_github_api_url(
        "https://pypi.org/pypi/pyload-ng/json",
        "https://api.github.com"
    ));
    assert!(!is_trusted_github_api_url(
        "https://pypi.org/pypi/pyload-ng/json",
        "https://pypi.org"
    ));
    assert!(is_trusted_github_api_url(
        "https://github.com/a/b",
        "https://api.github.com"
    ));
    assert!(!is_trusted_github_api_url(
        "http://api.github.com/repos/a/b/releases/latest",
        "https://api.github.com"
    ));
    assert!(is_trusted_github_api_url(
        "http://127.0.0.1:8080/repos/a/b/releases/latest",
        "http://127.0.0.1:8080"
    ));
    assert!(!is_trusted_github_api_url(
        "http://evil.com/repos/a/b/releases/latest",
        "http://evil.com"
    ));
}

#[test]
fn test_component_manifest_requirements_and_equality() {
    assert!(parse_component_manifest(
        "frontend:111111a,backend:222222b,proxy:333333c,frontend:444444d"
    )
    .is_none());
    assert!(parse_component_manifest("frontend:111111a").is_none());
    assert!(parse_component_manifest("frontend:111111a,backend:222222b").is_none());
    assert!(parse_component_manifest("backend:222222b,proxy:333333c").is_none());
    assert!(parse_component_manifest("frontend:111111a,proxy:333333c").is_none());
    assert!(parse_component_manifest("frontend:111111a,backend:222222b,proxy:333333c").is_some());
    assert!(parse_component_manifest("ui:111111a,server:222222b").is_some());

    let raw =
        "frontend:6e840acbda8d1234567890abcdef1234567890ab,backend:dd032e1d7bb2,proxy:1a2b3c4";
    assert_eq!(extract_version(raw, "git"), raw);

    let m1 = "frontend:111111a,backend:222222b,proxy:333333c";
    let m2 = "frontend:111111a,backend:222222b,proxy:333333c,worker:444444d";
    assert!(!versions_match_target_internal(m1, m2));
    assert!(is_remote_version_newer(m1, m2));
    assert!(is_remote_version_newer(m2, m1));
    assert!(versions_match_target_internal(m1, m1));
    assert!(is_newer_version(m1, m2));
}

#[test]
fn test_installed_version_failure_preserves_checked_at_and_surfaces_warning() {
    let prev = PackageUpdateRecord {
        package_id: "qbittorrent".to_string(),
        installed: true,
        installed_version: "4.6.0".to_string(),
        latest_version: "4.6.1".to_string(),
        update_available: true,
        checked_at: "2026-11-01T12:00:00Z".to_string(),
        release_url: "https://github.com/qbittorrent/qBittorrent/releases/tag/release-4.6.1"
            .to_string(),
        error: String::new(),
        source_key: "github:https://api.github.com|qbittorrent/qbittorrent".to_string(),
    };

    let rec = build_package_update_record(
        "qbittorrent",
        true,
        Err(anyhow::anyhow!("probe timed out")),
        Ok((
            "4.6.2".to_string(),
            "https://github.com/qbittorrent/qBittorrent/releases/tag/release-4.6.2".to_string(),
        )),
        Some(&prev),
        "2026-11-08T12:00:00Z".to_string(),
    );

    assert_eq!(rec.installed_version, "4.6.0");
    assert_eq!(rec.latest_version, "4.6.2");
    assert_eq!(rec.checked_at, "2026-11-08T12:00:00Z");
    assert_eq!(
        rec.error,
        "Installed version probe returned no output; retaining last known installed version"
    );
    assert_eq!(
        public_update_error(&rec.error),
        "Installed version probe returned no output; retaining last known installed version"
    );
}

#[tokio::test]
async fn test_rate_limit_handling_and_stale_cache_fallback() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 4096];
        let length = socket.read(&mut request).await.unwrap();
        let _ = length;
        let response = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        socket.write_all(response.as_bytes()).await.unwrap();
    });

    let client = build_github_http_client();
    let api_base = format!("http://{address}");
    let repo = "testowner/testrepo";

    let cache_key = github_release_cache_key(&api_base, repo);
    {
        let mut cache = github_release_cache();
        cache.insert(
            cache_key.clone(),
            (
                "1.0.0".to_string(),
                "https://github.com/testowner/testrepo/releases/tag/v1.0.0".to_string(),
                Instant::now() - Duration::from_secs(3600),
                "2026-11-08T11:00:00Z".to_string(),
            ),
        );
    }

    let res = detect_latest_github_release(&client, &api_base, repo).await;
    server.await.unwrap();
    assert!(res.is_err());
    let err_str = res.unwrap_err().to_string();
    assert!(err_str.contains("rate limit"));

    let rec = build_package_update_record_for_source(
        &api_base,
        "github",
        repo,
        true,
        Ok("0.9.0".to_string()),
        Err(anyhow::anyhow!("rate limit")),
        None,
        "2026-11-08T12:00:00Z".to_string(),
        "",
    );
    assert_eq!(rec.latest_version, "1.0.0");
    assert_eq!(rec.checked_at, "2026-11-08T11:00:00Z");
    assert_eq!(rec.error, "Latest version could not be confirmed");
}

#[test]
fn test_component_manifest_newer_comparison() {
    let local = "frontend:6e840ac,backend:dd032e1,proxy:1a2b3c4";
    let remote_same =
        "frontend:6e840acbda8d1234567890abcdef1234567890ab,backend:dd032e1d7bb2,proxy:1a2b3c4";
    assert!(!is_remote_version_newer(local, remote_same));

    let remote_diff = "frontend:6e840ac,backend:ffffff1,proxy:1a2b3c4";
    assert!(is_remote_version_newer(local, remote_diff));

    let remote_missing = "frontend:6e840ac,backend:dd032e1,proxy:1a2b3c4,worker:555555a";
    assert!(is_remote_version_newer(local, remote_missing));

    // Generic component manifests comp1:1.1,comp2:2.0 vs comp1:1.10,comp2:2.0
    let gen_local = "comp1:1.1,comp2:2.0";
    let gen_remote = "comp1:1.10,comp2:2.0";
    assert!(!versions_match_target_internal(gen_local, gen_remote));
    assert!(is_remote_version_newer(gen_local, gen_remote));
    assert!(!is_remote_version_newer(gen_remote, gen_local));
}

#[tokio::test]
async fn test_cache_hit_preserves_observed_at_checked_at() {
    let repo = "test-cached-owner/test-cached-repo";
    let api_base = "https://api.github.com";
    let cache_key = github_release_cache_key(api_base, repo);
    let cached_time = "2026-11-01T10:00:00Z";
    {
        let mut cache = github_release_cache();
        cache.insert(
            cache_key,
            (
                "3.4.5".to_string(),
                format!("https://github.com/{repo}/releases/tag/v3.4.5"),
                Instant::now(),
                cached_time.to_string(),
            ),
        );
    }

    let pkg = Package {
        name: "test-cached-pkg".into(),
        update_source: "github".into(),
        update_repo: repo.into(),
        version_command: vec!["printf".into(), "%s".into(), "3.4.5".into()],
        ..Default::default()
    };

    let client = build_github_http_client();
    let (record, _) = probe_package_update(&client, api_base, &pkg).await;
    assert_eq!(record.latest_version, "3.4.5");
    assert_eq!(record.checked_at, cached_time);
}

#[test]
fn test_threadfin_fallback_preserves_newer_previous_and_sets_error() {
    let expected_key = crate::get_package_catalog()
        .unwrap()
        .into_iter()
        .find(|p| p.name == "threadfin")
        .map(|p| canonical_update_source_key("https://api.github.com", &p))
        .unwrap();
    let prev = PackageUpdateRecord {
        package_id: "threadfin".to_string(),
        installed: true,
        installed_version: "1.1.0".to_string(),
        latest_version: "1.3.0".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "https://github.com/Threadfin/Threadfin/releases/tag/1.3.0".to_string(),
        error: String::new(),
        source_key: expected_key,
    };

    let failed_record = build_package_update_record(
        "threadfin",
        true,
        Ok("1.1.0".to_string()),
        Err(anyhow::anyhow!("GitHub release fetch failed")),
        Some(&prev),
        "2026-11-08T12:00:00Z".to_string(),
    );

    // Newer version 1.3.0 from previous observation must NOT be overwritten by static fallback (1.2.37)
    assert_eq!(failed_record.latest_version, "1.3.0");
    assert_eq!(failed_record.checked_at, "2026-11-01T00:00:00Z");
    assert_eq!(failed_record.error, "Latest version could not be confirmed");
}

#[tokio::test]
async fn test_stale_af_version_receipt_contradicting_live_runtime_fails() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let temp_dir = std::env::temp_dir().join(format!("af-test-stale-ver-{}", uuid::Uuid::new_v4()));
    let opt_dir = temp_dir.join("opt/test-stale-pkg");
    std::fs::create_dir_all(&opt_dir).unwrap();
    std::fs::write(opt_dir.join(".af-version"), "1.0.0").unwrap();

    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let pkg = Package {
        name: "test-stale-pkg".into(),
        version_command: vec!["printf".into(), "%s".into(), "2.0.0".into()],
        ..Default::default()
    };

    // Live runtime says 2.0.0 but disk receipt says 1.0.0 -> must FAIL
    let res = probe_installed_package_version_strict(&pkg).await;
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("Stale or mismatched .af-version receipt"),
        "actual error: {err_msg}"
    );

    // Now fix .af-version to match live runtime
    std::fs::write(opt_dir.join(".af-version"), "2.0.0").unwrap();
    let res_ok = probe_installed_package_version_strict(&pkg).await;
    assert!(res_ok.is_ok());
    assert_eq!(res_ok.unwrap(), "2.0.0");

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_probe_installed_package_version_strict() {
    let pkg = Package {
        name: "test-pkg".into(),
        ..Default::default()
    };
    assert!(probe_installed_package_version_strict(&pkg).await.is_err());
}

#[test]
fn test_monitored_component_policy_skips_unconfigured_optional_and_oneshots() {
    let autobrr_unconfigured = crate::resolve_service_component_policies_with("rclone", false);
    let monitored_units: Vec<String> = autobrr_unconfigured
        .into_iter()
        .filter(is_component_policy_monitored)
        .map(|p| p.unit)
        .collect();
    assert_eq!(monitored_units, vec!["rclone".to_string()]);

    let recyclarr_policies = crate::resolve_service_component_policies_with("recyclarr", false);
    let recyclarr_monitored: Vec<String> = recyclarr_policies
        .into_iter()
        .filter(is_component_policy_monitored)
        .map(|p| p.unit)
        .collect();
    assert_eq!(recyclarr_monitored, vec!["recyclarr.timer".to_string()]);
}

#[tokio::test]
async fn test_piped_strict_probe_verifies_all_three_git_repos_against_receipt() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let temp_dir = std::env::temp_dir().join(format!("af-test-piped-git-{}", uuid::Uuid::new_v4()));
    let opt_piped = temp_dir.join("opt/piped");
    let opt_frontend = opt_piped.join("frontend");
    let opt_backend = opt_piped.join("backend");
    let opt_proxy = opt_piped.join("proxy");

    let init_repo = |dir: &Path, name: &str| -> String {
        std::fs::create_dir_all(dir).unwrap();
        assert!(std::process::Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(dir)
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(dir)
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir)
            .status()
            .unwrap()
            .success());
        std::fs::write(dir.join("component.txt"), name).unwrap();
        assert!(std::process::Command::new("git")
            .args(["add", "component.txt"])
            .current_dir(dir)
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("git")
            .args(["commit", "-m", "initial commit"])
            .current_dir(dir)
            .status()
            .unwrap()
            .success());
        let out = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .to_ascii_lowercase()
    };

    let fe_sha = init_repo(&opt_frontend, "piped-frontend");
    let be_sha = init_repo(&opt_backend, "piped-backend");
    let pr_sha = init_repo(&opt_proxy, "piped-proxy");

    let manifest = format!("frontend:{fe_sha},backend:{be_sha},proxy:{pr_sha}");
    std::fs::write(opt_piped.join(".af-version"), &manifest).unwrap();

    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let pkg = Package {
        name: "piped".into(),
        update_repo: "TeamPiped/Piped".into(),
        update_source: "git".into(),
        ..Default::default()
    };

    // 1. Success when .af-version matches all 3 repos in installer layout
    let res_ok = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_ok.is_ok(),
        "Expected success when .af-version matches: {:?}",
        res_ok.err()
    );
    assert_eq!(res_ok.unwrap(), manifest);

    // 2. Fails when any of the 3 repos is on a different commit than .af-version
    let mismatched = format!(
        "frontend:{fe_sha},backend:{},proxy:{pr_sha}",
        "0".repeat(40)
    );
    std::fs::write(opt_piped.join(".af-version"), &mismatched).unwrap();
    let res_mismatch = probe_installed_package_version_strict(&pkg).await;
    assert!(res_mismatch.is_err());
    let err = res_mismatch.unwrap_err().to_string();
    assert!(
        err.contains("Stale or mismatched .af-version receipt"),
        "Expected mismatch error, got: {err}"
    );

    // 3. Fails when one repo has incomplete git probe
    std::fs::write(opt_piped.join(".af-version"), &manifest).unwrap();
    let proxy_git = opt_proxy.join(".git");
    let proxy_git_bak = opt_proxy.join(".git_bak");
    std::fs::rename(&proxy_git, &proxy_git_bak).unwrap();
    let res_incomplete = probe_installed_package_version_strict(&pkg).await;
    assert!(res_incomplete.is_err());

    // Restore git dir and clean up
    let _ = std::fs::rename(&proxy_git_bak, &proxy_git);
    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);

    // 4. Verify flat layout fallback (/opt/piped/.git, /opt/piped-backend/.git, /opt/piped-proxy/.git)
    let flat_temp_dir =
        std::env::temp_dir().join(format!("af-test-piped-flat-{}", uuid::Uuid::new_v4()));
    let flat_piped = flat_temp_dir.join("opt/piped");
    let flat_backend = flat_temp_dir.join("opt/piped-backend");
    let flat_proxy = flat_temp_dir.join("opt/piped-proxy");
    let fe_flat = init_repo(&flat_piped, "piped-frontend");
    let be_flat = init_repo(&flat_backend, "piped-backend");
    let pr_flat = init_repo(&flat_proxy, "piped-proxy");
    let flat_manifest = format!("frontend:{fe_flat},backend:{be_flat},proxy:{pr_flat}");
    std::fs::write(flat_piped.join(".af-version"), &flat_manifest).unwrap();
    std::env::set_var("AETHERFLOW_FS_ROOT", &flat_temp_dir);
    let res_flat = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_flat.is_ok(),
        "Expected success with flat layout fallback: {:?}",
        res_flat.err()
    );
    assert_eq!(res_flat.unwrap(), flat_manifest);
    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&flat_temp_dir);
}

#[tokio::test]
async fn test_cache_hit_isolation_sequential_and_concurrent() {
    let api_base = "https://api.github.com";
    let repo_a = "test-iso/repo-a";
    let repo_b = "test-iso/repo-b";
    let cached_time_a = "2026-11-01T01:00:00Z";
    let cached_time_b = "2026-11-02T02:00:00Z";

    {
        let mut cache = github_release_cache();
        cache.insert(
            github_release_cache_key(api_base, repo_a),
            (
                "1.0.0".to_string(),
                format!("https://github.com/{repo_a}/releases/tag/v1.0.0"),
                Instant::now(),
                cached_time_a.to_string(),
            ),
        );
        cache.insert(
            github_release_cache_key(api_base, repo_b),
            (
                "2.0.0".to_string(),
                format!("https://github.com/{repo_b}/releases/tag/v2.0.0"),
                Instant::now(),
                cached_time_b.to_string(),
            ),
        );
    }

    let pkg_a = Package {
        name: "test-pkg-a".into(),
        update_source: "github".into(),
        update_repo: repo_a.into(),
        version_command: vec!["printf".into(), "%s".into(), "1.0.0".into()],
        ..Default::default()
    };
    let pkg_b = Package {
        name: "test-pkg-b".into(),
        update_source: "github".into(),
        update_repo: repo_b.into(),
        version_command: vec!["printf".into(), "%s".into(), "2.0.0".into()],
        ..Default::default()
    };

    let client = build_github_http_client();

    // 1. Sequential probe: timestamps must not cross-contaminate
    let (rec_a, _) = probe_package_update(&client, api_base, &pkg_a).await;
    let (rec_b, _) = probe_package_update(&client, api_base, &pkg_b).await;
    assert_eq!(rec_a.checked_at, cached_time_a);
    assert_eq!(rec_b.checked_at, cached_time_b);

    // 2. Concurrent probe: timestamps must not cross-contaminate
    let (res_a, res_b) = tokio::join!(
        probe_package_update(&client, api_base, &pkg_a),
        probe_package_update(&client, api_base, &pkg_b),
    );
    assert_eq!(res_a.0.checked_at, cached_time_a);
    assert_eq!(res_b.0.checked_at, cached_time_b);
}

#[tokio::test]
async fn test_piped_discovery_uses_oldest_constituent_observed_at() {
    let sha_fe = "1111111111111111111111111111111111111111";
    let sha_be = "2222222222222222222222222222222222222222";
    let sha_px = "3333333333333333333333333333333333333333";

    let time_fe = "2026-11-05T10:00:00+00:00";
    let time_be = "2026-11-01T08:00:00+00:00"; // oldest!
    let time_px = "2026-11-03T12:00:00+00:00";

    {
        let mut cache = git_remote_head_cache();
        cache.insert(
            git_head_cache_key("https://github.com/TeamPiped/Piped.git", "TeamPiped/Piped"),
            (
                sha_fe.to_string(),
                "https://github.com/TeamPiped/Piped/commits/HEAD".to_string(),
                Instant::now(),
                time_fe.to_string(),
            ),
        );
        cache.insert(
            git_head_cache_key(
                "https://github.com/TeamPiped/Piped-Backend.git",
                "TeamPiped/Piped-Backend",
            ),
            (
                sha_be.to_string(),
                "https://github.com/TeamPiped/Piped-Backend/commits/HEAD".to_string(),
                Instant::now(),
                time_be.to_string(),
            ),
        );
        cache.insert(
            git_head_cache_key(
                "https://github.com/TeamPiped/Piped-Proxy.git",
                "TeamPiped/Piped-Proxy",
            ),
            (
                sha_px.to_string(),
                "https://github.com/TeamPiped/Piped-Proxy/commits/HEAD".to_string(),
                Instant::now(),
                time_px.to_string(),
            ),
        );
    }

    let res = detect_latest_piped_manifest().await.unwrap();
    assert_eq!(
        res.0,
        format!("frontend:{sha_fe},backend:{sha_be},proxy:{sha_px}")
    );
    // Constituent observations hit the cache with different timestamps -> manifest MUST take oldest!
    assert_eq!(res.2, time_be);
}
