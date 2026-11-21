use super::*;

static TEST_ENV_MUTEX: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

#[cfg(unix)]
#[test]
fn heal_state_survives_unknown_and_active_lifecycle_until_recovery() {
    use crate::inventory_regressions::{isolated, Fixture};
    use std::os::unix::fs::PermissionsExt;
    let name = "workers::tests::heal_state_survives_unknown_and_active_lifecycle_until_recovery";
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
    let name = "workers::tests::healing_status_timeouts_kill_and_reap_both_probe_children";
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
    let name = "workers::tests::heal_poll_is_read_only_and_unknown_snapshots_skip_controls";
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
    let name = "workers::tests::version_probe_timeouts_reap_apt_binary_and_git_process_trees";
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
    let name = "workers::tests::version_probe_cancellation_and_overflow_retain_cleanup_ownership";
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
    if !isolated("workers::tests::legacy_update_errors_are_sanitized_from_database_and_cache") {
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

#[test]
fn test_semver_build_metadata_and_debian_ordering() {
    // SemVer 2.0.0 build metadata is ignored for version precedence
    assert!(!is_remote_version_newer("1.0.0", "1.0.0+build.2"));
    assert!(!is_remote_version_newer("1.0.0+build.2", "1.0.0"));
    assert_eq!(
        compare_versions("1.0.0", "1.0.0+build.2"),
        std::cmp::Ordering::Equal
    );
    assert_eq!(
        compare_versions("1.0.0+build.2", "1.0.0"),
        std::cmp::Ordering::Equal
    );

    // Prereleases with letter suffix are strictly OLDER than bare release
    assert!(is_remote_version_newer("1.0.0-foo", "1.0.0"));
    assert!(!is_remote_version_newer("1.0.0", "1.0.0-foo"));
    assert_eq!(
        compare_versions("1.0.0-foo", "1.0.0"),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        compare_versions("1.0.0", "1.0.0-foo"),
        std::cmp::Ordering::Greater
    );

    assert!(is_remote_version_newer("1.0.0-alpha.1", "1.0.0"));
    assert_eq!(
        compare_versions("1.0.0-alpha.1", "1.0.0"),
        std::cmp::Ordering::Less
    );

    assert!(is_remote_version_newer("1.0.0-rc.1", "1.0.0"));
    assert_eq!(
        compare_versions("1.0.0-rc.1", "1.0.0"),
        std::cmp::Ordering::Less
    );

    // SemVer 2.0.0: numeric prereleases after hyphen (like 1.0.0-1, 1.0.0-0.3.7) are prereleases (LOWER precedence than 1.0.0)
    assert!(is_remote_version_newer("1.0.0-1", "1.0.0"));
    assert!(!is_remote_version_newer("1.0.0", "1.0.0-1"));
    assert_eq!(
        compare_versions("1.0.0-1", "1.0.0"),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        compare_versions("1.0.0", "1.0.0-1"),
        std::cmp::Ordering::Greater
    );

    assert!(is_remote_version_newer("1.0.0-0.3.7", "1.0.0"));
    assert_eq!(
        compare_versions("1.0.0-0.3.7", "1.0.0"),
        std::cmp::Ordering::Less
    );

    // Apt mode: Debian package revisions (-1 > bare, +deb11u1 < +deb11u2, +b1 < +b2)
    assert!(is_remote_version_newer_for_source(
        "1.0.0", "1.0.0-1", "apt"
    ));
    assert!(!is_remote_version_newer_for_source(
        "1.0.0-1", "1.0.0", "apt"
    ));
    assert_eq!(
        compare_versions_for_source("1.0.0", "1.0.0-1", "apt"),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        compare_versions_for_source("1.0.0-1", "1.0.0", "apt"),
        std::cmp::Ordering::Greater
    );

    assert!(is_remote_version_newer_for_source(
        "1.2.3-1ubuntu1",
        "1.2.3-2ubuntu1",
        "apt"
    ));
    assert_eq!(
        compare_versions_for_source("1.2.3-1ubuntu1", "1.2.3-2ubuntu1", "apt"),
        std::cmp::Ordering::Less
    );

    assert!(is_remote_version_newer_for_source(
        "1.2.3+deb11u1",
        "1.2.3+deb11u2",
        "apt"
    ));
    assert_eq!(
        compare_versions_for_source("1.2.3+deb11u1", "1.2.3+deb11u2", "apt"),
        std::cmp::Ordering::Less
    );
    assert!(is_remote_version_newer_for_source(
        "1.2.3+b1", "1.2.3+b2", "apt"
    ));
    assert_eq!(
        compare_versions_for_source("1.2.3+b1", "1.2.3+b2", "apt"),
        std::cmp::Ordering::Less
    );

    // Release prefixes normalized
    assert_eq!(
        compare_versions("release_1.0.0", "v1.0.0"),
        std::cmp::Ordering::Equal
    );
    assert_eq!(
        compare_versions("rel_1.0.0", "1.0.0"),
        std::cmp::Ordering::Equal
    );
    assert_eq!(
        compare_versions("release-1.0.0", "1.0.0+build.1"),
        std::cmp::Ordering::Equal
    );
}

#[test]
fn test_stacked_tag_prefixes_in_extract_version() {
    assert_eq!(extract_version("release-v1.2.3", ""), "1.2.3");
    assert_eq!(extract_version("release_v1.2.3", ""), "1.2.3");
    assert_eq!(extract_version("rel-v1.2.3", ""), "1.2.3");
    assert_eq!(extract_version("rel_v1.2.3", ""), "1.2.3");
    assert_eq!(extract_version("release_1.2.3", ""), "1.2.3");
    assert_eq!(extract_version("v1.2.3", ""), "1.2.3");
}

#[test]
fn test_git_commit_sha_antisymmetry_and_newer() {
    let sha1 = "6e840acbda8d1234567890abcdef1234567890ab";
    let sha2 = "9999999bda8d1234567890abcdef1234567890ab";
    // Distinct commits: compare_versions must be antisymmetric total order
    let ord1 = compare_versions(sha1, sha2);
    let ord2 = compare_versions(sha2, sha1);
    assert_eq!(ord1, ord2.reverse());
    assert_ne!(ord1, std::cmp::Ordering::Equal);

    // Prefix-matching commits are equal
    assert_eq!(compare_versions("6e840ac", sha1), std::cmp::Ordering::Equal);
    assert_eq!(compare_versions(sha1, "6e840ac"), std::cmp::Ordering::Equal);

    // is_remote_version_newer: distinct commit on tracked branch is an update
    assert!(is_remote_version_newer(sha1, sha2));
    assert!(is_remote_version_newer(sha2, sha1));
    // Same/prefix-matching commit is NOT an update
    assert!(!is_remote_version_newer(sha1, "6e840ac"));
    assert!(!is_remote_version_newer("6e840ac", sha1));
}

#[tokio::test]
async fn test_detect_installed_version_fails_closed_when_live_cmd_fails_with_af_version() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-fail-closed-{}", uuid::Uuid::new_v4()));
    let opt_dir = temp_dir.join("opt/test-fail-pkg");
    std::fs::create_dir_all(&opt_dir).unwrap();
    std::fs::write(opt_dir.join(".af-version"), "1.0.0").unwrap();

    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let pkg = Package {
        name: "test-fail-pkg".into(),
        // A live command that is guaranteed to fail
        version_command: vec!["/bin/false".into()],
        ..Default::default()
    };

    // Even though .af-version exists with "1.0.0", the configured live probe failed,
    // so detect_installed_version MUST fail closed (Err)
    let res = detect_installed_version(&pkg).await;
    assert!(
        res.is_err(),
        "Expected detect_installed_version to fail closed when live cmd fails"
    );

    let rec = build_package_update_record(
        "test-fail-pkg",
        true,
        res,
        Ok(("1.0.0".to_string(), "https://example.com".to_string())),
        None,
        "2026-11-08T12:00:00Z".to_string(),
    );
    assert_eq!(rec.error, "Installed version could not be confirmed");

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_stale_cache_origin_isolation_and_observed_at_preservation() {
    let origin_a = "https://api.github.com";
    let origin_b = "https://github-enterprise.internal.net";
    let repo = "myorg/myrepo";
    let observed_time = "2026-11-08T09:30:00Z";

    // Insert into cache under origin A
    {
        let mut cache = github_release_cache();
        cache.insert(
            github_release_cache_key(origin_a, repo),
            (
                "2.5.0".to_string(),
                format!("https://github.com/{repo}/releases/tag/v2.5.0"),
                Instant::now() - Duration::from_secs(3600),
                observed_time.to_string(),
            ),
        );
    }

    // Stale lookup under origin B must return None (origin isolation!)
    assert_eq!(get_cached_github_release_stale(origin_b, repo), None);

    // Stale lookup under origin A must return the cached version, URL, and observed_at
    let cached = get_cached_github_release_stale(origin_a, repo);
    assert!(cached.is_some());
    let (v, _u, obs) = cached.unwrap();
    assert_eq!(v, "2.5.0");
    assert_eq!(obs, observed_time);

    // When used in build_package_update_record_for_source with Err and no prior DB record,
    // checked_at is set to observed_time
    let rec = build_package_update_record_for_source(
        origin_a,
        "github",
        repo,
        true,
        Ok("2.4.0".to_string()),
        Err(anyhow::anyhow!("API timeout")),
        None,
        "2026-11-08T12:00:00Z".to_string(),
        "",
    );
    assert_eq!(rec.latest_version, "2.5.0");
    assert_eq!(rec.checked_at, observed_time);

    // When static fallback is used with no prior DB record and no cache hit, checked_at is empty ("")
    let rec_static = build_package_update_record_for_source(
        origin_b,
        "github",
        "threadfin",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("API timeout")),
        None,
        "2026-11-08T12:00:00Z".to_string(),
        "",
    );
    // threadfin has static fallback; since it had no cache hit under origin_b and no prior DB record,
    // checked_at must be empty string
    assert_eq!(rec_static.checked_at, "");
}

#[test]
fn test_source_provenance_validation_invalidates_prev_on_mismatch_or_legacy() {
    let origin_a = "https://api.github.com";
    let origin_b = "https://internal-ghe.example.com";
    let repo_a = "owner/repo-a";
    let repo_b = "owner/repo-b";

    let matching_prev = PackageUpdateRecord {
        package_id: "testpkg".to_string(),
        installed: true,
        installed_version: "1.0.0".to_string(),
        latest_version: "1.1.0".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "https://github.com/owner/repo-a/releases/tag/v1.1.0".to_string(),
        error: String::new(),
        source_key: format!("github:{}|{}", normalize_api_origin(origin_a), repo_a),
    };

    // 1. Matching provenance: previous version, URL, checked_at, and update_available are preserved on error
    let expected_key_a = format!("github:{}|{}", normalize_api_origin(origin_a), repo_a);
    let rec_matching = build_package_update_record_for_source(
        origin_a,
        "github",
        "testpkg",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("network unreachable")),
        Some(&matching_prev),
        "2026-11-08T12:00:00Z".to_string(),
        &expected_key_a,
    );
    assert_eq!(rec_matching.latest_version, "1.1.0");
    assert_eq!(
        rec_matching.release_url,
        "https://github.com/owner/repo-a/releases/tag/v1.1.0"
    );
    assert_eq!(rec_matching.checked_at, "2026-11-01T00:00:00Z");
    assert!(rec_matching.update_available);

    // 2. Mismatched origin (origin changed from origin_a to origin_b):
    // prev record must be INVALIDATED (treated as None for latest_version/release_url/checked_at/update_available)
    let expected_key_b_origin = format!("github:{}|{}", normalize_api_origin(origin_b), repo_a);
    let rec_mismatched_origin = build_package_update_record_for_source(
        origin_b,
        "github",
        "testpkg",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("network unreachable")),
        Some(&matching_prev),
        "2026-11-08T12:00:00Z".to_string(),
        &expected_key_b_origin,
    );
    assert_eq!(rec_mismatched_origin.latest_version, "");
    assert_eq!(rec_mismatched_origin.release_url, "");
    assert_eq!(rec_mismatched_origin.checked_at, "");
    assert!(!rec_mismatched_origin.update_available);

    // 3. Mismatched repo (repo changed from repo_a to repo_b):
    let expected_key_b_repo = format!("github:{}|{}", normalize_api_origin(origin_a), repo_b);
    let rec_mismatched_repo = build_package_update_record_for_source(
        origin_a,
        "github",
        "testpkg",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("network unreachable")),
        Some(&matching_prev),
        "2026-11-08T12:00:00Z".to_string(),
        &expected_key_b_repo,
    );
    assert_eq!(rec_mismatched_repo.latest_version, "");
    assert_eq!(rec_mismatched_repo.release_url, "");
    assert_eq!(rec_mismatched_repo.checked_at, "");
    assert!(!rec_mismatched_repo.update_available);

    // 4. Legacy record without source_key (source_key is empty):
    let legacy_prev = PackageUpdateRecord {
        package_id: "testpkg".to_string(),
        installed: true,
        installed_version: "1.0.0".to_string(),
        latest_version: "1.1.0".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "https://github.com/owner/repo-a/releases/tag/v1.1.0".to_string(),
        error: String::new(),
        source_key: String::new(), // legacy empty
    };
    let rec_legacy = build_package_update_record_for_source(
        origin_a,
        "github",
        "testpkg",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("network unreachable")),
        Some(&legacy_prev),
        "2026-11-08T12:00:00Z".to_string(),
        &expected_key_a,
    );
    assert_eq!(rec_legacy.latest_version, "");
    assert_eq!(rec_legacy.release_url, "");
    assert_eq!(rec_legacy.checked_at, "");
    assert!(!rec_legacy.update_available);
}

#[test]
fn test_fallback_timestamps_for_stale_cache_and_static_fallback() {
    let origin = "https://api.github.com";
    let repo = "demo/fallback-test";
    let cache_obs = "2026-11-07T15:30:00Z";

    // Seed stale cache for repo
    {
        let mut cache = github_release_cache();
        cache.insert(
            github_release_cache_key(origin, repo),
            (
                "3.0.0".to_string(),
                format!("https://github.com/{repo}/releases/tag/v3.0.0"),
                Instant::now() - Duration::from_secs(7200),
                cache_obs.to_string(),
            ),
        );
    }

    // prev record has an old checked_at, but empty latest_version
    let prev_empty_latest = PackageUpdateRecord {
        package_id: "demo-pkg".to_string(),
        installed: true,
        installed_version: "2.9.0".to_string(),
        latest_version: "".to_string(),
        update_available: false,
        checked_at: "2026-11-01T10:00:00Z".to_string(),
        release_url: "".to_string(),
        error: "earlier error".to_string(),
        source_key: format!("github:{}|{}", normalize_api_origin(origin), repo),
    };

    // When upstream errors, but stale cache provides version 3.0.0,
    // checked_at MUST be cache_obs ("2026-11-07T15:30:00Z"), NOT prev.checked_at and NOT now!
    let rec_cache = build_package_update_record_for_source(
        origin,
        "github",
        repo,
        true,
        Ok("2.9.0".to_string()),
        Err(anyhow::anyhow!("503 Service Unavailable")),
        Some(&prev_empty_latest),
        "2026-11-08T18:00:00Z".to_string(),
        &format!("github:{}|{}", normalize_api_origin(origin), repo),
    );
    assert_eq!(rec_cache.latest_version, "3.0.0");
    assert_eq!(rec_cache.checked_at, cache_obs);

    // When upstream errors and static fallback provides version (threadfin),
    // and prev_record had empty latest_version, checked_at MUST be empty string ("")!
    let prev_threadfin_empty = PackageUpdateRecord {
        package_id: "threadfin".to_string(),
        installed: true,
        installed_version: "1.0.0".to_string(),
        latest_version: "".to_string(),
        update_available: false,
        checked_at: "2026-11-01T10:00:00Z".to_string(),
        release_url: "".to_string(),
        error: "failed previously".to_string(),
        source_key: format!(
            "github:{}|Threadfin/Threadfin",
            normalize_api_origin(origin)
        ),
    };

    let rec_static = build_package_update_record_for_source(
        origin,
        "github",
        "threadfin",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("GitHub API down")),
        Some(&prev_threadfin_empty),
        "2026-11-08T18:00:00Z".to_string(),
        &format!(
            "github:{}|Threadfin/Threadfin",
            normalize_api_origin(origin)
        ),
    );
    assert!(!rec_static.latest_version.is_empty());
    assert_eq!(rec_static.checked_at, ""); // MUST NOT copy prev.checked_at!
}

#[tokio::test]
async fn test_origin_scoped_rate_limit_cooldowns_isolated() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    clear_github_rate_limits();

    // Start mock origin A: always returns 429 Too Many Requests
    let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = listener_a.local_addr().unwrap();
    let req_count_a = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let req_count_a_server = req_count_a.clone();
    let server_a = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener_a.accept().await {
            req_count_a_server.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut buf = vec![0; 2048];
            let _ = socket.read(&mut buf).await;
            let resp = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nx-ratelimit-resource: core\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    // Start mock origin B: returns 200 OK with release JSON
    let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_b = listener_b.local_addr().unwrap();
    let server_b = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener_b.accept().await {
            let mut buf = vec![0; 2048];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"tag_name":"v2.0.0","html_url":"http://mock-b/release"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    let client = build_github_http_client();
    let origin_a = format!("http://{addr_a}");
    let origin_b = format!("http://{addr_b}");

    // First call to origin A gets 429 with x-ratelimit-resource: core and records rate limit cooldown
    let res_a = detect_latest_github_release(&client, &origin_a, "owner/repo").await;
    assert!(res_a.is_err());
    assert!(res_a.unwrap_err().to_string().contains("rate limit"));
    assert_eq!(req_count_a.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Subsequent release discovery request to origin A checking "releases" must be suppressed
    // WITHOUT hitting the server, because "core" cooldown is active and shared across buckets!
    let res_a2 = detect_latest_github_release(&client, &origin_a, "owner/repo").await;
    assert!(res_a2.is_err());
    assert!(res_a2
        .unwrap_err()
        .to_string()
        .contains("rate limit backoff active"));
    assert_eq!(req_count_a.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Cooldown checks across origin A buckets
    assert!(is_github_api_rate_limited(&origin_a, "core"));
    assert!(is_github_api_rate_limited(&origin_a, "releases"));
    assert!(is_github_rate_limited_for_origin(&origin_a, "releases"));
    assert!(github_rate_limit_remaining_secs_for_origin(&origin_a, "releases") > 0);

    // Origin B must be COMPLETELY UNAFFECTED!
    assert!(!is_github_api_rate_limited(&origin_b, "core"));
    assert!(!is_github_api_rate_limited(&origin_b, "releases"));
    assert!(!is_github_api_rate_limited(&origin_b, "default"));

    let res_b = detect_latest_github_release(&client, &origin_b, "owner/repo").await;
    assert!(
        res_b.is_ok(),
        "Origin B request must succeed despite Origin A rate limit: {:?}",
        res_b
    );
    let (ver_b, url_b, _) = res_b.unwrap();
    assert_eq!(ver_b, "2.0.0");
    assert_eq!(url_b, "http://mock-b/release");

    server_a.abort();
    server_b.abort();
    clear_github_rate_limits();
}

#[tokio::test]
async fn test_retired_readarr_discovery_preserves_pinned_target() {
    let client = build_github_http_client();
    let pkg = Package {
        name: "readarr".into(),
        update_source: "retired".into(),
        ..Default::default()
    };

    // 1. Older Readarr installation (0.4.17.0) -> latest_version == "0.4.18.2805", update_available == true
    let mut rec_older = build_package_update_record_for_source(
        "https://api.github.com",
        "retired",
        "readarr",
        true,
        Ok("0.4.17.0".to_string()),
        Ok(("0.4.18.2805".to_string(), String::new())),
        None,
        "2026-11-09T00:00:00Z".to_string(),
        "",
    );
    if rec_older.latest_version.is_empty() {
        rec_older.latest_version = "0.4.18.2805".to_string();
    }
    rec_older.update_available = rec_older.installed
        && is_remote_version_newer_for_source(
            &rec_older.installed_version,
            &rec_older.latest_version,
            &pkg.update_source,
        );
    rec_older.error = String::new();
    assert_eq!(rec_older.latest_version, "0.4.18.2805");
    assert!(rec_older.update_available);
    assert_eq!(rec_older.error, "");

    // 2. Up-to-date Readarr installation (0.4.18.2805) -> latest_version == "0.4.18.2805", update_available == false
    let mut rec_uptodate = build_package_update_record_for_source(
        "https://api.github.com",
        "retired",
        "readarr",
        true,
        Ok("0.4.18.2805".to_string()),
        Ok(("0.4.18.2805".to_string(), String::new())),
        None,
        "2026-11-09T00:00:00Z".to_string(),
        "",
    );
    if rec_uptodate.latest_version.is_empty() {
        rec_uptodate.latest_version = "0.4.18.2805".to_string();
    }
    rec_uptodate.update_available = rec_uptodate.installed
        && is_remote_version_newer_for_source(
            &rec_uptodate.installed_version,
            &rec_uptodate.latest_version,
            &pkg.update_source,
        );
    rec_uptodate.error = String::new();
    assert_eq!(rec_uptodate.latest_version, "0.4.18.2805");
    assert!(!rec_uptodate.update_available);
    assert_eq!(rec_uptodate.error, "");

    // Pinned version returned without querying upstream GitHub
    let detected = detect_latest_version(
        &client,
        "https://invalid-host-unreachable.example.com",
        &pkg,
    )
    .await
    .unwrap();
    assert_eq!(detected.0, "0.4.18.2805");
}

#[test]
fn test_fresh_latest_observation_keeps_own_timestamp_when_installed_probe_falls_back() {
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
        source_key: "github:https://api.github.com|qbittorrent/qbittorrent|stable".to_string(),
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
}

#[test]
fn test_debian_version_preservation_and_comparison() {
    assert!(is_remote_version_newer_for_source(
        "1.0.0",
        "1.0.0+git1",
        "apt"
    ));
    assert!(!is_remote_version_newer_for_source(
        "1.0.0+git1",
        "1.0.0",
        "apt"
    ));
    assert_eq!(
        compare_debian_versions_str("1.0.0", "1.0.0+git1"),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        compare_debian_versions_str("1.0.0+git1", "1.0.0"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_debian_versions_str("1:1.0-1", "1.0-1"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_debian_versions_str("1.0~rc1-1", "1.0-1"),
        std::cmp::Ordering::Less
    );
}

#[test]
fn test_channel_provenance_and_retained_tag_revalidation() {
    let pkg_nightly = Package {
        name: "testpkg".into(),
        update_source: "github".into(),
        update_repo: "owner/repo".into(),
        update_channel: "nightly".into(),
        ..Default::default()
    };
    let key_nightly = canonical_update_source_key("https://api.github.com", &pkg_nightly);
    assert!(key_nightly.ends_with("|nightly"));

    let pkg_stable = Package {
        name: "testpkg".into(),
        update_source: "github".into(),
        update_repo: "owner/repo".into(),
        update_channel: "stable".into(),
        ..Default::default()
    };
    let key_stable = canonical_update_source_key("https://api.github.com", &pkg_stable);
    assert!(key_stable.ends_with("|stable"));
    assert_ne!(key_nightly, key_stable);

    let prev_nightly = PackageUpdateRecord {
        package_id: "testpkg".to_string(),
        installed: true,
        installed_version: "1.0.0".to_string(),
        latest_version: "1.2.0-rc1".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "https://github.com/owner/repo/releases/tag/v1.2.0-rc1".to_string(),
        error: String::new(),
        source_key: key_nightly,
    };

    // When switching to stable channel and upstream fails, prev_nightly is invalidated
    let rec = build_package_update_record_for_source(
        "https://api.github.com",
        "github",
        "testpkg",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("GitHub API down")),
        Some(&prev_nightly),
        "2026-11-08T12:00:00Z".to_string(),
        &key_stable,
    );
    assert_eq!(rec.latest_version, "");
    assert_eq!(rec.checked_at, "");
    assert!(!rec.update_available);

    // When channel == "stable", a prerelease latest_version (1.2.0-rc1 or 1.0.0-1) is not retained on fallback
    let prev_prerelease_on_stable = PackageUpdateRecord {
        package_id: "testpkg".to_string(),
        installed: true,
        installed_version: "1.0.0".to_string(),
        latest_version: "1.2.0-rc1".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "".to_string(),
        error: String::new(),
        source_key: key_stable.clone(),
    };
    let rec_filtered = build_package_update_record_for_source(
        "https://api.github.com",
        "github",
        "testpkg",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("GitHub API down")),
        Some(&prev_prerelease_on_stable),
        "2026-11-08T12:00:00Z".to_string(),
        &key_stable,
    );
    assert_eq!(rec_filtered.latest_version, "");
    assert_eq!(rec_filtered.checked_at, "");
    assert!(!rec_filtered.update_available);
}

#[tokio::test]
async fn test_git_tag_channel_filtering_and_prerelease_rules() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-git-channel-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let run_git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(&temp_dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    };

    run_git(&["init", "-b", "main"]);
    run_git(&["config", "user.email", "test@example.com"]);
    run_git(&["config", "user.name", "Test"]);
    std::fs::write(temp_dir.join("README.md"), "hello").unwrap();
    run_git(&["add", "README.md"]);
    run_git(&["commit", "-m", "initial commit"]);

    // Create tags:
    // v0.9.0 (stable)
    // v1.0.0-0.1 (numeric prerelease)
    // v1.0.0-nightly (arbitrary prerelease)
    run_git(&["tag", "v0.9.0"]);
    run_git(&["tag", "v1.0.0-0.1"]);
    run_git(&["tag", "v1.0.0-nightly"]);

    let repo_url = temp_dir.to_str().unwrap();

    // 1. On "stable" (or ""), numeric prerelease v1.0.0-0.1 and v1.0.0-nightly are ignored -> selects 0.9.0!
    let res_stable = detect_latest_git_tag_for_channel(repo_url, "", "stable").await;
    assert!(
        res_stable.is_ok(),
        "Expected stable tag: {:?}",
        res_stable.err()
    );
    assert_eq!(res_stable.unwrap().0, "0.9.0");

    let res_default = detect_latest_git_tag_for_channel(repo_url, "", "").await;
    assert!(res_default.is_ok());
    assert_eq!(res_default.unwrap().0, "0.9.0");

    // 2. On "prerelease" or "nightly" channel, prereleases are allowed -> selects 1.0.0-nightly
    let res_nightly = detect_latest_git_tag_for_channel(repo_url, "", "nightly").await;
    assert!(res_nightly.is_ok());
    assert_eq!(res_nightly.unwrap().0, "1.0.0-nightly");

    // 3. Repository with ONLY prereleases:
    // Delete v0.9.0
    run_git(&["tag", "-d", "v0.9.0"]);
    run_git(&["tag", "v1.0.0-rc.1"]);

    // On "stable", no stable candidate exists -> MUST RETURN Err (never fall back to prerelease!)
    let res_no_stable = detect_latest_git_tag_for_channel(repo_url, "", "stable").await;
    assert!(
        res_no_stable.is_err(),
        "Expected Err when only prerelease tags exist on stable channel"
    );
    let err_msg = res_no_stable.unwrap_err().to_string();
    assert!(
        err_msg.contains("No stable release tags found"),
        "actual error: {err_msg}"
    );

    // On "rc" or "beta", selects v1.0.0-rc.1
    let res_rc = detect_latest_git_tag_for_channel(repo_url, "", "rc").await;
    assert!(res_rc.is_ok());
    assert_eq!(res_rc.unwrap().0, "1.0.0-rc.1");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_rate_limit_body_only_403_activates_cooldown() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    clear_github_rate_limits();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let req_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let req_count_srv = req_count.clone();

    let server = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            req_count_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut buf = vec![0; 2048];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"message": "API rate limit exceeded for 203.0.113.1."}"#;
            let resp = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");
    let repo = "owner/rate-limited-repo";

    // First call receives 403 with rate limit body and NO rate-limit headers
    let res1 = detect_latest_github_release(&client, &origin, repo).await;
    assert!(res1.is_err());
    let err1 = res1.unwrap_err().to_string();
    assert!(
        err1.contains("rate limit"),
        "expected rate limit error, got: {err1}"
    );
    assert_eq!(req_count.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Cooldown must be recorded across both "releases" and "core"/"default"
    assert!(is_github_rate_limited_for_origin(&origin, "releases"));
    assert!(is_github_api_rate_limited(&origin, "core"));
    assert!(is_github_api_rate_limited(&origin, "default"));

    // Second consecutive release discovery request must be SUPPRESSED without hitting the mock server
    let res2 = detect_latest_github_release(&client, &origin, repo).await;
    assert!(res2.is_err());
    let err2 = res2.unwrap_err().to_string();
    assert!(
        err2.contains("rate limit backoff active"),
        "expected backoff error, got: {err2}"
    );
    assert_eq!(
        req_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "Second request must be suppressed and not hit the server!"
    );

    server.abort();
    clear_github_rate_limits();
}

#[test]
fn test_dpkg_differential_ordering() {
    use std::cmp::Ordering::{Equal, Greater, Less};
    let pairs = [
        ("1.0", "1.0.0", Less),
        ("1.0.0", "1.0", Greater),
        ("1.0.0-rc1", "1.0.0", Greater),
        ("1.0.0", "1.0.0-rc1", Less),
        ("1.0.0~rc1", "1.0.0", Less),
        ("1.0.0", "1.0.0~rc1", Greater),
        ("1.0.0+git1", "1.0.0", Greater),
        ("1.0.0", "1.0.0+git1", Less),
        ("1.0.0+b1", "1.0.0", Greater),
        ("1.0.0", "1.0.0+b1", Less),
        ("1:1.0", "2.0", Greater),
        ("2.0", "1:1.0", Less),
        ("1.0-1", "1.0-2", Less),
        ("1.0-2", "1.0-1", Greater),
        ("1.0~beta1~svn1245", "1.0~beta1", Less),
        ("1.0~beta1", "1.0~beta1~svn1245", Greater),
        ("1.0a", "1.0+a", Less),
        ("1.0+a", "1.0a", Greater),
        ("1.0.0+deb11u1", "1.0.0+deb11u2", Less),
        ("1.2.3-1ubuntu1", "1.2.3-2ubuntu1", Less),
        ("0.4.17", "0.4.18.2805", Less),
        ("0.4.18.2805", "0.4.18.2805", Equal),
        ("2:1.0.0", "2:1.0.0", Equal),
        ("1.0.0-1", "1.0.0-1", Equal),
        ("1.0~rc1", "1.0~rc2", Less),
        ("1.0+debug", "1.0", Greater),
        ("1.0-0", "1.0", Equal),
        ("1.0", "1.0-0", Equal),
    ];

    let dpkg_available = std::process::Command::new("dpkg")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let run_dpkg = |v1: &str, v2: &str| -> std::cmp::Ordering {
        let eq = std::process::Command::new("dpkg")
            .args(["--compare-versions", v1, "eq", v2])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if eq {
            return std::cmp::Ordering::Equal;
        }
        let lt = std::process::Command::new("dpkg")
            .args(["--compare-versions", v1, "lt", v2])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if lt {
            return std::cmp::Ordering::Less;
        }
        std::cmp::Ordering::Greater
    };

    for (v1, v2, expected_policy) in pairs {
        let actual = compare_debian_versions_str(v1, v2);
        assert_eq!(
            actual, expected_policy,
            "Debian Policy 5.6.12 mismatch for '{v1}' vs '{v2}': actual={actual:?}, expected={expected_policy:?}"
        );
        if dpkg_available {
            let expected_dpkg = run_dpkg(v1, v2);
            assert_eq!(
                actual, expected_dpkg,
                "Debian dpkg differential mismatch for '{v1}' vs '{v2}': actual={actual:?}, expected(dpkg)={expected_dpkg:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_readarr_failed_installed_probe_preserves_error_and_rejects_admission() {
    use crate::inventory_regressions::{isolated, Fixture};
    if !isolated(
        "workers::tests::test_readarr_failed_installed_probe_preserves_error_and_rejects_admission",
    ) {
        return;
    }
    let _fixture = Fixture::new();
    af_db::init_db().unwrap();
    ensure_app_updates_columns();

    // Seed previous DB record with installed_version = "0.4.17.0"
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO app_updates (package_name, installed_version, latest_version, update_available, update_url, checked_at, last_error, source_key)
             VALUES ('readarr', '0.4.17.0', '0.4.18.2805', 1, '', '2026-11-01T00:00:00Z', '', 'retired:readarr|stable')",
            [],
        ).unwrap();
    }

    let client = build_github_http_client();
    let pkg = Package {
        name: "readarr".into(),
        update_source: "retired".into(),
        // A version_command that fails:
        version_command: vec!["/bin/false".into()],
        ..Default::default()
    };

    let (rec, _notify) = probe_package_update(&client, "https://api.github.com", &pkg).await;

    // Verify last_error / error preserves the installed version check failure
    assert!(
        rec.error
            .to_ascii_lowercase()
            .contains("installed version check failed")
            || rec
                .error
                .to_ascii_lowercase()
                .contains("installed version could not be confirmed"),
        "Expected installed check failure in error, got: {}",
        rec.error
    );

    // Crucial requirement: update_available MUST BE FALSE when installed probe fails!
    assert!(
        !rec.update_available,
        "Failed installed probe must NOT allow update_available = true!"
    );

    // Also check DB persisted state:
    let conn = af_db::get_conn().unwrap();
    let (db_avail, db_err): (bool, Option<String>) = conn
        .query_row(
            "SELECT update_available, last_error FROM app_updates WHERE package_name = 'readarr'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(!db_avail);
    assert!(
        db_err
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("installed version check failed"),
        "Database last_error must preserve failure"
    );
}

#[test]
fn test_rclone_declarative_discovery_uses_github_source_and_preserves_build_metadata() {
    let pkg = Package {
        name: "rclone".into(),
        update_source: "github".into(),
        update_repo: "rclone/rclone".into(),
        version_command: vec!["rclone".into(), "--version".into()],
        ..Default::default()
    };

    // 1. canonical_update_source_key with DeclarativeRust engine must NOT map to APT
    let (eff_src, _) = effective_update_source_and_apt_package(&pkg);
    assert_eq!(eff_src, "github");

    let key = canonical_update_source_key("https://api.github.com", &pkg);
    assert_eq!(key, "github:https://api.github.com|rclone/rclone|stable");
    assert!(!key.contains("apt:"));

    // 2. extract_version preserves +debug, +git1-1, etc.
    assert_eq!(extract_version("rclone v1.75.2", ""), "1.75.2");
    assert_eq!(extract_version("v1.0.0+debug", ""), "1.0.0+debug");
    assert_eq!(extract_version("release-v1.0.0+git1-1", ""), "1.0.0+git1-1");
    assert_eq!(extract_version("1.0.0+b1", ""), "1.0.0+b1");

    // 3. Exact source key requirement rejects keys missing |<channel>
    let legacy_key = "github:https://api.github.com|rclone/rclone";
    let prev_record = PackageUpdateRecord {
        package_id: "rclone".to_string(),
        installed: true,
        installed_version: "1.74.0".to_string(),
        latest_version: "1.75.2".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "".to_string(),
        error: "".to_string(),
        source_key: legacy_key.to_string(),
    };

    let rec = build_package_update_record_for_source(
        "https://api.github.com",
        "github",
        "rclone/rclone",
        true,
        Ok("1.74.0".to_string()),
        Err(anyhow::anyhow!("network unreachable")),
        Some(&prev_record),
        "2026-11-08T00:00:00Z".to_string(),
        &key,
    );
    // Because legacy_key is missing "|stable", exact equality fails and legacy record is rejected!
    assert_eq!(rec.latest_version, "");
    assert_eq!(rec.checked_at, "");
    assert!(!rec.update_available);
}

#[test]
fn test_github_and_github_release_synonyms_and_source_key_normalization() {
    let pkg_github = Package {
        name: "rclone".into(),
        update_source: "github".into(),
        update_repo: "rclone/rclone".into(),
        update_channel: "stable".into(),
        version_command: vec!["rclone".into(), "--version".into()],
        ..Default::default()
    };
    let pkg_github_release = Package {
        name: "rclone".into(),
        update_source: "github_release".into(),
        update_repo: "rclone/rclone".into(),
        update_channel: "stable".into(),
        version_command: vec!["rclone".into(), "--version".into()],
        ..Default::default()
    };

    let key1 = canonical_update_source_key("https://api.github.com", &pkg_github);
    let key2 = canonical_update_source_key("https://api.github.com", &pkg_github_release);
    assert_eq!(key1, "github:https://api.github.com|rclone/rclone|stable");
    assert_eq!(key1, key2);

    let (src1, _) = effective_update_source_and_apt_package(&pkg_github);
    let (src2, _) = effective_update_source_and_apt_package(&pkg_github_release);
    assert_eq!(src1, "github");
    assert_eq!(src2, "github");

    assert!(should_track_package(&pkg_github));
    assert!(should_track_package(&pkg_github_release));
}

#[test]
fn test_recompute_update_available_from_fresh_installed_observation_on_upstream_failure() {
    let prev = PackageUpdateRecord {
        package_id: "testpkg".to_string(),
        installed: true,
        installed_version: "1.0.0".to_string(),
        latest_version: "2.0.0".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "https://github.com/example/testpkg/releases/tag/v2.0.0".to_string(),
        error: String::new(),
        source_key: "github:https://api.github.com|example/testpkg|stable".to_string(),
    };

    let key = "github:https://api.github.com|example/testpkg|stable";

    // Case a: Package upgraded to 2.0.0; upstream fails -> latest_version retained as 2.0.0, update_available recomputed to false!
    let rec_upgraded = build_package_update_record_for_source(
        "https://api.github.com",
        "github",
        "testpkg",
        true,
        Ok("2.0.0".to_string()),
        Err(anyhow::anyhow!("network unreachable")),
        Some(&prev),
        "2026-11-08T12:00:00Z".to_string(),
        key,
    );
    assert_eq!(rec_upgraded.latest_version, "2.0.0");
    assert_eq!(rec_upgraded.installed_version, "2.0.0");
    assert!(!rec_upgraded.update_available);
    assert_eq!(rec_upgraded.checked_at, "2026-11-01T00:00:00Z");

    // Case b: Package at 1.5.0; upstream fails -> latest_version retained as 2.0.0, update_available recomputed to true!
    let rec_intermediate = build_package_update_record_for_source(
        "https://api.github.com",
        "github",
        "testpkg",
        true,
        Ok("1.5.0".to_string()),
        Err(anyhow::anyhow!("network unreachable")),
        Some(&prev),
        "2026-11-08T12:00:00Z".to_string(),
        key,
    );
    assert_eq!(rec_intermediate.latest_version, "2.0.0");
    assert_eq!(rec_intermediate.installed_version, "1.5.0");
    assert!(rec_intermediate.update_available);
    assert_eq!(rec_intermediate.checked_at, "2026-11-01T00:00:00Z");
}

#[test]
fn test_explicit_trusted_origin_policy_for_custom_github_enterprise() {
    // 1. Configured GHE origin matches request URL
    assert!(should_attach_github_token(
        "https://ghe.internal.example/api/v3/repos/rclone/rclone/releases/latest",
        "https://ghe.internal.example/api/v3"
    ));

    // 2. Reject untrusted third-party registries even if configured as base
    assert!(!should_attach_github_token(
        "https://pypi.org/pypi/foo/json",
        "https://ghe.internal.example/api/v3"
    ));
    assert!(!should_attach_github_token(
        "https://pypi.org/pypi/foo/json",
        "https://pypi.org"
    ));
    assert!(!should_attach_github_token(
        "https://crates.io/api/v1/crates/foo",
        "https://crates.io"
    ));

    // 3. Reject plain http:// on non-loopback hosts
    assert!(!should_attach_github_token(
        "http://ghe.internal.example/api/v3/repos/a/b",
        "http://ghe.internal.example/api/v3"
    ));

    // 4. Loopback http is permitted
    assert!(should_attach_github_token(
        "http://127.0.0.1:8080/api/v3/repos/a/b",
        "http://127.0.0.1:8080"
    ));
    assert!(should_attach_github_token(
        "http://localhost:9090/repos/a/b",
        "http://localhost:9090"
    ));

    // 5. AF_TRUSTED_GITHUB_ORIGINS environment variable
    std::env::set_var(
        "AF_TRUSTED_GITHUB_ORIGINS",
        "https://extra-ghe.corp.local, https://custom.github.net",
    );
    assert!(should_attach_github_token(
        "https://extra-ghe.corp.local/api/v3/repos/a/b",
        "https://api.github.com"
    ));
    assert!(should_attach_github_token(
        "https://custom.github.net/repos/a/b",
        "https://api.github.com"
    ));
    assert!(!should_attach_github_token(
        "https://untrusted.corp.local/api/v3/repos/a/b",
        "https://api.github.com"
    ));
    std::env::remove_var("AF_TRUSTED_GITHUB_ORIGINS");
}

#[test]
fn test_exact_default_https_port_for_builtin_github_origins() {
    assert!(!should_attach_github_token(
        "https://api.github.com:8443/repos/a/b",
        "https://api.github.com"
    ));
    assert!(should_attach_github_token(
        "https://api.github.com:443/repos/a/b",
        "https://api.github.com"
    ));
    assert!(should_attach_github_token(
        "https://api.github.com:8443/repos/a/b",
        "https://api.github.com:8443"
    ));
}

#[test]
fn test_do_not_collapse_consecutive_hyphens_in_build_metadata() {
    let v1 = extract_version("1.0.0+build--old", "");
    let v2 = extract_version("1.0.0+build--new", "");
    assert_eq!(v1, "1.0.0+build--old");
    assert_eq!(v2, "1.0.0+build--new");
    assert_ne!(v1, v2);
    assert_eq!(
        extract_version_from_text("1.0.0+build--old"),
        "1.0.0+build--old"
    );
    assert_eq!(
        extract_version_from_text("1.0.0+build--new"),
        "1.0.0+build--new"
    );
    assert!(!af_release::lifecycle::versions_match_target(
        "1.0.0+build--old",
        "1.0.0+build--new"
    ));
    assert!(!versions_match_target_internal(
        "1.0.0+build--old",
        "1.0.0+build--new"
    ));
}

#[tokio::test]
async fn test_probe_installed_package_version_strict_requires_independent_runtime_evidence() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-isolated-receipt-{}", uuid::Uuid::new_v4()));
    let opt_dir = temp_dir.join("opt/isolated-pkg");
    std::fs::create_dir_all(&opt_dir).unwrap();
    // Only .af-version exists in isolation, no lock file, no binaries, no systemd units
    std::fs::write(opt_dir.join(".af-version"), "1.0.0").unwrap();

    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let pkg = Package {
        name: "isolated-pkg".into(),
        // Empty version_command means no live command probe
        version_command: vec![],
        ..Default::default()
    };

    let res = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res.is_err(),
        "Expected probe_installed_package_version_strict to fail without runtime evidence"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("No independent runtime evidence found alongside .af-version receipt"),
        "Expected 'No independent runtime evidence found alongside .af-version receipt', got: {err_msg}"
    );

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_extract_version_preserves_trailing_hyphens_in_build_metadata() {
    assert_eq!(extract_version("1.0.0+build-", ""), "1.0.0+build-");
    assert_eq!(extract_version("1.0.0+build--", ""), "1.0.0+build--");
    assert_eq!(extract_version("1.0.0-rc1-", ""), "1.0.0-rc1-");
    assert_eq!(extract_version_from_text("1.0.0+build-"), "1.0.0+build-");
    assert_eq!(extract_version_from_text("1.0.0+build--"), "1.0.0+build--");
    assert!(!af_release::lifecycle::versions_match_target(
        "1.0.0+build-",
        "1.0.0+build--"
    ));
}

#[tokio::test]
async fn test_github_release_discovery_rejects_prerelease_on_stable_channel() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0; 2048];
        let _ = socket.read(&mut buf).await.unwrap();
        // Upstream GitHub returns a release marked with tag "v2.0.0-rc1"
        let body = r#"{"tag_name":"v2.0.0-rc1","html_url":"http://mock/release/v2.0.0-rc1","prerelease":false}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        socket.write_all(resp.as_bytes()).await.unwrap();
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");
    let repo = "owner/prerelease-repo";

    // 1. Stable channel discovery must reject "v2.0.0-rc1"
    let res = detect_latest_github_release_for_channel(&client, &origin, repo, "stable").await;
    assert!(
        res.is_err(),
        "Stable channel must reject prerelease tag: {:?}",
        res
    );
    server.await.unwrap();

    // 2. Must NOT store under "stable" cache
    let stable_key = github_release_cache_key_for_channel(&origin, repo, "stable");
    let cached = github_release_cache().get(&stable_key).cloned();
    assert!(
        cached.is_none(),
        "Stable cache must not contain rejected prerelease: {:?}",
        cached
    );

    // 3. Stale cache fallback for stable channel must return None even if prerelease is in cache
    {
        let mut cache = github_release_cache();
        cache.insert(
            stable_key.clone(),
            (
                "2.0.0-rc1".to_string(),
                "http://mock/url".to_string(),
                Instant::now() - Duration::from_secs(3600),
                "2026-11-08T00:00:00Z".to_string(),
            ),
        );
    }
    assert_eq!(
        get_cached_github_release_stale_for_channel(&origin, repo, "stable"),
        None
    );

    // 4. Fresh cache lookup via detect_latest_github_release_for_channel must also reject cached 2.0.0-rc1
    let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();
    let origin2 = format!("http://{addr2}");
    let stable_key2 = github_release_cache_key_for_channel(&origin2, repo, "stable");
    {
        let mut cache = github_release_cache();
        cache.insert(
            stable_key2.clone(),
            (
                "2.0.0-rc1".to_string(),
                "http://mock/url".to_string(),
                Instant::now(),
                "2026-11-08T00:00:00Z".to_string(),
            ),
        );
    }
    let res_cached =
        detect_latest_github_release_for_channel(&client, &origin2, repo, "stable").await;
    assert!(res_cached.is_err());
}

#[tokio::test]
async fn test_mixed_case_stable_rejects_prerelease_and_does_not_pollute_cache() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 2048];
            let _ = socket.read(&mut buf).await.unwrap();
            let body = r#"{"tag_name":"v1.2.3","html_url":"http://mock/release/v1.2.3","prerelease":true}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(resp.as_bytes()).await.unwrap();
        }
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");
    let repo = "owner/mixedcase-stable-repo";

    let res_mixed =
        detect_latest_github_release_for_channel(&client, &origin, repo, "Stable").await;
    assert!(
        res_mixed.is_err(),
        "Stable channel (mixed-case) must reject prerelease:true: {:?}",
        res_mixed
    );

    let res_upper =
        detect_latest_github_release_for_channel(&client, &origin, repo, "STABLE").await;
    assert!(
        res_upper.is_err(),
        "STABLE channel (upper-case) must reject prerelease:true: {:?}",
        res_upper
    );

    server.await.unwrap();

    let stable_key = github_release_cache_key_for_channel(&origin, repo, "stable");
    let cached = github_release_cache().get(&stable_key).cloned();
    assert!(
        cached.is_none(),
        "Stable cache must not contain rejected prerelease: {:?}",
        cached
    );
}

#[test]
fn test_extract_version_preserves_hyphen_only_identifiers() {
    assert_eq!(extract_version("1.0.0--", ""), "1.0.0--");
    assert_eq!(extract_version("1.0.0+--", ""), "1.0.0+--");
    assert_eq!(extract_version("1.0.0+-", ""), "1.0.0+-");
    assert_eq!(extract_version("1.0.0+build-", ""), "1.0.0+build-");
    assert_eq!(extract_version("1.0.0+build--", ""), "1.0.0+build--");
    assert_eq!(extract_version("1.0.0-rc1-", ""), "1.0.0-rc1-");

    assert_eq!(extract_version("1.0.0-", ""), "1.0.0");
    assert_eq!(extract_version("1.0.0+", ""), "1.0.0");
}

#[tokio::test]
async fn test_runtime_evidence_rejects_non_runtime_and_receipt_rejects_symlink_fifo() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-runtime-evidence-{}", uuid::Uuid::new_v4()));
    let opt_dir = temp_dir.join("opt/evidence-pkg");
    std::fs::create_dir_all(&opt_dir).unwrap();

    let version_file = opt_dir.join(".af-version");
    std::fs::write(&version_file, "1.2.3").unwrap();
    std::fs::write(opt_dir.join("install.log"), "Installation finished").unwrap();
    std::fs::write(opt_dir.join("anything.lock"), "lock data").unwrap();

    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let pkg = Package {
        name: "evidence-pkg".into(),
        version_command: vec![],
        ..Default::default()
    };

    let res = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res.is_err(),
        "Expected failure without executable runtime files"
    );
    assert!(
        res.unwrap_err()
            .to_string()
            .contains("No independent runtime evidence found"),
        "Should reject non-runtime files as evidence"
    );

    use std::os::unix::fs::PermissionsExt;
    let non_exec_bin = opt_dir.join("non_exec_binary");
    std::fs::write(&non_exec_bin, "#!/bin/sh\necho hi\n").unwrap();
    std::fs::set_permissions(&non_exec_bin, std::fs::Permissions::from_mode(0o644)).unwrap();

    let res2 = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res2.is_err(),
        "Expected failure when binary is not executable (0o644)"
    );

    let symlink_receipt = opt_dir.join("symlink_receipt");
    std::os::unix::fs::symlink(&version_file, &symlink_receipt).unwrap();
    let sym_res = read_receipt_bounded_nofollow(&symlink_receipt);
    assert!(
        sym_res.is_err(),
        "read_receipt_bounded_nofollow must reject symlinks: {:?}",
        sym_res
    );

    let fifo_receipt = opt_dir.join("fifo_receipt");
    let c_fifo = std::ffi::CString::new(fifo_receipt.to_str().unwrap()).unwrap();
    let mkfifo_ret = unsafe { af_release::lifecycle::libc::mkfifo(c_fifo.as_ptr(), 0o644) };
    assert_eq!(mkfifo_ret, 0, "mkfifo failed");
    let fifo_res = read_receipt_bounded_nofollow(&fifo_receipt);
    assert!(
        fifo_res.is_err(),
        "read_receipt_bounded_nofollow must reject FIFOs: {:?}",
        fifo_res
    );

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_stale_or_empty_service_unit_file_rejected_as_runtime_evidence() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-stale-unit-{}", uuid::Uuid::new_v4()));
    let opt_dir = temp_dir.join("opt/stale-service-pkg");
    let systemd_dir = temp_dir.join("etc/systemd/system");
    std::fs::create_dir_all(&opt_dir).unwrap();
    std::fs::create_dir_all(&systemd_dir).unwrap();

    let version_file = opt_dir.join(".af-version");
    std::fs::write(&version_file, "1.2.3").unwrap();

    let service_file = systemd_dir.join("stale-service-pkg.service");

    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let pkg = Package {
        name: "stale-service-pkg".into(),
        lock_file: "/opt/stale-service-pkg/.af-version".into(),
        version_command: vec![],
        ..Default::default()
    };

    // 1. Empty .service file must be rejected
    std::fs::write(&service_file, "").unwrap();
    let res_empty = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_empty.is_err(),
        "Empty .service file must NOT certify runtime"
    );
    let err_msg = res_empty.unwrap_err().to_string();
    assert!(
        err_msg.contains("No independent runtime evidence found"),
        "Expected 'No independent runtime evidence found', got: {err_msg}"
    );

    // 2. .service file with no ExecStart= must be rejected
    std::fs::write(
        &service_file,
        "[Unit]\nDescription=Stale Service\n[Service]\nRestart=always\n",
    )
    .unwrap();
    let res_no_exec = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_no_exec.is_err(),
        ".service with no ExecStart= must NOT certify runtime"
    );

    // 3. .service file with ExecStart= pointing to nonexistent binary must be rejected
    std::fs::write(
        &service_file,
        "[Unit]\nDescription=Stale Service\n[Service]\nExecStart=/usr/local/bin/nonexistent_bin_xyz --flag\n",
    )
    .unwrap();
    let res_nonexistent = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_nonexistent.is_err(),
        ".service with nonexistent binary must NOT certify runtime"
    );

    // 4. .service file with ExecStart= pointing to a non-executable file (0o644) must be rejected
    use std::os::unix::fs::PermissionsExt;
    let non_exec_script = opt_dir.join("daemon.sh");
    std::fs::write(&non_exec_script, "#!/bin/sh\necho running\n").unwrap();
    std::fs::set_permissions(&non_exec_script, std::fs::Permissions::from_mode(0o644)).unwrap();

    std::fs::write(
        &service_file,
        "[Unit]\nDescription=Stale Service\n[Service]\nExecStart=-/opt/stale-service-pkg/daemon.sh\n",
    )
    .unwrap();
    let res_non_exec = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_non_exec.is_err(),
        ".service with non-executable binary must NOT certify runtime"
    );

    // 5. Positive control: when binary becomes executable (0o755), runtime evidence is certified
    std::fs::set_permissions(&non_exec_script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let res_valid = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_valid.is_ok(),
        "Valid executable in ExecStart= should satisfy runtime evidence: {:?}",
        res_valid.err()
    );
    assert_eq!(res_valid.unwrap(), "1.2.3");

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_github_release_discovery_for_prerelease_and_stable_channels() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                let (status, body) = if req.contains("/releases/latest") {
                    (
                        "200 OK",
                        r#"{"tag_name":"v1.9.0","html_url":"http://mock/release/v1.9.0","prerelease":false,"draft":false}"#.to_string(),
                    )
                } else if req.contains("/releases?per_page=100") {
                    (
                        "200 OK",
                        r#"[
                            {"tag_name":"v3.0.0-draft","html_url":"http://mock/release/v3.0.0-draft","prerelease":true,"draft":true},
                            {"tag_name":"v2.0.0-beta.1","html_url":"http://mock/release/v2.0.0-beta.1","prerelease":true,"draft":false},
                            {"tag_name":"v1.9.0","html_url":"http://mock/release/v1.9.0","prerelease":false,"draft":false}
                        ]"#.to_string(),
                    )
                } else {
                    ("404 Not Found", r#"{"message":"Not Found"}"#.to_string())
                };

                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");
    let repo = "owner/prerelease-discovery-repo";

    // 1. Beta channel queries /releases?per_page=100, skips draft v3.0.0-draft, discovers v2.0.0-beta.1 over v1.9.0
    let res_beta = detect_latest_github_release_for_channel(&client, &origin, repo, "beta").await;
    assert!(
        res_beta.is_ok(),
        "Beta channel discovery failed: {:?}",
        res_beta.err()
    );
    let (ver_beta, url_beta, _) = res_beta.unwrap();
    assert_eq!(ver_beta, "2.0.0-beta.1");
    assert_eq!(url_beta, "http://mock/release/v2.0.0-beta.1");

    // 2. Nightly channel queries /releases?per_page=100, skips draft, discovers v2.0.0-beta.1 over v1.9.0
    let repo_nightly = "owner/prerelease-discovery-nightly";
    let res_nightly =
        detect_latest_github_release_for_channel(&client, &origin, repo_nightly, "nightly").await;
    assert!(
        res_nightly.is_ok(),
        "Nightly channel discovery failed: {:?}",
        res_nightly.err()
    );
    let (ver_nightly, url_nightly, _) = res_nightly.unwrap();
    assert_eq!(ver_nightly, "2.0.0-beta.1");
    assert_eq!(url_nightly, "http://mock/release/v2.0.0-beta.1");

    // 3. Stable channel queries /releases/latest and selects v1.9.0
    let repo_stable = "owner/prerelease-discovery-stable";
    let res_stable =
        detect_latest_github_release_for_channel(&client, &origin, repo_stable, "stable").await;
    assert!(
        res_stable.is_ok(),
        "Stable channel discovery failed: {:?}",
        res_stable.err()
    );
    let (ver_stable, url_stable, _) = res_stable.unwrap();
    assert_eq!(ver_stable, "1.9.0");
    assert_eq!(url_stable, "http://mock/release/v1.9.0");

    server.abort();
}

#[tokio::test]
async fn test_git_head_cache_isolation_by_remote_url() {
    let repo = "org/app";
    let remote_a = "https://git.provider-a.com/org/app.git";
    let remote_b = "https://git.provider-b.com/org/app.git";

    let key_a = git_head_cache_key(remote_a, repo);
    let key_b = git_head_cache_key(remote_b, repo);
    assert_ne!(
        key_a, key_b,
        "Cache keys must be isolated across different remote URLs"
    );

    let sha_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let sha_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let now = Instant::now();
    let ts = "2026-11-09T00:00:00Z".to_string();

    {
        let mut cache = GIT_REMOTE_HEAD_CACHE.lock().unwrap();
        cache.insert(
            key_a.clone(),
            (
                sha_a.to_string(),
                "http://remote-a/commit".to_string(),
                now,
                ts.clone(),
            ),
        );
        cache.insert(
            key_b.clone(),
            (
                sha_b.to_string(),
                "http://remote-b/commit".to_string(),
                now,
                ts.clone(),
            ),
        );
    }

    let cached_a = GIT_REMOTE_HEAD_CACHE.lock().unwrap().get(&key_a).cloned();
    let cached_b = GIT_REMOTE_HEAD_CACHE.lock().unwrap().get(&key_b).cloned();

    assert_eq!(cached_a.unwrap().0, sha_a);
    assert_eq!(cached_b.unwrap().0, sha_b);
}

#[test]
fn test_tag_allowed_by_channel_preserves_debian_revisions_and_rejects_prereleases() {
    // Stable channel must allow valid Debian package revisions:
    assert!(tag_allowed_by_channel("1:1.2.3-1+b1", "stable"));
    assert!(tag_allowed_by_channel("2.4.5-1ubuntu1", "stable"));
    assert!(tag_allowed_by_channel("1.0.0-1deb12u1", "stable"));
    assert!(tag_allowed_by_channel("1.2.3-1", "stable"));
    assert!(tag_allowed_by_channel("0ubuntu0.22.04.1", "stable"));

    // Stable channel must reject true prereleases:
    assert!(!tag_allowed_by_channel("1.2.3-rc1", "stable"));
    assert!(!tag_allowed_by_channel("1.2.3-beta.1", "stable"));
    assert!(!tag_allowed_by_channel("1.0.0-alpha", "stable"));
    assert!(!tag_allowed_by_channel("1.0.0-nightly.20261109", "stable"));
    assert!(!tag_allowed_by_channel("1.0.0-0.1", "stable"));
    assert!(!tag_allowed_by_channel("1.0.0--", "stable"));

    // Retained APT target preservation on discovery failure:
    let prev_record = PackageUpdateRecord {
        package_id: "deb-pkg".to_string(),
        installed: true,
        installed_version: "1:1.2.3-1".to_string(),
        latest_version: "1:1.2.3-1+b1".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "".to_string(),
        error: "".to_string(),
        source_key: "apt:deb-pkg|stable".to_string(),
    };

    let rec = build_package_update_record_for_source(
        "",
        "apt",
        "deb-pkg",
        true,
        Ok("1:1.2.3-1".to_string()),
        Err(anyhow::anyhow!("apt repository timeout")),
        Some(&prev_record),
        "2026-11-09T00:00:00Z".to_string(),
        "apt:deb-pkg|stable",
    );

    // Retained target must NOT be cleared because "1:1.2.3-1+b1" is a valid stable revision!
    assert_eq!(rec.latest_version, "1:1.2.3-1+b1");
    assert!(rec.update_available);
    assert_eq!(rec.checked_at, "2026-11-01T00:00:00Z");

    // And check for ubuntu and debian suffixes:
    for deb_ver in ["2.4.5-1ubuntu1", "1.0.0-1deb12u1"] {
        let prev = PackageUpdateRecord {
            package_id: "deb-pkg2".to_string(),
            installed: true,
            installed_version: "1.0.0".to_string(),
            latest_version: deb_ver.to_string(),
            update_available: true,
            checked_at: "2026-11-01T00:00:00Z".to_string(),
            release_url: "".to_string(),
            error: "".to_string(),
            source_key: "apt:deb-pkg2|stable".to_string(),
        };
        let r = build_package_update_record_for_source(
            "",
            "apt",
            "deb-pkg2",
            true,
            Ok("1.0.0".to_string()),
            Err(anyhow::anyhow!("apt repository timeout")),
            Some(&prev),
            "2026-11-09T00:00:00Z".to_string(),
            "apt:deb-pkg2|stable",
        );
        assert_eq!(r.latest_version, deb_ver);
        assert!(r.update_available);
    }
}

#[tokio::test]
async fn test_systemd_unit_validation_execstart_reset_and_missing_script() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-systemd-reset-{}", uuid::Uuid::new_v4()));
    let opt_dir = temp_dir.join("opt/test-svc");
    let systemd_dir = temp_dir.join("etc/systemd/system");
    std::fs::create_dir_all(&opt_dir).unwrap();
    std::fs::create_dir_all(&systemd_dir).unwrap();

    std::fs::write(opt_dir.join(".af-version"), "1.0.0").unwrap();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let pkg = Package {
        name: "test-svc".into(),
        lock_file: "/opt/test-svc/.af-version".into(),
        version_command: vec![],
        ..Default::default()
    };

    let service_file = systemd_dir.join("test-svc.service");

    // 1. ExecStart=/bin/true followed by empty ExecStart= reset line must be REJECTED!
    std::fs::write(
        &service_file,
        "[Unit]\nDescription=Test Service\n[Service]\nExecStart=/bin/true\nExecStart=\n",
    )
    .unwrap();
    let res_reset = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_reset.is_err(),
        "Unit file with ExecStart=/bin/true followed by ExecStart= reset MUST be rejected!"
    );

    // 2. ExecStart=/bin/sh /nonexistent/script.sh must be REJECTED because referenced script does not exist!
    std::fs::write(
        &service_file,
        "[Unit]\nDescription=Test Service\n[Service]\nExecStart=/bin/sh /nonexistent/script.sh\n",
    )
    .unwrap();
    let res_missing_script = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_missing_script.is_err(),
        "Unit file with interpreter pointing to missing script MUST be rejected!"
    );

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_detect_latest_github_release_prerelease_channel_selects_highest_version() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let mut buf = vec![0; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]);
            let body = if req_str.contains("repo-pre-beta") {
                r#"[
                    {"tag_name": "v1.9.0-beta", "html_url": "https://github.com/mock/repo/releases/v1.9.0-beta", "prerelease": true},
                    {"tag_name": "v2.0.0-beta.1", "html_url": "https://github.com/mock/repo/releases/v2.0.0-beta.1", "prerelease": true}
                ]"#
            } else {
                r#"[
                    {"tag_name": "v1.9.0-beta", "html_url": "https://github.com/mock/repo/releases/v1.9.0-beta", "prerelease": true},
                    {"tag_name": "v2.0.0", "html_url": "https://github.com/mock/repo/releases/v2.0.0", "prerelease": false}
                ]"#
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");

    // 1. Channel "prerelease" with v1.9.0-beta and v2.0.0
    let res_pre = detect_latest_github_release_for_channel(
        &client,
        &origin,
        "test-owner/repo-pre",
        "prerelease",
    )
    .await
    .unwrap();
    assert_eq!(
        res_pre.0, "2.0.0",
        "prerelease channel must select higher version 2.0.0 over 1.9.0-beta"
    );
    assert_ne!(res_pre.0, "1.9.0-beta");

    // 2. Channel "beta" with v1.9.0-beta and v2.0.0
    let res_beta =
        detect_latest_github_release_for_channel(&client, &origin, "test-owner/repo-beta", "beta")
            .await
            .unwrap();
    assert_eq!(
        res_beta.0, "2.0.0",
        "beta channel must select higher version 2.0.0 over 1.9.0-beta"
    );
    assert_ne!(res_beta.0, "1.9.0-beta");

    // 3. Channel "all" with v1.9.0-beta and v2.0.0
    let res_all =
        detect_latest_github_release_for_channel(&client, &origin, "test-owner/repo-all", "all")
            .await
            .unwrap();
    assert_eq!(
        res_all.0, "2.0.0",
        "all channel must select higher version 2.0.0 over 1.9.0-beta"
    );
    assert_ne!(res_all.0, "1.9.0-beta");

    // 4. Channel "prerelease" with v1.9.0-beta and v2.0.0-beta.1
    let res_pre_beta = detect_latest_github_release_for_channel(
        &client,
        &origin,
        "test-owner/repo-pre-beta",
        "prerelease",
    )
    .await
    .unwrap();
    assert_eq!(
        res_pre_beta.0, "2.0.0-beta.1",
        "prerelease channel must select higher version 2.0.0-beta.1 over 1.9.0-beta"
    );

    server.abort();
}

#[test]
fn test_git_remotes_case_sensitivity_and_normalization() {
    let url1 = "https://Git.Example.com/team/App.git";
    let url2 = "https://git.example.com/team/app.git";
    let url3 = "HTTPS://GIT.EXAMPLE.COM:443/team/App.git";
    let url4 = "https://git.example.com/team/App.git";

    // git_head_cache_key:
    let key1 = git_head_cache_key(url1, "team/App");
    let key2 = git_head_cache_key(url2, "team/app");
    let key3 = git_head_cache_key(url3, "team/App");
    let key4 = git_head_cache_key(url4, "team/App");

    assert_ne!(
        key1, key2,
        "team/App.git and team/app.git must produce distinct git_head_cache_key values"
    );
    assert_eq!(key1, key3, "HTTPS://GIT.EXAMPLE.COM:443/team/App.git and https://Git.Example.com/team/App.git must normalize to same key");
    assert_eq!(key1, key4);

    // canonical_update_source_key:
    let pkg1 = Package {
        name: "app".into(),
        update_source: "git".into(),
        update_repo: "team/App".into(),
        update_repo_url: url1.into(),
        ..Default::default()
    };
    let pkg2 = Package {
        name: "app".into(),
        update_source: "git".into(),
        update_repo: "team/app".into(),
        update_repo_url: url2.into(),
        ..Default::default()
    };
    let pkg3 = Package {
        name: "app".into(),
        update_source: "git".into(),
        update_repo: "team/App".into(),
        update_repo_url: url3.into(),
        ..Default::default()
    };
    let pkg4 = Package {
        name: "app".into(),
        update_source: "git".into(),
        update_repo: "team/App".into(),
        update_repo_url: url4.into(),
        ..Default::default()
    };

    let ckey1 = canonical_update_source_key("", &pkg1);
    let ckey2 = canonical_update_source_key("", &pkg2);
    let ckey3 = canonical_update_source_key("", &pkg3);
    let ckey4 = canonical_update_source_key("", &pkg4);

    assert_ne!(
        ckey1, ckey2,
        "canonical_update_source_key must preserve path case and distinguish App vs app"
    );
    assert_eq!(
        ckey1, ckey3,
        "canonical_update_source_key must normalize authority and default port :443"
    );
    assert_eq!(ckey1, ckey4);
}

#[test]
fn test_channel_source_debian_revisions_and_semver_rejection() {
    // 1. Rejected on stable in both tag_allowed_by_channel and is_prerelease_version_for_channel
    assert!(is_prerelease_version_for_channel("1.2.3-foo-1"));
    assert!(is_prerelease_version_for_channel("1.2.3-1.2"));
    assert!(!tag_allowed_by_channel("1.2.3-foo-1", "stable"));
    assert!(!tag_allowed_by_channel("1.2.3-1.2", "stable"));

    // Source-aware for github and git:
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-foo-1",
        "stable",
        "github"
    ));
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-1.2",
        "stable",
        "github"
    ));
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-foo-1",
        "stable",
        "git"
    ));
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-1.2",
        "stable",
        "git"
    ));

    // 2. Allowed on stable for APT / retained targets
    assert!(!is_prerelease_version_for_channel("1:1.2.3-1+b1"));
    assert!(!is_prerelease_version_for_channel("2.4.5-1ubuntu1"));
    assert!(!is_prerelease_version_for_channel("1.0.0-1deb12u1"));
    assert!(!is_prerelease_version_for_channel("1.2.3-1"));

    assert!(tag_allowed_by_channel_for_source(
        "1:1.2.3-1+b1",
        "stable",
        "apt"
    ));
    assert!(tag_allowed_by_channel_for_source(
        "2.4.5-1ubuntu1",
        "stable",
        "apt"
    ));
    assert!(tag_allowed_by_channel_for_source(
        "1.0.0-1deb12u1",
        "stable",
        "apt"
    ));
    assert!(tag_allowed_by_channel_for_source(
        "1.2.3-1", "stable", "apt"
    ));

    assert!(tag_allowed_by_channel("1:1.2.3-1+b1", "stable"));
    assert!(tag_allowed_by_channel("2.4.5-1ubuntu1", "stable"));
    assert!(tag_allowed_by_channel("1.0.0-1deb12u1", "stable"));
    assert!(tag_allowed_by_channel("1.2.3-1", "stable"));
}

#[test]
fn test_systemd_unit_execstart_under_unit_rejected() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-systemd-unit-sec-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let service_file = temp_dir.join("test-invalid.service");
    std::fs::write(
        &service_file,
        "[Unit]\nDescription=Test Service\nExecStart=/bin/true\n[Service]\nTimeoutSec=30\n",
    )
    .unwrap();
    let pkg = Package {
        name: "test-invalid".into(),
        ..Default::default()
    };
    let is_valid = is_valid_systemd_service_unit(&service_file, &pkg);
    assert!(!is_valid, "systemd unit with ExecStart under [Unit] must be rejected by is_valid_systemd_service_unit");

    let bin_true = std::path::Path::new("/bin/true");
    if bin_true.exists() {
        let valid_file = temp_dir.join("test-valid.service");
        std::fs::write(
            &valid_file,
            "[Unit]\nDescription=Test Service\n[Service]\nExecStart=/bin/true\n",
        )
        .unwrap();
        let is_valid_ok = is_valid_systemd_service_unit(&valid_file, &pkg);
        assert!(
            is_valid_ok,
            "systemd unit with ExecStart under [Service] must be accepted"
        );
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_git_remotes_credentials_and_ssh_user_case() {
    let u1 = "Deploy@Git.Example.com:Team/App.git";
    let u2 = "deploy@Git.Example.com:Team/App.git";

    let k1 = git_head_cache_key(u1, "team/App");
    let k2 = git_head_cache_key(u2, "team/App");
    assert_ne!(
        k1, k2,
        "Deploy@host and deploy@host must produce distinct git_head_cache_key values"
    );

    let pkg1 = Package {
        name: "app".into(),
        update_source: "git".into(),
        update_repo: "team/App".into(),
        update_repo_url: u1.into(),
        ..Default::default()
    };
    let pkg2 = Package {
        name: "app".into(),
        update_source: "git".into(),
        update_repo: "team/App".into(),
        update_repo_url: u2.into(),
        ..Default::default()
    };
    let ck1 = canonical_update_source_key("", &pkg1);
    let ck2 = canonical_update_source_key("", &pkg2);
    assert_ne!(
        ck1, ck2,
        "Deploy@host and deploy@host must produce distinct canonical_update_source_key values"
    );

    let cred_url = "https://admin:super_secret_token@git.example.com/team/App.git";
    let pkg_cred = Package {
        name: "app-cred".into(),
        update_source: "git".into(),
        update_repo: "team/App".into(),
        update_repo_url: cred_url.into(),
        ..Default::default()
    };
    let ckey_cred = canonical_update_source_key("", &pkg_cred);
    let head_key_cred = git_head_cache_key(cred_url, "team/App");
    let disp_url = sanitize_git_remote_url_for_display(cred_url);

    assert!(
        !ckey_cred.contains("super_secret_token"),
        "canonical key must not leak password"
    );
    assert!(!ckey_cred.contains("admin:super_secret_token"));
    assert!(
        !head_key_cred.contains("super_secret_token"),
        "cache key must not leak password"
    );
    assert!(!head_key_cred.contains("admin:super_secret_token"));
    assert!(
        !disp_url.contains("super_secret_token"),
        "display url must not leak password"
    );
    assert!(!disp_url.contains("admin:super_secret_token"));
    assert_eq!(disp_url, "https://git.example.com/team/App.git");

    // Test persistence in SQLite
    let rec = PackageUpdateRecord {
        package_id: "test-cred-pkg".into(),
        release_url: cred_url.into(),
        error: "failed with secret: super_secret_token".into(),
        ..Default::default()
    };
    persist_package_update_record(&rec);
    if let Ok(conn) = af_db::get_conn() {
        let mut stmt = conn
            .prepare("SELECT update_url, last_error FROM app_updates WHERE package_name = ?1")
            .unwrap();
        let mut rows = stmt.query(params!["test-cred-pkg"]).unwrap();
        if let Some(row) = rows.next().unwrap() {
            let saved_url: String = row.get(0).unwrap();
            let saved_err: String = row.get(1).unwrap();
            assert!(!saved_url.contains("super_secret_token"));
            assert!(!saved_url.contains("admin:super_secret_token"));
            assert!(!saved_err.contains("super_secret_token"));
        }
    }
}

#[test]
fn test_systemd_unit_validation_case_sensitive_and_no_execstartpre() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-systemd-unit-pre-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let pkg = Package {
        name: "test-pre".into(),
        ..Default::default()
    };

    // 1. ExecStartPre only in [Service] -> invalid!
    let pre_only = temp_dir.join("pre-only.service");
    std::fs::write(
        &pre_only,
        "[Unit]\nDescription=Pre Only\n[Service]\nExecStartPre=/bin/true\n",
    )
    .unwrap();
    assert!(
        !is_valid_systemd_service_unit(&pre_only, &pkg),
        "ExecStartPre alone must not satisfy is_valid_systemd_service_unit"
    );

    // 2. Lowercase execstart= in [Service] -> invalid!
    let lower_only = temp_dir.join("lower-only.service");
    std::fs::write(
        &lower_only,
        "[Unit]\nDescription=Lower Only\n[Service]\nexecstart=/bin/true\n",
    )
    .unwrap();
    assert!(
        !is_valid_systemd_service_unit(&lower_only, &pkg),
        "lowercase execstart= must not satisfy is_valid_systemd_service_unit"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn github_numeric_release_links_keep_the_configured_repository() {
    let base = "https://api.github.com";
    assert_eq!(
        github_releases_next_request_url(
            "https://api.github.com/repositories/17803236/releases?per_page=30&page=2",
            base,
            "rclone/rclone",
        )
        .as_deref(),
        Some("https://api.github.com/repos/rclone/rclone/releases?per_page=30&page=2"),
    );
    assert_eq!(
        github_releases_next_request_url(
            "https://ghe.internal/api/v3/repositories/123/releases?page=3",
            "https://ghe.internal/api/v3",
            "org/repo",
        )
        .as_deref(),
        Some("https://ghe.internal/api/v3/repos/org/repo/releases?per_page=100&page=3"),
    );
    for url in [
        "https://evil.example/repositories/17803236/releases?page=2",
        "https://api.github.com/repos/other/repo/releases?page=2",
        "https://api.github.com/repositories/17803236/issues?page=2",
        "https://api.github.com/repositories/not-an-id/releases?page=2",
        "https://api.github.com/repositories/17803236/releases?page=0",
        "https://api.github.com/repositories/17803236/releases?page=2&page=3",
        "https://api.github.com/repositories/17803236/releases?per_page=0&page=2",
        "https://api.github.com/repositories/17803236/releases?per_page=101&page=2",
        "https://api.github.com/repositories/17803236/releases?per_page=30&per_page=100&page=2",
        "https://api.github.com/repositories/17803236/releases?page=2#fragment",
        "https://user@api.github.com/repositories/17803236/releases?page=2",
    ] {
        assert!(
            github_releases_next_request_url(url, base, "rclone/rclone").is_none(),
            "{url}"
        );
    }
}

#[tokio::test]
async fn github_numeric_release_pagination_observes_the_next_page() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for page in [1, 2] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);
            let expected = if page == 1 {
                "GET /repos/owner/numeric-links/releases?per_page=100 HTTP/1.1".to_string()
            } else {
                "GET /repos/owner/numeric-links/releases?per_page=100&page=2 HTTP/1.1".to_string()
            };
            assert!(request.starts_with(&expected), "{request}");
            let body = format!(
                r#"[{{"tag_name":"v{page}.0.0","html_url":"https://github.com/owner/numeric-links/releases/tag/v{page}.0.0"}}]"#
            );
            let link = if page == 1 {
                format!("Link: <http://{addr}/repositories/123/releases?per_page=100&page=2>; rel=\"next\"\r\n")
            } else {
                String::new()
            };
            socket.write_all(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{link}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            ).as_bytes()).await.unwrap();
        }
    });
    let result = detect_latest_github_release_for_channel(
        &build_github_http_client(),
        &format!("http://{addr}"),
        "owner/numeric-links",
        "stable",
    )
    .await
    .unwrap();
    assert_eq!(result.0, "2.0.0");
    server.await.unwrap();
}

#[tokio::test]
async fn test_github_release_discovery_multi_page_pagination() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let mut buf = vec![0; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]);

            let body: String = if req_str.contains("page=2") {
                r#"[{"tag_name": "v2.1.0-beta.1", "html_url": "https://github.com/org/repo/releases/v2.1.0-beta.1", "prerelease": true, "draft": false}]"#.to_string()
            } else {
                let mut items = Vec::new();
                for i in 1..=GITHUB_RELEASE_PAGE_SIZE {
                    items.push(format!(
                        r#"{{"tag_name": "v1.9.{}", "html_url": "https://github.com/org/repo/releases/v1.9.{}", "prerelease": false, "draft": false}}"#,
                        i, i
                    ));
                }
                format!("[{}]", items.join(","))
            };

            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");

    let res = detect_latest_github_release_for_channel(
        &client,
        &origin,
        "test-owner/multi-page-repo",
        "prerelease",
    )
    .await
    .unwrap();
    assert_eq!(
        res.0, "2.1.0-beta.1",
        "Pagination must fetch page 2 and discover higher 2.1.0-beta.1 over page 1's v1.9.100"
    );

    server.abort();
}

#[test]
fn test_retained_git_tags_and_apt_dotted_revisions() {
    // Git tags: 1.2.3-1 is a SemVer prerelease, rejected on stable
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-1", "stable", "git_tags"
    ));
    assert!(!tag_allowed_by_channel_for_source(
        "1.0.0-0.1",
        "stable",
        "git_tags"
    ));
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-1.2",
        "stable",
        "git_tags"
    ));

    // APT: 1.0.0-0.1, 1.2.3-1.2, 1:1.2.3-1+b1, 1.2.3-1 are valid Debian NMU revisions, preserved on stable!
    assert!(tag_allowed_by_channel_for_source(
        "1.0.0-0.1",
        "stable",
        "apt"
    ));
    assert!(tag_allowed_by_channel_for_source(
        "1.2.3-1.2",
        "stable",
        "apt"
    ));
    assert!(tag_allowed_by_channel_for_source(
        "1:1.2.3-1+b1",
        "stable",
        "apt"
    ));
    assert!(tag_allowed_by_channel_for_source(
        "1.2.3-1", "stable", "apt"
    ));
    assert!(tag_allowed_by_channel_for_source(
        "2.4.5-1ubuntu1",
        "stable",
        "apt"
    ));

    // APT rejects prerelease tags
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-rc1",
        "stable",
        "apt"
    ));
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-foo-1",
        "stable",
        "apt"
    ));
}

#[tokio::test]
async fn test_github_release_discovery_stable_channel_scans_pages_and_picks_highest() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let mut buf = vec![0; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]);

            let (status, body) = if req_str.contains("/releases/latest") {
                (
                    "HTTP/1.1 200 OK",
                    r#"{"tag_name": "v1.9.4", "html_url": "https://github.com/org/repo/releases/v1.9.4", "prerelease": false, "draft": false}"#,
                )
            } else if req_str.contains("/releases?per_page=100") {
                (
                    "HTTP/1.1 200 OK",
                    r#"[
                        {"tag_name": "v1.9.4", "html_url": "https://github.com/org/repo/releases/v1.9.4", "prerelease": false, "draft": false},
                        {"tag_name": "v2.0.0", "html_url": "https://github.com/org/repo/releases/v2.0.0", "prerelease": false, "draft": false}
                    ]"#,
                )
            } else {
                ("HTTP/1.1 404 Not Found", r#"{"message": "Not Found"}"#)
            };

            let resp = format!(
                "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");

    let res = detect_latest_github_release_for_channel(
        &client,
        &origin,
        "test-owner/backport-repo",
        "stable",
    )
    .await
    .unwrap();
    assert_eq!(
        res.0, "2.0.0",
        "Stable release discovery must scan releases and select higher 2.0.0 over backport 1.9.4"
    );
    assert_eq!(res.1, "https://github.com/org/repo/releases/v2.0.0");

    server.abort();
}

#[tokio::test]
async fn test_github_release_discovery_fails_closed_on_page_2_failure() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let mut buf = vec![0; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]);

            let (status, body) = if req_str.contains("page=2") {
                (
                    "HTTP/1.1 500 Internal Server Error",
                    r#"{"message": "Server Error"}"#.to_string(),
                )
            } else {
                let mut items = Vec::new();
                for i in 1..=GITHUB_RELEASE_PAGE_SIZE {
                    items.push(format!(
                        r#"{{"tag_name": "v1.0.{}", "html_url": "https://github.com/org/repo/releases/v1.0.{}", "prerelease": false, "draft": false}}"#,
                        i, i
                    ));
                }
                ("HTTP/1.1 200 OK", format!("[{}]", items.join(",")))
            };

            let resp = format!(
                "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");
    let repo = "test-owner/fail-page2-repo";

    let res = detect_latest_github_release_for_channel(&client, &origin, repo, "stable").await;
    assert!(
        res.is_err(),
        "Must fail closed when page 2 returns HTTP 500"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("GitHub API returned 500") || err_msg.contains("on page 2"),
        "error: {err_msg}"
    );

    let cache_key = github_release_cache_key_for_channel(&origin, repo, "stable");
    let cached = github_release_cache().get(&cache_key).cloned();
    assert!(
        cached.is_none(),
        "Incomplete discovery result must NOT be cached!"
    );

    server.abort();
}

#[test]
fn test_canonical_update_source_key_and_persistence_scrub_secrets() {
    // 1. API base with userinfo and query parameters
    let dirty_api =
        "https://user:super_secret_pass@api.github.internal.com:443/v3?token=secret_query#anchor";
    let pkg_github = Package {
        name: "myapp".into(),
        update_source: "github".into(),
        update_repo: "myorg/myapp".into(),
        update_channel: "stable".into(),
        ..Default::default()
    };

    let key = canonical_update_source_key(dirty_api, &pkg_github);
    assert!(
        !key.contains("super_secret_pass"),
        "Key must not contain password: {key}"
    );
    assert!(
        !key.contains("user:"),
        "Key must not contain userinfo: {key}"
    );
    assert!(
        !key.contains("secret_query"),
        "Key must not contain query parameters: {key}"
    );
    assert_eq!(
        key,
        "github:https://api.github.internal.com/v3|myorg/myapp|stable"
    );

    // 2. Git remote URL with query parameters containing secret tokens
    let dirty_git_url =
        "https://git.example.com/team/App.git?token=secret123&access_token=xyz#frag";
    let pkg_git = Package {
        name: "myapp-git".into(),
        update_source: "git".into(),
        update_repo: "team/App".into(),
        update_repo_url: dirty_git_url.into(),
        update_channel: "stable".into(),
        ..Default::default()
    };

    let git_key = canonical_update_source_key("", &pkg_git);
    assert!(
        !git_key.contains("secret123"),
        "Git source key must not contain token: {git_key}"
    );
    assert!(
        !git_key.contains("access_token"),
        "Git source key must not contain access_token: {git_key}"
    );

    let disp_git = sanitize_git_remote_url_for_display(dirty_git_url);
    assert_eq!(disp_git, "https://git.example.com/team/App.git");
    assert!(!disp_git.contains("secret123"));
    assert!(!disp_git.contains("access_token"));

    // 3. Test persist_package_update_record sanitizes source_key, latest_version, installed_version
    let dirty_record = PackageUpdateRecord {
        package_id: "test-scrub-pkg".into(),
        installed: true,
        installed_version: "1.0.0-token=secret_in_version".into(),
        latest_version: "2.0.0-password=secret_in_latest".into(),
        update_available: true,
        checked_at: "2026-11-09T00:00:00Z".into(),
        release_url: "https://git.example.com/repo.git?secret=leak".into(),
        error: "curl -u admin:super_secret_curl https://example.com".into(),
        source_key: "github:https://api.github.com|myorg/myapp|stable?token=secret_in_key".into(),
    };

    persist_package_update_record(&dirty_record);
    if let Ok(conn) = af_db::get_conn() {
        let mut stmt = conn.prepare("SELECT installed_version, latest_version, update_url, last_error, source_key FROM app_updates WHERE package_name = ?1").unwrap();
        let mut rows = stmt.query(params!["test-scrub-pkg"]).unwrap();
        if let Some(row) = rows.next().unwrap() {
            let saved_inst: String = row.get(0).unwrap();
            let saved_latest: String = row.get(1).unwrap();
            let saved_url: String = row.get(2).unwrap();
            let saved_err: String = row.get(3).unwrap();
            let saved_key: String = row.get(4).unwrap();

            assert!(
                !saved_inst.contains("secret_in_version"),
                "installed_version must redact secrets"
            );
            assert!(
                !saved_latest.contains("secret_in_latest"),
                "latest_version must redact secrets"
            );
            assert!(
                !saved_url.contains("leak"),
                "update_url must redact secrets"
            );
            assert!(
                !saved_err.contains("super_secret_curl"),
                "last_error must redact curl user credentials"
            );
            assert!(
                !saved_key.contains("secret_in_key"),
                "source_key must redact secrets"
            );
        }
    }
}

#[test]
fn test_strict_semver_prerelease_rules_for_git_sources() {
    for src in &["github", "github_release", "git", "git_tags"] {
        // Numeric prerelease / hyphen after SemVer:
        assert!(
            !tag_allowed_by_channel_for_source("1.2.3-1", "stable", src),
            "Source {src} must reject 1.2.3-1 on stable"
        );
        assert!(
            !tag_allowed_by_channel_for_source("1.2.3-debug.1", "stable", src),
            "Source {src} must reject 1.2.3-debug.1 on stable"
        );
        assert!(
            !tag_allowed_by_channel_for_source("1.2.3-ubuntu1", "stable", src),
            "Source {src} must reject 1.2.3-ubuntu1 on stable"
        );
        assert!(
            !tag_allowed_by_channel_for_source("1.2.3-deb11u1", "stable", src),
            "Source {src} must reject 1.2.3-deb11u1 on stable"
        );
        assert!(
            tag_allowed_by_channel_for_source("1.2.3", "stable", src),
            "Source {src} must allow 1.2.3 on stable"
        );
    }
}

#[tokio::test]
async fn test_wave19_audit_findings_workers() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Finding 1: detect_latest_github_release_for_channel fails closed when 10 pages exceeded
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let mut buf = vec![0; 4096];
            let _ = socket.read(&mut buf).await.unwrap_or(0);

            let mut items = Vec::new();
            for i in 1..=GITHUB_RELEASE_PAGE_SIZE {
                items.push(format!(
                    r#"{{"tag_name": "v1.0.{}", "html_url": "https://github.com/org/repo/releases/v1.0.{}", "prerelease": false, "draft": false}}"#,
                    i, i
                ));
            }
            let body = format!("[{}]", items.join(","));
            let next_link = format!("<http://{addr}/repos/test-owner/overflow-repo/releases?per_page=100&page=99>; rel=\"next\"");
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nLink: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                next_link,
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");
    let res = detect_latest_github_release_for_channel(
        &client,
        &origin,
        "test-owner/overflow-repo",
        "stable",
    )
    .await;
    assert!(
        res.is_err(),
        "Must fail closed when release pagination exceeds MAX_RELEASE_PAGES without exhaustion"
    );
    let err_str = res.err().unwrap().to_string();
    assert!(
        err_str.contains("GitHub release pagination exceeded maximum page limit (10) for 'test-owner/overflow-repo'; refusing to cache incomplete release set"),
        "Error message mismatch: {err_str}"
    );

    let cache_key =
        github_release_cache_key_for_channel(&origin, "test-owner/overflow-repo", "stable");
    assert!(
        GITHUB_RELEASE_CACHE
            .lock()
            .unwrap()
            .get(&cache_key)
            .is_none(),
        "Incomplete release scan must not be cached"
    );
    server.abort();

    // Finding 2: sanitize_api_base_for_source_key preserves path case
    assert_eq!(
        sanitize_api_base_for_source_key("https://Git.Example.com/TeamA/api/"),
        "https://git.example.com/TeamA/api"
    );
    assert_eq!(
        sanitize_api_base_for_source_key("https://Git.Example.com/TeamA/api?token=secret#frag"),
        "https://git.example.com/TeamA/api"
    );
    // Fallback when URL parse fails preserves path case and hashes query
    let fallback_input = "invalid url ://Git.Example.com/TeamA/api?foo=bar#frag";
    assert_eq!(
        sanitize_api_base_for_source_key(fallback_input),
        format!(
            "invalid url ://git.example.com/TeamA/api?q#{}",
            sha256_hex_12(b"foo=bar")
        )
    );

    // Finding 4: sanitize_git_remote_url_for_display and normalize_git_remote_url_preserve_path_case
    assert_eq!(
        sanitize_git_remote_url_for_display("git@github.com:Org/Repo.git?token=secret#readme"),
        "ssh://git@github.com/Org/Repo.git"
    );
    assert_eq!(
        normalize_git_remote_url_preserve_path_case(
            "git@github.com:Org/Repo.git?token=secret#readme"
        ),
        format!(
            "ssh://git@github.com/Org/Repo?q#{}",
            sha256_hex_12(b"token=secret")
        )
    );

    // Finding 3: persist_package_update_record / sanitize_source_key_for_persistence preserves ssh:// and cred#...
    let canonical_ssh_key = "git-repo:ssh://Deploy@git.example.com/Team/App.git#main";
    let canonical_cred_key = "git-repo:https://cred#0123456789ab@github.com/org/repo.git#main";
    assert_eq!(
        sanitize_source_key_for_persistence(canonical_ssh_key),
        canonical_ssh_key
    );
    assert_eq!(
        sanitize_source_key_for_persistence(canonical_cred_key),
        canonical_cred_key
    );
    assert_eq!(
        af_release::lifecycle::sanitize_persisted_lifecycle_text(canonical_ssh_key),
        canonical_ssh_key
    );

    // Raw credentials in unnormalized source keys are scrubbed
    let dirty_ssh_key = "git-repo:ssh://Deploy:secretpass@git.example.com/Team/App.git#main";
    let cleaned_ssh = sanitize_source_key_for_persistence(dirty_ssh_key);
    assert!(!cleaned_ssh.contains("secretpass"));
    assert!(cleaned_ssh.contains("cred#"));

    // Test persist_package_update_record preserves canonical ssh and cred keys
    let rec = PackageUpdateRecord {
        package_id: "test-ssh-key-pkg".into(),
        source_key: canonical_ssh_key.into(),
        latest_version: "1.0.0".into(),
        installed_version: "1.0.0".into(),
        release_url: "ssh://Deploy@git.example.com/Team/App.git".into(),
        ..Default::default()
    };
    persist_package_update_record(&rec);
    if let Ok(conn) = af_db::get_conn() {
        let saved_key: String = conn
            .query_row(
                "SELECT source_key FROM app_updates WHERE package_name = ?1",
                params!["test-ssh-key-pkg"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            saved_key, canonical_ssh_key,
            "Persisted source_key must match canonical SSH key"
        );
    }

    // Finding 7: compare_versions and compare_versions_for_source with 7+ digit tags
    assert_eq!(
        compare_versions("10000000", "9000000"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_versions("v10000000", "v9000000"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_versions_for_source("10000000", "9000000", "git"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_versions_for_source("v10000000", "v9000000", "git"),
        std::cmp::Ordering::Greater
    );
    assert!(is_newer_version_scalar_for_source(
        "9000000", "10000000", "git"
    ));
    assert!(!is_newer_version_scalar_for_source(
        "10000000", "9000000", "git"
    ));
}

#[test]
fn test_wave20_builder_b_regressions() {
    // 1. API base cache key and rate limit isolation across base paths (/TeamA/api/v3 vs /TeamB/api/v3)
    let key_a = github_release_cache_key_for_channel(
        "https://ghe.internal/TeamA/api/v3",
        "myorg/repo",
        "stable",
    );
    let key_b = github_release_cache_key_for_channel(
        "https://ghe.internal/TeamB/api/v3",
        "myorg/repo",
        "stable",
    );
    assert_ne!(
        key_a, key_b,
        "Cache keys for /TeamA/api/v3 and /TeamB/api/v3 must be distinct!"
    );
    assert!(key_a.contains("teama/api/v3") || key_a.contains("TeamA/api/v3"));
    assert!(key_b.contains("teamb/api/v3") || key_b.contains("TeamB/api/v3"));

    clear_github_rate_limits();
    let base_a = "https://ghe.internal/TeamA/api/v3";
    let base_b = "https://ghe.internal/TeamB/api/v3";
    record_github_api_rate_limit(base_a, "core", Duration::from_secs(60));
    assert!(is_github_rate_limited_for_origin(base_a, "core"));
    assert!(github_rate_limit_remaining_secs_for_origin(base_a, "core") > 0);
    assert!(!is_github_rate_limited_for_origin(base_b, "core"));
    assert_eq!(
        github_rate_limit_remaining_secs_for_origin(base_b, "core"),
        0
    );
    clear_github_rate_limits();

    // 2. Query-bearing Git source keys (?q#<12-hex>) idempotence on persistence
    let q_key_bare = "git-repo:https://github.com/org/repo.git?q#0123456789ab";
    assert_eq!(sanitize_source_key_for_persistence(q_key_bare), q_key_bare);
    let q_key_branch = "git-repo:https://github.com/org/repo.git?q#0123456789ab#main";
    assert_eq!(
        sanitize_source_key_for_persistence(q_key_branch),
        q_key_branch
    );
    // Repeated persistence calls are strictly idempotent
    assert_eq!(
        sanitize_source_key_for_persistence(&sanitize_source_key_for_persistence(q_key_branch)),
        q_key_branch
    );

    // 3. Cross-repo and off-origin pagination Link validation fail-closed behavior
    let api_base = "https://api.github.com";
    let ghe_base = "https://ghe.internal/api/v3";
    // Same repo, same origin -> allowed
    assert!(validate_github_releases_next_url(
        "https://api.github.com/repos/org/repo/releases?per_page=100&page=2",
        api_base,
        "org/repo"
    ));
    assert!(validate_github_releases_next_url(
        "https://ghe.internal/api/v3/repos/org/repo/releases?per_page=100&page=2",
        ghe_base,
        "org/repo"
    ));
    // Cross-repository -> rejected
    assert!(!validate_github_releases_next_url(
        "https://api.github.com/repos/attacker/evil/releases?per_page=100&page=2",
        api_base,
        "org/repo"
    ));
    assert!(!validate_github_releases_next_url(
        "https://ghe.internal/api/v3/repos/other/repo/releases?per_page=100&page=2",
        ghe_base,
        "org/repo"
    ));
    // Off-origin -> rejected
    assert!(!validate_github_releases_next_url(
        "https://evil.attacker.com/repos/org/repo/releases?per_page=100&page=2",
        api_base,
        "org/repo"
    ));

    // 4. Numeric short Git commit IDs recognized and distinct
    let num_sha1 = "9999999";
    let full_sha = "123456abcdef0123456789abcdef0123456789a";
    let num_sha2 = "1234567";

    // "9999999" vs "123456abcdef..." on "git"
    assert!(is_newer_version_scalar_for_source(
        num_sha1, full_sha, "git"
    ));
    assert!(is_newer_version_scalar_for_source(
        full_sha, num_sha1, "git"
    ));

    // "9999999" vs "1234567" on "git"
    assert!(is_newer_version_scalar_for_source(
        num_sha1, num_sha2, "git"
    ));
    assert!(is_newer_version_scalar_for_source(
        num_sha2, num_sha1, "git"
    ));

    // Prefix match is NOT an update
    let full_matching_9 = "9999999abcdef0123456789abcdef0123456789a";
    assert!(!is_newer_version_scalar_for_source(
        num_sha1,
        full_matching_9,
        "git"
    ));
    assert!(!is_newer_version_scalar_for_source(
        full_matching_9,
        num_sha1,
        "git"
    ));

    // Synthetic commit version rejects pure-numeric short SHA (which are SemVer prereleases)
    assert_eq!(parse_synthetic_commit_version("0.1.0-1234567"), None);
    assert_eq!(
        parse_synthetic_commit_version("0.1.0-6e840ac"),
        Some(("0.1.0", "6e840ac"))
    );
}

#[test]
fn test_wave21_builder_b_regressions() {
    // Finding 3: validate_github_releases_next_url path sensitivity
    let configured_base = "https://git.example.com/TeamA/api/v3";
    // Case mismatch on base path prefix -> rejected
    assert!(!validate_github_releases_next_url(
        "https://git.example.com/teama/api/v3/repos/owner/repo/releases?page=2",
        configured_base,
        "owner/repo"
    ));
    // Case mismatch on repo slug -> accepted (GitHub owner/repo slugs are case-insensitive)
    assert!(validate_github_releases_next_url(
        "https://git.example.com/TeamA/api/v3/repos/Owner/Repo/releases?page=2",
        configured_base,
        "owner/repo"
    ));
    assert!(validate_github_releases_next_url(
        "https://git.example.com/TeamA/api/v3/repos/owner/repo/releases?page=2",
        configured_base,
        "Owner/Repo"
    ));

    // Finding 8: Numeric SemVer prereleases
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-1234567",
        "2.0.0-1234567",
        ""
    ));
    assert!(!is_newer_version_scalar_for_source(
        "2.0.0-1234567",
        "1.0.0-1234567",
        ""
    ));
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-1234567",
        "2.0.0-1234567",
        "false"
    ));
    assert!(!is_newer_version_scalar_for_source(
        "2.0.0-1234567",
        "1.0.0-1234567",
        "false"
    ));
    assert!(is_newer_version_scalar("1.0.0-1234567", "2.0.0-1234567"));
    assert!(!is_newer_version_scalar("2.0.0-1234567", "1.0.0-1234567"));

    // Finding 8: Synthetic commit versions comparing differing version bases
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-6e840ac",
        "2.0.0-6e840ac",
        ""
    ));
    assert!(!is_newer_version_scalar_for_source(
        "2.0.0-6e840ac",
        "1.0.0-deadbeef",
        ""
    ));
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-6e840ac",
        "2.0.0-6e840ac",
        "false"
    ));
    assert!(!is_newer_version_scalar_for_source(
        "2.0.0-6e840ac",
        "1.0.0-deadbeef",
        "false"
    ));
    assert!(is_newer_version_scalar("1.0.0-6e840ac", "2.0.0-6e840ac"));
    assert!(!is_newer_version_scalar("2.0.0-6e840ac", "1.0.0-deadbeef"));

    // Finding 8: Same version base compares commit SHAs on git provenance
    assert!(!is_newer_version_scalar_for_source(
        "1.0.0-6e840ac",
        "1.0.0-6e840ac",
        "git"
    ));
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-6e840ac",
        "1.0.0-deadbeef",
        "git"
    ));
    assert!(!is_newer_version_scalar_for_source(
        "1.0.0-abcdef1",
        "1.0.0-abcdef0",
        "github"
    ));
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-abcdef0",
        "1.0.0-abcdef1",
        "github"
    ));
    assert!(!is_newer_version_scalar_for_source(
        "1.0.0-abcdef1",
        "1.0.0-abcdef0",
        ""
    ));
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-abcdef0",
        "1.0.0-abcdef1",
        ""
    ));
}

#[tokio::test]
async fn test_wave22_filebot_version_detection_and_update_check() {
    let temp_dir = std::env::temp_dir().join(format!("af-test-filebot-{}", uuid::Uuid::new_v4()));
    let opt_filebot_node = temp_dir.join("opt/filebot-node");
    let server_dir = opt_filebot_node.join("server");
    let opt_filebot = temp_dir.join("opt/filebot");

    std::fs::create_dir_all(&server_dir).unwrap();
    std::fs::create_dir_all(&opt_filebot).unwrap();

    // Node component files
    std::fs::write(server_dir.join("app.js"), "console.log('filebot-node');").unwrap();
    std::fs::write(
        server_dir.join("package.json"),
        r#"{"name":"filebot-node","version":"0.4.7.0"}"#,
    )
    .unwrap();
    std::fs::write(opt_filebot_node.join(".af-version"), "0.4.7.0").unwrap();

    // Separate CLI files in /opt/filebot with version 5.1.6
    std::fs::write(opt_filebot.join("filebot.sh"), "#!/bin/sh\nexit 0").unwrap();
    std::fs::write(opt_filebot.join(".af-version"), "5.1.6").unwrap();

    let install_dir = temp_dir.join("install");
    std::fs::create_dir_all(&install_dir).unwrap();
    std::fs::write(install_dir.join(".filebot.lock"), "").unwrap();

    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let pkg = Package {
        name: "filebot".into(),
        lock_file: "/install/.filebot.lock".into(),
        update_source: "github".into(),
        update_repo: "filebot/filebot-node".into(),
        version_command: vec![
            "python3".into(),
            "-c".into(),
            "import json, os, pathlib, sys; root = pathlib.Path((os.environ.get('AETHERFLOW_FS_ROOT') or os.environ.get('AETHERFLOW_INSTALL_ROOT') or '/').strip() or '/'); base = root / 'opt/filebot-node'; sys.exit(1) if not (base / 'server/app.js').is_file() else None; vers = [json.loads(p.read_text(encoding='utf-8')).get('version', '').strip() for p in (base / 'package.json', base / 'server/package.json', base / 'client/package.json') if p.is_file()]; v = next((x for x in vers if x), ''); sys.exit(1) if not v else print(v)".into(),
        ],
        ..Default::default()
    };

    // 1. Receipt verification: must find 0.4.7.0 and NEVER 5.1.6
    let receipt = read_af_version_receipt(&pkg);
    assert_eq!(receipt, Some("0.4.7.0".to_string()));

    // 2. Runtime evidence verification: app.js satisfies runtime evidence
    assert!(has_independent_runtime_evidence(&pkg));

    // 3. Strict installed version probe detects 0.4.7.0
    let installed = probe_installed_package_version_strict(&pkg).await;
    assert!(
        installed.is_ok(),
        "Failed to probe installed version: {:?}",
        installed.err()
    );
    assert_eq!(installed.unwrap(), "0.4.7.0");

    // 4. Live version command executes python probe with active fs_root
    let live_ver = run_live_version_command(&pkg, Duration::from_secs(5)).await;
    assert!(
        live_ver.is_ok(),
        "Live version probe failed: {:?}",
        live_ver.err()
    );
    assert_eq!(live_ver.unwrap().trim(), "0.4.7.0");

    // 5. Update availability: 0.4.8.1 is newer than 0.4.7.0
    assert!(is_remote_version_newer_for_source(
        "0.4.7.0", "0.4.8.1", "github"
    ));

    // 6. Certification match for 0.4.8.1 target
    assert!(af_release::lifecycle::versions_match_target(
        "0.4.8.1", "0.4.8.1"
    ));

    // 7. Update to 0.4.8.1
    std::fs::write(
        server_dir.join("package.json"),
        r#"{"name":"filebot-node","version":"0.4.8.1"}"#,
    )
    .unwrap();
    std::fs::write(opt_filebot_node.join(".af-version"), "0.4.8.1").unwrap();

    let updated_installed = probe_installed_package_version_strict(&pkg).await.unwrap();
    assert_eq!(updated_installed, "0.4.8.1");
    assert!(!is_remote_version_newer_for_source(
        "0.4.8.1", "0.4.8.1", "github"
    ));

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave22_semver_prerelease_provenance_and_numeric() {
    // GitHub release source: SemVer ordering is enforced (downgrades are false)
    assert!(!is_newer_version_scalar_for_source(
        "1.0.0-abcdef1",
        "1.0.0-abcdef0",
        "github"
    ));
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-abcdef0",
        "1.0.0-abcdef1",
        "github"
    ));
    assert!(!is_newer_version_scalar_for_source(
        "1.0.0-abcdef1",
        "1.0.0-abcdef0",
        ""
    ));
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-abcdef0",
        "1.0.0-abcdef1",
        ""
    ));

    // Explicit git source: different commit hashes are treated as newer
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-abcdef1",
        "1.0.0-abcdef0",
        "git"
    ));

    // 40-digit numeric prereleases: must not be treated as commit SHAs and must not overflow
    let num40_hi = "1.0.0-1234567890123456789012345678901234567899";
    let num40_lo = "1.0.0-1234567890123456789012345678901234567898";
    assert!(!is_newer_version_scalar_for_source(
        num40_hi, num40_lo, "github"
    ));
    assert!(is_newer_version_scalar_for_source(
        num40_lo, num40_hi, "github"
    ));
    assert!(!is_newer_version_scalar_for_source(num40_hi, num40_lo, ""));
    assert!(is_newer_version_scalar_for_source(num40_lo, num40_hi, ""));

    // 39-digit vs 40-digit numeric prereleases: numerical comparison
    let num39 = "1.0.0-999999999999999999999999999999999999999";
    let num40 = "1.0.0-1000000000000000000000000000000000000000";
    assert!(is_newer_version_scalar_for_source(num39, num40, ""));
    assert!(!is_newer_version_scalar_for_source(num40, num39, ""));

    // is_git_commit_sha rejects pure decimal strings of length 40
    assert!(!is_git_commit_sha(
        "1234567890123456789012345678901234567890"
    ));
    assert!(is_git_commit_sha(
        "123456789012345678901234567890123456789a"
    ));
    assert!(!is_git_commit_sha("1234567"));
    assert!(is_git_commit_sha("6e840ac"));

    // parse_synthetic_commit_version rejects pure numeric suffixes
    assert_eq!(
        parse_synthetic_commit_version("1.0.0-1234567890123456789012345678901234567890"),
        None
    );
    assert_eq!(parse_synthetic_commit_version("1.0.0-1234567"), None);
    assert_eq!(
        parse_synthetic_commit_version("1.0.0-6e840ac"),
        Some(("1.0.0", "6e840ac"))
    );
}

#[tokio::test]
async fn test_github_package_with_git_checkout_uses_version_command_not_git_head() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let temp_dir = std::env::temp_dir().join(format!("af-test-gh-git-{}", uuid::Uuid::new_v4()));
    let opt_dir = temp_dir.join("opt/demo-gh");
    std::fs::create_dir_all(&opt_dir).unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(&opt_dir)
        .status()
        .unwrap()
        .success());
    assert!(std::process::Command::new("git")
        .args(["config", "user.email", "test@example.com"])
        .current_dir(&opt_dir)
        .status()
        .unwrap()
        .success());
    assert!(std::process::Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(&opt_dir)
        .status()
        .unwrap()
        .success());
    std::fs::write(opt_dir.join(".af-version"), "1.4.2").unwrap();
    assert!(std::process::Command::new("git")
        .args(["add", ".af-version"])
        .current_dir(&opt_dir)
        .status()
        .unwrap()
        .success());
    assert!(std::process::Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(&opt_dir)
        .status()
        .unwrap()
        .success());

    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);
    let pkg = Package {
        name: "demo-gh".into(),
        update_source: "github".into(),
        version_command: vec!["printf".into(), "%s".into(), "1.4.2".into()],
        ..Default::default()
    };
    let res = probe_installed_package_version_strict(&pkg).await.unwrap();
    assert_eq!(res, "1.4.2");

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_apt_receipt_matches_live_debian_revision() {
    assert!(apt_receipt_matches_live_debian_revision(
        "apt",
        "1.9.1",
        "1.9.1-2+deb13u1"
    ));
    assert!(apt_receipt_matches_live_debian_revision(
        "apt",
        "1.9.1",
        "1:1.9.1-1+b1"
    ));
    assert!(!apt_receipt_matches_live_debian_revision(
        "apt", "1.9.1", "1.9.2-1"
    ));
    assert!(!apt_receipt_matches_live_debian_revision(
        "apt",
        "1.9.1",
        "1.9.1-rc1"
    ));
    assert!(!apt_receipt_matches_live_debian_revision(
        "apt",
        "1.9.1",
        "1.9.1~rc1-1"
    ));
    assert!(!apt_receipt_matches_live_debian_revision(
        "github",
        "1.9.1",
        "1.9.1-2+deb13u1"
    ));
}

#[tokio::test]
async fn test_mediaflow_progress_broadcast_and_empty_output_preserves_source() {
    let name =
        "workers::tests::test_mediaflow_progress_broadcast_and_empty_output_preserves_source";
    if std::env::var("AF_MEDIAFLOW_TEST_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_MEDIAFLOW_TEST_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let root = env::temp_dir().join(format!("af-mediaflow-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("media")).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", root.join("media"));
    af_db::init_db().unwrap();

    let src_file = root.join("media/movie.mp4");
    fs::write(&src_file, b"original-video-bytes").unwrap();

    // Fake ffmpeg that strips optional file: prefix, exits 0, and writes a 0-byte output file
    let fake_ffmpeg = root.join("bin/ffmpeg");
    fs::write(
        &fake_ffmpeg,
        "#!/bin/sh\nout=\"\"\nfor arg in \"$@\"; do out=\"$arg\"; done\nout=\"${out#file:}\"\n: > \"$out\"\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&fake_ffmpeg, fs::Permissions::from_mode(0o755)).unwrap();
    let fake_ffprobe = root.join("bin/ffprobe");
    fs::write(&fake_ffprobe, "#!/bin/sh\necho 10.0\n").unwrap();
    fs::set_permissions(&fake_ffprobe, fs::Permissions::from_mode(0o755)).unwrap();
    env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            env::var("PATH").unwrap()
        ),
    );

    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, None, &src_file);
    }

    let mut rx = subscribe_mediaflow_progress();
    assert!(process_next_mediaflow_job().await);

    let mut events = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        events.push(serde_json::from_str::<serde_json::Value>(&msg).unwrap());
    }
    assert!(events.iter().any(|e| e["status"] == "running"));
    assert!(events.iter().any(|e| e["status"] == "failed"));

    // Source file must remain untouched!
    assert_eq!(fs::read(&src_file).unwrap(), b"original-video-bytes");
    let status: String = af_db::get_conn()
        .unwrap()
        .query_row("SELECT status FROM mediaflow_queue LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(status, "FAILED");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_smart_backup_honors_persisted_next_run_and_acquires_lock() {
    let name = "workers::tests::test_smart_backup_honors_persisted_next_run_and_acquires_lock";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }
    let root = env::temp_dir().join(format!("af-smart-backup-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AETHERFLOW_BACKUP_DIR", root.join("backups"));
    af_db::init_db().unwrap();
    ensure_smart_backup_columns();

    // Future backup_next_run_at must prevent running prematurely
    let future = (Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "UPDATE settings SET smart_backup_enabled = 'true', smart_backup_hour = ?1, smart_backup_last_run = '', backup_schedule_mode = 'smart', backup_next_run_at = ?2 WHERE id = 1",
            params![Utc::now().hour() as i64, future],
        )
        .unwrap();
    }
    check_and_run_smart_backup();
    assert!(!root.join("backups").exists());

    // Past backup_next_run_at must run and create a verified snapshot
    let past = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "UPDATE settings SET backup_next_run_at = ?1 WHERE id = 1",
            params![past],
        )
        .unwrap();
    }
    check_and_run_smart_backup();
    let backups: Vec<_> = fs::read_dir(root.join("backups"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("sqlite"))
        .collect();
    assert_eq!(backups.len(), 1);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_reconcile_mediaflow_startup_marks_stranded_processing_and_cleans_temps() {
    let name = "workers::tests::test_reconcile_mediaflow_startup_marks_stranded_processing_and_cleans_temps";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }
    let root = env::temp_dir().join(format!("af-mf-reconcile-{}", uuid::Uuid::new_v4()));
    let media = root.join("media");
    let trash = media.join(".mediaflow_trash");
    fs::create_dir_all(&trash).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", &media);
    env::set_var("MEDIAFLOW_TRASH_RETENTION_SECS", "0");
    af_db::init_db().unwrap();

    let movie = media.join("sample.mkv");
    fs::write(&movie, b"video").unwrap();
    let stale_tmp = media.join(".tmp_mediaflow_77.mkv");
    fs::write(&stale_tmp, b"partial").unwrap();
    let expired_trash = trash.join("77_old.mkv");
    fs::write(&expired_trash, b"trashed").unwrap();
    let expired_meta = trash.join("77_old.mkv.meta.json");
    fs::write(
        &expired_meta,
        serde_json::to_vec(&MediaflowTrashMeta {
            job_id: 77,
            trashed_at_unix: Utc::now().timestamp() - 3600,
            original_name: "old.mkv".to_string(),
        })
        .unwrap(),
    )
    .unwrap();
    let unverified_trash = trash.join("77_unverified.mkv");
    fs::write(&unverified_trash, b"keep-without-meta").unwrap();

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO mediaflow_queue (id, file_path, status) VALUES (77, ?1, 'PROCESSING')",
            params![movie.to_string_lossy().to_string()],
        )
        .unwrap();
    }

    reconcile_mediaflow_startup();

    let (status, err_log): (String, String) = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status, error_log FROM mediaflow_queue WHERE id = 77",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "FAILED");
    assert_eq!(err_log, "Interrupted by service restart");
    assert!(!stale_tmp.exists());
    assert!(!expired_trash.exists());
    assert!(!expired_meta.exists());
    assert!(
        unverified_trash.exists(),
        "trash entries lacking verified .meta.json must never be deleted"
    );
    assert!(movie.exists());

    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[tokio::test]
async fn test_mediaflow_mid_transcode_source_replacement_preserves_replacement_untouched() {
    let name = "workers::tests::test_mediaflow_mid_transcode_source_replacement_preserves_replacement_untouched";
    if std::env::var("AF_MEDIAFLOW_SWAP_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_MEDIAFLOW_SWAP_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root = env::temp_dir().join(format!("af-mf-swap-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("media")).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", root.join("media"));
    af_db::init_db().unwrap();

    let src_file = root.join("media/movie.mp4");
    fs::write(&src_file, b"original-v1-video-payload").unwrap();

    // Fake ffmpeg verifies pinned `/proc/self/fd/<fd>` input, atomically swaps `movie.mp4` mid-transcode
    // when AF_SWAP_TARGET is set, and writes transcoded bytes into the exclusive 0600 temp file.
    let fake_ffmpeg = root.join("bin/ffmpeg");
    fs::write(
        &fake_ffmpeg,
        "#!/bin/sh\nset -eu\nin_uri=\"\"\nout=\"\"\nprev=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"-i\" ]; then in_uri=\"$arg\"; fi\n  prev=\"$arg\"\n  out=\"$arg\"\ndone\nin_path=\"${in_uri#file:}\"\ncat \"$in_path\" > /dev/null\nif [ -n \"${AF_SWAP_TARGET:-}\" ]; then\n  printf 'upgraded-replacement-4k-remux' > \"${AF_SWAP_TARGET}.new\"\n  mv \"${AF_SWAP_TARGET}.new\" \"$AF_SWAP_TARGET\"\nfi\nout_path=\"${out#file:}\"\nprintf 'transcoded-hevc-stream-payload' > \"$out_path\"\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&fake_ffmpeg, fs::Permissions::from_mode(0o755)).unwrap();
    let fake_ffprobe = root.join("bin/ffprobe");
    fs::write(&fake_ffprobe, "#!/bin/sh\necho 12.0\n").unwrap();
    fs::set_permissions(&fake_ffprobe, fs::Permissions::from_mode(0o755)).unwrap();
    env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            env::var("PATH").unwrap()
        ),
    );
    env::set_var("AF_SWAP_TARGET", &src_file);

    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, Some(1), &src_file);
    }

    assert!(process_next_mediaflow_job().await);

    // 1. Replacement file MUST remain completely untouched and never moved into `.mediaflow_trash`!
    assert_eq!(
        fs::read(&src_file).unwrap(),
        b"upgraded-replacement-4k-remux"
    );
    assert!(!root.join("media/movie_hevc.mkv").exists());
    let trash_dir = root.join("media/.mediaflow_trash");
    if trash_dir.exists() {
        assert_eq!(fs::read_dir(&trash_dir).unwrap().count(), 0);
    }
    // No leftover `.tmp_mediaflow_*` files
    let media_entries: Vec<String> = fs::read_dir(root.join("media"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(media_entries, vec!["movie.mp4".to_string()]);

    let (status, err_log): (String, String) = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status, error_log FROM mediaflow_queue WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "FAILED");
    assert_eq!(err_log, MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG);

    // 2. Normal un-swapped job succeeds end-to-end with pinned dirfd + random 0600 temp file
    env::remove_var("AF_SWAP_TARGET");
    let src_ok = root.join("media/clean.mp4");
    fs::write(&src_ok, b"untouched-original-source").unwrap();
    let orig_ino = fs::symlink_metadata(&src_ok).unwrap().ino();
    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, Some(2), &src_ok);
    }
    assert!(process_next_mediaflow_job().await);
    assert!(!src_ok.exists());
    assert_eq!(
        fs::read(root.join("media/clean_hevc.mkv")).unwrap(),
        b"transcoded-hevc-stream-payload"
    );
    let trashed_ino = fs::symlink_metadata(root.join("media/.mediaflow_trash/2_clean.mp4"))
        .unwrap()
        .ino();
    assert_eq!(trashed_ino, orig_ino);

    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn test_heal_auto_approve_false_queues_deduplicated_action_and_notifies_all_admins() {
    use crate::inventory_regressions::{isolated, Fixture};
    let name = "workers::tests::test_heal_auto_approve_false_queues_deduplicated_action_and_notifies_all_admins";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    let db_path = fixture.root.join("heal-admins.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::remove_var("AF_HEAL_AUTO_APPROVE");
    af_db::init_db().unwrap();

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DELETE FROM users", []).unwrap();
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role) VALUES (10, 'admin_a', 'x', 'admin'), (20, 'admin_b', 'x', 'admin'), (30, 'viewer_c', 'x', 'user')",
            [],
        )
        .unwrap();
    }

    fixture.write_packages(&[Fixture::package("fixture", "systemd", "fixture-main")]);
    fixture.command(
        "systemctl",
        "printf '%s\\n' \"$*\" >> \"$AF_STATUS_CALLS\"\ncase \"$1 $2\" in 'is-active fixture-main') echo inactive; exit 3;; is-active*) echo active;; show*) printf 'LoadState=loaded\\nType=simple\\n';; *) exit 92;; esac\n",
    );

    let runtime = tokio::runtime::Runtime::new().unwrap();
    *HEAL_STATES.lock().unwrap() = HashMap::new();
    runtime.block_on(perform_heal_check());
    // Second tick must deduplicate pending action and avoid spamming notifications
    runtime.block_on(perform_heal_check());

    let conn = af_db::get_conn().unwrap();
    let pending_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pending_actions WHERE source = 'af-heal' AND action = 'systemctl restart fixture-main' AND status = 'pending'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending_count, 1);

    let mut notified_uids: Vec<i64> = Vec::new();
    let mut stmt = conn
        .prepare("SELECT user_id FROM notifications ORDER BY user_id ASC")
        .unwrap();
    for uid in stmt
        .query_map([], |r| r.get::<_, i64>(0))
        .unwrap()
        .flatten()
    {
        notified_uids.push(uid);
    }
    assert_eq!(notified_uids, vec![10, 20]);
}

#[cfg(unix)]
#[tokio::test]
async fn test_mediaflow_3yr_mtime_retention_sigpipe_large_stderr_0644_perms_and_intent_recovery() {
    let name = "workers::tests::test_mediaflow_3yr_mtime_retention_sigpipe_large_stderr_0644_perms_and_intent_recovery";
    if std::env::var("AF_MEDIAFLOW_P4_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_MEDIAFLOW_P4_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    let root = env::temp_dir().join(format!("af-mf-p4-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("media")).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", root.join("media"));
    // 7-day retention: 3-year-old source mtime MUST NOT cause immediate pruning!
    env::set_var("MEDIAFLOW_TRASH_RETENTION_SECS", "604800");
    af_db::init_db().unwrap();

    // Fake ffmpeg emits >192 KiB to stderr (proving no SIGPIPE after 64 KiB!) before writing output.
    let fake_ffmpeg = root.join("bin/ffmpeg");
    fs::write(
        &fake_ffmpeg,
        "#!/bin/sh\nset -eu\nout=\"\"\nfor arg in \"$@\"; do out=\"$arg\"; done\nout_path=\"${out#file:}\"\ndd if=/dev/zero bs=1024 count=200 2>/dev/null | tr '\\0' 'E' >&2\nprintf 'END_OF_LARGE_STDERR\\n' >&2\nprintf 'hevc-published-payload-bytes' > \"$out_path\"\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&fake_ffmpeg, fs::Permissions::from_mode(0o755)).unwrap();
    let fake_ffprobe = root.join("bin/ffprobe");
    fs::write(&fake_ffprobe, "#!/bin/sh\necho 10.0\n").unwrap();
    fs::set_permissions(&fake_ffprobe, fs::Permissions::from_mode(0o755)).unwrap();
    env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            env::var("PATH").unwrap()
        ),
    );

    // Source media file with 3-year-old mtime and restrictive 0600 permissions
    let src_vintage = root.join("media/classic_film.mp4");
    fs::write(&src_vintage, b"three-year-old-h264-original").unwrap();
    fs::set_permissions(&src_vintage, fs::Permissions::from_mode(0o600)).unwrap();
    let three_years_ago = Utc::now().timestamp() - (3 * 365 * 86_400);
    {
        let c_src = CString::new(src_vintage.as_os_str().as_bytes()).unwrap();
        let ts = libc::timespec {
            tv_sec: three_years_ago as libc::time_t,
            tv_nsec: 0,
        };
        let times = [ts, ts];
        assert_eq!(
            unsafe { libc::utimensat(libc::AT_FDCWD, c_src.as_ptr(), times.as_ptr(), 0) },
            0
        );
    }

    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, Some(10), &src_vintage);
    }

    assert!(process_next_mediaflow_job().await);

    // 1. Published output exists, has mode 0644 (never 0600, never exec/suid), and job is COMPLETED
    let published = root.join("media/classic_film_hevc.mkv");
    assert!(published.is_file());
    let pub_mode = fs::symlink_metadata(&published)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(pub_mode, 0o644);
    assert_eq!(compute_published_media_mode(0o4755), 0o644);
    assert_eq!(compute_published_media_mode(0o0664), 0o664);

    // 2. Trashed original + .meta.json BOTH survive post-publish prune AND survive process restart!
    let trashed = root.join("media/.mediaflow_trash/10_classic_film.mp4");
    let trashed_meta = root.join("media/.mediaflow_trash/10_classic_film.mp4.meta.json");
    assert!(
        trashed.is_file(),
        "3-year-old media original must NOT be pruned immediately after transcode!"
    );
    assert!(trashed_meta.is_file());
    let meta_mode = fs::symlink_metadata(&trashed_meta)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(meta_mode, 0o600);
    assert!(!root
        .join("media/.mediaflow_trash/.publish_intent_10.json")
        .exists());

    reconcile_mediaflow_startup();
    assert!(
        trashed.is_file(),
        "3-year-old media original must survive startup reconciliation until retention genuinely expires!"
    );

    // Once trashed_at_unix genuinely exceeds retention, both media and .meta.json are pruned cleanly
    fs::write(
        &trashed_meta,
        serde_json::to_vec(&MediaflowTrashMeta {
            job_id: 10,
            trashed_at_unix: Utc::now().timestamp() - 700_000,
            original_name: "classic_film.mp4".to_string(),
        })
        .unwrap(),
    )
    .unwrap();
    prune_mediaflow_trash_dir(
        &root.join("media/.mediaflow_trash"),
        mediaflow_trash_retention(),
    );
    assert!(!trashed.exists());
    assert!(!trashed_meta.exists());

    // 3. Startup reconciliation recovers PROCESSING job to COMPLETED when durable publish_intent + files exist
    let recovered_orig = root.join("media/crash_window.mp4");
    let recovered_pub = root.join("media/crash_window_hevc.mkv");
    let recovered_trash = root.join("media/.mediaflow_trash/11_crash_window.mp4");
    let intent_file = root.join("media/.mediaflow_trash/.publish_intent_11.json");
    fs::write(&recovered_pub, b"completed-before-sqlite-crash").unwrap();
    fs::write(&recovered_trash, b"original-in-trash").unwrap();
    // Legacy publish intent JSON without `source_fingerprint` must still recover cleanly.
    fs::write(
        &intent_file,
        serde_json::to_vec(&serde_json::json!({
            "job_id": 11,
            "published_path": recovered_pub.to_string_lossy().to_string(),
            "trash_entry_name": "11_crash_window.mp4",
            "new_size": 29
        }))
        .unwrap(),
    )
    .unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO mediaflow_queue (id, file_path, original_codec, original_size, status) VALUES (11, ?1, 'h264', 17, 'PROCESSING')",
            params![recovered_orig.to_string_lossy().to_string()],
        )
        .unwrap();
    }

    reconcile_mediaflow_startup();

    let (rec_status, rec_path, rec_size): (String, String, i64) = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status, file_path, new_size FROM mediaflow_queue WHERE id = 11",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(rec_status, "COMPLETED");
    assert_eq!(rec_path, recovered_pub.to_string_lossy());
    assert_eq!(rec_size, 29);
    assert!(!intent_file.exists());
    assert!(root
        .join("media/.mediaflow_trash/11_crash_window.mp4.meta.json")
        .is_file());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_smart_backup_optimal_window_telemetry_and_utc_hour_alignment() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE metrics_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            cpu_avg REAL DEFAULT 0,
            mem_used_gb REAL DEFAULT 0,
            mem_total_gb REAL DEFAULT 0
        );",
    )
    .unwrap();

    // < 24 samples returns honest heuristic_default with 0.35 confidence at 03:00 UTC
    for h in 0..5 {
        conn.execute(
            "INSERT INTO metrics_history (timestamp, cpu_avg, mem_used_gb, mem_total_gb) VALUES (?1, 40.0, 8.0, 16.0)",
            params![format!("2026-11-18T{h:02}:15:00Z")],
        )
        .unwrap();
    }
    let heuristic = analyze_optimal_backup_window(&conn);
    assert_eq!(heuristic.source, "heuristic_default");
    assert_eq!(heuristic.optimal_hour, 3);
    assert!((heuristic.confidence - 0.35).abs() < 1e-6);

    // >= 24 samples across 24 UTC hours picks lowest combined CPU + memory load hour (05:00 UTC)
    conn.execute("DELETE FROM metrics_history", []).unwrap();
    for h in 0..24 {
        let (cpu, mem_used) = if h == 5 {
            (4.0, 2.0) // 4% CPU, 12.5% RAM -> 8.25% combined
        } else {
            (65.0, 12.0) // 65% CPU, 75% RAM -> 70% combined
        };
        for m in [10, 40] {
            conn.execute(
                "INSERT INTO metrics_history (timestamp, cpu_avg, mem_used_gb, mem_total_gb) VALUES (?1, ?2, ?3, 16.0)",
                params![format!("2026-11-19T{h:02}:{m:02}:00Z"), cpu, mem_used],
            )
            .unwrap();
        }
    }
    let measured = analyze_optimal_backup_window(&conn);
    assert_eq!(measured.source, "metrics_history");
    assert_eq!(measured.optimal_hour, 5);
    assert_eq!(measured.hour, 5);
    assert!(measured.confidence >= 0.75);

    // Next backup alignment: >= 1h in the future, aligned to optimal_hour:00:00 UTC
    let now_before = chrono::DateTime::parse_from_rfc3339("2026-11-20T03:30:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let next_same_day = compute_next_optimal_backup_at(now_before, 5);
    assert_eq!(next_same_day.to_rfc3339(), "2026-11-20T05:00:00+00:00");

    // Within 1h of 05:00 UTC (04:30 UTC) advances to next day's 05:00:00 UTC
    let now_too_close = chrono::DateTime::parse_from_rfc3339("2026-11-20T04:30:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let next_tomorrow = compute_next_optimal_backup_at(now_too_close, 5);
    assert_eq!(next_tomorrow.to_rfc3339(), "2026-11-21T05:00:00+00:00");
}

fn insert_pinned_mediaflow_approved(
    conn: &rusqlite::Connection,
    id: Option<i64>,
    file_path: &Path,
) {
    let pinned = open_and_pin_mediaflow_source(&file_path.to_string_lossy()).unwrap();
    let ident = &pinned.identity;
    let size = i64::try_from(ident.size).unwrap();
    if let Some(job_id) = id {
        conn.execute(
            "INSERT INTO mediaflow_queue (id, file_path, original_codec, original_size, status, source_dev, source_ino, source_size, source_mtime_sec, source_mtime_nsec, source_fingerprint)
             VALUES (?1, ?2, 'h264', ?3, 'APPROVED', ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                job_id,
                pinned.canon_src.to_string_lossy().to_string(),
                size,
                ident.dev as i64,
                ident.ino as i64,
                size,
                ident.mtime_sec,
                ident.mtime_nsec,
                ident.fingerprint,
            ],
        )
        .unwrap();
    } else {
        conn.execute(
            "INSERT INTO mediaflow_queue (file_path, original_codec, original_size, status, source_dev, source_ino, source_size, source_mtime_sec, source_mtime_nsec, source_fingerprint)
             VALUES (?1, 'h264', ?2, 'APPROVED', ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                pinned.canon_src.to_string_lossy().to_string(),
                size,
                ident.dev as i64,
                ident.ino as i64,
                size,
                ident.mtime_sec,
                ident.mtime_nsec,
                ident.fingerprint,
            ],
        )
        .unwrap();
    }
}

#[test]
fn test_mediaflow_default_roots_align_with_systemd_and_retain_explicit_overrides() {
    assert_eq!(
        DEFAULT_MEDIAFLOW_ROOTS,
        &["/mnt", "/media", "/srv", "/data"]
    );
    assert!(!DEFAULT_MEDIAFLOW_ROOTS.contains(&"/home"));

    let default_roots = mediaflow_allowed_roots_from_raw(None);
    let blank_roots = mediaflow_allowed_roots_from_raw(Some("   "));
    assert_eq!(default_roots, blank_roots);
    if let Ok(canon_home) = fs::canonicalize("/home") {
        assert!(
            !default_roots.contains(&canon_home),
            "/home must not be a default MediaFlow candidate root under ProtectHome=read-only"
        );
    }

    let tmp = env::temp_dir().join(format!("af-mf-roots-{}", uuid::Uuid::new_v4()));
    let valid_a = tmp.join("custom-a");
    let valid_b = tmp.join("custom-b");
    let file_not_dir = tmp.join("not-a-dir.mp4");
    fs::create_dir_all(&valid_a).unwrap();
    fs::create_dir_all(&valid_b).unwrap();
    fs::write(&file_not_dir, b"fixture").unwrap();

    let raw = format!(
        "{}, relative/ignored, {}, {}, {}",
        valid_a.display(),
        tmp.join("missing").display(),
        file_not_dir.display(),
        valid_b.display()
    );
    let configured = mediaflow_allowed_roots_from_raw(Some(&raw));
    assert_eq!(
        configured,
        vec![
            fs::canonicalize(&valid_a).unwrap(),
            fs::canonicalize(&valid_b).unwrap(),
        ]
    );

    // Explicit configuration with no valid directories must fail closed instead of widening to defaults.
    let closed = mediaflow_allowed_roots_from_raw(Some("/definitely-nonexistent-mediaflow-root"));
    assert!(closed.is_empty());

    let _ = fs::remove_dir_all(&tmp);
}

#[cfg(unix)]
#[tokio::test]
async fn test_mediaflow_worker_blocks_source_change_and_legacy_rows_before_execution() {
    let name =
        "workers::tests::test_mediaflow_worker_blocks_source_change_and_legacy_rows_before_execution";
    if std::env::var("AF_MEDIAFLOW_IDENT_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_MEDIAFLOW_IDENT_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let root = env::temp_dir().join(format!("af-mf-ident-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("media")).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", root.join("media"));
    af_db::init_db().unwrap();

    let ffmpeg_called = root.join("ffmpeg_was_invoked");
    let fake_ffmpeg = root.join("bin/ffmpeg");
    fs::write(
        &fake_ffmpeg,
        format!(
            "#!/bin/sh\necho invoked > \"{}\"\nexit 0\n",
            ffmpeg_called.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_ffmpeg, fs::Permissions::from_mode(0o755)).unwrap();
    env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            env::var("PATH").unwrap()
        ),
    );

    // 1. Atomic file replacement between approval and worker claim -> NEEDS_RESCAN, ffmpeg never spawned.
    let replaced_src = root.join("media/replaced.mp4");
    fs::write(&replaced_src, b"original-scanned-fixture-v1").unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, Some(101), &replaced_src);
    }
    let tmp_swap = root.join("media/replaced.mp4.new");
    fs::write(&tmp_swap, b"new-unreviewed-media-file-v2").unwrap();
    fs::rename(&tmp_swap, &replaced_src).unwrap();

    assert!(process_next_mediaflow_job().await);
    assert!(!ffmpeg_called.exists());
    assert_eq!(
        fs::read(&replaced_src).unwrap(),
        b"new-unreviewed-media-file-v2"
    );
    let (status1, err1): (String, String) = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status, error_log FROM mediaflow_queue WHERE id = 101",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status1, "NEEDS_RESCAN");
    assert_eq!(err1, MEDIAFLOW_SOURCE_CHANGED_BEFORE_EXEC_MSG);

    // 2. Same-inode, same-size in-place edit between approval and worker claim -> NEEDS_RESCAN, ffmpeg never spawned.
    let edited_src = root.join("media/edited_in_place.mp4");
    fs::write(&edited_src, b"AAAA-1111-fixture-bytes!").unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, Some(102), &edited_src);
    }
    fs::write(&edited_src, b"BBBB-2222-fixture-bytes!").unwrap();

    assert!(process_next_mediaflow_job().await);
    assert!(!ffmpeg_called.exists());
    assert_eq!(fs::read(&edited_src).unwrap(), b"BBBB-2222-fixture-bytes!");
    let status2: String = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status FROM mediaflow_queue WHERE id = 102",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status2, "NEEDS_RESCAN");

    // 3. Legacy APPROVED row missing persisted identity -> NEEDS_RESCAN without running ffmpeg.
    let legacy_src = root.join("media/legacy_approved.mp4");
    fs::write(&legacy_src, b"legacy-media-fixture-bytes").unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO mediaflow_queue (id, file_path, original_codec, original_size, status) VALUES (103, ?1, 'h264', 26, 'APPROVED')",
            params![legacy_src.to_string_lossy().to_string()],
        )
        .unwrap();
    }
    assert!(process_next_mediaflow_job().await);
    assert!(!ffmpeg_called.exists());
    assert_eq!(
        fs::read(&legacy_src).unwrap(),
        b"legacy-media-fixture-bytes"
    );
    let (status3, err3): (String, String) = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status, error_log FROM mediaflow_queue WHERE id = 103",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status3, "NEEDS_RESCAN");
    assert_eq!(err3, MEDIAFLOW_MISSING_IDENTITY_MSG);

    // 4. Startup reconciliation also transitions legacy identity-less PENDING_APPROVAL/APPROVED rows to NEEDS_RESCAN.
    let legacy_pending = root.join("media/legacy_pending.mp4");
    fs::write(&legacy_pending, b"legacy-pending-bytes").unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO mediaflow_queue (id, file_path, original_codec, original_size, status) VALUES (104, ?1, 'h264', 20, 'PENDING_APPROVAL')",
            params![legacy_pending.to_string_lossy().to_string()],
        )
        .unwrap();
    }
    reconcile_mediaflow_startup();
    let status4: String = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status FROM mediaflow_queue WHERE id = 104",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status4, "NEEDS_RESCAN");

    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[tokio::test]
async fn test_mediaflow_mid_transcode_in_place_edit_aborts_publication_safely() {
    let name =
        "workers::tests::test_mediaflow_mid_transcode_in_place_edit_aborts_publication_safely";
    if std::env::var("AF_MEDIAFLOW_INPLACE_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_MEDIAFLOW_INPLACE_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let root = env::temp_dir().join(format!("af-mf-inplace-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("media")).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", root.join("media"));
    af_db::init_db().unwrap();

    let src_file = root.join("media/in_place.mp4");
    fs::write(&src_file, b"original-1111-same-length!").unwrap();

    // Fake ffmpeg overwrites `src_file` IN PLACE (same inode & exact same byte length) mid-transcode.
    let fake_ffmpeg = root.join("bin/ffmpeg");
    fs::write(
        &fake_ffmpeg,
        "#!/bin/sh\nset -eu\nout=\"\"\nfor arg in \"$@\"; do out=\"$arg\"; done\nprintf 'modified-2222-same-length!' > \"$AF_INPLACE_TARGET\"\nout_path=\"${out#file:}\"\nprintf 'transcoded-hevc-output' > \"$out_path\"\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&fake_ffmpeg, fs::Permissions::from_mode(0o755)).unwrap();
    let fake_ffprobe = root.join("bin/ffprobe");
    fs::write(&fake_ffprobe, "#!/bin/sh\necho 10.0\n").unwrap();
    fs::set_permissions(&fake_ffprobe, fs::Permissions::from_mode(0o755)).unwrap();
    env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            env::var("PATH").unwrap()
        ),
    );
    env::set_var("AF_INPLACE_TARGET", &src_file);

    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, Some(201), &src_file);
    }

    assert!(process_next_mediaflow_job().await);

    assert_eq!(fs::read(&src_file).unwrap(), b"modified-2222-same-length!");
    assert!(!root.join("media/in_place_hevc.mkv").exists());
    let trash_dir = root.join("media/.mediaflow_trash");
    if trash_dir.exists() {
        assert_eq!(fs::read_dir(&trash_dir).unwrap().count(), 0);
    }
    let (status, err_log): (String, String) = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status, error_log FROM mediaflow_queue WHERE id = 201",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "FAILED");
    assert_eq!(err_log, MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG);

    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[tokio::test]
async fn test_mediaflow_inflight_cancellation_stops_ffmpeg_and_preserves_source() {
    let name =
        "workers::tests::test_mediaflow_inflight_cancellation_stops_ffmpeg_and_preserves_source";
    if std::env::var("AF_MEDIAFLOW_CANCEL_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_MEDIAFLOW_CANCEL_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let root = env::temp_dir().join(format!("af-mf-cancel-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("media")).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", root.join("media"));
    af_db::init_db().unwrap();

    let src_file = root.join("media/long_movie.mp4");
    fs::write(&src_file, b"original-untouched-source-bytes").unwrap();
    let started_marker = root.join("ffmpeg_started");

    let fake_ffmpeg = root.join("bin/ffmpeg");
    fs::write(
        &fake_ffmpeg,
        format!(
            "#!/bin/sh\nout=\"\"\nfor arg in \"$@\"; do out=\"$arg\"; done\nout_path=\"${{out#file:}}\"\nprintf 'partial' > \"$out_path\"\necho started > \"{}\"\nsleep 30\nexit 0\n",
            started_marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_ffmpeg, fs::Permissions::from_mode(0o755)).unwrap();
    let fake_ffprobe = root.join("bin/ffprobe");
    fs::write(&fake_ffprobe, "#!/bin/sh\necho 30.0\n").unwrap();
    fs::set_permissions(&fake_ffprobe, fs::Permissions::from_mode(0o755)).unwrap();
    env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            env::var("PATH").unwrap()
        ),
    );

    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, Some(301), &src_file);
    }

    let mut rx = subscribe_mediaflow_progress();
    let worker_handle = tokio::spawn(async { process_next_mediaflow_job().await });

    let mut started = false;
    for _ in 0..100 {
        if started_marker.exists() {
            started = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(started, "fake ffmpeg should have started");

    assert_eq!(
        cancel_inflight_mediaflow_job(301),
        CancelInflightOutcome::CancelSignalled
    );
    let processed = tokio::time::timeout(Duration::from_secs(5), worker_handle)
        .await
        .expect("worker must terminate promptly after cancellation")
        .unwrap();
    assert!(processed);

    // Source bytes untouched, no published output, no temp leftovers, no trash entries.
    assert_eq!(
        fs::read(&src_file).unwrap(),
        b"original-untouched-source-bytes"
    );
    assert!(!root.join("media/long_movie_hevc.mkv").exists());
    let media_entries: Vec<String> = fs::read_dir(root.join("media"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(media_entries, vec!["long_movie.mp4".to_string()]);

    let (status, err_log): (String, String) = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status, error_log FROM mediaflow_queue WHERE id = 301",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "CANCELLED");
    assert_eq!(err_log, MEDIAFLOW_CANCELLED_MSG);

    let mut events = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        events.push(serde_json::from_str::<serde_json::Value>(&msg).unwrap());
    }
    assert!(events.iter().any(|e| e["status"] == "cancelled"));

    let _ = fs::remove_dir_all(&root);
}
