use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::atomic::Ordering;

pub(super) fn isolated(name: &str) -> bool {
    if env::var("AF_INVENTORY_REGRESSION_CHILD").as_deref() == Ok(name) {
        return true;
    }
    assert!(std::process::Command::new(env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("AF_INVENTORY_REGRESSION_CHILD", name)
        .status()
        .unwrap()
        .success());
    false
}

pub(super) struct Fixture {
    pub root: PathBuf,
    pub catalog: PathBuf,
    pub automation: PathBuf,
    pub journal: PathBuf,
    pub calls: PathBuf,
}

impl Fixture {
    pub fn new() -> Self {
        let root = env::temp_dir().join(format!("af-inventory-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("install")).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        env::set_var("AETHERFLOW_FS_ROOT", &root);
        env::set_var("AETHERFLOW_RELEASE_ROOT", &root);
        env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
        let catalog = root.join("packages.json");
        let automation = root.join("automation.json");
        env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
        env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);
        fs::write(&automation, "{}").unwrap();
        let config = af_release::ReleaseConfig::for_root(&root);
        let journal = af_release::config::try_resolve_db_path(&config, None)
            .unwrap()
            .path;
        fs::create_dir_all(journal.parent().unwrap()).unwrap();
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            env::set_var(key, &journal);
        }
        crate::initialize_package_jobs(rusqlite::Connection::open(&journal).unwrap()).unwrap();
        let calls = root.join("calls");
        env::set_var("AF_STATUS_CALLS", &calls);
        env::set_var(
            "PATH",
            format!(
                "{}:{}",
                root.join("bin").display(),
                env::var("PATH").unwrap()
            ),
        );
        let fixture = Self {
            root,
            catalog,
            automation,
            journal,
            calls,
        };
        fixture.write_packages(&[Self::package("fixture", "systemd", "fixture-main")]);
        fixture.install("fixture");
        fixture.command("systemctl", "printf '%s\\n' \"$*\" >> \"$AF_STATUS_CALLS\"\ncase \"$1\" in show) printf 'ActiveState=active\\nSubState=running\\n';; is-active) echo active;; *) exit 92;; esac\n");
        fixture.command("pm2", "test \"$1\" = jlist || exit 92\nprintf '%s\\n' \"pm2 $*\" >> \"$AF_STATUS_CALLS\"\nprintf '[]'\n");
        fixture
    }

    pub fn package(name: &str, kind: &str, service: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name, "label": name, "description": "disposable fixture",
            "lock_file": format!("/install/.{name}.lock"), "category": "test",
            "service_type": kind, "service_name": service
        })
    }

    pub fn write_packages(&self, packages: &[serde_json::Value]) {
        fs::write(&self.catalog, serde_json::to_vec(packages).unwrap()).unwrap();
    }

    pub fn install(&self, name: &str) {
        fs::write(self.root.join(format!("install/.{name}.lock")), "installed").unwrap();
    }

    pub fn command(&self, name: &str, body: &str) {
        let path = self.root.join("bin").join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn inventory_unknown_evidence_never_becomes_known_absence() {
    let name = "inventory_regressions::inventory_unknown_evidence_never_becomes_known_absence";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    let services = get_active_services().unwrap();
    assert_eq!(services.len(), 4);
    assert_eq!(services["fixture"].units, ["fixture-main"]);
    let mut collision = Fixture::package("second-fixture", "systemd", "second-unit");
    collision["label"] = serde_json::json!("fixture");
    fixture.install("second-fixture");
    fixture.write_packages(&[
        Fixture::package("fixture", "systemd", "fixture-main"),
        collision,
    ]);
    assert!(get_active_services()
        .unwrap_err()
        .to_string()
        .contains("duplicate service inventory label"));
    fs::write(&fixture.catalog, "{corrupt").unwrap();
    let error = get_active_services().unwrap_err();
    assert!(error.to_string().contains("expected"), "{error}");
    fixture.write_packages(&[Fixture::package("fixture", "systemd", "fixture-main")]);
    fs::set_permissions(&fixture.catalog, fs::Permissions::from_mode(0o000)).unwrap();
    assert_eq!(
        fs::read(&fixture.catalog).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert!(get_active_services()
        .unwrap_err()
        .to_string()
        .contains("cannot read catalog"));
    fs::set_permissions(&fixture.catalog, fs::Permissions::from_mode(0o600)).unwrap();
    let missing_catalog = fixture.root.join("missing.json");
    env::set_var("AETHERFLOW_PACKAGES_CONFIG", &missing_catalog);
    assert!(get_active_services().is_err());
    env::set_var("AETHERFLOW_PACKAGES_CONFIG", &fixture.catalog);
    fs::write(&fixture.automation, "not json").unwrap();
    assert!(get_active_services().is_err());
    fs::write(&fixture.automation, "{}").unwrap();
    let lock = fixture.root.join("install/.fixture.lock");
    fs::remove_file(&lock).unwrap();
    assert_eq!(get_active_services().unwrap().len(), 3);
    fs::create_dir(&lock).unwrap();
    assert!(get_active_services()
        .unwrap_err()
        .to_string()
        .contains("not a regular file"));
    fs::remove_dir(&lock).unwrap();
    symlink(fixture.root.join("missing-lock"), &lock).unwrap();
    assert!(get_active_services().is_err());
    fs::remove_file(&lock).unwrap();
    fixture.install("fixture");
    let install = fixture.root.join("install");
    fs::set_permissions(&install, fs::Permissions::from_mode(0o000)).unwrap();
    assert_eq!(
        fs::symlink_metadata(&lock).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let inventory = get_active_services();
    fs::set_permissions(&install, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(inventory
        .unwrap_err()
        .to_string()
        .contains("cannot inspect installation lock"));
    assert_eq!(get_active_services().unwrap().len(), 4);
    println!("real catalog and lock corruption/permission/type failures return unknown; genuine absent lock yields three core services");
}

#[test]
fn inventory_reads_catalog_once_and_preserves_component_mapping() {
    let name =
        "inventory_regressions::inventory_reads_catalog_once_and_preserves_component_mapping";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    fixture.write_packages(&[
        Fixture::package("fixture", "systemd", "fixture-main"),
        Fixture::package("rclone", "systemd", "rclone"),
        Fixture::package("recyclarr", "systemd", "recyclarr"),
        Fixture::package("fixture-node", "pm2", "fixture-node"),
    ]);
    for package in ["rclone", "recyclarr", "fixture-node"] {
        fixture.install(package);
    }
    fs::write(&fixture.automation, serde_json::json!({
        "fixture": {"sandbox_service_units": ["fixture-main.service", "fixture-side.service", "fixture-schedule.timer"]},
        "rclone": {"sandbox_service_units": ["rclone-vfs"]},
        "recyclarr": {"sandbox_service_units": ["recyclarr.timer"]}
    }).to_string()).unwrap();
    fixture.command("systemctl", "printf '%s\\n' \"$*\" >> \"$AF_STATUS_CALLS\"\ntest \"$1\" = show || exit 92\ncase \"$2\" in rclone-vfs|recyclarr) printf 'ActiveState=inactive\\nSubState=dead\\n';; *) printf 'ActiveState=active\\nSubState=running\\n';; esac\n");
    fixture.command("pm2", "test \"$1\" = jlist || exit 92\nprintf 'pm2 jlist\\n' >> \"$AF_STATUS_CALLS\"\nprintf '[{\"name\":\"fixture-node\",\"pm2_env\":{\"status\":\"online\"}}]'\n");
    CATALOG_READ_COUNT.store(0, Ordering::SeqCst);
    let services = get_active_services().unwrap();
    assert_eq!(CATALOG_READ_COUNT.load(Ordering::SeqCst), 1);
    assert_eq!(services.len(), 7);
    assert_eq!(
        services["fixture"].units,
        ["fixture-main", "fixture-side", "fixture-schedule.timer"]
    );
    assert_eq!(services["fixture"].components[2].role, "timer");
    assert_eq!(services["rclone"].status, "running");
    assert_eq!(services["rclone"].components[1].role, "optional");
    assert!(!services["rclone"].components[1].configured);
    assert_eq!(services["recyclarr"].components[0].status, "idle");
    assert_eq!(services["recyclarr"].components[1].role, "timer");
    assert_eq!(services["fixture-node"].managed_by, "pm2");
    assert_eq!(services["fixture-node"].status, "running");
    let calls = fs::read_to_string(&fixture.calls).unwrap();
    assert_eq!(
        calls
            .lines()
            .filter(|line| line.starts_with("show "))
            .count(),
        10,
        "{calls}"
    );
    assert_eq!(calls.lines().filter(|line| *line == "pm2 jlist").count(), 1);
    CATALOG_READ_COUNT.store(0, Ordering::SeqCst);
    assert_eq!(get_active_services().unwrap().len(), 7);
    assert_eq!(CATALOG_READ_COUNT.load(Ordering::SeqCst), 1);
    assert_eq!(fs::read_to_string(&fixture.calls).unwrap(), calls);
    println!("one real catalog load per snapshot, ten unique fake systemctl calls and one pm2 listing; warm snapshot reuses status cache");
}

#[test]
fn systemctl_status_timeout_kills_reaps_and_does_not_inherit_guard() {
    let name =
        "inventory_regressions::systemctl_status_timeout_kills_reaps_and_does_not_inherit_guard";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    let fifo = fixture.root.join("blocked-status");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    env::set_var("AF_BLOCK_FIFO", fifo);
    env::set_var("AF_STATUS_PID", fixture.root.join("status.pid"));
    let guard_path = fixture.root.join("unrelated-maintenance.lock");
    env::set_var("AF_STATUS_GUARD", &guard_path);
    let guard = af_release::ReleaseLockGuard::acquire(&guard_path, Duration::ZERO).unwrap();
    let job = PackageJobInfo {
        job_id: "status-descriptor-fixture".into(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 0,
        last_line: String::new(),
        started_at: Utc::now().to_rfc3339(),
        expected_target_version: None,
    };
    assert!(try_start_package_job(job));
    env::set_var("AF_TEST_ROOT", &fixture.root);
    fixture.command("systemctl", "for descriptor in /proc/$$/fd/*; do\n target=$(readlink \"$descriptor\")\n case \"$target\" in \"$AF_STATUS_GUARD\"|\"$AF_TEST_ROOT\"/*owners/*|\"$AF_TEST_ROOT\"/*leases/*|\"$AF_TEST_ROOT\"/*launch*) printf 'descriptor leak: %s\\n' \"$target\" > \"$AF_TEST_ROOT/leaked\"; exit 91;; esac\ndone\nprintf '%s' \"$$\" > \"$AF_STATUS_PID\"\nexec /bin/cat \"$AF_BLOCK_FIFO\"\n");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let start = Instant::now();
    let status = runtime
        .block_on(async { query_single_systemd_unit_status("fixture-blocked", "required", true) });
    assert_eq!(status.0, "unknown");
    assert!(start.elapsed() >= Duration::from_secs(2));
    assert!(start.elapsed() < Duration::from_secs(4));
    assert!(!fixture.root.join("leaked").exists());
    let pid = fs::read_to_string(fixture.root.join("status.pid")).unwrap();
    assert!(
        !Path::new("/proc").join(pid).exists(),
        "timed-out child must be reaped"
    );
    assert_eq!(get_systemd_unit_info("fixture-blocked").0, "unknown");
    let components = policies_for_units(vec!["fixture-blocked".into()], false);
    assert_eq!(
        get_service_info_for_policies("fixture", components).0,
        "unknown"
    );
    finish_package_job("fixture", "update", true, "", "status-descriptor-fixture").unwrap();
    drop(guard);
    drop(af_release::ReleaseLockGuard::acquire(&guard_path, Duration::ZERO).unwrap());
    println!("actual FIFO-blocked systemctl query returned unknown after {:?}; child killed/reaped; maintenance and launch leases were not inherited", start.elapsed());
}

#[test]
fn linux_query_failures_remain_unknown_in_both_aggregation_paths() {
    let name =
        "inventory_regressions::linux_query_failures_remain_unknown_in_both_aggregation_paths";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    for failure in ["exit 1\n", "printf 'malformed success output'\n"] {
        clear_service_status_cache();
        fixture.command("systemctl", failure);
        assert_eq!(get_systemd_unit_info("fixture-main").0, "unknown");
        assert_eq!(get_service_info_detailed("fixture").0, "unknown");
        let inventory = get_active_services().unwrap();
        assert_eq!(inventory["fixture"].status, "unknown");
        assert_eq!(inventory["AetherFlow Frontend"].status, "unknown");
        assert_eq!(inventory["Apache2 Web Server"].status, "unknown");
    }
    clear_service_status_cache();
    fs::remove_file(fixture.root.join("bin/systemctl")).unwrap();
    env::set_var("PATH", fixture.root.join("bin"));
    assert_eq!(get_systemd_unit_info("fixture-main").0, "unknown");
    assert_eq!(get_service_info_detailed("fixture").0, "unknown");
    println!("failed exit, malformed successful output and absent systemctl remain unknown in single-unit, component and inventory views");
}

#[test]
fn configured_pm2_failures_are_unknown_but_a_successful_empty_list_is_stopped() {
    let name = "inventory_regressions::configured_pm2_failures_are_unknown_but_a_successful_empty_list_is_stopped";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    fixture.write_packages(&[Fixture::package("fixture", "pm2", "fixture-main")]);
    for script in [
        "exit 42\n",
        "printf '{invalid'\n",
        "printf '{}'\n",
        "sleep 10\n",
    ] {
        fixture.command("pm2", script);
        clear_service_status_cache();
        assert!(get_pm2_services().is_err());
        let services = get_active_services().unwrap();
        let service = &services["fixture"];
        assert_eq!(service.status, "unknown");
        assert_eq!(service.components[0].status, "unknown");
        assert_eq!(get_pm2_service_info("fixture-main").0, "unknown");
    }
    for (listing, expected) in [
        ("[]", "stopped"),
        (
            r#"[{"name":"fixture-main","pm2_env":{"status":"online"}}]"#,
            "running",
        ),
        (
            r#"[{"name":"fixture-main","pm2_env":{"status":"stopped"}}]"#,
            "stopped",
        ),
        (
            r#"[{"name":"fixture-main","pm2_env":{"status":"future-state"}}]"#,
            "unknown",
        ),
    ] {
        fixture.command("pm2", &format!("printf '%s' '{listing}'\n"));
        clear_service_status_cache();
        assert_eq!(get_pm2_service_info("fixture-main").0, expected);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_fallback_controls_time_out_and_stop_without_reexecuting_actions() {
    let name = "inventory_regressions::stalled_fallback_controls_time_out_and_stop_without_reexecuting_actions";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    std::env::set_var("AETHERFLOW_RUNNER_SOCK", fixture.root.join("absent.sock"));
    fixture.command(
        "sudo",
        "printf '%s\\n' sudo >> \"$AF_STATUS_CALLS\"; exit 1\n",
    );
    for manager in ["systemd-unit", "pm2"] {
        fixture.command(
            if manager == "pm2" { "pm2" } else { "systemctl" },
            "printf '%s\\n' \"$*\" >> \"$AF_STATUS_CALLS\"; sleep 60\n",
        );
        let error = super::control_service_with_budget(
            "fixture-main",
            "restart",
            manager,
            Duration::from_millis(150),
        )
        .await
        .unwrap_err();
        assert!(super::is_service_control_timeout(&error), "{error:#}");
        let config = af_release::ReleaseConfig::for_root(&fixture.root);
        let lock = af_release::resolve_maintenance_lock_path_for_config(&config).unwrap();
        assert!(af_release::ReleaseLockGuard::acquire(&lock, Duration::from_secs(1)).is_ok());
    }
    // A sudo timeout is already an unconfirmed mutation: direct fallback must
    // not run a second restart after the budget has expired.
    fixture.command("sudo", "sleep 60\n");
    fixture.command("systemctl", "printf duplicated >> \"$AF_STATUS_CALLS\"\n");
    let error = super::control_service_with_budget(
        "fixture-main",
        "restart",
        "systemd-unit",
        Duration::from_millis(100),
    )
    .await
    .unwrap_err();
    assert!(super::is_service_control_timeout(&error));
    assert!(!fs::read_to_string(&fixture.calls)
        .unwrap()
        .contains("duplicated"));
}

#[test]
fn unobserved_service_version_remains_unknown_until_measured() {
    let name = "inventory_regressions::unobserved_service_version_remains_unknown_until_measured";
    if !isolated(name) {
        return;
    }
    let _fixture = Fixture::new();
    af_db::init_db().unwrap();
    clear_service_status_cache();
    let services = get_active_services().unwrap();
    assert!(
        services["fixture"].version.is_empty(),
        "an unobserved version is not latest"
    );
    assert!(services["fixture"].installed_version.is_empty());
    af_db::get_conn().unwrap().execute(
        "INSERT INTO app_updates(package_name, installed_version, latest_version, update_available, update_url, checked_at, last_error) VALUES('fixture', '2.4.1', '2.4.2', 1, '', '2026-11-06T00:00:00Z', '')", [],
    ).unwrap();
    let services = get_active_services().unwrap();
    assert_eq!(services["fixture"].version, "2.4.1");
    assert_eq!(services["fixture"].installed_version, "2.4.1");
    assert_eq!(services["fixture"].latest_version, "2.4.2");
}
