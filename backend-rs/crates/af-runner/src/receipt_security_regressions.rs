use super::*;
use crate::{discover_system_update, query_self_update_job_at, query_self_update_job_in};
use std::fs;
use std::os::unix::fs::symlink;

const UNIT: &str = "aetherflow-self-update-deploy-stable-1234567890abcdef1234567890abcdef.service";

struct Fixture {
    root: PathBuf,
    config: af_release::ReleaseConfig,
    jobs: PathBuf,
    path: PathBuf,
    terminal: SelfUpdateJobStatus,
}

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("af-receipt-security-{}", uuid::Uuid::new_v4()));
        let config = af_release::ReleaseConfig::for_root(&root);
        let jobs = af_release::resolve_self_update_jobs_dir_for_config(&config).unwrap();
        fs::create_dir_all(&jobs).unwrap();
        let path = jobs.join(format!("{UNIT}.json"));
        let terminal = SelfUpdateJobStatus {
            status: "succeeded".into(),
            completed: true,
            success: true,
            job_unit: UNIT.into(),
            error: String::new(),
            exit_code: Some(0),
        };
        Self {
            root,
            config,
            jobs,
            path,
            terminal,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn security_receipt_final_symlink_is_not_terminal_evidence() {
    let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
    let fixture = Fixture::new();
    let external = fixture.root.join("external.json");
    fs::write(&external, serde_json::to_vec(&fixture.terminal).unwrap()).unwrap();
    symlink(&external, &fixture.path).unwrap();
    let query = query_self_update_job_at(UNIT, &fixture.path).await;
    let discovery = discover_system_update(&fixture.config).await;
    let writer = write(&fixture.path, &fixture.terminal);
    println!("query={query:?}; discovery={discovery:?}; writer={writer:?}");
    assert!(
        writer.is_err(),
        "existing writer confinement must remain intact"
    );
    assert!(
        query.is_err(),
        "redirected terminal receipt was trusted: {query:?}"
    );
    assert!(
        discovery.is_err(),
        "redirected receipt cleared admission: {discovery:?}"
    );
}

#[tokio::test]
async fn security_receipt_parent_symlinks_are_rejected_even_when_empty() {
    let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
    for terminal in [false, true] {
        let fixture = Fixture::new();
        let external = fixture.root.join("external");
        fs::create_dir(&external).unwrap();
        if terminal {
            fs::write(
                external.join(fixture.path.file_name().unwrap()),
                serde_json::to_vec(&fixture.terminal).unwrap(),
            )
            .unwrap();
        }
        fs::remove_dir(&fixture.jobs).unwrap();
        symlink(&external, &fixture.jobs).unwrap();
        assert!(query_self_update_job_at(UNIT, &fixture.path).await.is_err());
        assert!(discover_system_update(&fixture.config).await.is_err());
    }
}

#[tokio::test]
async fn security_receipt_nonregular_corrupt_and_aliased_entries_fail_closed() {
    let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
    for kind in [
        "directory",
        "fifo",
        "hardlink",
        "dangling",
        "malformed",
        "identity",
        "invariant",
        "oversized",
    ] {
        let fixture = Fixture::new();
        match kind {
            "directory" => fs::create_dir(&fixture.path).unwrap(),
            "fifo" => {
                let name = c_name(fixture.path.as_os_str()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            "hardlink" => {
                let external = fixture.root.join("external.json");
                fs::write(&external, serde_json::to_vec(&fixture.terminal).unwrap()).unwrap();
                fs::hard_link(external, &fixture.path).unwrap();
            }
            "dangling" => symlink(fixture.root.join("missing"), &fixture.path).unwrap(),
            "malformed" => fs::write(&fixture.path, b"{not-json").unwrap(),
            "oversized" => fs::write(&fixture.path, vec![b' '; 1024 * 1024 + 1]).unwrap(),
            _ => {
                let mut invalid = fixture.terminal.clone();
                if kind == "identity" {
                    invalid.job_unit = UNIT.replace("stable", "nightly");
                } else {
                    invalid.exit_code = Some(1);
                }
                fs::write(&fixture.path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            }
        }
        let query = query_self_update_job_at(UNIT, &fixture.path).await;
        let discovery = discover_system_update(&fixture.config).await;
        println!("kind={kind}; query={query:?}; discovery={discovery:?}");
        assert!(query.is_err(), "{kind}: {query:?}");
        assert!(discovery.is_err(), "{kind}: {discovery:?}");
    }
}

#[tokio::test]
async fn security_receipt_lock_identity_and_contention_fail_closed() {
    let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
    let fixture = Fixture::new();
    write(&fixture.path, &fixture.terminal).unwrap();
    let guard = ReceiptLock::acquire(&fixture.path).unwrap();
    let query = query_self_update_job_at(UNIT, &fixture.path).await;
    assert_eq!(
        query.unwrap_err().0,
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(discover_system_update(&fixture.config).await.is_err());
    drop(guard);
    assert_eq!(
        query_self_update_job_at(UNIT, &fixture.path).await.unwrap(),
        fixture.terminal
    );
    let lock = fixture.path.with_extension("json.lock");
    fs::remove_file(&lock).unwrap();
    let external = fixture.root.join("external-lock");
    fs::write(&external, b"").unwrap();
    symlink(&external, &lock).unwrap();
    assert!(query_self_update_job_at(UNIT, &fixture.path).await.is_err());
    assert!(discover_system_update(&fixture.config).await.is_err());
    fs::remove_file(&lock).unwrap();
    fs::hard_link(&external, &lock).unwrap();
    assert!(query_self_update_job_at(UNIT, &fixture.path).await.is_err());
}

#[tokio::test]
async fn security_receipt_held_directory_rejects_replacement_and_disappearance() {
    let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
    let fixture = Fixture::new();
    write(&fixture.path, &fixture.terminal).unwrap();
    let directory = ReceiptDirectory::open_existing(&fixture.jobs)
        .unwrap()
        .unwrap();
    assert!(directory
        .names()
        .unwrap()
        .contains(&fixture.path.file_name().unwrap().to_os_string()));
    fs::remove_file(&fixture.path).unwrap();
    assert!(query_self_update_job_in(UNIT, &fixture.path, &directory)
        .await
        .is_err());
    fs::rename(&fixture.jobs, fixture.root.join("original")).unwrap();
    fs::create_dir(&fixture.jobs).unwrap();
    fs::write(
        &fixture.path,
        serde_json::to_vec(&fixture.terminal).unwrap(),
    )
    .unwrap();
    assert!(directory.names().is_err());
    assert!(query_self_update_job_in(UNIT, &fixture.path, &directory)
        .await
        .is_err());
    assert!(directory
        .compare_exchange(
            fixture.path.file_name().unwrap(),
            &fixture.terminal,
            &fixture.terminal
        )
        .is_err());
    let traversed = fixture
        .jobs
        .join("..")
        .join("external")
        .join(fixture.path.file_name().unwrap());
    assert!(query_self_update_job_at(UNIT, &traversed).await.is_err());
}

#[tokio::test]
async fn security_receipt_launch_liveness_and_normal_terminal_states_survive() {
    let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
    let fixture = Fixture::new();
    let owner = begin_launch(&fixture.path).unwrap();
    let mut launching = fixture.terminal.clone();
    launching.status = "launching".into();
    launching.completed = false;
    launching.success = false;
    launching.exit_code = None;
    write(&fixture.path, &launching).unwrap();
    assert_eq!(
        query_self_update_job_at(UNIT, &fixture.path).await.unwrap(),
        launching
    );
    assert_eq!(
        discover_system_update(&fixture.config).await.unwrap(),
        launching
    );
    write(&fixture.path, &fixture.terminal).unwrap();
    assert_eq!(
        query_self_update_job_at(UNIT, &fixture.path).await.unwrap(),
        fixture.terminal
    );
    assert!(
        discover_system_update(&fixture.config)
            .await
            .unwrap()
            .completed
    );
    drop(owner);
    fs::remove_file(&fixture.path).unwrap();
    assert_eq!(
        query_self_update_job_at(UNIT, &fixture.path)
            .await
            .unwrap_err()
            .0,
        axum::http::StatusCode::NOT_FOUND
    );
    fs::remove_dir_all(&fixture.jobs).unwrap();
    assert!(
        discover_system_update(&fixture.config)
            .await
            .unwrap()
            .completed
    );
    assert!(
        !fixture.jobs.exists(),
        "discovery must not create absent receipt directories"
    );
}

#[tokio::test]
async fn security_receipt_running_owner_redirection_is_not_liveness() {
    let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
    let fixture = Fixture::new();
    let mut running = fixture.terminal.clone();
    running.status = "running".into();
    running.completed = false;
    running.success = false;
    running.exit_code = None;
    write(&fixture.path, &running).unwrap();
    let external = fixture.root.join("external-owner");
    fs::write(&external, uuid::Uuid::new_v4().to_string()).unwrap();
    symlink(&external, launch_owner_path(&fixture.path)).unwrap();
    assert!(query_self_update_job_at(UNIT, &fixture.path).await.is_err());
    assert!(discover_system_update(&fixture.config).await.is_err());
    fs::remove_file(launch_owner_path(&fixture.path)).unwrap();
    fs::write(
        launch_owner_path(&fixture.path),
        format!("{}{}ignored-suffix", uuid::Uuid::new_v4(), " ".repeat(128)),
    )
    .unwrap();
    assert!(query_self_update_job_at(UNIT, &fixture.path).await.is_err());
}

#[tokio::test]
async fn security_receipt_reconciliation_reread_and_public_query_remain_confined() {
    let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
    use std::os::unix::fs::PermissionsExt;
    let name = "job_receipts::security_regressions::security_receipt_reconciliation_reread_and_public_query_remain_confined";
    if std::env::var("AF_RECEIPT_SECURITY_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_RECEIPT_SECURITY_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    let fixture = Fixture::new();
    std::env::set_var("AETHERFLOW_FS_ROOT", &fixture.root);
    std::env::set_var("AETHERFLOW_RELEASE_ROOT", &fixture.root);
    std::env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    std::env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", "/not-executed");
    let external = fixture.root.join("external.json");
    fs::write(&external, serde_json::to_vec(&fixture.terminal).unwrap()).unwrap();
    let mut running = fixture.terminal.clone();
    running.status = "running".into();
    running.completed = false;
    running.success = false;
    running.exit_code = None;
    write(&fixture.path, &running).unwrap();
    let control = fixture.root.join("systemctl-fixture");
    fs::write(&control, "#!/bin/sh\nrm -- \"$AF_RECEIPT_SECURITY_PATH\"\nln -s -- \"$AF_RECEIPT_SECURITY_EXTERNAL\" \"$AF_RECEIPT_SECURITY_PATH\"\nprintf 'LoadState=loaded\\nActiveState=inactive\\nExecMainStatus=0\\n'\n").unwrap();
    fs::set_permissions(&control, fs::Permissions::from_mode(0o755)).unwrap();
    std::env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &control);
    std::env::set_var("AF_RECEIPT_SECURITY_PATH", &fixture.path);
    std::env::set_var("AF_RECEIPT_SECURITY_EXTERNAL", &external);
    let query = crate::query_self_update_status_local(UNIT).await;
    let discovery = crate::query_self_update_status_local("").await;
    println!("reconciliation query={query:?}; public discovery={discovery:?}");
    assert!(query.is_err());
    assert!(discovery.is_err());
    assert_eq!(
        fs::read(&external).unwrap(),
        serde_json::to_vec(&fixture.terminal).unwrap()
    );
}
