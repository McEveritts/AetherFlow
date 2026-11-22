use super::*;
use flate2::write::GzEncoder;
use flate2::Compression;
use rusqlite::Connection;
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tar::{Builder, EntryType, Header};

mod config_artifact_tests;
mod deploy_lifecycle_tests;
mod rollback_security_tests;

pub(super) struct TempSandbox {
    root: PathBuf,
}

impl TempSandbox {
    pub(super) fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "af-release-test-{}-{}",
            label,
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    pub(super) fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for TempSandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Builds an in-memory `.tar.gz` archive containing the specified `(path, contents, entry_type)` entries,
/// writes it to `dest_archive`, and returns `(archive_path, sha256_manifest_string)`.
pub(super) fn build_synthetic_release_tarball(
    dest_archive: &Path,
    artifact_name: &str,
    entries: &[(&str, &[u8], EntryType)],
) -> (PathBuf, String) {
    if let Some(parent) = dest_archive.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let file = fs::File::create(dest_archive).unwrap();
    let enc = GzEncoder::new(file, Compression::fast());
    let mut tar = Builder::new(enc);

    for (rel_path, data, entry_type) in entries {
        let mut header = Header::new_gnu();
        header.set_entry_type(*entry_type);
        if *entry_type == EntryType::Directory {
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            tar.append_data(&mut header, *rel_path, std::io::empty())
                .unwrap();
        } else if *entry_type == EntryType::Symlink {
            header.set_size(0);
            header.set_mode(0o777);
            tar.append_link(&mut header, *rel_path, "synthetic-target")
                .unwrap();
        } else {
            header.set_size(data.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            tar.append_data(&mut header, *rel_path, *data).unwrap();
        }
    }
    let enc = tar.into_inner().unwrap();
    enc.finish().unwrap();

    let digest = compute_file_sha256(dest_archive).unwrap();
    let manifest = format!("{}  {}\n", digest, artifact_name);
    (dest_archive.to_path_buf(), manifest)
}

#[derive(Clone)]
pub(super) struct MockArtifactProvider {
    pub(super) resolved_tag: Result<String, String>,
    pub(super) archive_source: PathBuf,
    pub(super) manifest_content: String,
}

impl ArtifactProvider for MockArtifactProvider {
    fn resolve_release_tag(
        &self,
        _config: &ReleaseConfig,
        _channel: ReleaseChannel,
    ) -> ReleaseResult<String> {
        match &self.resolved_tag {
            Ok(t) => Ok(t.clone()),
            Err(msg) => Err(ReleaseError::TagResolution {
                channel: "mock".to_string(),
                reason: msg.clone(),
            }),
        }
    }

    fn fetch_release_bundle(
        &self,
        config: &ReleaseConfig,
        _channel: ReleaseChannel,
        _tag: &str,
        staging_dir: &Path,
    ) -> ReleaseResult<(PathBuf, String)> {
        let dest = staging_dir.join(&config.artifact_name);
        fs::copy(&self.archive_source, &dest)
            .map_err(|e| ReleaseError::io("copying mock archive", e))?;
        Ok((dest, self.manifest_content.clone()))
    }
}

#[derive(Default, Clone)]
pub(super) struct MockLifecycle {
    pub(super) unit_env: Option<String>,
    pub(super) calls: Arc<Mutex<Vec<String>>>,
    pub(super) corrupt_db_on_restart: Option<PathBuf>,
    pub(super) fail_stop_services: bool,
    pub(super) stale_identity: bool,
    pub(super) always_stale_identity: bool,
}

impl MockLifecycle {
    pub(super) fn recorded_calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl LifecycleController for MockLifecycle {
    fn verify_running_release(&self, _config: &ReleaseConfig) -> ReleaseResult<()> {
        let restart_count = self
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| *c == "restart_units")
            .count();
        if self.always_stale_identity || (self.stale_identity && restart_count <= 1) {
            return Err(ReleaseError::Systemd {
                action: "verify runtime identity".to_string(),
                reason: "old executable is still running".to_string(),
            });
        }
        Ok(())
    }

    fn query_unit_environment(&self, unit: &str) -> Option<String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("query_env:{}", unit));
        self.unit_env.clone()
    }

    fn restart_systemd_units(&self, config: &ReleaseConfig) -> ReleaseResult<()> {
        self.calls.lock().unwrap().push("restart_units".to_string());
        let packaged_systemd_dir = crate::health::packaged_systemd_directory(config)?;
        if packaged_systemd_dir.is_dir() {
            let _ = install_packaged_unit_if_missing(
                &packaged_systemd_dir.join("aetherflow-runner.service"),
                &config.systemd_units_dst,
            )?;
            let _ = install_packaged_unit_if_missing(
                &packaged_systemd_dir.join("aetherflow-api.service"),
                &config.systemd_units_dst,
            )?;
        }
        if let Some(ref db_to_corrupt) = self.corrupt_db_on_restart {
            // Corrupt the DB on the first restart to simulate a bad migration during candidate boot
            if self
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| *c == "restart_units")
                .count()
                == 1
            {
                fs::write(db_to_corrupt, b"NOT A VALID SQLITE FILE CORRUPTED").unwrap();
                fs::write(format!("{}-wal", db_to_corrupt.display()), b"stale-wal").unwrap();
                fs::write(format!("{}-shm", db_to_corrupt.display()), b"stale-shm").unwrap();
            }
        }
        Ok(())
    }

    fn stop_database_services(&self, db_path: &Path) -> ReleaseResult<()> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("stop_db_services:{}", db_path.display()));
        if self.fail_stop_services {
            return Err(ReleaseError::Systemd {
                action: "systemctl stop aetherflow-api.service aetherflow-runner.service"
                    .to_string(),
                reason: "simulated service stop failure".to_string(),
            });
        }
        Ok(())
    }

    fn terminate_legacy_pm2(&self) -> ReleaseResult<()> {
        self.calls.lock().unwrap().push("terminate_pm2".to_string());
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct MockHealthProber {
    responses: Arc<Mutex<VecDeque<Result<HealthCheckAttempt, String>>>>,
}

impl MockHealthProber {
    pub(super) fn new(items: Vec<Result<HealthCheckAttempt, String>>) -> Self {
        Self {
            responses: Arc::new(Mutex::new(items.into_iter().collect())),
        }
    }
}

impl HealthProber for MockHealthProber {
    fn check_once(&self, _endpoint: &str) -> ReleaseResult<HealthCheckAttempt> {
        let mut q = self.responses.lock().unwrap();
        match q.pop_front() {
            Some(Ok(att)) => Ok(att),
            Some(Err(msg)) => Err(ReleaseError::Systemd {
                action: "health_probe".to_string(),
                reason: msg,
            }),
            None => Ok(HealthCheckAttempt {
                http_status: 503,
                body: r#"{"status":"starting"}"#.to_string(),
            }),
        }
    }
}

pub(super) fn seed_valid_sqlite_db(path: &Path, marker: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode = WAL; \
         CREATE TABLE IF NOT EXISTS test_state (id INTEGER PRIMARY KEY, marker TEXT);",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO test_state (marker) VALUES (?1)",
        rusqlite::params![marker],
    )
    .unwrap();
}

pub(super) fn read_sqlite_marker(path: &Path) -> String {
    let conn = Connection::open(path).unwrap();
    conn.query_row(
        "SELECT marker FROM test_state ORDER BY id DESC LIMIT 1",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

pub(super) fn legacy_completed_manifest(state: &RecoveryState) -> serde_json::Value {
    let mut manifest = serde_json::to_value(state).unwrap();
    manifest["phase"] = serde_json::json!("completed");
    manifest.as_object_mut().unwrap().remove("started_at");
    manifest["source"] = serde_json::json!("manual-deployment");
    manifest
}
