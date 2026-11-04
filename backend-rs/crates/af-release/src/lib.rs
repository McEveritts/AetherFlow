//! `af-release` — AetherFlow Rust Release Management Foundation.
//!
//! Incrementally replaces `deploy/release-manager.sh` with a strongly-typed, lock-serialized,
//! crash-recoverable Rust library and administrative interface while preserving:
//! - Stage 0: FHS state & secret layout verification and 4-tier live SQLite path resolution (`resolve_db_path`).
//! - Stage 1: Release tag resolution (`stable`, `nightly`), SHA-256 manifest verification,
//!   Zip-Slip-safe archive extraction, and `--dry-run --offline` simulation.
//! - Stage 1.5: WAL-safe online SQLite backups (`rusqlite::backup::Backup` opened read-only so hot WALs are never checkpointed),
//!   `PRAGMA integrity_check` verification, and `MANIFEST.sha256` generation.
//! - Stage 2: Atomic symlink swaps (`/opt/AetherFlow/current`) and `.previous_release` tracking.
//! - Stage 3: Non-destructive systemd unit installation (`install_packaged_unit_if_missing`), service restarts,
//!   and deep readiness probing (`/health/ready`).
//! - Stage 4: Automatic and manual rollback with service stop prior to WAL/SHM sidecar removal and SQLite corruption quarantine.
//! - Stage 5: Old release pruning (`cleanup_old_releases`) protecting active and previous targets.
//! - Stage 6: One-shot PM2 -> systemd migration (`migrate-systemd`).

pub mod admin;
pub mod artifact;
pub mod config;
pub mod engine;
pub mod error;
pub mod fs_security;
pub mod health;
pub mod lock;
pub mod runtime;
pub mod snapshot;
pub mod symlink;

pub use admin::{
    ensure_interoperable_maintenance_lock_file, execute_self_update_sync, is_unsupported_error,
    resolve_maintenance_lock_path_for_config, resolve_release_manager_conf,
    resolve_release_manager_conf_for_root, resolve_self_update_jobs_dir_for_config,
    resolve_self_update_jobs_dir_from_process_env, run_cli_from_args, validate_self_update_request,
    ValidatedSelfUpdateRequest,
};
pub use artifact::{
    compute_file_sha256, extract_and_validate_release_archive, parse_sha256_manifest,
    parse_stable_tag_from_redirect_url, prepare_release_permissions,
    resolve_stable_tag_from_latest_redirect, select_release_tag_from_json,
    simulate_offline_artifact, stage_running_release_manager, verify_artifact_checksum,
    ArtifactProvider, GitHubReleaseItem, GithubHttpArtifactProvider,
};
pub use config::{
    decode_quoted_or_raw_conf_value, escape_conf_value, parse_conf_file, parse_conf_str,
    read_env_file_value, read_env_str_value, read_systemd_environment_value, resolve_db_path,
    try_parse_conf_entries, try_resolve_db_path, validate_no_parent_traversal, DbPathSource,
    ReleaseChannel, ReleaseCommand, ReleaseConfig, ReleaseOptions, ResolvedDbPath,
};
pub use engine::{
    append_jsonl_log, CleanupReport, DeployReport, MigrateSystemdReport, ReleaseEngine,
    ReleaseEngineStatus, ReleaseLogEntry, ReleaseOutcome, RollbackReport,
};
pub use error::{ExitCode, ReleaseError, ReleaseResult};
pub use fs_security::{
    apply_data_dir_ownership_and_mode, apply_service_ownership, atomic_copy_file_with_mode,
    atomic_write_bytes_with_mode, create_dir_all_no_symlinks, create_new_dir_exclusive,
    ensure_no_symlink_ancestors, ensure_no_symlink_in_relative_chain, open_exclusive_private_file,
    set_dir_mode, set_file_mode, OwnershipMetadata,
};
pub use health::{
    install_packaged_unit_if_missing, is_healthy_status, parse_endpoint_socket_addr,
    parse_health_status, poll_readiness_probe, sync_cli_entrypoints,
    verify_isolated_systemd_lifecycle_authorized, wait_for_listener_stopped, HealthCheckAttempt,
    HealthProber, LifecycleController, NoopLifecycleController, ReqwestHealthProber,
    SystemdLifecycleController,
};
pub use lock::{RecoveryState, ReleaseLockGuard, ReleasePhase};
pub use snapshot::{
    create_dry_run_placeholder_db, create_state_snapshot, restore_state_if_corrupted,
    sqlite_integrity, sqlite_online_backup, verify_snapshot_manifest, RestoreReport,
    SnapshotReport,
};
pub use symlink::{
    atomic_replace_symlink, canonicalize_preserve_normal, cleanup_old_releases,
    perform_symlink_swap, read_current_link_target, read_previous_release, write_previous_release,
};

#[cfg(test)]
mod tests {
    use super::*;
    use af_models::SelfUpdateRequest;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use rusqlite::Connection;
    use std::collections::{HashMap, VecDeque};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tar::{Builder, EntryType, Header};

    struct TempSandbox {
        root: PathBuf,
    }

    impl TempSandbox {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "af-release-test-{}-{}",
                label,
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn path(&self) -> &Path {
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
    fn build_synthetic_release_tarball(
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
                tar.append_link(&mut header, *rel_path, "/etc/passwd")
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
    struct MockArtifactProvider {
        resolved_tag: Result<String, String>,
        archive_source: PathBuf,
        manifest_content: String,
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
    struct MockLifecycle {
        unit_env: Option<String>,
        calls: Arc<Mutex<Vec<String>>>,
        corrupt_db_on_restart: Option<PathBuf>,
        fail_stop_services: bool,
        stale_identity: bool,
    }

    impl MockLifecycle {
        fn recorded_calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl LifecycleController for MockLifecycle {
        fn verify_running_release(&self, _config: &ReleaseConfig) -> ReleaseResult<()> {
            if self.stale_identity {
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
    struct MockHealthProber {
        responses: Arc<Mutex<VecDeque<Result<HealthCheckAttempt, String>>>>,
    }

    impl MockHealthProber {
        fn new(items: Vec<Result<HealthCheckAttempt, String>>) -> Self {
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

    fn seed_valid_sqlite_db(path: &Path, marker: &str) {
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

    fn read_sqlite_marker(path: &Path) -> String {
        let conn = Connection::open(path).unwrap();
        conn.query_row(
            "SELECT marker FROM test_state ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn test_parse_conf_and_env_file_precedence() {
        let sb = TempSandbox::new("conf-env");
        let conf_file = sb.path().join("release-manager.conf");
        fs::write(
            &conf_file,
            r#"
# Comment line
RELEASES_DIR="${RELEASES_DIR:-/opt/AetherFlow/releases}"
RELEASE_CHANNEL="${RELEASE_CHANNEL:-stable}"
MAX_RELEASES="${MAX_RELEASES:-3}"
SYSTEMD_UNITS_SRC="${SYSTEMD_UNITS_SRC:-${SCRIPT_DIR}/systemd}"
"#,
        )
        .unwrap();

        let mut env_map = HashMap::new();
        env_map.insert("RELEASE_CHANNEL".to_string(), "experimental".to_string());
        env_map.insert("MAX_RELEASES".to_string(), "5".to_string());

        let cfg = ReleaseConfig::load_with_env(Some(&conf_file), &env_map).unwrap();
        assert_eq!(cfg.release_channel, ReleaseChannel::Nightly);
        assert_eq!(cfg.max_releases, 5);
        assert_eq!(
            cfg.releases_dir,
            PathBuf::from("/opt/AetherFlow/releases")
        );
        assert_eq!(cfg.systemd_units_src, sb.path().join("systemd"));

        // Verify read_env_str_value last-wins and quote-stripping rules
        let env_content = r#"
# Database config
DB_PATH="/stale/path.sqlite"
export DB_PATH='/opt/AetherFlow/backend/data/aetherflow.sqlite'
DB_PATH=""
AETHERFLOW_DB_PATH=fallback.sqlite
"#;
        assert_eq!(
            read_env_str_value(env_content, "DB_PATH").as_deref(),
            Some("/opt/AetherFlow/backend/data/aetherflow.sqlite")
        );
        assert_eq!(
            read_env_str_value(env_content, "AETHERFLOW_DB_PATH").as_deref(),
            Some("fallback.sqlite")
        );
    }

    #[test]
    fn test_resolve_db_path_four_tier_precedence() {
        let sb = TempSandbox::new("db-precedence");
        let mut cfg = ReleaseConfig::for_root(sb.path());
        cfg.isolated_root = None;
        fs::create_dir_all(&cfg.env_dir).unwrap();

        let r4 = resolve_db_path(&cfg, None);
        assert_eq!(r4.path, cfg.host_data_dir.join("aetherflow.sqlite"));
        assert_eq!(r4.source, DbPathSource::DataDirDefault);

        let unit_blob = "Environment=GIN_MODE=release \"DB_PATH=/srv/systemd/af.sqlite\"\n";
        let r3 = resolve_db_path(&cfg, Some(unit_blob));
        assert_eq!(r3.path, PathBuf::from("/srv/systemd/af.sqlite"));
        assert_eq!(
            r3.source,
            DbPathSource::SystemdUnit {
                unit: "aetherflow-api".to_string(),
                key: "DB_PATH".to_string()
            }
        );

        fs::write(
            &cfg.host_env_file,
            "AETHERFLOW_DB_PATH=/opt/AetherFlow/backend/data/aetherflow.sqlite\n",
        )
        .unwrap();
        let r2 = resolve_db_path(&cfg, Some(unit_blob));
        assert_eq!(
            r2.path,
            PathBuf::from("/opt/AetherFlow/backend/data/aetherflow.sqlite")
        );
        assert_eq!(
            r2.source,
            DbPathSource::EnvFile {
                path: cfg.host_env_file.clone(),
                key: "AETHERFLOW_DB_PATH".to_string()
            }
        );

        fs::write(
            &cfg.host_env_file,
            "AETHERFLOW_DB_PATH=/opt/secondary.sqlite\nDB_PATH=/opt/primary.sqlite\n",
        )
        .unwrap();
        let r2b = resolve_db_path(&cfg, Some(unit_blob));
        assert_eq!(r2b.path, PathBuf::from("/opt/primary.sqlite"));

        cfg.af_db_path_override = Some(PathBuf::from("/override/af.sqlite"));
        let r1 = resolve_db_path(&cfg, Some(unit_blob));
        assert_eq!(r1.path, PathBuf::from("/override/af.sqlite"));
        assert_eq!(r1.source, DbPathSource::AfDbPathEnv);
    }

    #[test]
    fn test_select_release_tag_all_channels() {
        let sample_json = r#"[
            {"tag_name": "v4.1.0-draft", "target_commitish": "master", "draft": true, "prerelease": false},
            {"tag_name": "experimental", "target_commitish": "experimental", "draft": false, "prerelease": true},
            {"tag_name": "v4.0.1-nightly.20261031", "target_commitish": "nightly", "draft": false, "prerelease": true},
            {"tag_name": "v4.0.0", "target_commitish": "master", "draft": false, "prerelease": false}
        ]"#;

        assert_eq!(
            select_release_tag_from_json(ReleaseChannel::Stable, sample_json).unwrap(),
            "v4.0.0"
        );
        assert_eq!(
            select_release_tag_from_json(ReleaseChannel::Nightly, sample_json).unwrap(),
            "v4.0.1-nightly.20261031"
        );
        assert_eq!(
            select_release_tag_from_json("experimental".parse::<ReleaseChannel>().unwrap(), sample_json).unwrap(),
            "v4.0.1-nightly.20261031"
        );

        // Fallback behavior when JSON is empty: nightly and legacy experimental -> "nightly", stable -> Err
        assert_eq!(
            select_release_tag_from_json(ReleaseChannel::Nightly, "").unwrap(),
            "nightly"
        );
        assert_eq!(
            select_release_tag_from_json("experimental".parse::<ReleaseChannel>().unwrap(), "").unwrap(),
            "nightly"
        );
        assert!(select_release_tag_from_json(ReleaseChannel::Stable, "").is_err());
    }

    #[test]
    fn test_artifact_checksum_and_zip_slip_rejection() {
        let sb = TempSandbox::new("artifact-sec");
        let cfg = ReleaseConfig::for_root(sb.path());

        // 1. Valid archive and SHA256SUMS
        let good_tar = sb.path().join("good.tar.gz");
        let (_, manifest) = build_synthetic_release_tarball(
            &good_tar,
            &cfg.artifact_name,
            &[
                ("aetherflow-api", b"#!/bin/sh\necho v4\n", EntryType::Regular),
                (".version", b"v4.0.0\n", EntryType::Regular),
                ("config/packages.json", b"[]", EntryType::Regular),
            ],
        );
        let digest = verify_artifact_checksum(&good_tar, &manifest, &cfg.artifact_name).unwrap();
        assert_eq!(digest.len(), 64);

        // 2. Tampered checksum must fail with ChecksumMismatch
        let bad_manifest =
            format!("0000000000000000000000000000000000000000000000000000000000000000  {}\n", cfg.artifact_name);
        let err = verify_artifact_checksum(&good_tar, &bad_manifest, &cfg.artifact_name).unwrap_err();
        assert!(matches!(err, ReleaseError::ChecksumMismatch { .. }));

        // 3. Archive containing a symlink entry must be rejected
        let symlink_tar = sb.path().join("symlink.tar.gz");
        build_synthetic_release_tarball(
            &symlink_tar,
            &cfg.artifact_name,
            &[
                ("aetherflow-api", b"binary", EntryType::Regular),
                ("evil-link", b"", EntryType::Symlink),
            ],
        );
        let extract_dir = sb.path().join("extract-symlink");
        let sym_err =
            extract_and_validate_release_archive(&symlink_tar, &extract_dir, "v4.0.0", &cfg)
                .unwrap_err();
        assert!(matches!(sym_err, ReleaseError::ArchiveExtraction { .. }));

        // 4. Archive missing aetherflow-api binary must be rejected
        let missing_bin_tar = sb.path().join("nobin.tar.gz");
        build_synthetic_release_tarball(
            &missing_bin_tar,
            &cfg.artifact_name,
            &[(".version", b"v4.0.0\n", EntryType::Regular)],
        );
        let extract_nobin = sb.path().join("extract-nobin");
        let nobin_err =
            extract_and_validate_release_archive(&missing_bin_tar, &extract_nobin, "v4.0.0", &cfg)
                .unwrap_err();
        assert!(matches!(nobin_err, ReleaseError::ArtifactVerification(_)));
    }

    #[cfg(unix)]
    #[test]
    fn healthy_old_runtime_triggers_rollback_instead_of_completion() {
        let sandbox = TempSandbox::new("stale-runtime");
        let mut config = ReleaseConfig::for_root(sandbox.path());
        config.health_interval = Duration::ZERO;
        seed_valid_sqlite_db(&config.data_dir.join("aetherflow.sqlite"), "preserve-live-data");
        let previous = config.releases_dir.join("previous");
        fs::create_dir_all(&previous).unwrap();
        fs::write(previous.join("aetherflow-api"), b"old").unwrap();
        fs::write(previous.join(".version"), "v4.0.0-old").unwrap();
        std::os::unix::fs::symlink(&previous, &config.current_link).unwrap();
        let archive = sandbox.path().join("release.tar.gz");
        let (_, manifest) = build_synthetic_release_tarball(&archive, &config.artifact_name, &[
            ("aetherflow-api", b"new", EntryType::Regular),
            (".version", b"v4.0.0-new", EntryType::Regular),
        ]);
        let provider = MockArtifactProvider {
            resolved_tag: Ok("v4.0.0-new".to_string()), archive_source: archive, manifest_content: manifest,
        };
        let lifecycle = MockLifecycle { stale_identity: true, ..Default::default() };
        let prober = MockHealthProber::new(vec![Ok(HealthCheckAttempt {
            http_status: 200, body: r#"{"status":"ready"}"#.to_string(),
        })]);
        let engine = ReleaseEngine::new(config.clone(), provider, lifecycle, prober);
        let result = engine.execute(&ReleaseOptions {
            command: ReleaseCommand::Deploy, channel: ReleaseChannel::Nightly,
            dry_run: false, offline: false, from_source: false,
        });
        assert!(matches!(result, Err(ReleaseError::RolledBackAfterProbeFailure { .. })));
        assert_eq!(fs::read_link(&config.current_link).unwrap(), previous);
        let recovery = RecoveryState::load(&config.releases_dir).unwrap().unwrap();
        assert_eq!(recovery.phase, ReleasePhase::Complete);
        assert!(recovery.last_error.unwrap().contains("old executable"));
    }

    #[test]
    fn test_full_deploy_lifecycle_and_housekeeping_pruning() {
        let sb = TempSandbox::new("full-deploy");
        let mut cfg = ReleaseConfig::for_root(sb.path());
        cfg.max_releases = 2;
        cfg.health_interval = Duration::from_millis(1);

        // Seed live database at a non-FHS legacy path referenced via ENV_FILE
        let custom_db = sb.path().join("opt/AetherFlow/backend/data/aetherflow.sqlite");
        seed_valid_sqlite_db(&custom_db, "live-v3-data");
        fs::create_dir_all(&cfg.env_dir).unwrap();
        fs::write(
            &cfg.host_env_file,
            format!("DB_PATH={}\n", custom_db.display()),
        )
        .unwrap();

        // Pre-install a custom aetherflow-api.service unit to verify Stage 3 does NOT overwrite it
        fs::create_dir_all(&cfg.systemd_units_dst).unwrap();
        let existing_api_unit = cfg.systemd_units_dst.join("aetherflow-api.service");
        fs::write(&existing_api_unit, "# Custom ReadWritePaths preserved\n").unwrap();

        let tar_path = sb.path().join("release.tar.gz");
        let (_, manifest) = build_synthetic_release_tarball(
            &tar_path,
            &cfg.artifact_name,
            &[
                ("aetherflow-api", b"rust-v4-binary", EntryType::Regular),
                (".version", b"v4.0.0\n", EntryType::Regular),
                (
                    "deploy/systemd/aetherflow-api.service",
                    b"# Packaged API unit\n",
                    EntryType::Regular,
                ),
                (
                    "deploy/systemd/aetherflow-runner.service",
                    b"# Packaged Runner unit\n",
                    EntryType::Regular,
                ),
            ],
        );

        let provider = MockArtifactProvider {
            resolved_tag: Ok("v4.0.0".to_string()),
            archive_source: tar_path,
            manifest_content: manifest,
        };
        let lifecycle = MockLifecycle::default();
        let prober = MockHealthProber::new(vec![
            Ok(HealthCheckAttempt {
                http_status: 503,
                body: r#"{"status":"starting"}"#.to_string(),
            }),
            Ok(HealthCheckAttempt {
                http_status: 200,
                body: r#"{"database":"ok","redis":"disabled","status":"ready","uptime":"0.1s"}"#
                    .to_string(),
            }),
            Ok(HealthCheckAttempt {
                http_status: 200,
                body: r#"{"status":"ready"}"#.to_string(),
            }),
            Ok(HealthCheckAttempt {
                http_status: 200,
                body: r#"{"status":"ready"}"#.to_string(),
            }),
        ]);

        let engine = ReleaseEngine::new(cfg.clone(), provider, lifecycle.clone(), prober);
        let opts = ReleaseOptions {
            command: ReleaseCommand::Deploy,
            channel: ReleaseChannel::Stable,
            dry_run: false,
            offline: false,
            from_source: false,
        };

        // Deploy 1
        let out1 = match engine.execute(&opts).unwrap() {
            ReleaseOutcome::Deploy(r) => r,
            _ => panic!("expected deploy outcome"),
        };
        assert_eq!(out1.release_tag, "v4.0.0");
        assert!(out1.snapshot.created);
        assert_eq!(out1.health_status.as_deref(), Some("ready"));
        // Verify Stage 0 did NOT copy custom_db into FHS data_dir since resolved DB was elsewhere
        assert!(!cfg.host_data_dir.join(&cfg.sqlite_db).exists());
        // Verify existing systemd unit was preserved while missing runner unit was installed
        assert_eq!(
            fs::read_to_string(&existing_api_unit).unwrap(),
            "# Custom ReadWritePaths preserved\n"
        );
        assert!(cfg
            .systemd_units_dst
            .join("aetherflow-runner.service")
            .is_file());

        let completed_state = RecoveryState::load(&cfg.releases_dir).unwrap().unwrap();
        let legacy_state = legacy_completed_manifest(&completed_state);
        let legacy_bytes = serde_json::to_vec_pretty(&legacy_state).unwrap();
        let state_path = RecoveryState::state_file_path(&cfg.releases_dir);
        fs::write(&state_path, &legacy_bytes).unwrap();
        let legacy_status = engine.inspect_status().unwrap();
        let loaded_state = legacy_status.recovery_state.unwrap();
        assert_eq!(loaded_state.phase, ReleasePhase::Complete);
        assert_eq!(loaded_state.started_at, completed_state.updated_at);
        assert_eq!(
            loaded_state.candidate_release,
            completed_state.candidate_release
        );
        assert_eq!(loaded_state.snapshot_path, completed_state.snapshot_path);
        assert!(!loaded_state.is_unfinished());
        assert_eq!(fs::read(&state_path).unwrap(), legacy_bytes);

        // Deploy 2 & Deploy 3 to trigger Stage 5 pruning (max_releases = 2)
        let out2 = match engine.execute(&opts).unwrap() {
            ReleaseOutcome::Deploy(r) => r,
            _ => panic!("expected deploy outcome"),
        };
        let out3 = match engine.execute(&opts).unwrap() {
            ReleaseOutcome::Deploy(r) => r,
            _ => panic!("expected deploy outcome"),
        };

        assert_eq!(out3.pruned_releases.len(), 1);
        assert!(!out1.release_dir.exists(), "oldest release should be pruned");
        assert!(
            out2.release_dir.exists(),
            "previous release must be protected from pruning"
        );
        assert!(
            out3.release_dir.exists(),
            "current release must be protected from pruning"
        );

        let status = engine.inspect_status().unwrap();
        assert_eq!(status.current_version.as_deref(), Some("v4.0.0"));
        assert_eq!(
            status.recovery_state.unwrap().phase,
            ReleasePhase::Complete
        );
        let canonical_state: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(canonical_state["phase"], "complete");
        assert!(canonical_state["started_at"].as_str().is_some());
        assert!(canonical_state.get("source").is_none());
    }

    fn legacy_completed_manifest(state: &RecoveryState) -> serde_json::Value {
        let mut manifest = serde_json::to_value(state).unwrap();
        manifest["phase"] = serde_json::json!("completed");
        manifest.as_object_mut().unwrap().remove("started_at");
        manifest["source"] = serde_json::json!("manual-deployment");
        manifest
    }

    #[test]
    fn test_regression_completed_phase_alias_serializes_canonically() {
        let phase: ReleasePhase = serde_json::from_str(r#""completed""#).unwrap();
        assert_eq!(phase, ReleasePhase::Complete);
        assert_eq!(serde_json::to_string(&phase).unwrap(), r#""complete""#);
    }

    #[test]
    fn test_regression_native_recovery_still_requires_started_at() {
        let sandbox = TempSandbox::new("missing-recovery-start");
        for phase in [
            "stage0_fhs_layout",
            "stage1_scaffold",
            "stage1_5_snapshot",
            "stage2_symlink_swap",
            "stage3_health_probe",
            "stage4_rollback",
            "stage5_cleanup",
            "stage6_migrate_systemd",
            "complete",
            "failed",
            "unknown",
        ] {
            let state = RecoveryState::new(ReleaseCommand::Deploy, ReleaseChannel::Nightly, false);
            let mut payload = serde_json::to_value(state).unwrap();
            payload["phase"] = serde_json::json!(phase);
            payload.as_object_mut().unwrap().remove("started_at");
            fs::write(
                RecoveryState::state_file_path(sandbox.path()),
                serde_json::to_vec(&payload).unwrap(),
            )
            .unwrap();
            assert!(
                RecoveryState::load(sandbox.path()).is_err(),
                "phase={phase}"
            );
        }
    }

    #[test]
    fn test_regression_legacy_completed_manifest_requires_valid_completion_time() {
        let sandbox = TempSandbox::new("invalid-legacy-completion");
        let state = RecoveryState::new(ReleaseCommand::Deploy, ReleaseChannel::Nightly, false);
        for timestamp in [
            None,
            Some(serde_json::json!(null)),
            Some(serde_json::json!(42)),
            Some(serde_json::json!("not-a-timestamp")),
        ] {
            let mut payload = legacy_completed_manifest(&state);
            if let Some(timestamp) = timestamp {
                payload["updated_at"] = timestamp;
            } else {
                payload.as_object_mut().unwrap().remove("updated_at");
            }
            fs::write(
                RecoveryState::state_file_path(sandbox.path()),
                serde_json::to_vec(&payload).unwrap(),
            )
            .unwrap();
            assert!(RecoveryState::load(sandbox.path()).is_err());
        }
        for (field, value) in [
            ("command", serde_json::json!("rollback")),
            ("dry_run", serde_json::json!(true)),
            ("started_at", serde_json::json!(null)),
        ] {
            let mut payload = legacy_completed_manifest(&state);
            payload[field] = value;
            fs::write(
                RecoveryState::state_file_path(sandbox.path()),
                serde_json::to_vec(&payload).unwrap(),
            )
            .unwrap();
            assert!(
                RecoveryState::load(sandbox.path()).is_err(),
                "field={field}"
            );
        }
    }

    #[test]
    fn test_automatic_rollback_and_corrupted_db_recovery_on_probe_failure() {
        let sb = TempSandbox::new("rollback-corrupt");
        let mut cfg = ReleaseConfig::for_root(sb.path());
        cfg.health_retries = 2;
        cfg.health_interval = Duration::from_millis(1);

        let live_db = cfg.host_data_dir.join(&cfg.sqlite_db);
        seed_valid_sqlite_db(&live_db, "golden-before-bad-deploy");

        let tar_path = sb.path().join("release.tar.gz");
        let (_, manifest) = build_synthetic_release_tarball(
            &tar_path,
            &cfg.artifact_name,
            &[
                ("aetherflow-api", b"binary", EntryType::Regular),
                (".version", b"v4.0.0\n", EntryType::Regular),
            ],
        );

        let provider = MockArtifactProvider {
            resolved_tag: Ok("v4.0.0".to_string()),
            archive_source: tar_path,
            manifest_content: manifest,
        };

        // First deploy succeeds to establish a valid `.previous_release` target
        let initial_lifecycle = MockLifecycle::default();
        let initial_prober = MockHealthProber::new(vec![Ok(HealthCheckAttempt {
            http_status: 200,
            body: r#"{"status":"ready"}"#.to_string(),
        })]);
        let initial_engine = ReleaseEngine::new(
            cfg.clone(),
            provider.clone(),
            initial_lifecycle,
            initial_prober,
        );
        let opts = ReleaseOptions::default();
        let first_deploy = match initial_engine.execute(&opts).unwrap() {
            ReleaseOutcome::Deploy(r) => r,
            _ => panic!("expected deploy"),
        };

        // Second deploy: simulates database corruption during service restart AND fails readiness probes
        let bad_lifecycle = MockLifecycle {
            unit_env: None,
            calls: Arc::new(Mutex::new(Vec::new())),
            corrupt_db_on_restart: Some(live_db.clone()),
            fail_stop_services: false,
            stale_identity: false,
        };
        let failing_prober = MockHealthProber::new(vec![
            Ok(HealthCheckAttempt {
                http_status: 500,
                body: r#"{"status":"degraded"}"#.to_string(),
            }),
            Ok(HealthCheckAttempt {
                http_status: 500,
                body: r#"{"status":"degraded"}"#.to_string(),
            }),
        ]);
        let bad_engine =
            ReleaseEngine::new(cfg.clone(), provider, bad_lifecycle.clone(), failing_prober);

        let err = bad_engine.execute(&opts).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::HealthProbeFailedRollback);
        match err {
            ReleaseError::RolledBackAfterProbeFailure {
                reverted_to,
                db_restored,
                ..
            } => {
                assert_eq!(
                    canonicalize_preserve_normal(&reverted_to),
                    canonicalize_preserve_normal(&first_deploy.release_dir)
                );
                assert!(db_restored, "corrupted live DB must be restored from pre-swap snapshot");
            }
            other => panic!("unexpected error variant: {:?}", other),
        }

        // Verify current_link points back to first_deploy, WAL/SHM sidecars were cleaned,
        // services were stopped BEFORE restore, and live DB has original marker data intact.
        assert_eq!(
            read_current_link_target(&cfg.current_link).unwrap(),
            canonicalize_preserve_normal(&first_deploy.release_dir)
        );
        assert_eq!(sqlite_integrity(&live_db), "ok");
        assert_eq!(read_sqlite_marker(&live_db), "golden-before-bad-deploy");
        assert!(!PathBuf::from(format!("{}-wal", live_db.display())).exists());
        assert!(!PathBuf::from(format!("{}-shm", live_db.display())).exists());

        let calls = bad_lifecycle.recorded_calls();
        assert!(
            calls.iter().any(|c| c.starts_with("stop_db_services:")),
            "services must be stopped before restoring corrupted database"
        );
    }

    #[test]
    fn test_dry_run_offline_never_touches_host_or_restarts_systemd() {
        let sb = TempSandbox::new("dry-run-offline");
        let cfg = ReleaseConfig::for_root(sb.path());
        let host_db = cfg.host_data_dir.join(&cfg.sqlite_db);
        seed_valid_sqlite_db(&host_db, "production-data");

        let provider = MockArtifactProvider {
            resolved_tag: Err("network should not be called in offline dry-run".to_string()),
            archive_source: PathBuf::new(),
            manifest_content: String::new(),
        };
        let lifecycle = MockLifecycle::default();
        let prober = MockHealthProber::new(vec![]);

        let engine = ReleaseEngine::new(cfg.clone(), provider, lifecycle.clone(), prober);
        let opts =
            ReleaseOptions::parse_args(["deploy", "--dry-run", "--offline", "--channel", "experimental"], ReleaseChannel::Stable)
                .unwrap();

        let report = match engine.execute(&opts).unwrap() {
            ReleaseOutcome::Deploy(r) => r,
            _ => panic!("expected deploy report"),
        };

        assert!(report.dry_run);
        assert!(report.offline);
        assert_eq!(report.channel, ReleaseChannel::Nightly);
        assert!(report.release_dir.starts_with(&cfg.dry_run_root));
        assert!(report.current_link.starts_with(&cfg.dry_run_root));
        assert!(!cfg.current_link.exists(), "production current_link must remain untouched");
        assert!(
            !lifecycle
                .recorded_calls()
                .iter()
                .any(|c| c == "restart_units"),
            "dry-run must never restart systemd units"
        );
    }

    #[test]
    fn test_unsupported_from_source_and_offline_validation() {
        let err_offline =
            ReleaseOptions::parse_args(["deploy", "--offline"], ReleaseChannel::Stable)
                .unwrap_err();
        assert_eq!(err_offline.exit_code(), ExitCode::ConfigurationOrUsageError);

        let err_source =
            ReleaseOptions::parse_args(["deploy", "--from-source"], ReleaseChannel::Stable)
                .unwrap_err();
        assert!(is_unsupported_error(&err_source));
        assert_eq!(err_source.exit_code(), ExitCode::ConfigurationOrUsageError);
    }

    #[test]
    fn test_runner_self_update_contract_validation() {
        // Empty defaults -> deploy + stable
        let req_default = SelfUpdateRequest {
            command: String::new(),
            channel: String::new(),
        };
        let v_default = validate_self_update_request(&req_default).unwrap();
        assert_eq!(v_default.command, ReleaseCommand::Deploy);
        assert_eq!(v_default.channel, ReleaseChannel::Stable);

        // Experimental channel is accepted
        let req_exp = SelfUpdateRequest {
            command: "deploy".to_string(),
            channel: "experimental".to_string(),
        };
        let v_exp = validate_self_update_request(&req_exp).unwrap();
        assert_eq!(v_exp.channel, ReleaseChannel::Nightly);

        // Invalid command / channel preserve exact runner error strings
        let bad_cmd = SelfUpdateRequest {
            command: "destroy".to_string(),
            channel: "stable".to_string(),
        };
        assert_eq!(
            validate_self_update_request(&bad_cmd).unwrap_err().error,
            "invalid self-update command"
        );

        let bad_ch = SelfUpdateRequest {
            command: "deploy".to_string(),
            channel: "beta".to_string(),
        };
        assert_eq!(
            validate_self_update_request(&bad_ch).unwrap_err().error,
            "invalid update channel"
        );
    }

    #[test]
    fn test_lock_contention_returns_lock_busy() {
        let sb = TempSandbox::new("lock-busy");
        let lock_path = sb.path().join(".release.lock");
        let _guard1 = ReleaseLockGuard::acquire(&lock_path, Duration::from_millis(100)).unwrap();

        let err = ReleaseLockGuard::acquire(&lock_path, Duration::from_millis(60)).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::LockContention);
    }

    // ── Safety Review Regression Tests ──────────────────────────────────────

    #[test]
    fn test_regression_preplanted_collision_and_symlink_escape_rejected() {
        let sb = TempSandbox::new("escape-regression");
        let cfg = ReleaseConfig::for_root(sb.path());

        let tar_path = sb.path().join("release.tar.gz");
        build_synthetic_release_tarball(
            &tar_path,
            &cfg.artifact_name,
            &[
                ("aetherflow-api", b"binary-content", EntryType::Regular),
                ("config/app.json", b"{\"ok\":true}", EntryType::Regular),
            ],
        );

        // 1. Pre-existing non-empty release directory or pre-planted file inside release_dir must be rejected
        let preplanted_dir = sb.path().join("preplanted-release");
        fs::create_dir_all(&preplanted_dir).unwrap();
        fs::write(preplanted_dir.join("aetherflow-api"), b"preplanted").unwrap();
        let err_non_empty =
            extract_and_validate_release_archive(&tar_path, &preplanted_dir, "v4.0.0", &cfg)
                .unwrap_err();
        assert!(matches!(err_non_empty, ReleaseError::ArchiveExtraction { .. }));

        // 2. Duplicate file entry inside tarball must be rejected by open_exclusive_private_file / collision check
        let dup_tar = sb.path().join("dup.tar.gz");
        build_synthetic_release_tarball(
            &dup_tar,
            &cfg.artifact_name,
            &[
                ("aetherflow-api", b"first", EntryType::Regular),
                ("aetherflow-api", b"second-overwrite", EntryType::Regular),
            ],
        );
        let dup_extract_dir = sb.path().join("dup-extract");
        let err_dup =
            extract_and_validate_release_archive(&dup_tar, &dup_extract_dir, "v4.0.0", &cfg)
                .unwrap_err();
        assert!(matches!(err_dup, ReleaseError::ArchiveExtraction { .. }));

        // 3. On Unix, pre-existing symlinked release_dir or ancestor symlink must be rejected before extraction
        #[cfg(unix)]
        {
            let outside_victim = sb.path().join("outside-victim");
            fs::create_dir_all(&outside_victim).unwrap();
            let symlink_release_dir = sb.path().join("symlink-release-dir");
            std::os::unix::fs::symlink(&outside_victim, &symlink_release_dir).unwrap();

            let err_sym = extract_and_validate_release_archive(
                &tar_path,
                &symlink_release_dir,
                "v4.0.0",
                &cfg,
            )
            .unwrap_err();
            assert!(
                matches!(
                    err_sym,
                    ReleaseError::PathValidation { .. } | ReleaseError::ArchiveExtraction { .. }
                ),
                "expected symlinked release_dir to be rejected, got: {:?}",
                err_sym
            );
            assert!(
                !outside_victim.join("aetherflow-api").exists(),
                "must never extract files into symlink target outside root"
            );

            // Ancestor symlink test
            let nested_under_symlink = symlink_release_dir.join("sub-release");
            let err_anc = extract_and_validate_release_archive(
                &tar_path,
                &nested_under_symlink,
                "v4.0.0",
                &cfg,
            )
            .unwrap_err();
            assert!(matches!(err_anc, ReleaseError::PathValidation { .. }));
        }
    }

    #[test]
    fn test_rollback_database_failure_remains_failed_without_readmitting_writers() {
        for fail_stop_services in [false, true] {
            let sandbox = TempSandbox::new("rollback-recovery-failure");
            let config = ReleaseConfig::for_root(sandbox.path());
            let live_db = config.host_data_dir.join(&config.sqlite_db);
            seed_valid_sqlite_db(&live_db, "protected-rollback-state");
            let previous_release = config.releases_dir.join("1700000001");
            let candidate_release = config.releases_dir.join("1700000002");
            fs::create_dir_all(&previous_release).unwrap();
            fs::create_dir_all(&candidate_release).unwrap();
            let resolved = ResolvedDbPath {
                path: live_db.clone(),
                source: DbPathSource::DataDirDefault,
            };
            create_state_snapshot(&config, &resolved, &previous_release, false).unwrap();
            fs::write(
                previous_release.join("data-snapshot/MANIFEST.sha256"),
                format!("{}  {}.bak\n", "0".repeat(64), config.sqlite_db),
            )
            .unwrap();
            fs::write(&live_db, b"CORRUPT DATABASE MUST REMAIN UNMODIFIED").unwrap();
            let wal_path = PathBuf::from(format!("{}-wal", live_db.display()));
            fs::write(&wal_path, b"PRESERVED WAL SENTINEL").unwrap();
            let shm_path = PathBuf::from(format!("{}-shm", live_db.display()));
            fs::write(&shm_path, b"PRESERVED SHM SENTINEL").unwrap();
            fs::write(
                config.releases_dir.join(".previous_release"),
                previous_release.to_string_lossy().as_bytes(),
            )
            .unwrap();
            atomic_replace_symlink(&config.current_link, &candidate_release, "failed-rollback")
                .unwrap();
            let lifecycle = MockLifecycle {
                fail_stop_services,
                ..MockLifecycle::default()
            };
            let provider = MockArtifactProvider {
                resolved_tag: Err("rollback must not fetch a release".to_string()),
                archive_source: PathBuf::new(),
                manifest_content: String::new(),
            };
            let engine = ReleaseEngine::new(
                config.clone(), provider, lifecycle.clone(), MockHealthProber::new(vec![]),
            );
            let options = ReleaseOptions {
                command: ReleaseCommand::Rollback,
                ..ReleaseOptions::default()
            };
            let error = engine.execute(&options).unwrap_err();
            assert_eq!(error.exit_code(), ExitCode::RollbackFailed);
            assert!(error.to_string().contains("database recovery failed"));
            let calls = lifecycle.recorded_calls();
            assert!(calls.iter().any(|call| call.starts_with("stop_db_services:")));
            assert!(!calls.iter().any(|call| call == "restart_units"));
            let recovery = RecoveryState::load(&config.releases_dir).unwrap().unwrap();
            assert_eq!(recovery.phase, ReleasePhase::Failed);
            assert!(recovery.last_error.unwrap().contains("database recovery failed"));
            assert_eq!(fs::read(&live_db).unwrap(), b"CORRUPT DATABASE MUST REMAIN UNMODIFIED");
            assert_eq!(fs::read(&wal_path).unwrap(), b"PRESERVED WAL SENTINEL");
            assert_eq!(fs::read(&shm_path).unwrap(), b"PRESERVED SHM SENTINEL");
            assert!(!fs::read_to_string(&config.log_file).unwrap().contains("ROLLBACK COMPLETE"));
            if fail_stop_services {
                assert!(error.to_string().contains("writer quiescence also failed"));
            }
        }
    }

    #[test]
    fn test_regression_restore_rejects_stop_services_failure_and_tampered_snapshot() {
        let sb = TempSandbox::new("restore-safety");
        let cfg = ReleaseConfig::for_root(sb.path());
        let live_db = cfg.host_data_dir.join(&cfg.sqlite_db);
        seed_valid_sqlite_db(&live_db, "clean-v4-state");

        let resolved = ResolvedDbPath {
            path: live_db.clone(),
            source: DbPathSource::DataDirDefault,
        };
        let release_dir = cfg.releases_dir.join("1700000001");
        create_new_dir_exclusive(&release_dir, 0o755, 0o755).unwrap();

        let snap = create_state_snapshot(&cfg, &resolved, &release_dir, false).unwrap();
        assert!(snap.created);

        // Corrupt the live DB
        fs::write(&live_db, b"CORRUPTED LIVE DB BYTES").unwrap();
        fs::write(format!("{}-wal", live_db.display()), b"active-wal").unwrap();

        // Case A: stop_services returns Err -> restore MUST fail closed and MUST NOT remove WAL or overwrite DB
        let stop_err = restore_state_if_corrupted(
            &cfg,
            &resolved,
            &release_dir,
            false,
            |_db| {
                Err(ReleaseError::Systemd {
                    action: "systemctl stop".to_string(),
                    reason: "permission denied stopping service".to_string(),
                })
            },
        )
        .unwrap_err();
        assert!(stop_err
            .to_string()
            .contains("stopping services failed"));
        assert!(
            PathBuf::from(format!("{}-wal", live_db.display())).exists(),
            "WAL sidecar must not be removed when stopping services failed"
        );

        // Case B: Tamper with MANIFEST.sha256 -> restore MUST fail closed before stopping services or copying
        let manifest_path = snap.manifest_path.as_ref().unwrap();
        let original_manifest = fs::read_to_string(manifest_path).unwrap();
        fs::write(
            manifest_path,
            format!(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  {}.bak\n",
                cfg.sqlite_db
            ),
        )
        .unwrap();

        let mut stop_called = false;
        let tamper_err = restore_state_if_corrupted(
            &cfg,
            &resolved,
            &release_dir,
            false,
            |_db| {
                stop_called = true;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(
            tamper_err.to_string().contains("SHA-256 mismatch"),
            "expected SHA-256 mismatch error, got: {}",
            tamper_err
        );
        assert!(
            !stop_called,
            "services should not even be stopped if snapshot manifest verification fails"
        );

        // Restore valid manifest -> restore succeeds atomically and recovers original marker
        fs::write(manifest_path, original_manifest).unwrap();
        let ok_report =
            restore_state_if_corrupted(&cfg, &resolved, &release_dir, false, |_db| Ok(())).unwrap();
        assert!(ok_report.restored_from_snapshot);
        assert!(ok_report.quarantined_corrupted_path.is_some());
        assert_eq!(read_sqlite_marker(&live_db), "clean-v4-state");
    }

    #[test]
    fn test_regression_interrupted_post_swap_deploy_blocks_overwrite_until_rollback() {
        let sb = TempSandbox::new("interrupted-recovery");
        let mut cfg = ReleaseConfig::for_root(sb.path());
        cfg.health_interval = Duration::from_millis(1);

        let tar_path = sb.path().join("release.tar.gz");
        let (_, manifest) = build_synthetic_release_tarball(
            &tar_path,
            &cfg.artifact_name,
            &[
                ("aetherflow-api", b"binary", EntryType::Regular),
                (".version", b"v4.0.0\n", EntryType::Regular),
            ],
        );

        let provider = MockArtifactProvider {
            resolved_tag: Ok("v4.0.0".to_string()),
            archive_source: tar_path,
            manifest_content: manifest,
        };
        let lifecycle = MockLifecycle::default();
        let prober = MockHealthProber::new(vec![
            Ok(HealthCheckAttempt {
                http_status: 200,
                body: r#"{"status":"ready"}"#.to_string(),
            }),
            Ok(HealthCheckAttempt {
                http_status: 200,
                body: r#"{"status":"ready"}"#.to_string(),
            }),
        ]);

        let engine = ReleaseEngine::new(cfg.clone(), provider, lifecycle, prober);
        let deploy_opts = ReleaseOptions::default();

        // 1. Deploy good release R1
        let r1 = match engine.execute(&deploy_opts).unwrap() {
            ReleaseOutcome::Deploy(r) => r,
            _ => panic!("expected deploy"),
        };

        // 2. Simulate an interrupted unhealthy deployment R2 that crashed right after Stage 2 symlink swap
        // (`current` points to broken R2, `.previous_release` points to R1, `.recovery_state.json` is in Stage3HealthProbe)
        let broken_r2 = cfg.releases_dir.join("9999999999");
        create_new_dir_exclusive(&broken_r2, 0o755, 0o755).unwrap();
        perform_symlink_swap(
            &cfg.releases_dir,
            &cfg.current_link,
            &broken_r2,
            "9999999999",
        )
        .unwrap();

        let mut crashed_state =
            RecoveryState::new(ReleaseCommand::Deploy, ReleaseChannel::Stable, false);
        crashed_state.phase = ReleasePhase::Stage3HealthProbe;
        crashed_state.candidate_release = Some(broken_r2.clone());
        crashed_state.previous_release = Some(r1.release_dir.clone());
        crashed_state.save(&cfg.releases_dir).unwrap();

        // 3. Attempting a new `deploy` while R2 is unfinished MUST fail closed so `.previous_release` (R1)
        // is not overwritten with broken R2!
        let blocked_err = engine.execute(&deploy_opts).unwrap_err();
        assert_eq!(blocked_err.exit_code(), ExitCode::RollbackFailed);
        assert!(blocked_err
            .to_string()
            .contains("unfinished after symlink swap"));
        assert_eq!(
            canonicalize_preserve_normal(&read_previous_release(&cfg.releases_dir).unwrap()),
            canonicalize_preserve_normal(&r1.release_dir),
            "known-good .previous_release (R1) must remain intact"
        );

        // 4. Running `rollback` recovers cleanly back to R1 and marks recovery state Complete
        let rollback_opts = ReleaseOptions {
            command: ReleaseCommand::Rollback,
            ..ReleaseOptions::default()
        };
        let rb = match engine.execute(&rollback_opts).unwrap() {
            ReleaseOutcome::Rollback(r) => r,
            _ => panic!("expected rollback"),
        };
        assert_eq!(
            canonicalize_preserve_normal(&rb.reverted_to),
            canonicalize_preserve_normal(&r1.release_dir)
        );
        assert_eq!(
            read_current_link_target(&cfg.current_link).unwrap(),
            canonicalize_preserve_normal(&r1.release_dir)
        );
        assert_eq!(
            RecoveryState::load(&cfg.releases_dir).unwrap().unwrap().phase,
            ReleasePhase::Complete
        );

        // 5. Subsequent deploy now succeeds cleanly
        let r3 = match engine.execute(&deploy_opts).unwrap() {
            ReleaseOutcome::Deploy(r) => r,
            _ => panic!("expected deploy after rollback"),
        };
        assert_eq!(
            canonicalize_preserve_normal(&r3.previous_release.unwrap()),
            canonicalize_preserve_normal(&r1.release_dir)
        );
    }

    #[test]
    fn test_regression_snapshot_and_recovery_permissions_and_cleanup_state() {
        let sb = TempSandbox::new("perms-and-state");
        let cfg = ReleaseConfig::for_root(sb.path());
        let live_db = cfg.host_data_dir.join(&cfg.sqlite_db);
        seed_valid_sqlite_db(&live_db, "secret-data");

        // Legacy .env migration in Stage 0
        fs::create_dir_all(cfg.legacy_opt_root.join("backend")).unwrap();
        fs::write(
            cfg.legacy_opt_root.join("backend/.env"),
            "JWT_SECRET=topsecret\n",
        )
        .unwrap();

        let provider = MockArtifactProvider {
            resolved_tag: Ok("v4.0.0".to_string()),
            archive_source: PathBuf::new(),
            manifest_content: String::new(),
        };
        let engine = ReleaseEngine::new(
            cfg.clone(),
            provider,
            MockLifecycle::default(),
            MockHealthProber::new(vec![]),
        );

        let resolved = engine.ensure_fhs_layout(&cfg, false).unwrap();
        let release_dir = cfg.releases_dir.join("1700000002");
        create_new_dir_exclusive(&release_dir, 0o755, 0o755).unwrap();
        let snap = create_state_snapshot(&cfg, &resolved, &release_dir, false).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let data_dir_mode = fs::symlink_metadata(&cfg.data_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(data_dir_mode, 0o700, "data_dir must be 0700");

            let env_mode = fs::symlink_metadata(&cfg.host_env_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(env_mode, 0o600, "migrated .env must be 0600");

            let snap_dir = release_dir.join("data-snapshot");
            let snap_dir_mode = fs::symlink_metadata(&snap_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(snap_dir_mode, 0o700, "data-snapshot dir must be 0700");

            let bak_mode = fs::symlink_metadata(snap.backup_path.as_ref().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(bak_mode, 0o600, "snapshot .bak must be 0600");

            let manifest_mode = fs::symlink_metadata(snap.manifest_path.as_ref().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(manifest_mode, 0o600, "MANIFEST.sha256 must be 0600");
        }
        let _ = snap;

        // Verify `cleanup` and `migrate-systemd` persist started/completed recovery state
        let cleanup_opts = ReleaseOptions {
            command: ReleaseCommand::Cleanup,
            ..ReleaseOptions::default()
        };
        engine.execute(&cleanup_opts).unwrap();
        let rec_cleanup = RecoveryState::load(&cfg.releases_dir).unwrap().unwrap();
        assert_eq!(rec_cleanup.command, ReleaseCommand::Cleanup);
        assert_eq!(rec_cleanup.phase, ReleasePhase::Complete);

        let migrate_opts = ReleaseOptions {
            command: ReleaseCommand::MigrateSystemd,
            dry_run: true,
            ..ReleaseOptions::default()
        };
        engine.execute(&migrate_opts).unwrap();
        let rec_mig = RecoveryState::load(&cfg.with_dry_run(true).releases_dir).unwrap().unwrap();
        assert_eq!(rec_mig.command, ReleaseCommand::MigrateSystemd);
        assert_eq!(rec_mig.phase, ReleasePhase::Complete);
    }
    #[cfg(unix)]
    #[test]
    fn test_current_unit_source_only_allows_managed_release_link() {
        use std::os::unix::fs::symlink;
        let sandbox = TempSandbox::new("unit-source-link");
        let config = ReleaseConfig::for_root(sandbox.path());
        let release = config.releases_dir.join("1700000003");
        fs::create_dir_all(release.join("deploy/systemd")).unwrap();
        symlink(&release, &config.current_link).unwrap();
        assert_eq!(crate::health::packaged_systemd_directory(&config).unwrap(), release.join("deploy/systemd"));
        fs::remove_file(&config.current_link).unwrap();
        let outside = sandbox.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, &config.current_link).unwrap();
        assert!(crate::health::packaged_systemd_directory(&config).is_err());
        fs::remove_file(&config.current_link).unwrap();
        fs::remove_dir_all(&release).unwrap();
        symlink(&outside, &release).unwrap();
        symlink(&release, &config.current_link).unwrap();
        assert!(crate::health::packaged_systemd_directory(&config).is_err());
        let regular_file = sandbox.path().join("regular");
        fs::write(&regular_file, "not a directory").unwrap();
        assert!(ensure_no_symlink_ancestors(&regular_file.join("child")).is_err());
    }

    #[test]
    fn test_select_release_tag_from_json_channel_isolation() {
        let payload = r#"[
            {"tag_name": "v4.0.0-experimental", "target_commitish": "experimental", "prerelease": true, "draft": false},
            {"tag_name": "v3.3.0-nightly.1", "target_commitish": "nightly", "prerelease": true, "draft": false},
            {"tag_name": "v3.2.7", "target_commitish": "master", "prerelease": false, "draft": false}
        ]"#;

        assert_eq!(
            select_release_tag_from_json(ReleaseChannel::Stable, payload).unwrap(),
            "v3.2.7"
        );
        // Nightly must ignore v4.0.0-experimental and select v3.3.0-nightly.1
        assert_eq!(
            select_release_tag_from_json(ReleaseChannel::Nightly, payload).unwrap(),
            "v3.3.0-nightly.1"
        );
        assert_eq!(
            select_release_tag_from_json("experimental".parse::<ReleaseChannel>().unwrap(), payload).unwrap(),
            "v3.3.0-nightly.1"
        );
    }

    #[test]
    fn test_parse_stable_tag_from_redirect_url_validation() {
        assert_eq!(
            parse_stable_tag_from_redirect_url(
                "https://github.com/McEveritts/AetherFlow/releases/tag/v3.2.7",
                "https://github.com",
                "McEveritts/AetherFlow"
            )
            .unwrap(),
            "v3.2.7"
        );
        // Prerelease / hyphenated tags must be rejected by stable redirect parser
        assert!(
            parse_stable_tag_from_redirect_url(
                "https://github.com/McEveritts/AetherFlow/releases/tag/v4.0.0-experimental",
                "https://github.com",
                "McEveritts/AetherFlow"
            )
            .is_err()
        );
        // Unredirected /releases/latest URL must return Err
        assert!(
            parse_stable_tag_from_redirect_url(
                "https://github.com/McEveritts/AetherFlow/releases/latest",
                "https://github.com",
                "McEveritts/AetherFlow"
            )
            .is_err()
        );
    }

    #[test]
    fn test_regression_conf_serialization_roundtrip_and_strict_rejection() {
        let sandbox = TempSandbox::new("conf-roundtrip");
        let mut cfg = ReleaseConfig::for_root(sandbox.path());
        cfg.git_branch = "feat/quote\"backslash\\dollar$tick`tab\t".to_string();
        let conf_path = sandbox.path().join("serialized.conf");
        cfg.write_protected_config_file(&conf_path).unwrap();

        let parsed = parse_conf_file(&conf_path).unwrap();
        assert_eq!(
            parsed.get("GIT_BRANCH").map(|val| val.as_str()),
            Some("feat/quote\"backslash\\dollar$tick`tab\t")
        );

        let bad_conf = sandbox.path().join("bad-unterminated.conf");
        fs::write(&bad_conf, "RELEASES_DIR=\"/unterminated\n").unwrap();
        assert!(parse_conf_file(&bad_conf).is_err());

        let bad_sub = sandbox.path().join("bad-cmdsub.conf");
        fs::write(&bad_sub, "RELEASES_DIR=\"$(id)\"\n").unwrap();
        assert!(parse_conf_file(&bad_sub).is_err());
    }

    #[test]
    fn test_regression_isolated_root_db_and_systemd_and_cli_containment() {
        let sandbox = TempSandbox::new("isolated-containment");
        let mut cfg = ReleaseConfig::for_root(sandbox.path());
        fs::create_dir_all(&cfg.env_dir).unwrap();

        let host_blob = "Environment=\"DB_PATH=/var/lib/aetherflow/aetherflow.sqlite\"\n";
        let resolved_default = try_resolve_db_path(&cfg, Some(host_blob)).unwrap();
        assert_eq!(
            resolved_default.path,
            cfg.host_data_dir.join("aetherflow.sqlite")
        );
        assert_eq!(resolved_default.source, DbPathSource::DataDirDefault);

        fs::write(&cfg.host_env_file, "DB_PATH=/var/lib/aetherflow/outside.sqlite\n").unwrap();
        assert!(try_resolve_db_path(&cfg, None).is_err());

        let inside_a = sandbox.path().join("var/lib/aetherflow/a.sqlite");
        let inside_b = sandbox.path().join("var/lib/aetherflow/b.sqlite");
        fs::write(
            &cfg.host_env_file,
            format!(
                "DB_PATH={}\nAETHERFLOW_DB_PATH={}\n",
                inside_a.display(),
                inside_b.display()
            ),
        )
        .unwrap();
        assert!(try_resolve_db_path(&cfg, None).is_err());

        fs::write(&cfg.host_env_file, format!("DB_PATH={}\n", inside_a.display())).unwrap();
        let resolved_inside = try_resolve_db_path(&cfg, None).unwrap();
        assert_eq!(resolved_inside.path, inside_a);

        let lock_path = resolve_maintenance_lock_path_for_config(&cfg).unwrap();
        assert_eq!(
            lock_path,
            sandbox.path().join("var/lib/aetherflow/.snapshot.lock")
        );

        let jobs_dir = resolve_self_update_jobs_dir_for_config(&cfg).unwrap();
        assert_eq!(
            jobs_dir,
            sandbox.path().join("var/lib/aetherflow/.self-update-jobs")
        );

        assert!(verify_isolated_systemd_lifecycle_authorized(&cfg).is_err());

        cfg.cli_bin_dir = PathBuf::from("/usr/local/bin");
        assert!(sync_cli_entrypoints(&cfg, "100").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_prepare_release_permissions_normalizes_modes_and_verifies_binaries() {
        use std::os::unix::fs::PermissionsExt;

        let sb = TempSandbox::new("release-perms");
        let release_dir = sb.path().join("release");
        fs::create_dir_all(release_dir.join("config")).unwrap();
        fs::write(release_dir.join("aetherflow-api"), b"#!/bin/sh\nexit 0\n").unwrap();
        fs::write(release_dir.join("af"), b"#!/bin/sh\nexit 0\n").unwrap();
        fs::write(release_dir.join(".version"), b"v4.0.0\n").unwrap();
        fs::write(release_dir.join("config/app.json"), b"{}").unwrap();

        // Start with restrictive/group-writable permissions to ensure prepare_release_permissions fixes them
        fs::set_permissions(&release_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(release_dir.join("config"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            release_dir.join("aetherflow-api"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::set_permissions(release_dir.join("af"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(
            release_dir.join(".version"),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();

        prepare_release_permissions(&release_dir).unwrap();

        assert_eq!(
            fs::symlink_metadata(&release_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::symlink_metadata(release_dir.join("config"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::symlink_metadata(release_dir.join("aetherflow-api"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::symlink_metadata(release_dir.join("af"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::symlink_metadata(release_dir.join(".version"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_regression_create_dir_all_no_symlinks_preserves_existing_parent_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let sandbox = TempSandbox::new("preserve-parent-mode");
        let sticky_parent = sandbox.path().join("sticky-tmp");
        fs::create_dir_all(&sticky_parent).unwrap();
        fs::set_permissions(&sticky_parent, fs::Permissions::from_mode(0o1777)).unwrap();

        let child_dir = sticky_parent.join("nested-private");
        create_dir_all_no_symlinks(&child_dir, 0o750).unwrap();

        let parent_mode = fs::symlink_metadata(&sticky_parent)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(parent_mode, 0o1777);

        let child_mode = fs::symlink_metadata(&child_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(child_mode, 0o750);
    }
}
