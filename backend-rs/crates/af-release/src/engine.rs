//! Orchestration engine implementing Stage 0 through Stage 6 of `deploy/release-manager.sh`,
//! structured JSONL deployment logging, and administrative status/inspection APIs.

use crate::artifact::{
    extract_and_validate_release_archive, simulate_offline_artifact, verify_artifact_checksum,
    ArtifactProvider, GithubHttpArtifactProvider,
};
use crate::config::{
    try_resolve_db_path, ReleaseChannel, ReleaseCommand, ReleaseConfig, ReleaseOptions,
    ResolvedDbPath,
};
use crate::error::{ReleaseError, ReleaseResult};
use crate::fs_security::{
    apply_data_dir_ownership_and_mode, apply_service_ownership, atomic_copy_file_with_mode,
    create_dir_all_no_symlinks, create_new_dir_exclusive, ensure_no_symlink_ancestors,
    set_dir_mode, OwnershipMetadata,
};
use crate::health::{
    poll_readiness_probe, sync_cli_entrypoints, verify_isolated_systemd_lifecycle_authorized,
    HealthProber, LifecycleController, ReqwestHealthProber, SystemdLifecycleController,
};
use crate::lock::{RecoveryState, ReleaseLockGuard, ReleasePhase};
use crate::snapshot::{
    create_state_snapshot, restore_state_if_corrupted, sqlite_online_backup, RestoreReport,
    SnapshotReport,
};
use crate::symlink::{
    atomic_replace_symlink, canonicalize_preserve_normal, cleanup_old_releases,
    perform_symlink_swap, read_current_link_target, read_previous_release, write_previous_release,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static EPOCH_MONOTONIC_SEQ: AtomicU64 = AtomicU64::new(0);

/// Generates a unique monotonic epoch release identifier (matching `EPOCH="$(date +%s)"`,
/// while guaranteeing uniqueness if multiple deployments occur within the same second in tests)
/// and ensures the candidate directory does not already exist under `releases_dir`.
fn allocate_unique_release_epoch_id(releases_dir: &Path) -> String {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    loop {
        let prev = EPOCH_MONOTONIC_SEQ.load(Ordering::SeqCst);
        let next = if now_secs > prev { now_secs } else { prev + 1 };
        EPOCH_MONOTONIC_SEQ.store(next, Ordering::SeqCst);
        let candidate_id = next.to_string();
        if fs::symlink_metadata(releases_dir.join(&candidate_id)).is_err() {
            return candidate_id;
        }
    }
}
/// Structured JSONL log line matching `log()` in `deploy/release-manager.sh`:
/// `{"ts":"2026-10-31T20:00:00Z","level":"INFO","msg":"..."}`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseLogEntry {
    pub ts: String,
    pub level: String,
    pub msg: String,
}

/// Appends a JSONL log line to `log_file` and emits via `tracing`.
pub fn append_jsonl_log(log_file: &Path, level: &str, msg: &str) {
    let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let entry = ReleaseLogEntry {
        ts,
        level: level.to_string(),
        msg: msg.to_string(),
    };
    if let Ok(serialized) = serde_json::to_string(&entry) {
        if let Some(parent) = log_file.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_file) {
            let _ = writeln!(file, "{}", serialized);
        }
    }
    match level {
        "ERROR" | "FATAL" | "CRITICAL" => tracing::error!(level = level, "{}", msg),
        "WARN" => tracing::warn!(level = level, "{}", msg),
        _ => tracing::info!(level = level, "{}", msg),
    }
}

/// Summary report returned by a successful `deploy` execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployReport {
    pub epoch_id: String,
    pub channel: ReleaseChannel,
    pub release_tag: String,
    pub release_dir: PathBuf,
    pub current_link: PathBuf,
    pub previous_release: Option<PathBuf>,
    pub resolved_db: ResolvedDbPath,
    pub snapshot: SnapshotReport,
    pub health_status: Option<String>,
    pub pruned_releases: Vec<PathBuf>,
    pub dry_run: bool,
    pub offline: bool,
}

/// Summary report returned by a `rollback` execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReport {
    pub reverted_to: PathBuf,
    pub snapshot_release: PathBuf,
    pub resolved_db: ResolvedDbPath,
    pub restore_report: Option<RestoreReport>,
    pub restore_error: Option<String>,
    pub dry_run: bool,
}

/// Summary report returned by a `cleanup` execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupReport {
    pub retained_max: usize,
    pub pruned_releases: Vec<PathBuf>,
}

/// Summary report returned by a `migrate-systemd` execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateSystemdReport {
    pub resolved_db: ResolvedDbPath,
    pub health_status: Option<String>,
    pub dry_run: bool,
}

/// Unified outcome returned by [`ReleaseEngine::execute`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case")]
pub enum ReleaseOutcome {
    Deploy(DeployReport),
    Rollback(RollbackReport),
    Cleanup(CleanupReport),
    MigrateSystemd(MigrateSystemdReport),
}

/// Administrative status snapshot of the release engine layout on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseEngineStatus {
    pub current_release: Option<PathBuf>,
    pub current_version: Option<String>,
    pub previous_release: Option<PathBuf>,
    pub available_releases: Vec<PathBuf>,
    pub resolved_db: ResolvedDbPath,
    pub recovery_state: Option<RecoveryState>,
}

/// Reusable, dependency-injected Rust release engine replacing `deploy/release-manager.sh`.
pub struct ReleaseEngine<A, L, H>
where
    A: ArtifactProvider,
    L: LifecycleController,
    H: HealthProber,
{
    base_config: ReleaseConfig,
    artifact_provider: A,
    lifecycle: L,
    health_prober: H,
}

impl
    ReleaseEngine<
        GithubHttpArtifactProvider,
        SystemdLifecycleController,
        ReqwestHealthProber,
    >
{
    /// Constructs a production `ReleaseEngine` wired to GitHub Releases HTTP, bare-metal `systemctl`,
    /// and `/health/ready` probing.
    pub fn new_production(base_config: ReleaseConfig) -> Self {
        Self {
            base_config,
            artifact_provider: GithubHttpArtifactProvider::default(),
            lifecycle: SystemdLifecycleController,
            health_prober: ReqwestHealthProber,
        }
    }
}

impl<A, L, H> ReleaseEngine<A, L, H>
where
    A: ArtifactProvider,
    L: LifecycleController,
    H: HealthProber,
{
    /// Constructs a `ReleaseEngine` with custom artifact, lifecycle, and health prober implementations.
    pub fn new(
        base_config: ReleaseConfig,
        artifact_provider: A,
        lifecycle: L,
        health_prober: H,
    ) -> Self {
        Self {
            base_config,
            artifact_provider,
            lifecycle,
            health_prober,
        }
    }

    pub fn config(&self) -> &ReleaseConfig {
        &self.base_config
    }

    /// Inspects the current immutable-release directory layout, active version, resolved DB path,
    /// and any persisted `.recovery_state.json` without mutating host state.
    pub fn inspect_status(&self) -> ReleaseResult<ReleaseEngineStatus> {
        let unit_env = if self.base_config.isolated_root.is_some() {
            None
        } else {
            self.lifecycle.query_unit_environment("aetherflow-api")
        };
        let resolved_db = try_resolve_db_path(&self.base_config, unit_env.as_deref())?;
        let current_release = read_current_link_target(&self.base_config.current_link);
        let current_version = current_release
            .as_ref()
            .and_then(|dir| fs::read_to_string(dir.join(".version")).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let previous_release = fs::read_to_string(self.base_config.releases_dir.join(".previous_release"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        let mut available_releases = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.base_config.releases_dir) {
            for e in entries.flatten() {
                if let Ok(ft) = e.file_type() {
                    if ft.is_dir() && !e.file_name().to_string_lossy().starts_with('.') {
                        available_releases.push(e.path());
                    }
                }
            }
        }
        available_releases.sort();

        let recovery_state = RecoveryState::load(&self.base_config.releases_dir)?;

        Ok(ReleaseEngineStatus {
            current_release,
            current_version,
            previous_release,
            available_releases,
            resolved_db,
            recovery_state,
        })
    }

    /// Executes any `ReleaseOptions` command (`deploy`, `rollback`, `cleanup`, `migrate-systemd`)
    /// under an exclusive engine lock and the shared cross-process maintenance lock.
    pub fn execute(&self, opts: &ReleaseOptions) -> ReleaseResult<ReleaseOutcome> {
        opts.validate()?;
        let effective_cfg = self.base_config.with_dry_run(opts.dry_run);
        effective_cfg.validate()?;

        if !opts.dry_run
            && self.lifecycle.requires_isolated_systemd_authorization()
            && matches!(
                opts.command,
                ReleaseCommand::Deploy | ReleaseCommand::Rollback | ReleaseCommand::MigrateSystemd
            )
        {
            verify_isolated_systemd_lifecycle_authorized(&effective_cfg)?;
        }

        ensure_no_symlink_ancestors(&effective_cfg.releases_dir)?;
        create_dir_all_no_symlinks(&effective_cfg.releases_dir, 0o755)?;

        let shared_lock_path =
            crate::admin::ensure_interoperable_maintenance_lock_file(&effective_cfg)?;
        let _shared_maintenance_lock =
            ReleaseLockGuard::acquire(&shared_lock_path, effective_cfg.snapshot_timeout)?;

        if !opts.dry_run {
            crate::admin::ensure_no_active_package_lifecycle_jobs(&effective_cfg, opts.command)?;
        }

        let lock_path = effective_cfg.releases_dir.join(".release.lock");
        let _engine_lock = ReleaseLockGuard::acquire(&lock_path, effective_cfg.snapshot_timeout)?;

        self.guard_unfinished_recovery_state(&effective_cfg, opts)?;

        match opts.command {
            ReleaseCommand::Deploy => {
                let report = self.run_deploy_locked(&effective_cfg, opts)?;
                Ok(ReleaseOutcome::Deploy(report))
            }
            ReleaseCommand::Rollback => {
                let report = self.run_rollback_locked(&effective_cfg, opts.dry_run, None)?;
                Ok(ReleaseOutcome::Rollback(report))
            }
            ReleaseCommand::Cleanup => {
                let report = self.run_cleanup_locked(&effective_cfg, opts.dry_run)?;
                Ok(ReleaseOutcome::Cleanup(report))
            }
            ReleaseCommand::MigrateSystemd => {
                let report = self.run_migrate_systemd_locked(&effective_cfg, opts.dry_run)?;
                Ok(ReleaseOutcome::MigrateSystemd(report))
            }
        }
    }

    fn guard_unfinished_recovery_state(
        &self,
        cfg: &ReleaseConfig,
        opts: &ReleaseOptions,
    ) -> ReleaseResult<()> {
        let Some(existing) = RecoveryState::load(&cfg.releases_dir)? else {
            return Ok(());
        };
        if !existing.is_unfinished() {
            return Ok(());
        }

        if existing.has_unhealthy_or_interrupted_post_swap_deploy() {
            match opts.command {
                ReleaseCommand::Rollback => {
                    if let Some(ref good_prev) = existing.previous_release {
                        if good_prev.is_dir() {
                            let _ = write_previous_release(&cfg.releases_dir, good_prev);
                        }
                    }
                    return Ok(());
                }
                other_cmd => {
                    return Err(ReleaseError::Rollback(format!(
                        "refusing to run '{}' while an interrupted deployment (operation_id={}, phase={:?}, candidate={:?}, previous_release={:?}) is unfinished after symlink swap; run 'rollback' first so the last known-good '.previous_release' pointer is not overwritten",
                        other_cmd,
                        existing.operation_id,
                        existing.phase,
                        existing.candidate_release,
                        existing.previous_release
                    )));
                }
            }
        }

        if matches!(
            existing.phase,
            ReleasePhase::Stage0FhsLayout
                | ReleasePhase::Stage1Scaffold
                | ReleasePhase::Stage1_5Snapshot
        ) {
            if let Some(ref cand) = existing.candidate_release {
                let current_target = read_current_link_target(&cfg.current_link);
                let prev_target = read_previous_release(&cfg.releases_dir).ok();
                let canon_cand = canonicalize_preserve_normal(cand);
                let is_active = current_target
                    .as_ref()
                    .map(|c| c == &canon_cand || c == cand)
                    .unwrap_or(false);
                let is_prev = prev_target
                    .as_ref()
                    .map(|p| canonicalize_preserve_normal(p) == canon_cand || p == cand)
                    .unwrap_or(false);
                if !is_active && !is_prev && cand.starts_with(&cfg.releases_dir) && cand.is_dir() {
                    let _ = fs::remove_dir_all(cand);
                }
            }
        }

        Ok(())
    }

    /// Stage 0: Verifies FHS State & Secret Layout and resolves the live SQLite database path.
    pub fn ensure_fhs_layout(
        &self,
        cfg: &ReleaseConfig,
        dry_run: bool,
    ) -> ReleaseResult<ResolvedDbPath> {
        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            "=== STAGE 0: Verifying FHS State & Secret Layout ===",
        );

        create_dir_all_no_symlinks(&cfg.releases_dir, 0o755)?;
        create_dir_all_no_symlinks(&cfg.data_dir, 0o700)?;
        create_dir_all_no_symlinks(&cfg.env_dir, 0o755)?;
        if dry_run {
            set_dir_mode(&cfg.data_dir, 0o700)?;
            let _ = create_dir_all_no_symlinks(&cfg.repo_dir, 0o755);
        } else {
            apply_data_dir_ownership_and_mode(&cfg.data_dir)?;
        }

        let unit_env = if cfg.isolated_root.is_some() {
            None
        } else {
            self.lifecycle.query_unit_environment("aetherflow-api")
        };
        let resolved = try_resolve_db_path(cfg, unit_env.as_deref())?;
        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            &format!(
                "Resolved database path: {} (source: {})",
                resolved.path.display(),
                resolved.source
            ),
        );

        let fhs_db = cfg.host_data_dir.join(&cfg.sqlite_db);
        if resolved.path == fhs_db && !fhs_db.is_file() {
            let legacy_candidates = [
                cfg.legacy_opt_root
                    .join("backend/data")
                    .join(&cfg.sqlite_db),
                cfg.legacy_opt_root.join("backend").join(&cfg.sqlite_db),
            ];
            for legacy_db in &legacy_candidates {
                if legacy_db.is_file() {
                    if dry_run {
                        append_jsonl_log(
                            &cfg.log_file,
                            "INFO",
                            &format!(
                                "[DRY-RUN] Would migrate legacy SQLite database from {} to {}; dry-run does not write outside {}.",
                                legacy_db.display(),
                                fhs_db.display(),
                                cfg.dry_run_root.display()
                            ),
                        );
                        break;
                    }
                    append_jsonl_log(
                        &cfg.log_file,
                        "INFO",
                        &format!(
                            "Migrating legacy SQLite database from {} to {}...",
                            legacy_db.display(),
                            fhs_db.display()
                        ),
                    );
                    if let Some(parent) = fhs_db.parent() {
                        create_dir_all_no_symlinks(parent, 0o700)?;
                    }
                    let legacy_owner = OwnershipMetadata::capture(legacy_db);
                    sqlite_online_backup(legacy_db, &fhs_db)?;
                    apply_service_ownership(&fhs_db, legacy_owner.as_ref(), 0o600)?;
                    break;
                }
            }
        } else if resolved.path != fhs_db {
            append_jsonl_log(
                &cfg.log_file,
                "INFO",
                &format!(
                    "Skipping legacy database copy into {}; live database is {} (source: {}).",
                    fhs_db.display(),
                    resolved.path.display(),
                    resolved.source
                ),
            );
        }

        if !dry_run && !cfg.host_env_file.is_file() {
            let legacy_envs = [
                cfg.legacy_opt_root.join("backend/.env"),
                cfg.legacy_opt_root.join(".env"),
            ];
            for legacy_env in &legacy_envs {
                if legacy_env.is_file() {
                    append_jsonl_log(
                        &cfg.log_file,
                        "INFO",
                        &format!(
                            "Migrating legacy environment secrets from {} to {}...",
                            legacy_env.display(),
                            cfg.host_env_file.display()
                        ),
                    );
                    if let Some(parent) = cfg.host_env_file.parent() {
                        create_dir_all_no_symlinks(parent, 0o755)?;
                    }
                    let legacy_env_owner = OwnershipMetadata::capture(legacy_env);
                    atomic_copy_file_with_mode(
                        legacy_env,
                        &cfg.host_env_file,
                        0o600,
                        legacy_env_owner.as_ref(),
                    )?;
                    break;
                }
            }
        }

        Ok(resolved)
    }

    fn run_deploy_locked(
        &self,
        cfg: &ReleaseConfig,
        opts: &ReleaseOptions,
    ) -> ReleaseResult<DeployReport> {
        let mut recovery = RecoveryState::new(ReleaseCommand::Deploy, opts.channel, opts.dry_run);
        recovery.phase = ReleasePhase::Stage0FhsLayout;
        recovery.save(&cfg.releases_dir)?;

        let resolved_db = match self.ensure_fhs_layout(cfg, opts.dry_run) {
            Ok(r) => r,
            Err(e) => {
                recovery.phase = ReleasePhase::Failed;
                recovery.last_error = Some(e.to_string());
                let _ = recovery.save(&cfg.releases_dir);
                return Err(e);
            }
        };
        recovery.resolved_db_path = Some(resolved_db.path.clone());
        recovery.resolved_db_source = Some(resolved_db.source.to_string());

        let epoch_id = allocate_unique_release_epoch_id(&cfg.releases_dir);
        let release_dir = cfg.releases_dir.join(&epoch_id);
        recovery.candidate_release = Some(release_dir.clone());
        recovery.phase = ReleasePhase::Stage1Scaffold;
        recovery.save(&cfg.releases_dir)?;

        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            &format!("=== STAGE 1: Release Scaffold (Channel: {}) ===", opts.channel),
        );
        if let Err(err) = create_new_dir_exclusive(&release_dir, 0o755, 0o755) {
            recovery.phase = ReleasePhase::Failed;
            recovery.last_error = Some(err.to_string());
            let _ = recovery.save(&cfg.releases_dir);
            append_jsonl_log(&cfg.log_file, "ERROR", &err.to_string());
            return Err(err);
        }

        let release_tag = match self.stage_1_scaffold(cfg, opts, &release_dir) {
            Ok(tag) => tag,
            Err(err) => {
                let _ = fs::remove_dir_all(&release_dir);
                recovery.phase = ReleasePhase::Failed;
                recovery.last_error = Some(err.to_string());
                let _ = recovery.save(&cfg.releases_dir);
                append_jsonl_log(&cfg.log_file, "ERROR", &err.to_string());
                return Err(err);
            }
        };

        if let Err(err) = crate::artifact::prepare_release_permissions(&release_dir) {
            let _ = fs::remove_dir_all(&release_dir);
            recovery.phase = ReleasePhase::Failed;
            recovery.last_error = Some(err.to_string());
            let _ = recovery.save(&cfg.releases_dir);
            append_jsonl_log(&cfg.log_file, "ERROR", &err.to_string());
            return Err(err);
        }
        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            "Release permissions normalized and service access verified.",
        );

        // STAGE 1.5: State Snapshot
        recovery.phase = ReleasePhase::Stage1_5Snapshot;
        recovery.save(&cfg.releases_dir)?;
        append_jsonl_log(&cfg.log_file, "INFO", "=== STAGE 1.5: State Snapshot ===");

        let snapshot = match create_state_snapshot(cfg, &resolved_db, &release_dir, opts.dry_run) {
            Ok(snap) => {
                if let Some(ref bak) = snap.backup_path {
                    append_jsonl_log(
                        &cfg.log_file,
                        "INFO",
                        &format!("Snapshot integrity check PASSED: {}", bak.display()),
                    );
                } else {
                    append_jsonl_log(
                        &cfg.log_file,
                        "WARN",
                        &format!(
                            "No database file at {}; skipping snapshot.",
                            resolved_db.path.display()
                        ),
                    );
                }
                append_jsonl_log(
                    &cfg.log_file,
                    "INFO",
                    "=== STAGE 1.5 COMPLETE: State snapshot captured ===",
                );
                snap
            }
            Err(err) => {
                let _ = fs::remove_dir_all(&release_dir);
                recovery.phase = ReleasePhase::Failed;
                recovery.last_error = Some(err.to_string());
                let _ = recovery.save(&cfg.releases_dir);
                append_jsonl_log(&cfg.log_file, "ERROR", &err.to_string());
                return Err(err);
            }
        };
        recovery.snapshot_path = snapshot.backup_path.clone();
        recovery.save(&cfg.releases_dir)?;

        let prior_previous_release = read_previous_release(&cfg.releases_dir).ok();
        let current_before_swap = read_current_link_target(&cfg.current_link);
        recovery.previous_release = current_before_swap
            .clone()
            .or_else(|| prior_previous_release.clone());
        recovery.phase = ReleasePhase::Stage2SymlinkSwap;
        recovery.save(&cfg.releases_dir)?;
        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            "=== STAGE 2: Atomic Symlink Swap ===",
        );

        let previous_release = match perform_symlink_swap(
            &cfg.releases_dir,
            &cfg.current_link,
            &release_dir,
            &epoch_id,
        ) {
            Ok(prev) => {
                sync_cli_entrypoints(cfg, &epoch_id)?;
                if let Some(ref p) = prev {
                    append_jsonl_log(
                        &cfg.log_file,
                        "INFO",
                        &format!("Previous release recorded: {}", p.display()),
                    );
                }
                append_jsonl_log(
                    &cfg.log_file,
                    "INFO",
                    &format!(
                        "Symlink updated atomically: {} -> {}",
                        cfg.current_link.display(),
                        release_dir.display()
                    ),
                );
                prev
            }
            Err(err) => {
                recovery.phase = ReleasePhase::Failed;
                recovery.last_error = Some(err.to_string());
                let _ = recovery.save(&cfg.releases_dir);
                append_jsonl_log(&cfg.log_file, "ERROR", &err.to_string());
                return Err(err);
            }
        };
        recovery.previous_release = previous_release.clone();
        recovery.save(&cfg.releases_dir)?;

        recovery.phase = ReleasePhase::Stage3HealthProbe;
        recovery.save(&cfg.releases_dir)?;
        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            "=== STAGE 3: Systemd Restart & Deep Readiness Probe ===",
        );

        let health_status = if opts.dry_run {
            append_jsonl_log(
                &cfg.log_file,
                "INFO",
                "[DRY-RUN] Skipping systemctl restart and health probe.",
            );
            None
        } else {
            match self.stage_3_restart_and_probe(cfg) {
                Ok(status) => {
                    append_jsonl_log(
                        &cfg.log_file,
                        "INFO",
                        &format!("Health probe PASSED (status={})", status),
                    );
                    Some(status)
                }
                Err(probe_err) => {
                    append_jsonl_log(&cfg.log_file, "ERROR", &probe_err.to_string());
                    recovery.phase = ReleasePhase::Stage4Rollback;
                    recovery.last_error = Some(probe_err.to_string());
                    let _ = recovery.save(&cfg.releases_dir);

                    match self.run_rollback_locked(cfg, opts.dry_run, Some(&release_dir)) {
                        Ok(rb_report) => {
                            if let Some(ref prior_prev) = prior_previous_release {
                                if prior_prev.is_dir()
                                    && canonicalize_preserve_normal(prior_prev)
                                        != canonicalize_preserve_normal(&rb_report.reverted_to)
                                {
                                    let _ = write_previous_release(&cfg.releases_dir, prior_prev);
                                }
                            }
                            let db_restored = rb_report
                                .restore_report
                                .as_ref()
                                .map(|r| r.restored_from_snapshot)
                                .unwrap_or(false);
                            return Err(ReleaseError::RolledBackAfterProbeFailure {
                                probe_error: probe_err.to_string(),
                                reverted_to: rb_report.reverted_to,
                                db_restored,
                            });
                        }
                        Err(rb_err) => {
                            recovery.phase = ReleasePhase::Stage4Rollback;
                            recovery.last_error = Some(format!(
                                "probe failed ({}) and rollback failed: {}",
                                probe_err, rb_err
                            ));
                            let _ = recovery.save(&cfg.releases_dir);
                            return Err(ReleaseError::Rollback(format!(
                                "probe failed ({}) and rollback also failed: {}",
                                probe_err, rb_err
                            )));
                        }
                    }
                }
            }
        };

        recovery.phase = ReleasePhase::Stage5Cleanup;
        recovery.save(&cfg.releases_dir)?;
        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            &format!(
                "=== STAGE 5: Pruning Old Releases (retaining {}) ===",
                cfg.max_releases
            ),
        );
        let pruned_releases =
            cleanup_old_releases(&cfg.releases_dir, &cfg.current_link, cfg.max_releases)?;
        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            &format!("Pruned {} old release(s).", pruned_releases.len()),
        );

        recovery.phase = ReleasePhase::Complete;
        recovery.save(&cfg.releases_dir)?;

        if opts.dry_run {
            append_jsonl_log(
                &cfg.log_file,
                "INFO",
                &format!(
                    "DRY-RUN SUCCESSFUL: Release {} ({}) staged at {}. Systemd was not restarted.",
                    epoch_id,
                    opts.channel,
                    cfg.current_link.display()
                ),
            );
        } else {
            append_jsonl_log(
                &cfg.log_file,
                "INFO",
                &format!(
                    "DEPLOYMENT SUCCESSFUL: Release {} ({}) is now live.",
                    epoch_id, opts.channel
                ),
            );
        }

        Ok(DeployReport {
            epoch_id,
            channel: opts.channel,
            release_tag,
            release_dir,
            current_link: cfg.current_link.clone(),
            previous_release,
            resolved_db,
            snapshot,
            health_status,
            pruned_releases,
            dry_run: opts.dry_run,
            offline: opts.offline,
        })
    }

    fn stage_1_scaffold(
        &self,
        cfg: &ReleaseConfig,
        opts: &ReleaseOptions,
        release_dir: &Path,
    ) -> ReleaseResult<String> {
        if opts.dry_run && opts.offline {
            append_jsonl_log(
                &cfg.log_file,
                "INFO",
                "[DRY-RUN] Offline mode: simulating single-binary artifact verification and extraction.",
            );
            return simulate_offline_artifact(release_dir, cfg);
        }

        let target_tag = self
            .artifact_provider
            .resolve_release_tag(cfg, opts.channel)?;
        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            &format!(
                "Resolved release tag {} for channel {}.",
                target_tag, opts.channel
            ),
        );

        let staging_dir = cfg.releases_dir.join(format!(
            ".staging-{}-{}-{}",
            target_tag,
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        create_new_dir_exclusive(&staging_dir, 0o755, 0o700)?;

        let bundle_res = self
            .artifact_provider
            .fetch_release_bundle(cfg, &target_tag, &staging_dir);
        let (archive_path, manifest_content) = match bundle_res {
            Ok(pair) => pair,
            Err(err) => {
                let _ = fs::remove_dir_all(&staging_dir);
                return Err(err);
            }
        };

        let digest_res =
            verify_artifact_checksum(&archive_path, &manifest_content, &cfg.artifact_name);
        let actual_digest = match digest_res {
            Ok(d) => d,
            Err(err) => {
                let _ = fs::remove_dir_all(&staging_dir);
                return Err(err);
            }
        };
        append_jsonl_log(&cfg.log_file, "INFO", &format!("SHA-256 OK {}", actual_digest));

        let extract_res =
            extract_and_validate_release_archive(&archive_path, release_dir, &target_tag, cfg);
        let _ = fs::remove_dir_all(&staging_dir);
        extract_res?;

        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            &format!(
                "=== STAGE 1 COMPLETE: Pre-built release {} staged at {} ===",
                target_tag,
                release_dir.display()
            ),
        );
        Ok(target_tag)
    }

    fn stage_3_restart_and_probe(&self, cfg: &ReleaseConfig) -> ReleaseResult<String> {
        self.lifecycle.restart_systemd_units(cfg)?;
        let status = poll_readiness_probe(
            &self.health_prober,
            &cfg.health_endpoint,
            cfg.health_retries,
            cfg.health_interval,
        )?;
        self.lifecycle.verify_running_release(cfg)?;
        Ok(status)
    }

    fn run_rollback_locked(
        &self,
        cfg: &ReleaseConfig,
        dry_run: bool,
        failed_deploy_release: Option<&Path>,
    ) -> ReleaseResult<RollbackReport> {
        append_jsonl_log(
            &cfg.log_file,
            "ERROR",
            "=== STAGE 4: ROLLBACK INITIATED ===",
        );

        let existing_recovery = RecoveryState::load(&cfg.releases_dir)?;
        let mut recovery = existing_recovery.clone().unwrap_or_else(|| {
            RecoveryState::new(ReleaseCommand::Rollback, cfg.release_channel, dry_run)
        });
        if failed_deploy_release.is_none() {
            if let Some(operation_id) = std::env::var("AETHERFLOW_UPDATE_OPERATION_ID")
                .ok()
                .and_then(|value| uuid::Uuid::parse_str(&value).ok())
            {
                recovery.operation_id = operation_id.to_string();
            }
        }
        recovery.phase = ReleasePhase::Stage4Rollback;
        recovery.save(&cfg.releases_dir)?;

        let previous_target = match read_previous_release(&cfg.releases_dir) {
            Ok(p) => p,
            Err(e) => {
                if let Some(ref rec_prev) = recovery.previous_release {
                    if rec_prev.is_dir() {
                        write_previous_release(&cfg.releases_dir, rec_prev)?;
                        rec_prev.clone()
                    } else {
                        recovery.phase = ReleasePhase::Failed;
                        recovery.last_error = Some(e.to_string());
                        let _ = recovery.save(&cfg.releases_dir);
                        return Err(e);
                    }
                } else {
                    recovery.phase = ReleasePhase::Failed;
                    recovery.last_error = Some(e.to_string());
                    let _ = recovery.save(&cfg.releases_dir);
                    return Err(e);
                }
            }
        };

        let epoch_id = allocate_unique_release_epoch_id(&cfg.releases_dir);
        atomic_replace_symlink(
            &cfg.current_link,
            &previous_target,
            &format!("rollback.{}", epoch_id),
        )?;
        sync_cli_entrypoints(cfg, &epoch_id)?;
        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            &format!(
                "Symlink reverted: {} -> {}",
                cfg.current_link.display(),
                previous_target.display()
            ),
        );

        let inferred_failed_candidate = existing_recovery
            .as_ref()
            .filter(|r| r.has_unhealthy_or_interrupted_post_swap_deploy())
            .and_then(|r| r.candidate_release.as_deref())
            .filter(|p| p.join("data-snapshot").is_dir());

        let snapshot_release = failed_deploy_release
            .or(inferred_failed_candidate)
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| previous_target.clone());
        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            &format!(
                "Database recovery snapshot release: {}",
                snapshot_release.display()
            ),
        );

        let unit_env = if cfg.isolated_root.is_some() {
            None
        } else {
            self.lifecycle.query_unit_environment("aetherflow-api")
        };
        let resolved_db = try_resolve_db_path(cfg, unit_env.as_deref())?;

        let restore_report = match restore_state_if_corrupted(
            cfg,
            &resolved_db,
            &snapshot_release,
            dry_run,
            |db_path| self.lifecycle.stop_database_services(db_path),
        ) {
            Ok(rep) => {
                if rep.restored_from_snapshot {
                    append_jsonl_log(
                        &cfg.log_file,
                        "CRITICAL",
                        &format!(
                            "Database RESTORED to {} from verified snapshot in {}",
                            resolved_db.path.display(),
                            snapshot_release.display()
                        ),
                    );
                } else {
                    append_jsonl_log(
                        &cfg.log_file,
                        "INFO",
                        &format!(
                            "Database integrity check PASSED ({}).",
                            resolved_db.path.display()
                        ),
                    );
                }
                Some(rep)
            }
            Err(err) => {
                let stop_error = if dry_run {
                    None
                } else {
                    self.lifecycle.stop_database_services(&resolved_db.path).err()
                };
                let failure = match stop_error {
                    Some(stop_error) => format!(
                        "database recovery failed: {}; writer quiescence also failed: {}",
                        err, stop_error
                    ),
                    None => format!(
                        "database recovery failed: {}; database services remain stopped",
                        err
                    ),
                };
                append_jsonl_log(&cfg.log_file, "ERROR", &failure);
                recovery.phase = ReleasePhase::Failed;
                recovery.last_error = Some(failure.clone());
                recovery.save(&cfg.releases_dir)?;
                return Err(ReleaseError::Rollback(failure));
            }
        };

        if !dry_run {
            if let Err(err) = self.lifecycle.restart_systemd_units(cfg) {
                recovery.phase = ReleasePhase::Failed;
                recovery.last_error = Some(err.to_string());
                let _ = recovery.save(&cfg.releases_dir);
                return Err(err);
            }
        }

        append_jsonl_log(
            &cfg.log_file,
            "ERROR",
            &format!(
                "=== ROLLBACK COMPLETE: Reverted to {} ===",
                previous_target.display()
            ),
        );

        recovery.phase = ReleasePhase::Complete;
        recovery.previous_release = Some(previous_target.clone());
        recovery.save(&cfg.releases_dir)?;

        Ok(RollbackReport {
            reverted_to: previous_target,
            snapshot_release,
            resolved_db,
            restore_report,
            restore_error: None,
            dry_run,
        })
    }

    fn run_cleanup_locked(
        &self,
        cfg: &ReleaseConfig,
        dry_run: bool,
    ) -> ReleaseResult<CleanupReport> {
        let mut recovery =
            RecoveryState::new(ReleaseCommand::Cleanup, cfg.release_channel, dry_run);
        recovery.phase = ReleasePhase::Stage5Cleanup;
        recovery.save(&cfg.releases_dir)?;

        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            &format!(
                "=== STAGE 5: Pruning Old Releases (retaining {}) ===",
                cfg.max_releases
            ),
        );
        let pruned_releases =
            match cleanup_old_releases(&cfg.releases_dir, &cfg.current_link, cfg.max_releases) {
                Ok(pruned) => pruned,
                Err(err) => {
                    recovery.phase = ReleasePhase::Failed;
                    recovery.last_error = Some(err.to_string());
                    let _ = recovery.save(&cfg.releases_dir);
                    return Err(err);
                }
            };
        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            &format!("Pruned {} old release(s).", pruned_releases.len()),
        );

        recovery.phase = ReleasePhase::Complete;
        recovery.save(&cfg.releases_dir)?;

        Ok(CleanupReport {
            retained_max: cfg.max_releases,
            pruned_releases,
        })
    }

    fn run_migrate_systemd_locked(
        &self,
        cfg: &ReleaseConfig,
        dry_run: bool,
    ) -> ReleaseResult<MigrateSystemdReport> {
        let mut recovery =
            RecoveryState::new(ReleaseCommand::MigrateSystemd, cfg.release_channel, dry_run);
        recovery.phase = ReleasePhase::Stage6MigrateSystemd;
        recovery.save(&cfg.releases_dir)?;

        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            "=== STAGE 6: PM2 -> Systemd Single-Binary Migration ===",
        );
        let resolved_db = match self.ensure_fhs_layout(cfg, dry_run) {
            Ok(r) => r,
            Err(err) => {
                recovery.phase = ReleasePhase::Failed;
                recovery.last_error = Some(err.to_string());
                let _ = recovery.save(&cfg.releases_dir);
                return Err(err);
            }
        };
        recovery.resolved_db_path = Some(resolved_db.path.clone());
        recovery.resolved_db_source = Some(resolved_db.source.to_string());
        recovery.save(&cfg.releases_dir)?;

        if dry_run {
            append_jsonl_log(
                &cfg.log_file,
                "INFO",
                "[DRY-RUN] Would install aetherflow-runner.service and aetherflow-api.service and stop PM2.",
            );
            recovery.phase = ReleasePhase::Complete;
            recovery.save(&cfg.releases_dir)?;
            return Ok(MigrateSystemdReport {
                resolved_db,
                health_status: None,
                dry_run: true,
            });
        }

        if let Err(err) = self.lifecycle.terminate_legacy_pm2() {
            recovery.phase = ReleasePhase::Failed;
            recovery.last_error = Some(err.to_string());
            let _ = recovery.save(&cfg.releases_dir);
            return Err(err);
        }

        // Ensure any old listener on the health endpoint socket has stopped before starting the new systemd unit
        if let Some(addr) = crate::health::parse_endpoint_socket_addr(&cfg.health_endpoint) {
            if let Err(err) =
                crate::health::wait_for_listener_stopped(addr, std::time::Duration::from_secs(5))
            {
                recovery.phase = ReleasePhase::Failed;
                recovery.last_error = Some(err.to_string());
                let _ = recovery.save(&cfg.releases_dir);
                return Err(err);
            }
        }

        let health_status = match self.stage_3_restart_and_probe(cfg) {
            Ok(status) => status,
            Err(err) => {
                recovery.phase = ReleasePhase::Failed;
                recovery.last_error = Some(err.to_string());
                let _ = recovery.save(&cfg.releases_dir);
                return Err(err);
            }
        };

        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            "MIGRATION COMPLETE: AetherFlow is running under hardened systemd units.",
        );

        recovery.phase = ReleasePhase::Complete;
        recovery.save(&cfg.releases_dir)?;

        Ok(MigrateSystemdReport {
            resolved_db,
            health_status: Some(health_status),
            dry_run: false,
        })
    }
}
