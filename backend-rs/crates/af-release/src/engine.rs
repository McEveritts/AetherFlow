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
#[cfg(not(unix))]
use crate::fs_security::sync_parent_dir_best_effort;
use crate::fs_security::{
    apply_data_dir_ownership_and_mode, apply_root_aetherflow_dir_ownership_and_mode,
    apply_root_owned_dir_mode, atomic_copy_file_root_aetherflow,
    atomic_replace_helper_file_root_owned, create_dir_all_no_symlinks, create_new_dir_exclusive,
    ensure_no_symlink_ancestors, set_dir_mode,
};
use crate::health::{
    poll_readiness_probe, preflight_cli_entrypoints, sync_cli_entrypoints,
    verify_deployed_frontend_assets, verify_isolated_systemd_lifecycle_authorized, HealthProber,
    LifecycleController, ReqwestHealthProber, SystemdLifecycleController,
};
use crate::lock::{RecoveryState, ReleaseLockGuard, ReleasePhase};
use crate::snapshot::{
    create_state_snapshot, restore_state_if_corrupted, RestoreReport, SnapshotReport,
};
use crate::symlink::{
    atomic_replace_symlink, canonicalize_preserve_normal, cleanup_old_releases,
    perform_symlink_swap, prune_old_releases, read_current_link_target,
    read_previous_release_in_roots, validate_previous_release_target, write_previous_release,
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
        let prev = EPOCH_MONOTONIC_SEQ
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
                Some(if now_secs > cur {
                    now_secs
                } else {
                    cur.saturating_add(1)
                })
            })
            .expect("monotonic epoch update always returns Some");
        let next = if now_secs > prev {
            now_secs
        } else {
            prev.saturating_add(1)
        };
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
        let path_safe = if let Some(parent) = log_file.parent() {
            create_dir_all_no_symlinks(parent, 0o750).is_ok()
                && ensure_no_symlink_ancestors(log_file).is_ok()
        } else {
            ensure_no_symlink_ancestors(log_file).is_ok()
        };
        let target_is_symlink = fs::symlink_metadata(log_file)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if path_safe && !target_is_symlink {
            let mut opts = OpenOptions::new();
            opts.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o640)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
            }
            if let Ok(mut file) = opts.open(log_file) {
                #[cfg(unix)]
                let fd_ok = {
                    use std::os::unix::fs::MetadataExt;
                    file.metadata()
                        .map(|m| m.is_file() && m.nlink() == 1)
                        .unwrap_or(false)
                };
                #[cfg(not(unix))]
                let fd_ok = file.metadata().map(|m| m.is_file()).unwrap_or(false);
                if fd_ok {
                    #[cfg(unix)]
                    {
                        use std::os::unix::io::AsRawFd;
                        unsafe {
                            let fd = file.as_raw_fd();
                            let fl = libc::fcntl(fd, libc::F_GETFL);
                            if fl >= 0 {
                                let _ = libc::fcntl(fd, libc::F_SETFL, fl & !libc::O_NONBLOCK);
                            }
                            let _ = libc::flock(fd, libc::LOCK_SH);
                        }
                    }
                    let _ = writeln!(file, "{}", serialized);
                    let _ = file.flush();
                    #[cfg(unix)]
                    {
                        use std::os::unix::io::AsRawFd;
                        unsafe {
                            let _ = libc::flock(file.as_raw_fd(), libc::LOCK_UN);
                        }
                    }
                }
            }
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
    #[cfg(test)]
    fail_next_post_swap_cli_sync: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ReleaseEngine<GithubHttpArtifactProvider, SystemdLifecycleController, ReqwestHealthProber> {
    /// Constructs a production `ReleaseEngine` wired to GitHub Releases HTTP, bare-metal `systemctl`,
    /// and `/health/ready` probing.
    pub fn new_production(base_config: ReleaseConfig) -> Self {
        Self {
            base_config,
            artifact_provider: GithubHttpArtifactProvider::default(),
            lifecycle: SystemdLifecycleController,
            health_prober: ReqwestHealthProber,
            #[cfg(test)]
            fail_next_post_swap_cli_sync: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )),
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
            #[cfg(test)]
            fail_next_post_swap_cli_sync: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )),
        }
    }

    #[cfg(test)]
    pub(crate) fn arm_next_post_swap_cli_sync_failure(&self) {
        self.fail_next_post_swap_cli_sync
            .store(true, std::sync::atomic::Ordering::SeqCst);
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
        let current_release =
            read_current_link_target(&self.base_config.current_link).filter(|dir| {
                is_confined_to_isolated_root(dir, self.base_config.isolated_root.as_deref())
            });
        let current_version = current_release
            .as_ref()
            .and_then(|dir| read_small_regular_file_nofollow(&dir.join(".version")))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let previous_release = read_small_regular_file_nofollow(
            &self.base_config.releases_dir.join(".previous_release"),
        )
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .filter(|dir| is_confined_to_isolated_root(dir, self.base_config.isolated_root.as_deref()));

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
        if opts.dry_run {
            let iso = effective_cfg.isolated_root.as_deref();
            crate::fs_security::ensure_trusted_dry_run_dir(
                &effective_cfg.dry_run_root,
                &effective_cfg.releases_dir,
                0o755,
                iso,
            )?;
            crate::fs_security::ensure_trusted_dry_run_dir(
                &effective_cfg.dry_run_root,
                &effective_cfg.data_dir,
                0o700,
                iso,
            )?;
            crate::fs_security::ensure_trusted_dry_run_dir(
                &effective_cfg.dry_run_root,
                &effective_cfg.env_dir,
                0o750,
                iso,
            )?;
            crate::fs_security::ensure_trusted_dry_run_dir(
                &effective_cfg.dry_run_root,
                &effective_cfg.repo_dir,
                0o755,
                iso,
            )?;
        } else {
            create_dir_all_no_symlinks(&effective_cfg.releases_dir, 0o755)?;
        }

        let unit_env = if effective_cfg.isolated_root.is_none() {
            self.lifecycle.query_unit_environment("aetherflow-api")
        } else {
            None
        };
        let shared_lock_path = crate::admin::ensure_interoperable_maintenance_lock_file_with_env(
            &effective_cfg,
            unit_env.as_deref(),
        )?;
        let _shared_maintenance_lock =
            ReleaseLockGuard::acquire(&shared_lock_path, effective_cfg.snapshot_timeout)?;

        if !opts.dry_run {
            crate::admin::ensure_no_active_package_lifecycle_jobs_with_env(
                &effective_cfg,
                opts.command,
                unit_env.as_deref(),
            )?;
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

        let allowed_releases_dirs: Vec<&Path> = if opts.dry_run {
            vec![
                cfg.releases_dir.as_path(),
                self.base_config.releases_dir.as_path(),
            ]
        } else {
            vec![cfg.releases_dir.as_path()]
        };

        if existing.has_unhealthy_or_interrupted_post_swap_deploy() {
            match opts.command {
                ReleaseCommand::Rollback => {
                    if let Some(ref good_prev) = existing.previous_release {
                        if validate_previous_release_target(good_prev, &allowed_releases_dirs)
                            .is_ok()
                        {
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
                let prev_target =
                    read_previous_release_in_roots(&cfg.releases_dir, &allowed_releases_dirs).ok();
                let canon_cand = canonicalize_preserve_normal(cand);
                let is_active = current_target
                    .as_ref()
                    .map(|c| c == &canon_cand || c == cand)
                    .unwrap_or(false);
                let is_prev = prev_target
                    .as_ref()
                    .map(|p| canonicalize_preserve_normal(p) == canon_cand || p == cand)
                    .unwrap_or(false);
                let canon_releases = canonicalize_preserve_normal(&cfg.releases_dir);
                let is_real_dir = fs::symlink_metadata(cand)
                    .map(|m| !m.file_type().is_symlink() && m.is_dir())
                    .unwrap_or(false);
                if !is_active
                    && !is_prev
                    && is_real_dir
                    && canon_cand != canon_releases
                    && canon_cand.starts_with(&canon_releases)
                {
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
        if dry_run {
            let iso = cfg.isolated_root.as_deref();
            crate::fs_security::ensure_trusted_dry_run_dir(
                &cfg.dry_run_root,
                &cfg.releases_dir,
                0o755,
                iso,
            )?;
            crate::fs_security::ensure_trusted_dry_run_dir(
                &cfg.dry_run_root,
                &cfg.data_dir,
                0o700,
                iso,
            )?;
            crate::fs_security::ensure_trusted_dry_run_dir(
                &cfg.dry_run_root,
                &cfg.env_dir,
                0o750,
                iso,
            )?;
            crate::fs_security::ensure_trusted_dry_run_dir(
                &cfg.dry_run_root,
                &cfg.repo_dir,
                0o755,
                iso,
            )?;
            set_dir_mode(&cfg.data_dir, 0o700)?;
            set_dir_mode(&cfg.env_dir, 0o750)?;
        } else {
            create_dir_all_no_symlinks(&cfg.releases_dir, 0o755)?;
            create_dir_all_no_symlinks(&cfg.data_dir, 0o700)?;
            create_dir_all_no_symlinks(&cfg.env_dir, 0o750)?;
            apply_data_dir_ownership_and_mode(&cfg.data_dir)?;
            apply_root_aetherflow_dir_ownership_and_mode(&cfg.env_dir)?;
            #[cfg(unix)]
            if cfg.isolated_root.is_none() && unsafe { libc::geteuid() } == 0 {
                for host_dir in [
                    Path::new("/var/log/aetherflow"),
                    Path::new("/run/aetherflow"),
                    Path::new("/install"),
                ] {
                    create_dir_all_no_symlinks(host_dir, 0o750)?;
                    apply_root_aetherflow_dir_ownership_and_mode(host_dir)?;
                }
            }
        }

        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            "=== STAGE 0: Verifying FHS State & Secret Layout ===",
        );

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

        let current_slot_dirs = resolve_confined_legacy_current_slots(cfg);

        let fhs_db = cfg.host_data_dir.join(&cfg.sqlite_db);
        if resolved.path == fhs_db && !is_regular_non_symlink_file(&fhs_db) {
            let mut legacy_candidates = vec![
                cfg.legacy_opt_root
                    .join("backend/data")
                    .join(&cfg.sqlite_db),
                cfg.legacy_opt_root.join("backend").join(&cfg.sqlite_db),
            ];
            for slot_dir in &current_slot_dirs {
                legacy_candidates.push(slot_dir.join("backend/data").join(&cfg.sqlite_db));
                legacy_candidates.push(slot_dir.join("backend").join(&cfg.sqlite_db));
            }
            for legacy_db in &legacy_candidates {
                if is_regular_non_symlink_file(legacy_db) {
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
                    // Assign service ownership (`aetherflow:aetherflow 0600` when running as root)
                    // rather than preserving `root:root 0600` from a legacy v3 DB so `aetherflow-api`
                    // (`User=aetherflow`) can open the migrated database cleanly on Stage 3 start.
                    crate::snapshot::sqlite_online_backup_with_ownership(
                        legacy_db, &fhs_db, None, true,
                    )?;
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
            let mut legacy_envs = vec![
                cfg.legacy_opt_root.join("backend/.env"),
                cfg.legacy_opt_root.join(".env"),
            ];
            for slot_dir in &current_slot_dirs {
                legacy_envs.push(slot_dir.join("backend/.env"));
                legacy_envs.push(slot_dir.join(".env"));
            }
            for legacy_env in &legacy_envs {
                if is_regular_non_symlink_file(legacy_env) {
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
                        apply_root_aetherflow_dir_ownership_and_mode(parent)?;
                    }
                    atomic_copy_file_root_aetherflow(legacy_env, &cfg.host_env_file, 0o640)?;
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
            &format!(
                "=== STAGE 1: Release Scaffold (Channel: {}) ===",
                opts.channel
            ),
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

        if let Err(err) =
            crate::artifact::prepare_release_permissions_with_options(&release_dir, !opts.dry_run)
        {
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

        if let Err(err) = preflight_cli_entrypoints(cfg, &release_dir)
            .and_then(|()| preflight_release_packages_and_helpers(cfg, &release_dir, opts.dry_run))
        {
            let _ = fs::remove_dir_all(&release_dir);
            recovery.phase = ReleasePhase::Failed;
            recovery.last_error = Some(err.to_string());
            let _ = recovery.save(&cfg.releases_dir);
            append_jsonl_log(&cfg.log_file, "ERROR", &err.to_string());
            return Err(err);
        }

        let allowed_releases_dirs: Vec<&Path> = if opts.dry_run {
            vec![
                cfg.releases_dir.as_path(),
                self.base_config.releases_dir.as_path(),
            ]
        } else {
            vec![cfg.releases_dir.as_path()]
        };
        let prior_previous_release =
            read_previous_release_in_roots(&cfg.releases_dir, &allowed_releases_dirs).ok();
        let current_before_swap = read_current_link_target(&cfg.current_link);
        recovery.previous_release = current_before_swap
            .clone()
            .or_else(|| prior_previous_release.clone());
        recovery.phase = ReleasePhase::Stage2SymlinkSwap;
        if let Err(err) = recovery.save(&cfg.releases_dir) {
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
            "=== STAGE 2: Atomic Symlink Swap ===",
        );

        let previous_release = match perform_symlink_swap(
            &cfg.releases_dir,
            &cfg.current_link,
            &release_dir,
            &epoch_id,
        ) {
            Ok(prev) => prev,
            Err(err) => {
                let swapped_to_candidate = read_current_link_target(&cfg.current_link)
                    .map(|target| {
                        canonicalize_preserve_normal(&target)
                            == canonicalize_preserve_normal(&release_dir)
                    })
                    .unwrap_or(false);
                if swapped_to_candidate {
                    return Err(self.rollback_after_post_swap_failure(
                        cfg,
                        opts.dry_run,
                        &release_dir,
                        prior_previous_release.as_deref(),
                        &mut recovery,
                        err,
                    ));
                }
                recovery.phase = ReleasePhase::Failed;
                recovery.last_error = Some(err.to_string());
                let _ = recovery.save(&cfg.releases_dir);
                append_jsonl_log(&cfg.log_file, "ERROR", &err.to_string());
                return Err(err);
            }
        };

        let post_swap_res: ReleaseResult<Option<String>> = (|| {
            #[cfg(test)]
            if self
                .fail_next_post_swap_cli_sync
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(ReleaseError::SymlinkSwap {
                    link: cfg.cli_bin_dir.join("af"),
                    target: cfg.current_link.join("af"),
                    reason: "injected post-swap CLI sync failure".to_string(),
                });
            }
            sync_cli_entrypoints(cfg, &epoch_id)?;
            sync_release_packages_and_helpers(cfg, &release_dir, opts.dry_run)?;
            if let Some(ref p) = previous_release {
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
            recovery.previous_release = previous_release.clone();
            recovery.save(&cfg.releases_dir)?;

            recovery.phase = ReleasePhase::Stage3HealthProbe;
            recovery.save(&cfg.releases_dir)?;
            append_jsonl_log(
                &cfg.log_file,
                "INFO",
                "=== STAGE 3: Systemd Restart & Deep Readiness Probe ===",
            );

            if opts.dry_run {
                append_jsonl_log(
                    &cfg.log_file,
                    "INFO",
                    "[DRY-RUN] Skipping systemctl restart and health probe.",
                );
                Ok(None)
            } else {
                let status = self.stage_3_restart_and_probe(cfg)?;
                append_jsonl_log(
                    &cfg.log_file,
                    "INFO",
                    &format!("Health probe PASSED (status={})", status),
                );
                Ok(Some(status))
            }
        })();

        let health_status = match post_swap_res {
            Ok(status) => status,
            Err(post_err) => {
                return Err(self.rollback_after_post_swap_failure(
                    cfg,
                    opts.dry_run,
                    &release_dir,
                    prior_previous_release.as_deref(),
                    &mut recovery,
                    post_err,
                ));
            }
        };

        // Activation and readiness succeeded. A retention failure can be retried
        // independently, so finish the deployment journal before pruning.
        recovery.phase = ReleasePhase::Complete;
        recovery.save(&cfg.releases_dir)?;
        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            &format!(
                "=== STAGE 5: Pruning Old Releases (retaining {}) ===",
                cfg.max_releases
            ),
        );
        let mut pruned_releases = Vec::new();
        if let Err(error) = prune_old_releases(
            &cfg.releases_dir,
            &cfg.current_link,
            cfg.max_releases,
            &mut pruned_releases,
        ) {
            append_jsonl_log(
                &cfg.log_file,
                "WARN",
                &format!("Release retention cleanup can be retried: {error}"),
            );
        }
        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            &format!("Pruned {} old release(s).", pruned_releases.len()),
        );

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
                "[DRY-RUN] Offline mode: simulating release artifact verification and extraction with placeholders.",
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

        let bundle_res = self.artifact_provider.fetch_release_bundle(
            cfg,
            opts.channel,
            &target_tag,
            &staging_dir,
        );
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
        append_jsonl_log(
            &cfg.log_file,
            "INFO",
            &format!("SHA-256 OK {}", actual_digest),
        );

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

    fn rollback_after_post_swap_failure(
        &self,
        cfg: &ReleaseConfig,
        dry_run: bool,
        release_dir: &Path,
        prior_previous_release: Option<&Path>,
        recovery: &mut RecoveryState,
        post_err: ReleaseError,
    ) -> ReleaseError {
        append_jsonl_log(&cfg.log_file, "ERROR", &post_err.to_string());
        recovery.phase = ReleasePhase::Stage4Rollback;
        recovery.last_error = Some(post_err.to_string());
        let _ = recovery.save(&cfg.releases_dir);

        match self.run_rollback_locked(cfg, dry_run, Some(release_dir)) {
            Ok(rb_report) => {
                if let Some(prior_prev) = prior_previous_release {
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
                ReleaseError::RolledBackAfterProbeFailure {
                    probe_error: post_err.to_string(),
                    reverted_to: rb_report.reverted_to,
                    db_restored,
                }
            }
            Err(rb_err) => {
                recovery.phase = ReleasePhase::Stage4Rollback;
                recovery.last_error = Some(format!(
                    "post-swap step failed ({}) and rollback failed: {}",
                    post_err, rb_err
                ));
                let _ = recovery.save(&cfg.releases_dir);
                ReleaseError::Rollback(format!(
                    "post-swap step failed ({}) and rollback also failed: {}",
                    post_err, rb_err
                ))
            }
        }
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
        if let Some(active_release) = read_current_link_target(&cfg.current_link) {
            verify_deployed_frontend_assets(&active_release)?;
        }
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
        let mut recovery = match existing_recovery.clone() {
            Some(existing) if failed_deploy_release.is_some() || existing.is_unfinished() => {
                existing
            }
            _ => RecoveryState::new(ReleaseCommand::Rollback, cfg.release_channel, dry_run),
        };
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

        let allowed_releases_dirs: Vec<&Path> = if dry_run {
            vec![
                cfg.releases_dir.as_path(),
                self.base_config.releases_dir.as_path(),
            ]
        } else {
            vec![cfg.releases_dir.as_path()]
        };
        let previous_target =
            match read_previous_release_in_roots(&cfg.releases_dir, &allowed_releases_dirs) {
                Ok(p) => p,
                Err(e) => {
                    let fallback_previous = recovery.previous_release.as_ref().or_else(|| {
                        existing_recovery
                            .as_ref()
                            .and_then(|rec| rec.previous_release.as_ref())
                    });
                    if let Some(rec_prev) = fallback_previous {
                        if validate_previous_release_target(rec_prev, &allowed_releases_dirs)
                            .is_ok()
                        {
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

        let current_before_rollback = fs::canonicalize(&cfg.current_link).ok();

        let epoch_id = allocate_unique_release_epoch_id(&cfg.releases_dir);
        atomic_replace_symlink(
            &cfg.current_link,
            &previous_target,
            &format!("rollback.{}", epoch_id),
        )?;
        recovery.previous_release = Some(previous_target.clone());
        if recovery.candidate_release.is_none() {
            if let Some(ref cur) = current_before_rollback {
                if canonicalize_preserve_normal(cur)
                    != canonicalize_preserve_normal(&previous_target)
                {
                    recovery.candidate_release = Some(cur.clone());
                }
            }
        }
        recovery.save(&cfg.releases_dir)?;
        let cli_sync_res = sync_cli_entrypoints(cfg, &epoch_id);
        if let Err(ref cli_err) = cli_sync_res {
            append_jsonl_log(
                &cfg.log_file,
                "ERROR",
                &format!(
                    "Failed to re-sync CLI entrypoint during rollback: {}",
                    cli_err
                ),
            );
        }
        let helper_sync_res = sync_release_packages_and_helpers(cfg, &previous_target, dry_run);
        if let Err(ref helper_err) = helper_sync_res {
            append_jsonl_log(
                &cfg.log_file,
                "ERROR",
                &format!(
                    "Failed to re-sync release packages and system helpers during rollback: {}",
                    helper_err
                ),
            );
        }
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

        let outgoing_current_snapshot = current_before_rollback.as_deref().filter(|cur| {
            canonicalize_preserve_normal(cur) != canonicalize_preserve_normal(&previous_target)
                && cur.join("data-snapshot").is_dir()
        });

        let snapshot_release = failed_deploy_release
            .or(inferred_failed_candidate)
            .or(outgoing_current_snapshot)
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
                    self.lifecycle
                        .stop_database_services(&resolved_db.path)
                        .err()
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
                recovery.phase = ReleasePhase::Stage4Rollback;
                recovery.last_error = Some(failure.clone());
                recovery.save(&cfg.releases_dir)?;
                return Err(ReleaseError::Rollback(failure));
            }
        };

        if !dry_run {
            if let Err(err) = self.lifecycle.restart_systemd_units(cfg) {
                recovery.phase = ReleasePhase::Stage4Rollback;
                recovery.last_error = Some(err.to_string());
                let _ = recovery.save(&cfg.releases_dir);
                return Err(err);
            }
            if let Err(err) = poll_readiness_probe(
                &self.health_prober,
                &cfg.health_endpoint,
                cfg.health_retries,
                cfg.health_interval,
            )
            .and_then(|_| self.lifecycle.verify_running_release(cfg))
            .and_then(|_| {
                if let Some(active_release) = read_current_link_target(&cfg.current_link) {
                    verify_deployed_frontend_assets(&active_release)?;
                }
                Ok(())
            }) {
                recovery.phase = ReleasePhase::Stage4Rollback;
                recovery.last_error = Some(err.to_string());
                let _ = recovery.save(&cfg.releases_dir);
                return Err(err);
            }
        }

        if let Err(cli_err) = cli_sync_res {
            recovery.phase = ReleasePhase::Stage4Rollback;
            recovery.last_error = Some(cli_err.to_string());
            let _ = recovery.save(&cfg.releases_dir);
            return Err(cli_err);
        }
        if let Err(helper_err) = helper_sync_res {
            recovery.phase = ReleasePhase::Stage4Rollback;
            recovery.last_error = Some(helper_err.to_string());
            let _ = recovery.save(&cfg.releases_dir);
            return Err(helper_err);
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

fn is_regular_non_symlink_file(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type().is_file() && !meta.file_type().is_symlink(),
        Err(_) => false,
    }
}

fn resolve_confined_legacy_current_slots(cfg: &ReleaseConfig) -> Vec<PathBuf> {
    let mut allowed_roots = Vec::new();
    for root in [&cfg.releases_dir, &cfg.legacy_opt_root] {
        if let Ok(canon) = fs::canonicalize(root) {
            if !allowed_roots.contains(&canon) {
                allowed_roots.push(canon);
            }
        }
    }
    if allowed_roots.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let legacy_current = cfg.legacy_opt_root.join("current");
    for candidate in [&cfg.current_link, &legacy_current] {
        let Ok(canon_slot) = fs::canonicalize(candidate) else {
            continue;
        };
        if !canon_slot.is_dir() {
            continue;
        }
        let confined = allowed_roots
            .iter()
            .any(|allowed| canon_slot != *allowed && canon_slot.starts_with(allowed));
        if confined && !out.contains(&canon_slot) {
            out.push(canon_slot);
        }
    }
    out
}

fn is_confined_to_isolated_root(candidate: &Path, isolated_root: Option<&Path>) -> bool {
    let Some(root) = isolated_root else {
        return true;
    };
    let Ok(canon_root) = fs::canonicalize(root) else {
        return false;
    };
    let Ok(canon_cand) = fs::canonicalize(candidate) else {
        return false;
    };
    canon_cand == canon_root || canon_cand.starts_with(&canon_root)
}

fn read_small_regular_file_nofollow(path: &Path) -> Option<String> {
    use std::io::Read;

    #[cfg(unix)]
    let file = {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
        use std::path::Component;

        let leaf_os = path.file_name()?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut cur_dir: Option<OwnedFd> = None;

        for comp in parent.components() {
            let dirfd = cur_dir.as_ref().map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
            match comp {
                Component::Prefix(_) | Component::ParentDir => return None,
                Component::CurDir => {}
                Component::RootDir => {
                    let c_root = CString::new("/").ok()?;
                    let fd = unsafe {
                        libc::open(
                            c_root.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return None;
                    }
                    cur_dir = Some(unsafe { OwnedFd::from_raw_fd(fd) });
                }
                Component::Normal(seg) => {
                    let c_seg = CString::new(seg.as_bytes()).ok()?;
                    let fd = unsafe {
                        libc::openat(
                            dirfd,
                            c_seg.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return None;
                    }
                    cur_dir = Some(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
        }

        let dirfd = cur_dir.as_ref().map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
        let c_leaf = CString::new(leaf_os.as_bytes()).ok()?;
        let leaf_fd = unsafe {
            libc::openat(
                dirfd,
                c_leaf.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if leaf_fd < 0 {
            return None;
        }
        let f = fs::File::from(unsafe { OwnedFd::from_raw_fd(leaf_fd) });
        let meta = f.metadata().ok()?;
        if !meta.is_file() || meta.len() > 4096 || (meta.permissions().mode() & 0o002) != 0 {
            return None;
        }
        f
    };

    #[cfg(not(unix))]
    let file = {
        let f = fs::OpenOptions::new().read(true).open(path).ok()?;
        let meta = f.metadata().ok()?;
        if !meta.is_file() || meta.len() > 4096 {
            return None;
        }
        f
    };

    let mut buf = String::new();
    file.take(4096).read_to_string(&mut buf).ok()?;
    Some(buf)
}

const MAX_PACKAGE_SYNC_DEPTH: usize = 32;

/// Atomically synchronizes release packages and system helper scripts from `release_dir/packages`
/// to all 5 host/isolated targets (`PIPE-02`), matching `setup/modules/02-packages.sh:340-350`
/// and `deploy/release-manager.sh:1954-1970`:
/// 1. `<legacy_opt_root>/packages/` (`/opt/AetherFlow/packages/`)
/// 2. `<root>/usr/local/bin/AetherFlow/*` (`/usr/local/bin/AetherFlow/*`)
/// 3. `<root>/usr/local/bin/af-certbot-sync` (regular `0o755 root:root` file, NEVER a symlink)
/// 4. `<root>/usr/bin/af-certbot-sync` (regular `0o755 root:root` file, NEVER a symlink)
/// 5. `<root>/usr/bin/af-systemd-sandbox` (regular `0o755 root:root` file, NEVER a symlink)
///
struct HelperSyncTargets {
    src_packages: PathBuf,
    target_opt_packages: PathBuf,
    target_bin_aetherflow: PathBuf,
    target_local_certbot: PathBuf,
    target_usr_certbot: PathBuf,
    target_usr_sandbox: PathBuf,
    target_usr_bin_dir: PathBuf,
}

fn should_skip_package_sync_entry(
    name: &std::ffi::OsStr,
    depth: usize,
    in_system_dir: bool,
) -> bool {
    name == "EGM.md"
        || (depth == 0 && name == "README.md")
        || (depth == 1 && in_system_dir && name == "af-heal")
}

fn resolve_helper_sync_targets(
    cfg: &ReleaseConfig,
    release_dir: &Path,
) -> ReleaseResult<Option<HelperSyncTargets>> {
    let src_packages = release_dir.join("packages");
    ensure_no_symlink_ancestors(&src_packages)?;
    match fs::symlink_metadata(&src_packages) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(ReleaseError::PathValidation {
                    path: src_packages,
                    reason: "release packages path is a symlink or non-directory".to_string(),
                });
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(ReleaseError::io(
                format!("inspecting release packages {}", src_packages.display()),
                err,
            ));
        }
    }

    // Do not wipe existing host package trees when a minimal/synthetic release archive
    // contains an empty placeholder `packages/` directory.
    let mut has_entries = false;
    for entry_res in fs::read_dir(&src_packages).map_err(|err| {
        ReleaseError::io(
            format!("reading release packages {}", src_packages.display()),
            err,
        )
    })? {
        let entry = entry_res.map_err(|err| {
            ReleaseError::io(
                format!("iterating release packages {}", src_packages.display()),
                err,
            )
        })?;
        if !should_skip_package_sync_entry(&entry.file_name(), 0, false) {
            has_entries = true;
            break;
        }
    }
    if !has_entries {
        return Ok(None);
    }

    let target_root = cfg
        .isolated_root
        .clone()
        .unwrap_or_else(|| PathBuf::from("/"));
    let target_opt_packages = cfg.legacy_opt_root.join("packages");
    let target_bin_aetherflow = cfg.cli_bin_dir.join("AetherFlow");
    let target_local_certbot = cfg.cli_bin_dir.join("af-certbot-sync");
    let target_usr_bin_dir = target_root.join("usr/bin");
    let target_usr_certbot = target_usr_bin_dir.join("af-certbot-sync");
    let target_usr_sandbox = target_usr_bin_dir.join("af-systemd-sandbox");

    if let Some(ref iso) = cfg.isolated_root {
        for (label, target) in [
            ("opt/AetherFlow/packages", target_opt_packages.as_path()),
            ("cli_bin_dir/AetherFlow", target_bin_aetherflow.as_path()),
            (
                "cli_bin_dir/af-certbot-sync",
                target_local_certbot.as_path(),
            ),
            ("usr/bin/af-certbot-sync", target_usr_certbot.as_path()),
            ("usr/bin/af-systemd-sandbox", target_usr_sandbox.as_path()),
        ] {
            if !crate::config::path_is_within_root(target, iso) {
                return Err(ReleaseError::PathValidation {
                    path: target.to_path_buf(),
                    reason: format!(
                        "helper sync target {} '{}' escapes isolated root '{}'",
                        label,
                        target.display(),
                        iso.display()
                    ),
                });
            }
        }
    }

    Ok(Some(HelperSyncTargets {
        src_packages,
        target_opt_packages,
        target_bin_aetherflow,
        target_local_certbot,
        target_usr_certbot,
        target_usr_sandbox,
        target_usr_bin_dir,
    }))
}

fn preflight_helper_tree_target(target_dir: &Path, src_packages: &Path) -> ReleaseResult<()> {
    ensure_no_symlink_ancestors(target_dir)?;
    if let Ok(meta) = fs::symlink_metadata(target_dir) {
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(ReleaseError::PathValidation {
                path: target_dir.to_path_buf(),
                reason: "helper sync directory target is a symlink or non-directory".to_string(),
            });
        }
        if !same_directory_inode(src_packages, target_dir) {
            preflight_existing_subtree_no_symlink_dirs(src_packages, target_dir, 0, false)?;
        }
    }
    Ok(())
}

fn preflight_existing_subtree_no_symlink_dirs(
    src_dir: &Path,
    dst_dir: &Path,
    depth: usize,
    in_system_dir: bool,
) -> ReleaseResult<()> {
    if depth > MAX_PACKAGE_SYNC_DEPTH {
        return Err(ReleaseError::PathValidation {
            path: dst_dir.to_path_buf(),
            reason: format!(
                "package sync destination nesting exceeded maximum depth ({MAX_PACKAGE_SYNC_DEPTH})"
            ),
        });
    }
    // Pin destination directory via O_DIRECTORY | O_NOFOLLOW to prevent symlink traversal.
    #[cfg(unix)]
    let _dst_dir_fd = crate::fs_security::open_dir_nofollow(dst_dir)?;

    // Reject any symlinked subdirectory or unexpected non-regular entry anywhere in dst_dir
    // that sync_dir_recursive or stale pruning will descend into.
    for entry_res in fs::read_dir(dst_dir).map_err(|err| {
        ReleaseError::io(
            format!(
                "reading destination directory {} for helper preflight",
                dst_dir.display()
            ),
            err,
        )
    })? {
        let entry = entry_res.map_err(|err| {
            ReleaseError::io(
                format!(
                    "iterating destination directory {} for helper preflight",
                    dst_dir.display()
                ),
                err,
            )
        })?;
        let name = entry.file_name();
        let dst_path = entry.path();
        let dst_meta = fs::symlink_metadata(&dst_path).map_err(|err| {
            ReleaseError::io(
                format!(
                    "stat destination entry {} for helper preflight",
                    dst_path.display()
                ),
                err,
            )
        })?;
        if dst_meta.file_type().is_symlink() {
            // Check whether a matching source entry is a directory (which cannot overwrite a symlink).
            let src_path = src_dir.join(&name);
            if let Ok(src_meta) = fs::symlink_metadata(&src_path) {
                if src_meta.is_dir() && !should_skip_package_sync_entry(&name, depth, in_system_dir)
                {
                    return Err(ReleaseError::PathValidation {
                        path: dst_path,
                        reason: "destination package directory is a symlink".to_string(),
                    });
                }
            }
        } else if dst_meta.is_dir() {
            let src_path = src_dir.join(&name);
            let child_is_system = depth == 0 && name == "system";
            if let Ok(src_meta) = fs::symlink_metadata(&src_path) {
                if !should_skip_package_sync_entry(&name, depth, in_system_dir) {
                    if src_meta.is_dir() {
                        preflight_existing_subtree_no_symlink_dirs(
                            &src_path,
                            &dst_path,
                            depth + 1,
                            child_is_system,
                        )?;
                    } else if src_meta.is_file() {
                        return Err(ReleaseError::PathValidation {
                            path: dst_path,
                            reason: "destination package file target is an existing directory"
                                .to_string(),
                        });
                    }
                }
            }
        } else if !dst_meta.is_file() {
            let src_path = src_dir.join(&name);
            if let Ok(src_meta) = fs::symlink_metadata(&src_path) {
                if !should_skip_package_sync_entry(&name, depth, in_system_dir)
                    && (src_meta.is_dir() || src_meta.is_file())
                {
                    return Err(ReleaseError::PathValidation {
                        path: dst_path,
                        reason: "destination package target is a non-regular special file"
                            .to_string(),
                    });
                }
            }
        }
    }

    // Also inspect every source entry against its destination counterpart in case dst_dir
    // contains an entry that is a non-directory at a source directory slot.
    for entry_res in fs::read_dir(src_dir).map_err(|err| {
        ReleaseError::io(
            format!(
                "reading source directory {} for destination parity preflight",
                src_dir.display()
            ),
            err,
        )
    })? {
        let entry = entry_res.map_err(|err| {
            ReleaseError::io(
                format!(
                    "iterating source directory {} for destination parity preflight",
                    src_dir.display()
                ),
                err,
            )
        })?;
        let name = entry.file_name();
        if should_skip_package_sync_entry(&name, depth, in_system_dir) {
            continue;
        }
        let src_path = entry.path();
        let dst_path = dst_dir.join(&name);
        let src_meta = fs::symlink_metadata(&src_path).map_err(|err| {
            ReleaseError::io(format!("stat source entry {}", src_path.display()), err)
        })?;
        if let Ok(dst_meta) = fs::symlink_metadata(&dst_path) {
            if src_meta.is_dir() && (dst_meta.file_type().is_symlink() || !dst_meta.is_dir()) {
                return Err(ReleaseError::PathValidation {
                    path: dst_path,
                    reason: "destination package directory is a symlink or non-directory"
                        .to_string(),
                });
            }
        }
    }
    Ok(())
}

fn preflight_helper_file_target(target_file: &Path) -> ReleaseResult<()> {
    crate::config::validate_no_parent_traversal(target_file, "helper target path")?;
    if let Some(parent) = target_file.parent().filter(|p| !p.as_os_str().is_empty()) {
        ensure_no_symlink_ancestors(parent)?;
    }
    if let Ok(meta) = fs::symlink_metadata(target_file) {
        if meta.is_dir() && !meta.file_type().is_symlink() {
            return Err(ReleaseError::PathValidation {
                path: target_file.to_path_buf(),
                reason: "helper binary target is a directory".to_string(),
            });
        }
        if !meta.file_type().is_symlink() && !meta.is_file() {
            return Err(ReleaseError::PathValidation {
                path: target_file.to_path_buf(),
                reason: "helper binary target is a non-regular special file".to_string(),
            });
        }
    }
    Ok(())
}

fn preflight_source_tree(src_dir: &Path, depth: usize, in_system_dir: bool) -> ReleaseResult<()> {
    if depth > MAX_PACKAGE_SYNC_DEPTH {
        return Err(ReleaseError::PathValidation {
            path: src_dir.to_path_buf(),
            reason: format!(
                "package sync directory nesting exceeded maximum depth ({MAX_PACKAGE_SYNC_DEPTH})"
            ),
        });
    }
    for entry_res in fs::read_dir(src_dir).map_err(|err| {
        ReleaseError::io(
            format!(
                "reading source directory {} for helper preflight",
                src_dir.display()
            ),
            err,
        )
    })? {
        let entry = entry_res.map_err(|err| {
            ReleaseError::io(
                format!(
                    "iterating source directory {} for helper preflight",
                    src_dir.display()
                ),
                err,
            )
        })?;
        let name = entry.file_name();
        if should_skip_package_sync_entry(&name, depth, in_system_dir) {
            continue;
        }
        let src_path = entry.path();
        let meta = fs::symlink_metadata(&src_path).map_err(|err| {
            ReleaseError::io(format!("stat source entry {}", src_path.display()), err)
        })?;
        if meta.file_type().is_symlink() {
            return Err(ReleaseError::PathValidation {
                path: src_path,
                reason: "refusing symlink inside release packages tree".to_string(),
            });
        }
        if meta.is_dir() {
            preflight_source_tree(&src_path, depth + 1, depth == 0 && name == "system")?;
        } else if !meta.is_file() {
            return Err(ReleaseError::PathValidation {
                path: src_path,
                reason: "refusing non-regular entry inside release packages tree".to_string(),
            });
        }
    }
    Ok(())
}

/// Validates source `packages/` tree and all 5 helper sync targets BEFORE swapping `current`
/// (matching `deploy/release-manager.sh`'s `--preflight-only` gate).
pub(crate) fn preflight_release_packages_and_helpers(
    cfg: &ReleaseConfig,
    release_dir: &Path,
    dry_run: bool,
) -> ReleaseResult<()> {
    let Some(targets) = resolve_helper_sync_targets(cfg, release_dir)? else {
        return Ok(());
    };
    preflight_source_tree(&targets.src_packages, 0, false)?;
    if dry_run {
        return Ok(());
    }
    preflight_helper_tree_target(&targets.target_opt_packages, &targets.src_packages)?;
    preflight_helper_tree_target(&targets.target_bin_aetherflow, &targets.src_packages)?;

    let src_certbot = targets.src_packages.join("system/af-certbot-sync");
    if fs::symlink_metadata(&src_certbot).is_ok() {
        preflight_helper_file_target(&targets.target_local_certbot)?;
        preflight_helper_file_target(&targets.target_usr_certbot)?;
    }
    let src_sandbox = targets.src_packages.join("system/af-systemd-sandbox");
    if fs::symlink_metadata(&src_sandbox).is_ok() {
        preflight_helper_file_target(&targets.target_usr_sandbox)?;
    }
    Ok(())
}

fn remove_retired_af_heal_if_present(usr_bin_dir: &Path) -> ReleaseResult<()> {
    let heal_path = usr_bin_dir.join("af-heal");
    let meta = match fs::symlink_metadata(&heal_path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(ReleaseError::io(
                format!("inspecting retired helper {}", heal_path.display()),
                err,
            ));
        }
    };
    if meta.is_dir() && !meta.file_type().is_symlink() {
        return Ok(());
    }
    ensure_no_symlink_ancestors(usr_bin_dir)?;
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::io::AsRawFd;
        let dir_fd = crate::fs_security::open_dir_nofollow(usr_bin_dir)?;
        let c_name = CString::new("af-heal").expect("static name has no NUL");
        let rc = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c_name.as_ptr(), 0) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(ReleaseError::io(
                    format!("unlinking retired helper {}", heal_path.display()),
                    err,
                ));
            }
        }
        crate::fs_security::sync_parent_dir_best_effort(usr_bin_dir);
    }
    #[cfg(not(unix))]
    {
        let _ = fs::remove_file(&heal_path);
    }
    Ok(())
}

/// Respects `dry_run` (no-op) and `cfg.isolated_root` containment strictly.
pub(crate) fn sync_release_packages_and_helpers(
    cfg: &ReleaseConfig,
    release_dir: &Path,
    dry_run: bool,
) -> ReleaseResult<()> {
    if dry_run {
        return Ok(());
    }

    let Some(targets) = resolve_helper_sync_targets(cfg, release_dir)? else {
        return Ok(());
    };

    // Target 1: /opt/AetherFlow/packages/
    if !same_directory_inode(&targets.src_packages, &targets.target_opt_packages) {
        sync_directory_tree_atomic_root_owned(
            &targets.src_packages,
            &targets.target_opt_packages,
            0o755,
        )?;
    }

    // Target 2: <cli_bin_dir>/AetherFlow/*
    if !same_directory_inode(&targets.src_packages, &targets.target_bin_aetherflow) {
        sync_directory_tree_atomic_root_owned(
            &targets.src_packages,
            &targets.target_bin_aetherflow,
            0o755,
        )?;
    }

    // Targets 3 & 4: <cli_bin_dir>/af-certbot-sync and /usr/bin/af-certbot-sync (regular files, never symlinks)
    let src_certbot = targets.src_packages.join("system/af-certbot-sync");
    sync_single_system_helper_if_present(
        &src_certbot,
        &[&targets.target_local_certbot, &targets.target_usr_certbot],
    )?;

    // Target 5: /usr/bin/af-systemd-sandbox (regular file, never symlink)
    let src_sandbox = targets.src_packages.join("system/af-systemd-sandbox");
    sync_single_system_helper_if_present(&src_sandbox, &[&targets.target_usr_sandbox])?;

    // Clean up retired `/usr/bin/af-heal` helper matching `deploy/release-manager.sh`.
    remove_retired_af_heal_if_present(&targets.target_usr_bin_dir)?;

    append_jsonl_log(
        &cfg.log_file,
        "INFO",
        "Synchronized release packages and root-owned system helpers atomically.",
    );
    Ok(())
}

fn sync_single_system_helper_if_present(src: &Path, targets: &[&Path]) -> ReleaseResult<()> {
    ensure_no_symlink_ancestors(src)?;
    match fs::symlink_metadata(src) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(ReleaseError::PathValidation {
                    path: src.to_path_buf(),
                    reason: "release system helper source must be a regular non-symlink file"
                        .to_string(),
                });
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(ReleaseError::io(
                format!("inspecting release system helper {}", src.display()),
                err,
            ));
        }
    }

    for dst in targets {
        crate::config::validate_no_parent_traversal(dst, "helper target path")?;
        if let Some(parent) = dst.parent().filter(|p| !p.as_os_str().is_empty()) {
            ensure_no_symlink_ancestors(parent)?;
            create_dir_all_no_symlinks(parent, 0o755)?;
        }
        atomic_replace_helper_file_root_owned(src, dst, 0o755)?;
    }
    Ok(())
}

fn same_directory_inode(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(ma), Ok(mb)) = (fs::symlink_metadata(a), fs::symlink_metadata(b)) {
            return !ma.file_type().is_symlink()
                && !mb.file_type().is_symlink()
                && ma.dev() == mb.dev()
                && ma.ino() == mb.ino();
        }
        false
    }
    #[cfg(not(unix))]
    {
        canonicalize_preserve_normal(a) == canonicalize_preserve_normal(b)
    }
}

fn sync_directory_tree_atomic_root_owned(
    src_root: &Path,
    dst_root: &Path,
    file_mode: u32,
) -> ReleaseResult<()> {
    ensure_no_symlink_ancestors(src_root)?;
    ensure_no_symlink_ancestors(dst_root)?;
    apply_root_owned_dir_mode(dst_root, 0o755)?;
    sync_dir_recursive(src_root, dst_root, file_mode, 0, false)
}

fn sync_dir_recursive(
    src_dir: &Path,
    dst_dir: &Path,
    file_mode: u32,
    depth: usize,
    in_system_dir: bool,
) -> ReleaseResult<()> {
    if depth > MAX_PACKAGE_SYNC_DEPTH {
        return Err(ReleaseError::PathValidation {
            path: src_dir.to_path_buf(),
            reason: format!(
                "package sync directory nesting exceeded maximum depth ({MAX_PACKAGE_SYNC_DEPTH})"
            ),
        });
    }

    let mut expected_names = std::collections::BTreeSet::new();
    let entries = fs::read_dir(src_dir).map_err(|err| {
        ReleaseError::io(
            format!(
                "reading source directory {} for helper sync",
                src_dir.display()
            ),
            err,
        )
    })?;

    for entry_res in entries {
        let entry = entry_res.map_err(|err| {
            ReleaseError::io(
                format!("iterating source directory {}", src_dir.display()),
                err,
            )
        })?;
        let name = entry.file_name();
        if should_skip_package_sync_entry(&name, depth, in_system_dir) {
            continue;
        }
        let src_path = entry.path();
        let dst_path = dst_dir.join(&name);

        let src_meta = fs::symlink_metadata(&src_path).map_err(|err| {
            ReleaseError::io(format!("stat source entry {}", src_path.display()), err)
        })?;
        if src_meta.file_type().is_symlink() {
            return Err(ReleaseError::PathValidation {
                path: src_path,
                reason: "refusing symlink inside release packages tree".to_string(),
            });
        }

        let child_is_system = depth == 0 && name == "system";
        expected_names.insert(name);

        if src_meta.is_dir() {
            if let Ok(dst_meta) = fs::symlink_metadata(&dst_path) {
                if dst_meta.file_type().is_symlink() || !dst_meta.is_dir() {
                    return Err(ReleaseError::PathValidation {
                        path: dst_path,
                        reason: "destination package directory is a symlink or non-directory"
                            .to_string(),
                    });
                }
            }
            apply_root_owned_dir_mode(&dst_path, 0o755)?;
            sync_dir_recursive(&src_path, &dst_path, file_mode, depth + 1, child_is_system)?;
        } else if src_meta.is_file() {
            atomic_replace_helper_file_root_owned(&src_path, &dst_path, file_mode)?;
        } else {
            return Err(ReleaseError::PathValidation {
                path: src_path,
                reason: "refusing non-regular entry inside release packages tree".to_string(),
            });
        }
    }

    // Prune stale files/directories in dst_dir that are absent from src_dir without following symlinks.
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::AsRawFd;

        let dst_dir_fd = crate::fs_security::open_dir_nofollow(dst_dir)?;
        let dfd = dst_dir_fd.as_raw_fd();
        let dst_entries = fs::read_dir(dst_dir).map_err(|err| {
            ReleaseError::io(
                format!(
                    "reading destination directory {} for pruning",
                    dst_dir.display()
                ),
                err,
            )
        })?;
        for entry_res in dst_entries {
            let entry = entry_res.map_err(|err| {
                ReleaseError::io(
                    format!("iterating destination directory {}", dst_dir.display()),
                    err,
                )
            })?;
            let name = entry.file_name();
            if expected_names.contains(&name) {
                continue;
            }
            let name_c =
                CString::new(name.as_bytes()).map_err(|_| ReleaseError::PathValidation {
                    path: dst_dir.join(&name),
                    reason: "stale package entry name contains NUL byte".to_string(),
                })?;
            prune_stale_entry_at_dfd(dfd, &name_c, &dst_dir.join(&name), depth + 1)?;
        }
        crate::fs_security::sync_dir_fd(dfd, dst_dir)?;
    }

    #[cfg(not(unix))]
    {
        let dst_entries = fs::read_dir(dst_dir).map_err(|err| {
            ReleaseError::io(
                format!(
                    "reading destination directory {} for pruning",
                    dst_dir.display()
                ),
                err,
            )
        })?;
        for entry_res in dst_entries {
            let entry = entry_res.map_err(|err| {
                ReleaseError::io(
                    format!("iterating destination directory {}", dst_dir.display()),
                    err,
                )
            })?;
            let name = entry.file_name();
            if expected_names.contains(&name) {
                continue;
            }
            let stale_path = entry.path();
            let meta = match fs::symlink_metadata(&stale_path) {
                Ok(m) => m,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(ReleaseError::io(
                        format!("stat stale package entry {}", stale_path.display()),
                        err,
                    ));
                }
            };
            if meta.file_type().is_symlink() || !meta.is_dir() {
                fs::remove_file(&stale_path).map_err(|err| {
                    ReleaseError::io(
                        format!("removing stale package entry {}", stale_path.display()),
                        err,
                    )
                })?;
            } else {
                remove_dir_tree_no_symlinks(&stale_path, depth + 1)?;
            }
        }
        sync_parent_dir_best_effort(dst_dir);
    }

    Ok(())
}

#[cfg(unix)]
fn prune_stale_entry_at_dfd(
    parent_dfd: std::os::unix::io::RawFd,
    name_c: &std::ffi::CStr,
    display_path: &Path,
    depth: usize,
) -> ReleaseResult<()> {
    use std::ffi::{CStr, CString};
    use std::os::unix::io::{AsRawFd, FromRawFd};

    if depth > MAX_PACKAGE_SYNC_DEPTH + 16 {
        return Err(ReleaseError::PathValidation {
            path: display_path.to_path_buf(),
            reason: "stale directory pruning exceeded maximum depth".to_string(),
        });
    }

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            parent_dfd,
            name_c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(ReleaseError::io(
            format!("stat stale package entry {}", display_path.display()),
            err,
        ));
    }

    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        if unsafe { libc::unlinkat(parent_dfd, name_c.as_ptr(), 0) } != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(ReleaseError::io(
                    format!("removing stale package entry {}", display_path.display()),
                    err,
                ));
            }
        }
        return Ok(());
    }

    let child_fd = unsafe {
        libc::openat(
            parent_dfd,
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if child_fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(ReleaseError::io(
            format!("opening stale directory {}", display_path.display()),
            err,
        ));
    }
    let child_file = unsafe { fs::File::from_raw_fd(child_fd) };
    let dup_fd = unsafe { libc::fcntl(child_file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup_fd < 0 {
        return Err(ReleaseError::io(
            format!(
                "duplicating fd for stale directory {}",
                display_path.display()
            ),
            std::io::Error::last_os_error(),
        ));
    }
    let dir_ptr = unsafe { libc::fdopendir(dup_fd) };
    if dir_ptr.is_null() {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(dup_fd) };
        return Err(ReleaseError::io(
            format!("fdopendir stale directory {}", display_path.display()),
            err,
        ));
    }

    let mut child_names: Vec<CString> = Vec::new();
    loop {
        let entry_ptr = unsafe { libc::readdir(dir_ptr) };
        if entry_ptr.is_null() {
            break;
        }
        let d_name = unsafe { CStr::from_ptr((*entry_ptr).d_name.as_ptr()) };
        let bytes = d_name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        child_names.push(d_name.to_owned());
    }
    unsafe { libc::closedir(dir_ptr) };

    for child_c in &child_names {
        let child_display = display_path.join(String::from_utf8_lossy(child_c.as_bytes()).as_ref());
        prune_stale_entry_at_dfd(child_file.as_raw_fd(), child_c, &child_display, depth + 1)?;
    }
    drop(child_file);

    if unsafe { libc::unlinkat(parent_dfd, name_c.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOENT) {
            return Err(ReleaseError::io(
                format!("removing stale directory {}", display_path.display()),
                err,
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn remove_dir_tree_no_symlinks(dir: &Path, depth: usize) -> ReleaseResult<()> {
    if depth > MAX_PACKAGE_SYNC_DEPTH + 16 {
        return Err(ReleaseError::PathValidation {
            path: dir.to_path_buf(),
            reason: "stale directory pruning exceeded maximum depth".to_string(),
        });
    }
    let meta = fs::symlink_metadata(dir)
        .map_err(|err| ReleaseError::io(format!("stat stale directory {}", dir.display()), err))?;
    if meta.file_type().is_symlink() {
        return fs::remove_file(dir).map_err(|err| {
            ReleaseError::io(format!("removing stale symlink {}", dir.display()), err)
        });
    }
    for entry_res in fs::read_dir(dir).map_err(|err| {
        ReleaseError::io(format!("reading stale directory {}", dir.display()), err)
    })? {
        let entry = entry_res.map_err(|err| {
            ReleaseError::io(format!("iterating stale directory {}", dir.display()), err)
        })?;
        let child = entry.path();
        let child_meta = fs::symlink_metadata(&child).map_err(|err| {
            ReleaseError::io(format!("stat stale child {}", child.display()), err)
        })?;
        if child_meta.file_type().is_symlink() || !child_meta.is_dir() {
            fs::remove_file(&child).map_err(|err| {
                ReleaseError::io(format!("removing stale child {}", child.display()), err)
            })?;
        } else {
            remove_dir_tree_no_symlinks(&child, depth + 1)?;
        }
    }
    fs::remove_dir(dir)
        .map_err(|err| ReleaseError::io(format!("removing stale directory {}", dir.display()), err))
}

#[cfg(test)]
mod wave1b_engine_tests {
    use super::*;
    use crate::artifact::compute_file_sha256;
    use crate::health::{HealthCheckAttempt, HealthProber, LifecycleController};
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::collections::{BTreeSet, VecDeque};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tar::{Builder, EntryType, Header};

    struct TestProvider {
        tag: String,
        archive: PathBuf,
        manifest: String,
    }
    impl ArtifactProvider for TestProvider {
        fn resolve_release_tag(
            &self,
            _config: &ReleaseConfig,
            _channel: ReleaseChannel,
        ) -> ReleaseResult<String> {
            Ok(self.tag.clone())
        }
        fn fetch_release_bundle(
            &self,
            config: &ReleaseConfig,
            _channel: ReleaseChannel,
            _tag: &str,
            staging_dir: &Path,
        ) -> ReleaseResult<(PathBuf, String)> {
            let dst = staging_dir.join(&config.artifact_name);
            fs::copy(&self.archive, &dst).map_err(|e| ReleaseError::io("copy mock archive", e))?;
            Ok((dst, self.manifest.clone()))
        }
    }

    #[derive(Default)]
    struct TestLifecycle;
    impl LifecycleController for TestLifecycle {
        fn query_unit_environment(&self, _unit: &str) -> Option<String> {
            None
        }
        fn restart_systemd_units(&self, _config: &ReleaseConfig) -> ReleaseResult<()> {
            Ok(())
        }
        fn stop_database_services(&self, _db_path: &Path) -> ReleaseResult<()> {
            Ok(())
        }
        fn terminate_legacy_pm2(&self) -> ReleaseResult<()> {
            Ok(())
        }
    }

    struct TestProber(Mutex<VecDeque<u16>>);
    impl HealthProber for TestProber {
        fn check_once(&self, _endpoint: &str) -> ReleaseResult<HealthCheckAttempt> {
            let code = self.0.lock().unwrap().pop_front().unwrap_or(200);
            Ok(HealthCheckAttempt {
                http_status: code,
                body: if code == 200 {
                    r#"{"status":"ready"}"#.to_string()
                } else {
                    r#"{"status":"degraded"}"#.to_string()
                },
            })
        }
    }

    fn build_tar(dest: &Path, artifact_name: &str, entries: &[(&str, &[u8])]) -> (PathBuf, String) {
        let file = fs::File::create(dest).unwrap();
        let enc = GzEncoder::new(file, Compression::fast());
        let mut tar = Builder::new(enc);
        for (rel, data) in entries {
            let mut h = Header::new_gnu();
            h.set_entry_type(EntryType::Regular);
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append_data(&mut h, *rel, *data).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap();
        let sha = compute_file_sha256(dest).unwrap();
        (dest.to_path_buf(), format!("{sha}  {artifact_name}\n"))
    }

    #[test]
    fn crate09_allocate_unique_release_epoch_id_is_concurrently_strictly_unique() {
        let root = std::env::temp_dir().join(format!("af-epoch-seq-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let collected = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let dir = root.clone();
            let out = Arc::clone(&collected);
            handles.push(std::thread::spawn(move || {
                let mut local = Vec::with_capacity(64);
                for _ in 0..64 {
                    local.push(allocate_unique_release_epoch_id(&dir));
                }
                out.lock().unwrap().extend(local);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let all = collected.lock().unwrap();
        let unique: BTreeSet<&String> = all.iter().collect();
        assert_eq!(
            unique.len(),
            all.len(),
            "concurrent epoch ID allocations must never collide"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn crate09_preflight_cli_failure_cleans_up_staged_release_dir() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let root =
            std::env::temp_dir().join(format!("af-preflight-clean-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let mut cfg = ReleaseConfig::for_root(&root);
        cfg.health_interval = Duration::ZERO;

        let ro_bin = root.join("ro-bin");
        fs::create_dir_all(&ro_bin).unwrap();
        fs::set_permissions(&ro_bin, fs::Permissions::from_mode(0o555)).unwrap();
        cfg.cli_bin_dir = ro_bin.clone();

        let tar = root.join("v4.0.1.tar.gz");
        let (_, manifest) = build_tar(
            &tar,
            &cfg.artifact_name,
            &[
                ("aetherflow-api", b"api"),
                ("bin/af", b"cli"),
                (".version", b"v4.0.1\n"),
                ("web/dist/index.html", b"<html></html>"),
                ("web/dist/app.wasm", b"\0asm\x01\0\0\0"),
            ],
        );

        let engine = ReleaseEngine::new(
            cfg.clone(),
            TestProvider {
                tag: "v4.0.1".to_string(),
                archive: tar,
                manifest,
            },
            TestLifecycle,
            TestProber(Mutex::new(VecDeque::new())),
        );
        let err = engine.execute(&ReleaseOptions::default()).unwrap_err();
        let _ = fs::set_permissions(&ro_bin, fs::Permissions::from_mode(0o755));

        assert_eq!(err.exit_code(), crate::error::ExitCode::PreSwapFailure);
        let rec = RecoveryState::load(&cfg.releases_dir).unwrap().unwrap();
        assert_eq!(rec.phase, ReleasePhase::Failed);
        let leaked = rec.candidate_release.expect("candidate recorded");
        assert!(
            !leaked.exists(),
            "preflight_cli_entrypoints failure must clean up release_dir {}",
            leaked.display()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn pipe02_deploy_and_rollback_atomically_sync_all_five_helper_targets_as_regular_files() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        let root = std::env::temp_dir().join(format!("af-pipe02-sync-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let mut cfg = ReleaseConfig::for_root(&root);
        cfg.health_interval = Duration::ZERO;
        cfg.health_retries = 1;

        // Pre-seed a stale file in /opt/AetherFlow/packages and /usr/local/bin/AetherFlow to verify pruning.
        let opt_packages = root.join("opt/AetherFlow/packages");
        let bin_aetherflow = root.join("usr/local/bin/AetherFlow");
        fs::create_dir_all(opt_packages.join("system")).unwrap();
        fs::create_dir_all(bin_aetherflow.join("system")).unwrap();
        fs::write(opt_packages.join("system/af-heal"), b"stale-heal").unwrap();
        fs::write(bin_aetherflow.join("system/af-heal"), b"stale-heal").unwrap();

        // Deploy v4.0.1 with all package/system helpers.
        let tar_v1 = root.join("v4.0.1.tar.gz");
        let (_, manifest_v1) = build_tar(
            &tar_v1,
            &cfg.artifact_name,
            &[
                ("aetherflow-api", b"api-v1"),
                ("bin/af", b"cli-v1"),
                (".version", b"v4.0.1\n"),
                ("web/dist/index.html", b"<html>v1</html>"),
                ("web/dist/app.wasm", b"\0asm\x01\0\0\0"),
                ("packages/common.sh", b"# common-v1\n"),
                ("packages/lib/helpers.sh", b"# lib-v1\n"),
                (
                    "packages/package/install/installpackage-demo",
                    b"# demo-v1\n",
                ),
                (
                    "packages/system/af-certbot-sync",
                    b"#!/bin/bash\necho certbot-v1\n",
                ),
                (
                    "packages/system/af-systemd-sandbox",
                    b"#!/bin/bash\necho sandbox-v1\n",
                ),
            ],
        );
        let eng_v1 = ReleaseEngine::new(
            cfg.clone(),
            TestProvider {
                tag: "v4.0.1".to_string(),
                archive: tar_v1,
                manifest: manifest_v1,
            },
            TestLifecycle,
            TestProber(Mutex::new(VecDeque::from([200]))),
        );
        eng_v1.execute(&ReleaseOptions::default()).unwrap();

        let local_certbot = root.join("usr/local/bin/af-certbot-sync");
        let usr_certbot = root.join("usr/bin/af-certbot-sync");
        let usr_sandbox = root.join("usr/bin/af-systemd-sandbox");

        // Verify ALL 5 targets synced as regular 0o755 non-symlink files, and stale af-heal pruned!
        for path in [
            opt_packages.join("common.sh"),
            opt_packages.join("lib/helpers.sh"),
            opt_packages.join("package/install/installpackage-demo"),
            opt_packages.join("system/af-certbot-sync"),
            opt_packages.join("system/af-systemd-sandbox"),
            bin_aetherflow.join("common.sh"),
            bin_aetherflow.join("lib/helpers.sh"),
            bin_aetherflow.join("package/install/installpackage-demo"),
            bin_aetherflow.join("system/af-certbot-sync"),
            bin_aetherflow.join("system/af-systemd-sandbox"),
            local_certbot.clone(),
            usr_certbot.clone(),
            usr_sandbox.clone(),
        ] {
            let meta = fs::symlink_metadata(&path)
                .unwrap_or_else(|_| panic!("missing {}", path.display()));
            assert!(
                !meta.file_type().is_symlink() && meta.file_type().is_file(),
                "{} must be a regular non-symlink file",
                path.display()
            );
            assert_eq!(
                meta.permissions().mode() & 0o777,
                0o755,
                "{} must have mode 0755",
                path.display()
            );
        }
        assert!(!opt_packages.join("system/af-heal").exists());
        assert!(!bin_aetherflow.join("system/af-heal").exists());
        assert_eq!(
            fs::read(&local_certbot).unwrap(),
            b"#!/bin/bash\necho certbot-v1\n"
        );
        assert_eq!(
            fs::read(&usr_certbot).unwrap(),
            b"#!/bin/bash\necho certbot-v1\n"
        );
        assert_eq!(
            fs::read(&usr_sandbox).unwrap(),
            b"#!/bin/bash\necho sandbox-v1\n"
        );
        let certbot_v1_ino = fs::symlink_metadata(&local_certbot).unwrap().ino();

        // Deploy v4.0.2 -> updates all 5 targets atomically (new inode!).
        let tar_v2 = root.join("v4.0.2.tar.gz");
        let (_, manifest_v2) = build_tar(
            &tar_v2,
            &cfg.artifact_name,
            &[
                ("aetherflow-api", b"api-v2"),
                ("bin/af", b"cli-v2"),
                (".version", b"v4.0.2\n"),
                ("web/dist/index.html", b"<html>v2</html>"),
                ("web/dist/app.wasm", b"\0asm\x01\0\0\0"),
                ("packages/common.sh", b"# common-v2\n"),
                (
                    "packages/system/af-certbot-sync",
                    b"#!/bin/bash\necho certbot-v2\n",
                ),
                (
                    "packages/system/af-systemd-sandbox",
                    b"#!/bin/bash\necho sandbox-v2\n",
                ),
            ],
        );
        let eng_v2 = ReleaseEngine::new(
            cfg.clone(),
            TestProvider {
                tag: "v4.0.2".to_string(),
                archive: tar_v2,
                manifest: manifest_v2,
            },
            TestLifecycle,
            TestProber(Mutex::new(VecDeque::from([200, 200]))),
        );
        eng_v2.execute(&ReleaseOptions::default()).unwrap();
        assert_ne!(
            fs::symlink_metadata(&local_certbot).unwrap().ino(),
            certbot_v1_ino
        );
        assert_eq!(
            fs::read(&usr_certbot).unwrap(),
            b"#!/bin/bash\necho certbot-v2\n"
        );
        assert_eq!(
            fs::read(&usr_sandbox).unwrap(),
            b"#!/bin/bash\necho sandbox-v2\n"
        );
        assert_eq!(
            fs::read(opt_packages.join("common.sh")).unwrap(),
            b"# common-v2\n"
        );

        // Rollback -> reverts all 5 targets atomically back to v4.0.1!
        eng_v2
            .execute(&ReleaseOptions {
                command: ReleaseCommand::Rollback,
                ..ReleaseOptions::default()
            })
            .unwrap();
        assert_eq!(
            fs::read(&local_certbot).unwrap(),
            b"#!/bin/bash\necho certbot-v1\n"
        );
        assert_eq!(
            fs::read(&usr_certbot).unwrap(),
            b"#!/bin/bash\necho certbot-v1\n"
        );
        assert_eq!(
            fs::read(&usr_sandbox).unwrap(),
            b"#!/bin/bash\necho sandbox-v1\n"
        );
        assert_eq!(
            fs::read(opt_packages.join("common.sh")).unwrap(),
            b"# common-v1\n"
        );
        assert_eq!(
            fs::read(bin_aetherflow.join("lib/helpers.sh")).unwrap(),
            b"# lib-v1\n"
        );

        // Dry-run must NOT mutate any of the 5 targets.
        let dry_rel = root.join("dry-rel");
        fs::create_dir_all(dry_rel.join("packages/system")).unwrap();
        fs::write(
            dry_rel.join("packages/system/af-certbot-sync"),
            b"DRY-SHOULD-NOT-WRITE",
        )
        .unwrap();
        sync_release_packages_and_helpers(&cfg, &dry_rel, true).unwrap();
        assert_eq!(
            fs::read(&local_certbot).unwrap(),
            b"#!/bin/bash\necho certbot-v1\n"
        );

        // Legacy symlinked leaf (/usr/local/bin/af-certbot-sync -> victim) is atomically replaced
        // with a regular 0755 file without touching victim (matching release-manager.sh PIPE-02).
        let victim = root.join("victim");
        fs::write(&victim, b"UNTOUCHED").unwrap();
        fs::remove_file(&local_certbot).unwrap();
        symlink(&victim, &local_certbot).unwrap();
        preflight_release_packages_and_helpers(&cfg, &dry_rel, false).unwrap();
        sync_release_packages_and_helpers(&cfg, &dry_rel, false).unwrap();
        assert!(!fs::symlink_metadata(&local_certbot)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&local_certbot).unwrap(), b"DRY-SHOULD-NOT-WRITE");
        assert_eq!(fs::read(&victim).unwrap(), b"UNTOUCHED");

        // Symlinked subdirectory inside destination tree (/opt/AetherFlow/packages/system)
        // MUST fail closed in preflight BEFORE any symlink swap!
        let outside_dir = root.join("outside-dir");
        fs::create_dir_all(&outside_dir).unwrap();
        fs::remove_dir_all(opt_packages.join("system")).unwrap();
        symlink(&outside_dir, opt_packages.join("system")).unwrap();
        let sym_err = preflight_release_packages_and_helpers(&cfg, &dry_rel, false).unwrap_err();
        assert!(matches!(sym_err, ReleaseError::PathValidation { .. }));

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn pipe15_ensure_fhs_layout_sets_0750_env_dir_and_0640_migrated_env_file() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("af-pipe15-env-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let cfg = ReleaseConfig::for_root(&root);
        fs::create_dir_all(cfg.legacy_opt_root.join("backend")).unwrap();
        fs::write(cfg.legacy_opt_root.join("backend/.env"), "JWT_SECRET=abc\n").unwrap();

        let eng = ReleaseEngine::new(
            cfg.clone(),
            TestProvider {
                tag: "v4.0.1".to_string(),
                archive: PathBuf::new(),
                manifest: String::new(),
            },
            TestLifecycle,
            TestProber(Mutex::new(VecDeque::new())),
        );
        eng.ensure_fhs_layout(&cfg, false).unwrap();

        let env_dir_mode = fs::symlink_metadata(&cfg.env_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(env_dir_mode, 0o750, "env_dir must be 0750");

        let env_file_mode = fs::symlink_metadata(&cfg.host_env_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(env_file_mode, 0o640, "migrated env file must be 0640");

        let _ = fs::remove_dir_all(&root);
    }
}
