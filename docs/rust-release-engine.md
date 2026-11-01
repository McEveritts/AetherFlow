# AetherFlow Rust Release Engine (`af-release`)

## Overview & Incremental Migration Architecture

`af-release` (`backend-rs/crates/af-release`) provides the native Rust release-management foundation that incrementally replaces [`deploy/release-manager.sh`](../deploy/release-manager.sh) for AetherFlow's bare-metal `systemd` + `Apache2` control plane.

To guarantee zero-downtime safety during migration:
1. **Production Shell Path Preserved**: `deploy/release-manager.sh` and `deploy/release-manager.conf` remain untouched on disk and continue to be staged into every candidate release directory (`${RELEASE_DIR}/deploy/`).
2. **No Unsafe Partial Activation**: `af-release` is delivered as a standalone, self-contained workspace crate with explicit dependency-injected traits (`ArtifactProvider`, `LifecycleController`, `HealthProber`). The parent workspace (`backend-rs/Cargo.toml`), privileged runner (`af-runner`), and API binary (`af-api`) can switch `/v1/self-update` and `aetherflow-api release` over to `af-release` once integrated, while falling back to `deploy/release-manager.sh` for any explicitly unsupported legacy mode (such as `--from-source`).
3. **Pure Bare-Metal Systemd**: Zero Docker dependencies. All service lifecycle transitions operate strictly on `aetherflow-runner.service` and `aetherflow-api.service` under `/opt/AetherFlow/current`.

---

## Stage-by-Stage Parity with `deploy/release-manager.sh`

| Stage | `release-manager.sh` Function | `af-release` Module & API | Preserved Invariants |
| :--- | :--- | :--- | :--- |
| **Locking & Recovery** | Per-snapshot `flock` (`SNAPSHOT_TIMEOUT`) | [`lock::ReleaseLockGuard`], [`lock::RecoveryState`] | Adds whole-operation exclusive locking (`${RELEASES_DIR}/.release.lock`) plus atomic crash-recovery journaling (`${RELEASES_DIR}/.recovery_state.json`) written via exclusive (`create_new`) `0600` UUID-tagged temp files, `sync_all()`, and `rename`. Honors unfinished post-swap recovery states before any new mutation so the known-good `.previous_release` pointer is never overwritten by an interrupted unhealthy deployment. |
| **Stage 0: FHS & DB Resolution** | `ensure_fhs_layout`, `resolve_db_path`, `read_env_file_value`, `read_systemd_environment_value` | [`config::resolve_db_path`], [`ReleaseEngine::ensure_fhs_layout`], [`fs_security::apply_service_ownership`] | Exact 4-tier live SQLite path precedence: `AF_DB_PATH` $\to$ `DB_PATH` / `AETHERFLOW_DB_PATH` parsed from `ENV_FILE` (never sourced, last non-empty wins) $\to$ `systemctl show -p Environment aetherflow-api` (POSIX `shlex` tokenization) $\to$ `${DATA_DIR}/${SQLITE_DB}`. Enforces `0700` on `DATA_DIR` and `0600` **before writing** on migrated SQLite DBs and `.env` files while preserving source `uid`/`gid` or resolving the `aetherflow` service user via `getpwnam_r`. |
| **Stage 1: Release Scaffold** | `resolve_release_tag`, `pull_prebuilt_artifact`, `simulate_offline_artifact`, `stage_running_release_manager` | [`artifact::select_release_tag_from_json`], [`artifact::verify_artifact_checksum`], [`artifact::extract_and_validate_release_archive`], [`fs_security::create_new_dir_exclusive`] | Supports `stable`, `nightly`, and `experimental` channels. Stages downloads in fresh, globally unique (`UUIDv4` + PID) `0700` directories created exclusively (`create_dir`). Verifies every ancestor and relative component against symlinks (`lstat`), extracts regular files exclusively (`create_new(true)`), rejects collisions/pre-planted files/symlinks/device nodes, verifies `./aetherflow-api`, stamps `.version`, and stages `release-manager.sh` + `release-manager.conf`. |
| **Stage 1.5: State Snapshot** | `state_snapshot`, `sqlite_online_backup`, `sqlite_integrity` | [`snapshot::create_state_snapshot`], [`snapshot::sqlite_online_backup`], [`snapshot::sqlite_integrity`] | Creates `${RELEASE_DIR}/data-snapshot` with `0700` permissions and pre-creates exclusive `0600` temporary DB files **before** running `rusqlite::backup::Backup` (`SQLITE_OPEN_READ_ONLY` on source so hot WALs are never checkpointed), `sync_all()`, and atomic `rename` to `.bak`. Verifies `PRAGMA integrity_check == "ok"` before symlink swap and writes `MANIFEST.sha256` (`0600`). |
| **Stage 2: Atomic Symlink Swap** | `symlink_swap` | [`symlink::perform_symlink_swap`], [`symlink::atomic_replace_symlink`] | Records the resolved current target atomically in `${RELEASES_DIR}/.previous_release` (`0600`, guarded against self-overwrite when `previous == current`), creates `${CURRENT_LINK}.tmp.<epoch>.<nanos>.<uuid>`, and atomically renames it over `${CURRENT_LINK}`. |
| **Stage 3: Systemd & Readiness** | `install_packaged_unit`, `restart_systemd_units`, `parse_health_status`, `health_probe` | [`health::install_packaged_unit_if_missing`], [`health::poll_readiness_probe`], [`health::LifecycleController`] | Installs packaged systemd units **only if missing** (never overwrites live `/etc/systemd/system/aetherflow-api.service` so custom `ReadWritePaths` are preserved), runs `daemon-reload`, stops legacy `aetherflow-frontend.service` / PM2, propagates `systemctl enable` and `restart` errors, and polls `/health/ready` for HTTP 200 with `"status": "ready"` or `"ok"`. |
| **Stage 4: Rollback & Restore** | `rollback`, `state_restore`, `stop_database_services` | [`ReleaseEngine::execute`] (`ReleaseCommand::Rollback`), [`snapshot::restore_state_if_corrupted`], [`snapshot::verify_snapshot_manifest`] | Reverts `current` to `.previous_release` (and restores prior `.previous_release` on automatic rollback when available so `previous != current`). If the live DB fails `PRAGMA integrity_check`: (1) verifies `MANIFEST.sha256` digest and `PRAGMA integrity_check == "ok"` on `.bak`, (2) requires `stop_database_services` to succeed (`?`), (3) copies `.bak` to an exclusive `0600` sibling temp file, `sync_all()`, and verifies temp integrity, (4) preserves `uid`/`gid` from the existing DB or `aetherflow` user, (5) quarantines `${db}.corrupted.<epoch>.<uuid>`, removes `-wal`/`-shm` sidecars, and atomically renames the verified temp DB into place. |
| **Stage 5: Housekeeping** | `cleanup_old_releases` | [`symlink::cleanup_old_releases`] | Tracks `Stage5Cleanup` $\to$ `Complete` / `Failed` in `.recovery_state.json`. Retains `MAX_RELEASES` newest directories sorted by epoch while unconditionally exempting both `current` and `.previous_release` targets from deletion. |
| **Stage 6: Systemd Migration** | `migrate_systemd` | [`ReleaseCommand::MigrateSystemd`], [`health::wait_for_listener_stopped`] | Tracks `Stage6MigrateSystemd` $\to$ `Complete` / `Failed` in `.recovery_state.json`. Verifies FHS layout, terminates legacy PM2 daemons, runs a bounded TCP listener termination check on the health endpoint socket before starting the new systemd unit, and verifies `/health/ready`. |

---

## Public API Surface (`af_release`)

### Core Configuration & Options (`af_release::config`)
- `ReleaseChannel`: `Stable`, `Nightly`, `Experimental` (`FromStr`, `Display`, `Serialize`, `Deserialize`).
- `ReleaseCommand`: `Deploy`, `Rollback`, `Cleanup`, `MigrateSystemd`.
- `ReleaseOptions`:
  - `ReleaseOptions::parse_args(args, default_channel) -> ReleaseResult<ReleaseOptions>`
  - `ReleaseOptions::validate(&self) -> ReleaseResult<()>`
- `ReleaseConfig`:
  - `ReleaseConfig::default()` — canonical FHS production layout (`/opt/AetherFlow/releases`, `/opt/AetherFlow/current`, `/var/lib/aetherflow`, `/etc/aetherflow/aetherflow.env`).
  - `ReleaseConfig::for_root(root)` — sandboxed root layout for tests.
  - `ReleaseConfig::load_with_env(conf_path, env_map) -> ReleaseResult<ReleaseConfig>`
  - `ReleaseConfig::load_from_process_env(conf_path) -> ReleaseResult<ReleaseConfig>`
  - `ReleaseConfig::with_dry_run(&self, dry_run) -> ReleaseConfig`
- `resolve_db_path(config, systemd_env_blob) -> ResolvedDbPath`

### Engine, Filesystem Security & Traits (`af_release::engine`, `af_release::fs_security`, `af_release::artifact`, `af_release::health`)
- `ReleaseEngine<A: ArtifactProvider, L: LifecycleController, H: HealthProber>`:
  - `ReleaseEngine::new_production(config)`
  - `ReleaseEngine::new(config, artifact_provider, lifecycle, health_prober)`
  - `ReleaseEngine::execute(&self, opts: &ReleaseOptions) -> ReleaseResult<ReleaseOutcome>`
  - `ReleaseEngine::inspect_status(&self) -> ReleaseResult<ReleaseEngineStatus>`
  - `ReleaseEngine::ensure_fhs_layout(&self, cfg: &ReleaseConfig, dry_run: bool) -> ReleaseResult<ResolvedDbPath>`
- Hardened Filesystem Primitives (`af_release::fs_security`):
  - `ensure_no_symlink_ancestors`, `ensure_no_symlink_in_relative_chain`
  - `create_dir_all_no_symlinks`, `create_new_dir_exclusive`
  - `open_exclusive_private_file`, `atomic_write_bytes_with_mode`, `atomic_copy_file_with_mode`
  - `OwnershipMetadata`, `apply_service_ownership`, `apply_data_dir_ownership_and_mode`

### Runner & CLI Integration (`af_release::admin`)
- `validate_self_update_request(req: &af_models::SelfUpdateRequest) -> Result<ValidatedSelfUpdateRequest, af_models::RunnerResponse>`
  - Accepts `command` $\in$ `{"", "deploy", "rollback"}` and `channel` $\in$ `{"", "stable", "nightly", "experimental"}`.
- `execute_self_update_sync(req: &ValidatedSelfUpdateRequest, config: ReleaseConfig) -> (ExitCode, af_models::RunnerResponse)`
- `run_cli_from_args(args, conf_override) -> (ExitCode, ReleaseResult<ReleaseOutcome>)`

---

## Error & Exit-Code Contract (`af_release::error`)

| `ExitCode` | Numeric | `ReleaseError` Variants | Meaning |
| :--- | :---: | :--- | :--- |
| `ExitCode::Success` | `0` | — | Command completed (and passed readiness probe if live). |
| `ExitCode::PreSwapFailure` | `1` | `TagResolution`, `ArtifactVerification`, `ChecksumMismatch`, `ArchiveExtraction`, `Snapshot`, `IntegrityFailed`, `SymlinkSwap`, `Systemd`, `Io` | Pre-swap or lifecycle failure; candidate directory is cleaned up before symlink swap. |
| `ExitCode::HealthProbeFailedRollback` | `2` | `HealthProbeFailed`, `RolledBackAfterProbeFailure` | Stage 3 readiness probe failed after `HEALTH_RETRIES`; Stage 4 rollback to `.previous_release` succeeded. |
| `ExitCode::RollbackFailed` | `3` | `Rollback` | Stage 4 rollback encountered an unrecoverable error, or an unfinished post-swap deployment in `.recovery_state.json` requires explicit `rollback` before a new deploy. |
| `ExitCode::ConfigurationOrUsageError` | `4` | `Config`, `PathValidation`, `Unsupported` | Invalid CLI flags, path/symlink traversal in config or release directories, `--offline` without `--dry-run`, or unsupported `--from-source`. |
| `ExitCode::LockContention` | `5` | `LockBusy` | Another release operation is currently holding `.release.lock` or `.snapshot.lock`. |

---

## Documented Parity Gaps & Intentional Boundaries

1. **`--from-source` Fallback Mode (`ReleaseError::Unsupported`)**:
   - `deploy/release-manager.sh --from-source` runs `git fetch`, `rsync`, `npm ci && npm run build`, and `cargo build --release` or `go build` on the target host.
   - `af-release` intentionally rejects `--from-source` with `ReleaseError::Unsupported` (`ExitCode::ConfigurationOrUsageError = 4`) to enforce the v4.0 pull-based, SHA-256-verified single-binary architecture and avoid requiring Node.js/Rust/Go toolchains on production hosts. Callers needing an emergency source build should invoke `deploy/release-manager.sh --from-source` directly (checked via [`is_unsupported_error`]).
2. **OS User Ownership (`chown aetherflow:aetherflow`)**:
   - `af-release` enforces `0700` directory permissions on `DATA_DIR` and `data-snapshot/`, and `0600` file permissions **before writing** on SQLite databases, snapshots, manifests, recovery journals, and `.env` files on Unix.
   - During Stage 0 migration and Stage 4 database restore, `af-release` preserves existing `(uid, gid)` metadata from the previous database/secret file or resolves the `aetherflow` service user via `getpwnam_r` (`lchown`) so files created while running as `root` (`af-runner`) remain readable by `User=aetherflow` (`aetherflow-api.service`).
3. **Parent Workspace Integration Steps**:
   - `crates/af-release` is registered in `backend-rs/Cargo.toml` with `rusqlite = { workspace = true, features = ["backup"] }`.
   - In `af-runner/src/lib.rs` (`handle_self_update`), call `af_release::validate_self_update_request(&req)` so the `"experimental"` channel is accepted alongside `"stable"` and `"nightly"`, and either invoke `af_release::execute_self_update_sync` inside `tokio::task::spawn_blocking` or retain `deploy/release-manager.sh` until rollout sign-off.


## Isolated Linux Validation

`cargo test -p af-release` passes all 15 tests, including release extraction collisions, ancestor symlink rejection, interrupted deployment recovery, checksum-verified database recovery, failed service-stop handling, private permissions, and managed-current-link validation. Atomic file operations preserve existing parent-directory permissions; migrating secret files enforces the requested `0600` mode rather than retaining permissive legacy mode bits. The intentional `current` symlink is resolved only to a direct, symlink-free child of the configured releases directory before reading packaged systemd units.

These tests use temporary filesystem layouts and mocked service lifecycles. They do not constitute a live systemd rollout test, and production self-update remains Bash-backed. Path-based checks still assume trusted parent directories; they are not a kernel-enforced replacement for dirfd-relative no-symlink operations.
