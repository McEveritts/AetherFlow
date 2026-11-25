# AetherFlow Rust Release Engine (`af-release`)

## Overview & Release Architecture

`af-release` (`backend-rs/crates/af-release`) is AetherFlow's default native Rust release engine for bare-metal `systemd` + `Apache2` deployments, superseding [`deploy/release-manager.sh`](../deploy/release-manager.sh) for routine pull-based deployments and rollbacks.

Key operational goals (atomic symlink swap, WAL-safe pre-swap SQLite snapshot, binary/asset verification, and automatic rollback on failed readiness):

1. **Default Production Engine (`NativeRustRelease`)**: `af-release` is wired into `af-runner` (`/v1/self-update`) and `af-cli` (`af release`) with trait-injected boundaries (`ArtifactProvider`, `LifecycleController`, `HealthProber`).
2. **Shell Escape Hatch Preserved**: `deploy/release-manager.sh` and `deploy/release-manager.conf` continue to be staged into every candidate release directory (`${RELEASE_DIR}/deploy/`). Operators can route `/v1/self-update` through `deploy/release-manager.sh` by setting `AETHERFLOW_FORCE_BASH_RELEASE=1` or `AETHERFLOW_RELEASE_ENGINE=bash` (valid values for `AETHERFLOW_RELEASE_ENGINE`: `rust` [default], `bash`) in `/etc/aetherflow/aetherflow.env` or a systemd drop-in for `aetherflow-runner.service`, followed by restarting `aetherflow-runner.service`.
3. **Systemd Service Lifecycle**: All service transitions operate directly on `aetherflow-runner.service` and `aetherflow-api.service` under `/opt/AetherFlow/current` (restarting both units during cutover; requests briefly pause during the API restart).

---

## Stage-by-Stage Parity with `deploy/release-manager.sh`

| Stage | `release-manager.sh` Function | `af-release` Module & API | Preserved Invariants |
| :--- | :--- | :--- | :--- |
| **Locking & Recovery** | `acquire_release_lock`, `check_package_lifecycle_reservations`, `guard_and_init_recovery_state`, `save_recovery_state`, per-snapshot `flock` (`SNAPSHOT_TIMEOUT`, default `30s`; unconfigured shell fallback `10s`) | `lock::ReleaseLockGuard`, `lock::RecoveryState`, `ensure_interoperable_maintenance_lock_file` | Acquires whole-operation exclusive locking (`${RELEASES_DIR}/.release.lock`), shared maintenance lock (`/run/aetherflow/.snapshot.lock`), and checks active SQLite `package_lifecycle_jobs` admission. Persists atomic crash-recovery journaling (`${RELEASES_DIR}/.recovery_state.json`) via exclusive (`create_new`) `0600` UUID-tagged temp files, `sync_all()`, and `rename`. Honors unfinished post-swap recovery states before any new mutation so `.previous_release` is never overwritten by an interrupted unhealthy deployment. |
| **Stage 0: FHS & DB Resolution** | `ensure_fhs_layout`, `resolve_db_path`, `read_env_file_value`, `read_systemd_environment_value` | `config::resolve_db_path`, `config::try_resolve_db_path`, `ReleaseEngine::ensure_fhs_layout`, `fs_security::apply_service_ownership` | Resolves the live SQLite path across 4 tiers (`AF_DB_PATH` / `DB_PATH` / `AETHERFLOW_DB_PATH` — see [Live SQLite Database Path Resolution](./upgrading.md#live-sqlite-database-path-resolution) and notes below). Enforces `0700` on `DATA_DIR` and `0600` before writing migrated SQLite DBs and `.env` files while preserving source `uid`/`gid` or falling back to `aetherflow:aetherflow`. |
| **Stage 1: Release Scaffold & Provenance** | `resolve_release_tag`, `pull_prebuilt_artifact` (runs sibling `${SCRIPT_DIR}/verify-provenance.py`, copied into `${RELEASE_DIR}/deploy/` by `stage_running_release_manager`), `simulate_offline_artifact`, `stage_running_release_manager` | `artifact::select_release_tag_from_json`, `artifact::verify_artifact_checksum`, `artifact::verify_release_provenance`, `artifact::extract_and_validate_release_archive`, `fs_security::create_new_dir_exclusive` | Supports `stable` and `nightly` channels with strict v4+ semver tag validation. Enforces SHA-256 verification and **Sigstore + SLSA v1 build provenance verification**: `af-release` embeds [`deploy/verify-provenance.py`](../deploy/verify-provenance.py) via `include_str!` and pipes it over `stdin` to `python3 -I -B -` (+ `openssl`), whereas standalone `deploy/release-manager.sh` requires the external sibling `${SCRIPT_DIR}/verify-provenance.py` file (optional local override `AETHERFLOW_PROVENANCE_BUNDLE_FILE`; break-glass bypass `AETHERFLOW_SKIP_PROVENANCE_VERIFY=1` for direct `--local` / shell runs). Stages downloads in unique `0700` dirs (`UUIDv4` + PID), verifies every ancestor/component against symlinks (`lstat`), extracts regular files exclusively into `0755` `release_dir`, verifies `./aetherflow-api`, `.version` stamp match, external `web/dist` frontend assets (`validate_external_frontend_assets` in Stage 1; `health::verify_deployed_frontend_assets` runs in Stage 3 and Stage 4 rollback), normalizes permissions (`prepare_release_permissions`), and stages `release-manager.sh` + `release-manager.conf` + `verify-provenance.py` + `log-retention.py`. |
| **Stage 1.5: State Snapshot** | `state_snapshot`, `sqlite_online_backup`, `sqlite_integrity` | `snapshot::create_state_snapshot`, `snapshot::sqlite_online_backup`, `snapshot::sqlite_integrity` | Creates `${RELEASE_DIR}/data-snapshot` (`0700`) and pre-creates exclusive `0600` temp DB files before running `rusqlite::backup::Backup` (`SQLITE_OPEN_READ_ONLY` on source so hot WALs are never checkpointed), `sync_all()`, and atomic `rename` to `.bak`. Verifies `PRAGMA integrity_check == "ok"` before swap and writes `MANIFEST.sha256` (`0600`). |
| **Stage 2: Atomic Symlink Swap** | `symlink_swap` | `symlink::perform_symlink_swap`, `symlink::atomic_replace_symlink`, `sync_cli_entrypoints` | Records the resolved current target atomically in `${RELEASES_DIR}/.previous_release` (`0600`, guarded against self-overwrite when `previous == current`), creates `${CURRENT_LINK}.tmp.<epoch>.<nanos>.<uuid>`, atomically renames it over `${CURRENT_LINK}`, and synchronizes `/usr/local/bin/af`. |
| **Stage 3: Systemd & Readiness** | `install_packaged_unit`, `restart_systemd_units`, `parse_health_status`, `health_probe` | `health::install_packaged_unit_if_missing`, `health::install_systemd_hardening_dropins`, `health::refresh_installed_transcode_shim`, `health::restart_transcode_worker_if_active_with_bin`, `health::run_post_restart_log_retention_with_bin`, `health::poll_readiness_probe`, `health::LifecycleController::verify_running_release`, `health::verify_deployed_frontend_assets`, `health::LifecycleController` | Enforces isolated-guest authorization gate when running under custom roots (`AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE=1` + `/etc/aetherflow-disposable-guest`). Installs packaged systemd units (`aetherflow-api`, `aetherflow-runner`, `aetherflow-log-retention.{service,timer}`) only if missing (preserving operator drop-ins), installs hardening drop-ins, prepares `/run/aetherflow` (`root:aetherflow`, `0750`), refreshes any existing `/usr/lib/aetherflow/transcode/ffmpeg` shim atomically (dormant if absent; refuses symlinks), runs `daemon-reload`, stops legacy `aetherflow-frontend.service` / PM2 processes if present, enables and restarts `aetherflow-runner.service` and `aetherflow-api.service` (required, plus `af-transcode-worker.service` only if active), and **then** runs `/var/log/aetherflow` ownership setup, `systemctl enable --now aetherflow-log-retention.timer`, and `systemctl start aetherflow-log-retention.service` best-effort (logging structured `WARN` entries to `deploy.log` on failure without aborting cutover). Polls `/health/ready` up to `HEALTH_RETRIES` (default `10` at `HEALTH_INTERVAL=3s`; unconfigured shell fallback `15` at `HEALTH_INTERVAL=2s`), and verifies running `/proc/<pid>/exe` paths (`verify_running_release`) plus deployed `web/dist` assets. |
| **Stage 4: Rollback & Restore** | `rollback`, `state_restore`, `stop_database_services` | `ReleaseEngine::execute` (`ReleaseCommand::Rollback`), `snapshot::restore_state_if_corrupted`, `snapshot::verify_snapshot_manifest` | Reverts `current` to `.previous_release` (restoring prior `.previous_release` on auto-rollback when available), then runs the same `restart_systemd_units` sequence (restarting `aetherflow-runner` and `aetherflow-api` first and executing log-retention housekeeping best-effort with structured `WARN` logging so a non-compliant log file under `/var/log/aetherflow` never blocks Stage 4 rollback) and readiness poll. If the live DB fails `PRAGMA integrity_check`: verifies `MANIFEST.sha256` and `.bak` integrity, stops database writers, copies `.bak` to an exclusive `0600` sibling temp file and re-verifies integrity, preserves `uid`/`gid` (or `aetherflow` user), quarantines `${db}.corrupted.<epoch>.<uuid>`, removes `-wal`/`-shm` sidecars, and atomically renames the verified temp DB into place. |
| **Stage 5: Housekeeping** | `cleanup_old_releases` | `symlink::cleanup_old_releases` | Retains `MAX_RELEASES` (default `3` in `af-release` and `deploy/release-manager.conf`; unconfigured shell fallback `5`) newest release directories sorted by epoch while unconditionally exempting both `current` and `.previous_release`. During `ReleaseCommand::Deploy`, `.recovery_state.json` is marked `Complete` before pruning (prune failures log `WARN`); standalone `ReleaseCommand::Cleanup` tracks `Stage5Cleanup -> Complete / Failed` in `.recovery_state.json`. |
| **Stage 6: Systemd Migration** | `migrate_systemd` | `ReleaseCommand::MigrateSystemd`, `health::wait_for_listener_stopped` | Invoked via `af release migrate-systemd` to transition legacy PM2 hosts onto systemd: tracks `Stage6MigrateSystemd -> Complete / Failed` in `.recovery_state.json`, verifies FHS layout, stops legacy PM2 daemons, runs a bounded TCP listener termination check on the health endpoint socket before starting `aetherflow-api.service`, and verifies `/health/ready`. |

**Stage 0 DB Resolution & File-Mode Details**:

- **Tier 1 (Process env / conf)**: Always fails closed on conflicting non-empty `AF_DB_PATH`, `DB_PATH`, or `AETHERFLOW_DB_PATH` values.
- **Tier 2 (`ENV_FILE` `/etc/aetherflow/aetherflow.env`)**: Parsed safely (never sourced as shell); fails closed on conflicts when `isolated_root.is_some()`, while production hosts pick the first non-empty key in `AF_DB_PATH` > `DB_PATH` > `AETHERFLOW_DB_PATH` order.
- **Tier 3 (`systemctl show -p Environment aetherflow-api`)**: Uses POSIX `shlex` tokenization with no cross-key conflict check (`af-release` inspects all three keys; `deploy/release-manager.sh` inspects `DB_PATH` and `AETHERFLOW_DB_PATH` only).
- **Tier 4 (Fallback)**: `${DATA_DIR}/${SQLITE_DB}` (`/var/lib/aetherflow/aetherflow.sqlite`). `systemd` PID 1 reads `EnvironmentFile=` as `root` (`AetherFlow-Setup` creates `aetherflow.env` as `0640 root:aetherflow`, while `af-release` legacy `.env` migration writes `0600`).

---

## Public API Surface (`af_release`)

### Core Configuration & Options (`af_release::config`)

- `ReleaseChannel`: `Stable`, `Nightly` (`FromStr`, `Display`, `Serialize`, `Deserialize`).
- `ReleaseCommand`: `Deploy`, `Rollback`, `Cleanup`, `MigrateSystemd`.
- `ReleaseOptions`: `parse_args(args, default_channel)` and `validate(&self)`.
- `ReleaseConfig`:
  - `ReleaseConfig::default()` — canonical FHS production layout (`/opt/AetherFlow/releases`, `/opt/AetherFlow/current`, `/var/lib/aetherflow`, `/etc/aetherflow/aetherflow.env`).
  - `ReleaseConfig::for_root(root)` — sandboxed root layout for tests.
  - `ReleaseConfig::load_with_env(conf_path, env_map)`, `load_from_process_env(conf_path)`, `load_for_root_with_env(root, conf_path, env_map)`, `load_for_root_from_process_env(root, conf_path)`, `with_dry_run(&self, dry_run)`.
- Database Path Resolution: `resolve_db_path`, `try_resolve_db_path`.

### Engine, Provenance, Filesystem Security & Traits (`af_release::{engine, fs_security, artifact, health}`)

- `ReleaseEngine<A: ArtifactProvider, L: LifecycleController, H: HealthProber>`: `new_production`, `new`, `execute`, `inspect_status`, `ensure_fhs_layout`.
- Artifact & Provenance: `GithubHttpArtifactProvider` (falls back to GitHub `/releases/latest` HTTP redirect headers on `stable` when REST API rate limits apply), `verify_release_provenance`, `prepare_release_permissions`.
- Lifecycle & Verification: `install_systemd_hardening_dropins`, `sync_cli_entrypoints`, `verify_deployed_frontend_assets`, `verify_isolated_systemd_lifecycle_authorized`.
- Hardened Filesystem Primitives (`af_release::fs_security`): `ensure_no_symlink_ancestors`, `ensure_no_symlink_in_relative_chain`, `create_dir_all_no_symlinks`, `create_new_dir_exclusive`, `open_exclusive_private_file`, `atomic_write_bytes_with_mode`, `atomic_copy_file_with_mode`, `OwnershipMetadata`, `apply_service_ownership`, `apply_data_dir_ownership_and_mode`, `apply_root_aetherflow_dir_ownership_and_mode`.

### Runner & CLI Integration (`af_release::admin`, re-exported at `af_release::*`)

- `validate_self_update_request(req: &af_models::SelfUpdateRequest) -> Result<ValidatedSelfUpdateRequest, af_models::RunnerResponse>`
  - Accepts `command` in `{"", "deploy", "rollback"}` and `channel` in `{"", "stable", "nightly"}` (retired `experimental` aliases to `nightly`).
- `execute_self_update_sync(req: &ValidatedSelfUpdateRequest, config: ReleaseConfig) -> (ExitCode, af_models::RunnerResponse)`
- `run_cli_from_args(args, conf_override) -> (ExitCode, ReleaseResult<ReleaseOutcome>)`
- Path & Lock Helpers: `ensure_interoperable_maintenance_lock_file`, `resolve_self_update_jobs_dir_for_config`, `resolve_self_update_jobs_dir_from_process_env`, `resolve_release_manager_conf_for_root`.

---

## Error & Exit-Code Contract (`af_release::error`)

| `ExitCode` | Numeric | `ReleaseError` Variants | Meaning |
| :--- | :---: | :--- | :--- |
| `ExitCode::Success` | `0` | — | Command completed (and passed readiness probe if live). |
| `ExitCode::PreSwapFailure` | `1` | `TagResolution`, `ArtifactVerification`, `ChecksumMismatch`, `ArchiveExtraction`, `Snapshot`, `IntegrityFailed`, `SymlinkSwap`, `Systemd`, `Io` | Pre-swap or lifecycle failure; candidate directory is cleaned up before symlink swap. |
| `ExitCode::HealthProbeFailedRollback` | `2` | `HealthProbeFailed`, `RolledBackAfterProbeFailure` | Stage 3 readiness probe failed after `HEALTH_RETRIES`; Stage 4 rollback to `.previous_release` succeeded. |
| `ExitCode::RollbackFailed` | `3` | `Rollback` | Stage 4 rollback failed, or an unfinished post-swap deployment in `.recovery_state.json` blocks new deploys until cleared with `sudo af release rollback --local [--channel <stable\|nightly>]`. |
| `ExitCode::ConfigurationOrUsageError` | `4` | `Config`, `PathValidation`, `Unsupported` | Invalid CLI flags, path/symlink traversal in config or release directories, `--offline` without `--dry-run`, or unsupported `--from-source`. |
| `ExitCode::LockContention` | `5` | `LockBusy` | Another release or host maintenance operation holds `.release.lock` or `.snapshot.lock`. |

When invoked through `af release --local`, `af-cli` remaps `af_release::ExitCode` into `CliExitCode` (and records `CliExitCode` in `<unit>.json` receipts): `ConfigurationOrUsageError (4) -> 2`, `PreSwapFailure (1)` / `HealthProbeFailedRollback (2)` / `LockContention (5) -> 4`, and `RollbackFailed (3) -> 7`.

### CLI Execution Modes (`--local`, `--dry-run`, `--offline`)

- **`--local`**: Executes `af_release::ReleaseEngine` directly in the invoking root process (used inside transient self-update units and standalone CLI recovery) rather than dispatching over `/run/aetherflow/runner.sock`. `ReleaseConfig::load_for_root_with_env` (and `deploy/release-manager.sh`) unify loading of `HEALTH_ENDPOINT`, GitHub auth tokens (`AF_GITHUB_TOKEN` / `GITHUB_TOKEN` / `GH_TOKEN`, held in redacted non-`Debug`/non-`Serialize` `RedactedSecret` memory), and root-only `AETHERFLOW_SKIP_PROVENANCE_VERIFY` from `/etc/aetherflow/aetherflow.env` (`0600`, skipped when `AETHERFLOW_SKIP_ENV_FILES=1`) with exact precedence: `process env > explicit --config assignment > aetherflow.env > default-fallback --config line > compiled default` (runner-socket `af release deploy` without `--local` continues to reject shell-exported `AETHERFLOW_RELEASE_CONF` with exit code `2`).
- **`--dry-run`**: Validates configuration, resolution, and archive/snapshot preflight without mutating `/opt/AetherFlow/current` or restarting live services.
- **`--offline`**: Must be paired with `--dry-run` (`af release deploy --local --offline --dry-run`); simulates archive staging without contacting GitHub.

---

## Completed Deployment Metadata Compatibility

- **Distinct Files**: `${RELEASES_DIR}/.recovery_state.json` tracks active release command, phase, candidate path, and timestamps (`started_at`, `updated_at`), while `.deployment.json` stores per-release deployment metadata inside a release slot.
- **Legacy Compatibility**: The recovery reader accepts legacy phase `completed` as `complete`. For completed non-dry-run `deploy` records only, a missing `started_at` is populated from a valid RFC 3339 `updated_at` as a compatibility value (not a recovered start time).
- **Fail-Closed Validation & Read-Only Status**: Missing required fields, invalid types, and unknown phases fail closed, and interrupted post-swap deployments require explicit rollback. Status inspection never rewrites the journal; the next native release operation writes the canonical `complete` schema.

> [!WARNING]
> Do not copy `.deployment.json` into `.recovery_state.json`.

---

## Runtime Integration & Permission Normalization

- **Workspace & Runner Wiring**: `crates/af-release` is registered in `backend-rs/Cargo.toml` and wired into [`af-runner/src/self_update.rs`](../backend-rs/crates/af-runner/src/self_update.rs) (`handle_self_update`), [`af-api/src/storage/updater.rs`](../backend-rs/crates/af-api/src/storage/updater.rs) (`run_update`), and `af-cli` (`af release`).
- **Transient Unit Dispatch**: `handle_self_update` validates incoming requests with `af_release::validate_self_update_request(&req)` and spawns a per-launch transient unit (`aetherflow-self-update-<command>-<channel>-<8hex>.service`) via `systemd-run --collect`. By default (`NativeRustRelease`), `resolve_af_cli_binary()` resolves explicit `AETHERFLOW_CLI_BIN`, then `env::current_exe().parent()` (`bin/af`, `af`) before falling back to mutable `/opt/AetherFlow/current/bin/af`, `/opt/AetherFlow/current/af`, and `/usr/local/bin/af`, launching `af [--root <root>] release <command> --channel <channel> --local --config <job_conf> --job-status-file <status_json> --job-unit <unit>` with private `0600` job configs and `0600` receipts. Setting `AETHERFLOW_FORCE_BASH_RELEASE=1` or `AETHERFLOW_RELEASE_ENGINE=bash` runs `deploy/release-manager.sh` in the same isolated transient unit.
- **Release Permission Normalization (`artifact::prepare_release_permissions`)**: Sets directories to `0755`, explicitly sets `0755` on `aetherflow-api`, `af`, `bin/af`, `speedtest-backend`, `bin/speedtest-backend`, `af-transcode`, `bin/af-transcode`, `deploy/release-manager.sh`, `deploy/verify-provenance.py`, `deploy/log-retention.py`, and `plugins/telemetry-inspector/backend/hooks/start.sh`, and normalizes all other regular files via `(mode | 0o444) & !0o022` (preserving archive execute bits on `packages/*` while removing group/other write bits).
- **OS User Ownership**: Enforces `0700` directory permissions on `DATA_DIR` and `data-snapshot/` and `0600` file permissions before writing on SQLite databases, snapshots, manifests, recovery journals, and migrated `.env` files, preserving existing `(uid, gid)` metadata or resolving `aetherflow` via `getpwnam_r` (`lchown`).

---

## Intentional Boundary: `--from-source` Fallback Mode

- `deploy/release-manager.sh --from-source` runs `git fetch`, `rsync`, enforces `rustc >= 1.95.0`, installs pinned WASM tools (`bash scripts/install_wasm_build_tools.sh --ensure`), stages `FRONTEND_DIST_DIR="${RELEASE_DIR}/web/dist"` via `bash scripts/build_wasm_frontend.sh --stage` (Rust/Trunk WASM; no Node.js required), and compiles `cargo build --release --locked --bin aetherflow-api --bin af --bin speedtest-backend --bin af-transcode` on the target host.
- `af-release` intentionally rejects `--from-source` with `ReleaseError::Unsupported` (`ExitCode::ConfigurationOrUsageError = 4`, checked via `is_unsupported_error`) to keep production hosts on pull-based, SHA-256 + Sigstore-verified prebuilt release archives without requiring Rust/Trunk build toolchains. Operators needing an emergency source build invoke `deploy/release-manager.sh --from-source` directly.

## Isolated Linux Validation

`cargo test --manifest-path backend-rs/Cargo.toml -p af-release --locked` covers release extraction collisions, ancestor symlink rejection, `prepare_release_permissions` normalization, `/releases/latest` redirect tag parsing, interrupted deployment recovery, checksum-verified database recovery, failed service-stop handling, private permissions, managed-current-link validation, and completed-manifest compatibility.
