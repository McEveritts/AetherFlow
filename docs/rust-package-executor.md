# Rust Declarative Package Executor (`af-runner::package_executor`)

This document describes the architecture, security model, wire protocol, failure/rollback semantics, public Rust interfaces, and recipe migration status for the AetherFlow Marketplace package execution engine. [`backend-rs/crates/af-runner/src/package_executor.rs`](../backend-rs/crates/af-runner/src/package_executor.rs) acts as a public re-export façade over 10 submodules (`apache_ingress`, `command_env`, `declarative_recipes/{catalog,lifecycle,rclone_helpers,readiness_and_fetch,steps_files_services,steps_system}`, `helpers`, `legacy_readiness`, `model`, `policy`, `rollback`, `stream_dispatch`, and `validation`).

---

## 1. Architecture & Hybrid Dispatch Model

All privileged Marketplace lifecycle operations (`install`, `update`, `reinstall`, `remove`) flow through `af-runner` via:

- **`POST /v1/package`** over `/run/aetherflow/runner.sock` (`handle_package` in [`backend-rs/crates/af-runner/src/systemctl_handlers.rs`](../backend-rs/crates/af-runner/src/systemctl_handlers.rs), which dispatches via `package_lifecycle::execute_coordinated_package_stream`; target-policy validation `validate_package_target_policy` runs inside `execute_package_request_stream` in `stream_dispatch.rs`, emitting `__RUNNER_EXIT_ERROR__:<reason>` on the HTTP `200` stream on rejection), or
- **`af_runner::execute_package_local`** / **`af_runner::execute_package_request_stream`** for internal runner execution and test harnesses (all `af package` CLI mutations route exclusively over `/run/aetherflow/runner.sock` via `POST /v1/package`).

The 77-app Marketplace uses two package execution paths in `af-runner`:

1. **`PackageEngineMode::DeclarativeRust` (Opt-In via `AETHERFLOW_ENABLE_RUST_PACKAGES=1`)**:
   - Disabled by default (`AETHERFLOW_ENABLE_RUST_PACKAGES` defaults to `false`). To enable it on a host, set `AETHERFLOW_ENABLE_RUST_PACKAGES=1` in `/etc/aetherflow/aetherflow.env` (or a systemd drop-in for `aetherflow-runner.service`) and restart `aetherflow-runner.service`.
   - Selected only when `AETHERFLOW_ENABLE_RUST_PACKAGES=1` (or `true`) is set, `AETHERFLOW_FORCE_BASH_PACKAGES` is not set, and `get_declarative_recipe(pkg_id)` returns `Some(DeclarativePackageRecipe)`.
   - Executes a typed sequence of `DeclarativeStep` variants inside `DeclarativePackageExecutor` with pre-flight validation, cancellation-aware advisory locking, ancestor `lstat` verification, SHA-256 / magic-header artifact verification, pre-start systemd drop-in sandboxing (for non-privileged units), and transactional rollback journaling.
2. **`PackageEngineMode::LegacyBashFallback` (Default)**:
   - Selected by default when `AETHERFLOW_ENABLE_RUST_PACKAGES` is unset/disabled, when `AETHERFLOW_FORCE_BASH_PACKAGES=1` is set as an operational override, or when `get_declarative_recipe(pkg_id)` returns `None`.
   - Resolves `packages/package/{install,remove}/<script_name>` (plus an optional `update/` lookup path checked by `resolve_package_script_path`; shipped catalog scripts live under `install/` and `remove/`), registers per-package cancellation before waiting on locks, acquires the **same** process-wide `PACKAGE_MUTEX`, shared maintenance lock, and persistent cross-process `.af-package-executor.flock` lock as the Rust engine, runs `bash` in an isolated process group (`process_group(0)`), ignores ambient `DELETE_DATA` environment variables in favor of the request's explicit `delete_data` boolean, and streams `stdout`/`stderr` line-by-line.

The `/v1/package` response includes the HTTP header `X-AetherFlow-Package-Engine: declarative_rust | legacy_bash_fallback` for observability.

---

## 2. Security Boundaries

Declarative recipes enforce strict validation before and during execution:

- **Direct `execve` Dispatch (Zero Shell Primitives)**:
  - All 23 typed `DeclarativeStep` variants (`AptInstall`, `Systemctl`, `EnsureSystemUser`, `PurgeSystemUser`, `UnmountPaths`, etc.) invoke OS binaries directly via `tokio::process::Command::new(program).args(...)` with `stdin(Stdio::null())`, `process_group(0)` on Unix, and `kill_on_drop(true)`.
  - `DeclarativeStep::RunCommand` has been removed completely; both `mergerfs` and `rclone` unmount active FUSE paths through the shell-free fail-closed `DeclarativeStep::UnmountPaths { paths, only_if_delete_data }` primitive (`is_active_mountpoint` → `fusermount -u` → non-lazy `umount` → re-check).
- **Strict Identifier Allowlists**:
  - Package IDs: `SAFE_PKG_ID` (`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
  - Systemd units: `SAFE_SERVICE_NAME` (`^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,63}$`), invoked with `--` before unit arguments (`systemctl <op> -- <unit>`)
  - System users: `SAFE_USERNAME` (`^[a-z_][a-z0-9_-]{0,31}$`), explicitly forbidding `root` and `www-data` in `EnsureSystemUser` / `PurgeSystemUser`
  - APT package names: `SAFE_APT_PKG_NAME` (`^[a-z0-9][a-z0-9+.-]{0,127}$`, Debian Policy §5.6.1)
  - GitHub repositories: `SAFE_GITHUB_REPO` (`^[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.-]{1,100}$`)
- **Filesystem Prefix Sandboxing & Shared-Root Protection (`validate_managed_path`, `validate_chown_target_path`)**:
  - All declarative file/directory reads, writes, backups, and removals must be absolute Unix paths within `ALLOWED_MANAGED_PREFIXES`:
    `/etc/`, `/var/lib/`, `/var/log/`, `/var/run/`, `/run/`, `/opt/`, `/usr/local/bin/`, `/install/`, `/mnt/`.
  - Any path containing `..` (`Component::ParentDir`), NUL/newline control characters, or matching `FORBIDDEN_EXACT_PATHS` (`/`, `/bin`, `/sbin`, `/etc`, `/etc/apt`, `/etc/default`, `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`, `/etc/fstab`, `/etc/ssh`, `/etc/ssh/sshd_config`, `/etc/systemd`, `/etc/systemd/system`, `/var`, `/var/lib`, `/var/cache`, `/var/log`, `/var/run`, `/run`, `/opt`, `/opt/AetherFlow`, `/usr`, `/usr/bin`, `/usr/sbin`, `/usr/local`, `/usr/local/bin`, `/install`, `/mnt`) is rejected with `PackageExecutorError::SecurityViolation`.
  - Recursive ownership mutations (`EnsureDirectories` with `owner`/`group` or `EnsureSystemUser` home directory) are additionally checked against `SHARED_SYSTEM_CHOWN_PATHS`, forbidding `chown -R` on shared system directories.
- **Ancestor Symlink Inspection & `lstat` Error Propagation (`validate_filesystem_path`)**:
  - Every filesystem target (managed paths, readonly config probes, temp download paths, artifact cache files, `file://` staging sources, tar extraction destinations, and rollback journal targets) is verified component-by-component using `fs::symlink_metadata` (`lstat`).
  - Any existing ancestor or leaf component that is a symlink is rejected with `PackageExecutorError::SecurityViolation`. Non-`NotFound` `lstat` errors (`EACCES`, `ENOTDIR`, `ELOOP`) propagate immediately as `PackageExecutorError::Io`.
- **Archive Traversal & Link Entry Protection**:
  - `extract_binaries_from_targz` inspects every tar entry before reading and aborts with `SecurityViolation` if any entry contains `..`, is a symlink or hardlink, or if a requested target member is not a regular file.

---

## 3. Dependency Locking, Progress, Cancellation & Rollback

### 3.1 Dependency & State Locking

Each package operation (both `DeclarativeRust` and `LegacyBashFallback`) coordinates four guards in order:

1. **Per-Package In-Flight Guard (`register_package_cancellation`)**: Registered **before** waiting on global mutexes or file locks so queued operations can be cancelled immediately and duplicate concurrent operations on the same `package_id` are rejected with `PackageExecutorError::LockConflict`.
2. **Process-Wide Async Mutex (`acquire_package_mutex_with_cancel`)**: Serializes package mutations within `af-runner` while honoring `CancellationToken` while queued.
3. **Cross-Process Advisory File Lock (`CrossProcessLockGuard::acquire_with_cancel`)**:
   - Opens `<lock_dir>/.af-package-executor.flock` (default lock directory `/install`, overridden under isolated test roots) **without** `O_TRUNC`.
   - Acquires `flock(LOCK_EX | LOCK_NB)` with cancellation-aware polling, writing holder metadata only after holding the lock. `Drop` releases the descriptor (`LOCK_UN`) and never unlinks the inode.
4. **Shared Maintenance Lock & SQLite Job Reservation (`acquire_package_maintenance_guard`)**: Coordinates exclusive admission against self-updates (`af-release`) and host maintenance (`af-host`), persisting active lifecycle state in SQLite `package_lifecycle_jobs`.

**Post-Execution Completion Marker & Ingress Sync**:

- `/install/.<pkg>.lock` is written atomically only after all steps and pre-start sandboxing succeed on `install`/`update`/`reinstall`, and removed on successful `remove`. On `remove` with `delete_data == false`, a retained-data marker (`/install/.<pkg>.retained`) is written.
- On live hosts (non-isolated root), writing the completion lock invokes `sync_certbot_and_managed_ingress()` in the background (calling `/usr/local/bin/af-certbot-sync` or `/usr/bin/af-certbot-sync` with **no arguments**, then reconciling active external TLS Apache vhosts from SQLite `app_ingress_configs`) and awaits `apply_runner_blueprint_in_background` synchronously (emitting `__RUNNER_EXIT_ERROR__` on failure, and skipped/deferred whenever `AETHERFLOW_DEFER_BLUEPRINT_SYNC=1`, `expected_target_version.is_some()`, or `!lifecycle_job_id.is_empty()`).

### 3.2 Live Structured Progress & Wire Compatibility

- `PackageProgressEvent` carries `package_id`, `action`, `engine`, `phase` (`Preflight`, `LockAcquire`, `ExecuteStep`, `VerifyArtifact`, `SandboxApply`, `FinalizeLock`, `Rollback`, `Complete`, `Failed`, `Cancelled`), `step_index`, `total_steps`, `progress_pct` (`0..=100`), `message`, and RFC 3339 `timestamp`.
- `execute_declarative_recipe_stream` and `execute_package_request_stream` stream incremental lines over an async channel (`[PROGRESS:<pct>] <message>`, script log lines, and `__RUNNER_EXIT_ERROR__:<reason>`).
- The outer coordinated wrapper `package_lifecycle::execute_coordinated_package_stream` emits durable `__RUNNER_JOB__:<json>` (`JOB_MARKER`) and `__RUNNER_LIFECYCLE__:<json>` (`RECEIPT_MARKER`) frames **only when `request.lifecycle_job_id` is empty** (`HostBackend::script` neutralizes any inner marker lines with a `[LOG] ` prefix so scripts cannot forge receipts).
- `af-cli`'s `PackageStreamAccumulator::finish_verified()` enforces matching `JOB_MARKER` and `RECEIPT_MARKER` frames on the wire (failing closed on missing/failed receipts or `__RUNNER_EXIT_ERROR__:`). By contrast, `af-api` (`backend-rs/crates/af-api/src/routes/marketplace/job_runner.rs`) pre-admits a non-empty `lifecycle_job_id`, checks `__RUNNER_EXIT_ERROR__:` via `IncrementalPackageLineDecoder`, and manages durable job receipts, target certification, and rollback directly in `job_runner.rs`.

### 3.3 Cooperative Process-Group Cancellation & Bounded Output

- Callers can cancel an in-flight or queued operation via `af_runner::cancel_package_execution(pkg_id)`, `af_runner::dispatch_package_cancel(pkg_id)`, or `POST /v1/package/cancel` (`{"package_id": "<pkg>"}`).
- `CancellationToken` is checked while queued on locks, before every step, across chunked HTTP downloads, and during subprocess execution.
- Both `TokioCommandRunner` and `LegacyBashFallback` spawn child processes in a dedicated Unix process group (`cmd.process_group(0)`). On cancellation, `terminate_child_process_group` sends `SIGTERM`, waits up to `AETHERFLOW_ROLLBACK_GRACE_MS` (default `2500ms`), then sends `SIGKILL` to `-pgid` and reaps children and pipe readers.
- Command output retention in `TokioCommandRunner` is capped at `MAX_COMMAND_OUTPUT_BYTES` (64 KiB per stream) while draining remaining pipe output to EOF.

### 3.4 Pre-Start Systemd Sandboxing & Transactional Rollback (`RollbackJournal`)

- When `recipe.apply_systemd_sandbox` is enabled on `Install`, `Reinstall`, or `Update`, pre-start sandboxing runs before `AptInstall` and before the first `Systemctl` activation step (and refreshes after `WriteSystemdUnit`). `apply_sandbox_in_root_with_journal` (`package_executor/helpers.rs`) intentionally writes both `aetherflow-sandbox.conf` and `10-aetherflow-sandbox.conf` under `/etc/systemd/system/<unit>.d/` (where `<unit>` already includes `.service`, ensuring drop-in precedence while maintaining backwards compatibility with legacy filenames — distinct from standalone `af sandbox apply` / `sandbox_ops.rs::apply_package_sandbox_local`, which writes `10-aetherflow-sandbox.conf` and removes legacy `aetherflow-sandbox.conf`) for non-privileged units, while skipping `privileged`/`none`/exempt units (`fail2ban.service`, `netdata.service`, `x2goserver*`, `mergerfs*`, `rclone-vfs*`, plus `xrdp` via `"sandbox_profile": "privileged"`) and removing any pre-existing drop-ins.
- Before modifying files or mutable directories, `RollbackJournal` stages file backups (`<target>.bak-af.<uuid>`) and directory snapshots (`stage_directory_snapshots_with_cancel`).
- On step failure or cancellation, `RollbackJournal::rollback` runs in reverse order: quiesces touched services, stops/disables/removes newly created unit files, restores file backups and directory snapshots, rolls back APT installs/upgrades where recorded, restores deferred `.af-version` state, and removes newly created files and temporary downloads.

---

## 4. Exported Public Interfaces (`af_runner`)

The following public types and functions are exported from `af_runner` (and `af_runner::package_executor`) for `af-services`, `af-cli`, and test suites:

| Symbol | Kind | Purpose |
| :--- | :--- | :--- |
| `PackageAction` (`PackageOperation` alias) | `enum` | `Install`, `Update`, `Reinstall`, `Remove` (`parse`, `as_str`) |
| `PackageEngineMode` | `enum` | `DeclarativeRust`, `LegacyBashFallback` |
| `ExecutionPhase` | `enum` | `Preflight`, `LockAcquire`, `ExecuteStep`, `VerifyArtifact`, `SandboxApply`, `FinalizeLock`, `Rollback`, `Complete`, `Failed`, `Cancelled` |
| `PackageProgressEvent` | `struct` | Structured progress event with `to_wire_line()` |
| `PackageExecutionOutcome` | `struct` | Final execution summary (steps, lock path, resolved version, sandbox status, logs) |
| `ArtifactVerificationPolicy` | `struct` | Size bounds, SHA-256 digest, gzip/ELF magic header requirements |
| `ArchAssetMap` | `struct` | Per-architecture (`amd64`, `arm64`, `armhf`) asset filename mapping |
| `DeclarativeStep` | `enum` | 23 typed shell-free lifecycle primitives (`AptUpdate`, `AptInstall`, `AptRemove` [serde alias `apt_purge`], `EnsureSystemUser`, `PurgeSystemUser`, `EnsureDirectories`, `ProbeSshPort`, `ResolveGitHubReleaseTag`, `DownloadAndExtractTarGz`, `DownloadBinary`, `WriteTemplateFile`, `WriteSystemdUnit`, `Systemctl`, `PurgeSystemdUnit`, `RemovePaths`, `GenerateSelfSignedTlsCert`, `CaptureDpkgVersion`, `EnsureThreadfinConfig`, `InstallRcloneBinary`, `RemoveRcloneFiles`, `MergeIniSettings`, `UnmountPaths`, `WaitForHttpReady`) |
| `SystemctlOp` | `enum` | `DaemonReload`, `EnableNow`, `Enable`, `Start`, `Restart`, `TryRestart`, `Stop`, `Disable`, `ResetFailed` |
| `DeclarativePackageRecipe` | `struct` | Validated package lifecycle recipe (`validate()`, `steps_for_action()`) |
| `PackageExecutorError` | `enum` | Typed error hierarchy (`Validation`, `SecurityViolation`, `LockConflict`, `Cancelled`, `ArtifactVerification`, `VerificationFailed`, `StepFailed`, `ExecutionError`, `Io`) |
| `CancellationToken` | `struct` | Cooperative cancellation handle (`new`, `cancel`, `is_cancelled`, `check`) |
| `CommandRunner` / `TokioCommandRunner` | `trait` / `struct` | Pluggable command execution backend for production vs isolated test mocking |
| `PackageExecutionEnv` | `struct` | Execution environment (`default()`, `isolated(root)`, `resolve_path`, `resolve_lock_file`) |
| `DeclarativePackageExecutor` | `struct` | Core recipe executor (`new`, `with_runner`, `execute_recipe`) |
| `get_declarative_recipe` / `list_declarative_recipe_ids` | `fn` | Looks up or lists all 9 built-in declarative recipes |
| `is_rust_package_engine_enabled` / `select_package_engine*` | `fn` | Evaluates feature flags to select `DeclarativeRust` or `LegacyBashFallback` |
| `can_resolve_package_operation` / `validate_package_target_policy` / `validate_threadfin_target_policy` / `package_requires_download_sha256` | `fn` | Validates catalog availability, target-version policy, and SHA-256 requirements |
| `execute_declarative_recipe_stream` / `execute_package_request_stream` / `execute_package_local` | `fn` | Executes declarative or hybrid package actions with incremental progress streaming |
| `cancel_package_execution` / `dispatch_package_cancel` | `fn` | Signals cooperative cancellation for an active package operation |
| `verify_artifact_file` / `validate_managed_path` / `validate_chown_target_path` / `resolve_effective_runner_app_port` / `ensure_package_sandbox_dropin_under_root` / `script_matches_package_identity` / `detect_rclone_*` / `parse_progress_line` | `fn` | Artifact verification, path/sandbox guards, port resolution, rclone inspection, and progress parsing |

---

## 5. Recipe Migration Status vs Legacy Bash Fallback

Nine Marketplace applications are registered in `BUILTIN_DECLARATIVE_RECIPES` (`backend-rs/crates/af-runner/src/package_executor/declarative_recipes.rs`), restricted to catalog packages with verified install, update, and remove lifecycle steps:

### 5.1 Migrated to Native Declarative Rust (`PackageEngineMode::DeclarativeRust` when `AETHERFLOW_ENABLE_RUST_PACKAGES=1`)

| Package ID | Archetype | Key Operations |
| :--- | :--- | :--- |
| `fail2ban` | APT + SSH Port Detection + Systemd | Installs `fail2ban`, `python3-systemd`, `iptables`; probes `/etc/ssh/sshd_config` for custom `Port`; writes `/etc/fail2ban/jail.local`; runs `fail2ban.service` (`sandbox_profile: "privileged"`, exempt from sandbox drop-ins). |
| `quassel` | APT + Self-Signed TLS + Dpkg Version + Systemd | Installs `quassel-core`, ensures `quasselcore` user and `/var/lib/quassel`, generates 4096-bit self-signed TLS cert (`GenerateSelfSignedTlsCert`), writes `/etc/systemd/system/quasselcore.service`, captures installed dpkg version (`CaptureDpkgVersion`), and manages `quasselcore.service`. |
| `threadfin` | Pinned GitHub Binary + Systemd | Downloads pinned `Threadfin/Threadfin` release `1.2.37` with per-architecture SHA-256 and ELF verification into `/usr/local/bin/threadfin`, creates `threadfin` system user and `/var/lib/threadfin` (`0755`, keeping `conf/` at `0750`), writes `EnsureThreadfinConfig` (`-bind={{BIND_ADDRESS}}`), manages `threadfin.service`, and verifies HTTP readiness via `WaitForHttpReady { path: "/status" }`. |
| `znc` | APT + Loopback Config + Dpkg Version + Systemd | Installs `znc`, creates `znc` user and `/var/lib/znc/configs`, writes `znc.conf` (`SSL = false`), captures dpkg version, manages `znc.service`, and checks HTTP readiness (`WaitForHttpReady`). |
| `xrdp` | APT + Desktop Session + Systemd | Installs `xrdp`, `xorgxrdp`, `xfce4`, `xfce4-goodies`, `dbus-x11`, configures `/etc/xrdp/startwm.sh`, captures dpkg version, and manages both `xrdp.service` and `xrdp-sesman.service` (`privileged`). |
| `x2go` | APT + SSH Remote Desktop | Installs `x2goserver`, `x2goserver-xsession`, `xfce4`, `dbus-x11`, captures dpkg version, and manages `x2goserver.service` (`privileged`). |
| `netdata` | APT + Local Telemetry Daemon | Installs `netdata`, configures `/etc/netdata/netdata.conf` via `MergeIniSettings` (`{{BIND_ADDRESS}}`, `{{APP_PORT}}`), captures dpkg version, manages `netdata.service` (`privileged`), and verifies `/api/v1/info` (`WaitForHttpReady`). |
| `mergerfs` | APT Union Filesystem | Installs `mergerfs` and `fuse3`, records installed dpkg version in `/var/lib/mergerfs/.af-version`, manages `mergerfs.service` (`privileged`), and unmounts `/mnt/unionfs` & `/mnt/mergerfs` safely on removal/purge without deleting branch data. |
| `rclone` | Upstream Binary + Rclone Web RCD / VFS | Installs `fuse3` and the upstream executable at `/opt/AetherFlow/apps/rclone/rclone`; manages `rclone.service` (`127.0.0.1:5572`) and `rclone-vfs.service` using `/etc/rclone/rclone.env` (migrating `/etc/aetherflow/rclone.env` if present); unmounts `/mnt/remote` via shell-free fail-closed `DeclarativeStep::UnmountPaths { only_if_delete_data: true }` on data purge. |

### 5.2 Remaining Marketplace Packages (`PackageEngineMode::LegacyBashFallback`)

- The remaining 68 catalog packages run their native Bash installers (`packages/package/install/installpackage-*`, sourcing `packages/common.sh` / `packages/lib/*.sh`) under the shared advisory lock and process-group cancellation supervisor. Packages with multi-unit or complex stateful workflows—such as Scrutiny, Prometheus (GitHub releases + loopback-bound `node_exporter`), Syncthing (XML GUI seeding + `insecureSkipHostcheck`), and noVNC (3 units + VNC password + collision-guarded display port)—intentionally remain on their hardened Bash installers.

---

## 6. Validation and Safety Boundary

Run the `af-runner` package executor verification suite covering all 9 built-in declarative recipes, `GenerateSelfSignedTlsCert`, `CaptureDpkgVersion`, persistent advisory lock preservation, queued and process-group cancellation, bounded command output, live progress streaming, ancestor-symlink rejection, and atomic rollback backups:

```bash
cargo test --manifest-path backend-rs/Cargo.toml -p af-runner --locked
```

Every APT-backed recipe captures the installed Debian version, uses `unknown` until a version is resolved, and preserves configuration and system accounts on removal unless `delete_data` (`DELETE_DATA=true`) is explicitly requested. For additional recipe details, developer authoring rules, and lifecycle repair history, see [Native Declarative Packages](./v4-native-packages.md), [Marketplace Developer Guide](./marketplace-developer-guide.md), and [Marketplace Lifecycle Repair](./marketplace-repair.md).
