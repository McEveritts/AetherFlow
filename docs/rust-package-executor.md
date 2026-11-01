# Rust Declarative Package Executor (`af-runner::package_executor`)

This document describes the architecture, security model, wire protocol, failure/rollback semantics, public Rust interfaces, and recipe migration status for the AetherFlow Marketplace package execution engine in [`backend-rs/crates/af-runner/src/package_executor.rs`](../backend-rs/crates/af-runner/src/package_executor.rs).

---

## 1. Architecture & Hybrid Dispatch Model

All privileged Marketplace lifecycle operations (`install`, `update`, `remove`) flow through `af-runner` via:
- **`POST /v1/package`** over `/run/aetherflow/runner.sock` (`handle_package` in `af-runner/src/lib.rs`), or
- **`af_runner::execute_package_local`** / **`af_runner::execute_package_request_stream`** for direct in-process execution by future CLI and bare-metal provisioner binaries.

To guarantee zero regressions across the 70+ Marketplace applications while eliminating unsafe shell evaluation in migrated recipes, `af-runner` implements a **two-tier hybrid dispatch model** controlled by explicit feature gates:

1. **`PackageEngineMode::DeclarativeRust` (Opt-In via `AETHERFLOW_ENABLE_RUST_PACKAGES=1`)**:
   - Disabled by default (`AETHERFLOW_ENABLE_RUST_PACKAGES` defaults to `false`).
   - Selected only when `AETHERFLOW_ENABLE_RUST_PACKAGES=1` (or `true`) is set, `AETHERFLOW_FORCE_BASH_PACKAGES` is not set, and `get_declarative_recipe(pkg_id)` returns `Some(DeclarativePackageRecipe)`.
   - Executes a strongly-typed sequence of [`DeclarativeStep`] variants inside [`DeclarativePackageExecutor`] with pre-flight validation, cancellation-aware advisory locking, ancestor `lstat` verification, SHA-256 / magic-header artifact verification, pre-start systemd drop-in sandboxing, and transactional rollback journaling.
2. **`PackageEngineMode::LegacyBashFallback` (Default)**:
   - Selected by default when `AETHERFLOW_ENABLE_RUST_PACKAGES` is unset/disabled, when `AETHERFLOW_FORCE_BASH_PACKAGES=1` is set as an operational override, or when `get_declarative_recipe(pkg_id)` returns `None`.
   - Resolves `packages/package/{install,remove,update}/<script_name>` via `resolve_package_script_path`, registers per-package cancellation before waiting on locks, acquires the **same** process-wide `PACKAGE_MUTEX` and persistent cross-process `.af-package-executor.flock` lock as the Rust engine, runs `bash` in an isolated process group (`process_group(0)`), and streams `stdout`/`stderr` line-by-line.

The `/v1/package` response includes the HTTP header `X-AetherFlow-Package-Engine: declarative_rust | legacy_bash_fallback` for observability.

---

## 2. Security Boundaries

Declarative recipes enforce conservative security boundaries prior to and during execution:

- **Zero Arbitrary Shell Evaluation**:
  - `DeclarativeStep` contains **no** `bash -c` or `sh -c` step variant. Every external OS command (`apt-get`, `systemctl`, `id`, `useradd`, `userdel`, `groupdel`, `chown`) is invoked via direct `execve` argument vectors (`tokio::process::Command::new(program).args(...)`) with `stdin(Stdio::null())`, `process_group(0)` on Unix, and `kill_on_drop(true)`.
- **Strict Identifier Allowlists**:
  - Package IDs: `SAFE_PKG_ID` (`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
  - Systemd units: `SAFE_SERVICE_NAME` (`^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,63}$`), invoked with `--` before unit arguments (`systemctl <op> -- <unit>`)
  - System users: `SAFE_USERNAME` (`^[a-z_][a-z0-9_-]{0,31}$`), explicitly forbidding `root` and `www-data` in `EnsureSystemUser` / `PurgeSystemUser`
  - APT package names: `SAFE_APT_PKG_NAME` (`^[a-z0-9][a-z0-9+.-]{0,127}$`, Debian Policy §5.6.1)
  - GitHub repositories: `SAFE_GITHUB_REPO` (`^[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.-]{1,100}$`)
- **Filesystem Prefix Sandboxing & Shared-Root Protection (`validate_managed_path`, `validate_chown_target_path`)**:
  - All declarative file/directory reads, writes, backups, and removals must be absolute Unix paths within `ALLOWED_MANAGED_PREFIXES`:
    `/etc/`, `/var/lib/`, `/var/log/`, `/var/run/`, `/run/`, `/opt/`, `/usr/local/bin/`, `/install/`.
  - Any path containing `..` (`Component::ParentDir`), NUL/newline control characters, or matching `FORBIDDEN_EXACT_PATHS` (`/`, `/bin`, `/sbin`, `/etc`, `/etc/apt`, `/etc/default`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`, `/etc/fstab`, `/etc/ssh/sshd_config`, `/etc/systemd/system`, `/var/lib`, `/var/cache`, `/opt/AetherFlow`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/install`) is rejected with `PackageExecutorError::SecurityViolation`.
  - Recursive ownership mutations (`EnsureDirectories` with `owner`/`group` or `EnsureSystemUser` home directory) are additionally checked against `SHARED_SYSTEM_CHOWN_PATHS`, strictly forbidding `chown -R` on shared system directories such as `/usr/local/bin`, `/etc/default`, `/etc`, `/var/lib`, `/var/log`, `/var/run`, `/run`, `/opt`, or `/install`.
- **Ancestor Symlink Inspection & `lstat` Error Propagation (`validate_filesystem_path`)**:
  - Every filesystem target (resolved managed paths, readonly config probes, temp download paths, artifact cache files, `file://` staging sources, tar extraction destinations, and rollback journal targets) is verified component-by-component using `fs::symlink_metadata` (`lstat`).
  - Any existing ancestor or leaf component that is a symlink is rejected with `PackageExecutorError::SecurityViolation`.
  - Any non-`NotFound` `lstat` error (such as `EACCES`/`PermissionDenied`, `ENOTDIR`, or `ELOOP`) is propagated immediately as `PackageExecutorError::Io` rather than being ignored.
- **Archive Traversal & Link Entry Protection**:
  - `extract_binaries_from_targz` inspects every tar entry before reading and aborts with `SecurityViolation` if any entry contains `..`, is a symlink or hardlink, or if a requested target member is not a regular file.

---

## 3. Dependency Locking, Progress, Cancellation & Rollback

### 3.1 Dependency & State Locking
Each package operation (both `DeclarativeRust` and `LegacyBashFallback`) acquires three coordinated locks in order:
1. **Per-Package In-Flight Guard (`register_package_cancellation`)**: Registered **before** waiting on global mutexes or file locks so queued operations can be cancelled immediately and duplicate concurrent operations on the same `package_id` are rejected immediately with `PackageExecutorError::LockConflict`.
2. **Process-Wide Async Mutex (`acquire_package_mutex_with_cancel`)**: Serializes package mutations within `af-runner` while remaining responsive to `CancellationToken` while queued.
3. **Cross-Process Advisory File Lock (`CrossProcessLockGuard::acquire_with_cancel`)**:
   - Opens `${LOCK_DIR}/.af-package-executor.flock` **without** `O_TRUNC` (`truncate(true)` is never used prior to lock acquisition).
   - Acquires `flock(LOCK_EX | LOCK_NB)` with cancellation-aware polling (`acquire_with_cancel`), and truncates/writes holder diagnostic metadata **only after** the advisory lock is held.
   - `Drop` releases the descriptor (`LOCK_UN`) and **never unlinks** the persistent `.af-package-executor.flock` inode on disk, preventing split-brain lock races across concurrent openers.
4. **Completion Marker (`/install/.<pkg>.lock`) & Certbot Sync**:
   - Written atomically **only** after all steps and pre-start systemd sandboxing succeed on `install`/`update`, and removed on `remove`. Failed or cancelled runs never leave a false-positive `/install/.<pkg>.lock`.
   - On live hosts (`fs_root.is_none()`), writing the completion lock triggers `/usr/local/bin/af-certbot-sync <pkg_id>` asynchronously in the background when present, preserving parity with `packages/common.sh::write_lock`.

### 3.2 Live Structured Progress & Wire Compatibility
- [`PackageProgressEvent`] carries `package_id`, `action`, `engine`, `phase` (`Validate`, `LockAcquire`, `ExecuteStep`, `SandboxApply`, `FinalizeLock`, `Rollback`, `Complete`, `Failed`, `Cancelled`), `step_index`, `total_steps`, `progress_pct` (`0..=100`), `message`, and RFC3339 `timestamp`.
- `execute_declarative_recipe_stream` and `execute_package_request_stream` stream `[PROGRESS:<pct>] <message>` wire lines incrementally over an async channel as each phase/step begins, without buffering the entire run into a `Vec` before yielding.
- `dispatch_package_action` and `af-api` (`routes.rs`) consume the chunked HTTP response from `af-runner` line-by-line with bounded line lengths, parsing `[PROGRESS:<pct>]` updates live for WebSocket/UI consumers while preserving JSON and `__RUNNER_EXIT_ERROR__:` markers.

### 3.3 Cooperative Process-Group Cancellation & Bounded Output
- Callers can cancel an in-flight or queued operation via:
  - `af_runner::cancel_package_execution(pkg_id)` (in-process),
  - `af_runner::dispatch_package_cancel(pkg_id)` (client helper), or
  - `POST /v1/package/cancel` (`{"package_id": "<pkg>"}`).
- `CancellationToken` is honored while queued for `PACKAGE_MUTEX` or `.af-package-executor.flock`, before every step, across chunked HTTP downloads (`resp.chunk()`), and during subprocess execution.
- Both `TokioCommandRunner` and the `LegacyBashFallback` runner spawn child processes in a dedicated Unix process group (`cmd.process_group(0)`). On cancellation, `terminate_child_process_group` sends `SIGTERM` followed by `SIGKILL` to `-pgid` and reaps the child and pipe readers so background grandchildren holding `stdout`/`stderr` open cannot hang cancellation.
- Command output retention in `TokioCommandRunner` is capped at `MAX_COMMAND_OUTPUT_BYTES` (64 KiB per stream) while draining remaining pipe output to EOF.

### 3.4 Pre-Start Systemd Sandboxing & Transactional Rollback (`RollbackJournal`)
- When `recipe.apply_systemd_sandbox` is enabled on `Install` or `Update`, the systemd sandbox drop-in (`aetherflow-sandbox.conf` and `10-aetherflow-sandbox.conf`) is applied **before** the first `Systemctl` activation step (`DaemonReload`, `EnableNow`, `Enable`, `Start`, `Restart`) so the service never starts unsandboxed.
- Before overwriting any existing configuration file, binary, or systemd unit/drop-in, `RollbackJournal::stage_file_mutation` validates the path and copies the original file to `<target>.bak-af.<uuid>`.
- On step failure or cancellation, `RollbackJournal::rollback` runs in reverse order:
  1. Stops, disables, and removes newly created systemd unit files.
  2. Restores `<target>.bak-af.<uuid>` backups over modified files.
  3. Removes newly created files and temporary download artifacts.

---

## 4. Exported Public Interfaces (`af_runner`)

The following stable public types and functions are exported from `af_runner` (and `af_runner::package_executor`) for `af-services`, future CLI tools, and the bare-metal provisioner:

| Symbol | Kind | Purpose |
| :--- | :--- | :--- |
| `PackageAction` | `enum` | `Install`, `Update`, `Remove` (`parse`, `as_str`) |
| `PackageEngineMode` | `enum` | `DeclarativeRust`, `LegacyBashFallback` |
| `ExecutionPhase` | `enum` | `Validate`, `LockAcquire`, `ExecuteStep`, `SandboxApply`, `FinalizeLock`, `Rollback`, `Complete`, `Failed`, `Cancelled` |
| `PackageProgressEvent` | `struct` | Structured progress event with `to_wire_line()` |
| `PackageExecutionOutcome` | `struct` | Final execution summary (steps, lock path, resolved version, sandbox status, logs) |
| `ArtifactVerificationPolicy` | `struct` | Size bounds, SHA-256 digest, gzip/ELF magic header requirements |
| `ArchAssetMap` | `struct` | Per-architecture (`amd64`, `arm64`, `armhf`) asset filename mapping |
| `DeclarativeStep` | `enum` | Typed installation/removal primitives (`AptUpdate`, `AptInstall`, `AptPurge`, `EnsureSystemUser`, `PurgeSystemUser`, `EnsureDirectories`, `ProbeSshPort`, `ResolveGitHubReleaseTag`, `DownloadAndExtractTarGz`, `DownloadBinary`, `WriteTemplateFile`, `WriteSystemdUnit`, `Systemctl`, `PurgeSystemdUnit`, `RemovePaths`, `GenerateSelfSignedTlsCert`, `CaptureDpkgVersion`) |
| `SystemctlOp` | `enum` | `DaemonReload`, `EnableNow`, `Enable`, `Start`, `Restart`, `Stop`, `Disable`, `ResetFailed` |
| `DeclarativePackageRecipe` | `struct` | Complete validated package lifecycle recipe (`validate()`, `steps_for_action()`) |
| `PackageExecutorError` | `enum` | Typed error hierarchy (`Validation`, `SecurityViolation`, `LockConflict`, `Cancelled`, `ArtifactVerification`, `StepFailed`, `Io`) |
| `CancellationToken` | `struct` | Cooperative cancellation handle (`new`, `cancel`, `is_cancelled`, `check`) |
| `CommandRunner` / `TokioCommandRunner` | `trait` / `struct` | Pluggable command execution backend for production vs isolated test mocking |
| `PackageExecutionEnv` | `struct` | Execution environment (`default()`, `isolated(root)`, `resolve_path`, `resolve_lock_file`) |
| `DeclarativePackageExecutor` | `struct` | Core recipe executor (`new`, `with_runner`, `execute_recipe`) |
| `get_declarative_recipe` | `fn` | Looks up a verified built-in declarative recipe by `pkg_id` |
| `list_declarative_recipe_ids` | `fn` | Lists all package IDs migrated to the native Rust executor |
| `select_package_engine` / `select_package_engine_with_flags` | `fn` | Returns `DeclarativeRust` or `LegacyBashFallback` for `pkg_id` honoring feature flags |
| `can_resolve_package_operation` | `fn` | Checks whether a package action can be satisfied by Rust recipe or Bash script |
| `execute_declarative_recipe_stream` | `fn` | Streams declarative recipe progress events live as each step executes |
| `execute_package_request_stream` | `fn` | Streams package execution lines (used by `POST /v1/package`) |
| `execute_package_local` | `fn` | Runs a package action in-process with line callback |
| `cancel_package_execution` / `dispatch_package_cancel` | `fn` | Signals cooperative cancellation for an active package operation |
| `verify_artifact_file` | `fn` | Verifies artifact size, magic bytes, and SHA-256 digest |
| `validate_managed_path` / `validate_chown_target_path` | `fn` | Validates a path against managed prefix, traversal, and shared-root `chown` rules |
| `parse_progress_line` | `fn` | Parses `[PROGRESS:<pct>] <message>` lines |

---

## 5. Recipe Migration Status vs Legacy Bash Fallback

Twelve Marketplace applications are registered in `BUILTIN_DECLARATIVE_RECIPES`. Registration is restricted to catalog packages with executable install, update, and remove steps:

### 5.1 Migrated to Native Declarative Rust (`PackageEngineMode::DeclarativeRust` when `AETHERFLOW_ENABLE_RUST_PACKAGES=1`)
| Package ID | Archetype | Key Operations |
| :--- | :--- | :--- |
| `fail2ban` | APT + SSH Port Detection + Systemd | Installs `fail2ban`, `python3-systemd`, `iptables`; probes `/etc/ssh/sshd_config` for custom `Port`; writes `/etc/fail2ban/jail.local`; applies systemd sandbox drop-in before service activation. |
| `quassel` | APT + Self-Signed TLS + Dpkg Version + Systemd | Installs `quassel-core`, ensures `quasselcore` user and `/var/lib/quassel`, generates 4096-bit self-signed TLS cert (`GenerateSelfSignedTlsCert`), captures installed dpkg version (`CaptureDpkgVersion`), and runs `quasselcore.service`. |
| `threadfin` | GitHub Binary + Systemd | Resolves latest `Threadfin/Threadfin` release tag, downloads and verifies ELF binary into `/opt/threadfin/threadfin`, creates `threadfin` system user and `/var/lib/threadfin`, and runs `threadfin.service`. |
| `znc` | APT + Self-Signed TLS + Systemd | Installs `znc`, creates `znc` user and `/var/lib/znc/configs`, generates `/var/lib/znc/znc.pem` (`GenerateSelfSignedTlsCert`), writes default `znc.conf`, and manages `znc.service`. |
| `xrdp` | APT + Desktop Session + Systemd | Installs `xrdp`, `xfce4`, `xfce4-goodies`, `dbus-x11`, configures `/etc/xrdp/startwm.sh`, and manages `xrdp.service`. |
| `novnc` | APT + Websockify Systemd | Installs `novnc`, `python3-websockify`, `tigervnc-standalone-server`, `xfce4`, and manages `novnc.service` on `127.0.0.1:6080`. |
| `x2go` | APT + SSH Remote Desktop | Installs `x2goserver`, `x2goserver-xsession`, `xfce4`, `xfce4-goodies`, captures dpkg version, and manages `x2goserver.service`. |
| `prometheus` | APT + Metrics Server | Installs `prometheus`, `prometheus-node-exporter`, writes `/etc/prometheus/prometheus.yml` (`127.0.0.1:9090`), and manages `prometheus.service`. |
| `netdata` | APT + Local Telemetry Daemon | Installs `netdata`, writes `/etc/netdata/netdata.conf` bound to `127.0.0.1:19999`, and manages `netdata.service`. |
| `mergerfs` | APT Union Filesystem | Installs `mergerfs` and `fuse3`, creates `/var/lib/aetherflow/mergerfs`, and records installed dpkg version. |
| `rclone` | APT + Rclone Web RCD | Installs `rclone` and `fuse3`, creates `rclone` user and `/var/lib/rclone`, and manages `rclone-web.service` (`127.0.0.1:5572`). |
| `syncthing` | APT Continuous File Sync | Installs `syncthing`, creates `syncthing` user and `/var/lib/syncthing`, and manages `syncthing@syncthing.service`. |

### 5.2 Remaining Marketplace Packages (`PackageEngineMode::LegacyBashFallback`)
- Other catalog packages continue to execute their native systemd Bash installers under the shared advisory lock and process-group cancellation supervisor. This includes Scrutiny: its previous Rust recipe omitted binary and web asset downloads and therefore no longer registers as executable. ClamAV and Mosquitto are outside the Marketplace catalog and are not registered.

## Validation and Safety Boundary

On November 1, 2026, `cargo test --workspace` passed all 131 tests in an isolated Linux checkout, including 29 `af-runner` tests covering all 15 built-in declarative recipes, `GenerateSelfSignedTlsCert`, `CaptureDpkgVersion`, persistent advisory lock inode/content preservation, queued cancellation, process-group cancellation, bounded command output, live progress streaming, ancestor-symlink rejection, and exclusive atomic writes/rollback backups.

The Marketplace lifecycle repair also captures the installed Debian version for every APT-backed recipe, uses `unknown` until a version is resolved, and preserves configuration and system accounts on removal unless `DELETE_DATA=true`. Automatic health recovery uses the same process mutex and persistent flock as privileged package execution. See [Marketplace repair validation](marketplace-repair.md).
