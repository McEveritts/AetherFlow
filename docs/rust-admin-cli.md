# AetherFlow Unified Rust Administrative CLI (`af` / `af-cli`)

## Overview & Architectural Boundaries

`af-cli` (`backend-rs/crates/af-cli`, binary name `af`, library crate `af_cli`) provides a bounded, unified Rust administrative CLI and resumable provisioning foundation for AetherFlow's pure bare-metal `systemd` + `Apache2` control plane (zero Docker).

### Key Design Principles

1. **Runner-Mediated Privileged Operations (`AF_UNIX`)**:
   Package lifecycle (`install`, `remove`, `update`, `cancel`), systemd service control (`start`, `stop`, `restart`, `reload`, `enable`, `disable`, `status`), disk quota enforcement (`setdisk` / `quota set`), systemd drop-in sandboxing (`sandbox apply`), and background self-update triggers (`release deploy` / `rollback`) are dispatched over `/run/aetherflow/runner.sock` using the canonical `af-models` wire structs (`PackageRunnerRequest`, `SystemctlRequest`, `QuotaRunnerRequest`, `SandboxRunnerRequest`, `SelfUpdateRequest`, `RunnerResponse`).
2. **Zero Duplicate Business Logic**:
   - Quota block calculations reuse `af_runner::parse_quota_size_to_1k_blocks` and `af_runner::{SAFE_USERNAME, SAFE_QUOTA_SIZE}`.
   - Systemd drop-in rendering reuses `af_runner::render_systemd_sandbox_dropin` and `af_runner::get_runner_package_definition`.
   - Release status, deployment, rollback, slot cleanup, and systemd migration reuse `af_release::{ReleaseConfig, ReleaseEngine, ReleaseOptions, ReleaseChannel, ReleaseCommand, validate_self_update_request}`.
   - Host backup creation, inventory listing, SHA-256 sidecar verification, chunk splitting/assembly, and non-destructive restore preflight reuse `af_host`.
3. **Conservative Release & Restore Safety**:
   - Runtime production release/rollback execution continues to default to the runner-mediated `release-manager.sh` cgroup boundary (`/v1/self-update`) while `af-release` and `af-host` undergo ancestor-symlink, permissions, and recovery hardening.
   - Live in-place destructive restore (`af backup restore`) is **intentionally unsupported** and fails closed via `af_host::execute_destructive_restore` (`HostBackupError::DestructiveRestoreUnsupported`, exit code `6`). Operators must run `af backup restore-preflight` against an isolated staging directory before performing state replacement during a service-stopped maintenance window.
4. **Resumable Provisioning Foundation (`STATE_VERSION=2`)**:
   - Implements persisted step completion (`/install/.aetherflow.state`), atomic key-value configuration (`/install/.aetherflow.conf`), crash-safe PID lockfile protection (`/run/aetherflow-setup.lock`), distro preflight checks, SHA-256 sidecar config overlays (`<target>.aetherflow-sha256` + `<target>.user-backup.<ts>`), and `--repair` / `--resume` / `--fresh` / `--dry-run`.
   - Enforces full ancestor symlink rejection (`ensure_no_symlink_ancestors`), exclusive unique sibling temporary files (`OpenOptions::create_new(true)` + `Uuid::new_v4()` + `sync_all()` before `fs::rename`), private `0600` permissions from inode creation time on state/secret/log files, and atomic hard-link/exclusive lockfile acquisition with stale-PID crash recovery.
   - **Retains `setup/AetherFlow-Setup`**: `af provision` does **not** claim to replace the full interactive shell installer (`whiptail` prompts, distro `apt-get` repository bootstrap, kernel BBR/tuned scripts, or interactive TLS setup).
   - **Never accepts arbitrary privileged commands or raw shell step strings.**

---

## Global Options & Exit Codes

### Global Flags

| Flag | Description |
| :--- | :--- |
| `--json` | Emit a structured JSON `CliResponseEnvelope` (`status`, `domain`, `action`, `exit_code`, `error_kind`, `message`, `data`) |
| `--socket <path>` | Override the privileged runner Unix socket path (default: `/run/aetherflow/runner.sock` or `AETHERFLOW_RUNNER_SOCK`) |
| `--root <dir>` | Override the filesystem root for isolated inspection, testing, backup preflight, or staging |
| `--dry-run`, `-n` | Validate arguments and compute execution plans without mutating live services or disk state |
| `-h`, `--help` | Display general or topic-specific usage help |
| `-V`, `--version` | Display binary version and target platform metadata |

### Deterministic Exit Codes (`CliExitCode`)

| Exit Code | Slug | Meaning |
| :--- | :--- | :--- |
| `0` | `ok` | Command succeeded |
| `2` | `usage_or_validation_error` | Invalid CLI syntax, unknown flag, or rejected identifier/traversal/symlink input |
| `3` | `runner_ipc_failure` | Privileged runner socket unreachable, timed out, or returned an execution error |
| `4` | `preflight_or_integrity_failure` | Release/backup/provisioning preflight, lockfile contention, or SHA-256 integrity failure |
| `5` | `privilege_required` | Insufficient local privileges (`UID != 0`) when mutating system paths directly |
| `6` | `unsupported_operation` | Intentionally unsupported flow (e.g., `af backup restore` or no-arg interactive TUI) |
| `7` | `execution_failure` | Filesystem, SQLite, or runtime execution error |

---

## Command Reference

### 1. Legacy `packages/system/af` Shorthands & `af package`

Preserves supported non-interactive subcommands of `packages/system/af`. The legacy `autodl` lock-name mapping is retained as a helper, but package operations still require a current runner-catalog entry; absent packages are rejected rather than bypassing the allowlist:

```bash
# Legacy top-level shorthands:
af install <pkg1> [pkg2...] [--port <port>]
af remove <pkg1> [pkg2...]
af list [--installed]
af update [pkg] [--channel <stable|nightly>]
af upgrade [--channel <stable|nightly>]

# Structured subcommands:
af package install <pkg1> [pkg2...] [--port <port>]
af package remove <pkg1> [pkg2...]
af package update [pkg] [--channel <stable|nightly>]
af package upgrade [--channel <stable|nightly>]
af package list [--installed]
af package info <pkg>
af package cancel <pkg>
```

- **IPC Route**: `POST /v1/package` (`PackageRunnerRequest`) and `POST /v1/package/cancel` (`SandboxRunnerRequest`).
- **Incremental Stream Protocol (`PackageStreamAccumulator`)**: Reads HTTP response frames incrementally via `http_body_util::BodyExt::frame` without buffering the full body in memory. Uses a bounded partial-line carry buffer (`MAX_PACKAGE_STREAM_LINE_CARRY_BYTES = 16 KiB`) and bounded log-line ring (`MAX_RETAINED_PACKAGE_LOG_LINES = 512`), surfaces `[PROGRESS:<pct>] <message>` lines live to `stdout` during human output (`!global.json`) while keeping `--json` output strictly valid JSON, and fails closed if `__RUNNER_EXIT_ERROR__:<reason>` is emitted by `af-runner`.
- **Rust Package Executor Gate**: In `af-runner`, native Rust package execution is **default off** unless `AETHERFLOW_ENABLE_RUST_PACKAGES=1` is explicitly set in the runner environment; `af-cli` never sets or enables that gate in real operations.

### 2. Systemd Service Control (`af service`)

```bash
af service <start|stop|restart|reload|enable|disable|status> <service_name>
```

- **IPC Route**: `POST /v1/systemctl` (`SystemctlRequest`).
- **Validation**: Enforces `af_runner::SAFE_SERVICE_NAME` and the 7 allowlisted systemctl actions.

### 3. User Disk Quota Management (`af quota` / `af setdisk`)

```bash
af quota set <username> <size>
af setdisk <username> <size>
af quota check-size <size>
```

- **IPC Route**: `POST /v1/quota` (`QuotaRunnerRequest`).
- **Validation**: Reuses `af_runner::SAFE_USERNAME`, `af_runner::SAFE_QUOTA_SIZE`, and `af_runner::parse_quota_size_to_1k_blocks` (`Option<(u64, u64)>`).

### 4. Systemd Drop-In Sandboxing (`af sandbox`)

```bash
af sandbox apply <package>
af sandbox render <package> [--user <username>]
```

- **IPC Route**: `POST /v1/sandbox` (`SandboxRunnerRequest`) for `apply`; in-process `af_runner::render_systemd_sandbox_dropin` for `render`.

### 5. Release Lifecycle & Self-Update (`af release`)

```bash
af release status [--config <path>]
af release deploy [--channel <stable|nightly>] [--local] [--offline] [--from-source] [--keep-releases <n>] [--config <path>]
af release rollback [--channel <stable|nightly>] [--local] [--config <path>]
af release cleanup [--keep-releases <n>] [--config <path>]
af release migrate-systemd [--config <path>]
```

- By default, `deploy` and `rollback` dispatch `SelfUpdateRequest` to `/v1/self-update` on `af-runner` (which invokes `deploy/release-manager.sh` in the root runner cgroup). Passing `--local` (or `--root <dir> --dry-run`) invokes `af_release::ReleaseEngine` (`ReleaseConfig::for_root` / `ReleaseConfig::load_from_process_env` and `ReleaseOutcome::{Deploy, Rollback, Cleanup, MigrateSystemd}`) directly.

### 6. Host Backup & Coordinated Staged Restore (`af backup`)

```bash
af backup create [--archive | --sqlite-only] [--backup-dir <dir>] [--db-path <file>] [--app-version <ver>] [--chunk-size <size>] [--operator-privileged]
af backup list [--backup-dir <dir>]
af backup verify <filename> [--backup-dir <dir>]
af backup restore-preflight <filename> --target-root <staging_dir> [--backup-dir <dir>] [--host-version <ver>] [--allow-staging-overwrite]
af backup restore <filename> --staging-root <staging_dir> [--backup-dir <dir>] [--host-version <ver>] [--allow-staging-overwrite] [--operator-privileged]
af backup delete <filename> [--backup-dir <dir>] [--operator-privileged]
af backup prune [--backup-dir <dir>] [--max-retained <n>] [--retention-days <days>] [--operator-privileged]
af backup chunk <filename> <size> [--backup-dir <dir>] [--operator-privileged]
af backup assemble --output <filename> --sha256 <hex> <chunk1> [chunk2...] [--backup-dir <dir>] [--operator-privileged]
af backup ownership
```

- **Non-Destructive Restore Preflight (`restore-preflight`)**: Validates `.sha256` sidecars, `.manifest.json` schema/semver compatibility, tar entry headers (rejecting `..`, rooted paths, and symlinks/hardlinks), and destination collisions under `--target-root` without writing to disk.
- **Coordinated Staged Restore (`restore --staging-root <dir>`)**: Calls `af_host::execute_staged_restore` to extract verified archive entries into an isolated staging directory (`0700` dirs / `0600` files), re-verifying every extracted file's SHA-256 digest and running `PRAGMA quick_check` on any extracted SQLite snapshot. Calling `af backup restore` without `--staging-root` fails closed with `HostBackupError::DestructiveRestoreUnsupported` (exit code `6`).

### 7. Host Maintenance Utilities (`af maintenance` & Top-Level Aliases)

```bash
af maintenance tune [--apply]
af tune [--apply]

af maintenance sentinel [--log-path <path>] [--threshold <n>]
af sentinel [--log-path <path>] [--threshold <n>]

af maintenance clean-logs [--log-dir <dir>] [--max-age-days <days>]
af clean-logs [--log-dir <dir>] [--max-age-days <days>]

af maintenance showspace [--home-dir <dir>]
af showspace [--home-dir <dir>]
```

- Delegates directly to `af_host::maintenance` (`apply_network_tuning`, `sentinel_scan_auth_log`, `clean_system_logs`, and `inspect_home_disk_space`).

### 8. Resumable Bare-Metal Provisioning Foundation (`af provision`)

```bash
af provision preflight [--os-release <path>] [--require-root]
af provision status
af provision list-steps
af provision run [<step1> ...] [--fresh | --resume] [--no-root-check]
af provision repair <step1> [step2...] [--no-root-check]
af provision overlay-config <source> <target> [--force]
af provision reset --confirm
```

- **14 Rust-Native Foundation Steps**: `checkroot`, `logcheck`, `checkkernel`, `makedirs`, `boot`, `harden_perms`, `bashrc`, `hostname`, `locale`, `skel`, `apachesudo`, `build_modern`, `bbr`, and `perms` execute natively in Rust with `# STATE_VERSION=2` persistence, ancestor symlink rejection, and atomic writes.
- **Safe Config Overlay**: `af provision overlay-config` tracks stock SHA-256 digests in `<target>.aetherflow-sha256` and backs up operator-modified files to `<target>.user-backup.<timestamp>` (`0600`) before applying updates.

---

## Remaining Intentional Boundaries

1. **Interactive `whiptail` TUI (`af` with no arguments)**:
   Calling `af` without arguments returns `CliExitCode::UnsupportedOperation` (`6`). Interactive dialog menus remain in `packages/system/af` and `setup/AetherFlow-Setup`.
2. **Interactive Shell Bootstrap (`setup/AetherFlow-Setup`)**:
   14 of the 39 canonical `ALL_STEPS` (`checkroot`, `logcheck`, `checkkernel`, `makedirs`, `boot`, `harden_perms`, `bashrc`, `hostname`, `locale`, `skel`, `apachesudo`, `build_modern`, `bbr`, `perms`) execute natively in Rust; the remaining 25 interactive/APT steps (`repos`, `pkgs`, `apacheconf`, `fix_cert`, `vsftpd`, `ffmpeg`, etc.) remain `RetainedShellBootstrap` steps in `setup/modules/*.sh`.
3. **Uncoordinated Live Root Restore**:
   `af backup restore` requires `--staging-root <dir>` (`execute_staged_restore`) and refuses uncoordinated live `/` overwrites (`DestructiveRestoreUnsupported`).

## Isolated Linux Validation

`cargo test -p af-cli` passes all 13 unit tests covering CLI parsing, runner IPC requests, incremental progress streaming, backup/staged-restore commands, maintenance commands (`tune`, `sentinel`, `clean-logs`, `showspace`), and all 14 Rust-native provisioning steps in isolated roots.
