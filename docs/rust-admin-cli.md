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
af update [pkg] [--channel <stable|nightly|experimental>]
af upgrade [--channel <stable|nightly|experimental>]

# Structured subcommands:
af package install <pkg1> [pkg2...] [--port <port>]
af package remove <pkg1> [pkg2...]
af package update [pkg] [--channel <stable|nightly|experimental>]
af package upgrade [--channel <stable|nightly|experimental>]
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
af release deploy [--channel <stable|nightly|experimental>] [--local] [--offline] [--from-source] [--keep-releases <n>] [--config <path>]
af release rollback [--channel <stable|nightly|experimental>] [--local] [--config <path>]
af release cleanup [--keep-releases <n>] [--config <path>]
af release migrate-systemd [--config <path>]
```

- By default, `deploy` and `rollback` dispatch `SelfUpdateRequest` to `/v1/self-update` on `af-runner` (which invokes `deploy/release-manager.sh` in the root runner cgroup). Passing `--local` (or `--root <dir> --dry-run`) invokes `af_release::ReleaseEngine` (`ReleaseConfig::for_root` / `ReleaseConfig::load_from_process_env` and `ReleaseOutcome::{Deploy, Rollback, Cleanup, MigrateSystemd}`) directly.

### 6. Host Backup & Non-Destructive Restore Preflight (`af backup`)

```bash
af backup create [--archive | --sqlite-only] [--backup-dir <dir>] [--db-path <file>] [--app-version <ver>] [--chunk-size <size>] [--operator-privileged]
af backup list [--backup-dir <dir>]
af backup verify <filename> [--backup-dir <dir>]
af backup restore-preflight <filename> --target-root <staging_dir> [--backup-dir <dir>] [--host-version <ver>] [--allow-staging-overwrite]
af backup delete <filename> [--backup-dir <dir>] [--operator-privileged]
af backup prune [--backup-dir <dir>] [--max-retained <n>] [--retention-days <days>] [--operator-privileged]
af backup chunk <filename> <size> [--backup-dir <dir>] [--operator-privileged]
af backup assemble --output <filename> --sha256 <hex> <chunk1> [chunk2...] [--backup-dir <dir>] [--operator-privileged]
af backup ownership
```

- **Non-Destructive Restore Preflight Only**: `af backup restore-preflight` validates `.sha256` sidecars, `.manifest.json` schema/semver compatibility, tar entry headers (rejecting `..`, rooted paths, and symlinks/hardlinks), and destination collisions under `--target-root` without writing to disk.
- **Destructive Live Restore Disabled**: `af backup restore` calls `af_host::execute_destructive_restore`, which always returns `HostBackupError::DestructiveRestoreUnsupported` (exit code `6`).

### 7. Resumable Bare-Metal Provisioning Foundation (`af provision`)

```bash
af provision preflight [--os-release <path>] [--require-root]
af provision status
af provision list-steps
af provision run [<step1> ...] [--fresh | --resume] [--no-root-check]
af provision repair <step1> [step2...] [--no-root-check]
af provision overlay-config <source> <target> [--force]
af provision reset --confirm
```

- **State File Compatibility & Hardening**: Reads and writes `/install/.aetherflow.state` with header `# STATE_VERSION=2` and `/install/.aetherflow.conf`, matching `setup/modules/06-state.sh`. Verifies all path ancestors against symlinks, writes via exclusive `create_new(true)` temporary files with `0600` private permissions at creation time and `sync_all()` before atomic `rename`, and guards execution with crash-safe PID lockfiles (`/run/aetherflow-setup.lock`).
- **Safe Config Overlay**: `af provision overlay-config` tracks stock SHA-256 digests in `<target>.aetherflow-sha256` and backs up operator-modified files to `<target>.user-backup.<timestamp>` (`0600`) before applying updates.

---

## Remaining Unsupported Migrations & Production Boundaries

1. **Interactive `whiptail` TUI (`af` with no arguments)**:
   Calling `af` without arguments returns `CliExitCode::UnsupportedOperation` (`6`). Interactive dialog menus remain in `packages/system/af` and `setup/AetherFlow-Setup`.
2. **Full Interactive Shell Installer (`setup/AetherFlow-Setup`)**:
   33 of the 39 canonical `ALL_STEPS` (interactive prompts, `apt` repo setup, kernel `bbr`, `vsftpd`, `ffmpeg`, `apacheconf`, `fix_cert`, etc.) remain `RetainedShellBootstrap` steps in `setup/modules/*.sh`. `af provision` provides the persisted `# STATE_VERSION=2` state store, preflight checks, safe config overlay, and the 6 core FHS/systemd/permission foundation steps (`checkroot`, `logcheck`, `checkkernel`, `makedirs`, `boot`, `harden_perms`).
3. **Destructive In-Place Live Restore (`af backup restore`)**:
   Intentionally unsupported in `af-host` and `af-cli` to prevent corrupting live SQLite WAL state or open service configs. Only non-destructive `af backup restore-preflight` is supported.
4. **Privileged Runner Socket Route for Host Backups**:
   `af-runner` does not yet expose a `/v1/backup` socket endpoint; `af backup` executes locally via `af-host` and requires root privileges (`UID == 0`), `--operator-privileged`, or an isolated `--root <dir>` when writing to system paths.
5. **Default-Off Rust Package Dispatch (`AETHERFLOW_ENABLE_RUST_PACKAGES=1`) & Ongoing Hardening**:
   Native Rust package execution in `af-runner` is gated off by default unless `AETHERFLOW_ENABLE_RUST_PACKAGES=1` is set, and runtime production release/restore operations remain on Bash until `af-host`, `af-release`, and `af-runner` remediation and Linux verification gates complete.

## Isolated Linux Validation

`cargo test -p af-cli` passes all 11 tests. Additional binary smoke checks cover JSON help/status, side-effect-free provision/package dry-runs, live Unix-socket progress arriving before the server finishes its response, and uncontaminated JSON output.

Provisioning uses canonical `/opt/AetherFlow` paths and a persistent advisory `.rust-guard` inode alongside the legacy PID lockfile. The advisory guard serializes Rust stale-PID recovery and is never unlinked; the PID file remains compatible with shell inspection. The legacy shell bootstrap does not honor the new advisory guard, so do not run shell and Rust provisioning concurrently. Full interactive setup and service-account provisioning remain shell-owned; these foundation tests are not a live-host provisioning certification.
