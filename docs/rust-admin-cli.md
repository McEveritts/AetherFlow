# AetherFlow Unified Rust Administrative CLI (`af` / `af-cli`)

## Overview & Architectural Boundaries

`af-cli` (`backend-rs/crates/af-cli`, binary name `af`, library crate `af_cli`) provides a bounded, unified Rust administrative CLI and resumable provisioning foundation for AetherFlow's bare-metal `systemd` + `Apache2` control plane.

### Key Design Principles

1. **Runner-Mediated Privileged Operations (`AF_UNIX`)**:
   Package lifecycle (`install`, `reinstall`, `remove`, `update`, `cancel`), systemd service control (`start`, `stop`, `restart`, `reload`, `enable`, `disable`, `status`), disk quota enforcement (`setdisk` / `quota set`), systemd drop-in sandboxing (`sandbox apply`), local DNS reconciliation (`hosts`), runner health probing (`health`), and background self-update triggers (`release deploy` / `rollback`) are dispatched over `/run/aetherflow/runner.sock` (`/v1/health`, `/v1/package`, `/v1/package/cancel`, `/v1/systemctl`, `/v1/quota`, `/v1/sandbox`, `/v1/hosts`, `/v1/self-update`) using the canonical `af-models` wire structs.
2. **Shared Crate Logic**:
   - Quota block calculations reuse `af_runner::parse_quota_size_to_1k_blocks` and `af_runner::{SAFE_USERNAME, SAFE_QUOTA_SIZE}`.
   - Systemd drop-in rendering reuses `af_runner::render_systemd_sandbox_dropin` and `af_runner::get_runner_package_definition`.
   - Release status, deployment, rollback, slot cleanup, and systemd migration reuse `af_release::{ReleaseConfig, ReleaseEngine, ReleaseOptions, ReleaseChannel, ReleaseCommand, validate_self_update_request}`.
   - Host backup creation, inventory listing, SHA-256 sidecar verification, chunk splitting/assembly, preflight planning, and confirmed staged restore reuse `af_host`.
3. **Conservative Release & Restore Safety**:
   - Runtime production release/rollback execution defaults to the runner-mediated native Rust `af-release` transient systemd unit (`/v1/self-update` running `af [--root <root>] release deploy|rollback --channel <channel> --local --config <job_conf> --job-status-file <status_json> --job-unit <unit>`), with `AETHERFLOW_FORCE_BASH_RELEASE=1` (or `AETHERFLOW_RELEASE_ENGINE=bash`) available as an explicit escape hatch to `deploy/release-manager.sh`.
   - Unconfirmed live restore (`af backup restore` without `--confirm-destructive-restore` or `--dry-run`) fails closed via `af_host::execute_destructive_restore` (`HostBackupError::DestructiveRestoreUnsupported`, exit code `6`). Passing `--dry-run` only checks that `<filename>` and `<filename>.manifest.json` exist as regular files; use `af backup restore-preflight` to compute a verified non-destructive `RestorePlan`. Executing a live restore requires explicit `--target-root <dir> --confirm-destructive-restore` (or `--confirm`), plus `--allow-overwrite` when targeting an existing live root `/`.
4. **Resumable Provisioning Foundation (`STATE_VERSION=2`)**:
   - Implements persisted step completion (`/install/.aetherflow.state`), atomic key-value configuration (`/install/.aetherflow.conf`), crash-safe PID lockfile protection (`/run/aetherflow-setup.lock`), distro preflight checks, SHA-256 sidecar config overlays (`<target>.aetherflow-sha256` + `<target>.user-backup.<ts>`), and `--repair` / `--resume` / `--fresh` / `--dry-run`.
   - Enforces full ancestor symlink rejection (`ensure_no_symlink_ancestors`), exclusive unique sibling temporary files (`OpenOptions::create_new(true)` + `Uuid::new_v4()` + `sync_all()` before `fs::rename`), private `0600` permissions from inode creation time on state/secret/log files, and atomic hard-link/exclusive lockfile acquisition with stale-PID crash recovery.
   - **Retains `setup/AetherFlow-Setup`**: `af provision` does **not** replace the full interactive shell installer (`whiptail` prompts, distro `apt-get` repository bootstrap, Apache vhost generation, or interactive TLS setup). The `bbr` network-tuning step executes natively in Rust via `af_host::apply_network_tuning`.
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
| `-h`, `--help`, `af help [topic]` | Display general or topic-specific usage help |
| `-V`, `--version`, `af version` | Display binary version and target platform metadata |

### Deterministic Exit Codes (`CliExitCode`)

| Exit Code | Slug | Meaning |
| :--- | :--- | :--- |
| `0` | `ok` | Command succeeded |
| `2` | `usage_or_validation_error` | Invalid CLI syntax, unknown flag, disallowed local override during runner dispatch, or rejected identifier/traversal/symlink input |
| `3` | `runner_ipc_failure` | Privileged runner socket unreachable, timed out, or returned an execution error |
| `4` | `preflight_or_integrity_failure` | Release/backup/provisioning preflight, lockfile contention, or SHA-256 integrity failure |
| `5` | `privilege_required` | Insufficient local privileges (`UID != 0`) when mutating system paths directly |
| `6` | `unsupported_operation` | Intentionally unsupported flow (e.g., unconfirmed live `af backup restore` without `--dry-run`, or no-arg interactive TUI) |
| `7` | `execution_failure` | Filesystem, SQLite, or runtime execution error |

---

## Command Reference

### 1. Legacy `packages/system/af` Shorthands & `af package`

Preserves supported non-interactive subcommands of `packages/system/af`. The legacy `autodl` lock-name mapping is retained as a helper, but package operations still require a current runner-catalog entry; absent packages are rejected rather than bypassing the allowlist. `af pkg` is accepted as an alias for `af package`, `af uninstall` for `af remove`, and `af package inspect` for `af package info` (short flags `-p` for `--port`, `-t` for `--target-version`, `-c` for `--channel`):

```bash
# Legacy top-level shorthands:
af install <pkg1> [pkg2...] [--port <port>]
af reinstall <pkg1> [pkg2...] [--port <port>]
af remove <pkg1> [pkg2...] [--purge]
af list [--installed]
af update [pkg] [--target-version <ver>] [--channel <stable|nightly>]
af upgrade [--channel <stable|nightly>]

# Structured subcommands:
af package install <pkg1> [pkg2...] [--port <port>]
af package reinstall <pkg1> [pkg2...] [--port <port>]
af package remove <pkg1> [pkg2...] [--purge]
af package update [pkg] [--target-version <ver>] [--channel <stable|nightly>]
af package upgrade [--channel <stable|nightly>]
af package list [--installed]
af package info <pkg>
af package cancel <pkg>
```

- **IPC Routes**: `POST /v1/package` (`PackageRunnerRequest`) and `POST /v1/package/cancel` (`SandboxRunnerRequest`). *(Note: `RunnerClientTransport::probe_package_version` targets `/v1/package/probe-version` on the client trait, though no `af package` CLI subcommand invokes it directly.)*
- **Verified Stream Protocol (`PackageStreamAccumulator`)**: Reads HTTP response frames incrementally via `http_body_util::BodyExt::frame` without buffering the full body in memory. Uses a bounded partial-line carry buffer (`MAX_PACKAGE_STREAM_LINE_CARRY_BYTES = 16 KiB`) and bounded log-line ring (`MAX_RETAINED_PACKAGE_LOG_LINES = 512`), parses incoming `[PROGRESS:<pct>] <message>` wire lines and formats live human output (`[pct%] <package_id>: <message>`, or indented log lines) to `stdout` when `!global.json` while keeping `--json` output strictly valid JSON, and calls `finish_verified()`, requiring matching durable `JOB_MARKER` and `RECEIPT_MARKER` frames (`LifecycleReceipt` with `status == "completed"`) and failing closed on `__RUNNER_EXIT_ERROR__:<reason>` or missing/failed receipts.
- **Purge Ownership Safety & Version Discovery**: `af package remove --purge` invokes `af_runner::inspect_package_purge_state` and fails closed on `AmbiguousMarkerless` retained-data states. `af update <pkg>` resolves target versions from `--target-version` / `AF_TARGET_VERSION`, SQLite `app_updates.latest_version`, or live upstream discovery (`github`, `github_release`, `git_tags`, `pypi`, `git`, `apt`, `pinned`) and honors `RCLONE_API_PORT` for `rclone`.
- **Rust Package Executor Gate**: In `af-runner`, native Rust package execution is **disabled by default** unless `AETHERFLOW_ENABLE_RUST_PACKAGES=1` is set in the runner environment; `af-cli` never sets or enables that gate automatically.

### 2. Systemd Service Control (`af service`)

Aliases: `af svc`, `af systemctl`.

```bash
af service <start|stop|restart|reload|enable|disable|status> <service_name>
```

- **IPC Route**: `POST /v1/systemctl` (`SystemctlRequest`).
- **Validation**: Enforces `af_runner::SAFE_SERVICE_NAME` and the 7 allowlisted `systemctl` actions.

### 3. User Disk Quota Management (`af quota` / `af setdisk`)

```bash
af quota set <username> <size>
af setdisk <username> <size>
af quota check-size <size>    # alias: af quota parse <size>
```

- **IPC Route**: `POST /v1/quota` (`QuotaRunnerRequest`).
- **Validation**: Reuses `af_runner::SAFE_USERNAME`, `af_runner::SAFE_QUOTA_SIZE`, and `af_runner::parse_quota_size_to_1k_blocks` (`Option<(u64, u64)>`).

### 4. Systemd Drop-In Sandboxing (`af sandbox`)

```bash
af sandbox apply <package>
af sandbox render <package> [--user <username>]   # aliases: preview, -u
```

- **IPC Route**: `POST /v1/sandbox` (`SandboxRunnerRequest`) for `apply`; in-process `af_runner::render_systemd_sandbox_dropin` for `render`.

### 5. Release Lifecycle & Self-Update (`af release`)

Top-level alias: `af self-update` (short flag `-c` for `--channel`).

```bash
af release status [--config <path>]
af release deploy [--channel <stable|nightly>] [--via-runner | --local | --direct-engine] [--offline] [--from-source] [--keep-releases <n>] [--config <path>] [--job-status-file <path>] [--job-unit <unit>]
af release rollback [--channel <stable|nightly>] [--via-runner | --local | --direct-engine] [--config <path>] [--job-status-file <path>] [--job-unit <unit>]
af release cleanup [--keep-releases <n>] [--config <path>]
af release migrate-systemd [--config <path>]
```

- By default (`ReleaseDispatchMode::RunnerSocket`, or explicitly `--via-runner`), `deploy` and `rollback` dispatch `SelfUpdateRequest` to `/v1/self-update` on `af-runner`, which launches a transient systemd unit (`aetherflow-self-update-<command>-<channel>-<8hex>.service`) executing `af release <command> --local` by default (or `deploy/release-manager.sh` when `AETHERFLOW_FORCE_BASH_RELEASE=1` or `AETHERFLOW_RELEASE_ENGINE=bash` is set). Passing local overrides (`--root`, `--config`, `--keep-releases`, `--job-status-file`, `--job-unit`, `AETHERFLOW_RELEASE_ROOT`, or `AETHERFLOW_RELEASE_CONF`) in runner-socket mode without `--local` is rejected with `CliError::Validation` (exit code `2`).
- Passing `--local`, `--direct-engine`, `--offline`, or `--from-source` switches to direct in-process `af_release::ReleaseEngine` execution, loading configuration via `ReleaseConfig::load_for_root_from_process_env` (also honoring `AETHERFLOW_SELF_UPDATE_STATUS_FILE` and `AETHERFLOW_SELF_UPDATE_JOB_UNIT`).

### 6. Host Backup & Coordinated Staged Restore (`af backup`)

Subcommand aliases: `ls` (`list`), `plan-restore` / `preflight` (`restore-preflight`), `recover` (`recover-interrupted`), `rm` (`delete`), `registry` (`ownership`). Mutating backup subcommands acquire `HostMaintenanceLockGuard` with a 30-second lock timeout.

```bash
af backup create [--archive | --sqlite-only | --db-only] [--backup-dir <dir>] [--db-path <file>] [--app-version <ver>] [--timestamp <slug>] [--chunk-size <size>] [--trusted-sqlite-uid <uid>] [--trusted-sqlite-gid <gid>] [--operator-privileged]
af backup list [--backup-dir <dir>]
af backup verify <filename> [--backup-dir <dir>] [--trusted-sqlite-uid <uid>]
af backup restore-preflight <filename> --target-root <staging_dir> [--backup-dir <dir>] [--host-version <ver>] [--max-sqlite-user-version <n>] [--trusted-sqlite-uid <uid>] [--allow-staging-overwrite]
af backup restore <filename> --target-root <staging_dir> --confirm-destructive-restore [--backup-dir <dir>] [--allow-overwrite | --allow-staging-overwrite] [--trusted-sqlite-uid <uid>] [--trusted-sqlite-gid <gid>] [--operator-privileged]
af backup recover-interrupted [--target-root <dir>] [--backup-dir <dir>] [--trusted-sqlite-uid <uid>] [--trusted-sqlite-gid <gid>] [--operator-privileged]
af backup delete <filename> [--backup-dir <dir>] [--operator-privileged]
af backup prune [--backup-dir <dir>] [--max-retained <n>] [--retention-days <days>] [--operator-privileged]
af backup chunk <filename> [(--size | --chunk-size) <size>] [--backup-dir <dir>] [--operator-privileged]   # default chunk size: 50 MiB
af backup assemble (--output | -o) <filename> --sha256 <hex> <chunk1> [chunk2...] [--backup-dir <dir>] [--operator-privileged]
af backup ownership
```

- **Non-Destructive Restore Preflight (`restore-preflight`)**: Validates `.sha256` sidecars, `.manifest.json` schema/semver compatibility, tar entry headers (rejecting `..`, rooted paths, and symlinks/hardlinks), and destination collisions under `--target-root` (alias `--staging-dir`; pass `--allow-staging-overwrite` when preflighting against existing targets) without writing to disk or stopping services, returning a `RestorePlan`. By contrast, `af backup restore --dry-run` only confirms `<filename>` and `<filename>.manifest.json` exist as regular files without running preflight or manifest validation.
- **Confirmed Staged Restore (`restore --target-root <dir> --confirm-destructive-restore`)**: Invokes `af_host::execute_staged_restore` (aliases `--staging-dir`, `--confirm`; pass `--allow-overwrite` when restoring onto an existing live root `/`) with service quiescence (note: on Linux without `--root`, even staging restores stop and restart live `aetherflow-api.service`), provenance-protected rollback recovery, SHA-256 verification, and `PRAGMA quick_check` + `PRAGMA integrity_check` (see [Rust Host Management](./rust-host-management.md) for canonical `/` allowlist limitations on `.master.creds` / `oidc_rsa.pem`). Calling live `af backup restore` without `--confirm-destructive-restore` (and without `--dry-run`) fails closed with `HostBackupError::DestructiveRestoreUnsupported` (exit code `6`).

### 7. Host Maintenance Utilities (`af maintenance` & Top-Level Aliases)

Additional aliases: `af af-tune`, `af af-sentinel`, `af clean-log`, `af maintenance clean-log`, `af maintenance registry`.

```bash
af maintenance tune [--root <path>] [--dry-run]
af tune [--root <path>] [--dry-run]

af maintenance sentinel [--log-path <path> | --file <path>] [--threshold <n>]
af sentinel [--log-path <path> | --file <path>] [--threshold <n>]

af maintenance clean-logs [--root <path>] [--max-size <bytes> | --size <bytes>] [--dry-run]
af clean-logs [--root <path>] [--max-size <bytes> | --size <bytes>] [--dry-run]

af maintenance showspace [--root <path>] [--user <user>]
af showspace [--root <path>] [--user <user>]

af maintenance ownership
```

- Delegates directly to `af_host::maintenance` (`apply_network_tuning`, `sentinel_scan_auth_log`, `clean_system_logs`, and `inspect_home_disk_space`).

### 8. Runner Health & Local DNS Reconciliation (`af health` & `af hosts`)

Aliases: `af ping` / `af status` (for `af health`); `af dns` (for `af hosts`).

```bash
af health

af hosts update <ip> <domain1> [domain2...]
af hosts remove <domain1> [domain2...]
af hosts reconcile [ip] [domain1...]
```

- `af health` probes `/v1/health` over `/run/aetherflow/runner.sock`.
- `af hosts` dispatches `/v1/hosts` requests to manage `/etc/hosts`, `dnsmasq` (`/etc/dnsmasq.d`), Pi-hole, and AdGuard Home local DNS mappings (`reconcile` defaults to `127.0.0.1` when no IP is supplied).

### 9. Resumable Bare-Metal Provisioning Foundation (`af provision`)

Aliases: `af setup` (for `af provision`), `af provision steps` (for `list-steps`), `af provision resume` (for `run --resume`), `--step` / `-s`, `--source` / `--target` (on `overlay-config`), and `--yes` (on `reset`).

```bash
af provision preflight [--os-release <path>] [--require-root]
af provision status
af provision list-steps
af provision run [<step1> ...] [--fresh | --resume] [--no-root-check]
af provision repair <step1> [step2...] [--no-root-check]
af provision overlay-config <source> <target> [--force]
af provision reset --confirm
```

- **14 Rust-Native Foundation Steps**: `checkroot`, `logcheck`, `checkkernel`, `makedirs`, `boot`, `harden_perms`, `bashrc`, `hostname`, `locale`, `skel`, `apachesudo`, `build_modern`, `bbr`, and `perms` execute natively in Rust with `# STATE_VERSION=2` persistence, ancestor symlink rejection, and atomic writes. Running `af provision run` without explicit step names executes only the **6** default foundation steps (`checkroot`, `logcheck`, `checkkernel`, `makedirs`, `boot`, `harden_perms`); the remaining 8 Rust-native steps run only when explicitly named.
- **Safe Config Overlay**: `af provision overlay-config` tracks stock SHA-256 digests in `<target>.aetherflow-sha256` and backs up operator-modified files to `<target>.user-backup.<timestamp>` (`0600`) before applying updates.

> [!WARNING]
> **Production Env Defaults in `af provision`**: Fresh `af provision` generation of `/etc/aetherflow/aetherflow.env` (`build_modern`) writes `BIND_ADDR=0.0.0.0` and `COOKIE_SECURE=false` and tightens existing `0640` env files to `0600`. On production hosts behind Apache2 HTTPS, verify `BIND_ADDR=127.0.0.1` and `COOKIE_SECURE=true` before starting `aetherflow-api.service`.

---

## Remaining Intentional Boundaries

1. **Interactive `whiptail` TUI (`af` with no arguments)**:
   Calling `af` without arguments returns `CliExitCode::UnsupportedOperation` (`6`). Interactive dialog menus remain in `packages/system/af` and `setup/AetherFlow-Setup`.
2. **Interactive Shell Bootstrap (`setup/AetherFlow-Setup`)**:
   Rust implements 14 of the 34 canonical steps in `af_cli::provision::CANONICAL_ALL_STEPS` (`checkroot`, `logcheck`, `checkkernel`, `makedirs`, `boot`, `harden_perms`, `bashrc`, `hostname`, `locale`, `skel`, `apachesudo`, `build_modern`, `bbr`, `perms`). Bash implements the 20 retained steps, including `repos`, `updates`, `depends`, `apacheconf`, `fix_cert`, `installftpd`, and `ffmpeg`, in `setup/modules/`.
3. **Unconfirmed Live Root Restore**:
   Live `af backup restore` requires explicit `--target-root <dir> --confirm-destructive-restore` (`execute_staged_restore`) and refuses unconfirmed non-dry-run invocations (`DestructiveRestoreUnsupported`, exit code `6`).

## Isolated Linux Validation

`cargo test --manifest-path backend-rs/Cargo.toml -p af-cli --locked` validates CLI parsing, runner IPC requests, incremental progress streaming, backup/staged-restore commands, maintenance commands (`tune`, `sentinel`, `clean-logs`, `showspace`), hosts reconciliation, and all 14 Rust-native provisioning steps in isolated roots.
