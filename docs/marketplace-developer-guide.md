# Marketplace Developer Guide

This guide details the conventions and technical requirements for adding new bare-metal applications to **AetherMarketplace** (**77 native Linux packages**).

## Package Execution Architecture (`af-runner`)

In AetherFlow v4.0.0, Marketplace installation, update, reinstall, and removal (runner action `remove`) execute through `aetherflow-runner.service` (`backend-rs/crates/af-runner`) with lifecycle ownership, maintenance lock, and admission checks. Script execution also uses a process-wide mutex and cross-process advisory file lock (`/install/.af-package-executor.flock`):

1. **Declarative Rust Recipes ([`declarative_recipes.rs`](../backend-rs/crates/af-runner/src/package_executor/declarative_recipes.rs) & [`catalog.rs`](../backend-rs/crates/af-runner/src/package_executor/declarative_recipes/catalog.rs))**:
   - 9 packages (`fail2ban`, `quassel`, `threadfin`, `znc`, `xrdp`, `x2go`, `netdata`, `mergerfs`, `rclone`) have opt-in native declarative Rust recipes (`DeclarativePackageRecipe`, enabled via `AETHERFLOW_ENABLE_RUST_PACKAGES=1`) with `lstat` ancestor-symlink validation, pre-start systemd sandboxing for non-privileged units, and `RollbackJournal`. See [Rust Package Executor](./rust-package-executor.md).
2. **Idempotent Bash Lifecycle Scripts (`packages/package/`)**:
   - All packages default to structured Bash scripts under `packages/package/{install,remove}/` that source `packages/common.sh`. Installers also handle update and reinstall actions. Start new installers from [`docs/installpackage-template.sh`](./installpackage-template.sh), which already demonstrates `af-<app_id>.service`, `validate_config_paths`, `write_config_file`, `af_github_curl`, and `127.0.0.1` loopback binding. See [Marketplace Lifecycle Log Retention](./marketplace-log-retention.md) for `/var/log/aetherflow` log rotation bounds.

```text
packages/
├── common.sh                             # Core helper loader (mandatory for Bash scripts)
├── lib/                                  # Modular shell libraries loaded by common.sh + CLI shim helper
│   ├── logging_archives.sh
│   ├── versions_apt.sh
│   ├── state_downloads.sh
│   ├── config_database.sh
│   ├── apache_dns_locks.sh
│   ├── redaction_receipts.sh
│   ├── systemd_credentials.sh
│   └── cli_shim.sh
├── system/                               # Host system scripts and af CLI compatibility shims
├── youtube-common.sh                     # Shared helper for Piped & Invidious
└── package/
    ├── install/
    │   └── installpackage-<app_id>       # Installation & in-place update entry point
    └── remove/
        └── removepackage-<app_id>        # Uninstallation entry point
```

---

## The `common.sh` Library

Every Bash marketplace script **must** use `#!/bin/bash` and source `packages/common.sh` (a lightweight loader that sources the 7 modular helper libraries under `packages/lib/` in order) using the standard 3-way release/legacy fallback and prepared logfile path:

```bash
#!/bin/bash
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SELF_DIR}/../../common.sh" ]]; then
    # shellcheck source=../../common.sh
    source "${SELF_DIR}/../../common.sh"
elif [[ -f /opt/AetherFlow/current/packages/common.sh ]]; then
    source /opt/AetherFlow/current/packages/common.sh
else
    source /opt/AetherFlow/packages/common.sh
fi

export LOGFILE="${LOGFILE:-/var/log/aetherflow/install-<app_id>.log}"
af_prepare_logfile_path "$LOGFILE"
```

### Essential Helper Functions

| Function | Library | Purpose |
| :--- | :--- | :--- |
| `require_root` | `logging_archives.sh` | Exits immediately if not running as `root` (`UID 0`). |
| `af_prepare_logfile_path` / `af_logged` | `logging_archives.sh` | Prepares and flock-coordinates `$LOGFILE` appends with `deploy/log-retention.py`. |
| `report_progress <pct> "<msg>"` | `redaction_receipts.sh` | Emits `[PROGRESS:<pct>] <msg>` to update the UI progress bars, **Deployment Status** drawer, and `af` CLI in real time. |
| `print_info` / `print_error` | `logging_archives.sh` | Writes timestamped messages to stdout (`print_info`) or stderr (`print_error`) and appends via `log()` to `$LOGFILE` (`install-<app>.log`, `remove-<app>.log`, or `install.log`). |
| `af_github_curl` / `download_file` / `verify_download_sha256` | `logging_archives.sh` / `state_downloads.sh` | Authenticated HTTPS-only GitHub API calls (`logging_archives.sh`), hardened downloads, and fail-closed SHA-256/SHA-512 digest verification (`state_downloads.sh`). |
| `af_validate_tar_archive` / `af_extract_zip_archive` | `logging_archives.sh` | Rejects symlinks, hardlinks, absolute paths, and `..` traversal before archive extraction. |
| `stage_app_archive` / `finish_app_archive_update` / `prune_app_archive_backups` | `config_database.sh` | Stages replacement application trees with `${destination}.af-backup.XXXXXX` rollback copies on the destination filesystem and prunes older completed backups post-activation (`finish_app_archive_update`, `write_lock`, and `replace_app_tree`), keeping the newest 2 completed backups while skipping `.af-archive-pending`, foreign owners, and symlinks. |
| `begin_state_transaction` / `prepare_apt_package_transaction` | `state_downloads.sh` / `versions_apt.sh` | Opens private `/var/backups/aetherflow-recovery/af-state-*` state snapshots (`state_downloads.sh`) or APT rollback transactions (`versions_apt.sh`); both the `apt-get()` wrapper and `rollback_apt_packages()` automatically inject `-o DPkg::Lock::Timeout=<N>` (validated digits-only `DPKG_LOCK_TIMEOUT`, default `120`) unless already provided. |
| `queue_app_version` / `commit_app_versions` | `versions_apt.sh` | Persists `.af-version` receipts atomically after readiness verification (preventing unintended downgrades unless `AF_ALLOW_DOWNGRADE=1`). |
| `write_lock <app_id>` | `apache_dns_locks.sh` | Writes `/install/.<app_id>.lock` upon verified readiness and triggers `af-certbot-sync` for `<app_id>.<baseDomain>` TLS ingress. |
| `remove_lock <app_id>` | `apache_dns_locks.sh` | Removes `/install/.<app_id>.lock` and legacy `/etc/Swizzin/.<app_id>.lock`; writes `/install/.<app_id>.retained` on ordinary uninstall; calls `purge_app_backups` (`state_downloads.sh`) on `DELETE_DATA=true` (deleting `/var/backups/aetherflow-<app_id>*`). |
| `apache_app_enter_maintenance` / `backup_file_once` | `apache_dns_locks.sh` | Swaps a per-app HTTP `503` maintenance vhost and reloads `apache2` without stopping unrelated Apache apps; `backup_file_once` creates a one-time `.bak-af` copy via `cp -a` (without symlink or single-link enforcement; single-link regular-file validation lives in `config_database.sh`). |
| `write_config_file` / `set_config_value` / `safe_config_python` / `validate_config_paths` | `config_database.sh` | Private `0600` config writes under `umask 077`, single-link regular-file validation (`ManagedConfig.validate`, `st_nlink == 1`), safe config updates, and path validation. |
| `safe_rm_rf` / `purge_systemd_unit` / `purge_system_user` | `logging_archives.sh` / `systemd_credentials.sh` | Symlink-safe recursive removal refusing mountpoints (`logging_archives.sh`), unit cleanup, and `DELETE_DATA=true`-gated account removal (`systemd_credentials.sh`). |
| `wait_for_service_ready` | `systemd_credentials.sh` | Bounded HTTP/socket/systemd readiness verification before writing locks or receipts. |
| `ensure_node` / `node_build <cmd...>` | `redaction_receipts.sh` / `versions_apt.sh` | Ensures Node/native build prerequisites (`redaction_receipts.sh`) and runs npm/yarn builds in an isolated build environment (`versions_apt.sh`). |
| `af_write_failure_receipt` / `af_prepare_job_scratch` | `redaction_receipts.sh` | Records sanitized failure receipts and checks scratch disk/inode headroom before compilation. |

---

## Mandatory Engineering Standards

### 1. Idempotency & Safe In-Place Updates

Scripts must be safe to run repeatedly for both fresh installs and in-place updates (`POST /api/v1/admin/packages/:id/update`):

- Preserve existing user data, SQLite/PostgreSQL databases, and generated secrets across reinstalls/updates.
- Stage new builds before stopping the running service, create a rollback backup (using `stage_app_archive` -> `${destination}.af-backup.XXXXXX`, `begin_state_transaction` -> `/var/backups/aetherflow-recovery/af-state-*`, or custom-transaction backups under `/var/backups/aetherflow-<app>.*`), verify HTTP/systemd readiness before calling `write_lock`, and attempt automatic rollback if activation fails.
- Preserve the installed `.af-version` receipt when replacing an application tree. Archive and state transactions retain authoritative pre-operation receipts in `$AF_TX_DIR/pre_versions/`; only `AF_ALLOW_DOWNGRADE=1` permits an older candidate version.
- Custom tree-swap transactions must call `queue_app_version <receipt> <version> <staged-directory> <private-backup-directory>` before activation so the queued receipt is retained in staging and the transaction snapshot.
- Require independently supplied SHA-256 metadata for every downloaded archive, binary, or bootstrap script, including optional source/theme archives. Never synthesize a checksum sidecar from downloaded bytes; isolated test transports must supply fixture metadata.

### 2. Data Retention on Uninstall (`DELETE_DATA`)

Uninstalling an application (`removepackage-<app_id>`) must stop and remove the `systemd` unit and application binaries while **retaining** user databases and configuration by default. Only purge persistent data when `DELETE_DATA=true` is explicitly set.

**Nextcloud Purge Ownership**:

- **Ownership Provenance**: Nextcloud purge resolves the retained `config.php` before detaching Apache. Automatic MySQL/MariaDB deletion requires a matching installer-created, private ownership record in `/opt/AetherFlow/logs/nextcloud_database_owner.json`, written only when a new install creates a previously absent local database and account (existing accounts are never adopted or reset, and updates do not manufacture provenance).
- **Fail-Closed Retention**: Missing, stale, linked, or insecure ownership records, ambiguous configurations, unsupported SQL backends, and unproven external data directories fail closed with configuration, credentials, data, and installation marker retained; legacy or operator-managed SQL databases require manual operator cleanup after verifying backups.
- **SQLite & Default Uninstall**: Confined SQLite storage is removed without issuing MySQL commands, and default retained uninstall (`DELETE_DATA=false`) does not require an ownership record.

### 3. Systemd Unit & Sandbox Conventions

- Name managed units `af-<app_id>.service` (or register the exact unit name in `config/packages.json` and `af-runner` allowlists).
- Bind web listeners to `127.0.0.1:<allocated_port>` behind the AetherFlow Apache2 Subdomain Gateway rather than exposing unencrypted ports on `0.0.0.0`.
- Where supported, `AF_BIND_ADDRESS` explicitly overrides the loopback default; keep the allocated `AF_APP_PORT` unchanged. Retain existing application authentication and whitelist policies during updates.
- Create credential/configuration files privately before writing secret bytes: use `write_config_file <path> 0600` under `umask 077`, and maintain credential-log directories at `0700`. Pass secrets through environment variables or standard input, never external command arguments.
- Preserve existing secrets by default. `seed_servarr_master_user` and `seed_jellyfin_master_user` (`packages/lib/systemd_credentials.sh`) rotate an existing password only when `AF_KEEP_EXISTING_SECRETS` is not truthy (`1|true|yes|on`, case-insensitive) **and** either `AF_CONFIG_PASS` / `AF_PASS` is nonempty or `AF_FORCE_PASSWORD_ROTATION=1` (which falls back to `MASTER_PASS` when `AF_CONFIG_PASS`/`AF_PASS` are unset).
- SeedCross legacy migration reads effective settings through the application interpreter as the `seedcross` service user, preserving expression-backed secrets and host policies. Keep the evaluated snapshot inside the private rollback directory, never in command arguments or progress output, and abort with rollback if settings cannot be evaluated; do not silently generate a replacement identity.
- Fresh Vaultwarden instances bind to loopback, disable signups unless `AF_VAULTWARDEN_SIGNUPS_ALLOWED=true`, and generate an independent random admin token unless `AF_CONFIG_PASS` supplies one explicitly. Keep the environment and admin-token receipt at `0600`.

### 4. Catalog & Automation Registration

When adding a new package:

1. Add the package definition to `config/packages.json` and register automation in `config/package_automation.json` when required.
2. Place the brand icon in `frontend-rs/public/img/<app_id>.png` (PNG only; Marketplace and Services icon loaders unconditionally request `/img/<app_id>.png`).
3. Add syntax and lifecycle regression tests under `tests/` and verify with `python3 tests/check_shell_hygiene.py`.

### 5. Completion, Configuration & Recovery

- Treat installer exit, required application/Apache configuration synchronization, ingress persistence, service restoration, and the final lifecycle receipt as separate failure boundaries. A successful installer alone must not publish a `completed` operation.
- Propagate required configuration validation or mutation errors through the runner stream and the direct lifecycle coordinator. Reject unsafe application configuration paths instead of silently skipping them.
- Fail closed when authoritative ingress or port-reservation lookups fail; an unavailable reservation database is not an empty reservation set.
- Before restoring mutable state, stop its writers and verify they are inactive. Preserve private recovery backups if either quiescence or restoration fails.
- For completed Maintainerr/Seerr transactions, call `retain_successful_app_backups` only after readiness, receipt publication, and `write_lock` succeed. It retains the current and one preceding explicitly marked successful backup; it never prunes unmarked or unresolved recovery copies. Report retention failures without rolling back a committed installation.
- An incomplete rollback must leave affected pre-stopped units stopped. Inspect retained recovery artifacts and restore a consistent runtime, configuration, and database before retrying.

### 6. Retained Database Migrations

- For retained Nextcloud or Gitea installations, derive the database backend, name, endpoint, user, and database path from the application's retained configuration. Never substitute the fresh-install default database for an operator-configured database.
- Use `read_app_database_config`, `backup_configured_database`, and `restore_configured_database` for supported MySQL/MariaDB, PostgreSQL, and SQLite configurations. Refuse unsupported or unsafe retained configuration instead of initializing a replacement database.
- Back up the configured application database before running a schema migration and restore that same target on failed activation. Backup failure must abort migration; unrelated databases must remain outside the rollback scope.
- PostgreSQL recovery must support an application database owner without global `CREATEDB`: restore into the existing database in one transaction, remove migration-only objects, and roll back the recovery transaction on error. Do not drop and recreate the configured database or use role-wide cleanup that can revoke privileges on unrelated databases.
- Verify database identity, object ownership, and recoverable extension versions before publishing a usable backup. Preserve configured ownership, privileges, comments, settings, sequences, and large objects; reject unsupported recovery requirements before migration.
- Keep database credentials out of command arguments and progress output. Preserve restrictive permissions on database dumps and recovery directories.

---

## Validation Checklist

Before submitting or promoting a package:

- [ ] `bash -n packages/package/install/installpackage-<app_id>` and `removepackage-<app_id>` pass with zero warnings.
- [ ] `python3 tests/check_shell_hygiene.py` passes.
- [ ] Emits structured `report_progress` milestones (`0..100`) and writes `/install/.<app_id>.lock` only after service readiness passes.
- [ ] Preserves user data on update and default uninstall (`DELETE_DATA!=true`).
- [ ] Dedicated unit tests in `tests/test_*.py` verify install, update, retained uninstall, reinstall, explicit purge, and rollback failures using disposable paths and mocked host commands.
- [ ] Configuration or ingress failure cannot produce a completed lifecycle receipt, and incomplete rollback cannot restart affected services.
- [ ] Database-backed migration tests cover retained nondefault databases and backup/restore failure, without changing unrelated databases.
- [ ] Audit evidence identifies the exact source checksum and distinguishes mocked lifecycle coverage from real vendor builds, application health, and live-host certification. Never run a destructive lifecycle matrix on the development or production host.
