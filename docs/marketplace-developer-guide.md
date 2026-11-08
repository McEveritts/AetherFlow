# Marketplace Developer Guide

This guide details the conventions and technical requirements for adding new bare-metal applications to the **AetherMarketplace** (currently **77 native Linux packages**).

## Package Execution Architecture (`af-runner`)

In AetherFlow v4.0.0, Marketplace installation, update, reinstall, and removal (runner action `remove`) execute through `aetherflow-runner.service` (`backend-rs/crates/af-runner`) with lifecycle ownership and admission checks. Script execution also uses a process-wide mutex and cross-process advisory file lock (`/install/.af-package-executor.flock`):

1. **Declarative Rust Recipes (`backend-rs/crates/af-runner/src/package_executor.rs`)**:
   - 12 packages (`fail2ban`, `quassel`, `threadfin`, `znc`, `xrdp`, `novnc`, `x2go`, `prometheus`, `netdata`, `mergerfs`, `rclone`, `syncthing`) have native declarative Rust recipes (`DeclarativePackageRecipe`) with `lstat` ancestor-symlink validation, pre-start systemd sandboxing, and `RollbackJournal`. See [Rust Package Executor](./rust-package-executor.md).
2. **Idempotent Bash Lifecycle Scripts (`packages/package/`)**:
   - Complex multi-component builds (such as `jellyfin`, `plex`, `palate`, `maintainerr`, `dispatcharr`, `mcvnc`, `invidious`, `piped`, and the `*Arr` stack) use structured Bash scripts under `packages/package/{install,remove}/` that source `packages/common.sh`. Installers also handle update and reinstall actions.

```bash
packages/
├── common.sh                             # Core helper library (Mandatory for Bash scripts)
├── youtube-common.sh                     # Shared helper for Piped & Invidious
└── package/
    ├── install/
    │   └── installpackage-<app_id>       # Installation & in-place update entry point
    └── remove/
        └── removepackage-<app_id>        # Uninstallation entry point
```

---

## The `common.sh` Library

Every Bash marketplace script **must** source `packages/common.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../../common.sh"
```

### Essential Helper Functions

| Function | Purpose |
| :--- | :--- |
| `require_root` | Exits immediately if not running as `root` (`UID 0`). |
| `report_progress <pct> "<msg>"` | Emits `[PROGRESS:<pct>] <msg>` to update the circular progress ring in the UI and `af` CLI in real time. |
| `print_info` / `print_error` | Logs timestamped diagnostic messages to `/var/log/aetherflow/install-<app>.log`. |
| `write_lock <app_id>` | Writes `/install/.<app_id>.lock` upon verified readiness and triggers `af-certbot-sync` for automatic `<app>.<baseDomain>` TLS ingress. |
| `remove_lock <app_id>` | Removes `/install/.<app_id>.lock` during uninstallation. |
| `backup_file_once <path>` | Creates a `.bak-af` backup before mutating a host file. |
| `node_build <cmd...>` | Executes Node.js/npm/yarn builds in a clean environment without polluting service runtime paths. |

---

## Mandatory Engineering Standards

### 1. Idempotency & Safe In-Place Updates
Scripts must be safe to run repeatedly for both fresh installs and in-place updates (`POST /api/v1/admin/packages/:id/update`):
- Preserve existing user data, SQLite/PostgreSQL databases, and generated secrets across reinstalls/updates.
- Stage new builds before stopping the running service, back up the prior installation to `/var/backups/aetherflow-<app>.*`, verify HTTP/systemd readiness before calling `write_lock`, and roll back automatically if activation fails.
- Preserve the installed `.af-version` receipt when replacing an application tree. Archive and state transactions retain authoritative pre-operation receipts in `$AF_TX_DIR/pre_versions/`; only `AF_ALLOW_DOWNGRADE=1` permits an older candidate version.
- Custom tree-swap transactions must call `queue_app_version <receipt> <version> <staged-directory> <private-backup-directory>` before activation so the queued receipt is also retained in staging and the transaction snapshot.
- Require independently supplied SHA-256 metadata for every downloaded archive, binary, or bootstrap script, including optional source/theme archives. Never synthesize a checksum sidecar from downloaded bytes to satisfy verification; isolated test transports must provide their own vendor-fixture metadata.

### 2. Data Retention on Uninstall (`DELETE_DATA`)
Uninstalling an application (`removepackage-<app_id>`) must stop and remove the `systemd` unit and application binaries while **retaining** user databases and configuration by default. Only purge persistent data when `DELETE_DATA=true` is explicitly set.

Nextcloud purge resolves the retained `config.php` before detaching Apache. Automatic SQL deletion requires a matching installer-created, private database-ownership record in `/opt/AetherFlow/logs/nextcloud_database_owner.json`. New installations record ownership only after creating a previously absent local MySQL database and account; existing accounts are never adopted or reset. Missing, stale, linked, or insecure records, ambiguous configurations, unsupported SQL backends, and unproven external data directories fail closed with configuration, credentials, data, and installation marker retained. Legacy or operator-managed SQL databases require explicit operator cleanup after verifying backups and ownership; updates do not manufacture provenance. Confined SQLite storage is removed without issuing MySQL commands. Default retained uninstall does not require a database-ownership record.

### 3. Systemd Unit & Sandbox Conventions
- Name managed units `af-<app_id>.service` (or register the exact unit name in `backend/config/packages.json` and `af-runner` allowlists).
- Bind web listeners to `127.0.0.1:<allocated_port>` behind the AetherFlow Apache2 Subdomain Gateway rather than exposing unencrypted ports on `0.0.0.0`.
- Where supported, `AF_BIND_ADDRESS` explicitly overrides the loopback default; keep the allocated `AF_APP_PORT` unchanged. Retain existing application authentication and whitelist policies during updates.
- Create credential/configuration files privately before writing any secret bytes: use `write_config_file <path> 0600` under `umask 077`, and maintain credential-log directories at `0700`. Pass secrets to configuration helpers through the environment or standard input, never external command arguments.
- Preserve existing secrets by default. Rotate an existing password only when `AF_CONFIG_PASS` is nonempty and `AF_KEEP_EXISTING_SECRETS!=1`, and use that explicit password rather than `MASTER_PASS`.
- SeedCross legacy migration reads effective settings through the application interpreter as the `seedcross` service user, preserving expression-backed secrets and host policies. Keep the evaluated snapshot inside the private rollback directory, never in command arguments or progress output, and abort with rollback if settings cannot be evaluated; do not silently generate a replacement identity.
- Fresh Vaultwarden instances bind to loopback, disable signups unless `AF_VAULTWARDEN_SIGNUPS_ALLOWED=true`, and generate an independent random admin token unless `AF_CONFIG_PASS` supplies one explicitly. Keep the environment and admin-token receipt at `0600`.

### 4. Catalog & Automation Registration
When adding a new package:
1. Add the package definition to both `config/packages.json` and `backend/config/packages.json`, keeping the copies identical. Register automation in both `config/package_automation.json` and `backend/config/package_automation.json` when required.
2. Place the brand icon in `frontend/public/img/<app_id>.png` (or `.svg`).
3. Add syntax and lifecycle regression tests under `tests/` and verify with `python3 tests/check_shell_hygiene.py`.

### 5. Completion, Configuration & Recovery
- Treat installer exit, required application/Apache configuration synchronization, ingress persistence, service restoration, and the final lifecycle receipt as separate failure boundaries. A successful installer alone must not publish a `completed` operation.
- Propagate required configuration validation or mutation errors through the runner stream and the direct lifecycle coordinator. Reject unsafe application configuration paths instead of silently skipping them.
- Fail closed when authoritative ingress or port-reservation lookups fail; an unavailable reservation database is not an empty reservation set.
- Before restoring mutable state, stop its writers and verify they are inactive. Preserve private recovery backups if either quiescence or restoration fails.
- For completed Maintainerr/Seerr transactions, call `retain_successful_app_backups` only after readiness, receipt publication, and `write_lock` succeed. It retains the current and one preceding explicitly marked successful backup; it never prunes unmarked or unresolved recovery copies. Report retention failures without rolling a committed installation back.
- An incomplete rollback must leave affected pre-stopped units stopped. Do not restart them merely because the installer process exited; inspect the retained recovery artifacts and restore a consistent runtime, configuration, and database before retrying.

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
- [ ] `bash -n packages/package/install/installpackage-<app>` and `removepackage-<app>` pass with zero warnings.
- [ ] `python3 tests/check_shell_hygiene.py` passes.
- [ ] Emits structured `report_progress` milestones (`0..100`) and writes `/install/.<app>.lock` only after service readiness passes.
- [ ] Preserves user data on update and default uninstall (`DELETE_DATA!=true`).
- [ ] Dedicated unit tests in `tests/test_*.py` verify install, update, retained uninstall, reinstall, explicit purge, and rollback failures using disposable paths and mocked host commands.
- [ ] Configuration or ingress failure cannot produce a completed lifecycle receipt, and incomplete rollback cannot restart affected services.
- [ ] Database-backed migration tests cover retained nondefault databases and backup/restore failure, without changing unrelated databases.
- [ ] Audit evidence identifies the exact source checksum and distinguishes mocked lifecycle coverage from real vendor builds, application health, and live-host certification. Never run a destructive lifecycle matrix on the development or production host.
