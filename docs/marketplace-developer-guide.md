# Marketplace Developer Guide

This guide details the conventions and technical requirements for adding new bare-metal applications to the **AetherMarketplace** (currently **77 native Linux packages**).

## Package Execution Architecture (`af-runner`)

In AetherFlow v4.0.0, all Marketplace lifecycle operations (`install`, `update`, `remove`) are executed by `aetherflow-runner.service` (`backend-rs/crates/af-runner`) under a process-wide mutex and cross-process advisory file lock (`/install/.af-package-executor.flock`):

1. **Declarative Rust Recipes (`backend-rs/crates/af-runner/src/package_executor.rs`)**:
   - 15 packages (`fail2ban`, `quassel`, `threadfin`, `znc`, `xrdp`, `novnc`, `x2go`, `scrutiny`, `prometheus`, `netdata`, `mergerfs`, `rclone`, `clamav`, `mosquitto`, `syncthing`) have native declarative Rust recipes (`DeclarativePackageRecipe`) with `lstat` ancestor-symlink validation, pre-start systemd sandboxing, and `RollbackJournal`. See [Rust Package Executor](./rust-package-executor.md).
2. **Idempotent Bash Lifecycle Scripts (`packages/package/`)**:
   - Complex multi-component builds (such as `jellyfin`, `plex`, `palate`, `maintainerr`, `dispatcharr`, `mcvnc`, `invidious`, `piped`, and the `*Arr` stack) use structured Bash scripts under `packages/package/{install,remove,update}/` that source `packages/common.sh`.

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

### 2. Data Retention on Uninstall (`DELETE_DATA`)
Uninstalling an application (`removepackage-<app_id>`) must stop and remove the `systemd` unit and application binaries while **retaining** user databases and configuration by default. Only purge persistent data when `DELETE_DATA=true` is explicitly set.

### 3. Systemd Unit & Sandbox Conventions
- Name managed units `af-<app_id>.service` (or register the exact unit name in `backend/config/packages.json` and `af-runner` allowlists).
- Bind web listeners to `127.0.0.1:<allocated_port>` behind the AetherFlow Apache2 Subdomain Gateway rather than exposing unencrypted ports on `0.0.0.0`.

### 4. Catalog & Automation Registration
When adding a new package:
1. Add the package definition to `backend/config/packages.json` (and `backend/config/package_automation.json` if it uses Zero-Touch configuration or Subdomain Gateway wiring).
2. Place the brand icon in `frontend/public/img/<app_id>.png` (or `.svg`).
3. Add syntax and lifecycle regression tests under `tests/` and verify with `python3 tests/check_shell_hygiene.py`.

---

## Validation Checklist

Before submitting or promoting a package:
- [ ] `bash -n packages/package/install/installpackage-<app>` and `removepackage-<app>` pass with zero warnings.
- [ ] `python3 tests/check_shell_hygiene.py` passes.
- [ ] Emits structured `report_progress` milestones (`0..100`) and writes `/install/.<app>.lock` only after service readiness passes.
- [ ] Preserves user data on update and default uninstall (`DELETE_DATA!=true`).
- [ ] Dedicated unit test in `tests/test_*.py` verifies install, update rollback, and remove paths.
