# Upgrading Guide

This guide covers the release channels, atomic upgrade pipeline (`af-release`, `aetherflow-self-update.service`, and `deploy/release-manager.sh`), and rollback procedures for **AetherFlow v4.0.0**.

## Upgrade Channels

AetherFlow supports two release channels managed from **Settings → System Updates** or via the unified `af` CLI (`sudo af release deploy --channel <channel>`):

| Channel | Source | Stability | Use Case |
| :--- | :--- | :--- | :--- |
| **Stable (`stable`)** | `master` / GitHub Releases | High | Production servers, SHA-256 verified Rust release bundles (`v4.0.0+`). |
| **Nightly (`nightly`)** | `nightly` / versioned GitHub pre-releases | Rolling | Rolling v4 Rust control plane updates, new Marketplace apps, and early validation (`v4.0.0-nightly.<run>.<attempt>`). |

The experimental release track is retired. Existing `experimental` channel settings and CLI arguments migrate to `nightly`; historical tags and releases remain available.

Changing the update channel in **Settings → System Updates** does not deploy an update automatically until you click **Install Update** or run `af release deploy`.

Nightly pre-releases use unique immutable tags such as `v4.0.0-nightly.85.1`, with the workflow run and attempt identifying the exact build and commit.

---

## Self-Update Architecture (`aetherflow-self-update.service`)

When triggered from the Web UI or CLI, the privileged runner (`aetherflow-runner.service`) starts the update inside an independent transient systemd unit (`aetherflow-self-update.service`) rather than running in-process:

1. **Caller-Restart Survival**: Because the updater runs in its own systemd unit, restarting `aetherflow-runner.service` and `aetherflow-api.service` during the release cutover never terminates the updater.
2. **Physical Binary Verification**: At startup, `aetherflow-api` captures its version from its physical executable path, and the release engine verifies both systemd units' actual running executable paths against the candidate release before marking the deployment complete.
3. **Restart-Surviving Status**: Progress, operation IDs, and recovery journals are exposed through `/api/v1/admin/system/update/status` and `sudo af release status`.

See [Self-Update Lifecycle](./self-update.md) and [Rust Release Engine (`af-release`)](./rust-release-engine.md) for full details.

---

## Upgrading from v3.2.x to v4.0.0

v4.0.0 replaces the legacy Go control plane (Zero-Go codebase) with the 11-crate **Rust (`Axum` + `Tokio`)** workspace (`backend-rs`) compiling `aetherflow-api`, the unified `af` (`af-cli`) binary, and the native Rust `speedtest-backend` (`af-librespeed`), paired with the 4-crate **Leptos Rust WebAssembly (`frontend-rs`)** dashboard shipped as external `web/dist` files. The updater switches the complete release together and preserves the existing HTTP/WebSocket API, `/run/aetherflow/runner.sock` socket, and SQLite data.

### Live SQLite Database Path Resolution
Both `af-release` and `deploy/release-manager.sh` resolve the live SQLite database in this exact 4-tier order:

1. `AF_DB_PATH`, when set in the deploy environment
2. `DB_PATH`, then `AETHERFLOW_DB_PATH`, parsed from `/etc/aetherflow/aetherflow.env` (never sourced as shell code)
3. `DB_PATH`, then `AETHERFLOW_DB_PATH`, from `systemctl show -p Environment aetherflow-api`
4. `/var/lib/aetherflow/aetherflow.sqlite`

Before the atomic `/opt/AetherFlow/current` symlink swap, the release engine takes a read-only online SQLite backup (`rusqlite::backup::Backup` / `sqlite3 --readonly .backup`) into `${RELEASE_DIR}/data-snapshot` (`0700`/`0600`) and verifies `PRAGMA integrity_check == "ok"` without checkpointing the live WAL.

### Running an Upgrade or Rollback via CLI

```bash
# Deploy the latest release on the stable or nightly channel
sudo af release deploy --local --channel stable
# (or via the shell release manager)
sudo /opt/AetherFlow/current/deploy/release-manager.sh deploy --channel stable

# Roll back to the previous known-good release
sudo af release rollback --local
```

If the post-swap `/health/ready` probe fails, the release manager restores `current` to the previous release.

### SQLite rollback behavior

Both release managers keep a live database that passes `PRAGMA integrity_check`. This preserves writes made after the pre-swap snapshot. If the database is missing or damaged, the release manager verifies the recovery snapshot and stops database writers before restoring it.

`/health/ready` checks SQLite access, core tables, and the privileged runner when enabled. Before rolling back across schema changes, confirm that the destination release can read the live schema. If the rollback requires an older schema, follow the staged restore procedure with a compatible backup. [Staged restore procedure](./RUNBOOK.md#backup--staged-restore-af-host)

---

## Building & Deploying from Source

To compile and package the API, CLI, LibreSpeed companion, and matching WASM dashboard locally:

```bash
# Install the pinned WASM build tools and add the printed tool directory to PATH.
bash scripts/install_wasm_build_tools.sh --ensure
# Build WASM, run the Rust workspace tests, and package the release.
bash scripts/build_gold.sh
```

Or step-by-step:

```bash
# Build and stage the external dashboard first.
bash scripts/build_wasm_frontend.sh --stage
# Build and package the native binaries with that staged dashboard.
BUILD_FRONTEND=0 bash scripts/build_gold.sh
```

---

## FAQ: Upgrading

**Q: Will my installed Marketplace apps be affected during an AetherFlow update?**  
**A:** No. AetherFlow updates only swap `/opt/AetherFlow/current` and restart `aetherflow-runner` and `aetherflow-api`. Your 77 Marketplace applications (Plex, Jellyfin, qBittorrent, Arr stack, etc.) run in independent `af-<app>.service` systemd units and continue running uninterrupted. For Jellyseerr / Seerr application upgrades and manual rollback steps, see [Jellyseerr / Seerr Upgrades](./seerr-upgrades.md).

**Q: Do I need to re-enroll 2FA or re-enter AI API keys after upgrading to v4.0.0?**  
**A:** TOTP secrets, user accounts, and `AES-256-GCM` encrypted credentials in SQLite are 100% compatible between v3.2.x and v4.0.0 as long as `AES_MASTER_KEY` and `JWT_SECRET` in `/etc/aetherflow/aetherflow.env` remain unchanged. Note: if 2FA was enrolled on an early v3 build that stored legacy unsalted 64-hex SHA-256 recovery code hashes, v4.0.0 rejects unsalted recovery hashes fail-closed (only salted `sha256:v1:<salt>:<hash>` and legacy `$2*` bcrypt hashes are accepted); after signing in with your TOTP authenticator app, regenerate fresh salted `sha256:v1:` recovery codes via **Settings → Security → Regenerate Recovery Codes** (`POST /api/v1/auth/user/2fa/recovery/regenerate`).

**Q: What happens to existing LibreSpeed BoltDB databases (`speedtest.db`) and result share links on upgrade?**

**A:** When `speedtest-backend` (`af-librespeed`) starts against a pre-v4 BoltDB file at `/opt/librespeed/speedtest.db` (or discovers an un-imported `.bolt.bak` / `speedtest.bolt` archive in the database directory), it atomically renames any active BoltDB file aside with `0600` owner-only permissions, initializes a WAL-mode SQLite telemetry database (`0600`), and imports legacy BoltDB telemetry rows transactionally into SQLite (`telemetry_bolt_migrations` tracks completed imports so interrupted startups resume cleanly on next boot). On upgrade, `installpackage-librespeed` enables `enable_id_obfuscation=true` when omitted (preserving any explicit `enable_id_obfuscation=false`), while `telemetry_legacy_raw_ids` preserves every pre-upgrade BoltDB, pre-obfuscation SQLite, and unobfuscated share ID so historical `/results?id=<id>` links keep resolving even as all new post-upgrade results require obfuscated tokens. If `settings.toml` previously pointed to an external SQLite/BoltDB file under `/var/lib/librespeed/` or `/srv/librespeed/`, `installpackage-librespeed` validates and migrates that configured database into `/opt/librespeed/speedtest.db` (archiving any stale local `/opt/librespeed/speedtest.db` to `speedtest.db.pre-migrate.<ts>.bak`).
