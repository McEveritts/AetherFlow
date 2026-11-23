# Upgrading Guide

This guide covers the release channels, atomic upgrade pipeline (`af-release`, transient `aetherflow-self-update-<command>-<channel>-<8hex>.service` units, and `deploy/release-manager.sh`), and rollback procedures for **AetherFlow v4.0.0**.

## Upgrade Channels

AetherFlow supports two release channels managed from **Settings → System Updates** or via the unified `af` CLI (`sudo af release deploy --channel <channel>`):

| Channel | Source | Stability | Use Case |
| :--- | :--- | :--- | :--- |
| **Stable (`stable`)** | `master` / GitHub Releases | High | Production servers; SHA-256 and Sigstore/SLSA v1 provenance-verified Rust release bundles (`v4.0.0+`). |
| **Nightly (`nightly`)** | `nightly` / versioned GitHub pre-releases | Rolling | Rolling v4 Rust control plane updates, new Marketplace apps, and early validation (`v4.0.0-nightly.<run>.<attempt>`). |

The experimental release track is retired. Existing `experimental` channel settings and CLI arguments alias to `nightly`; historical tags and releases remain available.

Changing the update channel in **Settings → System Updates** does not deploy an update automatically until you click **Install Update** or run `af release deploy`.

Nightly pre-releases use unique immutable tags such as `v4.0.0-nightly.85.1`, with the workflow run and attempt identifying the exact build and commit.

---

## Self-Update Architecture (`aetherflow-self-update-<command>-<channel>-<8hex>.service`)

When triggered from the Web UI or via runner-mediated CLI (`sudo af release deploy --channel <channel>`), `aetherflow-runner.service` launches each update inside a unique per-launch transient systemd unit (`aetherflow-self-update-<command>-<channel>-<8hex>.service` via `systemd-run --collect`) rather than running in-process:

1. **Caller-Restart Survival**: Because the updater runs in its own systemd unit, restarting `aetherflow-runner.service` and `aetherflow-api.service` during the release cutover never terminates the updater.
2. **Physical Binary Verification**: At startup, `aetherflow-api` captures its version from its physical executable path, and the release engine verifies both systemd units' actual running executable paths (`/proc/<pid>/exe`) against the candidate release before marking the deployment complete.
3. **Restart-Surviving Status**: Durable job receipts (`<data_dir>/.self-update-jobs/<unit>.json`) and recovery state are exposed on `GET /api/v1/auth/system/update/status` and `GET /api/v1/admin/system/update/status` (returning `state`, `action`, `operationId`, `job_unit`, `active_job_unit`, `status`, `completed`, `success`, `error`, and `exit_code`; interrupted post-swap journals surface as `state: "interrupted"`, `status: "recovery_required"`) as well as `sudo af release status`.

See [Self-Update Lifecycle](./self-update.md) and [Rust Release Engine (`af-release`)](./rust-release-engine.md) for full details.

---

## Upgrading from v3.2.x to v4.0.0

v4.0.0 replaces the legacy Go control plane with the 11-crate **Rust (`Axum` + `Tokio`)** workspace (`backend-rs`) compiling `aetherflow-api`, the unified `af` (`bin/af`) CLI binary, and the native Rust `speedtest-backend` (`bin/speedtest-backend`), paired with the 4-crate **Leptos Rust WebAssembly (`frontend-rs`)** dashboard shipped as external `web/dist` files. The updater switches the complete release together and preserves the existing HTTP/WebSocket API, `/run/aetherflow/runner.sock` socket, and SQLite data.

### Live SQLite Database Path Resolution

Ensure `python3` and `openssl` are installed on the host before upgrading (required for Sigstore/SLSA provenance checks and release scripts). Both `af-release` and `deploy/release-manager.sh` resolve the live SQLite database in 4 tiers:

1. Deploy process environment / conf (`AF_DB_PATH`, `DB_PATH`, `AETHERFLOW_DB_PATH` — conflicting non-empty values always fail closed)
2. `/etc/aetherflow/aetherflow.env` (parsed safely, never sourced as shell code; fails closed on cross-key conflicts in isolated-root `--root <dir>` tests, while production hosts select the first non-empty key in `AF_DB_PATH` > `DB_PATH` > `AETHERFLOW_DB_PATH` order)
3. `systemctl show -p Environment aetherflow-api` (no cross-key conflict check)
4. Default fallback: `/var/lib/aetherflow/aetherflow.sqlite`

Before the atomic `/opt/AetherFlow/current` symlink swap, the release engine verifies `SHA256SUMS` and Sigstore + SLSA v1 build provenance (`verify_release_provenance`), captures a read-only online SQLite backup (`rusqlite::backup::Backup` / `sqlite3 --readonly .backup`) into `${RELEASE_DIR}/data-snapshot` (`0700`/`0600`), and verifies `PRAGMA integrity_check == "ok"` without checkpointing the live WAL.

- **Runner Environment Non-Forwarding (`sudo env` Required for Overrides)**: `af-runner` does not forward `AETHERFLOW_SKIP_PROVENANCE_VERIFY=1` or GitHub tokens (`AF_GITHUB_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`) into transient self-update units. Both are honored only in the process environment of direct `--local` CLI runs or direct `deploy/release-manager.sh` invocations — pass them with `sudo env <VAR>=<VALUE> af release ... --local` (Debian/Ubuntu `sudo` strips shell-exported variables via `Defaults env_reset`).

- **Upgrade Compatibility Notes (Ingress & Host Validation)**:
  - **IP-Only Hosts**: Because `host_validation_middleware` now implicitly trusts only canonical loopback IPs (`127.0.0.0/8`, `::1`), ensure your host's LAN/public IP is listed in `ALLOWED_HOSTS` inside `/etc/aetherflow/aetherflow.env` before upgrading if you access the dashboard directly by IP.
  - **`.aether.local` & ruTorrent**: All 10 gateway-protected apps (including `rutorrent`) now require administrator authentication on `*.aether.local` by default (TOTP admins launch them seamlessly from `aetherflow.aether.local` via `aetherflow_local_app`); single-owner LAN hosts wanting passwordless RFC 1918/ULA access can set `AF_ALLOW_UNAUTH_LOCAL_LAN=1`. Updating the `rutorrent` package (`sudo af package update rutorrent`) automatically migrates legacy loopback `rutorrent.conf` Basic Auth to the internal proxy secret (`/etc/aetherflow/rutorrent-proxy-token.conf`) so external gateway SSO works without a `401` loop.

### Running an Upgrade or Rollback via CLI

On legacy **v3.2.x** hosts that do not yet have the Rust `af` CLI binary installed, trigger the initial jump to v4.0.0 from the Web UI (**Settings → System Updates**) or via `deploy/release-manager.sh` below. On **v4.0.0+** hosts, omitting `--local` dispatches through `aetherflow-runner.service`'s isolated transient systemd unit (`/v1/self-update`), while `--local` runs `af-release` directly in the invoking root shell (recommended for standalone recovery):

```bash
# v3.2.x initial jump (or shell release-manager escape hatch on v4.0.0+)
sudo /opt/AetherFlow/current/deploy/release-manager.sh deploy --channel stable

# v4.0.0+: deploy latest release directly in the invoking root shell
sudo af release deploy --local --channel stable

# v4.0.0+: dispatch through the isolated runner transient unit
sudo af release deploy --channel stable

# Roll back to the previous known-good release (--channel is optional on rollback)
sudo af release rollback --local
```

If the post-swap `/health/ready` probe fails, the release engine restores `current` to `.previous_release`.

### SQLite Rollback Behavior

Both release engines keep a live database that passes `PRAGMA integrity_check`. This preserves writes made after the pre-swap snapshot. If the database is missing or damaged, the release engine verifies the recovery snapshot and stops database writers before restoring it.

`/health/ready` verifies SQLite connectivity (`SELECT 1 FROM users LIMIT 1`) and the privileged runner socket (`/v1/health`) when `PRIVILEGED_RUNNER_ENABLED=true` (broader multi-table health checks run on `/health`). Before rolling back across schema changes, confirm that the destination release can read the live schema. If the rollback requires an older schema, follow the [Staged Restore Procedure](./RUNBOOK.md#backup--staged-restore-af-host) with a compatible backup.

---

## Building & Deploying from Source

To compile and package `aetherflow-api`, `bin/af`, `bin/speedtest-backend`, external `web/dist`, and `SHA256SUMS` locally into `dist/gold/<version>/` (see [Testing & Verification — Prerequisites](./testing.md#prerequisites) for required Rust/system toolchains; the build scripts locate tools installed by `install_wasm_build_tools.sh --ensure` automatically with no manual `PATH` change unless invoking `trunk` directly):

```bash
# Ensure pinned WASM build tools are installed
bash scripts/install_wasm_build_tools.sh --ensure
# Build WASM, run the Rust workspace tests, and package into dist/gold/<version>/
bash scripts/build_gold.sh
```

Or step-by-step:

```bash
# 1. Build and stage the external dashboard into web/dist/
bash scripts/build_wasm_frontend.sh --stage
# 2. Build and package the native binaries with that staged dashboard
BUILD_FRONTEND=0 bash scripts/build_gold.sh
```

To deploy a custom or source-built release onto a target host (`af release deploy --local` pulls from GitHub Releases and does not accept a local tarball path):

- **From remote Git on a host with Rust & WASM toolchains**: run `sudo /opt/AetherFlow/current/deploy/release-manager.sh deploy --from-source --channel <stable|nightly>` (runs `git fetch` and checks out the selected channel branch inside `REPO_DIR`, defaulting to `/opt/AetherFlow`, then compiles Rust + WASM locally; it does not deploy uncommitted local edits).
- **From a locally packaged `dist/gold/<version>/` tarball**: pass `AETHERFLOW_PREBUILT_TARBALL` and `AETHERFLOW_PREBUILT_SHA256_FILE` via `sudo env` into `setup/AetherFlow-Setup --repair build_modern` on an **existing deployed host** (preserving saved `/etc/aetherflow/aetherflow.env` and SQLite state; omit `--repair build_modern` on a **fresh host**):

```bash
sudo env AETHERFLOW_PREBUILT_TARBALL=/path/to/aetherflow-linux-amd64.tar.gz \
  AETHERFLOW_PREBUILT_SHA256_FILE=/path/to/SHA256SUMS \
  bash /opt/AetherFlow/setup/AetherFlow-Setup --repair build_modern
```

---

## FAQ: Upgrading

**Q: Will my installed Marketplace apps be affected during an AetherFlow update?**  
**A:** Installed application daemons continue running during an AetherFlow update. Updates only swap `/opt/AetherFlow/current` and restart `aetherflow-runner.service` and `aetherflow-api.service`; Marketplace apps run in their own `systemd` units (mostly upstream names such as `plexmediaserver`, `jellyfin`, `qbittorrent`, `sonarr`, `radarr`, or select `af-<app>.service` units) or under shared `apache2`. Applications accessed through the AetherFlow Subdomain Gateway experience a brief reverse-proxy interruption while `aetherflow-api.service` restarts. For Jellyseerr / Seerr application upgrades and manual rollback steps, see [Jellyseerr / Seerr Upgrades](./seerr-upgrades.md).

**Q: Do I need to re-enroll 2FA or re-enter AI API keys after upgrading to v4.0.0?**  
**A:** TOTP secrets, user accounts, and `AES-256-GCM` encrypted credentials in SQLite are preserved across upgrades from v3.2.x to v4.0.0 as long as `AES_MASTER_KEY` and `JWT_SECRET` in `/etc/aetherflow/aetherflow.env` remain unchanged, with one security exception: if 2FA was enrolled on an early v3 build that stored legacy unsalted 64-hex SHA-256 recovery code hashes, v4.0.0 rejects those unsalted hashes fail-closed (only `$2b$`/`$2*` bcrypt hashes and legacy salted `sha256:v1:<salt>:<hash>` hashes are accepted). After signing in with your TOTP authenticator app, regenerate fresh bcrypt-hashed (`$2b$...`) recovery codes via **Settings → Security → Regenerate Recovery Codes** (`POST /api/v1/auth/user/2fa/recovery/regenerate`).

**Q: What happens to existing LibreSpeed BoltDB databases (`speedtest.db`) and result share links on upgrade?**  
**A:** LibreSpeed upgrades are triggered when you update the `librespeed` Marketplace package (`sudo af package update librespeed`, which runs `packages/package/install/installpackage-librespeed`), not automatically during a platform update:

- **BoltDB-to-SQLite Auto-Migration**: When `speedtest-backend` (`af-librespeed`) starts against a pre-v4 BoltDB `/opt/librespeed/speedtest.db` (or an un-imported `.bolt.bak` / `speedtest.bolt` archive), it atomically renames the active BoltDB file aside (`0600`), initializes a WAL-mode SQLite telemetry database (`0600`), and transactionally imports legacy rows (`telemetry_bolt_migrations` tracks completed imports so interrupted startups recover on next boot).
- **Local Binary Preference, Provenance & Obfuscated Share IDs**: `installpackage-librespeed` prefers a trusted, root-owned, non-group/world-writable local `speedtest-backend` binary first (`AF_SPEEDTEST_BACKEND_BIN`, `/opt/AetherFlow/current/bin/speedtest-backend`, `/opt/AetherFlow/current/speedtest-backend`, or `/usr/local/lib/aetherflow/speedtest-backend`), falling back to downloading the matching GitHub Release archive with Sigstore SLSA provenance verification by default when no matching local binary is present. It migrates `idObfuscation_salt.bin` and enables `enable_id_obfuscation=true` when omitted (preserving explicit `enable_id_obfuscation=false`). Historical `/results?id=<id>` links remain resolvable via `telemetry_legacy_raw_ids` while new results require obfuscated tokens.
- **External Path Migration**: If `settings.toml` previously pointed to an external SQLite/BoltDB file under `/var/lib/librespeed/`, `/srv/librespeed/`, `/var/opt/librespeed/`, `/opt/librespeed-*`, `/opt/librespeed_*`, or `/opt/librespeed.*`, `installpackage-librespeed` validates and migrates it into `/opt/librespeed/speedtest.db` (archiving any stale local file to `speedtest.db.pre-migrate.<ts>.bak`).
