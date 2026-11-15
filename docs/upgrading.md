# Upgrading Guide

This guide covers the release channels, atomic upgrade pipeline (`af-release`, `aetherflow-self-update.service`, and `deploy/release-manager.sh`), and rollback procedures for **AetherFlow v4.0.0**.

## Upgrade Channels

AetherFlow supports three release channels managed from **Settings → System Updates** or via the unified `af` CLI (`sudo af release deploy --channel <channel>`):

| Channel | Source | Stability | Use Case |
| :--- | :--- | :--- | :--- |
| **Stable (`stable`)** | `master` / GitHub Releases | High | Production servers, SHA-256 verified single-binary Rust release bundles (`v4.0.0+`). |
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

v4.0.0 replaces the legacy Go control plane (Zero-Go codebase) with the 12-crate **Rust (`Axum` + `Tokio`)** workspace compiling `aetherflow-api`, the unified `af` (`af-cli`) binary, and the native Rust `speedtest-backend` (`af-librespeed`). The embedded Next.js 16 (Obsidian V2) frontend, HTTP/WebSocket API contract, `/run/aetherflow/runner.sock` socket, SQLite database schema, and installed `aetherflow-api` / `aetherflow-runner` systemd units transition in-place without data loss.

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
sudo bash /opt/AetherFlow/deploy/release-manager.sh deploy --channel stable

# Roll back to the previous known-good release
sudo af release rollback --local
```

If the post-swap `/health/ready` readiness probe fails, `current` automatically reverts to `.previous_release`. If the live database fails `PRAGMA integrity_check`, the verified pre-swap backup is atomically restored after stopping database services.

---

## Building & Deploying from Source

To compile and package the v4.0.0 single-binary Rust release bundle locally:

```bash
# Build Next.js 16 static export, run Zero-Go Rust workspace tests, and package aetherflow-api + af + speedtest-backend
bash scripts/build_gold.sh
```

Or step-by-step:

```bash
# 1. Build Frontend Static Export
npm ci
cd frontend && NEXT_STATIC_EXPORT=1 npm run build && cd ..
rm -rf web/dist && mkdir -p web/dist
cp -R frontend/out/. web/dist/

# 2. Build Pure-Rust Control Plane, Admin CLI & Native LibreSpeed Backend
cd backend-rs
cargo build --release --locked --bin aetherflow-api --bin af --bin speedtest-backend
```

---

## FAQ: Upgrading

**Q: Will my installed Marketplace apps be affected during an AetherFlow update?**  
**A:** No. AetherFlow updates only swap `/opt/AetherFlow/current` and restart `aetherflow-runner` and `aetherflow-api`. Your 77 Marketplace applications (Plex, Jellyfin, qBittorrent, Arr stack, etc.) run in independent `af-<app>.service` systemd units and continue running uninterrupted.

**Q: Do I need to re-enroll 2FA or re-enter AI API keys after upgrading to v4.0.0?**  
**A:** TOTP secrets, user accounts, and `AES-256-GCM` encrypted credentials in SQLite are 100% compatible between v3.2.x and v4.0.0 as long as `AES_MASTER_KEY` and `JWT_SECRET` in `/etc/aetherflow/aetherflow.env` remain unchanged. Note: if 2FA was enrolled on an early v3 build that stored legacy unsalted 64-hex SHA-256 recovery code hashes, v4.0.0 rejects unsalted recovery hashes fail-closed (`argon2id` required); after signing in with your TOTP authenticator app, regenerate fresh `Argon2id` recovery codes via **Settings → Security → Regenerate Recovery Codes** (`POST /api/v1/auth/user/2fa/recovery/regenerate`).

**Q: What happens to existing LibreSpeed BoltDB databases (`speedtest.db`) on upgrade?**  
**A:** When `speedtest-backend` (`af-librespeed`) starts against a pre-v4 BoltDB file at `/opt/librespeed/speedtest.db`, it atomically renames the legacy BoltDB file to `/opt/librespeed/speedtest.db.bolt.bak` with `0600` owner-only permissions and initializes a WAL-mode SQLite telemetry database (`0600`) at `/opt/librespeed/speedtest.db`.
