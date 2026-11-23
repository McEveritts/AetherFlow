# AetherFlow Operational Runbook

> **Version**: v4.0.0 · **Control Plane**: 11-Crate Rust Workspace (`backend-rs`) + 4-Crate Leptos WASM Frontend (`frontend-rs`)  
> **Audience**: System administrators and operators managing AetherFlow bare-metal deployments.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Startup & Systemd Units](#startup--systemd-units)
3. [Health & Readiness Checks](#health--readiness-checks)
4. [Unified Admin CLI (`af`)](#unified-admin-cli-af)
5. [Service Recovery (`af-heal`)](#service-recovery-af-heal)
6. [Authentication & Sessions](#authentication--sessions)
7. [OIDC Provider](#oidc-provider)
8. [Backup & Staged Restore (`af-host`)](#backup--staged-restore-af-host)
9. [Self-Update & Release Operations (`af-release`)](#self-update--release-operations-af-release)
10. [Database Maintenance](#database-maintenance)
11. [Notification Channels](#notification-channels)
12. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```text
┌──────────────────────────────────────────────────────────────────────┐
│                         AetherFlow v4.0.0                            │
│                                                                      │
│   [Operator Browser] ──HTTPS/WSS──> [Apache2 TLS & Subdomain Vhosts] │
│                                              │                       │
│                                       127.0.0.1:8080                 │
│                                              ▼                       │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ aetherflow-api.service (Unprivileged Rust Control Plane)       │  │
│  │  • af-api (Axum HTTP/WS, McBrowser, Plugins, External web/dist)│  │
│  │  • af-files (openat2 Scoped Filesystem Confinement)            │  │
│  │  • af-hardware (Zero-Fork sysinfo + NVML GPU FFI)              │  │
│  │  • af-services (77-App Catalog, Mutators, Workers, Cluster)    │  │
│  └──────────────────┬─────────────────────────────┬───────────────┘  │
│                     │                             │                  │
│                     ▼                             ▼                  │
│  ┌────────────────────────────────┐  ┌────────────────────────────┐  │
│  │ /var/lib/aetherflow/           │  │ /run/aetherflow/runner.sock│  │
│  │  • aetherflow.sqlite (WAL)     │  │ aetherflow-runner.service  │  │
│  │  • mcbrowser/user-<id> (0700)  │  │  • systemctl allowlists    │  │
│  │  • AES-256-GCM secrets         │  │  • Bash + 9 opt-in Rust    │  │
│  └────────────────────────────────┘  │  • WireGuard / Tailscale   │  │
│                                      │  • Transient Self-Updater  │  │
│                                      └────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

| Component | Binding / Path | Purpose |
| :--- | :--- | :--- |
| `aetherflow-api.service` | `127.0.0.1:8080` (Setup) / `0.0.0.0:8080` (bare) | Unprivileged Rust HTTP/WS API serving external `web/dist` WASM UI (`User=aetherflow`) |
| `aetherflow-runner.service` | `/run/aetherflow/runner.sock` | Privileged root Unix socket daemon (`aetherflow-api runner`, `0660 root:aetherflow`) |
| `aetherflow-self-update-<command>-<channel>-<8hex>.service` | Per-launch transient systemd unit | Isolated self-updater surviving `aetherflow-runner` and `aetherflow-api` restarts |
| `af` (`/opt/AetherFlow/current/bin/af`) | CLI binary (`af-cli`) | Unified administrative CLI for packages, services, quotas, backups, and releases |
| SQLite (`af-db`) | `/var/lib/aetherflow/aetherflow.sqlite` | Bundled WAL database (`max_size(1)` writer + `max_size(8)` reader pools) |
| McBrowser (`af-files` + `af-api::mcbrowser`) | `/var/lib/aetherflow/mcbrowser` | Capability-scoped per-user storage (`0700`) |

---

## Startup & Systemd Units

### Prerequisites

- **Target OS**: Debian 12/13 (Bookworm/Trixie) or Ubuntu 22.04/24.04 LTS (`systemd`).
- **Control Plane Runtime**: The control plane and dashboard require no Node.js, Go, or Redis daemons (compiled into `aetherflow-api`, `bin/af`, and `bin/speedtest-backend` with bundled SQLite). Individual Marketplace applications (such as Palate, Maintainerr, Seerr, Flood, n8n, The Lounge, Piped, and Uptime Kuma) install and use Node.js as required.
- **Mandatory Host Runtime Dependencies**: Production hosts require `python3` and `openssl` for `af-release` Sigstore/SLSA provenance verification (`deploy/verify-provenance.py`), deferred core service restarts, `deploy/log-retention.py`, and `deploy/release-manager.sh`.

### Environment File (`/etc/aetherflow/aetherflow.env`)

Both `aetherflow-api.service` and `aetherflow-runner.service` load `/etc/aetherflow/aetherflow.env` via `EnvironmentFile=` (PID 1 reads it as `root` before dropping privileges; runner-specific overrides can also be set via `sudo systemctl edit aetherflow-runner`):

| Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `JWT_SECRET` | **Yes** | — | `>= 32`-byte secret for HS256 JWT signing |
| `AES_MASTER_KEY` | **Yes** | — | 32-byte raw, 64-char hex, or Base64 key for AES-256-GCM encryption at rest |
| `ALLOWED_HOSTS` | **Yes** | — | Comma-separated permitted `Host` headers (`localhost,127.0.0.1,<your-domain>`); prevents hostname Host-header poisoning (note: `local_control_plane_host` accepts any valid IPv4/IPv6 literal — pin `PUBLIC_URL` and `OIDC_ISSUER` and reject catch-all IP `Host` headers at Apache2) |
| `BIND_ADDR` | Recommended | `0.0.0.0` (bare/`af provision`) / `127.0.0.1` (Setup) | **Must be `127.0.0.1` behind Apache2** so plaintext port `8080` is never exposed publicly |
| `PORT` | No | `8080` | HTTP/WS listen port (if changed, update Apache2's reverse-proxy target away from `127.0.0.1:8080`, set `HEALTH_ENDPOINT` in `aetherflow.env` + restart `aetherflow-runner` for UI updates, and pass `HEALTH_ENDPOINT` / `--config` explicitly on `--local` deploys/rollbacks; see [Health & Readiness Checks](#health--readiness-checks)) |
| `COOKIE_SECURE` | Recommended | `true` (`false` in `af provision` and IP/`*.local` Setup) | Enforce `Secure` attribute on `aetherflow_session` cookies in HTTPS deployments (fresh `af provision` and IP-only/`localhost`/`*.local` `AetherFlow-Setup` runs write `false` unless `COOKIE_SECURE`/`AF_TLS_ENABLED=1`/`SSL_ENABLED=1` is set) |
| `ALLOWED_CORS_ORIGIN` | No | Localhost origins (`http://localhost:3000/8080/$PORT`, `http://127.0.0.1:3000/8080/$PORT`) | Comma-separated explicit frontend origin URLs for CORS and WebSocket `Origin` checks |
| `AF_DB_PATH` / `DB_PATH` / `AETHERFLOW_DB_PATH` | No | `/var/lib/aetherflow/aetherflow.sqlite` | SQLite WAL database path (conflicting overrides fail closed) |
| `AF_MCBROWSER_ROOT` | No | `/var/lib/aetherflow/mcbrowser` | Private directory for Native McBrowser storage |
| `AF_HEAL_AUTO_APPROVE` | No | `false` | Set `true` or `1` for automatic service restart healing |
| `PRIVILEGED_RUNNER_ENABLED` | No | `false` (`aetherflow-api.service` sets `true`) | Trimmed, case-insensitive `1`, `true`, `yes`, or `on` enables privileged runner readiness probing alongside SQLite |

### Host Path Picker & Multi-GPU Drop-ins

- **Host Path Picker**: Administrator-only `GET /api/v1/auth/fs` defaults to `/mnt,/media,/srv,/data,/home` plus `env::temp_dir()` (`/tmp`) and `env::current_dir()` (when outside `/opt/AetherFlow` and `/var/lib/aetherflow`). Set `AF_ALLOWED_FS_ROOTS` in `/etc/aetherflow/aetherflow.env` to override.
- **Multi-GPU NVENC Drop-ins**: `aetherflow-api.service` allows `/dev/nvidia0` by default under `DevicePolicy=closed`. Multi-GPU hosts can add `DeviceAllow=/dev/nvidia1 rw` lines in `/etc/systemd/system/aetherflow-api.service.d/local.conf`, then reload and restart systemd.

### Managing the Control Plane Units

```bash
# Check status of both core units
sudo systemctl status aetherflow-runner aetherflow-api

# Restart in proper dependency order
sudo systemctl restart aetherflow-runner aetherflow-api

# Stream live systemd journals
sudo journalctl -u aetherflow-api -u aetherflow-runner -f
```

---

## Health & Readiness Checks

### Readiness Probe (`/health/ready`)

```bash
curl -s http://127.0.0.1:8080/health/ready | jq
```

Expected response:

```json
{
  "database": "ok",
  "runner": "ok",
  "redis": "disabled",
  "status": "ready",
  "uptime": "1420.5s",
  "version": "v4.0.0"
}
```

- `runner` reports `"ok"`, `"unreachable"`, or `"disabled"`. When `PRIVILEGED_RUNNER_ENABLED` is set to a trimmed, case-insensitive `1`, `true`, `yes`, or `on` (default in the packaged `aetherflow-api.service`), readiness probes SQLite and the configured privileged runner socket (`/v1/health`) concurrently under bounded two-second budgets. When `PRIVILEGED_RUNNER_ENABLED` is unset or false, `runner` reports `"disabled"` and SQLite alone determines readiness.
- If any required check fails, both `GET /health/ready` and `GET /api/v1/auth/ready` (which sets `Cache-Control: no-store` on both `200` and `503`) return HTTP `503` with `"status": "not_ready"`. A healthy database still reports `"database": "ok"` when `"runner": "unreachable"`. Process liveness (`GET /health/live`) remains independent and returns HTTP `200`.
- `version` is captured from the physical running executable on startup (not the mutable `/opt/AetherFlow/current` symlink).
- `redis` reports `"disabled"` in v4.0.0 because JWT revocation and active session tracking are persisted directly in SQLite (`af-db`).
- **Release Gate & `HEALTH_ENDPOINT` Overrides**: `deploy/release-manager.conf`, `af-release`, and the standalone `deploy/release-manager.sh` fallback all default `HEALTH_ENDPOINT` to `http://127.0.0.1:8080/health/ready`. On hosts with a custom `PORT`, update Apache2's reverse-proxy target away from `127.0.0.1:8080`, and note the two release execution paths: (a) setting `HEALTH_ENDPOINT` or `AETHERFLOW_RELEASE_CONF` (an external `KEY=VALUE` release config file outside `/opt/AetherFlow/current`) inside `/etc/aetherflow/aetherflow.env` and restarting `aetherflow-runner` governs **UI and runner-socket releases only**; (b) standalone `af release deploy|rollback --local` runs do **not** read `HEALTH_ENDPOINT` from `aetherflow.env` and will fail Stage 3 and Stage 4 readiness on `:8080` unless you pass `sudo env HEALTH_ENDPOINT=...` / `sudo env AETHERFLOW_RELEASE_CONF=...` (or `--config <external-conf>`, since Debian/Ubuntu `sudo` strips shell exports via `Defaults env_reset`); and (c) runner-socket `af release deploy` rejects shell-exported `AETHERFLOW_RELEASE_CONF` unless `--local` is passed. Any override used for deployment must report full application readiness to supply an equivalent gate. During rollback, older supported v4 readiness payloads containing `{"status":"ready"}` or `{"status":"ok"}` remain accepted.

---

## Unified Admin CLI (`af`)

The compiled `af` (`af-cli`) binary provides direct command-line control over the platform (add `--json` for structured machine output):

```bash
# Package lifecycle (77 bare-metal apps; Bash installers by default, 9 opt-in Rust recipes via AETHERFLOW_ENABLE_RUST_PACKAGES=1)
sudo af package list --installed
sudo af package install jellyfin qbittorrent
sudo af package update jellyfin
sudo af package remove jellyfin

# Systemd service control (via runner.sock allowlist; use the catalog service name, e.g., jellyfin)
sudo af service status jellyfin
sudo af service restart jellyfin

# Direct Linux POSIX disk quotas (UI Storage Quotas also syncs SQLite user_quotas) & systemd sandboxing
sudo af quota set alice 500G
sudo af sandbox apply qbittorrent

# Host maintenance (native Rust implementations in af-host)
sudo af maintenance tune          # Apply BBR + fq + 64 MiB socket sysctl tuning
sudo af maintenance sentinel      # Scan /var/log/auth.log for SSH brute-force offenders
sudo af maintenance clean-logs    # Truncate oversized .log files under /var/log and legacy installer lock dir /srv/aetherflow/lock
sudo af maintenance showspace     # Inspect per-user /home disk usage
```

See [Unified Rust Admin CLI (`af`)](./rust-admin-cli.md) for the complete command reference and exit codes, and [Marketplace Developer Guide](./marketplace-developer-guide.md) for modular `packages/common.sh` / `packages/lib/*.sh` helper details.

---

## Service Recovery (`af-heal`)

1. The `af-heal` worker in `af-services` (`start_heal_worker(10)`) polls managed `systemd` services every 10 seconds.
2. If an enabled service enters a `failed` or crashed state:
   - **Gated Mode (default)**: Queues a deduplicated `pending_action` in the **Approval Inbox** requiring administrator sign-off.
   - **Auto-Approve Mode (`AF_HEAL_AUTO_APPROVE=true` or `1`)**: Dispatches `systemctl restart` through `/run/aetherflow/runner.sock` with exponential backoff (`10s * 2^(attempt - 1)` = `10s`, `20s`, `40s`, up to **3 retries** per failure incident before requiring manual intervention).
3. Manual approvals and rejections are recorded in `admin_audit_log` (falling back to the API service journal if an audit write fails). Automated `af-heal` restarts emit `tracing` logs and in-app administrator notifications rather than writing `admin_audit_log` entries.

---

## Authentication & Sessions

### JWT & Session Revocation

| Property | Value |
| :--- | :--- |
| Algorithm | HS256 (`JWT_SECRET`) |
| Access Token TTL | 15 minutes (2-hour refresh grace window, 30-day absolute session cap) |
| Revocation Store | SQLite `revoked_tokens` + `sessions_revoked_after` (`active_sessions` additionally checked on perimeter forward-auth `/api/v1/public/auth/verify`, `/metrics`, and optional authenticated `GET /api/v1/public/marketplace`; see [Security & Hardening](./security.md)) |
| 2FA | Optional per-user TOTP (`totp-lite`) with bcrypt-hashed recovery codes |

Every authenticated request, OIDC token introspection, and WebSocket upgrade verifies that the token is not in `revoked_tokens` and that the owning user account remains active in SQLite. On a fresh host where `users` is empty (and `AETHERFLOW_WEB_ADMIN_PASSWORD` was not passed to `AetherFlow-Setup`), remote or Apache-proxied `POST /api/v1/public/auth/setup` requests fail closed with HTTP `403 SETUP_TOKEN_REQUIRED` until supplied with the one-time `0600` bootstrap token at `/var/lib/aetherflow/.setup-bootstrap-token` (or `AETHERFLOW_SETUP_TOKEN`) via `setup_token` or `X-AetherFlow-Setup-Token`.

---

## OIDC Provider

AetherFlow includes a built-in OpenID Connect provider for downstream applications:

- **RSA 2048-bit Key & Issuer Pinning**: Persisted at `OIDC_KEY_PATH` (`/var/lib/aetherflow/oidc_rsa.pem`, mode `0600`). Pin explicit `OIDC_ISSUER` and `PUBLIC_URL` in `/etc/aetherflow/aetherflow.env` so `/.well-known/openid-configuration` cannot reflect arbitrary IPv4/IPv6 `Host` literals (which bypass `ALLOWED_HOSTS` via `local_control_plane_host`).
- **Endpoints**:
  - `GET /.well-known/openid-configuration`
  - `GET /api/v1/public/oidc/authorize`
  - `POST /api/v1/public/oidc/token`
  - `GET /api/v1/public/oidc/userinfo`
  - `GET /api/v1/public/oidc/jwks`
  - `POST /api/v1/public/oidc/revoke`
  - `POST /api/v1/public/oidc/introspect`
  - `POST /api/v1/public/oidc/device/authorize`
  - `POST /api/v1/auth/oidc/consent`
  - `POST /api/v1/auth/oidc/device/verify`
  - `POST /api/v1/auth/oidc/device/consent`
  - `GET` / `POST /api/v1/admin/oidc/clients` and `DELETE /api/v1/admin/oidc/clients/:id`

---

## Backup & Staged Restore (`af-host`)

Dashboard and scheduled backups capture the AetherFlow SQLite database. `af-host` snapshots capture committed WAL data (default `VACUUM INTO`), verify **both** `PRAGMA quick_check` and `PRAGMA integrity_check`, and write archives to `/var/lib/aetherflow/backups/` (or `AETHERFLOW_BACKUP_DIR`) alongside a `.manifest.json` and `.sha256` sidecar. CLI backup commands take a bare `<backup-filename>` inside that backup directory (not an arbitrary absolute path).

`af backup create` (default `--archive`, or pass `--sqlite-only` for a standalone SQLite snapshot) archives:

- `/var/lib/aetherflow/aetherflow.sqlite`, `/var/lib/aetherflow/.master.creds` (if present — provisioning master credentials generated on every fresh first-admin setup and still accepted by Subdomain Gateway Basic Auth alongside SQLite `system_config.master_credentials`; see [Security & Hardening](./security.md)), and `/var/lib/aetherflow/oidc_rsa.pem` (if present).
- `/etc/aetherflow` and legacy `/etc/AetherFlow` configuration trees.
- `/home/aetherflow/.rtorrent.rc` only if present (operators with legacy seedbox user accounts must back up `/home/<user>/.rtorrent.rc` separately).
- Back up `/var/lib/aetherflow/mcbrowser`, `/var/lib/aetherflow/uploads` (FileShare), Marketplace application data/databases, and Apache configuration separately, keeping McBrowser synchronized with SQLite quota records. Periodically prune verified old `<app-dir>.af-backup.*` upgrade backup trees created by Marketplace installers to avoid unbounded disk growth.

> [!CAUTION]
> Do **not** bind-mount shared host directories under `/var/lib/aetherflow/mcbrowser/user-*`. Account deletion recursively removes `user-<id>` without a `st_dev` mount-boundary guard.

```bash
# 1. Create (full host archive or standalone SQLite snapshot), list, and verify backups in /var/lib/aetherflow/backups/
sudo af backup create
sudo af backup create --sqlite-only
sudo af backup list
sudo af backup verify <backup-filename>

# 2. Zero-downtime non-destructive preflight plan (validates SHA-256, manifest, tar entries, and collisions)
sudo af backup restore-preflight <backup-filename> --target-root /var/backups/af-restore-stage

# 3. Extract and verify into a staging directory
#    NOTE: On live Linux hosts (without the isolated-test global flag --root <dir>, which confines both
#    backup-dir and target-root inside <dir>), running restore into a staging directory still stops and
#    restarts live aetherflow-api.service automatically during restore quiescence. Use step 2 for zero-downtime checks.
sudo af backup restore <backup-filename> --target-root /var/backups/af-restore-stage --confirm-destructive-restore

# 4. Live restore directly onto / (supported for --sqlite-only / dashboard .sqlite backups, or .tar.gz
#    archives that do NOT contain .master.creds or oidc_rsa.pem; see canonical allowlist note below.
#    Note: restore-preflight accepts --allow-staging-overwrite; restore accepts --allow-overwrite.)
sudo af backup restore-preflight <backup-filename> --target-root / --allow-staging-overwrite
sudo af backup restore <backup-filename> --target-root / --allow-overwrite --confirm-destructive-restore

# 5. Restart aetherflow-runner when restoring a .tar.gz containing /etc/aetherflow/aetherflow.env
#    (af-host quiesces/restarts aetherflow-api.service only and clamps restored .env files to mode 0600),
#    then verify post-restore health:
sudo systemctl restart aetherflow-runner
sudo af health
curl -fsS http://127.0.0.1:8080/health/ready | jq

# 6. If a live restore was interrupted mid-flight (crash/power loss), finish recovery:
sudo af backup recover-interrupted --target-root /
```

> [!IMPORTANT]
> - **Canonical `/` Restore Allowlist Limitation**: When `--target-root /` is passed, `af-host` enforces `resolve_trusted_canonical_host_destination_with_sqlite_override` (`af-host/src/restore/policy.rs`), which currently excludes `var/lib/aetherflow/.master.creds` and `var/lib/aetherflow/oidc_rsa.pem`. Full `af backup create` archives containing either file fail closed with `UnsafeOverwriteRejected` on `--target-root /`.
> - **Manual Promotion Procedure (Full Archives)**:
>   1. Extract into `/var/backups/af-restore-stage` (step 3) and stop both units (`sudo systemctl stop aetherflow-api aetherflow-runner`).
>   2. Remove stale `-wal`/`-shm` sidecars and copy verified files into place with exact ownership/modes: `chown aetherflow:aetherflow` + `chmod 0600` on `/var/lib/aetherflow/oidc_rsa.pem` and `/var/lib/aetherflow/.master.creds`; `chown aetherflow:aetherflow` + `chmod 0640` on `/var/lib/aetherflow/aetherflow.sqlite`; `chown root:aetherflow` + `chmod 0640` (or `0600` `root:root`/`aetherflow:aetherflow`) on `/etc/aetherflow/aetherflow.env`.
>   3. Restart both services (`sudo systemctl restart aetherflow-runner aetherflow-api`) because `aetherflow-runner.service` also loads `/etc/aetherflow/aetherflow.env`.
> - Live `af backup restore` without `--confirm-destructive-restore` (or `--confirm`) fails closed (`ExitCode = 6`).
> - `af backup restore --dry-run` only checks that `<backup-filename>` and `<backup-filename>.manifest.json` exist as regular files; **always use `af backup restore-preflight`** for full SHA-256, manifest, tar-entry, and collision verification before restoring onto `/`. See [Rust Host Management (`af-host`)](./rust-host-management.md).

---

## Self-Update & Release Operations (`af-release`)

UI- and runner-triggered updates run inside per-launch transient `aetherflow-self-update-<command>-<channel>-<8hex>.service` units (`systemd-run --collect`) with durable JSON receipts under `/var/lib/aetherflow/.self-update-jobs/<unit>.json`, so restarting `aetherflow-runner` and `aetherflow-api` during the cutover never kills the updater. `runner.sock` IPC `/v1/self-update` defaults to the native Rust `af-release` engine (`NativeRustRelease`); operators can set `AETHERFLOW_FORCE_BASH_RELEASE=1` (or `AETHERFLOW_RELEASE_ENGINE=bash`) in `/etc/aetherflow/aetherflow.env` (or a `systemctl edit aetherflow-runner` drop-in) as an escape hatch to `deploy/release-manager.sh`.

Omitting `--local` dispatches through `aetherflow-runner.service`'s isolated transient systemd unit; passing `--local` executes `af-release` directly in the invoking root shell (recommended for standalone recovery when the runner or API is unhealthy):

```bash
# Inspect current release, active symlink, and recovery journal state
sudo af release status

# Deploy via the isolated runner transient systemd unit (recommended for live hosts)
sudo af release deploy --channel stable

# Deploy or roll back directly in the invoking root shell (standalone recovery;
# on custom-PORT hosts, use `sudo env HEALTH_ENDPOINT=...` or `--config <external-conf>`
# because --local ignores aetherflow.env and Debian/Ubuntu sudo strips shell exports)
sudo af release deploy --local --channel stable
sudo af release rollback --local
```

> [!NOTE]
> Both Stage 3 deploy and Stage 4 rollback synchronously execute `systemctl start aetherflow-log-retention.service` before restarting `aetherflow-runner` and `aetherflow-api`. If a deploy or rollback aborts in `Stage4Rollback` (`RollbackFailed`), check `sudo journalctl -u aetherflow-log-retention.service`, repair or remove any symlinked, hardlinked, non-`root`/`aetherflow`-owned, or group/world-writable managed log file under `/var/log/aetherflow` (`root:aetherflow`, `0640`), and re-run `sudo af release rollback --local`.

See [Self-Update Lifecycle](./self-update.md) and [Rust Release Engine (`af-release`)](./rust-release-engine.md).

---

## Database Maintenance

- **Bundled SQLite WAL**: `af-db` pairs a serialized writer pool (`DB_POOL`, `max_size(1)`, `busy_timeout = 5000`, `PRAGMA synchronous = NORMAL`) with a dedicated read-only WAL pool (`DB_READ_POOL`, `max_size(8)`, `query_only = ON`, `busy_timeout = 750ms`).
- **Automatic Pruning & Recovery (15-minute loop)**: Background maintenance prunes expired `oidc_auth_codes`, `oidc_device_codes`, `oidc_refresh_tokens`, `active_sessions`, `revoked_tokens`, `mfa_challenges`, old `metrics_history`, 90-day `login_history`, 90-day `streaming_bandwidth_samples`, and 90-day terminal `notification_delivery_log` rows, and runs `maintain_backup_upload_staging` (chunked backup upload cleanup), `recover_fileshare_pending_publishes` (FileShare `/var/lib/aetherflow/uploads` recovery), and `account_cleanup::recover` (durable account storage cleanup).
- **Manual WAL Checkpoint**: Requires the optional `sqlite3` CLI package (`apt-get install sqlite3`). Run as the `aetherflow` user (never as `root`, which can create `root:root`-owned `-wal`/`-shm` sidecars and block `aetherflow-api.service`):

```bash
sudo -u aetherflow sqlite3 /var/lib/aetherflow/aetherflow.sqlite "PRAGMA wal_checkpoint(TRUNCATE);"
```

---

## Notification Channels

- **Trigger & Delivery Lifecycle**: Rule triggers atomically persist per-rule cooldown (`notification_rules.last_triggered_at`), the local broadcast notification, and credential-free delivery intents in `notification_delivery_log`. Supported channels (`discord`, `telegram`, `slack`, `gotify`, `email` [HTTP/HTTPS email webhook, not native SMTP], `webhook`, `custom`) resume on startup and periodic ticks using bounded leased claims (`pending` -> `sending` -> `delivered` / `failed` / `uncertain`), 3-attempt exponential backoff, and decrypted channel configs.
- **SSRF Policy**: Outbound webhooks block private, loopback, link-local, metadata, unspecified, and multicast targets and unsafe redirects by default. Set `AETHERFLOW_ALLOW_PRIVATE_WEBHOOKS=1` to allow RFC1918/CGNAT/ULA private LAN targets (loopback, link-local, metadata, unspecified, and multicast remain blocked).
- **Crash-Window Semantics**: If the host crashes after an upstream receiver accepts a webhook and before SQLite commits the receipt, delivery retries up to attempt 3 under the claim lease and resolves to terminal `uncertain` if the final claim expires without receipt.
- **Retention & Visibility**: Terminal `notification_delivery_log` rows are pruned after 90 days; delivery status is surfaced without credentials via `GET /api/v1/admin/notifications/channels`.

---

## Troubleshooting

See [Troubleshooting & FAQ](./troubleshooting.md) for diagnostics covering `aetherflow-api.service`, `aetherflow-runner.service`, Apache2 Subdomain Gateway routing, `ReadWritePaths` systemd sandboxing, and APT lock contention, and [Marketplace Lifecycle Log Retention](./marketplace-log-retention.md) for `/var/log/aetherflow` log rotation.
