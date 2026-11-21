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

```
┌──────────────────────────────────────────────────────────────────────┐
│                         AetherFlow v4.0.0                            │
│                                                                      │
│   [Operator Browser] ──HTTPS/WSS──> [Apache2 + Subdomain Gateway]    │
│                                              │                       │
│                                       127.0.0.1:8080                 │
│                                              ▼                       │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ aetherflow-api.service (Unprivileged Rust Control Plane)       │  │
│  │  • af-api (Axum HTTP/WS + External web/dist WASM UI)            │  │
│  │  • af-files (Native McBrowser Scoped Tenant File Manager)      │  │
│  │  • af-hardware (Zero-Fork sysinfo + NVML GPU FFI)              │  │
│  │  • af-services (77-App Catalog, Mutators, Plugins, Workers)    │  │
│  └──────────────────┬─────────────────────────────┬───────────────┘  │
│                     │                             │                  │
│                     ▼                             ▼                  │
│  ┌────────────────────────────────┐  ┌────────────────────────────┐  │
│  │ /var/lib/aetherflow/           │  │ /run/aetherflow/runner.sock│  │
│  │  • aetherflow.sqlite (WAL)     │  │ aetherflow-runner.service  │  │
│  │  • mcbrowser/user-<id> (0700)  │  │  • systemctl allowlists    │  │
│  │  • AES-256-GCM secrets         │  │  • 12 Rust recipes + Bash  │  │
│  └────────────────────────────────┘  │  • WireGuard / Tailscale   │  │
│                                      │  • Isolated Self-Updater   │  │
│                                      └────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

| Component | Binding / Path | Purpose |
|-----------|----------------|---------|
| `aetherflow-api.service` | `127.0.0.1:8080` | Unprivileged Rust HTTP/WS API serving external `web/dist` WASM UI (`User=aetherflow`) |
| `aetherflow-runner.service` | `/run/aetherflow/runner.sock` | Privileged root UNIX socket daemon (`0660 root:aetherflow`) |
| `aetherflow-self-update.service` | Transient systemd unit | Isolated self-updater surviving `aetherflow-runner` and `aetherflow-api` restarts |
| `af` (`/opt/AetherFlow/current/af`) | CLI binary (`af-cli`) | Unified administrative CLI for packages, services, quotas, backups, and releases |
| SQLite (`af-db`) | `/var/lib/aetherflow/aetherflow.sqlite` | Single-writer WAL database (sessions, JWT revocation, settings, streaming history) |
| McBrowser (`af-files`) | `/var/lib/aetherflow/mcbrowser` | Capability-scoped per-user storage (`0700`) |

---

## Startup & Systemd Units

### Prerequisites
- **Target OS**: Debian 12/13 (Bookworm/Trixie) or Ubuntu 22.04/24.04 LTS (`systemd`)
- **Runtime**: Zero Node.js, Go, or Redis runtime required in production (compiled into `aetherflow-api` and `af` with bundled SQLite).

### Environment File (`/etc/aetherflow/aetherflow.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_SECRET` | **Yes** | — | $\ge 32$-byte secret for HS256 JWT signing |
| `AES_MASTER_KEY` | **Yes** | — | 32-byte raw or Base64 key for AES-256-GCM encryption at rest |
| `AF_DB_PATH` / `DB_PATH` | No | `/var/lib/aetherflow/aetherflow.sqlite` | SQLite WAL database path |
| `PORT` | No | `8080` | Loopback HTTP/WS listen port |
| `AF_MCBROWSER_ROOT` | No | `/var/lib/aetherflow/mcbrowser` | Private directory for Native McBrowser storage |
| `AF_HEAL_AUTO_APPROVE` | No | `false` | Set `true` for autonomous service restart healing |
| `PRIVILEGED_RUNNER_ENABLED` | No | `false` (`aetherflow-api.service` sets `true`) | Trimmed, case-insensitive `1`, `true`, `yes`, or `on` enables privileged runner readiness probing alongside SQLite |

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
- **Release Gate & `HEALTH_ENDPOINT` Overrides**: `deploy/release-manager.conf`, `af-release`, and the standalone `deploy/release-manager.sh` fallback all default `HEALTH_ENDPOINT` to `http://127.0.0.1:8080/health/ready`. Explicit `HEALTH_ENDPOINT` overrides are preserved; any override used for deployment must report full application readiness to supply an equivalent gate. During rollback, older supported v4 readiness payloads containing `{"status":"ready"}` or `{"status":"ok"}` remain accepted.

---

## Unified Admin CLI (`af`)

The compiled `af` (`af-cli`) binary provides direct command-line control over the platform (add `--json` for structured machine output):

```bash
# Package lifecycle (77 bare-metal apps)
sudo af package list --installed
sudo af package install jellyfin qbittorrent
sudo af package update jellyfin
sudo af package remove jellyfin

# Systemd service control (via runner.sock allowlist)
sudo af service status af-jellyfin
sudo af service restart af-jellyfin

# User disk quotas & systemd drop-in sandboxing
sudo af quota set alice 500G
sudo af sandbox apply qbittorrent

# Host maintenance (native Rust implementations in af-host)
sudo af maintenance tune          # Apply BBR + fq + 64 MiB socket sysctl tuning
sudo af maintenance sentinel      # Scan /var/log/auth.log for SSH brute-force offenders
sudo af maintenance clean-logs    # Truncate oversized .log files under /var/log and /srv/aetherflow/lock
sudo af maintenance showspace     # Inspect per-user /home disk usage
```

See [Unified Rust Admin CLI (`af`)](./rust-admin-cli.md) for the complete command reference and exit codes.

---

## Service Recovery (`af-heal`)

1. The `af-heal` worker in `af-services` (`start_heal_worker(10)`) polls managed `systemd` services every 10 seconds.
2. If an enabled service enters a `failed` or crashed state:
   - **Gated Mode (default)**: Queues a deduplicated `pending_action` in the **Approval Inbox** requiring administrator sign-off.
   - **Auto-Approve Mode (`AF_HEAL_AUTO_APPROVE=true` or `1`)**: Dispatches `systemctl restart` through `/run/aetherflow/runner.sock` with exponential backoff (`10s * 2^attempt`, up to **3 retries** per failure incident before requiring manual intervention).
3. Every approval, rejection, or automated execution is recorded in `admin_audit_log`.

---

## Authentication & Sessions

### JWT & Session Revocation
| Property | Value |
|----------|-------|
| Algorithm | HS256 (`JWT_SECRET`) |
| Access Token TTL | 15 minutes |
| Revocation Store | SQLite `revoked_tokens` + `active_sessions` (`af-db`) |
| 2FA | TOTP (`totp-lite`) with hashed recovery codes |

Every authenticated request, OIDC token introspection, and WebSocket upgrade verifies that the token is not in `revoked_tokens` and that the owning user account remains active in SQLite.

---

## OIDC Provider

AetherFlow includes a built-in OpenID Connect provider for downstream applications:
- **RSA 2048-bit Key**: Persisted at `OIDC_KEY_PATH` (`/var/lib/aetherflow/oidc_rsa.pem`).
- **Endpoints**:
  - `GET /.well-known/openid-configuration`
  - `GET /api/v1/public/oidc/authorize`
  - `POST /api/v1/public/oidc/token`
  - `GET /api/v1/public/oidc/userinfo`
  - `GET /api/v1/public/oidc/jwks`
  - `POST /api/v1/public/oidc/revoke`

---

## Backup & Staged Restore (`af-host`)

Backups use `af-host` to capture WAL-consistent SQLite snapshots (`OnlineBackupApi` or `VACUUM INTO`) verified with `PRAGMA quick_check`, paired with versioned `af-host.backup-manifest.v1` manifests and `.sha256` sidecars.

```bash
# Create a verified backup archive + manifest + SHA-256 sidecar
sudo af backup create

# List and verify backup inventory
sudo af backup list
sudo af backup verify <backup-filename>

# Run a non-destructive preflight against an isolated staging directory
sudo af backup restore-preflight <backup-filename> --target-root /var/backups/af-restore-stage

# Execute a confirmed staged restore into an isolated 0700 directory
sudo af backup restore <backup-filename> --target-root /var/backups/af-restore-stage --confirm-destructive-restore
```

> [!IMPORTANT]
> Calling `af backup restore` without `--confirm-destructive-restore` (or `--confirm`) is intentionally blocked (`ExitCode = 6`). Always run `restore-preflight` and extract/verify into an isolated `--target-root` staging directory first, then replace state during a maintenance window with `aetherflow-api` stopped. See [Rust Host Management (`af-host`)](./rust-host-management.md).

---

## Self-Update & Release Operations (`af-release`)

Updates run inside the isolated `aetherflow-self-update.service` systemd unit so restarting `aetherflow-runner` and `aetherflow-api` during the cutover never kills the updater.

```bash
# Inspect current release, active symlink, and recovery journal state
sudo af release status

# Deploy latest release on a channel (stable or nightly)
sudo af release deploy --local --channel stable

# Roll back to the previous known-good release and verify DB integrity
sudo af release rollback --local
```

See [Self-Update Lifecycle](./self-update.md) and [Rust Release Engine (`af-release`)](./rust-release-engine.md).

---

## Database Maintenance

- **Bundled SQLite WAL**: Connection pool is configured to `max_size(1)` for serialized writes with `busy_timeout = 5000` and `PRAGMA synchronous = NORMAL`.
- **Automatic Pruning**: Background workers prune expired `oidc_auth_codes`, `oidc_device_codes`, `active_sessions`, `revoked_tokens`, and old `metrics_history` rows every 15 minutes.
- **Manual WAL Checkpoint**:
  ```bash
  sudo sqlite3 /var/lib/aetherflow/aetherflow.sqlite "PRAGMA wal_checkpoint(TRUNCATE);"
  ```

---

## Notification Channels

Supported outbound webhook channels (`discord`, `telegram`, `slack`, `custom`) are dispatched asynchronously with 3-attempt exponential backoff and SSRF protection blocking private/loopback addresses and redirects. Delivery outcomes are recorded in `notification_delivery_log`.

---

## Troubleshooting

See the dedicated **[Troubleshooting & FAQ](./troubleshooting.md)** guide for common diagnostics covering `aetherflow-api.service`, `aetherflow-runner.service`, Apache2 Subdomain Gateway routing, `ReadWritePaths` systemd sandboxing, and APT lock contention, and **[Marketplace Lifecycle Log Retention](./marketplace-log-retention.md)** for `/var/log/aetherflow` installer log rotation.
