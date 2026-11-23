# AetherFlow v4.0 Security & Deployment Checklist

This checklist documents the runtime architecture, configuration contracts, privilege boundaries, and operational procedures for the **AetherFlow v4.0 Rust Control Plane** (`aetherflow-api` and `af` CLI).

> [!IMPORTANT]
> **Verification & Evidence Policy**
> Code changes, unit tests, or mocked filesystem drills do not by themselves certify production readiness across all target distributions. Refer to [docs/v4-clean-host-testing.md](./v4-clean-host-testing.md), [docs/v4-lifecycle-testing.md](./v4-lifecycle-testing.md), and [docs/v4-privileged-testing.md](./v4-privileged-testing.md) for the current clean-OS KVM test status and privileged/lifecycle verification ledgers.

---

## 1. Architecture & Filesystem Layout (FHS)

AetherFlow v4.0 replaces the legacy Go (`Gin`) + separate Next.js/PM2 stack with a Rust API (`aetherflow-api`), an external WASM dashboard (`web/dist`), a native administrative CLI (`af`), and the Rust LibreSpeed companion (`speedtest-backend`). The API runs behind **Apache2** reverse-proxy ingress (`127.0.0.1:8080`) with **SQLite WAL** persistence.

| Path | Owner / Mode | Purpose |
| --- | --- | --- |
| `/opt/AetherFlow/releases/<epoch>` | `root:root` (`0755`; `root:aetherflow` from initial Setup/Bash fallback) | Immutable versioned release directories containing `aetherflow-api`, `bin/af`, `bin/speedtest-backend`, `web/dist/`, `config/`, `packages/`, `deploy/`, `plugins/telemetry-inspector/`, `.version`, and `data-snapshot/`. |
| `/opt/AetherFlow/current` | Symlink | Atomic symlink pointing to the active `/opt/AetherFlow/releases/<epoch>` directory. |
| `/usr/local/bin/af` | `root:root` (`0755` wrapper script, or symlink when legacy wrapper is absent) | Installed CLI entrypoint delegating to `/opt/AetherFlow/current/bin/af` (with legacy `/opt/AetherFlow/current/af` and `af-*` fallback compatibility). |
| `/etc/aetherflow/aetherflow.env` | `root:aetherflow` (`0640` via Setup; `0600` via `af provision`/`af-release`) | Protected environment file read by `systemd` PID 1 (`EnvironmentFile=`) containing `JWT_SECRET`, `AES_MASTER_KEY`, `AF_DB_PATH` / `DB_PATH` / `AETHERFLOW_DB_PATH`, and `ALLOWED_HOSTS`. Never overwritten by upgrades. |
| `/var/lib/aetherflow/aetherflow.sqlite` | `aetherflow:aetherflow` (`0640`) | Primary SQLite database in `WAL` mode under `StateDirectoryMode=0700` and `UMask=0027` (including `users`, `settings`, `revoked_tokens`, `admin_audit_log`, and metrics history). |
| `/run/aetherflow/runner.sock` | `root:aetherflow` (`0660`) | Unix domain socket for the privileged `aetherflow-runner.service` (`aetherflow-api runner`) daemon. |

---

## 2. Environment Variables

Configure runtime variables in `/etc/aetherflow/aetherflow.env` (`chmod 0640`, owned by `root:aetherflow`).

### Required Variables

| Variable | Description | Validation & Fail-Closed Behavior |
| --- | --- | --- |
| `JWT_SECRET` | Session JWT signing secret | Must be at least 32 cryptographically random bytes. `aetherflow-api` (`validate_startup_jwt_secret`) fails closed at startup if `JWT_SECRET` is unset or shorter than 32 bytes. |
| `AES_MASTER_KEY` | AES-256-GCM key for encrypted database secrets | Exactly 32 raw bytes, 64 hex characters (32 decoded bytes), or base64 decoding to 32 bytes. `af-db::init_aes_key` fails closed under `AETHERFLOW_ENV=production` / `release` when unset, and always stops initialization on invalid nonempty keys. |
| `AF_DB_PATH` / `DB_PATH` / `AETHERFLOW_DB_PATH` | Absolute path to the live SQLite database | Shared resolution uses this precedence, rejects conflicting overrides, and enforces an isolated root when supplied. Installed units default to `/var/lib/aetherflow/aetherflow.sqlite`. |
| `ALLOWED_HOSTS` | Comma-separated allowlist of HTTP `Host` header values | Validated by host-check middleware (`localhost,localhost:8080,127.0.0.1,127.0.0.1:8080,<your-domain>`). Spoofed hostname `Host` headers are rejected with HTTP `400`. **Exemptions**: (1) `*.aether.local` is implicitly accepted even when omitted from `ALLOWED_HOSTS` and routes without Subdomain Gateway authentication for loopback, RFC1918 LAN, link-local, ULA, and `100.64.0.0/10` (Tailscale/CGNAT) clients; (2) `local_control_plane_host` accepts any valid IPv4/IPv6 literal, so pin `PUBLIC_URL` and `OIDC_ISSUER` in `aetherflow.env` and reject catch-all IP `Host` headers at Apache2. |

### Optional Runtime Variables

| Variable | Description | Default |
| --- | --- | --- |
| `AF_MCBROWSER_ROOT` | Dedicated private directory for Native McBrowser storage | `/var/lib/aetherflow/mcbrowser` (`0700`) |
| `PORT` | TCP port for `aetherflow-api` | `8080` |
| `BIND_ADDR` | Bind address for the HTTP listener | Set `127.0.0.1` behind Apache2. The normal runtime fallback is `0.0.0.0`; isolated E2E mode uses loopback. |
| `ALLOWED_CORS_ORIGIN` | Comma-separated allowed CORS origins | Localhost origins (`http://localhost:3000/8080/$PORT`, `http://127.0.0.1:3000/8080/$PORT`) |
| `COOKIE_SECURE` | Set `Secure` attribute on auth cookies | `true` in production HTTPS deployments (fresh `af provision` and IP-only/`localhost`/`*.local` `AetherFlow-Setup` runs write `false` — verify `true` behind HTTPS) |
| `AETHERFLOW_RUNNER_SOCK` | Path to the privileged runner Unix socket | `/run/aetherflow/runner.sock` |
| `PRIVILEGED_RUNNER_ENABLED` | Enables privileged runner readiness probing alongside SQLite (`1`, `true`, `yes`, `on`, trimmed and case-insensitive) | `false` (`aetherflow-api.service` sets `true`) |
| `AF_GITHUB_TOKEN` | Optional token for API update checks (falls back to `GITHUB_TOKEN`, `GH_TOKEN`). Note: `af-runner` does not forward GitHub tokens into transient self-update units, so UI-triggered `nightly` self-updates remain subject to GitHub's 60 req/hr unauthenticated IP cap. | Unauthenticated public API requests |

### Generating Cryptographic Secrets

```bash
# Generate JWT_SECRET (32 random bytes, hex-encoded = 64 characters)
openssl rand -hex 32

# Generate AES_MASTER_KEY (32 random bytes, base64-encoded)
openssl rand -base64 32
```

---

## 3. Systemd Units & Privilege Separation

AetherFlow v4.0 splits execution across two hardened systemd units installed from `/opt/AetherFlow/current/deploy/systemd/`:

1. **`aetherflow-api.service` (Unprivileged Control Plane)**
   - Runs as `User=aetherflow`, `Group=aetherflow`, `SupplementaryGroups=systemd-journal adm`.
   - `WorkingDirectory=/opt/AetherFlow/current`
   - `ExecStart=/opt/AetherFlow/current/aetherflow-api`
   - The packaged unit enables `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, `ProtectControlGroups=yes`, `ProtectKernelTunables=yes`, `ProtectClock=yes`, `ProtectKernelLogs=yes`, `ProtectKernelModules=yes`, `LockPersonality=yes`, `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `SystemCallArchitectures=native`, `SystemCallFilter=@system-service`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `DevicePolicy=closed` (with `/dev/dri`, `char-drm`, `/dev/nvidiactl`, `/dev/nvidia0`, `/dev/nvidia-modeset`, `/dev/nvidia-uvm`), and `UMask=0027`. Inspect the actual installed unit; additional sandbox flags are not implied.
   - `ReadWritePaths=/var/lib/aetherflow /var/log/aetherflow /run/aetherflow` plus optional `ReadWritePaths=-/srv -/mnt -/media -/data` and `ReadWritePaths=-/opt/AetherFlow/backend/data`.
2. **`aetherflow-runner.service` (Privileged Host Daemon)**
   - Runs `ExecStart=/opt/AetherFlow/current/aetherflow-api runner`.
   - The daemon creates `/run/aetherflow/runner.sock` with mode `0660`; this is not a systemd socket-activation unit. Socket permissions and the daemon's peer/operation authorization both require verification.
   - Executes strictly allowlisted package lifecycle, service control, quota, sandbox, backup/restore, isolated plugin, and self-update requests without exposing `sudo` or arbitrary shell execution to the `aetherflow` web user.

Verify unit configuration and sandbox paths before starting:

```bash
systemctl cat aetherflow-api.service | grep -E "WorkingDirectory|ExecStart|ProtectSystem|ReadWritePaths"
systemctl cat aetherflow-runner.service | grep -E "WorkingDirectory|ExecStart"
```

> [!CAUTION]
> **Do Not Copy the Commented `BindPaths=` Example Beneath `mcbrowser/user-*`**: The packaged `aetherflow-api.service` unit contains a legacy comment referencing `BindPaths=.../mcbrowser/user-1/Media`. Never bind-mount shared host directories under `/var/lib/aetherflow/mcbrowser/user-*`, because account deletion recursively removes `user-<id>` without a `st_dev` mount-boundary guard.

---

## 4. Deployment & Release Procedure

### Release & Self-Update Safety (`af-release` & `aetherflow-self-update-<command>-<channel>-<8hex>.service`)

- CI release archives and `af-release` (`prepare_release_permissions`) normalize extracted directories to `0755`, clear group/other write bits on regular files (`(mode | 0o444) & !0o022`, preserving existing archive execute bits on `packages/*`), explicitly set `0755` on `aetherflow-api`, `af`, `bin/af`, `speedtest-backend`, `bin/speedtest-backend`, `deploy/release-manager.sh`, `deploy/verify-provenance.py`, `deploy/log-retention.py`, and `plugins/telemetry-inspector/backend/hooks/start.sh`, and verify service-user access before switching `/opt/AetherFlow/current`.
- Self-updates launch in a unique transient `aetherflow-self-update-<command>-<channel>-<8hex>.service` systemd unit (`systemd-run --collect`) with `0600` job configuration and durable JSON receipts in `<data_dir>/.self-update-jobs/<unit>.json` so restarting `aetherflow-runner` and `aetherflow-api` never terminates the in-flight updater.
- Stable deployments resolve GitHub's public `/releases/latest` redirect when the REST API is rate-limited.
- API update checks share a 5-minute cache, cache transient failures for 1 minute, and honor `X-RateLimit-Reset` and `Retry-After` headers (`error: github_rate_limited`, `retryAt`).

### Binary Baseline & Reproducibility

- Prebuilt release archives (`aetherflow-linux-amd64.tar.gz` and `aetherflow-linux-arm64.tar.gz`) must be built against the **Ubuntu 22.04 (`GLIBC 2.35`)** baseline (`.github/workflows/release.yml` and `.github/workflows/ci.yml`) so dynamically linked binaries run across the supported OS matrix: Ubuntu 22.04, Ubuntu 24.04, Debian 12, and Debian 13.
- All release and source builds require a committed workspace `backend-rs/Cargo.lock` and compile with `--locked` (`cargo test --workspace --locked`, `cargo build --release --locked --bin aetherflow-api --bin af --bin speedtest-backend`).
- Release archives package `aetherflow-api`, `bin/af`, and `bin/speedtest-backend`, external `web/dist/`, canonical `config/`, `packages/`, `deploy/`, `plugins/telemetry-inspector/`, and `.version`, accompanied by `SHA256SUMS` and GitHub Sigstore/SLSA build provenance attestations.

### Fresh Installation (`setup/AetherFlow-Setup`)

- By default, `setup/AetherFlow-Setup` pulls and verifies the prebuilt v4 release archive and `SHA256SUMS` manifest for the selected channel (`--channel stable|nightly`) without installing Go or Node.js runtimes on the target host.
- If archive download, SHA-256 verification, or tar preflight validation (which rejects symlinks, hardlinks, device nodes, absolute paths, and `..` traversal) fails, the installer **fails closed** and never falls back to an unverified download, a legacy `v3.x` tag, or an implicit source build.
- Building from source on a host requires explicit opt-in (`bash AetherFlow-Setup --from-source` or `AETHERFLOW_BUILD_FROM_SOURCE=1`) and a locked `backend-rs/Cargo.lock`.

### Step-by-Step Deployment

1. **Set Environment Variables**: Ensure all required variables are populated in `/etc/aetherflow/aetherflow.env` with mode `0640`, owned by `root:aetherflow` (matching `setup/modules/modern_stack.sh`).
2. **Build or Pull a Verified Release**:

   ```bash
   # With the pinned WASM tools on PATH, build the release bundle and SHA256SUMS.
   bash scripts/build_gold.sh

   # Or deploy directly via the unified Rust CLI / release manager
   sudo af release deploy --local --channel stable
   ```

3. **Atomic Upgrades (`af release` / `deploy/release-manager.sh`)**:

   ```bash
   # Dry-run upgrade check against live database (read-only online backup into isolated sandbox)
   sudo af release deploy --local --channel nightly --dry-run

   # Live atomic upgrade
   sudo af release deploy --local --channel nightly
   ```

During every deployment:

1. **Lock Serialization**: Acquires `/opt/AetherFlow/releases/.release.lock` and the shared `/run/aetherflow/.snapshot.lock` (or an explicitly configured, protected maintenance-lock path). The runtime lock anchor is root-owned; the service-owned data directory is not repurposed as a root lock anchor.
2. **Stage 0 & 1**: Verifies `SHA256SUMS` and Sigstore/SLSA v1 build provenance, validates tar entries against symlink/traversal attacks, extracts into `/opt/AetherFlow/releases/<epoch>`, validates `web/dist` assets, and verifies `aetherflow` service-user read/execute access.
3. **Stage 1.5**: Captures a WAL-safe online SQLite backup (`sqlite3 --readonly .backup` / `rusqlite::backup::Backup`), verifies `PRAGMA integrity_check == ok`, and writes `data-snapshot/MANIFEST.sha256`.
4. **Stage 2 & 3 (Swap, Log Retention & Readiness)**:
   - Atomically swaps `/opt/AetherFlow/current` and updates `/usr/local/bin/af`.
   - Synchronously executes `aetherflow-log-retention.service` and enables `aetherflow-log-retention.timer` before restarting core units (non-compliant symlinks, hardlinks, wrong owners, or group/world-writable managed logs under `/var/log/aetherflow` abort both Stage 3 and Stage 4 rollback).
   - Restarts `aetherflow-runner.service` and `aetherflow-api.service`, then polls `http://127.0.0.1:8080/health/ready` (the default in `deploy/release-manager.conf`, `af-release`, and the standalone `deploy/release-manager.sh` fallback).
   - **Custom `PORT` / `HEALTH_ENDPOINT`**: Setting `HEALTH_ENDPOINT` in `/etc/aetherflow/aetherflow.env` + restarting `aetherflow-runner` applies to UI/runner-socket updates only. Standalone `--local` deploys/rollbacks ignore `HEALTH_ENDPOINT` in `aetherflow.env` and must pass `sudo env HEALTH_ENDPOINT=...` or `--config <external-conf>`. Any override used for deployment must report full application readiness; rollback preserves acceptance of older supported v4 readiness replies containing `{"status":"ready"}` or `{"status":"ok"}`.

---

## 5. Post-Deployment Verification

### Systemd Sandbox & Socket Permissions

Verify that `aetherflow-api.service` runs under `ProtectSystem=strict` and `aetherflow-runner.service` owns `/run/aetherflow/runner.sock`:

```bash
systemctl cat aetherflow-api.service | grep -E "ProtectSystem|StateDirectory|NoNewPrivileges"
ls -l /run/aetherflow/runner.sock
# Expected: srw-rw---- 1 root aetherflow ... /run/aetherflow/runner.sock
```

### Readiness and Dashboard Serving

```bash
# 1. Deep readiness probe (verifies SQLite pool health and enabled privileged runner health)
curl -fsS http://127.0.0.1:8080/health/ready | jq
# Expected JSON: {"database":"ok","runner":"ok","redis":"disabled","status":"ready","uptime":"...","version":"v4.0.0"}

# 2. Verify the WASM dashboard entry point is served.
curl -fsSI http://127.0.0.1:8080/

# 3. Verify native CLI version, health (requires root/aetherflow for runner.sock SO_PEERCRED), and active release status.
af --version
sudo af health
sudo af release status
```

- `runner` reports `"ok"`, `"unreachable"`, or `"disabled"`. With `PRIVILEGED_RUNNER_ENABLED` set to a trimmed, case-insensitive `1`, `true`, `yes`, or `on` (set to `true` in `aetherflow-api.service`), SQLite and the runner socket (`/v1/health`) are checked concurrently under two-second budgets; with it unset or false, `runner` is `"disabled"` and SQLite alone determines readiness.
- If a required check fails, both `/health/ready` and `/api/v1/auth/ready` (`Cache-Control: no-store` on `200` and `503`) return HTTP `503` with `"status": "not_ready"`, while keeping `"database": "ok"` when only the runner is unreachable.

### Authentication & SQLite Token Revocation (`revoked_tokens`)

AetherFlow v4.0 persists revoked JWT `jti` identifiers in the SQLite `revoked_tokens` table (Redis is not required for session revocation).

```bash
# 1. Verify af-api rejects a spoofed Host header directly on loopback
#    (Sending a mismatched Host to HTTPS Apache2 triggers TLS SNI mismatch 421 or the default vhost)
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Host: evil.example.com" \
  http://127.0.0.1:8080/api/v1/public/marketplace
# Expected: 400

# 2. Verify unauthenticated access to protected routes is blocked
curl -s -o /dev/null -w "%{http_code}\n" \
  http://127.0.0.1:8080/api/v1/auth/settings
# Expected: 401

# 3. Verify logout records JWT revocation in SQLite revoked_tokens
sudo -u aetherflow sqlite3 /var/lib/aetherflow/aetherflow.sqlite \
  "SELECT COUNT(*) FROM revoked_tokens;"
```

### First-Admin Onboarding & JWT Session Revocation Lifecycle

On a fresh host where `users` is empty (and `AETHERFLOW_WEB_ADMIN_PASSWORD` was not passed to `AetherFlow-Setup`), `POST /api/v1/public/auth/setup` over Apache2 or any non-loopback address fails closed with HTTP `403 SETUP_TOKEN_REQUIRED` unless you pass the one-time `0600` bootstrap token from `/var/lib/aetherflow/.setup-bootstrap-token` (or `AETHERFLOW_SETUP_TOKEN`) via `setup_token` or `X-AetherFlow-Setup-Token`. Direct unproxied loopback (`127.0.0.1:8080`) requests bypass this token until the first admin exists.

```bash
# Create a private 0600 temporary cookie jar (never write session cookies to a predictable /tmp path)
COOKIE_JAR="$(umask 077 && mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

# 1. Login and capture the HttpOnly aetherflow_session cookie (for accounts without 2FA;
#    TOTP-enrolled accounts return requires_mfa + mfa_token for /api/v1/public/auth/mfa/verify)
curl -fsS -c "$COOKIE_JAR" -X POST \
  https://your-server/api/v1/public/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"..."}' >/dev/null

# 2. Fetch a CSRF token and logout (records JTI in SQLite revoked_tokens)
CSRF=$(curl -fsS -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  https://your-server/api/v1/public/csrf-token | jq -r '.csrf_token')
curl -fsS -b "$COOKIE_JAR" -X POST \
  -H "X-CSRF-Token: $CSRF" \
  https://your-server/api/v1/auth/logout

# 3. Verify the revoked session cookie is immediately rejected
curl -s -o /dev/null -w "%{http_code}\n" \
  -b "$COOKIE_JAR" \
  https://your-server/api/v1/auth/settings
# Expected: 401
```

### Encryption at Rest (`enc:v1:`)

```bash
# Verify API keys are stored encrypted in SQLite
sudo -u aetherflow sqlite3 /var/lib/aetherflow/aetherflow.sqlite \
  "SELECT gemini_api_key FROM settings WHERE id = 1;"
# Expected: enc:v1:<base64(nonce || ciphertext)> (never plaintext)
```

---

## 6. Rollback Plan

> [!CAUTION]
> Do **not** remove `AES_MASTER_KEY`, `JWT_SECRET`, or `ALLOWED_HOSTS`, and do **not** downgrade encryption or authentication to plaintext/fail-open modes. Preserve the original encryption key during rollback. In v4.0.0, `af-db::init_aes_key` fails closed whenever `AES_MASTER_KEY` is missing or malformed under `AETHERFLOW_ENV=production` / `AETHERFLOW_ENV=release`, and `af-api` (`validate_startup_jwt_secret`) fails closed at startup whenever `JWT_SECRET` is unset or shorter than `32` bytes. Always explicitly validate `/etc/aetherflow/aetherflow.env` before and after rollback.

If an issue is encountered after deployment, execute an atomic rollback to `.previous_release` with WAL-safe database integrity verification (on hosts with a custom `PORT`, run `sudo env HEALTH_ENDPOINT=http://127.0.0.1:<port>/health/ready af release rollback --local` or pass `--config <external-conf>` because `--local` ignores `HEALTH_ENDPOINT` in `aetherflow.env` and Debian/Ubuntu `sudo` strips shell exports via `env_reset`; if rollback aborts in `Stage4Rollback` due to `aetherflow-log-retention.service`, inspect `journalctl -u aetherflow-log-retention.service`, fix managed log files under `/var/log/aetherflow` to `root:aetherflow` `0640` with no symlinks/hardlinks, and re-run):

```bash
sudo af release rollback --local
sudo af release status
```

---

*Baseline checklist anchored 2026-11-03 (AetherFlow v4.0.0)*
