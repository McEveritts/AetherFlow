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
| `/opt/AetherFlow/releases/<epoch>` | `root:aetherflow` (`0755`) | Immutable versioned release directories containing `aetherflow-api`, `bin/af`, `bin/speedtest-backend`, `web/dist/`, `config/`, `packages/`, `deploy/`, `plugins/telemetry-inspector/`, `.version`, and `data-snapshot/`. |
| `/opt/AetherFlow/current` | Symlink | Atomic symlink pointing to the active `/opt/AetherFlow/releases/<epoch>` directory. |
| `/usr/local/bin/af` | `root:root` (`0755`) | Installed CLI entrypoint delegating to `/opt/AetherFlow/current/bin/af` (with legacy `/opt/AetherFlow/current/af` and `af-*` fallback compatibility). |
| `/etc/aetherflow/aetherflow.env` | `root:aetherflow` (`0640`) | Protected environment file containing `JWT_SECRET`, `AES_MASTER_KEY`, `DB_PATH`, and `ALLOWED_HOSTS`. Never overwritten by upgrades. |
| `/var/lib/aetherflow/aetherflow.sqlite` | `aetherflow:aetherflow` (`0660`) | Primary SQLite database in `WAL` mode (including `users`, `settings`, `revoked_tokens`, `audit_log`, and metrics history). |
| `/run/aetherflow/runner.sock` | `root:aetherflow` (`0660`) | Unix domain socket for the privileged `aetherflow-runner.service` (`aetherflow-api runner`) daemon. |

---

## 2. Environment Variables

Configure runtime variables in `/etc/aetherflow/aetherflow.env` (`chmod 0640`, owned by `root:aetherflow`).

### Required Variables

| Variable | Description | Validation & Fail-Closed Behavior |
| --- | --- | --- |
| `JWT_SECRET` | Session JWT signing secret | Must be at least 32 cryptographically random bytes. `aetherflow-api` (`validate_startup_jwt_secret`) fails closed at startup if `JWT_SECRET` is unset or shorter than 32 bytes. |
| `AES_MASTER_KEY` | AES-256-GCM key for encrypted provider API keys | Exactly 32 raw bytes, 64 hex characters (32 decoded bytes), or base64 decoding to 32 bytes. `af-db::init_aes_key` fails closed under `AETHERFLOW_ENV=production` / `release` when unset, and always stops initialization on invalid nonempty keys. |
| `AF_DB_PATH` / `DB_PATH` / `AETHERFLOW_DB_PATH` | Absolute path to the live SQLite database | Shared resolution uses this precedence, rejects conflicting overrides, and enforces an isolated root when supplied. Installed units default to `/var/lib/aetherflow/aetherflow.sqlite`. |
| `ALLOWED_HOSTS` | Comma-separated allowlist of HTTP `Host` header values | Validated by host-check middleware (`localhost,localhost:8080,127.0.0.1,127.0.0.1:8080,<your-domain>`). Spoofed `Host` headers are rejected with HTTP `400`. |

### Optional Runtime Variables

| Variable | Description | Default |
| --- | --- | --- |
| `AF_MCBROWSER_ROOT` | Dedicated private directory for Native McBrowser storage | `/var/lib/aetherflow/mcbrowser` (`0700`) |
| `PORT` | TCP port for `aetherflow-api` | `8080` |
| `BIND_ADDR` | Bind address for the HTTP listener | Set `127.0.0.1` behind Apache2. The normal runtime fallback is `0.0.0.0`; isolated E2E mode uses loopback. |
| `ALLOWED_CORS_ORIGIN` | Comma-separated allowed CORS origins | Localhost origins (`http://localhost:8080`, etc.) |
| `COOKIE_SECURE` | Set `Secure` attribute on auth cookies | `true` in production HTTPS deployments |
| `AETHERFLOW_RUNNER_SOCK` | Path to the privileged runner Unix socket | `/run/aetherflow/runner.sock` |
| `PRIVILEGED_RUNNER_ENABLED` | Enables privileged runner readiness probing alongside SQLite (`1`, `true`, `yes`, `on`, trimmed and case-insensitive) | `false` (`aetherflow-api.service` sets `true`) |
| `AF_GITHUB_TOKEN` | Optional token for GitHub release discovery (falls back to `GITHUB_TOKEN`, `GH_TOKEN`) | Unauthenticated public API requests |

### Generating Cryptographic Secrets

```bash
# Generate JWT_SECRET (32 random bytes, hex-encoded = 64 characters)
openssl rand -hex 32

# Generate AES_MASTER_KEY (32 random bytes, base64-encoded)
openssl rand -base64 32
```

---

### Release & Self-Update Safety (`af-release` & `aetherflow-self-update-<command>-<channel>-<job>.service`)

- CI release archives and `af-release` normalize extracted directories to `0755`, remove group/other write access from files, set executable bits (`0755`) on `aetherflow-api`, `af`, `deploy/release-manager.sh`, `packages/system/*`, and `packages/package/*`, and verify service-user access before switching `/opt/AetherFlow/current`.
- Self-updates launch in an independent `aetherflow-self-update-<command>-<channel>-<job>.service` systemd unit with protected configuration and durable job-status receipts so restarting `aetherflow-runner` and `aetherflow-api` never terminates the in-flight updater.
- Stable deployments resolve GitHub's public `/releases/latest` redirect when the REST API is rate-limited.
- API update checks share a 5-minute cache, cache transient failures for 1 minute, and honor `X-RateLimit-Reset` and `Retry-After` headers (`error: github_rate_limited`, `retryAt`).

## 3. Systemd Units & Privilege Separation

AetherFlow v4.0 splits execution across two hardened systemd units installed from `/opt/AetherFlow/current/deploy/systemd/`:

1. **`aetherflow-api.service` (Unprivileged Control Plane)**
   - Runs as `User=aetherflow`, `Group=aetherflow`.
   - `WorkingDirectory=/opt/AetherFlow/current`
   - `ExecStart=/opt/AetherFlow/current/aetherflow-api`
   - The packaged unit enables `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, `ProtectControlGroups=yes`, `ProtectKernelTunables=yes`, and `RestrictSUIDSGID=yes`. Inspect the actual installed unit; additional sandbox flags are not implied.
   - `ReadWritePaths=/var/lib/aetherflow /var/log/aetherflow /run/aetherflow`
2. **`aetherflow-runner.service` (Privileged Host Daemon)**
   - Runs `ExecStart=/opt/AetherFlow/current/aetherflow-api runner`.
   - The daemon creates `/run/aetherflow/runner.sock` with mode `0660`; this is not a systemd socket-activation unit. Socket permissions and the daemon's peer/operation authorization both require verification.
   - Executes strictly allowlisted package lifecycle, service control, quota, sandbox, backup/restore, and self-update requests without exposing `sudo` or arbitrary shell execution to the `aetherflow` web user.

Verify unit configuration and sandbox paths before starting:

```bash
systemctl cat aetherflow-api.service | grep -E "WorkingDirectory|ExecStart|ProtectSystem|ReadWritePaths"
systemctl cat aetherflow-runner.service | grep -E "WorkingDirectory|ExecStart"
```

---

## 4. Deployment Procedure

### 1. Set Environment Variables
Ensure all required variables are populated in `/etc/aetherflow/aetherflow.env` with mode `0640`, owned by `root:aetherflow` (matching `setup/modules/modern_stack.sh`).

### 2. Build or Pull a Verified Release

```bash
# With the pinned WASM tools on PATH, build the release bundle and SHA256SUMS.
bash scripts/build_gold.sh

# Or deploy directly via the unified Rust CLI / release manager
sudo af release deploy --local --channel stable
```

### 3. Verify Systemd Sandbox & Socket Permissions

Verify that `aetherflow-api.service` runs under `ProtectSystem=strict` and `aetherflow-runner.service` owns `/run/aetherflow/runner.sock`:

```bash
systemctl cat aetherflow-api.service | grep -E "ProtectSystem|StateDirectory|NoNewPrivileges"
ls -l /run/aetherflow/runner.sock
# Expected: srw-rw---- 1 root aetherflow ... /run/aetherflow/runner.sock
```

### 4. Verify Readiness & Running Binary Identity

```bash
curl -s http://127.0.0.1:8080/health/ready | jq
sudo af release status
```

Expected `/health/ready` response:
```json
{
  "database": "ok",
  "runner": "ok",
  "redis": "disabled",
  "status": "ready",
  "uptime": "12.4s",
  "version": "v4.0.0"
}
```

- `runner` reports `"ok"`, `"unreachable"`, or `"disabled"`. With `PRIVILEGED_RUNNER_ENABLED` set to a trimmed, case-insensitive `1`, `true`, `yes`, or `on` (set to `true` in `aetherflow-api.service`), SQLite and the runner socket (`/v1/health`) are checked concurrently under two-second budgets; with it unset or false, `runner` is `"disabled"` and SQLite alone determines readiness.
- If a required check fails, both `/health/ready` and `/api/v1/auth/ready` (`Cache-Control: no-store` on `200` and `503`) return HTTP `503` with `"status": "not_ready"`, while keeping `"database": "ok"` when only the runner is unreachable.

---

## Post-Deployment Security Verification

### Binary Baseline & Reproducibility

- Prebuilt release archives (`aetherflow-linux-amd64.tar.gz`) must be built against the **Ubuntu 22.04 (`GLIBC 2.35`)** baseline (`.github/workflows/release.yml` and `.github/workflows/ci.yml`) so dynamically linked binaries run across Ubuntu 22.04, Ubuntu 24.04, Debian 12, Debian 13, and Kali Linux.
- All release and source builds require a committed workspace `backend-rs/Cargo.lock` and compile with `--locked` (`cargo test --workspace --locked`, `cargo build --release --locked --bin aetherflow-api --bin af --bin speedtest-backend`).
- Release archives package `aetherflow-api`, `bin/af`, and `bin/speedtest-backend`, external `web/dist/`, canonical `config/`, `packages/`, `deploy/`, `plugins/telemetry-inspector/`, and `.version`, accompanied by `SHA256SUMS` and GitHub build provenance attestations.

### Fresh Installation (`setup/AetherFlow-Setup`)

- By default, `setup/AetherFlow-Setup` pulls and verifies the prebuilt v4 release archive and `SHA256SUMS` manifest for the selected channel (`--channel stable|nightly`) without installing Go or Node.js compilers on the target host.
- If archive download, SHA-256 verification, or tar preflight validation (which rejects symlinks, hardlinks, device nodes, absolute paths, and `..` traversal) fails, the installer **fails closed** and never falls back to an unverified download, a legacy `v3.x` tag, or an implicit source build.
- Building from source on a host requires explicit opt-in (`bash AetherFlow-Setup --from-source` or `AETHERFLOW_BUILD_FROM_SOURCE=1`) and a locked `backend-rs/Cargo.lock`.

### Atomic Upgrades (`deploy/release-manager.sh` / `af release`)

```bash
# Dry-run upgrade check against live database (read-only online backup into isolated sandbox)
sudo /opt/AetherFlow/current/deploy/release-manager.sh deploy --channel nightly --dry-run

# Live atomic upgrade
sudo /opt/AetherFlow/current/deploy/release-manager.sh deploy --channel nightly
```

During every deployment:
1. **Lock Serialization**: Acquires `/opt/AetherFlow/releases/.release.lock` and the shared `/run/aetherflow/.snapshot.lock` (or an explicitly configured, protected maintenance-lock path). The runtime lock anchor is root-owned; the service-owned data directory is not repurposed as a root lock anchor.
2. **Stage 0 & 1**: Verifies `SHA256SUMS`, validates tar entries against symlink/traversal attacks, extracts into `/opt/AetherFlow/releases/<epoch>`, and verifies `aetherflow` service-user read/execute access.
3. **Stage 1.5**: Captures a WAL-safe online SQLite backup (`sqlite3 --readonly .backup` / `rusqlite::backup::Backup`), verifies `PRAGMA integrity_check == ok`, and writes `data-snapshot/MANIFEST.sha256`.
4. **Stage 2 & 3**: Atomically swaps `/opt/AetherFlow/current`, updates `/usr/local/bin/af`, restarts `aetherflow-runner.service` and `aetherflow-api.service`, and polls `http://127.0.0.1:8080/health/ready` (the default in `deploy/release-manager.conf`, `af-release`, and the standalone `deploy/release-manager.sh` fallback). Explicit `HEALTH_ENDPOINT` overrides are preserved; any override used for deployment must report full application readiness to supply an equivalent gate. Rollback preserves acceptance of older supported v4 readiness replies containing `{"status":"ready"}` or `{"status":"ok"}`.

---

## 5. Post-Deployment Verification

### Readiness and Dashboard Serving

```bash
# 1. Deep readiness probe (verifies SQLite pool health and enabled privileged runner health)
curl -fsS http://127.0.0.1:8080/health/ready
# Expected JSON: {"database":"ok","runner":"ok","redis":"disabled","status":"ready","uptime":"...","version":"..."}

# 2. Verify the WASM dashboard entry point is served.
curl -fsSI http://127.0.0.1:8080/

# 3. Verify native CLI version and health.
af health
```

### Authentication & SQLite Token Revocation (`revoked_tokens`)

AetherFlow v4.0 persists revoked JWT `jti` identifiers in the SQLite `revoked_tokens` table (Redis is not required for session revocation).

```bash
# 1. Verify spoofed Host header is rejected
curl -s -o /dev/null -w "%{http_code}" \
  -H "Host: evil.example.com" \
  https://your-server/api/v1/public/marketplace
# Expected: 400

# 2. Verify unauthenticated access to protected routes is blocked
curl -s -o /dev/null -w "%{http_code}\n" \
  http://127.0.0.1:8080/api/v1/auth/settings
# Expected: 401

# 3. Verify logout records JWT revocation in SQLite revoked_tokens
sqlite3 /var/lib/aetherflow/aetherflow.sqlite \
  "SELECT COUNT(*) FROM revoked_tokens;"
```

### JWT Session & SQLite Revocation Lifecycle

```bash
# 1. Login and capture the HttpOnly aetherflow_session cookie (for accounts without 2FA;
#    TOTP-enrolled accounts return requires_mfa + mfa_token for /api/v1/public/auth/mfa/verify)
curl -fsS -c /tmp/af-cookies.txt -X POST \
  https://your-server/api/v1/public/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"..."}' >/dev/null

# 2. Fetch a CSRF token and logout (records JTI in SQLite revoked_tokens)
CSRF=$(curl -fsS -b /tmp/af-cookies.txt -c /tmp/af-cookies.txt \
  https://your-server/api/v1/public/csrf-token | jq -r '.csrf_token')
curl -fsS -b /tmp/af-cookies.txt -X POST \
  -H "X-CSRF-Token: $CSRF" \
  https://your-server/api/v1/auth/logout

# 3. Verify the revoked session cookie is immediately rejected
curl -s -o /dev/null -w "%{http_code}\n" \
  -b /tmp/af-cookies.txt \
  https://your-server/api/v1/auth/settings
# Expected: 401
rm -f /tmp/af-cookies.txt
```

### Encryption at Rest (`enc:v1:`)

```bash
# Verify API keys are stored encrypted in SQLite
sudo sqlite3 /var/lib/aetherflow/aetherflow.sqlite \
  "SELECT gemini_api_key FROM settings WHERE id = 1;"
# Expected: enc:v1:<nonce>:<ciphertext> (never plaintext)
```

---

## Rollback Plan

> Do **not** remove `AES_MASTER_KEY`, `JWT_SECRET`, or `ALLOWED_HOSTS`, and do **not** downgrade encryption or authentication to plaintext/fail-open modes. Preserve the original encryption key during rollback. In v4.0.0, `af-db::init_aes_key` fails closed whenever `AES_MASTER_KEY` is missing or malformed under `AETHERFLOW_ENV=production` / `AETHERFLOW_ENV=release`, and `af-api` (`validate_startup_jwt_secret`) fails closed at startup whenever `JWT_SECRET` is unset or shorter than `32` bytes. Always explicitly validate `/etc/aetherflow/aetherflow.env` before and after rollback.


If an issue is encountered after deployment, execute an atomic rollback to `.previous_release` with WAL-safe database integrity verification:

```bash
sudo af release rollback --local
sudo af release status
```

---

*Last updated: 2026-11-03 (AetherFlow v4.0.0)*
