# AetherFlow v4.0 Security & Deployment Checklist

This checklist documents the runtime architecture, configuration contracts, privilege boundaries, and operational procedures for the **AetherFlow v4.0 Rust Control Plane** (`aetherflow-api` and `af` CLI).

> [!IMPORTANT]
> **Verification & Evidence Policy**
> Code changes, unit tests, or mocked filesystem drills do not by themselves certify production readiness across all target distributions. Refer to [docs/v4-backlog-verification.md](./v4-backlog-verification.md) and [docs/v4-clean-host-testing.md](./v4-clean-host-testing.md) for the current verification ledger and clean-OS KVM test status.

---

## 1. Architecture & Filesystem Layout (FHS)

AetherFlow v4.0 replaces the legacy Go (`Gin`) + separate Next.js/PM2 stack with a single embedded Rust binary (`aetherflow-api`) and native administrative CLI (`af`), running behind **Apache2** reverse-proxy ingress (`127.0.0.1:8080`) with **SQLite WAL** persistence.

| Path | Owner / Mode | Purpose |
| --- | --- | --- |
| `/opt/AetherFlow/releases/<epoch>` | `root:aetherflow` (`0755`) | Immutable versioned release directories containing `aetherflow-api`, `af` (`bin/af`), `config/`, `packages/`, `deploy/`, `.version`, and `data-snapshot/`. |
| `/opt/AetherFlow/current` | Symlink | Atomic symlink pointing to the active `/opt/AetherFlow/releases/<epoch>` directory. |
| `/usr/local/bin/af` | `root:root` (`0755`) | Installed CLI entrypoint delegating to `/opt/AetherFlow/current/af` (with legacy `af-*` fallback compatibility). |
| `/etc/aetherflow/aetherflow.env` | `root:aetherflow` (`0640`) | Protected environment file containing `JWT_SECRET`, `AES_MASTER_KEY`, `DB_PATH`, and `ALLOWED_HOSTS`. Never overwritten by upgrades. |
| `/var/lib/aetherflow/aetherflow.sqlite` | `aetherflow:aetherflow` (`0660`) | Primary SQLite database in `WAL` mode (including `users`, `settings`, `revoked_tokens`, `audit_log`, and metrics history). |
| `/run/aetherflow/runner.sock` | `root:aetherflow` (`0660`) | Unix domain socket for the privileged `aetherflow-runner.service` (`aetherflow-api runner`) daemon. |

---

## 2. Environment Variables

Configure runtime variables in `/etc/aetherflow/aetherflow.env` (`chmod 0640`, owned by `root:aetherflow`).

### Required Variables

| Variable | Description | Validation & Fail-Closed Behavior |
| --- | --- | --- |
| `JWT_SECRET` | Session JWT signing secret | Supply at least 32 cryptographically random bytes. The current helper uses an ephemeral process secret when unset and does not enforce a minimum configured length; deployment must enforce this requirement. |
| `AES_MASTER_KEY` | AES-256-GCM key for encrypted provider API keys | Exactly 32 raw bytes or base64 decoding to exactly 32 bytes. Hex strings and arbitrary passphrases are not supported. Invalid nonempty keys stop initialization. |
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
Ensure all required variables are populated in `/etc/aetherflow/aetherflow.env` with mode `0600` (`chown root:aetherflow` or `aetherflow:aetherflow`).

### 2. Build or Pull Verified Single-Binary Release

```bash
# Build production single-binary Rust bundle (aetherflow-api + af + SHA256SUMS)
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
  "redis": "disabled",
  "status": "ready",
  "uptime": "12.4s",
  "version": "v4.0.0"
}
```

---

## Post-Deployment Security Verification

### Binary Baseline & Reproducibility

- Prebuilt release archives (`aetherflow-linux-amd64.tar.gz`) must be built against the **Ubuntu 22.04 (`GLIBC 2.35`)** baseline (`.github/workflows/release.yml` and `.github/workflows/ci.yml`) so dynamically linked binaries run across Ubuntu 22.04, Ubuntu 24.04, Debian 12, Debian 13, and Kali Linux.
- All release and source builds require a committed workspace `backend-rs/Cargo.lock` and compile with `--locked` (`cargo test --workspace --locked`, `cargo build --release --locked --bin aetherflow-api --bin af`).
- Release archives package both `aetherflow-api` and `af` (`./af` and `./bin/af`), canonical `config/`, `packages/`, `deploy/`, and `.version`, accompanied by `SHA256SUMS` and GitHub build provenance attestations.

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
4. **Stage 2 & 3**: Atomically swaps `/opt/AetherFlow/current`, updates `/usr/local/bin/af`, restarts `aetherflow-runner.service` and `aetherflow-api.service`, and polls `http://127.0.0.1:8080/health/ready`.

---

## 5. Post-Deployment Verification

### Readiness & Embedded SPA Serving

```bash
# 1. Deep readiness probe (verifies SQLite pool health)
curl -fsS http://127.0.0.1:8080/health/ready
# Expected JSON: {"database":"ok","redis":"disabled","status":"ready","uptime":"..."}

# 2. Verify native CLI version and health
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
# 1. Login and inspect JWT
TOKEN=$(curl -s -X POST \
  https://your-server/api/v1/public/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"..."}' | jq -r '.token')

# 2. Logout (records JTI in SQLite revoked_tokens)
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  https://your-server/api/v1/auth/auth/logout

# 3. Verify revoked token is immediately rejected
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  https://your-server/api/v1/auth/settings
# Expected: 401
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

> Do **not** remove `AES_MASTER_KEY`, `JWT_SECRET`, or `ALLOWED_HOSTS`, and do **not** downgrade encryption or authentication to plaintext/fail-open modes. Preserve the original encryption key during rollback. Missing-secret handling is not uniformly fail-closed: the current AES initializer permits an unset key unless the compatibility variable `GIN_MODE=release` is set, while an unset JWT secret produces a process-local key. Explicitly validate production configuration rather than relying on startup rejection.


If an issue is encountered after deployment, execute an atomic rollback to `.previous_release` with WAL-safe database integrity verification:

```bash
sudo af release rollback --local
sudo af release status
```

---

*Last updated: 2026-11-03 (AetherFlow v4.0.0)*
