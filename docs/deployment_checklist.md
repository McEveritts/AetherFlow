# AetherFlow Security Deployment Checklist

## Pre-Deployment

### Environment Variables (`/etc/aetherflow/aetherflow.env`, mode `0600`)

#### Required
| Variable | Description | Validation |
| --- | --- | --- |
| `JWT_SECRET` | HS256 JWT signing secret | $\ge 32$ bytes, cryptographically random |
| `AES_MASTER_KEY` | AES-256-GCM encryption key for secrets at rest (`enc:v1:`) | Exactly 32 bytes (raw 32-char or Base64-encoded 32 bytes) |
| `ALLOWED_HOSTS` | Comma-separated allowed `Host` header values | Must include production domain(s) and LAN/public IP if accessed directly |

#### Recommended
| Variable | Description | Default |
| --- | --- | --- |
| `AF_DB_PATH` | Live SQLite WAL database path | `/var/lib/aetherflow/aetherflow.sqlite` |
| `AF_MCBROWSER_ROOT` | Dedicated `0700` directory for Native McBrowser storage | `/var/lib/aetherflow/mcbrowser` |
| `AETHERFLOW_BASE_DOMAIN` | Base domain for automatic `<app>.<baseDomain>` subdomain ingress | Configured in UI / Setup |
| `COOKIE_SECURE` | HTTPS-only session cookies | `true` |
| `OIDC_ISSUER` | OIDC issuer URL for downstream SSO | Auto-detected from request |
| `ADMIN_EMAIL` | Email for automatic admin role on first OAuth login | None |
| `AF_GITHUB_TOKEN` | Optional token for GitHub update discovery; falls back to `GITHUB_TOKEN`, then `GH_TOKEN` | Unauthenticated requests |

### Release & Self-Update Safety (`af-release` & `aetherflow-self-update.service`)

- CI release archives and `af-release` normalize extracted directories to `0755`, remove group/other write access from files, set executable bits (`0755`) on `aetherflow-api`, `af`, `deploy/release-manager.sh`, `packages/system/*`, and `packages/package/*`, and verify service-user access before switching `/opt/AetherFlow/current`.
- Self-updates launch in an independent `aetherflow-self-update.service` systemd unit with an atomic `0600` environment handoff so restarting `aetherflow-runner` and `aetherflow-api` never terminates the in-flight updater.
- Stable deployments resolve GitHub's public `/releases/latest` redirect when the REST API is rate-limited.
- API update checks share a 5-minute cache, cache transient failures for 1 minute, and honor `X-RateLimit-Reset` and `Retry-After` headers (`error: github_rate_limited`, `retryAt`).

### Generate Secrets

```bash
# Generate JWT_SECRET (32 random bytes, hex-encoded)
openssl rand -hex 32

# Generate AES_MASTER_KEY (32 random bytes, Base64-encoded)
openssl rand -base64 32
```

---

## Deployment Steps

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

### Authentication & Authorization

```bash
# 1. Verify spoofed Host header is rejected
curl -s -o /dev/null -w "%{http_code}" \
  -H "Host: evil.example.com" \
  https://your-server/api/v1/public/marketplace
# Expected: 400

# 2. Verify unauthenticated access is blocked
curl -s -o /dev/null -w "%{http_code}" \
  https://your-server/api/v1/auth/settings
# Expected: 401

# 3. Verify admin endpoint with regular user token
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
  https://your-server/api/v1/admin/users
# Expected: 403
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

If an issue is encountered after deployment, execute an atomic rollback to `.previous_release` with WAL-safe database integrity verification:

```bash
sudo af release rollback --local
sudo af release status
```

---

*Last updated: 2026-11-03 (AetherFlow v4.0.0)*
