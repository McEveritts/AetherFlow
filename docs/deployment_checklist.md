# AetherFlow Security Deployment Checklist

## Pre-Deployment

### Environment Variables (Required)

| Variable | Description | Validation |
| --- | --- | --- |
| `JWT_SECRET` | JWT signing secret | ≥32 bytes, cryptographically random |
| `AES_MASTER_KEY` | AES-256 encryption key for API keys at rest | Exactly 32 bytes (raw or base64-encoded) |
| `ALLOWED_HOSTS` | Comma-separated allowed Host header values | Must include production domain(s) |
| `GIN_MODE` | Gin framework mode | Set to `release` for production |

### Environment Variables (Recommended)

| Variable | Description | Default |
| --- | --- | --- |
| `REDIS_PASSWORD` | Redis authentication password | Empty (no auth) |
| `REDIS_ADDR` | Redis server address | `localhost:6379` |
| `COOKIE_SECURE` | HTTPS-only cookies | `true` |
| `CSRF_ENABLED` | Enable CSRF middleware | `false` |
| `OIDC_ISSUER` | OIDC issuer URL | Auto-detected from request |
| `ADMIN_EMAIL` | Email for auto-admin role | None |

### Generate Secrets

```bash
# Generate JWT_SECRET (32 random bytes, hex-encoded)
openssl rand -hex 32

# Generate AES_MASTER_KEY (32 random bytes, base64-encoded)
openssl rand -base64 32
```

---

## Deployment Steps

### 1. Set Environment Variables

Ensure all required variables are set in your `.env` or deployment config.

### 2. Redis Connectivity

```bash
# Verify Redis is reachable
redis-cli -a $REDIS_PASSWORD -h $REDIS_ADDR ping
# Expected: PONG
```

### 3. Database Migration — Encrypted API Keys

The `DecryptKey()` function has a built-in backwards-compatibility fallback:
- If the stored value is plaintext (not valid base64 or GCM decryption fails), it returns the raw value
- New keys saved via the Settings UI will be automatically encrypted
- **No explicit migration script is needed** — the system handles the transition seamlessly

To force-encrypt existing plaintext keys after setting `AES_MASTER_KEY`:
1. Open the AetherFlow Dashboard → Settings
2. Clear and re-enter your AI Provider API keys (Gemini, OpenAI, Anthropic)
3. Click Save — the keys will be stored encrypted

### 4. Build and Deploy

```bash
cd backend
GIN_MODE=release go build -o dist/aetherflow-api .
```

### 5. Verify systemd Sandbox Permissions

If your `aetherflow-api.service` uses `ProtectSystem=strict` (recommended for production), verify that `ReadWritePaths` includes all directories the backend needs to write to:
```bash
systemctl cat aetherflow-api.service | grep -E "ProtectSystem|ReadWritePaths"
# Expected:
# ProtectSystem=strict
# ReadWritePaths=/opt/AetherFlow /opt/AetherFlow_releases
```

> [!WARNING]
> Missing `ReadWritePaths` entries will **not** cause a startup failure. The service will boot normally but panic on the first SQLite write operation (e.g., credential initialization). See [Troubleshooting §6](./troubleshooting.md) for details.

### 6. Zero-Downtime Strategy

1. Deploy with all env vars set (especially `AES_MASTER_KEY`)
2. The system will:
   - Automatically decrypt both plaintext and encrypted API keys
   - Encrypt any newly saved API keys
   - Start the Redis JWT blacklist
   - Enforce host header validation
3. No database schema migration required
4. Rolling restart is safe — JWT tokens are stateless except for blacklist checks

---

## Post-Deployment Verification

### Authentication & Authorization

```bash
# 1. Verify spoofed Host header is rejected
curl -s -o /dev/null -w "%{http_code}" \
  -H "Host: evil.com" \
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

### JWT Lifecycle

```bash
# 1. Login and inspect JWT
TOKEN=$(curl -s -X POST \
  https://your-server/api/v1/public/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"..."}' | jq -r '.token')

# 2. Decode JWT and verify claims
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq .
# Expected: exp = 15 minutes from now, jti = UUID

# 3. Logout
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  https://your-server/api/v1/auth/auth/logout

# 4. Verify token is blacklisted
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  https://your-server/api/v1/auth/settings
# Expected: 401 (session revoked)

# 5. Verify blacklist in Redis
redis-cli -a $REDIS_PASSWORD GET "blacklist:$JTI_FROM_STEP_2"
# Expected: "true"
```

### Encryption

```bash
# Verify API keys are stored encrypted in SQLite
sqlite3 /path/to/aetherflow.sqlite \
  "SELECT gemini_api_key FROM settings WHERE id = 1;"
# Expected: Base64-encoded ciphertext (NOT plaintext API key)
```

---

## Security Monitoring

### Log Indicators

Watch for these log messages at startup:

| Message | Meaning | Action |
| --- | --- | --- |
| `AES-256-GCM encryption key loaded successfully.` | Encryption active | None |
| `WARNING: AES_MASTER_KEY not set.` | Encryption disabled | Set key immediately if production |
| `FATAL: AES_MASTER_KEY is required in production` | Server halted | Set the AES key |
| `Redis connected successfully.` | Blacklist active | None |
| `WARNING: Redis is unavailable` | Blacklist degraded | Check Redis connectivity |
| `WARNING: No billing webhook secret configured` | Webhooks unprotected | Set billing secrets |

### Runtime Security Events

Monitor logs for:
- `CSRF validation failed:` — Potential CSRF attack attempt
- `CRITICAL: crypto/rand failure` — System entropy exhaustion (critical)
- Authentication failures from unusual IPs in `login_history` table

---

## Rollback Plan

If issues are encountered:
1. **AES Key Issues**: Remove `AES_MASTER_KEY` and restart — system degrades to plaintext mode
2. **Redis Issues**: System automatically fails-open if Redis goes down
3. **Host Validation Issues**: Remove `ALLOWED_HOSTS` env var — allows all hosts (dev mode)
4. **CSRF Issues**: Remove `CSRF_ENABLED` env var — disables CSRF middleware

All security features are designed with safe fallback mechanisms to prevent total lockout.

---

*Last updated: 2026-04-02*
*Document owner: Security Architecture*
