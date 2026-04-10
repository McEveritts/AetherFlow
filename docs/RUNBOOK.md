# AetherFlow Operational Runbook

> **Version**: v3.1.0 · **Last Updated**: Phase 28 Week 4  
> **Audience**: System administrators and operators managing AetherFlow bare-metal deployments.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Startup Sequence](#startup-sequence)
3. [Health Checks](#health-checks)
4. [Service Recovery (af-heal)](#service-recovery-af-heal)
5. [Authentication & Sessions](#authentication--sessions)
6. [OIDC Provider](#oidc-provider)
7. [Backup Operations](#backup-operations)
8. [Database Maintenance](#database-maintenance)
9. [Notification Channels](#notification-channels)
10. [Monitoring & Telemetry](#monitoring--telemetry)
11. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
┌─────────────────────────────────────────────┐
│                AetherFlow                     │
│                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐│
│  │ Gin HTTP │  │ WebSocket│  │ gRPC Cluster ││
│  │ :3000    │  │ /ws      │  │ :50051       ││
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘│
│       │              │               │        │
│  ┌────┴──────────────┴───────────────┴──────┐│
│  │           Service Layer                   ││
│  │  af-heal · metrics · notifications        ││
│  │  lifecycle · plugins                      ││
│  └────┬──────────────────────────────┬──────┘│
│       │                              │        │
│  ┌────┴──────┐              ┌───────┴──────┐ │
│  │ SQLite    │              │ Redis        │ │
│  │ WAL mode  │              │ (optional)   │ │
│  └───────────┘              └──────────────┘ │
└─────────────────────────────────────────────┘
```

| Component | Port | Purpose |
|-----------|------|---------|
| HTTP API | 3000 | REST API + static frontend |
| WebSocket | 3000/ws | Real-time metrics, logs, notifications |
| gRPC | 50051 | Cluster node communication |
| SQLite | file | Primary data store (WAL mode) |
| Redis | 6379 | Session revocation cache (optional) |

---

## Startup Sequence

### Prerequisites
- Go 1.22+ runtime
- Node.js 20+ (frontend build only)
- Linux (systemd) or WSL Debian

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_PATH` | No | `data/aetherflow.sqlite` | SQLite database path |
| `JWT_SECRET` | **Yes** | — | 32+ char secret for JWT signing |
| `GIN_MODE` | No | `debug` | Set to `release` for production JSON logs |
| `REDIS_URL` | No | — | Redis connection string for session revocation |
| `AF_HEAL_AUTO_APPROVE` | No | `false` | Set `true` for autonomous healing |

### Boot Order

1. `logging.Init()` — structured logger (JSON in release, text in dev)
2. `config.LoadConfig()` — environment and config file merge
3. `db.InitDB()` — SQLite open, WAL mode, run migrations v1–v11
4. `db.InitRedis()` — optional session revocation cache
5. `services.InitNotificationEngine()` — webhook channels + rule evaluator
6. `services.InitMetricsRecorder()` — 15-min system sampling
7. `services.StartHealWorker()` — af-heal process monitor
8. `db.StartPruneLoop()` — expired data cleanup (every 15 min)
9. `api.SetupRoutes()` — HTTP/WS routes
10. `gin.Run()` — start accepting traffic

---

## Health Checks

### API Health Endpoint

```bash
curl -s http://localhost:3000/api/health | jq
```

Expected response:
```json
{
  "status": "healthy",
  "latency_ms": 0,
  "table_counts": {
    "users": 1,
    "active_sessions": 3,
    "oidc_clients": 2,
    "notifications": 15,
    "metrics_history": 96
  },
  "wal_pages": 0
}
```

### What to check
- `latency_ms > 100` → SQLite under write contention, check WAL checkpoint
- `wal_pages > 1000` → Force checkpoint: `PRAGMA wal_checkpoint(TRUNCATE);`
- Missing tables → Database corruption, restore from backup

---

## Service Recovery (af-heal)

### How it works
1. af-heal polls `GetActiveServices()` every 30 seconds
2. If a service is in `error`/`failed`/`crashed` state → queue restart
3. In **gated mode** (default): creates a `pending_action` requiring admin approval
4. In **auto-approve mode**: executes immediately via `systemctl restart`

### Restart Budget
- **10 restarts per hour per service** — prevents restart storms
- Budget resets every hour automatically
- Exceeded budget → `NotifyCritical` alert + skip

### Approval Flow
```
af-heal detects crash
    → QueueAction("warn", "af-heal", "restart:nginx:systemd", reason)
    → Admin sees in /api/admin/actions/pending
    → POST /api/admin/actions/:id/approve
    → af-heal polls IsActionApproved() every 10s
    → executes systemctl restart
    → MarkActionExecuted() on success / MarkActionFailed() on error
```

### Admin Audit Trail
Every approve/reject is recorded in `admin_audit_log`:
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/admin/audit-log?limit=20 | jq '.entries'
```

---

## Authentication & Sessions

### JWT Lifecycle
| Property | Value |
|----------|-------|
| Algorithm | HS256 |
| TTL | 15 minutes |
| Fingerprint | `cfp` claim (client fingerprint binding) |
| Refresh | Client must re-authenticate |

### Session Revocation
- Redis-backed (`session:revoked:{jti}` key with TTL)
- `AuthMiddleware` checks revocation on every request
- Error code: `AUTH_SESSION_REVOKED`

### Error Codes (Machine-Readable)

| Code | Meaning |
|------|---------|
| `AUTH_TOKEN_MISSING` | No Authorization header |
| `AUTH_TOKEN_INVALID` | Malformed or expired JWT |
| `AUTH_SESSION_REVOKED` | Session revoked via Redis |
| `AUTH_FINGERPRINT_MISMATCH` | Client fingerprint changed |
| `FORBIDDEN` | Non-admin accessing admin route |

---

## OIDC Provider

### Key Management
- RSA 2048-bit key persisted to `data/oidc_rsa.pem`
- `kid` = SHA-256 thumbprint of public key (JWK spec)
- Key survives restarts (loaded from disk on boot)

### Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/openid-configuration` | Discovery document |
| `GET /api/oidc/authorize` | Authorization code flow |
| `POST /api/oidc/token` | Token exchange |
| `GET /api/oidc/userinfo` | User info |
| `GET /api/oidc/jwks` | JWKS public keys |
| `POST /api/oidc/revoke` | Token revocation |

### Rate Limiting
- Token endpoint: **10 requests/minute** per IP (`oidcLimiter`)
- Error code: `RATE_LIMITED`

### Consent Persistence
- Stored in `oidc_consents` table (migration v7)
- Keyed by `(user_id, client_id)` with granted scopes
- Skip re-consent if scopes are a subset of previously granted

---

## Backup Operations

### Manual Backup
```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/admin/backup/run
```

### Backup Download (Requires Re-Auth)
```bash
curl -H "Authorization: Bearer $TOKEN" \
  -H "X-Reauth-Password: <admin-password>" \
  http://localhost:3000/api/admin/backup/download/backup_2024_01_01.sqlite \
  -o backup.sqlite
```

> **Security**: Backup downloads require re-authentication via `X-Reauth-Password` header to mitigate session riding attacks.

### Backup Verification
- Response includes `X-Checksum-SHA256` header
- Verify: `sha256sum backup.sqlite`

---

## Database Maintenance

### Migration History
The system runs idempotent migrations on startup:

| Version | Description |
|---------|-------------|
| v1-v5 | Core schema (users, services, packages, settings, etc.) |
| v6 | Smart backup next-run time|
| v7 | OIDC consent persistence |
| v8 | Active sessions table |
| v9 | Pending actions (approval gates) |
| v10 | Notification delivery log |
| v11 | Admin audit trail |

### Pruning Schedule
Automatic (every 15 minutes):

| Table | Retention |
|-------|-----------|
| `oidc_auth_codes` | Expired or used |
| `oidc_device_codes` | Expired |
| `oidc_refresh_tokens` | Expired or revoked |
| `active_sessions` | Expired |
| `metrics_history` | 90 days |
| `login_history` | 90 days |
| `billing_webhook_events` | 30 days |

### Manual Checkpoint
```sql
PRAGMA wal_checkpoint(TRUNCATE);
```

---

## Notification Channels

### Supported Types

| Type | Config Keys |
|------|-------------|
| `discord` | `url` (webhook URL) |
| `telegram` | `bot_token`, `chat_id` |
| `slack` | `url` (webhook URL) |
| `custom` | `url` (any HTTP endpoint) |

### Delivery Pipeline
1. Notification dispatched → persisted to `notifications` table
2. Broadcast via WebSocket to connected clients
3. Each enabled channel receives webhook POST (async)
4. Retry: 3 attempts with exponential backoff (1s, 2s, 4s)
5. Delivery result logged to `notification_delivery_log`

### Test a Channel
```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/admin/notifications/channels/1/test
```

---

## Monitoring & Telemetry

### Structured Logging
- **Production** (`GIN_MODE=release`): JSON to stdout
- **Development**: Human-readable text to stdout

Domain-tagged log fields:
```json
{
  "time": "2024-01-01T00:00:00Z",
  "level": "INFO",
  "msg": "recovery orchestrator initialized",
  "domain": "control",
  "component": "af-heal",
  "mode": "GATED",
  "budget": 10,
  "timeout": "30s"
}
```

### Standard Domains

| Domain | Components |
|--------|-----------|
| `control` | af-heal, lifecycle |
| `telemetry` | metrics-recorder |
| `notifications` | engine |
| `identity` | auth, oidc (migration pending) |
| `storage` | backup (migration pending) |

### WebSocket Real-Time Feeds

| Endpoint | Data |
|----------|------|
| `/api/ws` | System metrics (CPU, memory, disk, network) |
| `/api/ws/logs` | Live log stream |

WebSocket tickets: 30-second TTL, single-use, IP-bound.

---

## Troubleshooting

### Common Issues

**Service won't start**
```bash
journalctl -u aetherflow -n 50 --no-pager
```
Check for: missing `JWT_SECRET`, database lock, port conflict.

**Database locked errors**
```bash
# Force WAL checkpoint
sqlite3 data/aetherflow.sqlite "PRAGMA wal_checkpoint(TRUNCATE);"
```
Connection pool is set to `MaxOpenConns=1` by design.

**af-heal not restarting services**
1. Check `AF_HEAL_AUTO_APPROVE` — is gated mode enabled?
2. Check restart budget — `GET /api/admin/actions/pending?status=all`
3. Check audit log — `GET /api/admin/audit-log?action=action_reject`

**OIDC tokens rejected**
1. Verify RSA key exists at `data/oidc_rsa.pem`
2. Check `kid` matches JWKS endpoint
3. Check rate limiter (10 req/min per IP)

**WebSocket connection fails**
1. Verify ticket was requested within 30 seconds
2. Check IP matches the ticket-bound address
3. Error code: `WS_TICKET_EXPIRED`, `WS_TICKET_USED`, `WS_IP_MISMATCH`

**Notifications not delivering**
1. Check channel is enabled: `GET /api/admin/notifications/channels`
2. Check delivery log: `SELECT * FROM notification_delivery_log ORDER BY created_at DESC LIMIT 10;`
3. Test channel: `POST /api/admin/notifications/channels/:id/test`
