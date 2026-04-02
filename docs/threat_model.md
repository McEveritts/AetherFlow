# AetherFlow Threat Model

## 1. Overview

This document maps the CWEs identified in the CI/CD security audit to the AetherFlow
Go/Gin/SQLite/Redis architecture and identifies cascading attack vectors.

**Architecture**: Go 1.25 backend → Gin HTTP framework → SQLite (single-writer WAL mode) → Redis (JWT blacklist)

---

## 2. CWE Mapping

### CWE-284: Improper Access Control

| Component | Threat | Mitigation |
|-----------|--------|------------|
| Route groups | Endpoints accessible without authentication | Three-tier route hierarchy: `/public`, `/auth` (AuthMiddleware), `/admin` (AuthMiddleware + AdminOnly) |
| OIDC endpoints | Public by design; abuse potential | Rate limiting on auth endpoints (5 req/min), PKCE enforcement |
| WebSocket | Unauthenticated connection hijacking | AuthMiddleware gate + origin validation in upgrader |

### CWE-285: Improper Authorization

| Component | Threat | Mitigation |
|-----------|--------|------------|
| AdminOnly middleware | Role escalation via JWT payload manipulation | Server-side role fetch from DB on every request (`SELECT role FROM users WHERE id = ?`) — JWT `user_role` is NOT trusted alone |
| Quota management | Admin-only operations accessible to users | IDOR check: `authedUserID != requestedID && authedRole != "admin"` |

### CWE-613: Insufficient Session Expiration

| Component | Threat | Mitigation |
|-----------|--------|------------|
| JWT lifetime | Stolen tokens usable indefinitely | 15-minute expiry (`exp` claim) |
| Session revocation | Logout token remains valid | Redis blacklist with TTL matching remaining JWT lifespan |
| Cookie handling | Cookie persists after logout | Cookie deletion on logout (`MaxAge=-1`) |

### CWE-639: Insecure Direct Object Reference (IDOR)

| Component | Threat | Mitigation |
|-----------|--------|------------|
| Notifications | User A reads User B's notifications | `WHERE user_id = ?` bound to `c.Get("user_id")` from JWT context |
| Quota read | User A reads User B's quota | IDOR guard: context user ID must match URL `:id` or be admin |
| Profile update | User A updates User B's profile | `UpdateProfile` extracts user ID from JWT, not URL params |

### CWE-89: SQL Injection

| Component | Threat | Mitigation |
|-----------|--------|------------|
| Parameterized queries | Standard SQLi | All queries use `?` placeholders throughout |
| VACUUM INTO | Administrative command injection (not parameterizable) | Regex whitelist (`^[a-zA-Z0-9_.-]+\.sqlite$`) + `safeBackupPath()` for path canonicalization |
| Dynamic UPDATE (notification rules) | Query building with string concatenation | Field names are hardcoded constants; only values use `?` placeholders |

### CWE-78: OS Command Injection

| Component | Threat | Mitigation |
|-----------|--------|------------|
| `exec.Command` (systemctl) | Malicious service names | Regex allowlist: `^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,63}$` |
| `exec.Command` (update script) | Path manipulation | `os.Executable()` → absolute path resolution via `filepath.Clean()` |
| `exec.Command` (PM2) | Binary path hijacking | `findPM2Binary()` searches known absolute paths first |

---

## 3. Cascading Attack Vectors

### Chain 1: JWT Forgery → Universal IDOR
```
Weak JWT_SECRET → Forged token with arbitrary user_id
  → Bypasses ALL IDOR protections (notifications, quotas, profile)
  → Can escalate to admin by setting role claim (mitigated: role is re-fetched from DB)
```
**Mitigation**: JWT_SECRET must be ≥32 bytes, cryptographically random. `log.Fatal()` on missing secret.

### Chain 2: Redis Failure → Zombie Sessions
```
Redis outage → BlacklistCheck returns nil error
  → Revoked tokens (from logout) remain valid for up to 15 minutes
  → Session hijacking window extends to full JWT lifetime
```
**Mitigation**: Fail-open design. Accept the 15-min window as a tradeoff for availability. Short JWT lifetime limits blast radius.

### Chain 3: Missing AES Key → API Key Exposure
```
AES_MASTER_KEY not set → API keys stored in plaintext in SQLite
  → Database backup download (admin-only) → Attacker obtains .sqlite file
  → OR: Local File Inclusion (LFI) → Direct database read
  → Full Gemini API key compromise → Unauthorized AI usage / billing
```
**Mitigation**: Fail-fast in production mode. `log.Fatal()` when `GIN_MODE=release` and key is missing.

### Chain 4: Host Header Poisoning → OAuth Credential Theft
```
Spoofed Host header → getBaseURL() returns attacker domain
  → OAuth callback redirects to attacker site with authorization code
  → Attacker exchanges code for access token
```
**Mitigation**: `HostValidationMiddleware()` validates `c.Request.Host` against `ALLOWED_HOSTS` whitelist.

---

## 4. Trust Boundaries

```
[Internet] → [Reverse Proxy (nginx)] → [Gin HTTP Server (127.0.0.1:8080)]
                                              ↓
                                        [AuthMiddleware]
                                              ↓
                                        [Handler Logic]
                                         ↓           ↓
                                    [SQLite DB]   [Redis Cache]
                                         ↓
                                    [os/exec → systemd/PM2]
```

**Key boundary**: The Gin server binds to `127.0.0.1` only. All internet-facing traffic must pass through a reverse proxy. The `ALLOWED_HOSTS` check validates that the proxy is not forwarding spoofed host headers.

---

## 5. Risk Matrix

| Risk | Likelihood | Impact | Severity | Status |
|------|-----------|--------|----------|--------|
| JWT secret compromise | Low | Critical | HIGH | Mitigated (fail-fast on missing secret) |
| IDOR in notifications | Low | Medium | MEDIUM | Mitigated (context-bound queries) |
| SQL injection via VACUUM INTO | Low | High | HIGH | Mitigated (regex + path validation) |
| Command injection via service control | Low | Critical | HIGH | Mitigated (name regex + discrete args) |
| API key plaintext storage | Medium | High | HIGH | Mitigated (AES-GCM + fail-fast in prod) |
| CSRF on cookie-based flows | Low | Medium | MEDIUM | Mitigated (Bearer token architecture + opt-in CSRF middleware) |
| Open redirect via Host header | Low | Medium | MEDIUM | Mitigated (host whitelist middleware) |
| Redis downtime → zombie sessions | Low | Low | LOW | Accepted (15-min window, fail-open) |

---

*Last updated: 2026-04-02*
*Document owner: Security Architecture*
