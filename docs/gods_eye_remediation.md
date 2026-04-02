# God's Eye Remediation

## Scope

This plan is tailored to the current AetherFlow codebase on 2026-04-02.

The original audit body was not provided. This document therefore uses the stated CWE set and the requested 25 phases as the authoritative scope:

- CWE-284 Improper Access Control
- CWE-285 Improper Authorization
- CWE-613 Insufficient Session Expiration
- CWE-639 Insecure Direct Object Reference
- CWE-89 SQL Injection
- CWE-78 OS Command Injection

Primary backend touch points:

- `backend/api/routes.go`
- `backend/api/auth.go`
- `backend/api/notification_handlers.go`
- `backend/api/quota_handlers.go`
- `backend/api/backup.go`
- `backend/api/crypto.go`
- `backend/api/settings.go`
- `backend/api/oidc.go`
- `backend/db/db.go`
- `backend/db/redis.go`
- `backend/services/quota_manager.go`
- `backend/services/service_manager.go`
- `backend/services/systemctl.go`
- `.github/workflows/security.yml`

Current strengths already present in the repo:

- Three-tier route hierarchy exists in `backend/api/routes.go`.
- JWTs are already short-lived and include `jti` in `backend/api/oidc.go`.
- Redis-backed JWT revocation already exists in `backend/db/redis.go`.
- Notification queries are already user-scoped in `backend/api/notification_handlers.go`.
- Backup path canonicalization and filename checks already exist in `backend/api/backup.go`.
- Host-header validation and CSRF middleware already exist in `backend/api/auth.go`.
- Security tests already exist in `backend/api/auth_security_test.go`, `backend/api/routes_security_test.go`, and `backend/api/crypto_test.go`.

Current gaps that should be treated as open remediation items:

- `backend/api/routes.go` still exposes `/auth/system/metrics` to any authenticated user instead of the admin tier.
- `backend/api/quota_handlers.go` still uses `/user/quota/:id`; the safer self-service route is `/user/quota` bound only to `c.Get("user_id")`.
- `backend/api/crypto.go` currently uses a permissive plaintext fallback model; that is migration-friendly but weaker than a strict versioned ciphertext format.
- Several AI endpoints still read `gemini_api_key` directly from SQLite without a single shared decryption helper.
- Frontend session checks currently rely on cookies while `GetSession` in `backend/api/auth.go` expects a Bearer token, which affects any auth tightening rollout.

## Phase 1: Security Context & Threat Modeling Ingestion

### Architectural Strategy

Threat map against the current stack:

- CWE-284: route bleed between `/public`, `/auth`, and `/admin` in Gin.
- CWE-285: trusting user-controlled identifiers or role claims instead of server-side user state.
- CWE-613: JWTs without short expiry or revocation.
- CWE-639: notification, quota, profile, and settings access that relies on URL IDs instead of authenticated context.
- CWE-89: SQLite dynamic SQL, especially `VACUUM INTO`, where placeholders do not apply.
- CWE-78: `os/exec` calls that accept service names, usernames, repo URLs, script paths, or route input.

Cascading attack paths not explicitly listed:

- Forged JWT plus IDOR equals universal user impersonation.
- Redis outage plus revoked cookie equals a temporary zombie session window.
- Host-header poisoning plus OIDC/OAuth redirects equals credential theft.
- SQLite file theft plus plaintext Gemini key storage equals downstream API compromise and billing loss.
- Command injection in quota tooling can become host-level privilege escalation because several helpers call `sudo`, `bash`, or system binaries.

### Technical Execution

Components to review first:

- Request entry: `backend/api/routes.go`, `backend/api/auth.go`
- Session state: `backend/api/oidc.go`, `backend/db/redis.go`
- Sensitive storage: `backend/api/crypto.go`, `backend/api/settings.go`, `backend/db/db.go`
- Object authorization: `backend/api/notification_handlers.go`, `backend/api/quota_handlers.go`
- Injection surface: `backend/api/backup.go`, `backend/services/*.go`, `backend/api/updater.go`

Performance constraints to preserve during remediation:

- Keep SQLite in WAL mode and single-writer pool as configured in `backend/db/db.go`.
- Do not add per-request heavy joins or full-table scans to auth middleware.
- Bound Redis blacklist lookups with a short timeout; current `50ms` target in `backend/api/auth.go` is reasonable.
- Avoid repeated Gemini-key decryption and repeated settings queries inside hot request paths when one shared helper will do.

## Phase 2: Dependency & Module Hardening

### Architectural Strategy

Security baseline for the current repo:

- Go: stay on `go 1.25.0` or newer patch in the same line.
- Gin: `github.com/gin-gonic/gin v1.12.0`
- JWT: `github.com/golang-jwt/jwt/v5 v5.2.1`
- Redis: `github.com/redis/go-redis/v9 v9.18.0`
- SQLite driver: `github.com/mattn/go-sqlite3 v1.14.38`
- AES: use the standard library `crypto/aes` and `crypto/cipher`; there is no separate module to pin.

Module requirements:

- No floating `latest` in `go.mod`.
- Run `go mod verify` after updates.
- Gate merges on `govulncheck`, `go vet`, `staticcheck`, and `gosec`.

### Technical Execution

Current `backend/go.mod` already pins the core modules above.

Exact update commands:

```bash
cd backend
go get github.com/gin-gonic/gin@v1.12.0
go get github.com/golang-jwt/jwt/v5@v5.2.1
go get github.com/mattn/go-sqlite3@v1.14.38
go get github.com/redis/go-redis/v9@v9.18.0
go mod tidy
go mod verify
```

Exact validation and CVE scan commands:

```bash
cd backend
go list -m all
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go vet ./...
govulncheck ./...
gosec -severity medium -confidence medium ./...
```

## Phase 3: Route Re-Architecture Planning

### Architectural Strategy

Target route policy:

- Public: login bootstrap, OAuth start/callback, OIDC discovery/token endpoints, marketplace read-only endpoints, CSRF token issuance, billing provider webhooks.
- Authenticated: session, profile, user-owned notifications, user-owned quota read, fileshare read, AI chat, WebSocket.
- Admin-only: settings mutation, metrics, backup, service control, quota administration, users, logs, network, metadata, predictions.

High-priority adjustment for this repo:

- Move live system metrics out of `/auth` and into `/admin`.

### Technical Execution

Existing route boilerplate already matches the requested grouping model in `backend/api/routes.go`. The skeleton should remain:

```go
publicGroup := apiGroup.Group("/public")
authGroup := apiGroup.Group("/auth")
authGroup.Use(AuthMiddleware())
adminGroup := apiGroup.Group("/admin")
adminGroup.Use(AuthMiddleware(), AdminOnly())
```

Concrete repo action:

- Keep `GET /public/openapi.yaml`, `POST /public/auth/login`, `GET /public/auth/google/callback`.
- Keep `GET /auth/auth/session`, `PUT /auth/auth/profile`, `GET /auth/notifications`.
- Move `GET /auth/system/metrics` to `GET /admin/system/metrics`.

## Phase 4: Foundational Auth Middleware Implementation

### Architectural Strategy

`AuthMiddleware()` requirements:

- Accept the JWT from `Authorization: Bearer <token>`.
- Reject missing or malformed headers with `401 Unauthorized`.
- Reject invalid signatures, missing claims, expired tokens, and revoked sessions with `401 Unauthorized`.
- Never echo parser internals, raw token contents, or claim parse failures in the response body.
- Set the authenticated principal into Gin context only after JWT verification and server-side user existence checks.

### Technical Execution

The repo already implements the baseline in `backend/api/auth.go`:

- Header extraction
- HMAC algorithm enforcement
- `user_id` extraction
- user existence lookup
- `c.Set("user_id", userId)`
- `c.Set("user_role", role)`

Recommended exact hardening for this file:

- Standardize every auth failure body to `{"error":"Unauthorized"}`.
- Keep `401` for authentication failures and reserve `403` for authorization only.
- Preserve the Redis blacklist check after signature validation.

## Phase 5: Admin-Only Middleware Implementation

### Architectural Strategy

Role logic for AetherFlow:

- Do not trust a `role` claim from the client JWT.
- Resolve the user from the database and use server-side role state.
- RBAC is the right default here because the admin surface is static and operational.
- ABAC can be added later for scoped operators, but it is not needed to patch the listed CWEs.

### Technical Execution

Current implementation in `backend/api/auth.go` is acceptable because `AuthMiddleware()` already populates `user_role` from SQLite, not the JWT payload.

Recommended repo rule:

- Chain `AdminOnly()` only after `AuthMiddleware()`.
- Use it on metrics and all operational control endpoints.

Exact current pattern:

```go
adminGroup := apiGroup.Group("/admin")
adminGroup.Use(AuthMiddleware(), AdminOnly())
```

## Phase 6: Eradicating IDOR in Notification Logic

### Architectural Strategy

Notification IDOR test case:

1. Log in as User A.
2. Attempt to fetch User B notifications by query string, body field, or guessed notification ID.
3. Expect the backend to ignore any caller-supplied user identifier and scope every list or update query to the authenticated principal.

Required backend rule:

- Notification ownership must be derived only from `c.Get("user_id")`.

### Technical Execution

This is already implemented correctly in `backend/api/notification_handlers.go`:

```sql
SELECT ... FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?
UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?
UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0
```

No architectural rewrite is required here. Keep adding negative tests around:

- guessed notification IDs
- mass-dismiss on another user
- unread count leakage

## Phase 7: Eradicating IDOR in Quota Management

### Architectural Strategy

Quota IDOR is both a security and billing problem:

- A user reading another user quota leaks plan and tenancy data.
- A user updating another user quota can cause underbilling, overconsumption, or service disruption.

Required business rules:

- Self-service read routes must bind to the authenticated `user_id`.
- Admin quota updates stay in `/admin`.
- Never accept a user ID in the request body for self-service quota reads or writes.

### Technical Execution

Current state:

- `backend/api/quota_handlers.go` already blocks cross-user reads unless the caller is admin.
- The remaining cleanup is to remove self-service dependence on `:id`.

Exact preferred route and handler shape:

```go
authGroup.GET("/user/quota", GetOwnQuota)
```

```go
func GetOwnQuota(c *gin.Context) {
    rawUserID, _ := c.Get("user_id")
    userID, ok := rawUserID.(int)
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }

    record, err := services.GetUserQuotaRecord(userID)
    if err != nil {
        c.JSON(quotaErrorStatus(err), gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, record)
}
```

Admin updates should continue through:

- `PUT /admin/quotas/:id`
- `POST /admin/quotas/:id/refresh`

which already route into `services.SetQuotaForUserID()` and `services.RefreshUserQuotaRecord()`.

## Phase 8: Redis Infrastructure Configuration

### Architectural Strategy

Redis role in this repo:

- JWT revocation blacklist only
- low-latency O(1) key lookup
- isolated to private network or localhost

Security requirements:

- bind Redis to loopback or private subnet
- require auth if not socket-local
- set eviction policy that prefers expiring keys, such as `volatile-ttl`
- cap memory explicitly because blacklist keys are time-bounded and disposable

### Technical Execution

The current code in `backend/db/redis.go` already degrades gracefully when Redis is unavailable.

Recommended initialization shape:

```go
redis.NewClient(&redis.Options{
    Addr:         os.Getenv("REDIS_ADDR"),
    Password:     os.Getenv("REDIS_PASSWORD"),
    DB:           0,
    PoolSize:     100,
    MinIdleConns: 10,
    DialTimeout:  2 * time.Second,
    ReadTimeout:  500 * time.Millisecond,
    WriteTimeout: 500 * time.Millisecond,
})
```

Recommended Redis server settings:

```conf
bind 127.0.0.1
protected-mode yes
maxmemory 256mb
maxmemory-policy volatile-ttl
```

## Phase 9: JWT Generation Refactor (Short-Lived Tokens)

### Architectural Strategy

The current session model is correct in principle:

- access token lifetime: 15 minutes
- refresh or re-login for renewal
- unique `jti` per JWT

Why this matters:

- stolen cookies die quickly
- blacklist storage stays small
- replay risk is bounded by the short token lifetime

### Technical Execution

This is already implemented in `backend/api/oidc.go` inside `createStandardJWT()`:

```go
claims := jwt.MapClaims{
    "user_id": userID,
    "sub":     fmt.Sprintf("%d", userID),
    "iss":     "aetherflow",
    "iat":     time.Now().Unix(),
    "exp":     time.Now().Add(15 * time.Minute).Unix(),
    "jti":     uuid.New().String(),
}
```

Keep this function as the single source of truth for session-token issuance.

## Phase 10: JWT Revocation Storage Logic

### Architectural Strategy

Blacklisting `jti` in Redis is the correct design for AetherFlow:

- Redis is optimized for short-lived ephemeral state.
- SQLite should remain the system of record, not a write-heavy session cache.
- A whitelist model would require every request to hit durable state for all active sessions, which is unnecessary overhead for a mostly stateless API.

### Technical Execution

This is already implemented in `backend/db/redis.go`:

```go
func RevokeToken(jti string, expiration time.Duration) error {
    if RedisClient == nil {
        return nil
    }
    return RedisClient.Set(context.Background(), "blacklist:"+jti, "true", expiration).Err()
}
```

The TTL must always match `time.Until(exp)`.

## Phase 11: Integrating Redis Blacklist into Middleware

### Architectural Strategy

Latency target:

- blacklist lookup budget: `<= 50ms`
- fail closed on a confirmed blacklist hit
- fail open only on Redis infrastructure errors, because availability is preferable to locking out all API users during a transient cache outage

### Technical Execution

This is already implemented in `backend/api/auth.go`:

```go
ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
defer cancel()
if db.RedisClient.Get(ctx, "blacklist:"+jti).Err() == nil {
    c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
    return
}
```

The ordering is correct:

1. validate signature
2. extract `jti`
3. query Redis
4. verify user still exists in SQLite
5. set Gin context

## Phase 12: AES-GCM Cryptographic Utility Design

### Architectural Strategy

AES-GCM is appropriate because it gives:

- confidentiality
- integrity
- authenticity

Security requirements:

- fresh random nonce per encryption
- authenticated decryption only
- 32-byte AES-256 key
- versioned ciphertext format so encrypted data can be distinguished from legacy plaintext

### Technical Execution

Current code in `backend/api/crypto.go` already uses AES-GCM with a prepended nonce.

Recommended final format:

- store ciphertext as `enc:v1:<base64(nonce||ciphertext)>`
- reject malformed or tampered `enc:v1:` values with an error
- treat unprefixed values as legacy plaintext only during migration

Preferred low-level utility shape:

```go
func EncryptKey(plaintext, secret []byte) ([]byte, error)
func DecryptKey(ciphertext, secret []byte) ([]byte, error)
```

Repo note:

- the current implementation is migration-friendly but permissive because decryption falls back to returning the original value on some failures
- that should be replaced with explicit versioning rather than silent fallback

## Phase 13: Secure Key Management & Injection

### Architectural Strategy

Key injection order of preference:

1. Vault or cloud secret manager in production
2. environment variable at process start
3. never hardcode

Trade-off summary:

- env vars are simplest and acceptable for a small deployment behind a hardened service manager
- AWS Secrets Manager or Vault is stronger for rotation, auditability, and centralized access control

### Technical Execution

Current runtime loader exists in `backend/api/crypto.go` as `InitAESKey()`.

Production requirement:

- refuse startup if `AES_MASTER_KEY` is missing or not 32 bytes

Current `backend/main.go` already calls:

```go
api.InitAESKey()
```

Recommended environment contract:

```bash
AES_MASTER_KEY=<32-byte raw key or base64-encoded 32-byte key>
JWT_SECRET=<32+ random bytes>
```

## Phase 14: Integrating Encryption with SQLite

### Architectural Strategy

Threat addressed:

- if an attacker reads `aetherflow.sqlite` from disk or through LFI, the Gemini API key should not be usable without the AES master key

### Technical Execution

The repo already encrypts on write and decrypts on read in these paths:

- `backend/api/settings.go`
- `backend/api/ai_helpers.go`
- `backend/api/ai.go`

The remaining cleanup is to unify all Gemini-key reads behind one helper so no endpoint accidentally consumes encrypted text as if it were plaintext.

Files that should be refactored to use a shared helper:

- `backend/api/bandwidth.go`
- `backend/api/metadata.go`
- `backend/api/predictions.go`
- `backend/services/smart_backup.go`

## Phase 15: SQLite VACUUM INTO Vulnerability Analysis

### Architectural Strategy

Why `VACUUM INTO` is special:

- SQLite does not support normal `?` parameter binding for the target filename in this administrative statement.
- If untrusted input reaches the path string, the only safe defense is strict validation plus path confinement.

### Technical Execution

Current implementation in `backend/api/backup.go`:

```go
safePath := strings.ReplaceAll(backupFile, "'", "''")
_, err = db.DB.Exec(fmt.Sprintf(`VACUUM INTO '%s'`, safePath))
```

Mock exploit if validation were removed:

```text
filename = ../../../../var/www/html/pwned.sqlite
```

or, if quoting were broken:

```text
filename = backup.sqlite'; ATTACH DATABASE '/tmp/leak.db' AS leak; --
```

The current repo already reduces this risk with:

- `filepath.Base`
- `safeBackupPath()`
- regex whitelisting

## Phase 16: Regex Validation for Backup Filenames

### Architectural Strategy

Requested strict policy:

- alphanumeric
- underscores only
- one `.db` suffix
- no path separators
- no null bytes

Mathematically strict regex:

```regex
^[A-Za-z0-9_]+\.db$
```

### Technical Execution

Current repo policy in `backend/api/backup.go` is looser:

```go
var validBackupFilenameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+\.sqlite$`)
```

If the audit requires the stricter filename contract, change it to:

```go
var validBackupFilenameRe = regexp.MustCompile(`^[A-Za-z0-9_]+\.db$`)
```

and keep the existing `safeBackupPath()` path confinement logic.

## Phase 17: Patching Command Injection (CWE-78)

### Architectural Strategy

Rules for this repo:

- use absolute script paths where possible
- resolve helper scripts from trusted directories only
- validate user-controlled arguments against allowlists
- pass command arguments as discrete slices
- do not concatenate shell command strings

### Technical Execution

Current code is mostly aligned:

- `backend/api/updater.go` uses `os.Executable()` plus `filepath.Clean()`
- `backend/services/quota_manager.go` validates usernames
- `backend/services/systemctl.go` validates service names and uses discrete args
- `backend/services/systemd_sandbox.go` resolves trusted helper locations

Files worth re-reviewing whenever new input is added:

- `backend/services/network.go`
- `backend/services/app_updates.go`
- `backend/services/installer.go`
- `backend/services/logstream.go`

## Phase 18: State-Changing GET Refactoring

### Architectural Strategy

Security implications:

- GET must stay safe and idempotent
- state change over GET creates CSRF exposure and can be triggered by prefetchers, crawlers, or link previews

### Technical Execution

Current route audit in `backend/api/routes.go` is mostly good:

- mutating notification calls are `PUT` and `POST`
- settings mutation is `PUT`
- service control is `POST`
- user deletion is `DELETE`

Keep verifying that no new endpoints use GET for:

- deletes
- mark-as-read operations
- quota updates
- OIDC revocation

## Phase 19: CSRF Protection Implementation

### Architectural Strategy

For AetherFlow, the double-submit cookie pattern is the right fit because:

- most API routes use Bearer tokens and are naturally CSRF-resistant
- the remaining cookie-oriented flows are small and easy to defend with a token cookie plus `X-CSRF-Token` header

The synchronizer-token pattern is stronger when there is heavy server-rendered session state, which is not the main architecture here.

### Technical Execution

Current implementation exists across:

- `backend/api/csrf.go`
- `backend/api/auth.go`

Current behavior:

- sets a `csrf_token` cookie
- requires `X-CSRF-Token` on mutating cookie-authenticated requests
- skips CSRF for Bearer-token API calls

Recommended cookie flags:

- `Secure=true`
- `SameSite=Strict`
- if the frontend reads the token from JSON instead of cookie, set `HttpOnly=true`

## Phase 20: Patching Open Redirects (Host Header)

### Architectural Strategy

Threat:

- poisoned `Host` or `X-Forwarded-Host` can generate malicious absolute URLs in OAuth or password-reset flows

Allowed-domain criteria:

- exact hostnames only
- no wildcard trust
- include production and explicit local development hosts only

### Technical Execution

Current middleware in `backend/api/auth.go` already implements this:

- `HostValidationMiddleware()`
- `isAllowedHost()`
- host-based `getBaseURL()`

Recommended production env:

```bash
ALLOWED_HOSTS=app.aetherflow.com,api.aetherflow.com
```

## Phase 21: Patching Open Redirects (OIDC Params)

### Architectural Strategy

OIDC redirect rules:

- `redirect_uri` must be exact-match validated against the client registration
- never accept arbitrary caller-supplied redirect bases
- never build the redirect target from untrusted host data

### Technical Execution

This is already present in `backend/api/oidc.go`:

- `isAllowedRedirectURI()`
- `redirect_uri` comparison against registered client URIs from SQLite

Keep exact-match semantics. Do not relax to substring matching.

## Phase 22: Unit Testing the Cryptography & Auth

### Architectural Strategy

Negative security tests required:

- missing auth header
- malformed Bearer token
- expired JWT
- forged JWT signature
- missing `user_id`
- algorithm confusion attempt
- blacklisted `jti`
- mismatched CSRF token
- short or tampered AES-GCM ciphertext

### Technical Execution

The repo already contains table-driven and focused tests in:

- `backend/api/auth_security_test.go`
- `backend/api/crypto_test.go`

Add one missing high-value test:

- blacklisted `jti` returns `401` when Redis contains `blacklist:<jti>`

## Phase 23: Integration Testing the Gin Routes

### Architectural Strategy

Integration goals:

- prove route groups do not bleed
- prove standard users cannot hit admin handlers
- prove unsupported HTTP methods do not mutate state
- prove backup traversal is rejected

### Technical Execution

The repo already contains these tests in `backend/api/routes_security_test.go`:

- unauthenticated auth-route rejection
- standard-user admin rejection
- admin allow path
- method tampering
- route bleed
- backup traversal rejection

Add one explicit admin metrics test once metrics move under `/admin`:

```go
req, _ := http.NewRequest("GET", "/admin/system/metrics", nil)
```

Expect:

- standard user: `403`
- missing auth: `401`
- admin: `200`

## Phase 24: CI/CD Pipeline Update

### Architectural Strategy

Merge gates for AetherFlow should require:

- `go mod verify`
- `go vet`
- `govulncheck`
- `staticcheck`
- `gosec`
- backend test suite
- build verification

SQLite note:

- SQLite is embedded, so a dedicated container is unnecessary
- Redis does need a service container because blacklist checks are stateful

### Technical Execution

The repo already has `.github/workflows/security.yml`. It should remain the security gate entrypoint and enforce:

```yaml
- go mod verify
- govulncheck ./...
- go vet ./...
- staticcheck ./...
- gosec -severity medium -confidence medium ./...
- go test -v -count=1 -race ./...
- go build ./...
```

Required CI env for tests:

```yaml
env:
  JWT_SECRET: ci-test-secret-exactly-32bytes!!
  AES_MASTER_KEY: ci-test-aes-key-exactly-32bytes!
  REDIS_ADDR: localhost:6379
  ALLOWED_HOSTS: localhost:8080,127.0.0.1:8080
```

## Phase 25: Final Audit & Deployment Sign-Off

### Architectural Strategy

Final review of the combined changes:

- Auth: short-lived JWTs, blacklist revocation, host validation, clear route tiers
- Storage: encrypted Gemini key, SQLite WAL, no secret plaintext in backups
- Injection: strict filename validation, path confinement, discrete `os/exec` arguments
- CSRF: double-submit cookie pattern for cookie-authenticated mutating calls

Primary UX friction to manage:

- 15-minute JWT expiry may require silent refresh or more frequent re-login
- stricter admin scoping for metrics will change what non-admin users can see
- enforcing strict ciphertext parsing requires a controlled migration of legacy plaintext keys

### Technical Execution

Deployment checklist for this repo:

1. Set `JWT_SECRET`, `AES_MASTER_KEY`, `ALLOWED_HOSTS`, `REDIS_ADDR`, and `REDIS_PASSWORD`.
2. Verify Redis connectivity before deploy.
3. Build the backend with production env set.
4. Roll out the route-tier changes before enabling stricter frontend authorization checks.
5. Re-save the Gemini API key after `AES_MASTER_KEY` is configured so newly persisted values are encrypted.
6. Keep legacy plaintext decryption support only long enough to migrate stored secrets.
7. Monitor auth failures, CSRF failures, Redis warnings, and Host validation rejections after deploy.

Zero-downtime session migration strategy:

1. Deploy Redis first.
2. Deploy the backend with blacklist support enabled.
3. Keep current JWT signing secret stable during the rollout.
4. After all nodes share Redis, enforce logout-based revocation everywhere.
5. After the Gemini key has been re-saved in encrypted form, tighten decryption to strict versioned ciphertext only.

## Recommended Next Code Changes

These are the highest-value follow-up patches to implement in the repo after accepting this plan:

1. Move `/system/metrics` to the admin route group in `backend/api/routes.go`.
2. Replace `/user/quota/:id` with `/user/quota` for self-service reads.
3. Introduce versioned encrypted Gemini-key storage in `backend/api/crypto.go`.
4. Consolidate all Gemini-key reads through one decrypting helper.
5. Align frontend session handling with backend auth transport before tightening cookie-versus-Bearer behavior.
