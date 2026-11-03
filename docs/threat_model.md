# AetherFlow Threat Model

## 1. Overview

This document maps CWEs and privilege boundaries across the **AetherFlow v4.0.0** architecture:
- **Control Plane (`af-api`)**: Unprivileged Rust (`Axum` + `Tokio`) HTTP/WebSocket server + embedded Next.js 16 (Obsidian V2) SPA running as `User=aetherflow` under `ProtectSystem=strict` and `NoNewPrivileges=yes`.
- **Privileged Runner (`af-runner`)**: Root daemon listening exclusively on `/run/aetherflow/runner.sock` (`0660 root:aetherflow`).
- **Scoped File Manager (`af-files`)**: Native McBrowser tenant storage under `/var/lib/aetherflow/mcbrowser` (`0700`).
- **Persistence (`af-db` & `af-host`)**: Bundled SQLite (`rusqlite`) in single-writer `WAL` mode with AES-256-GCM (`enc:v1:`) secret encryption and manifest-verified online backups.

---

## 2. CWE Mapping & Mitigations

### CWE-284 / CWE-285: Improper Access Control & Authorization

| Component | Threat | Mitigation |
|-----------|--------|------------|
| Route hierarchy (`af-api`) | Unauthenticated or cross-role access | Three-tier router: `/api/v1/public`, `/api/v1/auth` (JWT + revocation check), `/api/v1/admin` (live DB `role == "admin"` verification). |
| Plugin proxy (`af-api` / `af-services`) | Plugin token used outside authorized routes | Segment-boundary `api_scopes` verification against `plugin.manifest.json` before proxying or handling requests. |
| Host filesystem picker (`/api/v1/auth/fs`) | Non-admin user enumerating host directories | Restricted strictly to live-verified `admin` accounts before any path canonicalization or existence checks; ordinary users are confined to `af-files` McBrowser. |
| Cluster metrics (`/cluster/v1/metrics`) | Unauthorized cluster scraping or spoofing | Enforces `X-Cluster-PSK` authentication and validates heartbeat `node_id` and status fields. |

### CWE-22 / CWE-59: Path Traversal & Improper Link Resolution (Symlink Following)

| Component | Threat | Mitigation |
|-----------|--------|------------|
| Native McBrowser (`af-files`) | Escaping `/var/lib/aetherflow/mcbrowser/user-<id>` via `..` or symlinks | Component-by-component validation rejecting `..`, NUL bytes, and unapproved symlink traversals; enforces `0700` per-user roots. |
| Declarative Package Executor (`af-runner`) | Arbitrary file overwrite or `chown -R` on system roots via symlink planting | `validate_filesystem_path` inspects every ancestor component via `lstat` (`symlink_metadata`), rejects symlinks with `SecurityViolation`, and blocks shared system paths (`FORBIDDEN_EXACT_PATHS`, `SHARED_SYSTEM_CHOWN_PATHS`). |
| Release & Backup Engines (`af-release`, `af-host`) | Malicious archive entries or symlinked staging directories | `ensure_no_symlink_ancestors`, exclusive `0700` UUID staging dirs (`create_new`), rejection of tar symlink/hardlink/device entries, and mandatory `SHA256SUMS` + `.manifest.json` verification before extraction. |

### CWE-78: OS Command Injection & Privilege Escalation

| Component | Threat | Mitigation |
|-----------|--------|------------|
| Privileged Runner (`af-runner`) | Unprivileged API executing arbitrary root commands | Zero shell evaluation in `DeclarativeStep` (direct `execve` argv vectors with `stdin(Stdio::null())` and `process_group(0)`). Strict regex allowlists on unit names (`SAFE_SERVICE_NAME`), package IDs (`SAFE_PKG_ID`), usernames (`SAFE_USERNAME`), and APT packages (`SAFE_APT_PKG_NAME`). |
| Human-Gated FlowAI (`af-api`) | Prompt injection triggering destructive host commands | LLM output is untrusted; proposed mutations are queued into `pending_actions` (Approval Inbox) and cannot execute without explicit administrator authorization (`POST /api/v1/admin/actions/:id/approve`). |
| Self-Updater (`af-runner::self_update`) | Command injection or credential leak via updater launch | Request channel/command validated via `af_release::validate_self_update_request`; launched in isolated `aetherflow-self-update.service` with atomic `0600` environment handoff removed immediately after systemd accepts execution. |

### CWE-613 / CWE-384: Session Expiration & Revocation

| Component | Threat | Mitigation |
|-----------|--------|------------|
| JWT lifecycle (`af-api`, `af-db`) | Stolen or logged-out tokens remaining usable | 15-minute HS256 access token expiry (`exp`), bounded refresh token lifetimes, and synchronous SQLite `revoked_tokens` + `active_sessions` checks on every HTTP request, Subdomain Gateway SSO check, OIDC introspection, and WebSocket upgrade (zero external Redis failure window). |
| Account deletion (`af-api`) | Deleted user retaining active session or strand of last admin | Immediate transactional deletion removes sessions/OIDC tokens, verifies token owner existence on upgrade, and enforces last-usable-admin protection. |

### CWE-311 / CWE-89: Cryptographic Storage & SQL Injection

| Component | Threat | Mitigation |
|-----------|--------|------------|
| Stored secrets (`af-db`) | Plaintext API keys or OIDC secrets in SQLite backups | Encrypted at rest using **AES-256-GCM** (`enc:v1:<nonce>:<ciphertext>`) keyed by `AES_MASTER_KEY`. |
| SQLite queries (`af-db`) | SQL injection | Parameterized `rusqlite::params![]` queries throughout; online backups use `rusqlite::backup::Backup` (`SQLITE_OPEN_READ_ONLY`) or validated `VACUUM INTO` inside private `0700` staging directories. |

### CWE-918 / CWE-601: SSRF & Host Header Poisoning

| Component | Threat | Mitigation |
|-----------|--------|------------|
| Outbound Webhooks & Streaming Collectors | SSRF against loopback, link-local, or RFC1918 targets | Shared URL validator restricts outbound webhooks and provider probes against private/loopback targets and blocks unsafe redirects. |
| Host Header Validation (`ALLOWED_HOSTS`) | Host header poisoning in OAuth/OIDC redirects | Middleware validates `Host` against `ALLOWED_HOSTS` and strips untrusted `X-Aetherflow-User` identity headers at the Subdomain Gateway perimeter. |

---

## 3. Trust Boundaries

```
[Internet] ──HTTPS/TLS──> [Apache2 + Subdomain Gateway]
                                   │
                            127.0.0.1:8080
                                   ▼
             [aetherflow-api.service (Rust / af-api)]
             (User=aetherflow • ProtectSystem=strict • NoNewPrivileges=yes)
                  ├──> [/var/lib/aetherflow/aetherflow.sqlite (0600)]
                  ├──> [/var/lib/aetherflow/mcbrowser/user-<id> (0700)]
                  └──> [/run/aetherflow/runner.sock (0660 root:aetherflow)]
                                   │
                                   ▼
             [aetherflow-runner.service (Root Daemon / af-runner)]
                  ├──> [systemd Service Manager]
                  ├──> [Declarative Rust Recipes / Locked Package Scripts]
                  └──> [aetherflow-self-update.service (af-release)]
```

---

## 4. Risk Matrix

| Risk | Likelihood | Impact | Severity | Status |
|------|-----------|--------|----------|--------|
| Privilege escalation across `runner.sock` | Low | Critical | HIGH | Mitigated (strict struct/regex allowlists + zero arbitrary shell eval + `lstat` guards) |
| Tenant file escape in McBrowser | Low | High | HIGH | Mitigated (`af-files` capability scoping + symlink/traversal rejection + admin-only `/fs`) |
| Zombie sessions during cache outage | None | Low | LOW | Eliminated (revocation persisted directly in bundled SQLite WAL; Redis removed) |
| Broken update killing the updater mid-restart | Low | High | HIGH | Mitigated (isolated `aetherflow-self-update.service` + WAL-safe snapshot + binary path check) |
| AI prompt injection mutating host state | Medium | High | HIGH | Mitigated (Global Approval Inbox gate + `admin_audit_log`) |
| API key plaintext exposure in DB | Low | High | HIGH | Mitigated (AES-256-GCM `enc:v1:` envelope encryption) |

---

*Last updated: 2026-11-03 (AetherFlow v4.0.0)*
