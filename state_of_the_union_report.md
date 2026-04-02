# State of the Union: AetherFlow Backend & Architecture

## 1. Architectural Summary & Data Flow

### Core Tech Stack
*   **Backend:** Go 1.25 utilizing the Gin web framework. 
*   **Frontend:** Next.js 16 (React 19), Zustand for state, SWR for data fetching, Tailwind CSS.
*   **Datastores:** 
    *   **SQLite:** The primary operational database (running in single-writer WAL mode).
    *   **Redis:** High-speed, ephemeral cache used strictly for JWT revocation (blacklist).

### Structural Paradigms & Data Flow
AetherFlow relies on a strongly isolated trust boundary. All internet traffic hits a reverse proxy (e.g., nginx) which terminates SSL and forwards requests to the Gin backend operating on `127.0.0.1`.

1.  **Routing & Authorization Strategy:** The API is structured cleanly into three access tiers:
    *   `/public`: Stateless/unauthenticated entry (login, webhooks).
    *   `/auth`: Standard user operations guarded by `AuthMiddleware`.
    *   `/admin`: Privileged operations guarded by `AuthMiddleware` followed by `AdminOnly()`.
2.  **Session state & Authentication:** Authentication operates on 15-minute, short-lived JWTs utilizing the Bearer scheme. Logout scenarios and session management explicitly reject tokens by looking up a unique `jti` (JWT ID) in the Redis blacklist.
3.  **Command Execution:** Privileged system-level execution occurs primarily through `os/exec` wrappers (e.g., `systemctl`, `systemd_sandbox`), utilizing strict allowlists and absolute paths to mitigate command injection.

---

## 2. Current State & Gap Analysis

The codebase has transitioned efficiently toward modern Zero-Trust and DevSecOps patterns, with numerous fixes applied successfully. 

### What is Functioning Correctly:
*   Route separation and hierarchical API group designs are in place.
*   IDOR (Insecure Direct Object Reference) is generally well-defended (e.g., notification queries depend strictly on the authenticated `user_id` inside the JWT). 
*   Token revocation via Redis `jti` is active.
*   Cryptographic helpers (AES-GCM) are set up to defend sensitive integrations (like the Gemini API keys).

### Half-Built Features & Integration Gaps:
*   **Role BLEED:** Even with route tiers built out, `/system/metrics` still resides under the `/auth` group, unintentionally granting standard users access to administrative system insights.
*   **Orphaned AI Handlers:** While `GetDecryptedGeminiKey()` was built as a consolidated crypto helper, several downstream services (`bandwidth.go`, `metadata.go`, `predictions.go`, `smart_backup.go`) are actively bypassing it and querying the SQLite table directly. 
*   **Cryptography Fallback:** The AES string-decryption currently implements a "permissive fallback" model—if decryption fails, it mistakenly assumes the payload was legacy plaintext and returns it. This undermines the ciphertext model.
*   **IDOR Remnants:** The self-service quota route still expects an ID in the URL (`/user/quota/:id`), which exposes a potential attack surface.
*   **Frontend State vs. Backend Auth:** The frontend relies on checking cookies to determine session validity, while the backend API (`GetSession`) operates via Bearer token extraction, causing an orchestration mismatch.

---

## 3. Security, Technical & Performance Audit

### Immediate Security Vulnerabilities & Misconfigurations:
> [!CAUTION]
> **Hardcoded SSH Credentials & Plaintext Secrets**
> Files such as `temp_ssh.go`, `temp_ssh.js`, `ssh_tool.py`, and `ssh_pty.py` contain committed plain-text credentials and must be purged.

*   **API Authentication Bypass:** The newly introduced AI chat endpoint (`/api/ai/chat`) lacks binding to the authentication middleware. 
*   **Command Injection Parity:** Package installation scripts are actively employing dangerous `curl | bash` semantics, exposing remote supply-chain execution risks.
*   **Silent Global Account Binding:** Certain bash installation scripts (`common.sh`) heavily rely on a universally shared/hardcoded `AETHERFLOW_USER`.
*   **Incomplete CSRF Rollout:** The backend creates CSRF cookies, but there's no synchronized enforcement requiring state-changing cookie interactions to present a Double-Submit Header.

### Performance & Scalability Bottlenecks:
> [!WARNING]
> **System Polling Deadlocks**
> The internal metrics loop ticks at 3 seconds, additionally triggering a `systemctl cat` roughly every 15 seconds. Firing process-creation system calls for status validation at this volume scales exceptionally poorly and will strain CPU headroom. 

*   **Redis Fail-Open Dependency:** A calculated risk exists: Redis is configured to fail open on timeout (<= 50ms). If Redis crashes, blacklisted JWTs will be accepted for their remaining 15-minute lifespan. The architectural tradeoff is availability over security lockouts (accepted by design, but noted for visibility).

---

## 4. Prioritized Action Plan

The following path ensures immediate architectural stability, starting with the most fragile surface areas identified in the DevSecOps audits.

### Tier 1 (Critical): Showstoppers & Security Holes
These tasks seal live vulnerabilities and fix active bleed contexts immediately.
1.  **Purge Hardcoded Keys:** Identify and securely delete `temp_ssh.go`, `temp_ssh.js`, `ssh_tool.py`, and `ssh_pty.py`. 
2.  **Seal Unauthorized AI Ends:** Add `AuthMiddleware()` to `/api/ai/chat` (and verify any other newly added AI endpoints).
3.  **Fix Supply Chain Traps:** Rewrite package installation pipelines to download `.sh` payloads, verify a checksum, and execute locally. Remove all `curl | bash` directives.
4.  **Harden System Metrics:** Move `GET /system/metrics` from `authGroup` to `adminGroup`.
5.  **Refactor IDOR Vectors:** Replace `GET /user/quota/:id` with `GET /user/quota` to force self-serve queries natively through the `c.Get("user_id")` context limit constraint.

### Tier 2 (Feature Completion): Architectural Finishing
These tasks connect half-built infrastructures to finalize zero-trust handling.
1.  **Enforce Cryptographic Strictness:** Patch `backend/api/crypto.go` to reject poorly formatted decrypt arguments, dropping the plaintext fallback functionality completely so the backend enforces versioned ciphertext (`enc:v1:`).
2.  **Harmonize Gemini Key Consumption:** Map all localized API key SQLite calls in `bandwidth.go`, `metadata.go`, `predictions.go`, and `smart_backup.go` to explicitly retrieve variables strictly from `GetDecryptedGeminiKey()`.
3.  **Complete CSRF Mitigation:** Enable strict double-submit cookie validation across all non-GET API routes operating against a cookie-first authenticated origin.
4.  **Align Frontend Session Management:** Clean up the Next.js and Zustand states to read API signals (`401 Unauthorized`) via Bears token requests instead of relying implicitly on client-side cookie persistence.

### Tier 3 (Optimization): Refactoring, Resilience & Testing
1.  **Refuel Metrics Efficiency:** Redesign the system polling interval. Cache systemctl states, rely on DBUS polling natively if possible, or batch process calls rather than creating high-frequency system execution overhead.
2.  **Negative Scenario Integration Guards:** Write explicit end-to-end integration tests asserting that blacklisted tokens (`blacklist:<jti>`) effectively yield HTTP 401. 
3.  **CI/CD Gating:** Activate rigid block constraints within `.github/workflows/security.yml` pushing `govulncheck`, `gosec`, and integration pipelines against PR merges.
