# API Reference

The AetherFlow API (`aetherflow-api`) is a high-concurrency **Rust (`Axum` + `Tokio`)** control plane (`backend-rs/crates/af-api`). It serves the external **Leptos Rust WebAssembly (`frontend-rs`)** static frontend from `web/dist` (`STATIC_DIR`), RESTful endpoints for state mutation, Server-Sent Events (SSE), and full-duplex WebSocket streams for real-time telemetry.

> [!NOTE]
> This API powers the AetherFlow dashboard and the `af` CLI, and can also be consumed programmatically by administrators with valid session tokens or Bearer JWTs.

---

## Authentication & Security Headers

All API endpoints under `/api/v1/auth/*` and `/api/v1/admin/*` require an active session. AetherFlow enforces `HttpOnly` cookies (or `Authorization: Bearer`), SQLite-backed token revocation, `ALLOWED_HOSTS` checks, and CSRF protection.

### Session Cookie & Bearer Token
Authentication is driven by the `aetherflow_session` cookie (containing a signed 15-minute HS256 JWT) or an `Authorization: Bearer <token>` header.

### CSRF Protection
For state-mutating cookie-authenticated requests (`POST`, `PUT`, `PATCH`, `DELETE`), include the CSRF token. The session refresh routes accept an expired session cookie and require `X-Requested-With: XMLHttpRequest` so the dashboard can renew its session after its CSRF token expires.

| Header | Description |
| :--- | :--- |
| `X-CSRF-Token` | The CSRF token issued during authentication or session initialization. |

---

## Core API Namespaces (`/api/v1`)

### 1. Public & Authentication (`/api/v1/public`, `/api/v1/auth`)
Handles login, TOTP 2FA verification, OAuth2/OIDC handshakes, and Subdomain Gateway SSO verification.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/auth/ready` | Authenticated readiness probe returning control-plane status, SQLite `database` health, and privileged `runner` health (`ok`, `unreachable`, or `disabled`) with `Cache-Control: no-store` on both `200` (`status: "ready"`) and `503` (`status: "not_ready"`). Unauthenticated probe: `/health/ready`. |
| `POST` | `/api/v1/public/auth/login` | Authenticates credentials and issues the JWT session + CSRF token. |
| `POST` | `/api/v1/public/auth/mfa/verify` | Validates a 6-digit TOTP code or recovery code during login. |
| `GET` | `/api/v1/public/auth/verify` | Perimeter SSO verification for Apache2 Subdomain Gateway (`X-Aetherflow-User` injection). Enforces active, unrevoked administrator sessions (rejecting revoked, expired, non-admin, or plugin-scoped tokens). |
| `GET` | `/api/v1/auth/session` | Returns the authenticated user's session profile, role, and 2FA status. |
| `POST` | `/api/v1/auth/refresh` | Rotates the current session. Cookie clients send `X-Requested-With: XMLHttpRequest`. The public alias is `/api/v1/public/auth/refresh`. |
| `PUT` | `/api/v1/auth/profile` | Updates the authenticated user's profile details. |
| `POST` | `/api/v1/auth/logout` | Revokes the active JWT (`revoked_tokens`) and clears `aetherflow_session`. |

> [!NOTE]
> **Readiness Contract**: Both `GET /health/ready` and `GET /api/v1/auth/ready` include `"runner"` (`"ok"`, `"unreachable"`, or `"disabled"`) alongside existing fields and return HTTP `503` (`"status": "not_ready"`) if any required check fails, while keeping `"database": "ok"` when only the runner is unreachable. When `PRIVILEGED_RUNNER_ENABLED` is set to a trimmed, case-insensitive `1`, `true`, `yes`, or `on`, SQLite and the runner socket (`/v1/health`) are probed concurrently within two-second budgets; when unset or false, `"runner"` reports `"disabled"` and SQLite determines readiness. `GET /api/v1/auth/ready` sets `Cache-Control: no-store` on both `200` and `503`, and neither route exposes diagnostic addresses or runner error bodies. Deployment release managers default `HEALTH_ENDPOINT` to `http://127.0.0.1:8080/health/ready`; explicit `HEALTH_ENDPOINT` overrides are preserved and must report full application readiness to provide an equivalent deployment gate.
>
> Protected external application requests routed through the Rust gateway require an active administrator session or rate-limited Basic authentication. Administrators enrolled in TOTP use a verified session. Apache-authenticated vhosts and applications with native logins retain their respective policies. See the [external subdomain authentication details](security.md).

### 2. System, Services & Self-Update (`/api/v1/auth`, `/api/v1/admin`)
Provides hardware telemetry, `systemd` service lifecycle control (via `aetherflow-runner`), and atomic release management.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/auth/system/metrics` | Returns live CPU, RAM, swap, disk I/O, network, and NVML/DRM GPU metrics. |
| `GET` | `/api/v1/auth/services` | Lists managed `systemd` services, ports, subdomains, and runtime states. |
| `POST` | `/api/v1/admin/services/{name}/control` | Dispatches allowlisted `systemctl` actions (`start`, `stop`, `restart`, `enable`, `disable`) over `/run/aetherflow/runner.sock`. |
| `GET` | `/api/v1/admin/system/update/check` | Checks GitHub Releases for `stable`, `nightly`, or `experimental` updates (with 5-min cache & rate-limit backoff). |
| `POST` | `/api/v1/admin/system/update/run` | Launches an isolated `aetherflow-self-update.service` deployment or rollback. |
| `GET` | `/api/v1/admin/system/update/status` | Returns restart-surviving self-update status, operation ID, and recovery journal state. |

### 3. AetherMarketplace (`/api/v1/public/marketplace`, `/api/v1/admin/packages`)
Controls the lifecycle of the **77 bare-metal applications**.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/public/marketplace` | Lists all 77 catalog packages and categories. Authenticated callers also receive installation status, update availability, and the resolved app launch target. Use `?require_auth=1` to require live inventory. |
| `GET` | `/api/v1/auth/packages/{id}/progress` | Returns progress or the terminal lifecycle receipt. Pass `?job_id=<id>` to follow a specific operation across later jobs on the same package. |
| `POST` | `/api/v1/admin/packages/{id}/install` | Starts asynchronous package installation via `af-runner` (declarative Rust or locked Bash). |
| `POST` | `/api/v1/admin/packages/{id}/update` | Performs an in-place package update with automatic service stop/restart and rollback protection. |
| `POST` | `/api/v1/admin/packages/{id}/reinstall` | Repairs or reinstalls an installed package while preserving its service configuration. |
| `POST` | `/api/v1/admin/packages/{id}/uninstall` | Uninstalls a package (preserving application data unless `?purge=true`). |
| `POST` | `/api/v1/admin/packages/updates/check` | Checks upstream versions across installed Marketplace packages. |
| `POST` | `/api/v1/admin/apps/launch` | Starts the dashboard session exchange for eligible Marketplace apps on managed public HTTPS routes. |

### 4. Native McBrowser (`af-files` — `/api/v1/auth/mcbrowser`)
Capability-scoped tenant file manager backed by `af-files`. See [Native McBrowser](./mcbrowser.md).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/auth/mcbrowser/entries` | Lists directory contents, breadcrumbs, sorting, and quota usage within the user's scoped root. |
| `GET/POST` | `/api/v1/auth/mcbrowser/uploads` | Lists or creates resumable chunked upload sessions (up to 64 GiB per file, `PATCH` chunks via `/api/v1/auth/mcbrowser/uploads/{id}`). |
| `GET/PUT` | `/api/v1/auth/mcbrowser/content` | Reads or saves UTF-8 text files (up to 10 MiB) with ETag conflict detection. |
| `POST` | `/api/v1/auth/mcbrowser/actions` | Executes safe built-in actions (checksums, 9-format archive creation/extraction, media metadata). |
| `GET/POST` | `/api/v1/auth/mcbrowser/shares` | Lists or creates password-protected, expiring public share links. |

### 5. Canonical Streaming Analytics (`/api/v1/auth/streaming`, `/api/v1/admin/streaming`)
Live Plex/Jellyfin/Emby session telemetry and snapshot-consistent playback history. See [Streaming History Contract](./streaming-history-contract.md).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/auth/streaming/dashboard` | Returns provider connection status, active Direct Play vs. Transcode sessions, and live bandwidth summary. |
| `GET` | `/api/v1/auth/streaming/history` | Queries canonical playback history with rolling/calendar windows and snapshot cursors. |
| `GET` | `/api/v1/auth/streaming/history/export` | Streams full-query CSV export bound to `snapshotToken`. |
| `POST` | `/api/v1/admin/streaming/imports/events` | Imports idempotent, checkpointed playback events (up to 500 per batch). |
| `POST` | `/api/v1/admin/streaming/reconciliation/preview` | Previews proposed history reconciliation changes without mutating stored records. |
| `POST` | `/api/v1/admin/streaming/reconciliation/apply` | Executes backup-verified, human-approved history reconciliation. |
| `GET` | `/api/v1/admin/streaming/portability/export` | Exports a native JSON streaming history archive (up to 8 MiB / 100,000 records). |
| `POST` | `/api/v1/admin/streaming/portability/preview` | Previews a native JSON archive restore (10 MiB JSON request envelope limit) and issues an approval token. |
| `POST` | `/api/v1/admin/streaming/portability/restore` | Applies an approved merge or replacement archive restore with verified on-disk backup. |

### 6. Network & Mesh VPN (`/api/v1/admin/network`)
Manages native **WireGuard** (`wg0`) and **Tailscale** via `aetherflow-runner`. See [Network: WireGuard & Tailscale](./network-vpn.md).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/admin/network/status` | Unified status and peer inventory for both WireGuard and Tailscale. |
| `GET/POST` | `/api/v1/admin/network/wireguard/peers` | Lists or enrolls persistent WireGuard peers (`0600` atomic `/etc/wireguard/wg0.conf`). |
| `POST` | `/api/v1/admin/network/wireguard/keygen` | Generates a one-time WireGuard client keypair held only in browser memory for QR/config handoff. |
| `POST` | `/api/v1/admin/network/tailscale/connect` | Initiates Tailscale login/reauthentication and returns the authorization URL. |
| `GET/POST` | `/api/v1/admin/network/tailscale/routes` | Reads or updates advertised Tailscale subnet routes. |

### 7. FlowAI & Action Approval Gate (`/api/v1/auth/ai`, `/api/v1/admin/actions`)
Interfaces with the multi-provider FlowAI engine (`af-api::intelligence`). See [FlowAI Assistant](./flowai.md).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/auth/ai/chat` | Multi-provider chat (Gemini, OpenAI, Anthropic, Ollama, LM Studio) with Assistant action detection. |
| `POST` | `/api/v1/auth/ai/support` | Grounded diagnostic session injecting live metrics and service logs (`full`, `logs`, `metrics`). |
| `POST` | `/api/v1/admin/settings/test-ai` | Tests provider connectivity using saved or unsaved API keys. |
| `GET` | `/api/v1/admin/actions/pending` | Lists Approval Inbox actions filtered by `status` (`pending`, `approved`, `queued`, `approved_history`, `rejected`, `executed`, `failed`, `unavailable`, `all`), reconciling queued deferred core-restart receipts before returning results. |
| `GET` | `/api/v1/admin/actions/{id}` | Returns a single Approval Inbox action record, reconciling any queued deferred core-restart `job_unit` receipt against `af-runner`'s durable status. |
| `POST` | `/api/v1/admin/actions/{id}/approve` | Authorizes and executes a pending action, recording an entry in `admin_audit_log`. Deferred `aetherflow-api`/`aetherflow-runner` restarts return `202 Accepted` (`status: "queued"`) with the persisted `job_unit` receipt instead of claiming immediate execution, and retries return `409 Conflict` without replaying. |

### 8. Cluster Master & Worker (`/api/v1/admin/cluster`)
Multi-node enrollment, telemetry heartbeats, and durable worker command orchestration (`af-services::cluster_daemon`; worker mTLS listener on `:50051` serves `/cluster/v1/register` and `/cluster/v1/heartbeat`).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/admin/cluster/enroll` | Issues a cluster enrollment token (`enrollment_token`) and worker mTLS onboarding instructions. |
| `GET` | `/api/v1/admin/cluster/nodes` | Lists registered cluster worker nodes, health status, and last-seen telemetry. |
| `DELETE` | `/api/v1/admin/cluster/nodes/{id}` | Removes a cluster worker node registration. |
| `GET` | `/api/v1/admin/cluster/nodes/{id}/metrics` | Returns recent telemetry metrics for a registered cluster worker node. |
| `GET` | `/api/v1/admin/cluster/commands` | Lists durable cluster worker commands and execution states (`queued`, `leased`, `executed`, `failed`, `unknown`). |
| `POST` | `/api/v1/admin/cluster/nodes/{id}/commands` | Enqueues a durable remote command for a registered cluster worker node. |

> [!NOTE]
> **Worker Command Delivery Durability, `unknown` Outcomes & Recovery Limits**:
> - Before invoking an admitted non-idempotent service mutation (`restart_service`, `start_service`, `stop_service`, `reload_service`, `systemctl`), the worker persists a confined `0600` execution intent receipt (`cluster_worker_command_receipts.json`, `O_NOFOLLOW`, `flock`, `fsync`) alongside its `0600` ACK outbox (`cluster_worker_ack_outbox.json`). If intent persistence fails, the mutation is refused and the command remains genuinely unstarted for normal lease retry.
> - **Operator-visible `unknown` status**: If a worker crashes or restarts after persisting execution intent and before persisting a final outcome, startup recovery transitions that receipt to terminal status `unknown` (with a diagnostic `result_message`) rather than guessing `executed`/`failed` or automatically replaying the mutation. The master records `unknown` and stops re-leasing the command; operators should inspect the target worker's service state and logs before issuing a new command.
> - **Lease fencing & reattachment**: Completed results (`executed`, `failed`, `unknown`) are persisted before ACK. Master lease fencing rejects delayed ACKs carrying stale `lease_generation` values. When a lost response or lease expiration causes the master to re-lease an already attempted command with a higher `lease_generation`, the worker validates command identity (`node_id`, `cmd_type`, `target`, `action`), reattaches the durable result to the freshly observed `lease_generation` without rerunning the host mutation, and rejects stale lease deliveries or conflicting command identities.
> - **Recovery limits**: Both the worker receipt ledger and ACK outbox are bounded to 256 entries and 512 KiB each; only master-confirmed terminal receipts are recycled. When all slots or byte budget are occupied by unconfirmed outcomes or active intents, new command dispatches fail closed with backpressure while existing in-flight commands, reattachments, and ACKs continue to drain. Deleting or corrupting the worker state directory removes local intent/outcome history (corrupt/symlinked/oversized receipt or outbox storage fails closed against new mutations). Legacy outbox records lacking identity metadata remain reattachable by command ID on newer leases until confirmed. Crashes before vs. after the underlying `systemctl`/service call within the intent window cannot be distinguished without host inspection and therefore resolve conservatively to `unknown`.

---

## Real-Time Telemetry (WebSockets)

AetherFlow pushes frame-0 hardware state, live service status, and package installation progress over a full-duplex WebSocket connection.

- **Ticket Handshake**: `GET /api/v1/auth/ws/ticket` (issues a single-use, 30-second TTL ticket).
- **WebSocket Endpoint**: `wss://<host>/api/v1/auth/ws?ticket=<ticket>`

Upon connection (`frame 0`), the server immediately broadcasts a `METRICS_UPDATE` snapshot containing cached CPU, memory, storage, GPU, network, and service states so charts and status badges hydrate without polling delay.
