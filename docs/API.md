# API Reference

The AetherFlow API (`aetherflow-api`) is a **Rust (`Axum` + `Tokio`)** control plane (`backend-rs/crates/af-api`). It serves the external **Leptos Rust WebAssembly (`frontend-rs`)** static frontend from `web/dist` (`STATIC_DIR` or `<exe-dir>/web/dist`), REST endpoints for state inspection and mutation, Server-Sent Events (SSE), and full-duplex WebSocket streams for real-time telemetry.

The authoritative OpenAPI 3.1 contract is maintained in [config/openapi-v1.yaml](../config/openapi-v1.yaml) and served at runtime from `GET /api/v1/public/openapi.yaml` and the zero-CDN Swagger UI at `GET /api/v1/public/swagger/`.

> [!NOTE]
> This HTTP/WebSocket API powers the AetherFlow WASM dashboard and can be consumed programmatically by authenticated users (`/api/v1/auth/*`) and administrators (`/api/v1/admin/*`) with valid session cookies or Bearer JWTs. By contrast, the local `af` CLI communicates with `aetherflow-runner.service` over `/run/aetherflow/runner.sock` and executes `af-release`, `af-host`, and `af-cli::provision` directly.

---

## Authentication & Security Headers

All API endpoints under `/api/v1/auth/*` and `/api/v1/admin/*` require an active session, except the session refresh route (`POST /api/v1/auth/refresh`), which accepts an expired session cookie within its 2-hour refresh grace window when paired with `X-Requested-With: XMLHttpRequest`. AetherFlow enforces `HttpOnly` cookies (or `Authorization: Bearer`), SQLite-backed token revocation, `ALLOWED_HOSTS` checks, and double-submit CSRF protection.

### Session Cookie & Bearer Token

Authentication uses the `aetherflow_session` cookie (containing a signed 15-minute HS256 JWT) or an `Authorization: Bearer <token>` header.

### CSRF Protection

For state-mutating cookie-authenticated requests (`POST`, `PUT`, `PATCH`, `DELETE`), include the double-submit CSRF token obtained from `GET /api/v1/public/csrf-token`. Requests authenticated with `Authorization: Bearer` and session refresh routes (`X-Requested-With: XMLHttpRequest`) are exempt from `X-CSRF-Token`.

| Header | Description |
| :--- | :--- |
| `X-CSRF-Token` | Double-submit token matching the `csrf_token` cookie issued by `GET /api/v1/public/csrf-token`. |

---

## Core API Namespaces (`/api/v1`)

### 1. Public, Authentication, Sessions & 2FA (`/api/v1/public`, `/api/v1/auth`)

Handles initial admin bootstrap, CSRF token issuance, login, TOTP 2FA verification, session management, OAuth2/OIDC handshakes, and Subdomain Gateway SSO verification.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/public/csrf-token` | Issues the `csrf_token` cookie and JSON `{ "csrf_token": "..." }` for double-submit CSRF validation. |
| `GET` | `/api/v1/public/auth/setup/check` | Reports whether initial administrator setup is required. |
| `POST` | `/api/v1/public/auth/setup` | Creates the first administrator account (remote/proxied requests require the one-time bootstrap token). |
| `POST` | `/api/v1/public/auth/login` | Authenticates credentials and sets the `HttpOnly` `aetherflow_session` cookie (or returns `{ "requires_mfa": true, "mfa_token": "..." }` for TOTP-enrolled accounts). Does not issue a CSRF token. |
| `POST` | `/api/v1/public/auth/mfa/verify` | Validates a 6-digit TOTP code or recovery code during login. |
| `GET` | `/api/v1/public/auth/verify` | Forward-auth perimeter SSO check subrequest returning `X-Aetherflow-User` and `Remote-User` response headers (the reverse proxy must strip untrusted client identity headers before forwarding; distinct from the Rust Subdomain Gateway, which strips spoofable headers and injects `X-Aetherflow-User` only). Enforces active, unrevoked administrator sessions against `revoked_tokens` and `active_sessions`. |
| `GET` | `/api/v1/public/openapi.yaml` | Serves the bundled OpenAPI 3.1 specification (`config/openapi-v1.yaml`). |
| `GET` | `/api/v1/public/swagger/` | Serves the zero-CDN interactive OpenAPI viewer. |
| `GET` | `/api/v1/auth/ready` | Authenticated readiness probe returning control-plane status, SQLite `database` health, and privileged `runner` health (`ok`, `unreachable`, or `disabled`) with `Cache-Control: no-store` on both `200` (`status: "ready"`) and `503` (`status: "not_ready"`). Unauthenticated probe: `/health/ready`. |
| `GET` | `/api/v1/auth/session` | Returns the authenticated user's session profile, role, and 2FA status. |
| `POST` | `/api/v1/auth/refresh` | Rotates the current session. Cookie clients send `X-Requested-With: XMLHttpRequest`. The public alias is `/api/v1/public/auth/refresh`. |
| `GET` | `/api/v1/auth/sessions` | Lists active sessions for the authenticated user (`DELETE /api/v1/auth/sessions/{jti}` revokes a specific session). |
| `PUT` | `/api/v1/auth/profile` | Updates the authenticated user's profile details (`PUT /api/v1/auth/profile/password`, `PUT`/`DELETE /api/v1/auth/profile/avatar`). |
| `POST` | `/api/v1/auth/user/2fa/setup` | Initiates TOTP 2FA enrollment (`POST /api/v1/auth/user/2fa/verify`, `POST /api/v1/auth/user/2fa/disable`, `POST /api/v1/auth/user/2fa/recovery/regenerate`). |
| `GET` | `/api/v1/auth/user/quota` | Returns the authenticated user's storage quota status and usage. |
| `GET` | `/api/v1/auth/fs` | Administrator-only host filesystem path picker bounded by `AF_ALLOWED_FS_ROOTS`. |
| `POST` | `/api/v1/auth/logout` | Revokes the active JWT (`revoked_tokens`) and clears `aetherflow_session`. |

> [!NOTE]
> **Readiness & Gateway Contracts**:
> - **Payload & Status**: `GET /health/ready` returns `{ status, version, uptime, database, redis, runner }`, whereas `GET /api/v1/auth/ready` returns `{ service: "aetherflow-api", status, database, runner }` (`runner` is `"ok"`, `"unreachable"`, or `"disabled"`). Failing any required check returns HTTP `503` (`"status": "not_ready"`) while keeping `"database": "ok"` if only the runner is unreachable.
> - **Runner Probing**: When `PRIVILEGED_RUNNER_ENABLED` is a trimmed, case-insensitive `1`, `true`, `yes`, or `on`, SQLite and `/v1/health` on the runner socket are probed concurrently with 2-second budgets; otherwise `"runner"` reports `"disabled"` and SQLite alone determines readiness.
> - **Headers & Release Gate**: `GET /api/v1/auth/ready` sets `Cache-Control: no-store` on both `200` and `503`, and neither route leaks diagnostic addresses or runner error bodies. Release managers default `HEALTH_ENDPOINT` to `http://127.0.0.1:8080/health/ready`; explicit overrides must report full application readiness.
> - **Subdomain Gateway Authentication**: Protected external application requests routed through the Rust gateway require an active administrator session or rate-limited Basic authentication (TOTP-enrolled admins must use a verified session, subject to the provisioning master-credential fallback and `.aether.local` private-IP routing rules documented in [Security & Hardening](./security.md)). Apache-authenticated vhosts and applications with native logins retain their respective policies.

### 2. System, Services & Self-Update (`/api/v1/auth`, `/api/v1/admin`)

Provides hardware telemetry, `systemd` service lifecycle control (via `aetherflow-runner`), and atomic release management.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/auth/system/metrics` | Returns live CPU, RAM, swap, disk I/O, network, and NVML/DRM GPU metrics (`GET /api/v1/auth/system/hardware` returns hardware inventory). |
| `GET` | `/api/v1/auth/services` | Lists managed `systemd` services, ports, subdomains, and runtime states. |
| `POST` | `/api/v1/admin/services/{name}/control` | Dispatches allowlisted `systemctl` actions (`start`, `stop`, `restart` only; `enable`/`disable` are rejected with HTTP `400` and restricted to the `af service` CLI) over `/run/aetherflow/runner.sock`. |
| `GET` | `/api/v1/admin/system/update/check` | Checks GitHub Releases for `stable` or `nightly` updates (retired `experimental` aliases to `nightly`; 5-minute cache and rate-limit backoff). Read-only authenticated alias: `GET /api/v1/auth/system/update/check`. |
| `POST` | `/api/v1/admin/system/update/run` | Launches a per-job transient systemd unit (`aetherflow-self-update-<command>-<channel>-<8hex>.service`) to execute a `deploy` operation (rollbacks run via `af release rollback`). |
| `GET` | `/api/v1/admin/system/update/status` | Returns restart-surviving self-update status, `operationId` (`job_unit`), and recovery state (`state`, `status`, `exit_code`, `error`). Read-only authenticated alias: `GET /api/v1/auth/system/update/status`. |

### 3. AetherMarketplace (`/api/v1/public/marketplace`, `/api/v1/admin/packages`)

Controls the lifecycle of the **77 bare-metal applications**.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/public/marketplace` | Lists all 77 catalog packages and categories. Authenticated callers also receive installation status, update availability, and the resolved app launch target. Use `?require_auth=1` to require live inventory. |
| `GET` | `/api/v1/auth/packages/{id}/progress` | Returns progress or the terminal lifecycle receipt. Pass `?job_id=<id>` to follow a specific operation across later jobs on the same package. |
| `POST` | `/api/v1/admin/packages/{id}/install` | Starts asynchronous package installation via `af-runner` (locked Bash by default, or opt-in declarative Rust recipes when `AETHERFLOW_ENABLE_RUST_PACKAGES=1`). |
| `POST` | `/api/v1/admin/packages/{id}/update` | Performs an in-place package update with service stop/restart and staged backup/rollback support where implemented by the installer or recipe. |
| `POST` | `/api/v1/admin/packages/{id}/reinstall` | Repairs or reinstalls an installed package while preserving its service configuration. |
| `POST` | `/api/v1/admin/packages/{id}/uninstall` | Uninstalls a package (preserving application data unless `?purge=true`). |
| `POST` | `/api/v1/admin/packages/updates/check` | Checks upstream versions across installed Marketplace packages. |
| `POST` | `/api/v1/admin/apps/launch` | Starts the dashboard session exchange for eligible Marketplace apps on managed public HTTPS routes. |

### 4. Native McBrowser (`af-files` + `af-api::mcbrowser` — `/api/v1/auth/mcbrowser`)

Capability-scoped tenant file manager backed by `af-files` primitives and `af-api::mcbrowser` handlers. See [Native McBrowser](./mcbrowser.md).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/auth/mcbrowser/entries` | Lists directory entries for `?path=...`, returning `{ path, entries, max_upload_bytes }` (quota usage is served by `GET /api/v1/auth/user/quota` and `GET /api/v1/auth/mcbrowser/usage`). |
| `GET/POST` | `/api/v1/auth/mcbrowser/uploads` | Lists or creates resumable chunked TUS upload sessions (up to 64 GiB per file; `PATCH`/`HEAD`/`DELETE` on `/api/v1/auth/mcbrowser/uploads/{id}`; files `<= 64 MiB` also use `PUT /api/v1/auth/mcbrowser/upload`). |
| `GET/PUT` | `/api/v1/auth/mcbrowser/content` | Reads or saves UTF-8 text files (up to 10 MiB) with ETag conflict detection. |
| `POST` | `/api/v1/auth/mcbrowser/actions` | Executes built-in actions (checksums, 9-format archive creation/extraction, media metadata). |
| `GET/POST` | `/api/v1/auth/mcbrowser/shares` | Lists or creates password-protected, expiring public share links (`DELETE /api/v1/auth/mcbrowser/shares/{id}`; public endpoints under `/api/v1/public/mcbrowser/shares/{token}`). |

### 5. Canonical Streaming Analytics (`/api/v1/auth/streaming`, `/api/v1/admin/streaming`)

Live Plex/Jellyfin/Emby session telemetry and snapshot-consistent playback history. See [Streaming History Contract](./streaming-history-contract.md).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/auth/streaming/dashboard` | Returns provider connection status, active Direct Play vs. Transcode sessions, and live bandwidth summary. |
| `GET` | `/api/v1/auth/streaming/history` | Queries canonical playback history with rolling/calendar windows and snapshot cursors (pattern and drilldown analytics live under `/api/v1/auth/streaming/patterns` and `/api/v1/auth/streaming/drilldown`). |
| `GET` | `/api/v1/auth/streaming/history/export` | Streams full-query CSV export bound to `?snapshot=<scope.snapshotToken>` (unknown query fields such as `?snapshotToken=...` are rejected with HTTP `400`). |
| `POST` | `/api/v1/admin/streaming/imports/events` | Imports idempotent, checkpointed playback events (up to 500 per batch, including native Plex/Tautulli JSON and CSV exports). |
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
| `GET/POST` | `/api/v1/admin/network/wireguard/peers` | Lists or enrolls persistent WireGuard peers (`0600` atomic `/etc/wireguard/wg0.conf`; `PUT`/`DELETE /api/v1/admin/network/wireguard/peers/{key}`). |
| `POST` | `/api/v1/admin/network/wireguard/keygen` | Generates a one-time WireGuard client keypair held only in browser memory for QR/config handoff. |
| `POST` | `/api/v1/admin/network/tailscale/connect` | Initiates Tailscale login/reauthentication and returns the authorization URL (`disconnect`, `logout`, `settings` also available). |
| `GET/POST` | `/api/v1/admin/network/tailscale/routes` | Reads or updates advertised Tailscale subnet routes. |

### 7. FlowAI, Action Approval Gate & Audit Log (`/api/v1/auth/ai`, `/api/v1/admin/actions`)

Interfaces with the multi-provider FlowAI engine (`af-api::intelligence`). See [FlowAI Assistant](./flowai.md).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/auth/ai/chat` | Multi-provider chat (Gemini, OpenAI, Anthropic, Ollama, LM Studio, `anthropic-local`) with service action detection for admin callers. |
| `POST` | `/api/v1/auth/ai/support` | Admin-only (`403` for non-admins) diagnostic session accepting optional `metrics_snapshot` and `system_logs` (falling back to recent `admin_audit_log` rows). |
| `POST` | `/api/v1/admin/settings/test-ai` | Tests provider connectivity using saved or unsaved API keys and model/endpoint selections. |
| `GET` | `/api/v1/admin/actions/pending` | Lists Approval Inbox actions filtered by `status` (`pending`, `approved`, `queued`, `approved_history`, `rejected`, `executed`, `failed`, `unavailable`, `all`), reconciling queued deferred core-restart receipts before returning results. |
| `GET` | `/api/v1/admin/actions/{id}` | Returns a single Approval Inbox action record, reconciling any queued deferred core-restart `job_unit` receipt against `af-runner`'s durable status. |
| `POST` | `/api/v1/admin/actions/{id}/approve` | Authorizes and executes a pending action, recording an entry in `admin_audit_log`. Deferred `aetherflow-api`/`aetherflow-runner` restarts return `202 Accepted` (`status: "queued"`) with the persisted `job_unit` receipt instead of claiming immediate execution, and retries return `409 Conflict` without replaying. |
| `POST` | `/api/v1/admin/actions/{id}/reject` | Rejects a pending Approval Inbox action and records the decision in `admin_audit_log`. |
| `GET` | `/api/v1/admin/audit-log` | Lists administrator audit log records (`admin_audit_log`). |

### 8. Cluster Master & Worker (`/api/v1/admin/cluster`)

Multi-node enrollment, telemetry heartbeats, and durable worker command orchestration (`af-services::cluster_daemon`). The TLS 1.3 mTLS listener (default `127.0.0.1:50051`, configured via `CLUSTER_GRPC_HOST:CLUSTER_GRPC_PORT`) serves both HTTP/2 gRPC (`cluster.ClusterService/{RegisterWorker,Heartbeat,GetMetrics,ExecuteCommand}`) and HTTPS JSON (`/cluster/v1/register`, `/cluster/v1/heartbeat`, `GET`/`POST /cluster/v1/commands`, `/cluster/v1/commands/ack`, `/cluster/v1/metrics`).

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
> - **Recovery limits**:
>   - **Capacity & backpressure**: Both the worker receipt ledger and ACK outbox are bounded to 256 entries and 512 KiB each; only master-confirmed terminal receipts are recycled. When full, new dispatches fail closed with backpressure while in-flight commands, reattachments, and ACKs drain.
>   - **State directory & legacy outbox**: Deleting or corrupting the worker state directory removes local intent/outcome history (corrupt, symlinked, or oversized storage fails closed against new mutations). Legacy outbox records lacking identity metadata remain reattachable by command ID on newer leases until confirmed.
>   - **Crash-window resolution**: Crashes before versus after the underlying `systemctl`/service call inside the intent window cannot be distinguished without host inspection and resolve conservatively to `unknown`.

### 9. Additional Control-Plane Namespaces

Full request/response schemas for these namespaces are defined in [config/openapi-v1.yaml](../config/openapi-v1.yaml):

| Domain | Representative Endpoints |
| :--- | :--- |
| **Backups** | `GET /api/v1/admin/backup/list`, `POST /api/v1/admin/backup/run`, `POST`/`GET /api/v1/admin/backup/download/{filename}`, `POST /api/v1/admin/backup/upload/{filename}` |
| **Plugins** | `GET /api/v1/auth/plugins`, `GET /api/v1/auth/plugins/{id}/ui`, `GET /api/v1/auth/plugins/{id}/proxy`, `GET /api/v1/admin/plugins`, `POST /api/v1/admin/plugins/{id}/control`, `POST /api/v1/admin/plugins/{id}/token` |
| **Users & Quotas** | `GET /api/v1/admin/quotas`, `PUT /api/v1/admin/quotas/{id}`, `POST /api/v1/admin/quotas/{id}/refresh` |
| **Notifications** | `GET /api/v1/auth/notifications`, `PUT /api/v1/auth/notifications/{id}/read`, `POST /api/v1/auth/notifications/dismiss-all`, `GET`/`POST /api/v1/admin/notifications/channels`, `GET`/`POST /api/v1/admin/notifications/rules` |
| **OIDC Provider** | `GET /api/v1/public/oidc/authorize`, `POST /api/v1/public/oidc/token`, `GET /api/v1/public/oidc/userinfo`, `GET /api/v1/public/oidc/jwks`, `POST /api/v1/public/oidc/revoke`, `POST /api/v1/public/oidc/introspect`, `POST /api/v1/public/oidc/device/authorize`, `POST /api/v1/auth/oidc/consent`, `POST /api/v1/auth/oidc/device/verify`, `POST /api/v1/auth/oidc/device/consent`, `GET`/`POST /api/v1/admin/oidc/clients` |
| **System Logs & Bookmarks** | `GET /api/v1/admin/logs`, `GET /api/v1/admin/logs/sources`, `GET`/`POST /api/v1/admin/logs/bookmarks`, `GET /api/v1/auth/ws/logs` |
| **MediaFlow** | `GET /api/v1/admin/mediaflow/queue`, `POST /api/v1/admin/mediaflow/scan`, `POST /api/v1/admin/mediaflow/approve/{id}`, `POST /api/v1/admin/mediaflow/decline/{id}` |
| **Ingress & Blueprints** | `GET /api/v1/admin/ingress/configs`, `PUT /api/v1/admin/ingress/apps/{appName}`, `POST /api/v1/admin/blueprints/{appName}/sync` |
| **FileShare** | `POST /api/v1/admin/fileshare/upload`, `GET /api/v1/admin/fileshare/download/{filename}`, `DELETE /api/v1/admin/fileshare/{filename}` |

---

## Real-Time Telemetry (WebSockets)

AetherFlow pushes initial hardware state, live service status, log streams, and package installation progress over full-duplex WebSocket connections.

- **Ticket Handshake**: `GET /api/v1/auth/ws/ticket` (issues a single-use, 30-second TTL ticket).
- **Telemetry WebSocket**: `wss://<host>/api/v1/auth/ws?ticket=<ticket>` — mounted behind `auth_middleware` and `Origin` validation, so callers (including non-browser programmatic clients) must present both an active `aetherflow_session` cookie or `Authorization: Bearer` header and a valid `?ticket=<ticket>`.
- **Log Stream WebSocket (Admin Only)**: `wss://<host>/api/v1/auth/ws/logs` — does not use `?ticket=`; requires an active administrator `aetherflow_session` cookie or `Authorization: Bearer` header (non-admins receive HTTP `403 FORBIDDEN`) plus `Origin` validation.

Upon connection, the server immediately sends an initial `METRICS_UPDATE` snapshot containing cached CPU, memory, storage, GPU, network, and service states so dashboard charts and status badges populate without waiting for the next polling interval.
