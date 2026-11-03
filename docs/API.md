# API Reference

The AetherFlow API (`aetherflow-api`) is a high-concurrency **Rust (`Axum` + `Tokio`)** control plane (`backend-rs/crates/af-api`). It serves the embedded Next.js 16 (Obsidian V2) static frontend, RESTful endpoints for state mutation, Server-Sent Events (SSE), and full-duplex WebSocket streams for real-time telemetry.

> [!NOTE]
> This API powers the AetherFlow dashboard and the `af` CLI, and can also be consumed programmatically by administrators with valid session tokens or Bearer JWTs.

---

## Authentication & Security Headers

All API endpoints under `/api/v1/auth/*` and `/api/v1/admin/*` require an active session. AetherFlow enforces `HttpOnly` cookies (or `Authorization: Bearer`), SQLite-backed token revocation, `ALLOWED_HOSTS` checks, and CSRF protection.

### Session Cookie & Bearer Token
Authentication is driven by the `aetherflow_session` cookie (containing a signed 15-minute HS256 JWT) or an `Authorization: Bearer <token>` header.

### CSRF Protection
For any state-mutating cookie-authenticated request (`POST`, `PUT`, `PATCH`, `DELETE`), include the CSRF token and matching origin:

| Header | Description |
| :--- | :--- |
| `X-CSRF-Token` | The CSRF token issued during authentication or session initialization. |

---

## Core API Namespaces (`/api/v1`)

### 1. Public & Authentication (`/api/v1/public`, `/api/v1/auth`)
Handles login, TOTP 2FA verification, OAuth2/OIDC handshakes, and Subdomain Gateway SSO verification.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health/ready` | Readiness probe returning database status, uptime, and physical running binary version. |
| `POST` | `/api/v1/public/auth/login` | Authenticates credentials and issues the JWT session + CSRF token. |
| `POST` | `/api/v1/public/auth/verify-2fa` | Validates a 6-digit TOTP code or recovery code during login. |
| `GET` | `/api/v1/public/auth/verify` | Perimeter SSO endpoint for Apache2 Subdomain Gateway (`X-Aetherflow-User` injection). |
| `GET` | `/api/v1/auth/profile` | Returns the authenticated user's profile, role, and 2FA status. |
| `POST` | `/api/v1/auth/auth/logout` | Revokes the active JWT (`revoked_tokens`) and clears `aetherflow_session`. |

### 2. System, Services & Self-Update (`/api/v1/auth`, `/api/v1/admin`)
Provides hardware telemetry, `systemd` service lifecycle control (via `aetherflow-runner`), and atomic release management.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/auth/system/metrics` | Returns live CPU, RAM, swap, disk I/O, network, and NVML/DRM GPU metrics. |
| `GET` | `/api/v1/auth/services` | Lists managed `systemd` services, ports, subdomains, and runtime states. |
| `POST` | `/api/v1/admin/services/:name/:action` | Dispatches allowlisted `systemctl` actions (`start`, `stop`, `restart`, `enable`, `disable`) over `/run/aetherflow/runner.sock`. |
| `GET` | `/api/v1/admin/system/update/check` | Checks GitHub Releases for `stable`, `nightly`, or `experimental` updates (with 5-min cache & rate-limit backoff). |
| `POST` | `/api/v1/admin/system/update/run` | Launches an isolated `aetherflow-self-update.service` deployment or rollback. |
| `GET` | `/api/v1/admin/system/update/status` | Returns restart-surviving self-update status, operation ID, and recovery journal state. |

### 3. AetherMarketplace (`/api/v1/public/marketplace`, `/api/v1/admin/packages`)
Controls the lifecycle of the **77 bare-metal applications**.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/public/marketplace` | Lists all 77 catalog packages, categories, installation status, and update availability. |
| `POST` | `/api/v1/admin/packages/:id/install` | Starts asynchronous package installation via `af-runner` (declarative Rust or locked Bash). |
| `POST` | `/api/v1/admin/packages/:id/update` | Performs an in-place package update with automatic service stop/restart and rollback protection. |
| `DELETE` | `/api/v1/admin/packages/:id` | Uninstalls a package (preserving application data unless `delete_data=true`). |
| `POST` | `/api/v1/admin/packages/updates/check` | Checks upstream versions across installed Marketplace packages. |

### 4. Native McBrowser (`af-files` — `/api/v1/auth/mcbrowser`)
Capability-scoped tenant file manager backed by `af-files`. See [Native McBrowser](./mcbrowser.md).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/auth/mcbrowser/list` | Lists directory contents, breadcrumbs, sorting, and quota usage within the user's scoped root. |
| `POST` | `/api/v1/auth/mcbrowser/uploads` | Creates or manages resumable chunked upload sessions (up to 64 GiB per file, 4 MiB `PATCH` chunks). |
| `GET/PUT` | `/api/v1/auth/mcbrowser/content` | Reads or saves UTF-8 text files (up to 10 MiB) with ETag conflict detection. |
| `POST` | `/api/v1/auth/mcbrowser/actions` | Executes safe built-in actions (checksums, 9-format archive creation/extraction, media metadata). |
| `POST` | `/api/v1/auth/mcbrowser/shares` | Creates password-protected, expiring public share links. |

### 5. Canonical Streaming Analytics (`/api/v1/auth/streaming`, `/api/v1/admin/streaming`)
Live Jellyfin/Plex session telemetry and snapshot-consistent playback history. See [Streaming History Contract](./streaming-history-contract.md).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/auth/streaming/sessions` | Returns active Direct Play vs. Transcode sessions and real-time bandwidth. |
| `GET` | `/api/v1/auth/streaming/history` | Queries canonical playback history with rolling/calendar windows and snapshot cursors. |
| `GET` | `/api/v1/auth/streaming/history/export` | Streams full-query CSV export bound to `snapshotToken`. |
| `POST` | `/api/v1/admin/streaming/import` | Imports idempotent, checkpointed playback events (up to 500 per batch). |
| `POST` | `/api/v1/admin/streaming/reconcile/*` | Previews and executes backup-verified, human-approved history reconciliation. |

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
| `GET` | `/api/v1/admin/actions/pending` | Lists pending AI or `af-heal` remediation actions in the Approval Inbox. |
| `POST` | `/api/v1/admin/actions/:id/approve` | Authorizes and executes a pending action, recording an entry in `admin_audit_log`. |

---

## Real-Time Telemetry (WebSockets)

AetherFlow pushes frame-0 hardware state, live service status, and package installation progress over a full-duplex WebSocket connection.

- **Ticket Handshake**: `POST /api/v1/auth/ws-ticket` (issues a single-use, 30-second TTL ticket).
- **WebSocket Endpoint**: `wss://<host>/api/v1/ws?ticket=<ticket>`

Upon connection (`frame 0`), the server immediately broadcasts a `METRICS_UPDATE` snapshot containing cached CPU, memory, storage, GPU, network, and service states so charts and status badges hydrate without polling delay.
