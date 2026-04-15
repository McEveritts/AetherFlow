# API Reference

The AetherFlow API is a high-performance Go backend built on the Gin framework. It provides both RESTful endpoints for state mutation and WebSocket connections for real-time telemetry.

> [!NOTE]
> This API is designed primarily for the AetherFlow dashboard, but it can be consumed programmatically by administrators with valid session tokens.

---

## Authentication

All API endpoints (except the login route) require an active session. AetherFlow uses HTTP-only cookies and CSRF protection to secure API interactions.

### The Session Cookie
Authentication is driven by the `aetherflow_session` cookie, which contains an encrypted JWT. This cookie is automatically managed by the browser but must be explicitly passed if using external clients like `curl` or Postman.

### CSRF Protection
For any non-GET request (POST, PUT, DELETE), you must include a valid CSRF token in the request headers.

| Header | Description |
| :--- | :--- |
| `X-CSRF-Token` | The token retrieved during the initial authentication handshake. |

---

## API Namespaces

The API is structured into four primary namespaces. All routes are prefixed with `/api/v1`.

### 1. Auth (`/auth`)
Handles session initialization, verification, and 2FA challenges.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/auth/login` | Authenticates user credentials and issues the session cookie. |
| `POST` | `/auth/verify-2fa` | Validates a TOTP code if local 2FA is active. |
| `GET` | `/auth/me` | Returns the current user profile and session validity. |
| `POST` | `/auth/logout` | Invalidates the JWT and clears the `aetherflow_session` cookie. |

### 2. System (`/system`)
Provides host-level diagnostics, service control, and configuration management.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/system/status` | Returns top-level health metrics (uptime, CPU, memory). |
| `GET` | `/system/logs` | Fetches the recent `journald` daemon logs for AetherFlow. |
| `POST` | `/system/services/:action` | Executes systemd actions (start, stop, restart) on a defined unit. |

### 3. Marketplace (`/marketplace`)
Controls the lifecycle of managed external applications.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/marketplace/catalog` | Lists all available apps and their local installation status. |
| `POST` | `/marketplace/install/:app` | Triggers the asynchronous installation workflow for an app. |
| `DELETE` | `/marketplace/remove/:app` | Initiates the safe uninstallation playbook for an app. |

### 4. AI (`/ai`)
Interfaces with the FlowAI sub-system for diagnostic execution and intent parsing.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/ai/chat` | Submits a query; optionally injects current system metrics if `support_mode=true`. |
| `GET` | `/ai/approvals` | Retrieves pending system mutations proposed by the AI in Assistant mode. |
| `POST` | `/ai/approvals/:id/decide`| Accepts or rejects an AI-proposed system mutation. |

---

## Real-Time Telemetry (WebSockets)

AetherFlow heavily utilizes WebSockets for sub-second telemetry feeds and streaming logs.

**Endpoint:** `ws://<host>:<port>/api/v1/ws`

### Sub-Protocols
When establishing a connection, the client must specify their intent by sending a subscription payload:

```json
{
  "type": "subscribe",
  "channel": "metrics.system"
}
```

### Available Channels
- `metrics.system`: Streams live CPU, RAM, and Disk IO data every 1000ms.
- `logs.daemon`: Pushes new lines from `/var/log/aetherflow/error.log` and `journald`.
- `marketplace.progress`: Emits structured task updates during package installations.

> [!WARNING]
> WebSocket connections are stateful and will be forcibly closed by the server if the `aetherflow_session` cookie expires. Clients must implement reconnect and re-authentication logic.
