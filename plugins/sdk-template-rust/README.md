# {{PLUGIN_NAME}} (Rust Plugin SDK Template)

Standard AetherFlow Rust plugin scaffold (`plugins/sdk-template-rust`).

## Security & Runtime Architecture (`backend-rs` v4.0.0)

- **Managed Discovery & Validation**: `aetherflow-api` discovers plugins under `plugins/<id>/plugin.manifest.json`, rejecting symbolic links, path traversal (`..`), and world-writable directories.
- **Scoped Short-Lived Plugin Tokens**:
  - Plugins authenticate with a dedicated credential class (`typ: "plugin"`, `iss: "aetherflow-plugin"`, `aud: "aetherflow-plugin-api"`) signed with an HMAC-derived plugin subkey and bound to the verified `plugin.manifest.json` + live database `token_epoch`.
  - **Never** pass an operator `aetherflow_session` JWT to a plugin. Operator session tokens and plugin tokens are cryptographically and structurally domain-separated.
  - Plugin tokens are enforced per HTTP method + route pattern and default-deny `/api/v1/auth/session`, `/api/v1/auth/refresh`, `/api/v1/admin/users`, `/api/v1/admin/settings`, and `/api/v1/admin/plugins/*`.
  - Disabling or stopping a plugin immediately increments its `token_epoch` and revokes all active plugin `jti`s.
- **Unprivileged Process & Systemd Isolation**:
  - Host-spawned plugin processes run with `PR_SET_NO_NEW_PRIVS`, scrubbed environment variables, and loopback-only binding (`127.0.0.1:<allocated_port>` in `21000..21999`).
  - If running via a custom systemd unit, always isolate the plugin user **outside** the `root:aetherflow` privileged runner group:
    ```ini
    [Service]
    User=aetherflow-plugin
    Group=aetherflow-plugin
    DynamicUser=yes
    SupplementaryGroups=
    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    PrivateTmp=yes
    ```
- **Sandboxed Frontend Origin & Loopback Proxy**:
  - Plugin UI mounts inside `<iframe sandbox="allow-scripts">` (without `allow-same-origin`), isolating it in an opaque origin that cannot read `document.cookie` or `localStorage`.
  - The iframe communicates with the host via `window.parent.postMessage({ type: 'AF_PLUGIN_PROXY_REQUEST', pluginId, path, method }, '*')`.
  - The host reverse proxy (`/api/v1/auth/plugins/:id/proxy/*`) connects strictly to `127.0.0.1:<allocated_port>`, rejects path traversal, caps bodies at 2 MiB, and strips `Cookie`, `Authorization`, `X-CSRF-Token`, and `Set-Cookie`.

## Layout

- `plugin.manifest.json`: Declarative plugin metadata, contract version, method-bound `api_scopes`, and lifecycle hook paths.
- `backend/`: Rust HTTP companion service (`axum` + `reqwest` + `tokio`) that queries verified AetherFlow v4.0.0 HTTP contracts and exposes `/healthz`, `/status`, and `/snapshot`.
  - `Cargo.toml`: Standalone Cargo manifest (`[workspace]` isolated so it does not mutate `backend-rs/Cargo.toml`).
  - `src/lib.rs`: Typed `AetherFlowClient`, verified endpoint path constants, configuration parser, HTTP router, and contract unit tests.
  - `src/main.rs`: Binary entrypoint reading `AETHERFLOW_API_BASE_URL`, `AETHERFLOW_PLUGIN_TOKEN`, `PLUGIN_BIND_ADDR`, and `PLUGIN_PORT`.
  - `hooks/start.sh` & `hooks/stop.sh`: Lifecycle scripts invoked by the host plugin manager or isolated unprivileged systemd unit.
- `frontend/`: React 19 / TypeScript panel component (`PluginPanel.tsx`) using the host `postMessage` capability bridge.
- `.env.example`: Environment variable template for local development.

## Verified AetherFlow HTTP Contracts Used

| Route | Auth Contract | Purpose |
| :--- | :--- | :--- |
| `GET /api/v1/public/marketplace` | Public (`None` required) | Reads catalog packages and installation state |
| `GET /api/v1/auth/system/metrics` | `Authorization: Bearer <scoped_plugin_token>` | Reads live CPU, memory, disk, swap, and uptime telemetry |
| `GET /health` | Public (`None` required) | Control-plane liveness probe (`/health/live`, `/health/ready`) |

## Development & Verification Flow

1. Generate a Rust plugin scaffold:
   ```bash
   bash scripts/create-plugin-sdk.sh my-plugin "My Plugin" plugins/my-plugin rust
   ```
2. Run unit and contract tests in `backend/`:
   ```bash
   cd plugins/my-plugin/backend
   cargo test
   ```
3. Build the release binary so the AetherFlow plugin manager can supervise it:
   ```bash
   cd plugins/my-plugin/backend
   cargo build --release
   ```
4. Enable and start the plugin from **Marketplace -> Installed Plugins & Runtime Extensions** (or `POST /api/v1/admin/plugins/my-plugin/control` with `{"action":"start"}`).
