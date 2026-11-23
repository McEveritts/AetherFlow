# {{PLUGIN_NAME}} (Rust Plugin SDK Template)

Standard AetherFlow Rust plugin scaffold (`plugins/sdk-template-rust`), the sole supported first-party AetherFlow plugin SDK.

## Security & Runtime Architecture (`backend-rs` v4.0.0)

- **Managed Discovery & Validation**: `aetherflow-api` discovers plugins under `plugins/<id>/plugin.manifest.json`, rejecting symbolic links, path traversal (`..`), untrusted ownership, and world-writable directories.
- **Scoped Short-Lived Plugin Tokens**:
  - Plugins authenticate with a dedicated credential class (`typ: "plugin"`, `iss: "aetherflow-plugin"`, `aud: "aetherflow-plugin-api"`) signed with an HMAC-derived plugin subkey and bound to the verified `plugin.manifest.json` and live database `token_epoch`.
  - **Never** pass an operator `aetherflow_session` JWT to a plugin. Operator session tokens and plugin tokens are cryptographically and structurally domain-separated.
  - `api_scopes` are validated against manifest permissions and default-deny `/api/v1/admin/*`, `/api/v1/ingress/*`, `/api/v1/auth/session`, `/api/v1/auth/sessions`, `/api/v1/auth/refresh`, `/api/v1/auth/logout`, `/api/v1/auth/ws`, `/api/v1/auth/profile`, `/api/v1/auth/user/2fa`, `/api/v1/auth/oidc`, `/api/v1/auth/plugins/*`, `/api/v1/plugins/*`, `/plugins/*` (and `/api/*` equivalents), plus non-GET/HEAD writes to `/api/v1/auth/{packages,services,system/update,deploy}`.
  - Disabling or stopping a plugin immediately increments `token_epoch` and revokes all active plugin `jti`s.
- **Runner-Managed OS & Systemd Isolation**:
  - `af-api` never spawns managed plugin binaries or `lifecycle_hooks.on_stop` hooks directly. Lifecycle actions delegate over `/run/aetherflow/runner.sock` (`/v1/plugins/{start,stop,status,token}`) to `aetherflow-runner.service`, which launches each managed plugin inside a transient `aetherflow-plugin-<id>.service` systemd unit with `DynamicUser=yes`, empty `SupplementaryGroups=`, `NoNewPrivileges=yes`, empty `CapabilityBoundingSet=`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectProc=invisible`, `KillMode=control-group`, `StateDirectory=aetherflow-plugin-<id>` (`0700`), read-only `/run/aetherflow-plugin-app` and `/run/aetherflow-plugin-token` (`AETHERFLOW_PLUGIN_TOKEN_FILE=/run/aetherflow-plugin-token/runtime.token`), and `InaccessiblePaths=` masking control-plane state.
  - `af-api` allocates the plugin port in `21000..=21999` and persists it in SQLite `plugins_registry`; `af-runner` validates the range and injects `PLUGIN_BIND_ADDR=127.0.0.1`, `PLUGIN_PORT=<allocated_port>`, and `PORT=<allocated_port>` as advisory environment conventions (only `af-api`'s reverse proxy enforces targeting `127.0.0.1:<allocated_port>`). Managed units share the host network namespace (`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` without `PrivateNetwork=yes`, `SocketBindDeny`/`SocketBindAllow`, or `IPAddressDeny`), so loopback services remain reachable from managed plugins. If `aetherflow-runner.service` or systemd isolation is unavailable, managed lifecycle operations fail closed with HTTP `503` (`PLUGIN_ISOLATION_UNAVAILABLE`).
  - **Standalone local development**: During local testing outside `af-runner`, you can run `cargo run` directly with `.env.example` values (`PLUGIN_PORT=21000` in `.env.example`; `DEFAULT_PLUGIN_PORT` in `backend/src/lib.rs` defaults to `9123` when `PLUGIN_PORT` is unset).
- **Sandboxed Frontend Origin & Loopback Proxy**:
  - Plugin UI mounts inside `<iframe sandbox="allow-scripts">` (without `allow-same-origin`) in an opaque origin that cannot access `document.cookie` or `localStorage`, served under `Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'; sandbox allow-scripts`.
  - The self-contained HTML/JS bundle (`frontend/dist/index.html`) completes the `postMessage` handshake (`AF_PLUGIN_READY` -> `AF_PLUGIN_INIT`) and sends scoped proxy requests (`AF_PLUGIN_PROXY_REQUEST`), receiving `AF_PLUGIN_PROXY_RESPONSE` payloads from the Leptos WASM host.
  - The host reverse proxy (`/api/v1/auth/plugins/:id/proxy/*`, plus `/plugins/:id/proxy/*`) connects strictly to `127.0.0.1:<allocated_port>`, rejects path traversal, caps request/response bodies at 2 MiB, blocks upstream `3xx` redirects, strips `Cookie`, `Authorization`, `X-CSRF-Token`, and `Set-Cookie`, and enforces `Content-Security-Policy: sandbox; default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` with `Cache-Control: private, no-store`.

## Layout

- `plugin.manifest.json`: Declarative plugin metadata, contract version, permissions, method-bound `api_scopes`, `frontend.entry` / `frontend.bundle` (`frontend/dist/index.html`), and lifecycle hook paths.
- `backend/`: Rust HTTP companion service (`axum` + `reqwest` + `tokio`) exposing `/healthz`, `/status`, and `/snapshot`.
  - `Cargo.toml`: Standalone Cargo manifest (`[workspace]` isolated so it does not mutate `backend-rs/Cargo.toml`).
  - `src/lib.rs`: Typed `AetherFlowClient`, endpoint path constants, configuration parser, HTTP router, and unit tests.
  - `src/main.rs`: Binary entrypoint reading `AETHERFLOW_API_BASE_URL` (default `http://127.0.0.1:8080`), `AETHERFLOW_PLUGIN_TOKEN_FILE` (preferred; re-read on every request by `AetherFlowClient::from_config`), `AETHERFLOW_PLUGIN_TOKEN` (standalone dev fallback), `AETHERFLOW_ALLOW_INSECURE_API_URL=1` (opt-in override to allow non-loopback `http://` base URLs), `PLUGIN_BIND_ADDR` (default `127.0.0.1`), and `PLUGIN_PORT` (default `9123`; `.env.example` sets `21000`).
  - `hooks/start.sh` & `hooks/stop.sh`: Lifecycle scripts executed inside the runner-managed transient systemd unit.
- `frontend/dist/index.html`: Self-contained sandboxed HTML/CSS/JS companion UI speaking `AF_PLUGIN_READY`, `AF_PLUGIN_INIT`, `AF_PLUGIN_PROXY_REQUEST`, and `AF_PLUGIN_PROXY_RESPONSE` over `window.parent.postMessage` (no Node.js build step required).
- `.env.example`: Environment variable template for standalone local development.

## AetherFlow HTTP Contracts Used

| Route | Auth Contract | Purpose |
| :--- | :--- | :--- |
| `GET /api/v1/public/marketplace` | Public (none required) | Reads catalog packages and installation state |
| `GET /api/v1/auth/system/metrics` | `Authorization: Bearer <scoped_plugin_token>` | Reads live CPU, memory, disk, swap, and uptime telemetry |

## Development & Verification Flow

1. Generate a Rust plugin scaffold (defaults to `rust`):
   ```bash
   bash scripts/create-plugin-sdk.sh my-plugin "My Plugin" plugins/my-plugin
   ```
2. Run unit and contract tests in `backend/`:
   ```bash
   cd plugins/my-plugin/backend
   cargo test
   ```
3. Build the release binary (`af-runner` automatically probes `backend/target/{release,debug}/<binary_name>` and falls back to `bin/<binary_name>` if absent; `plugin.manifest.json` has no `../bin/` path field because `backend.binary_name` must be a bare filename):
   ```bash
   cd plugins/my-plugin/backend
   cargo build --release
   # Optional: place the built binary in ../bin/ to use the runner's built-in bin/<binary_name> fallback
   mkdir -p ../bin
   cp target/release/aetherflow-plugin-my-plugin ../bin/
   ```
4. Enable and start the plugin from **Marketplace → Installed Plugins** (or `POST /api/v1/admin/plugins/my-plugin/control` with `{"action":"start"}`).
