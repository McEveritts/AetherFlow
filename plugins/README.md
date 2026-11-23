# AetherFlow Plugin SDK

Community plugins live under `plugins/<plugin-id>/` and are discovered and validated by the AetherFlow Rust control plane (`backend-rs`).

## Scaffolding a Plugin

Rust (`plugins/sdk-template-rust/`) is the sole supported first-party plugin SDK. Generate a plugin scaffold (the optional 4th SDK argument defaults to `rust`):

```bash
bash scripts/create-plugin-sdk.sh my-plugin "My Plugin" plugins/my-plugin
# or explicitly:
bash scripts/create-plugin-sdk.sh my-plugin "My Plugin" plugins/my-plugin rust
```

## Security & Isolation Contract

1. **Manifest, Path & Ownership Validation**:
   - Each plugin directory must contain a non-symlink `plugin.manifest.json` whose `id` matches the directory name (`^[a-z0-9][a-z0-9-_]{1,62}$`).
   - All declared relative paths (`lifecycle_hooks.on_start`, `lifecycle_hooks.on_stop`, `backend.manifest_path`, `backend.entry`, `frontend.entry`, `frontend.bundle`) must resolve inside the canonical plugin directory without symlink escapes or traversal (`..`); `backend.binary_name` is validated as a bare filename (slashes `/` and `\` are forbidden) used to probe candidate paths within the plugin directory.
   - Plugin directories and executables are checked against world-writable permissions and untrusted ownership before discovery or launch.
2. **Short-Lived Scoped Plugin Tokens**:
   - Plugins use a dedicated credential class (`typ: "plugin"`, `iss: "aetherflow-plugin"`, `aud: "aetherflow-plugin-api"`) signed with an HMAC-derived plugin subkey and bound to the verified `plugin.manifest.json` and database `token_epoch`.
   - **Never** pass an operator `aetherflow_session` JWT to a plugin.
   - **Managed runtime delivery**: `af-runner` delivers rotating tokens via a read-only file mount at `AETHERFLOW_PLUGIN_TOKEN_FILE=/run/aetherflow-plugin-token/runtime.token` (never in process environment variables, `argv`, or logs). The `AETHERFLOW_PLUGIN_TOKEN` environment variable is for standalone local development only.
   - **Permission-bound `api_scopes` & default-deny list**: Scopes are validated against declared manifest permissions (allowing read/write routes only for matching permissions: `telemetry:read` / `system:read`, `system:metrics:read`, `system:hardware:read`, `services:read`, `packages:read`, `marketplace:read`, `notifications:read`, `notifications:write`). Default-denied prefixes (`DEFAULT_DENY_ROUTE_PREFIXES`, covering both `/api/v1/*` and `/api/*`) block `/admin`, `/ingress`, `/auth/session`, `/auth/sessions`, `/auth/refresh`, `/auth/logout`, `/auth/ws`, `/auth/profile`, `/auth/user/2fa`, `/auth/oidc`, `/auth/plugins`, `/plugins`, plus non-GET/HEAD writes on `/auth/{packages,services,system/update,deploy}`.
   - Stopping or disabling a plugin immediately increments `token_epoch` and revokes all active plugin `jti`s.
3. **Independent OS & Filesystem Isolation (`af-runner` + Transient `systemd` Units)**:
   - Managed plugin backends and `lifecycle_hooks.on_stop` hooks are never spawned directly by `af-api` as the `aetherflow` OS user. `af-api` delegates lifecycle management to `aetherflow-runner.service` (`/v1/plugins/{start,stop,status,token}`), which independently verifies `plugin.manifest.json` and launches each managed plugin inside a transient `aetherflow-plugin-<plugin-id>.service` unit.
   - Each managed unit enforces `DynamicUser=yes` (unique unprivileged UID/GID distinct from `root`, `aetherflow`, and sibling plugins), empty `SupplementaryGroups=`, `NoNewPrivileges=yes`, empty `CapabilityBoundingSet=`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectProc=invisible`, `KillMode=control-group`, and `InaccessiblePaths=` masking private control-plane state (`/var/lib/aetherflow`, `/etc/aetherflow`, `/etc/AetherFlow`, `/run/aetherflow`, `/var/log/aetherflow`).
   - Validated plugin assets are mounted read-only at `/run/aetherflow-plugin-app` (`WorkingDirectory=/run/aetherflow-plugin-app`), rotating tokens are mounted read-only at `AETHERFLOW_PLUGIN_TOKEN_FILE=/run/aetherflow-plugin-token/runtime.token`, and writable plugin-private state is provided at `PLUGIN_STATE_DIR=/var/lib/aetherflow-plugin-<plugin-id>` (`StateDirectoryMode=0700`).
   - **Port Allocation Convention**: `af-api` allocates (or accepts an admin-selected) port in `21000..=21999` and persists it in SQLite `plugins_registry`. `af-runner` validates that the port is within `21000..=21999` and passes `PLUGIN_BIND_ADDR=127.0.0.1`, `PLUGIN_PORT=<allocated_port>`, and `PORT=<allocated_port>` as advisory environment conventions; only `af-api`'s host reverse proxy enforces targeting `127.0.0.1:<allocated_port>`.
   - **Fail-Closed Runner Requirement & External Backends**: If `aetherflow-runner.service` or systemd isolation is unavailable, managed starts/stops fail closed with HTTP `503` (`PLUGIN_ISOLATION_UNAVAILABLE`) without falling back to the API user. External plugin backends (manifests without a managed binary/start hook or local stop hook) operate independently without `af-runner`.
   - **Shared Host Network & Loopback Boundary**: Managed units set `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` without `PrivateNetwork=yes`, `SocketBindDeny`/`SocketBindAllow`, or `IPAddressDeny`. Plugins share the host network namespace and can reach loopback services (including loopback-unauthenticated `/metrics` and all 9 loopback-bound gateway-protected Marketplace apps) or make outbound connections — **install only loopback-trusted plugins**.
4. **Sandboxed UI & Loopback Reverse Proxy**:
   - Plugin UIs are self-contained HTML/CSS/JS bundles (`frontend/dist/index.html`, no Node.js/React build required) mounted by the Leptos WASM dashboard inside `<iframe sandbox="allow-scripts">` (opaque unique origin without `allow-same-origin`) and served with `Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'; sandbox allow-scripts`.
   - Communication with the host uses the `postMessage` capability bridge: the iframe emits `AF_PLUGIN_READY`, receives `AF_PLUGIN_INIT` (capabilities + granted scopes), and sends `AF_PLUGIN_PROXY_REQUEST` messages to receive `AF_PLUGIN_PROXY_RESPONSE` payloads.
   - The host reverse proxy (`/api/v1/auth/plugins/:id/proxy/*`, with top-level `/plugins/:id/proxy/*` alias) targets only `127.0.0.1:<allocated_port>`, rejects path traversal and plugin-token recursive calls, caps request and response bodies at 2 MiB, blocks upstream `3xx` redirects (`PLUGIN_REDIRECT_BLOCKED`), strips sensitive request/response headers (`Cookie`, `Authorization`, `Proxy-Authorization`, `X-CSRF-Token`, `Set-Cookie`, `Set-Cookie2`, `Location`, upstream `Content-Security-Policy`, `X-Frame-Options`, hop-by-hop headers), and enforces `Cache-Control: private, no-store` plus `Content-Security-Policy: sandbox; default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` on every proxied response.

## Templates

- **`plugins/telemetry-inspector/`**: Self-contained managed sample plugin (`sdk: "managed-sample"`) with an unprivileged loopback HTTP runtime (`backend/runtime.py` launched via `backend/hooks/start.sh`) and sandboxed HTML/JS UI (`frontend/dist/index.html`) for end-to-end lifecycle, health, token, and proxy verification.
- **[`plugins/sdk-template-rust/`](./sdk-template-rust/README.md)**: The first-party developer SDK template (Rust backend + self-contained sandboxed HTML/JS bundle at `frontend/dist/index.html`) instantiated by `scripts/create-plugin-sdk.sh`; excluded from runtime discovery until instantiated into its own plugin directory.
