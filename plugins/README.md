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

1. **Manifest Validation**: Each plugin directory must contain a non-symlink `plugin.manifest.json` whose `id` matches the directory name (`^[a-z0-9][a-z0-9-_]{1,62}$`). Relative paths (`on_start`, `on_stop`, `backend.entry`, `frontend.entry`) must remain strictly inside the canonical plugin directory.
2. **Short-Lived Scoped Plugin Tokens (`AETHERFLOW_PLUGIN_TOKEN`)**:
   - Plugins use a dedicated credential class (`typ: "plugin"`, `iss: "aetherflow-plugin"`, `aud: "aetherflow-plugin-api"`) signed with an HMAC-derived plugin subkey and bound to the verified `plugin.manifest.json` and database `token_epoch`.
   - **Never** pass an operator `aetherflow_session` JWT to a plugin.
   - `api_scopes` are enforced per HTTP method and route (`GET /api/v1/auth/system/metrics`, `GET /api/v1/public/marketplace`). Protected endpoints (`/api/v1/auth/session`, `/api/v1/auth/refresh`, `/api/v1/admin/users`, `/api/v1/admin/settings`, `/api/v1/admin/plugins/*`) are always default-denied.
   - Stopping or disabling a plugin immediately bumps `token_epoch` and revokes all active plugin `jti`s.
3. **Unprivileged Runtime & Systemd Isolation**:
   - Plugins bind strictly to `127.0.0.1:<allocated_port>` (`21000..21999`) with `NoNewPrivileges` (`PR_SET_NO_NEW_PRIVS`).
   - Systemd service units for plugins must run as an unprivileged user (`User=aetherflow-plugin`, `DynamicUser=yes`, `SupplementaryGroups=`) **outside** the `root:aetherflow` privileged runner socket group.
4. **Sandboxed UI & Loopback Reverse Proxy**:
   - Plugin UIs are self-contained HTML/CSS/JS bundles (`frontend/dist/index.html`, zero Node.js/React build step) mounted by the Leptos WASM dashboard inside `<iframe sandbox="allow-scripts">` (opaque unique origin without `allow-same-origin`).
   - Communication with the host uses the strict `postMessage` capability bridge: the iframe emits `AF_PLUGIN_READY`, receives `AF_PLUGIN_INIT` (capabilities + granted scopes), and issues `AF_PLUGIN_PROXY_REQUEST` messages to receive `AF_PLUGIN_PROXY_RESPONSE` payloads.
   - The host reverse proxy (`/api/v1/auth/plugins/:id/proxy/*`) targets only `127.0.0.1:<allocated_port>`, rejects path traversal, caps bodies at 2 MiB, and strips `Cookie`, `Authorization`, `X-CSRF-Token`, and `Set-Cookie`.
5. **Sample vs. SDK Templates**:
   - `plugins/telemetry-inspector/` is a self-contained managed sample plugin (`sdk: "managed-sample"`) with an unprivileged loopback HTTP runtime (`backend/runtime.py` launched via `backend/hooks/start.sh`) and custom sandboxed HTML/JS bundle (`frontend/dist/index.html`) for end-to-end lifecycle, health, token, and proxy verification.
   - `plugins/sdk-template-rust/` is the sole supported first-party developer SDK template (Rust backend + self-contained sandboxed HTML/JS bundle at `frontend/dist/index.html`) used by `scripts/create-plugin-sdk.sh` and is excluded from runtime discovery until instantiated as a concrete plugin directory.
