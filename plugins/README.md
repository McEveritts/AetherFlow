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
3. **Independent OS & Filesystem Isolation (`af-runner` + Transient `systemd` Units)**:
   - Managed plugin backends and `lifecycle_hooks.on_stop` hooks are never spawned directly by `af-api` as the `aetherflow` API OS user. `af-api` delegates lifecycle management to `aetherflow-runner.service` (`/v1/plugins/{start,stop,status,token}`), which independently verifies `plugin.manifest.json` and launches each managed plugin inside a transient `aetherflow-plugin-<plugin-id>.service` unit.
   - Each managed unit enforces `DynamicUser=yes` (unique unprivileged UID/GID distinct from `root`, `aetherflow`, and sibling plugins), empty `SupplementaryGroups=`, `NoNewPrivileges=yes`, empty `CapabilityBoundingSet=`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectProc=invisible`, `KillMode=control-group`, and `InaccessiblePaths=` masking private control-plane state (`/var/lib/aetherflow`, `/etc/aetherflow`, `/etc/AetherFlow`, `/run/aetherflow`, `/var/log/aetherflow`).
   - Validated plugin assets are mounted read-only at `/run/aetherflow-plugin-app` (`WorkingDirectory=/run/aetherflow-plugin-app`), rotating tokens are mounted read-only at `AETHERFLOW_PLUGIN_TOKEN_FILE=/run/aetherflow-plugin-token/runtime.token` (never passed in `argv`, env, or logs), and writable plugin-private state is provided at `PLUGIN_STATE_DIR=/var/lib/aetherflow-plugin-<plugin-id>` (`StateDirectoryMode=0700`).
   - Plugins bind strictly to `127.0.0.1:<allocated_port>` (`21000..21999`). If `aetherflow-runner.service` or systemd isolation is unavailable, managed starts/stops fail closed with HTTP `503` (`PLUGIN_ISOLATION_UNAVAILABLE`) and zero unsafe fallback. External plugin backends (manifests without a managed binary/start hook or local stop hook) continue to operate independently without `af-runner`.
4. **Sandboxed UI & Loopback Reverse Proxy**:
   - Plugin UIs are self-contained HTML/CSS/JS bundles (`frontend/dist/index.html`, zero Node.js/React build step) mounted by the Leptos WASM dashboard inside `<iframe sandbox="allow-scripts">` (opaque unique origin without `allow-same-origin`).
   - Communication with the host uses the strict `postMessage` capability bridge: the iframe emits `AF_PLUGIN_READY`, receives `AF_PLUGIN_INIT` (capabilities + granted scopes), and issues `AF_PLUGIN_PROXY_REQUEST` messages to receive `AF_PLUGIN_PROXY_RESPONSE` payloads.
   - The host reverse proxy (`/api/v1/auth/plugins/:id/proxy/*`) targets only `127.0.0.1:<allocated_port>`, rejects path traversal, caps bodies at 2 MiB, and strips `Cookie`, `Authorization`, `X-CSRF-Token`, and `Set-Cookie`.
5. **Sample vs. SDK Templates**:
   - `plugins/telemetry-inspector/` is a self-contained managed sample plugin (`sdk: "managed-sample"`) with an unprivileged loopback HTTP runtime (`backend/runtime.py` launched via `backend/hooks/start.sh`) and custom sandboxed HTML/JS bundle (`frontend/dist/index.html`) for end-to-end lifecycle, health, token, and proxy verification.
   - `plugins/sdk-template-rust/` is the sole supported first-party developer SDK template (Rust backend + self-contained sandboxed HTML/JS bundle at `frontend/dist/index.html`) used by `scripts/create-plugin-sdk.sh` and is excluded from runtime discovery until instantiated as a concrete plugin directory.
