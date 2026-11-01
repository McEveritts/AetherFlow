# {{PLUGIN_NAME}} (Rust Plugin SDK Template)

Standard AetherFlow Rust plugin scaffold (`plugins/sdk-template-rust`).

## Scope & Runtime Reality (Dormant Plugin Runtime Disclosure)

> [!IMPORTANT]
> **No Active Host Plugin Runtime in `backend-rs` (v4.0.0):**
> AetherFlow v4.0.0 runs a single-binary Rust control plane (`backend-rs` -> `aetherflow-api`). At this stage of the migration, **there is no active in-process or managed plugin runtime**:
> - Legacy `backend/services/plugin_manager.go` (a `wazero` WebAssembly host prototype) is dormant and has zero callers in either `backend/` or `backend-rs/`.
> - `aetherflow-api` does **not** automatically discover `plugin.manifest.json`, allocate dynamic ports (`port_allocation: "dynamic"`), execute `lifecycle_hooks` (`on_start` / `on_stop`), mount `/plugins/*` reverse-proxy routes, or dynamically load `frontend/src/index.tsx` slots at runtime.
> - `permissions` and `api_scopes` in `plugin.manifest.json` are **declarative contract metadata only**. `aetherflow-api` does **not** mint plugin-scoped tokens or enforce fine-grained per-plugin scope RBAC yet.
> - To call authenticated AetherFlow endpoints (such as `/api/v1/auth/system/metrics`), the standalone plugin process must be provisioned with a valid operator HS256 session JWT in `AETHERFLOW_PLUGIN_TOKEN` (sent via `Authorization: Bearer <jwt>`), or restrict itself to unauthenticated public routes such as `/api/v1/public/marketplace`.

## Layout

- `plugin.manifest.json`: Declarative plugin metadata, contract version, target API scopes, and lifecycle hook paths.
- `backend/`: Standalone Rust HTTP companion service (`axum` + `reqwest` + `tokio`) that queries verified AetherFlow v4.0.0 HTTP contracts and exposes `/healthz` and `/snapshot`.
  - `Cargo.toml`: Standalone Cargo manifest (`[workspace]` isolated so it does not mutate `backend-rs/Cargo.toml`).
  - `src/lib.rs`: Typed `AetherFlowClient`, verified endpoint path constants, configuration parser, HTTP router, and contract unit tests.
  - `src/main.rs`: Binary entrypoint reading `AETHERFLOW_API_BASE_URL`, `AETHERFLOW_PLUGIN_TOKEN`, `PLUGIN_BIND_ADDR`, and `PLUGIN_PORT`.
  - `hooks/start.sh` & `hooks/stop.sh`: Reference lifecycle scripts for operator-managed systemd or supervisor units.
- `frontend/`: React 19 / TypeScript panel component (`PluginPanel.tsx`) designed for static compilation into the Next.js shell once frontend slot registration is wired.
- `.env.example`: Environment variable template for standalone operation.

## Verified AetherFlow HTTP Contracts Used

Unlike the legacy Go template (which referenced the unversioned `/api/system/metrics` path), this Rust SDK template targets actual routes mounted by `backend-rs/crates/af-api/src/routes.rs`:

| Route | Auth Contract | Purpose |
| :--- | :--- | :--- |
| `GET /api/v1/public/marketplace` | Public (`None` required) | Reads catalog packages and installation state |
| `GET /api/v1/auth/system/metrics` | `Authorization: Bearer <jwt>` or `aetherflow_session` cookie | Reads live CPU, memory, disk, swap, and uptime telemetry |
| `GET /health` | Public (`None` required) | Control-plane liveness probe (`/health/live`, `/health/ready`) |

## Standalone Development & Verification Flow

1. Generate a Rust scaffold (the optional fourth argument selects the SDK; existing callers still default to Go):
   ```bash
   bash scripts/create-plugin-sdk.sh my-plugin "My Plugin" plugins/my-plugin rust
   ```
2. Configure `.env` from `.env.example` with a valid `AETHERFLOW_API_BASE_URL` (default `http://127.0.0.1:8080`) and an operator session JWT in `AETHERFLOW_PLUGIN_TOKEN` if calling `/api/v1/auth/*`.
3. Run unit and contract tests in `backend/`:
   ```bash
   cd plugins/my-plugin/backend
   cargo test
   ```
4. Build and run the standalone companion service:
   ```bash
   cd plugins/my-plugin/backend
   cargo run --release
   ```
5. Probe the plugin service locally:
   - `GET http://127.0.0.1:9123/healthz` -> plugin health and contract metadata
   - `GET http://127.0.0.1:9123/snapshot` -> combined marketplace + system metrics snapshot from AetherFlow
