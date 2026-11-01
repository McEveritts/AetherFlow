# Rust Migration Status (`v4.0.0`)

This document tracks the exact boundary between **already-shipped Rust services** in `backend-rs`, **implemented foundations awaiting production cutover**, and **unresolved/dormant contracts** across the AetherFlow repository.

---

## 1. Shipped & Integrated in `backend-rs`

The existing control plane uses six core crates compiled into `aetherflow-api`. The workspace now also registers `af-release`, `af-host`, and `af-cli`; registration does not imply production cutover.

| Component / Crate | Path | Status | Verified Responsibilities |
| :--- | :--- | :--- | :--- |
| **`af-api`** | `backend-rs/crates/af-api` | **Shipped & Integrated** | Axum 0.7 HTTP/WebSocket control plane, `rust-embed` Next.js 16 SPA delivery (`embed.rs` 5-step static/RSC resolver), HS256 JWT + TOTP + OIDC + CSRF + rate-limit middlewares, streaming subdomain reverse proxy (`Body::from_stream`), FlowAI multi-provider intelligence, MediaFlow endpoints, chunked backup upload/restore, cluster enrollment, and billing webhooks. |
| **`af-runner`** | `backend-rs/crates/af-runner` | **Shipped & Integrated** | Root UNIX domain socket daemon (`aetherflow-api runner` on `/run/aetherflow/runner.sock`, `0660 root:aetherflow`). Exposes `/v1/health`, `/v1/systemctl`, `/v1/package` (global `tokio::sync::Mutex` lock), `/v1/self-update`, `/v1/sandbox`, `/v1/hosts`, `/v1/network`, `/v1/quota`, and `/v1/app-meta`. |
| **`af-db`** | `backend-rs/crates/af-db` | **Shipped & Integrated** | Bundled `rusqlite` SQLite pool (`r2d2` `max_size(1)`) in `WAL` mode (`busy_timeout = 5000`, `synchronous = NORMAL`, `foreign_keys = ON`). Implements AES-256-GCM (`enc:v1:`) secret envelope encryption, active session storage, and SQLite-backed JWT revocation (eliminating the legacy Redis runtime requirement). |
| **`af-hardware`** | `backend-rs/crates/af-hardware` | **Shipped & Integrated** | Native `sysinfo` CPU/memory/swap/disk/network telemetry, `/proc/diskstats` & `/sys/block` I/O counters, and `libloading` dynamic FFI bindings to `libnvidia-ml.so.1` for zero-fork NVIDIA GPU telemetry. |
| **`af-services`** | `backend-rs/crates/af-services` | **Shipped & Integrated** | Marketplace catalog (`backend/config/packages.json` & `package_automation.json`) & blueprint dependency graph resolution, systemd/PM2 process probes, pure-Rust configuration mutators (`xml_xpath`, `ini_key`, `json_key`, `sqlite_query`, `pihole_Config`, `apache_vhosts`), background workers (`workers.rs`), and multi-node cluster heartbeat daemon (`cluster_daemon.rs`). |
| **`af-models`** | `backend-rs/crates/af-models` | **Shipped & Integrated** | Shared serde domain models, hardware snapshot structs, and runner IPC wire contracts. |
| **Release Build Pipeline** | `.github/workflows/release.yml`, `scripts/build_gold.sh` | **Shipped & Integrated** | Stages Next.js static export (`frontend/out/.` -> `backend/web/dist/`), runs `cargo test --workspace`, compiles `aetherflow-api` from `backend-rs`, and packages `aetherflow-linux-<arch>.tar.gz` + `SHA256SUMS`. |
| **Rust Plugin SDK Scaffold** | `plugins/sdk-template-rust/` | **Shipped (Standalone Scaffold)** | Standalone Rust companion plugin template (`axum` + `reqwest` + `tokio`) targeting verified `/api/v1/public/marketplace` and `/api/v1/auth/system/metrics` endpoints with explicit dormant-runtime disclosures. |

---

## 2. Implemented Foundations (NOT Yet Shipped or Integrated)

> [!WARNING]
> `af-release`, `af-host`, and `af-cli` are registered in `backend-rs/Cargo.toml`, but migration is not complete. The package executor is opt-in (`AETHERFLOW_ENABLE_RUST_PACKAGES=1`) and is undergoing validation; release/backup runtime cutover remains deferred. Hardened `af-host` passes 13 isolated Linux tests. Do not infer deployment or complete parity from workspace membership.

| Staged Component | Current Production Fallback | Unresolved Integration Boundary |
| :--- | :--- | :--- |
| **Rust Package Executor** | `af-runner` (`/v1/package` in `backend-rs/crates/af-runner/src/lib.rs`) validates package identifiers and serializes execution via a global `tokio::sync::Mutex`, then spawns `/bin/bash /opt/AetherFlow/current/packages/package/{install,remove,update}/<package>` (writing progress to `/srv/aetherflow/lock/pkg-<pkg>.log`). | The executor is wired into `af-runner` behind explicit opt-in; Bash remains the default. Only `fail2ban` is registered for opt-in native execution; `quassel` and `threadfin` remain deferred. Runner safety/streaming coverage passes 25 Linux tests; live-host cutover is not certified. |
| **`af-release`** | `af-runner` (`/v1/self-update`) and operator CLI upgrades execute `/bin/bash /opt/AetherFlow/current/deploy/release-manager.sh`. | `af-release` is a registered library with tested deployment/rollback primitives; review-driven hardening passes 15 isolated Linux tests. Live systemd rollout validation is still required; production self-update still calls Bash. |
| **`af-host`** | Privileged host helpers are executed as external scripts: `packages/system/af-systemd-sandbox`, `packages/system/setdisk`, `packages/system/af-certbot-sync` (called by `af-api`/`af-runner`), plus `packages/system/af-backup`, `packages/system/af-heal`, `packages/system/af-tune`, and `packages/system/af-sentinel.py`. | `af-host` is registered and its hardened backup/verification/preflight implementation passes 13 Linux tests. Existing API/scheduler consolidation and maintenance helper replacement remain incomplete; destructive live restore is unsupported. |
| **`af-cli`** | `packages/system/af` and `setup/AetherFlow-Setup` remain the installed administrative/bootstrap entrypoints. | Registered Rust `af` binary passes 11 isolated Linux tests and binary/socket smoke checks. It is not yet installed by release packaging, does not replace the interactive installer, and does not enable destructive restore or default Rust package dispatch. |

---

## 3. Unresolved Contracts & Dormant Subsystems

### 3.1 Plugin Runtime & Permission Model (`PluginManager` / `plugin.manifest.json`)
- **Dormant Legacy Host**: `backend/services/plugin_manager.go` defines a `wazero` WebAssembly host (`LoadPluginBytes`, `CallPluginFunc`), but it has **zero callers** in `backend/` and **no equivalent implementation** in `backend-rs/`.
- **Manifest & Lifecycle Loader Gap**: Neither `af-api` nor `af-services` parses `plugins/*/plugin.manifest.json`, executes `lifecycle_hooks.on_start` / `on_stop`, allocates dynamic ports (`port_allocation: "dynamic"`), or mounts a `/plugins/*` reverse proxy.
- **Declarative-Only Permissions & Scopes**: The `permissions` (`["marketplace:read", "system:metrics:read"]`) and `api_scopes` (`["/api/v1/public/marketplace", "/api/v1/auth/system/metrics"]`) fields in `plugin.manifest.json` are declarative metadata only. `af-api` (`backend-rs/crates/af-api/src/auth.rs`) validates standard operator HS256 session JWTs (`aetherflow_session` cookie or `Authorization: Bearer <jwt>`) and does not yet mint plugin-scoped tokens or enforce per-plugin route RBAC.
- **Frontend Slot Mounting**: `frontend/src/index.tsx` in both `plugins/sdk-template/` and `plugins/sdk-template-rust/` exports a static `PluginDefinition` (`slot: 'marketplace'`), but the Next.js shell does not dynamically bundle or hydrate third-party plugin directories at runtime.
- **Legacy Go SDK Drift**: `plugins/sdk-template/backend/main.go` and `plugins/sdk-template/frontend/src/lib/aetherflow.ts` still reference `/api/system/metrics` (unversioned) and `scripts/create-plugin-sdk.sh` defaults to the Go template and selects the Rust template with its optional fourth argument, `rust`. The new `plugins/sdk-template-rust/` uses the verified `/api/v1/auth/system/metrics` and `/api/v1/public/marketplace` routes.

### 3.2 Legacy Go Tree (`backend/`) & Shared Asset Paths
- Although `aetherflow-api` is built from `backend-rs/`, the `backend/` directory is still required at build and package time for two reasons:
  1. `backend/config/packages.json` and `backend/config/package_automation.json` are copied from `backend/config` into the release tarball (`config/`).
  2. `backend-rs/crates/af-api/src/embed.rs` embeds the compiled Next.js static export from `#[folder = "../../../backend/web/dist"]`.
- Retiring `backend/` completely requires relocating `backend/config/` and the embedded frontend staging path before removing legacy Go sources.

### 3.3 Bootstrap Installer Cutover (`setup/modules/modern_stack.sh`)
- `setup/modules/modern_stack.sh` still provisions a legacy Go/Node build-from-source layout rather than delegating to `deploy/release-manager.sh` to pull the pre-compiled Rust release tarball.


## 4. Integration Validation (October 31, 2026)

Validation ran in an isolated Linux checkout, not the production installation:

| Check | Result |
| :--- | :--- |
| `cargo test --workspace` | **109 passed**, zero failed: API 19, CLI 11, DB 2, hardware 3, host 13, models 2, release 15, runner 25, services 19. |
| `cargo check --workspace` | Passed; existing API dead-code warnings remain. |
| Rust SDK standalone tests | **3 passed**. |
| Build/scaffold Python tests | **4 passed**, using mock Cargo and temporary release/scaffold directories. |
| Shell syntax checks | Build/scaffold scripts and Rust SDK lifecycle hooks passed `bash -n`. |
| Rebuilt CLI smoke checks | JSON help/status; package/provision dry runs create no root directory; fake Unix-socket package stream emits human progress before completion and keeps JSON output clean. |

The workspace validation used a generated lockfile in the isolated checkout, not a committed/reproducible `--locked` dependency resolution. No production deployment, live package installation, service restart, commit, or branch creation was performed. Cross-architecture release packaging was checked with mocked build output, not real ARM cross-compilation. Production cutovers and the unsupported boundaries above remain separate work.
