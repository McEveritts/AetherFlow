# Rust Migration Status (`v4.0.0`)

This document tracks the exact boundary between **shipped & integrated Rust services** in `backend-rs`, **opt-in / hybrid transition gates**, and **remaining intentional boundaries** across the AetherFlow repository.

---

## 1. Shipped & Integrated in `backend-rs`

The V4 Rust control plane compiles eleven workspace crates into `aetherflow-api`, `af` (`af-cli`), and the streaming contract verification harness:

| Component / Crate | Path | Status | Verified Responsibilities |
| :--- | :--- | :--- | :--- |
| **`af-api`** | `backend-rs/crates/af-api` | **Shipped & Integrated** | Axum 0.7 HTTP/WebSocket control plane, `rust-embed` Next.js 16 SPA delivery (`embed.rs` 5-step static/RSC resolver), HS256 JWT + TOTP + OIDC + CSRF + rate-limit middlewares, plugin-scoped JWT minting & RBAC (`auth.rs`), streaming subdomain & plugin reverse proxy (`Body::from_stream`), GitHub update response cache + rate-limit backoff + `stable`/`nightly` channel isolation + branch-head SHA fallback (`storage.rs`), Native McBrowser HTTP handlers, canonical Streaming History & reconciliation, FlowAI multi-provider intelligence, MediaFlow endpoints, chunked backup upload/restore, cluster enrollment, and user storage quotas. |
| **`af-runner`** | `backend-rs/crates/af-runner` | **Shipped & Integrated** | Root UNIX domain socket daemon (`aetherflow-api runner` on `/run/aetherflow/runner.sock`, `0660 root:aetherflow`). Exposes `/v1/health`, `/v1/systemctl`, `/v1/package` (15 built-in declarative Rust recipes + Bash fallback under shared advisory lock), `/v1/package/cancel`, `/v1/self-update` (isolated `aetherflow-self-update.service` launcher supporting native `af-release` engine + `release-manager.sh`), `/v1/sandbox`, `/v1/hosts`, `/v1/network`, `/v1/quota`, and `/v1/app-meta`. |
| **`af-files`** | `backend-rs/crates/af-files` | **Shipped & Integrated** | Native McBrowser capability-scoped tenant file system engine (`/var/lib/aetherflow/mcbrowser`), resumable chunked uploads up to 64 GiB, ETag-guarded UTF-8 editing, 9-format archive extraction/creation, public shares, and FlowAI BFS search. |
| **`af-db`** | `backend-rs/crates/af-db` | **Shipped & Integrated** | Bundled `rusqlite` SQLite pool (`r2d2` `max_size(1)`) in `WAL` mode (`busy_timeout = 5000`, `synchronous = NORMAL`, `foreign_keys = ON`). Implements AES-256-GCM (`enc:v1:`) secret envelope encryption, active session storage, and SQLite-backed JWT revocation (eliminating the legacy Redis runtime requirement). |
| **`af-hardware`** | `backend-rs/crates/af-hardware` | **Shipped & Integrated** | Native `sysinfo` CPU/memory/swap/disk/network telemetry, `/proc/diskstats` & `/sys/block` I/O counters, and `libloading` dynamic FFI bindings to `libnvidia-ml.so.1` for zero-fork NVIDIA GPU telemetry. |
| **`af-services`** | `backend-rs/crates/af-services` | **Shipped & Integrated** | Marketplace catalog (77 bare-metal packages including Tailscale, Palate, Maintainerr, McVNC, KasmVNC, Piped, Invidious & Blueprints), systemd/PM2 process probes, pure-Rust configuration mutators (`xml_xpath`, `ini_key`, `json_key`, `sqlite_query`, `pihole_Config`, `apache_vhosts`), background workers (`workers.rs` wired to `af-host` for WAL-safe SQLite backups with `.manifest.json` + `.sha256` sidecars), native Plugin Manifest loader/validator/port allocator (`plugins.rs`), and multi-node cluster heartbeat daemon (`cluster_daemon.rs`). |
| **`af-release`** | `backend-rs/crates/af-release` | **Shipped & Integrated** | Native Rust release engine (`Deploy`, `Rollback`, `Cleanup`, `MigrateSystemd`) with 4-tier SQLite DB path resolution, `stable`/`nightly` channel isolation, `/releases/latest` HTTP redirect fallback, `prepare_release_permissions` normalization (`aetherflow-api`, `af`, `packages/system/*`, `packages/package/*`), WAL-safe pre-swap snapshot + corrupted DB auto-recovery, executable runtime verification, and crash-safe `.recovery_state.json` journaling. Wired into `af-runner` (`/v1/self-update`) and `af-cli` (`af release`). |
| **`af-host`** | `backend-rs/crates/af-host` | **Shipped & Integrated** | Shared Rust host backup, verification, maintenance, and staged restore library. Provides `VACUUM INTO` / Online Backup API SQLite snapshots, `af-host.backup-manifest.v1` manifests, 5-digit chunk splitting/assembly, staged restore extraction (`execute_staged_restore` / `execute_coordinated_restore`), and native system maintenance tools (`sentinel_scan_auth_log`, `apply_network_tuning`, `clean_system_logs`, `inspect_home_disk_space`). Wired into `af-services::workers` and `af-cli`. |
| **`af-cli`** | `backend-rs/crates/af-cli` | **Shipped & Integrated** | Unified Rust `af` administrative CLI binary compiled & packaged alongside `aetherflow-api`. Supports `package`, `service`, `quota`/`setdisk`, `sandbox`, `release`, `backup` (including `restore --staging-root`), `maintenance` (`tune`, `sentinel`, `clean-logs`, `showspace`), and `provision` (14 Rust-native foundation steps with `# STATE_VERSION=2` persistence). |
| **`af-models`** | `backend-rs/crates/af-models` | **Shipped & Integrated** | Shared serde domain models, hardware snapshot structs, and runner IPC wire contracts. |
| **`af-streaming-tests`** | `backend-rs/crates/af-streaming-tests` | **Shipped & Integrated** | Contract and integration verification suite for canonical streaming playback history, reconciliation, and portability. |
| **Release Build Pipeline** | `.github/workflows/release.yml`, `scripts/build_gold.sh`, `setup/modules/modern_stack.sh` | **Shipped & Integrated** | Stages Next.js static export (`frontend/out/.` -> `backend/web/dist/`), runs `cargo test --workspace`, compiles both `aetherflow-api` and `af` (`af-cli`) from `backend-rs`, packages `aetherflow-linux-<arch>.tar.gz` + `SHA256SUMS`, and provisions the V4 Rust stack in `modern_stack.sh`. |
| **Rust Plugin Runtime & SDK** | `af-services::plugins`, `af-api`, `plugins/sdk-template-rust/` | **Shipped & Integrated** | Manifest discovery & validation (`plugin.manifest.json`), deterministic/dynamic port allocation (`21000..=21999`), plugin-scoped JWT minting (`POST /api/v1/admin/plugins/:id/token`), route-scope RBAC middleware, and streaming reverse proxy (`/api/v1/auth/plugins/:id/proxy/*path` and `/plugins/:id/*path`). |

---

## 2. Hybrid Dispatch & Feature Gates

| Component | Default Mode | Opt-In / Override Flag | Coverage & Behavior |
| :--- | :--- | :--- | :--- |
| **Declarative Rust Package Executor (`af-runner`)** | Hybrid: Bash fallback (`LegacyBashFallback`) by default unless `AETHERFLOW_ENABLE_RUST_PACKAGES=1` is set | `AETHERFLOW_ENABLE_RUST_PACKAGES=1` (or force Bash via `AETHERFLOW_FORCE_BASH_PACKAGES=1`) | **15 built-in declarative Rust recipes** (`fail2ban`, `quassel`, `threadfin`, `znc`, `xrdp`, `novnc`, `x2go`, `scrutiny`, `prometheus`, `netdata`, `mergerfs`, `rclone`, `clamav`, `mosquitto`, `syncthing`) with `GenerateSelfSignedTlsCert`, `CaptureDpkgVersion`, pre-start systemd sandboxing, and `RollbackJournal`. Remaining 58 complex installers run under the same advisory lock and process-group supervisor. |
| **Release Self-Update (`af-runner` -> `af-release`)** | `deploy/release-manager.sh` in detached cgroup (or `af-release` when `AETHERFLOW_USE_RUST_RELEASE=1` or script absent) | `AETHERFLOW_USE_RUST_RELEASE=1` (or `af release deploy --local`) | `af-api` `run_update` dispatches `SelfUpdateRequest` over `/run/aetherflow/runner.sock` with local fallback. Both `af-release` and `deploy/release-manager.sh` normalize binary permissions (`aetherflow-api`, `bin/af`), support `stable`/`nightly`, and resolve `/releases/latest` redirects. |
| **Host Backups & Staged Restore (`af-host`)** | Native Rust in `af-services` smart backup worker and `af-cli` | `af backup restore --staging-root <dir>` | `execute_online_sqlite_backup` uses `af_host::create_sqlite_snapshot_backup` (`OnlineBackupApi` + `.manifest.json` + `.sha256`). Destructive live overwrite onto `/` remains blocked (`DestructiveRestoreUnsupported`); operators extract verified archives into an isolated `--staging-root` (`0700`/`0600`) with automatic SQLite `PRAGMA quick_check`. |
| **Bare-Metal Provisioning (`af-cli::provision`)** | 14 Rust-Native Foundation steps + 25 Retained Shell Bootstrap steps | `af provision run [<steps>...]` | `checkroot`, `logcheck`, `checkkernel`, `makedirs`, `boot`, `harden_perms`, `bashrc`, `hostname`, `locale`, `skel`, `apachesudo`, `build_modern`, `bbr`, and `perms` execute natively in Rust with `# STATE_VERSION=2` and symlink-free atomic writes. |

---

## 3. Intentional Boundaries & Shared Asset Paths

### 3.1 Frontend Dynamic Plugin Bundling
- Backend manifest loading, port allocation (`21000..=21999`), plugin-scoped JWT minting (`POST /api/v1/admin/plugins/:id/token`), per-route `api_scopes` enforcement, and streaming HTTP reverse proxying (`/plugins/:id/*path`) are fully implemented in `af-services::plugins` and `af-api`.
- Frontend UI slot components (`plugins/*/frontend/src/index.tsx`) remain compile-time/companion artifacts because the Next.js 16 dashboard is compiled as an immutable static export (`output: 'export'`) embedded into `aetherflow-api`.

### 3.2 Shared Asset Paths (`backend/config/` & `backend/web/dist/`)
- While the runtime control plane is 100% Rust (`backend-rs/`), two asset directories under `backend/` are used at build/package time:
  1. `backend/config/packages.json` and `backend/config/package_automation.json` are embedded at compile time and copied into release tarballs (`config/`).
  2. `backend-rs/crates/af-api/src/embed.rs` embeds the compiled Next.js static export from `#[folder = "../../../backend/web/dist"]`.

---

## 4. Integration Validation (November 1, 2026)

| Check | Result |
| :--- | :--- |
| `cargo test --workspace` | **131 passed**, zero failed: `af-api` (23), `af-cli` (13), `af-db` (2), `af-hardware` (3), `af-host` (18), `af-models` (2), `af-release` (18), `af-runner` (29), `af-services` (23). |
| Python release & build test suite | **42 ran (41 passed, 1 skipped)** across `tests/test_release_manager.py`, `tests/test_rust_build_tools.py`, `tests/test_installer_regressions.py`, and `tests/test_sandbox_regressions.py`. |
| Rust SDK standalone tests | **3 passed** (`plugins/sdk-template-rust`). |
