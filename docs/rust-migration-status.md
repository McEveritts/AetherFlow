# Rust Migration Status (`v4.0.0`)

This document tracks the exact boundary between **shipped & integrated Rust services** in `backend-rs`, **opt-in / hybrid transition gates**, and **remaining intentional boundaries** across the AetherFlow repository.

---

## 1. Shipped & Integrated in `backend-rs`

The V4 Rust control plane compiles eleven workspace crates into `aetherflow-api`, `af` (`af-cli`), and `speedtest-backend` (`af-librespeed`), paired with the four-crate Leptos WASM dashboard in `frontend-rs`:

| Component / Crate | Path | Status | Verified Responsibilities |
| :--- | :--- | :--- | :--- |
| **`af-api`** | `backend-rs/crates/af-api` | **Integrated** | Axum HTTP/WebSocket control plane, runtime Rust WASM asset delivery from `STATIC_DIR` or executable-adjacent `web/dist`, HS256 JWT + TOTP + OIDC + CSRF + rate-limit middlewares, plugin-scoped JWT minting & RBAC (`auth.rs`), streaming subdomain & plugin reverse proxy (`Body::from_stream`), GitHub update response cache + rate-limit backoff + `stable`/`nightly` channel isolation + branch-head SHA fallback (`storage.rs`), Native McBrowser HTTP handlers, canonical Streaming History & reconciliation (including integration tests), FlowAI multi-provider intelligence, MediaFlow endpoints, chunked backup upload/restore, cluster enrollment, and user storage quotas. |
| **`af-runner`** | `backend-rs/crates/af-runner` | **Shipped & Integrated** | Root UNIX domain socket daemon (`aetherflow-api runner` on `/run/aetherflow/runner.sock`, `0660 root:aetherflow`). Exposes `/v1/health`, `/v1/systemctl`, `/v1/package` (12 built-in declarative Rust recipes + Bash fallback under shared advisory lock), `/v1/package/cancel`, `/v1/self-update` (isolated `aetherflow-self-update.service` launcher supporting native `af-release` engine + `release-manager.sh`), `/v1/sandbox`, `/v1/hosts`, `/v1/network`, `/v1/quota`, and `/v1/app-meta`. |
| **`af-files`** | `backend-rs/crates/af-files` | **Shipped & Integrated** | Native McBrowser capability-scoped tenant file system engine (`/var/lib/aetherflow/mcbrowser`), resumable chunked uploads up to 64 GiB, ETag-guarded UTF-8 editing, 9-format archive extraction/creation, public shares, and FlowAI BFS search. |
| **`af-db`** | `backend-rs/crates/af-db` | **Shipped & Integrated** | Bundled `rusqlite` SQLite pool (`r2d2` `max_size(1)`) in `WAL` mode (`busy_timeout = 5000`, `synchronous = NORMAL`, `foreign_keys = ON`). Implements AES-256-GCM (`enc:v1:`) secret envelope encryption, active session storage, and SQLite-backed JWT revocation (eliminating the legacy Redis runtime requirement). |
| **`af-hardware`** | `backend-rs/crates/af-hardware` | **Shipped & Integrated** | Native `sysinfo` CPU/memory/swap/disk/network telemetry, `/proc/diskstats` & `/sys/block` I/O counters, and `libloading` dynamic FFI bindings to `libnvidia-ml.so.1` for zero-fork NVIDIA GPU telemetry. |
| **`af-services`** | `backend-rs/crates/af-services` | **Shipped & Integrated** | Marketplace catalog (77 bare-metal packages including Tailscale, Palate, Maintainerr, McVNC, KasmVNC, Piped, Invidious & Blueprints), systemd process probes, pure-Rust configuration mutators (`xml_xpath`, `ini_key`, `json_key`, `sqlite_query`, `pihole_Config`, `apache_vhosts`), background workers (`workers.rs` wired to `af-host` for WAL-safe SQLite backups with `.manifest.json` + `.sha256` sidecars), native Plugin Manifest loader/validator/port allocator (`plugins.rs`), and HTTPS REST multi-node cluster heartbeat daemon (`cluster_daemon.rs`). |
| **`af-release`** | `backend-rs/crates/af-release` | **Shipped & Integrated** | Native Rust release engine (`Deploy`, `Rollback`, `Cleanup`, `MigrateSystemd`) with 4-tier SQLite DB path resolution, `stable`/`nightly` channel isolation, `/releases/latest` HTTP redirect fallback, `prepare_release_permissions` normalization (`aetherflow-api`, `af`, `packages/system/*`, `packages/package/*`), WAL-safe pre-swap snapshot + corrupted DB auto-recovery, executable runtime verification, and crash-safe `.recovery_state.json` journaling. Wired into `af-runner` (`/v1/self-update`) and `af-cli` (`af release`). |
| **`af-host`** | `backend-rs/crates/af-host` | **Shipped & Integrated** | Shared Rust host backup, verification, maintenance, and staged restore library. Provides `VACUUM INTO` / Online Backup API SQLite snapshots, `af-host.backup-manifest.v1` manifests, 5-digit chunk splitting/assembly, staged restore extraction (`execute_staged_restore` / `execute_coordinated_restore`), and native system maintenance tools (`sentinel_scan_auth_log`, `apply_network_tuning`, `clean_system_logs`, `inspect_home_disk_space`). Wired into `af-services::workers` and `af-cli`. |
| **`af-cli`** | `backend-rs/crates/af-cli` | **Shipped & Integrated** | Unified Rust `af` administrative CLI binary compiled & packaged alongside `aetherflow-api`. Supports `package`, `service`, `quota`/`setdisk`, `sandbox`, `release`, `backup` (including `restore --target-root <dir> --confirm-destructive-restore`), `maintenance` (`tune`, `sentinel`, `clean-logs`, `showspace`), `hosts`, `health`, and `provision` (14 Rust-native foundation steps with `# STATE_VERSION=2` persistence). |
| **`af-models`** | `backend-rs/crates/af-models` | **Shipped & Integrated** | Shared serde domain models, hardware snapshot structs, and runner IPC wire contracts. |
| **`af-librespeed`** | `backend-rs/crates/af-librespeed` | **Shipped & Zero-Go** | Native Rust `speedtest-backend` companion binary with SQLite WAL telemetry vault, legacy BoltDB migration, and keyed ULID obfuscation. |
| **WASM Frontend** | `frontend-rs` | **Integrated** | Four-crate Leptos dashboard and dedicated WASM workers (`af-web-core`, `af-web-worker`, `af-web-ui`, `af-web-app`), shared `af-models`, sixteen tabs, public login/OIDC/share routes, six locales, strict CSP, and responsive light/dark themes. See `frontend-rs/README.md`. |
| **Release Build Pipeline** | `.github/workflows/release.yml`, `scripts/build_gold.sh`, `setup/modules/modern_stack.sh` | **Integrated & Zero-Go** | Builds Rust WASM assets with Trunk, enforces Zero-Go hygiene, and packages external `web/dist` beside `aetherflow-api`, `af`, and `speedtest-backend` in `aetherflow-linux-<arch>.tar.gz` with `SHA256SUMS`. |
| **Rust Plugin Runtime & SDK** | `af-services::plugins`, `af-api`, `plugins/sdk-template-rust/` | **Shipped & Integrated** | Manifest discovery & validation (`plugin.manifest.json`), deterministic/dynamic port allocation (`21000..=21999`), plugin-scoped JWT minting (`POST /api/v1/admin/plugins/:id/token`), route-scope RBAC middleware, and streaming reverse proxy (`/api/v1/auth/plugins/:id/proxy/*rest`, `/plugins/:id/ui`, and `/plugins/:id/proxy/*rest`). |

---

## 2. Hybrid Dispatch & Feature Gates

| Component | Default Mode | Opt-In / Override Flag | Coverage & Behavior |
| :--- | :--- | :--- | :--- |
| **Declarative Rust Package Executor (`af-runner`)** | Hybrid: Bash fallback (`LegacyBashFallback`) by default unless `AETHERFLOW_ENABLE_RUST_PACKAGES=1` is set | `AETHERFLOW_ENABLE_RUST_PACKAGES=1` (or force Bash via `AETHERFLOW_FORCE_BASH_PACKAGES=1`) | **12 built-in declarative Rust recipes** (`fail2ban`, `quassel`, `threadfin`, `znc`, `xrdp`, `novnc`, `x2go`, `prometheus`, `netdata`, `mergerfs`, `rclone`, `syncthing`) with `GenerateSelfSignedTlsCert`, `CaptureDpkgVersion`, pre-start systemd sandboxing, and `RollbackJournal`. Remaining 65 catalog installers run under the same advisory lock and process-group supervisor. |
| **Release Self-Update (`af-runner` -> `af-release`)** | Isolated transient unit (`aetherflow-self-update-<command>-<channel>-<id>.service`) running `deploy/release-manager.sh` (or physical `af release <command> --local` when `AETHERFLOW_ENABLE_RUST_RELEASE=1` — deprecated alias `AETHERFLOW_USE_RUST_RELEASE=1`) | `AETHERFLOW_ENABLE_RUST_RELEASE=1` (or `af release deploy --local`) | `af-api` `run_update` dispatches `SelfUpdateRequest` over `/run/aetherflow/runner.sock`. Both `af-release` and `deploy/release-manager.sh` normalize binary permissions (`aetherflow-api`, `bin/af`), support `stable`/`nightly`, and resolve `/releases/latest` redirects. |
| **Host Backups & Staged Restore (`af-host`)** | Native Rust in `af-services` smart backup worker and `af-cli` | `af backup restore <filename> --target-root <dir> --confirm-destructive-restore` | `execute_online_sqlite_backup` uses `af_host::create_sqlite_snapshot_backup` (`OnlineBackupApi` + `.manifest.json` + `.sha256`). Unconfirmed `af backup restore` fails closed (`DestructiveRestoreUnsupported`, exit code `6`); confirmed staged restore extracts verified archives into `--target-root` (`0700`/`0600`) with automatic SQLite `PRAGMA quick_check`. |
| **Bare-Metal Provisioning (`af-cli::provision`)** | 14 Rust-Native Foundation steps + 21 Retained Shell Bootstrap steps (35 canonical steps in `CANONICAL_ALL_STEPS`) | `af provision run [<steps>...]` | `checkroot`, `logcheck`, `checkkernel`, `makedirs`, `boot`, `harden_perms`, `bashrc`, `hostname`, `locale`, `skel`, `apachesudo`, `build_modern`, `bbr`, and `perms` execute natively in Rust with `# STATE_VERSION=2` and symlink-free atomic writes. |

---

## 3. Intentional Boundaries & Shared Asset Paths

### 3.1 Frontend Dynamic Plugin Bundling
- Backend manifest loading, port allocation (`21000..=21999`), plugin-scoped JWT minting (`POST /api/v1/admin/plugins/:id/token`), per-route `api_scopes` enforcement, and streaming HTTP reverse proxying (`/plugins/:id/ui`, `/plugins/:id/proxy`, `/plugins/:id/proxy/*rest`) are fully implemented in `af-services::plugins` and `af-api`.
- The WASM dashboard mounts enabled plugin interfaces in sandboxed frames and mediates scoped API requests; companion plugins use the pure-Rust SDK (`plugins/sdk-template-rust/`).

### 3.2 Shared Asset Paths
- The canonical `config/` directory holds the package catalog, automation rules, and OpenAPI contract and is copied into release archives.
- `frontend-rs/dist/` holds the generated WASM bundle. Releases retain `web/dist/` beside `aetherflow-api`. `STATIC_DIR` selects an explicit alternate bundle; frontend assets are never compiled into the API.
- `tests/test_zero_go_cutover.py` guards the removal of the legacy Go backend, alongside the production workflow and installer contracts.

---

## 4. Integration Validation (November 1, 2026 Baseline + Zero-Go Cutover)

| Check | Result |
| :--- | :--- |
| `cargo test --workspace` (Nov 1 baseline) | **131 passed**, zero failed across the core control plane crates; `backend-rs` consolidates into **11 crates** (`af-api`, `af-runner`, `af-files`, `af-db`, `af-services`, `af-release`, `af-host`, `af-cli`, `af-hardware`, `af-librespeed`, `af-models`) alongside the **4 WASM crates** in `frontend-rs` (`af-web-core`, `af-web-worker`, `af-web-ui`, `af-web-app`). |
| Python release & build test suite | Current regression coverage spans `tests/test_release_manager.py`, `tests/test_rust_build_tools.py`, `tests/test_marketplace_lifecycle.py`, `tests/test_sandbox_paths.py`, `tests/test_v4_release_bootstrap_ci.py`, and Zero-Go repository hygiene tests in `tests/test_zero_go_cutover.py` (extending the 42-test Nov 1 baseline). |
| Rust SDK standalone tests | **3 passed** (`plugins/sdk-template-rust`); legacy Go `plugins/sdk-template/` removed. |
