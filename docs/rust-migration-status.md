# Rust Migration Status (`v4.0.0`)

This document tracks the boundary between **shipped Rust services** in `backend-rs`, **opt-in / hybrid transition gates**, and **intentional architectural boundaries** across the AetherFlow repository.

---

## 1. Shipped & Integrated in `backend-rs`

The v4 Rust control plane compiles eleven workspace crates into `aetherflow-api`, `af` (`bin/af`), and `speedtest-backend` (`bin/speedtest-backend`), paired with the four-crate Leptos WASM dashboard in `frontend-rs`:

| Component / Crate | Path | Status | Verified Responsibilities |
| :--- | :--- | :--- | :--- |
| **`af-api`** | `backend-rs/crates/af-api` | **Shipped** | Axum HTTP/WebSocket control plane serving external `web/dist` WASM assets (`STATIC_DIR` or `<exe-dir>/web/dist`). Implements JWT/TOTP/OIDC/CSRF/rate-limit auth, plugin discovery/tokens/proxy (`backend-rs/crates/af-api/src/plugins/{tokens,proxy}.rs`, ports `21000..=21999`), streaming subdomain proxying (`Body::from_stream`), GitHub release caching (`storage/updater.rs`), Native McBrowser (`mcbrowser/`), canonical Streaming History, FlowAI, MediaFlow, chunked backup upload/restore, cluster enrollment, and storage quotas. See [API Reference](./API.md) and [Architecture](./architecture.md). |
| **`af-runner`** | `backend-rs/crates/af-runner` | **Shipped** | Root Unix domain socket daemon (`aetherflow-api runner` on `/run/aetherflow/runner.sock`, `0660 root:aetherflow`). Exposes `/v1/health`, `/v1/systemctl`, `/v1/package` (locked Bash fallback by default + 9 opt-in declarative Rust recipes under shared advisory lock), `/v1/package/cancel`, `/v1/package/lifecycle-snapshot`, `/v1/package/probe-version`, `/v1/self-update` and `/v1/self-update/status` (per-launch transient units `aetherflow-self-update-<command>-<channel>-<8hex>.service` running `af-release` by default or `deploy/release-manager.sh`), `/v1/backup`, `/v1/blueprint/apply`, `/v1/sandbox`, `/v1/hosts`, `/v1/network`, `/v1/quota`, `/v1/quota/usage`, `/v1/app-meta`, `/v1/dispatcharr-credentials`, `/v1/ingress/vhost`, `/v1/certbot-sync`, and `/v1/plugins/{start,stop,status,token}` (transient `DynamicUser=yes` plugin isolation units). |
| **`af-files`** | `backend-rs/crates/af-files` | **Shipped** | Low-level capability-scoped Linux `openat2` / `BrowserFs` filesystem confinement primitives enforcing `0700` per-user roots and traversal guards for `af-api::mcbrowser`. |
| **`af-db`** | `backend-rs/crates/af-db` | **Shipped** | Bundled `rusqlite` SQLite WAL pools: `max_size(1)` writer pool (`DB_POOL`, `busy_timeout = 5000`, `synchronous = NORMAL`, `foreign_keys = ON`) plus `max_size(8)` read-only pool (`DB_READ_POOL`, `query_only = ON`, `busy_timeout = 750ms`). Implements AES-256-GCM (`enc:v1:<base64(nonce \|\| ciphertext)>`) secret encryption, active session storage, and SQLite-backed JWT revocation (no Redis dependency). |
| **`af-hardware`** | `backend-rs/crates/af-hardware` | **Shipped** | Native `sysinfo` CPU/memory/swap/disk/network telemetry, `/proc/diskstats` I/O counters (filtered via `/sys/class/block/<dev>/{partition,dm}`), `/sys/block` storage device inventory, and `libloading` dynamic FFI bindings to `libnvidia-ml.so.1` for zero-fork NVIDIA GPU utilization, VRAM, and temperature telemetry. |
| **`af-services`** | `backend-rs/crates/af-services` | **Shipped** | Marketplace catalog (77 bare-metal packages & Blueprints), systemd process probes, SQLite/config mutator integration (`mutate_sqlite_setting`, re-exporting `af-runner::blueprint`'s `mutate_xml_element`, `mutate_ini_key`, and `mutate_json_key`; `mutate_pihole_toml`, `mutate_yaml_section_key`, `mutate_systemd_aspnetcore_urls`, and `mutate_dispatcharr_port` live directly in `af-runner::blueprint`; Apache vhost sync delegates to `/v1/ingress/vhost`), background workers (`workers.rs`, `af-heal`, MediaFlow queue poller, smart backup scheduler wired to `af-host`), and TLS 1.3 mTLS cluster daemon (`cluster_daemon.rs` serving both HTTP/2 gRPC `cluster.ClusterService` and `/cluster/v1/*` HTTPS JSON). |
| **`af-release`** | `backend-rs/crates/af-release` | **Shipped** | Default native Rust release engine (`Deploy`, `Rollback`, `Cleanup`, `MigrateSystemd`) with 4-tier SQLite DB resolution, `stable`/`nightly` channel isolation, `/releases/latest` redirect fallback, Sigstore/SLSA v1 provenance verification, external `web/dist` asset validation, `prepare_release_permissions` normalization, WAL-safe pre-swap snapshots, running-binary verification, and `.recovery_state.json` journaling. See [Rust Release Engine](./rust-release-engine.md). |
| **`af-host`** | `backend-rs/crates/af-host` | **Shipped** | Shared Rust host backup, verification, maintenance, and staged restore library. Provides `VACUUM INTO` (default) / `OnlineBackupApi` SQLite snapshots, `af-host.backup-manifest.v1` manifests, 5-digit chunk splitting/assembly, confirmed staged restore (`execute_staged_restore` with quiescence, rollback snapshots, and protected provenance journaling), and native host maintenance (`sentinel_scan_auth_log`, `apply_network_tuning`, `clean_system_logs`, `inspect_home_disk_space`). |
| **`af-cli`** | `backend-rs/crates/af-cli` | **Shipped** | Unified Rust `af` administrative CLI binary (`bin/af`). Supports `package`, `service`, `quota`/`setdisk`, `sandbox`, `release`, `backup` (including `restore --target-root <dir> --confirm-destructive-restore`), `maintenance` (`tune`, `sentinel`, `clean-logs`, `showspace`), `hosts`, `health`, and `provision` (14 Rust-native foundation steps with `# STATE_VERSION=2` persistence). |
| **`af-models`** | `backend-rs/crates/af-models` | **Shipped** | Shared `serde` domain models, hardware snapshot structs, and runner IPC wire contracts. |
| **`af-librespeed`** | `backend-rs/crates/af-librespeed` | **Shipped** | Native Rust `speedtest-backend` companion binary (`bin/speedtest-backend`) with SQLite WAL telemetry storage, legacy BoltDB v2 auto-migration, keyed ULID obfuscation, and PNG result badge rendering. |
| **WASM Frontend** | `frontend-rs` | **Shipped** | Four-crate Leptos dashboard and dedicated WASM workers (`af-web-core`, `af-web-worker`, `af-web-ui`, `af-web-app`), sixteen tabs, public login/OIDC/share routes, six locales, strict CSP, and light/dark themes. See [frontend-rs/README.md](../frontend-rs/README.md). |
| **Release Build Pipeline** | `.github/workflows/release.yml`, `scripts/build_gold.sh`, `setup/modules/modern_stack.sh` | **Shipped** | Builds Rust WASM assets with Trunk, enforces zero-Go hygiene, and packages external `web/dist` beside `aetherflow-api`, `bin/af`, and `bin/speedtest-backend` in multi-arch `aetherflow-linux-<arch>.tar.gz` (`amd64`/`arm64`) with `SHA256SUMS` and Sigstore provenance attestations. |
| **Rust Plugin Runtime & SDK** | `af-api::plugins`, `af-runner::plugins`, `plugins/sdk-template-rust/` | **Shipped** | Manifest discovery & validation (`plugin.manifest.json`), deterministic/dynamic port allocation (`21000..=21999`), isolated transient `DynamicUser=yes` units via `af-runner` (`AETHERFLOW_PLUGIN_TOKEN_FILE`), scoped JWT minting (`POST /api/v1/admin/plugins/:id/token`), route-scope RBAC middleware, and bounded reverse proxying (`/plugins/:id/ui`, `/plugins/:id/proxy`, `/plugins/:id/proxy/*rest`, `/api/v1/auth/plugins`, `/api/v1/auth/plugins/:id/{ui,proxy,proxy/*rest}`, `/api/v1/admin/plugins`, `/api/v1/admin/plugins/:id/control`). |

---

## 2. Hybrid Dispatch & Feature Gates

| Component | Default Mode | Opt-In / Override Flag | Coverage & Behavior |
| :--- | :--- | :--- | :--- |
| **Declarative Rust Package Executor (`af-runner`)** | Bash fallback (`LegacyBashFallback`) by default unless `AETHERFLOW_ENABLE_RUST_PACKAGES=1` is set | `AETHERFLOW_ENABLE_RUST_PACKAGES=1` (or force Bash via `AETHERFLOW_FORCE_BASH_PACKAGES=1`) | **9 built-in declarative Rust recipes** (`fail2ban`, `quassel`, `threadfin`, `znc`, `xrdp`, `x2go`, `netdata`, `mergerfs`, `rclone`) with `GenerateSelfSignedTlsCert`, `CaptureDpkgVersion`, pre-start systemd sandboxing for non-privileged units, and `RollbackJournal`. Remaining 68 catalog installers run under the same advisory lock and process-group supervisor. |
| **Release Self-Update (`af-runner` -> `af-release`)** | Transient unit (`aetherflow-self-update-<command>-<channel>-<8hex>.service`) running native `af-release` (`af release <command> --local`) by default | `AETHERFLOW_FORCE_BASH_RELEASE=1` (or `AETHERFLOW_RELEASE_ENGINE=bash`) to fall back to `deploy/release-manager.sh` | `af-api::storage::updater::run_update` dispatches `SelfUpdateRequest` over `/run/aetherflow/runner.sock`. Both `af-release` and `deploy/release-manager.sh` enforce SHA-256 + Sigstore/SLSA v1 provenance verification, `web/dist` asset checks, permission normalization, `stable`/`nightly` channels, and `/releases/latest` redirects. |
| **Host Backups & Staged Restore (`af-host`)** | Native Rust in `af-services` smart backup worker and `af-cli` | `af backup restore <filename> --target-root <dir> --confirm-destructive-restore` | `execute_online_sqlite_backup` calls `af_host::create_sqlite_snapshot_backup` with `SnapshotOptions::default()` (`SnapshotMethod::VacuumInto` + `.manifest.json` + `.sha256`). Unconfirmed live `af backup restore` fails closed (`DestructiveRestoreUnsupported`, exit code `6`); confirmed `execute_staged_restore` performs service quiescence, pre-restore rollback copying, protected provenance journaling, per-class file mode sanitization (`0600` cap on secrets, `0660`/`0640` on SQLite, `0755`/`0640` on regular configs), SHA-256 verification, and `PRAGMA quick_check` + `PRAGMA integrity_check`. |
| **Bare-Metal Provisioning (`af-cli::provision`)** | 14 Rust-native foundation steps (6 executed by default when no steps are named) + 20 retained shell bootstrap steps (34 in `CANONICAL_ALL_STEPS`) | `af provision run [<steps>...]` | `checkroot`, `logcheck`, `checkkernel`, `makedirs`, `boot`, `harden_perms`, `bashrc`, `hostname`, `locale`, `skel`, `apachesudo`, `build_modern`, `bbr`, and `perms` execute natively in Rust with `# STATE_VERSION=2` and symlink-free atomic writes. |

---

## 3. Intentional Boundaries & Shared Asset Paths

### 3.1 Sandboxed Plugin UI Boundary (No Dynamic Core WASM Bundling)

- **Intentional Boundary**: Plugins are **not** dynamically compiled or linked into the core `frontend-rs` WebAssembly bundle. Instead, the WASM dashboard renders enabled plugin UIs inside sandboxed iframes served with a strict CSP, isolating untrusted plugin UI code from core session cookies and WASM memory.
- Backend manifest loading, port allocation (`21000..=21999`), plugin-scoped JWT minting (`POST /api/v1/admin/plugins/:id/token`), per-route `api_scopes` enforcement, and 2 MiB-buffered HTTP reverse proxying live in `af-api::plugins`, while transient `DynamicUser=yes` process execution lives in `af-runner::plugins`. Companion plugins use the Rust SDK template in `plugins/sdk-template-rust/`.

### 3.2 Shared Asset Paths

- The canonical `config/` directory holds the package catalog (`packages.json`), automation metadata (`package_automation.json`), and OpenAPI 3.1 contract (`openapi-v1.yaml`). Release archives copy `config/` while excluding `openapi-v1.yaml` (`scripts/build_gold.sh`) because `af-api` embeds the OpenAPI spec at compile time.
- Shared Bash marketplace lifecycle helpers load through `packages/common.sh`, which sources the modular library files under `packages/lib/*.sh` (`logging_archives.sh`, `versions_apt.sh`, `state_downloads.sh`, `config_database.sh`, `apache_dns_locks.sh`, `redaction_receipts.sh`, `systemd_credentials.sh`).
- `frontend-rs/dist/` holds the generated WASM bundle. Releases stage `web/dist/` beside `aetherflow-api`. `STATIC_DIR` selects an explicit alternate bundle; frontend assets are never compiled into the API binary.
- `tests/test_zero_go_cutover.py` enforces the permanent removal of the legacy Go backend and legacy Go plugin template, alongside CI release workflow and installer contracts.

---

## 4. Verification Commands

Run the current workspace verification suites directly (see [Testing & Verification](./testing.md) for full details and environment variables):

| Check | Command |
| :--- | :--- |
| **Backend Rust workspace (11 crates)** | `cargo test --manifest-path backend-rs/Cargo.toml --workspace --locked -- --test-threads=1` |
| **Frontend Rust WASM workspace (4 crates)** | `cargo test --manifest-path frontend-rs/Cargo.toml --workspace --locked` |
| **Rust Plugin SDK (`plugins/sdk-template-rust/backend/Cargo.toml`)** | `cargo test --manifest-path plugins/sdk-template-rust/backend/Cargo.toml --locked` |
| **Python regression & Zero-Go suites** | `AETHERFLOW_SKIP_ENV_FILES=1 python3 tests/run_parallel_tests.py` |
| **Shell hygiene** | `python3 tests/check_shell_hygiene.py` |
