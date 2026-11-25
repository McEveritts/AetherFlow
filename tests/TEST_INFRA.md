# AetherFlow v4.0.0 — End-to-End Test Infrastructure Specification

**Document Version**: 4.0.0  
**Status**: ACTIVE (Pure-Rust Control Plane & Leptos WASM Frontend)  

---

## 1. E2E Testing Track Principles & Execution Modes

The `tests/e2e/` Python harness (`tests/run_e2e.py`) provides a 387-case requirement and source-contract check suite across AetherFlow's pure-Rust control plane (`backend-rs/`), Leptos WASM frontend (`frontend-rs/`), Playwright harness (`e2e/`), and Debian/Ubuntu packaging (`setup/`, `packages/`, `deploy/`).

### Core Principles

1. **Contract-Driven Checks**: Test cases map 37 core platform features (`F01`–`F37`) to explicit source, route, token, and API contracts across the repository.
2. **Execution Modes (`--mode`)**:
   - **Static Contract Inspection Mode (`--mode contract`, default)**: Evaluates repository files, route registrations, CSS design tokens, shell LF line endings, `bash -n` syntax, and SQL migrations without starting daemons (all 387 checks run offline).
   - **Live HTTP Mode (`--mode live`)**: Targets a running API via `--url` (default `http://localhost:8080`, optionally authenticated with `AETHERFLOW_E2E_USER` and `AETHERFLOW_E2E_PASS`), executing live HTTP probes alongside static contract checks. Privileged runner socket drills are executed separately via `scripts/v4_privileged_guest_drills.py`.
   - **Mock Mode (`--mode mock`)**: Accepted by the CLI for compatibility; no in-process mock HTTP server is implemented, so `--mode mock` currently executes the same static contract branch as `--mode contract`.
3. **Zero Placeholder Assertions (`T1_F37_04`)**: Every one of the **387** checks asserts concrete AST, source-symbol, syntax, or live HTTP predicates; `T1_F37_04` parses all `tests/e2e/**/*.py` ASTs and fails if any unconditional `self.assert_true(True, ...)` placeholder stub is introduced. Static contract checks still supplement—and do not substitute for—Rust workspace tests (`cargo test`), Playwright browser runs (`e2e/`), or KVM guest drills.
4. **Actionable Diagnostics**: Failing assertions report the feature ID, tier, expected contract, and observed mismatch.

---

## 2. 4-Tier Test Suite Architecture

The 4-tier contract harness covers 37 platform features (`F01`–`F37`):

```text
========================================================================================
                                4-TIER CONTRACT ARCHITECTURE
========================================================================================
 Tier 1: Feature Coverage (Category-Partition)
   └─ 5 test cases per feature (F01–F37) = 185 tests
   └─ Primary routes, components, CSS tokens, and packaging invariants.
----------------------------------------------------------------------------------------
 Tier 2: Boundary & Corner Cases (Adversarial Checks)
   └─ 5 test cases per feature (F01–F37) = 185 tests
   └─ Traversal rejection, auth/CSRF guards, port/size limits, privilege units, LF/apt-key.
----------------------------------------------------------------------------------------
 Tier 3: Cross-Feature Combinations (Pairwise Checks)
   └─ 12 multi-feature interoperability contract suites
   └─ Ingress + Gateway + Hosts, Auth Refresh + Profile, PathSelector + FS + MediaFlow.
----------------------------------------------------------------------------------------
 Tier 4: Scenario Checks (Static & Read-Only Live Probes)
   └─ 5 multi-step operator scenario checklists
   └─ Bootstrap, App Ingress, Quotas, Mesh VPN, AI Anomaly & Notifications.
========================================================================================
 Total Contract Harness: 387 Tests (supplemented by Rust, unittest, Playwright & VM suites)
========================================================================================
```

### Tier 1: Feature Coverage

- **Rule**: 5 test cases per feature (`F01`–`F37`).
- **Scope**: Route presence and expected status/schema contracts, Leptos WASM component mounting, Unified Flat Design System CSS token checks in `frontend-rs/styles/input.css`, and Debian 12/13 packaging conventions.

### Tier 2: Boundary & Corner Cases

- **Rule**: 5 test cases per feature (`F01`–`F37`).
- **Scope**:
  - **Encoding & Path Traversal**: `../../etc/passwd`, NUL-byte, and URL-encoded path rejection.
  - **Authentication & CSRF**: Missing/expired/tampered tokens, CSRF validation on state-mutating cookie requests, and admin RBAC enforcement.
  - **Resource Limits & Overflows**: Avatar upload bounds (`> 2 MiB`), Axum default `2 MiB` request body limit on `runner.sock`, and TCP/UDP port range checks (`1..=65535`).
  - **Privilege Separation**: Unprivileged `aetherflow-api.service` under `ProtectSystem=strict` and `NoNewPrivileges=yes`, zero blanket `NOPASSWD: ALL` sudoers.
  - **Syntax & Portability**: LF line endings and absence of deprecated `apt-key` invocations (and `software-properties-common` gated to Ubuntu rather than Debian in Tier 1 `F30`).

### Tier 3: Cross-Feature Combinations (`tests/e2e/tier3_pairwise/test_pairwise_combos.py`)

1. `T3_COMBO_01` (`TestComboIngressDnsProxyTopology`, `feature_id="F05+F07+F06+F09"`): Ingress CRUD (`F05`) + Hosts Runner (`F07`) + Reverse Proxy Topology (`F06`) + Migration 17 (`F09`).
2. `T3_COMBO_02` (`TestComboAuthSessionPasswordLifecycle`): Auth Refresh (`F02`) + Profile Password (`F03`) + Profile Security UI (`F22`).
3. `T3_COMBO_03` (`TestComboPathSelectorFsMediaflow`): DirectoryPicker (`F01`, `F20`) + FS Handler (`F01`) + MediaFlow `ApiClient` auth (`F20`).
4. `T3_COMBO_04` (`TestComboQuotasRunner`): Quotas Panel (`F26`) + Runner Quota Socket (`F07`, `F08`).
5. `T3_COMBO_05` (`TestComboNetworkVpnRunner`): Network Panel (`F24`) + Runner Network Socket (`F07`, `F08`).
6. `T3_COMBO_06` (`TestComboPeerClusterManagement`, `feature_id="F10+F27"`): Peer runtime (`F10`), Cluster tab (`F27`), and peer admin routes.
7. `T3_COMBO_07` (`TestComboExternalWasmSpaAtmosphere`): External WASM Build (`F32`) + `web/dist` Serving (`F32`) + Flat Design System CSS (`F13`, `F14`) + Legacy Purge (`F11`).
8. `T3_COMBO_08` (`TestComboPrivilegeBoundarySandbox`): Systemd Privilege Units (`F33`) + Sudoers Purge (`F34`) + Runner Sandboxing (`F07`, `F08`).
9. `T3_COMBO_09` (`TestComboDebian13AptPackaging`): APT Template (`F28`) + Core OS Detection (`F29`) + Package Modernization (`F30`) + Keyrings (`F31`).
10. `T3_COMBO_10` (`TestComboAiTelemetryPredictions`): Predictions History (`F19`) + Bandwidth Card + Overview Mounting (`F19`).
11. `T3_COMBO_11` (`TestComboDeploySseGateway`, `feature_id="F21+Deploy"`): Deployment SSE Stream (`/api/v1/auth/deploy/stream` + `EventSource` in `tabs/mediaflow.rs` and `af-api/src/storage.rs`, `F21`).
12. `T3_COMBO_12` (`TestComboResponsiveDockScrollerContainment`): Tri-Mode Dock (`F15`) + Scroller Containment (`F16`) + Primitives (`F18`).

### Tier 4: Scenario Verification (`tests/e2e/tier4_realworld/test_realworld_scenarios.py`)

In `--mode contract`, Tier 4 verifies static file/route/symbol presence; in `--mode live`, `T4_SCENARIO_01` authenticates via `POST /api/v1/public/auth/login` and Tier 4 scenarios issue read-only HTTP `GET` checks against the running API without mutating host packages, quotas, or VPN interfaces:

1. `T4_SCENARIO_01` (`TestScenarioOperatorBootstrap`): Contract mode checks `af-api/src/main.rs` and `af-runner/src/lib.rs` existence, `/profile/password` and `/system/topology` routes in `routes.rs`, and `--af-bg-canvas` / `--obs-bg-base` in `input.css`; live mode probes `GET /health/ready`, `POST /api/v1/public/auth/login`, and `GET /api/v1/auth/system/topology`.
2. `T4_SCENARIO_02` (`TestScenarioAppIngressProvisioning`): Contract mode checks `/ingress`, `app_subdomain_proxy_middleware`, `/deploy/stream`, and `tailscale_ingress.rs`; live mode probes `GET /api/v1/admin/ingress/configs`.
3. `T4_SCENARIO_03` (`TestScenarioMultitenantQuotaEnforcement`): Contract mode checks `/quotas`, runner `/v1/quota`, and `tabs/quotas.rs`; live mode probes `GET /api/v1/admin/quotas`.
4. `T4_SCENARIO_04` (`TestScenarioMeshVpnOrchestration`): Contract mode checks `/network`, runner `/v1/network`, and `tabs/network/mod.rs`; live mode probes `GET /api/v1/admin/network/status`.
5. `T4_SCENARIO_05` (`TestScenarioAiAnomalyHealing`): Contract mode checks `/predictions` and `/notifications` in `routes.rs` and `start_heal_worker` in `af-services/src/workers.rs`; live mode probes `GET /api/v1/admin/ai/predictions/history` and `GET /api/v1/admin/notifications/rules`.

---

## 3. Test Runner Architecture & Directory Layout

### Directory Structure

```text
tests/
├── e2e/
│   ├── __init__.py
│   ├── runner.py                                # Discovery, CLI options, and execution engine
│   ├── framework.py                             # Assertions, static contract inspector, live HTTP client
│   ├── tier1_features/                          # Tier 1: 37 feature suites (185 tests)
│   │   ├── __init__.py
│   │   ├── test_f01_to_f06_backend_api.py
│   │   ├── test_f07_to_f12_backend_core.py
│   │   ├── test_f13_to_f18_obsidian_design.py
│   │   ├── test_f19_to_f23_component_mounting.py
│   │   ├── test_f24_to_f27_operator_panels.py
│   │   ├── test_f28_to_f31_debian_packaging.py
│   │   └── test_f32_to_f37_system_pipeline.py
│   ├── tier2_boundaries/                        # Tier 2: 37 boundary suites (185 tests)
│   │   ├── __init__.py
│   │   ├── test_boundaries_api.py
│   │   ├── test_boundaries_backend_core.py
│   │   ├── test_boundaries_components.py
│   │   ├── test_boundaries_debian.py
│   │   ├── test_boundaries_obsidian.py
│   │   ├── test_boundaries_operator_panels.py
│   │   └── test_boundaries_pipeline.py
│   ├── tier3_pairwise/                          # Tier 3: 12 cross-feature suites
│   │   ├── __init__.py
│   │   └── test_pairwise_combos.py
│   └── tier4_realworld/                         # Tier 4: 5 scenario suites
│       ├── __init__.py
│       └── test_realworld_scenarios.py
├── fixtures/                                    # Shared regression test fixtures
├── check_shell_hygiene.py                       # Shell hygiene and syntax gate
├── run_e2e.py                                   # Root entrypoint (`python3 tests/run_e2e.py`)
├── run_e2e.sh                                   # Linux / WSL bash wrapper
├── run_parallel_tests.py                        # Parallel unittest runner for `tests/test_*.py`
├── TEST_INFRA.md                                # This specification
├── TEST_READY.md                                # Static contract baseline summary
└── test_*.py                                    # Python unittest regression suites
```

### CLI Flags & Invocation

`tests/e2e/runner.py` supports `--tier`, `--feature`, `--mode {contract,live,mock}`, `--url`, `--verbose` (`-v`), `--fail-fast`, `--json-out`, and `--report-out` (plus `AETHERFLOW_E2E_USER` / `AETHERFLOW_E2E_PASS` in live mode):

```bash
# Run all 4 tiers in static contract verification mode
python3 tests/run_e2e.py --mode contract

# Run with bash wrapper
./tests/run_e2e.sh

# Filter by tier or feature ID with verbose/fail-fast output
python3 tests/run_e2e.py --tier 1 --verbose --fail-fast
python3 tests/run_e2e.py --feature F05 --json-out /tmp/f05.json --report-out /tmp/f05.md

# Run in live mode against a running AetherFlow daemon
AETHERFLOW_E2E_USER=admin AETHERFLOW_E2E_PASS=<password> \
  python3 tests/run_e2e.py --mode live --url http://127.0.0.1:8080

# Run all Python unittest regression suites in parallel
AETHERFLOW_SKIP_ENV_FILES=1 python3 tests/run_parallel_tests.py

# Run Playwright live WASM E2E (default E2E_PLAYWRIGHT_SPECS=[.]live[.]spec[.]ts$ runs embedded.live.spec.ts only;
# pass a non-empty override such as E2E_PLAYWRIGHT_SPECS="tests/e2e" or explicit spec paths relative to e2e/ to run all specs)
bash scripts/run_embedded_e2e.sh \
  --binary backend-rs/target/release/aetherflow-api \
  --static-dir web/dist --playwright
```

### Exit Codes

- `0`: All executed tests passed.
- `1`: One or more tests failed, or a runtime/live-mode initialization error occurred (`RuntimeError`).
- `2`: Invalid CLI arguments (`argparse`).

---

## 4. Feature Expected Output Derivation Matrix

| Feature | Primary Contract / Interface | Authoritative Expected Output |
| :--- | :--- | :--- |
| **F01** | `GET /api/v1/auth/fs?path=...` (`af-api` `routes/fs_browser.rs`) | Admin-only `200 OK` with `{"current_path", "parent_path", "entries": [...]}`. Non-admins, traversal (`../../etc`), or paths outside allowed roots -> `400`/`403`. |
| **F02** | `POST /api/v1/public/auth/refresh` (and `/api/v1/auth/refresh`) | `200 OK` with refreshed session cookie/token metadata (accepts expired tokens within 2-hour grace window); exempt from double-submit CSRF in `csrf_middleware`, while cookie requests require `X-Requested-With: XMLHttpRequest` (`403` if omitted). Expired beyond 2-hour grace, revoked, or invalid -> `401`. |
| **F03** | `PUT /api/v1/auth/profile/password` | Verifies `current_password`, enforces min 8 chars for `new_password`. Success -> `200 OK`; wrong current password -> `403 Forbidden` (`INVALID_CURRENT_PASSWORD`); short password -> `400`. |
| **F04** | `PUT/DELETE /api/v1/auth/profile/avatar` | `PUT` accepts valid image URL or base64 data URI (max 2 MiB) -> `200 OK`; `DELETE` clears avatar -> `200 OK`; invalid/oversized -> `400`/`413`. |
| **F05** | `GET /api/v1/admin/ingress/configs` & `PUT .../apps/:appName` | `GET` returns `{"configs": [...]}`. `PUT` upserts SQLite `app_ingress_configs` and triggers Apache2 Certbot SAN sync and Subdomain Gateway routing (`1..=65535`). |
| **F06** | `GET /api/v1/auth/system/topology` | `200 OK` with live `nodes` and `links` representing real daemons (API, Runner, SQLite WAL, Apache2, and active managed services—no Redis or hardcoded dummy nodes). |
| **F07** | `/run/aetherflow/runner.sock` (`/v1/sandbox`, `/v1/hosts`, `/v1/network`, `/v1/quota`, etc.) | HTTP/1.1 over Unix domain socket (`0660 root:aetherflow`), Axum default 2 MiB max body, `SO_PEERCRED` + `/proc/<pid>/exe` caller check, strict allowlist execution. |
| **F08** | Caller Refactoring (`af-services`, `af-runner`) | No direct `sudo` or mutating `systemctl` calls in `af-api`; privileged mutations route through `af-runner` socket (`/v1/*`). |
| **F09** | SQLite Migration 17 (`app_ingress_configs`) | Idempotent table schema `app_ingress_configs(app_name TEXT PRIMARY KEY, public_domain TEXT DEFAULT '', external_access_enabled BOOLEAN DEFAULT 0, listen_port INTEGER DEFAULT 0, tls_enabled BOOLEAN DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`. |
| **F10** | Peer Runtime | The API manages peer runtime startup and shutdown (`peers::start().await` / `peers::shutdown().await`). The listener waits for a configured identity, the versioned admin router serves the peer list and pairing controls, and legacy `/cluster/` routes and `cluster_daemon.rs` are retired. |
| **F11** | Retire Legacy Next.js Frontend | Legacy `frontend/` directory and `frontend/src/app/api/fs/route.ts` removed; UI lives in `frontend-rs/` and Playwright harness lives in `e2e/`. |
| **F12** | Backend Unit Tests | `cargo test --workspace --locked` in `backend-rs/` passes across all 12 crates (including fs, auth, profile, ingress, runner socket, and peer lifecycle tests). |
| **F13** | Flat Canvas Foundation | `frontend-rs/styles/input.css` defines polarity-scoped dark (`#07090e`) and light (`#f4f6fa`) `--af-bg-canvas` tokens (retaining `--obs-bg-base` alias), solid `html`/`body` canvas fill, and zero `backdrop-filter`, `body::before` aurora, or `body::after` tactile grain layers. |
| **F14** | Semantic Flat Surface & Control Tokens | Polarity-scoped `--af-*` surface, hairline, control, and tone tokens across `:root` and `html[data-theme="light"]`, Tailwind v4 `@theme inline` + `@layer components`, static `.af-card` / opt-in `.af-card-interactive`, flat `.af-btn-primary`, and 120Hz cadence timing (`--obs-ease-spring-120`). |
| **F15** | Responsive Navigation Shell | Single `.af-sidebar` rail across `>=768px` (`84px` collapsed by default, toggleable to `238px` via `.af-sidebar-expanded`), plus `.af-mobile-dock` bottom dock and `.af-hamburger` slide-over `<Drawer>` at `<768px` in `frontend-rs/crates/af-web-app/src/shell.rs` with safe-area padding and `>=44px` touch targets. |
| **F16** | Scroller Containment Invariant | No blanket `html, body { overflow-x: hidden }`; horizontal overflow scoped via `min-w-0`, `max-w-full`, and `overflow-x-auto`. |
| **F17** | Display & Input Controls | `frontend-rs/crates/af-web-app/src/tabs/settings/mod.rs` exposes high-refresh cadence (`settings-high-refresh-mode`), touch mode (`settings-touch-mode`), reduced motion, haptic feedback, and `immersive_overview` (`dashboardDensity`: `compact`/`immersive`) with `localStorage` persistence and passive legacy key tolerance (retiring aurora, tactile grain, and card hover lift). |
| **F18** | Flat UI Primitives | `frontend-rs/crates/af-web-ui/src/{primitives.rs,grid.rs}` and `frontend-rs/crates/af-web-app/src/routes/{login.rs,consent.rs}` implement `.af-card`, `.af-btn` / `.af-btn-primary`, `.af-input`, and opaque `.af-modal` without legacy `.glass-*` classes. |
| **F19** | Mount Bandwidth & Predictions | Mounted in `tabs/overview/mod.rs`; `CapacityPredictions` reads real history from `/api/v1/admin/ai/predictions/history` (zero synthetic `Math.sin()` waves). |
| **F20** | Mount Metadata & DirectoryPicker | `DirectoryPicker` is defined in `tabs/fileshare/local_storage.rs` and mounted in `tabs/settings/metadata.rs` (and `tabs/fileshare/local_storage.rs`), querying `/api/v1/auth/fs` with cookie auth (`tabs/mediaflow.rs` uses a plain text input for its scan directory). |
| **F21** | Mount ExternalAccess & Deploy | `ExternalAccessSettings` is defined in `tabs/network/tailscale_ingress.rs` and mounted in `tabs/network/mod.rs` (with **External access** shortcut buttons in `tabs/services/` and `tabs/marketplace/`); `/api/v1/auth/deploy/stream` (`EventSource`) is consumed in `tabs/mediaflow.rs`, while `DeploymentStatus` in `tabs/marketplace/catalog.rs` polls `/api/v1/auth/packages/{id}/progress`. |
| **F22** | Wire Profile Controls | `tabs/settings/security.rs` wires `PUT /api/v1/auth/profile/password` and `PUT/DELETE /api/v1/auth/profile/avatar`. |
| **F23** | Real App Topology Map | `af-web-ui/src/topology.rs` & `af-web-core/src/topology.rs` render live nodes from `/api/v1/auth/system/topology`. |
| **F24** | Network & VPN Panel | `tabs/network/` manages WireGuard peers/keygen, Tailscale status/peers/routes, external access ingress, and network hardware inventory. |
| **F25** | Notifications & Alerting Panel | `tabs/notifications.rs` manages notification rules, channels, and test alert triggers. |
| **F26** | Storage Quotas Panel | `tabs/quotas.rs` manages user storage quotas, usage thresholds, and manual disk usage refresh. |
| **F27** | Cluster Peer Links | `tabs/cluster/` displays peer links and supports pairing windows, comparison-code confirmation, endpoint changes, and link revocation. |
| **F28** | Modernize Debian APT Template | `setup/templates/apt.sources/debian.template` uses `https://deb.debian.org/debian` with `non-free-firmware`. |
| **F29** | Debian 13 Core OS Detection | `setup/modules/00-core.sh` supports Trixie without `VERSION_ID` and detects PHP 8.4 natively. |
| **F30** | Modernize Package Dependencies | `setup/modules/02-packages.sh` gates `software-properties-common` to Ubuntu (removing it from Debian), updates `pcregrep` -> `pcre2-utils` and `libncurses-dev`, and drops dead packages. |
| **F31** | Keyring Migration Across `packages/` | Zero `apt-key` occurrences; package scripts use `/usr/share/keyrings/*.gpg` with `[signed-by=...]`. |
| **F32** | Rust API & External WASM Build Pipeline | `scripts/build_wasm_frontend.sh --stage` + `modern_stack.sh` stage `web/dist/` alongside `aetherflow-api`, `bin/af`, `bin/speedtest-backend`, and `bin/af-transcode` (`af-api/src/embed.rs` resolves `STATIC_DIR` or executable-adjacent `web/dist`). |
| **F33** | Systemd Privilege Units | `deploy/systemd/` contains `aetherflow-api.service` (`ProtectSystem=strict`, `ProtectHome=read-only`, `NoNewPrivileges=yes`, `User=aetherflow`) and `aetherflow-runner.service` (`User=root`). |
| **F34** | Sudoers & PM2 Purge | No `/etc/sudoers.d/aetherflow` with `NOPASSWD: ALL`; no root PM2 commands. |
| **F35** | Shell Script Line Endings & Syntax | Shell scripts in `setup/`, `deploy/`, and `packages/` use LF line endings and pass `bash -n`. |
| **F36** | Automated Contract Test Suite | 4-tier automated contract suite covering `F01`–`F37`. |
| **F37** | Full Verification & Hardening | Combined verification across `tests/run_e2e.py`, `tests/run_parallel_tests.py`, Rust workspace tests (`backend-rs`, `frontend-rs`, `plugins/sdk-template-rust/backend`), Playwright (`e2e/`), and VM guest drills. |
