# AetherFlow v4.0.0 — End-to-End Test Infrastructure Specification

**Document Version**: 4.0.0  
**Status**: ACTIVE (Pure-Rust Control Plane & Leptos WASM Frontend)  

---

## 1. E2E Testing Track Principles & Philosophy

The AetherFlow v4.0.0 test infrastructure provides deterministic, requirement-driven verification across the entire pure-Rust software stack (Leptos Rust WASM frontend in `frontend-rs/`, Axum Rust REST/SSE/WS backend in `backend-rs/`, root privileged runner socket `af-runner`, SQLite WAL database, Playwright browser harness in `e2e/`, and Debian 12/13 systemd packaging).

### Core Principles
1. **Opaque-Box & Requirement-Driven**:
   - Every test case is derived strictly from architecture contracts and interface specifications across `backend-rs/`, `frontend-rs/`, `e2e/`, `setup/`, `packages/`, and `deploy/`.
   - Tests evaluate system behavior at public interfaces (HTTP REST endpoints, Server-Sent Events, UNIX domain sockets, filesystem outputs, static WASM asset contracts, and CSS token systems) rather than internal private variables.
2. **Authoritative Expected Output Derivation**:
   - For every test case, expected outputs are grounded in explicit contracts (status codes, JSON schemas, cryptographic properties, sandboxing boundaries, and systemd security policies).
   - Dynamic values (timestamps, PIDs, random tokens) use deterministic structural matching and regex pattern validation.
3. **Progressive Testability & Dual-Mode Execution**:
   - **Contract & Static Code Inspection Mode (`--mode contract`)**: Evaluates code artifacts, route tables, AST/regex declarations, CSS token hierarchies, shell script line endings (`LF`), and migration files. Enables 100% of the 387-test E2E contract suite to execute without requiring running daemons.
   - **Live System Mode (`--mode live`)**: Executes real HTTP requests against `http://localhost:8080` (or `AETHERFLOW_API_URL`), tests live Server-Sent Events (`/api/v1/auth/deploy/stream`), and exercises the privileged runner UNIX domain socket (`/run/aetherflow/runner.sock`).
   - **Simulated Harness Mode (`--mode mock`)**: Spins up an in-process mock server adhering to all interface contracts to verify test harness logic and validate consumer integrations.
4. **Strict Isolation & Zero State Leakage**:
   - Tests are independent and idempotent. Each test initializes its own fixtures, avoids ordering dependencies, and cleans up temporary resources upon completion.
5. **Actionable Diagnostics & Zero-Facade Integrity**:
   - Tests assert real logic and error conditions. Facade tests that unconditionally pass are strictly forbidden.
   - Failures report the exact feature ID, tier, input parameters, expected contract, and observed mismatch.

---

## 2. 4-Tier Test Suite Architecture

The 4-tier E2E suite covers all 37 core platform features (F01–F37):

```
========================================================================================
                                4-TIER TEST ARCHITECTURE
========================================================================================
 Tier 1: Feature Coverage (Category-Partition)
   └─ 5 test cases per feature (F01–F37) = 185 tests
   └─ Happy-path, primary behaviors, valid inputs, expected state transitions.
----------------------------------------------------------------------------------------
 Tier 2: Boundary & Corner Cases (Adversarial Verification)
   └─ 5 test cases per feature (F01–F37) = 185 tests
   └─ Empty inputs, path traversal, injection payloads, limits, permission boundaries.
----------------------------------------------------------------------------------------
 Tier 3: Cross-Feature Combinations (Pairwise Interoperability)
   └─ 12 multi-feature integration suites
   └─ Ingress + Apache2 Gateway + Hosts, Auth Refresh + Password, PathSelector + FS + MediaFlow.
----------------------------------------------------------------------------------------
 Tier 4: Real-World Application Scenarios (Operator E2E Workflows)
   └─ 5 complete end-to-end lifecycles
   └─ Operator Bootstrap, App Provisioning, Multi-Tenant Quotas, Mesh VPN, Anomaly Healing.
========================================================================================
 Total E2E Contract Suite: 387 Systematic Tests (plus 1,000+ unittest regression tests)
========================================================================================
```

### Tier 1: Feature Coverage (Equivalence Classes & Happy Paths)
- **Objective**: Verify that every feature performs its intended specification under standard, valid conditions.
- **Rule**: 5 distinct test cases per feature (F01 through F37).
- **Scope**:
  - Valid REST requests return HTTP 200/201/204 with valid JSON schema.
  - Leptos WASM components and routes compile and mount cleanly without hardcoded stubs.
  - Design system tokens and atmospheric styles in `frontend-rs/styles/input.css` conform to Obsidian V2 definitions.
  - Packaging scripts, APT sources, and systemd templates conform to Debian 12/13 specifications.

### Tier 2: Boundary & Corner Cases (Adversarial Hardening)
- **Objective**: Verify system robustness against hostile, malformed, or extreme inputs.
- **Rule**: 5 distinct boundary test cases per feature (F01 through F37).
- **Scope**:
  - **Encoding & Path Traversal**: Directory traversal attacks (`../../etc/passwd`), null-byte injections, URL-encoded path bypasses.
  - **Authentication & CSRF**: Missing tokens, expired tokens, forged `X-CSRF-Token`, tampered JWT signatures, unauthenticated calls to admin routes.
  - **Resource Limits & Overflows**: Oversized payloads (>2MB avatars, >4096-byte runner socket bodies), integer overflows in ports (<1 or >65535).
  - **Privilege Separation**: Non-root execution under `ProtectSystem=strict` and `NoNewPrivileges=yes`, rejection of unauthorized `sudo` calls.
  - **Syntax & Portability**: Detection of Windows CRLF line endings in shell scripts, deprecation checks for `apt-key` and `software-properties-common`.

### Tier 3: Cross-Feature Combinations (Pairwise Interaction)
- **Objective**: Verify multi-subsystem interoperability and data handoffs.
- **Suites**:
  1. `test_combo_ingress_dns_proxy`: Ingress CRUD (F05) + Privileged Hosts Runner (F07) + Reverse Proxy Topology (F06, F23) + Migration 17 (F09).
  2. `test_combo_auth_session_lifecycle`: Auth Refresh (F02) + Profile Password (F03) + Session Invalidation + Wire Profile UI (F22).
  3. `test_combo_pathselector_fs_mediaflow`: DirectoryPicker (F01, F20) + FS Handler (F01) + MediaFlow Transcoding + Token Fixes (F20).
  4. `test_combo_quota_runner`: Quotas Panel (F26) + Runner Quota Socket (F07, F08) + Storage Quota Enforcement (F26).
  5. `test_combo_network_wireguard_tailscale`: Network Panel (F24) + Runner Network Socket (F07, F08) + Key Generation.
  6. `TestComboPeerClusterManagement` checks the peer runtime (F10), Cluster tab (F27), and peer admin routes.
  7. `test_combo_wasm_binary_spa_tokens`: External WASM Build (F32) + External `web/dist` Serving (F32) + Obsidian CSS (F13, F14) + Legacy Purge (F11).
  8. `test_combo_privilege_boundary_sandbox`: Systemd Privilege Units (F33) + Sudoers Purge (F34) + Caller Migration (F08) + Runner Sandboxing (F07).
  9. `test_combo_debian13_apt_packaging`: APT Template (F28) + Core OS Detection (F29) + Package Modernization (F30) + Keyring Migration (F31).
  10. `test_combo_ai_telemetry_predictions`: Predictions History (F19) + AI Bandwidth Tuning (F19) + Overview Dashboard Mounting (F19).
  11. `test_combo_deploy_sse_gateway`: External Access (F21) + Deployment SSE Stream (F21) + Apache2 Subdomain Gateway Routing (F05).
  12. `test_combo_responsive_ui_containment`: Tri-Mode Dock (F15) + Scroller Containment (F16) + Touch Targets (F15) + Primitives (F18).

### Tier 4: Real-World Application Scenarios (Operator Lifecycles)
- **Objective**: Exercise complex, multi-step real-world administrator workflows from start to finish.
- **Scenarios**:
  1. `test_scenario_operator_bootstrap`: Clean system install on Debian 13 -> Rust API + external WASM bundle startup -> privileged runner socket binding -> unprivileged user drops capabilities -> admin login -> password update -> profile avatar -> topology verification.
  2. `test_scenario_app_ingress_provisioning`: Radarr application deployment -> dynamic Apache2 Subdomain Gateway upstream proxying -> external domain assignment -> `/etc/hosts` sync via privileged runner -> deployment SSE status streaming -> topology visualization.
  3. `test_scenario_multitenant_quota_enforcement`: User provisioning -> storage quota assignment via runner `setdisk` -> usage refresh -> quota recalculation -> boundary limit enforcement.
  4. `test_scenario_mesh_vpn_orchestration`: Operator navigates to Network & VPN panel -> generates WireGuard keypair -> enrolls peer -> advertises Tailscale subnet route via privileged runner -> live interface verification.
  5. `test_scenario_ai_anomaly_healing`: Hardware metrics collection -> AI predictions report computation (real metrics history, no sine waves) -> anomaly alert rule trigger -> notification dispatch -> automated self-healing action dispatched through runner socket.

---

## 3. Test Runner Architecture & Directory Layout

### Directory Structure
```
tests/
├── e2e/
│   ├── __init__.py
│   ├── runner.py                                # Core discovery and execution engine
│   ├── framework.py                             # Test harness, assertions, contract inspector, live client
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
│   ├── tier3_pairwise/                          # Tier 3: 12 cross-feature integration suites
│   │   ├── __init__.py
│   │   └── test_pairwise_combos.py
│   └── tier4_realworld/                         # Tier 4: 5 realistic application scenarios
│       ├── __init__.py
│       └── test_realworld_scenarios.py
├── fixtures/                                    # Shared regression test fixtures
├── check_shell_hygiene.py                       # Shell hygiene and syntax gate
├── run_e2e.py                                   # Root entrypoint (`python3 tests/run_e2e.py`)
├── run_e2e.sh                                   # Linux / WSL bash wrapper
├── run_parallel_tests.py                        # Parallel unittest runner for `tests/test_*.py`
├── TEST_INFRA.md                                # This specification
├── TEST_READY.md                                # Baseline & verification report
└── test_*.py                                    # Python unittest suites (CI, WASM, marketplace, security, release)
```

### Test Invocation & CLI Interface

The Python test suites run with standard Python 3 (and zero third-party Python dependencies beyond PyYAML where noted):

```bash
# Run all 4 tiers in contract/static verification mode
python3 tests/run_e2e.py

# Run with bash wrapper
./tests/run_e2e.sh

# Filter by tier or feature ID
python3 tests/run_e2e.py --tier 1
python3 tests/run_e2e.py --feature F05

# Run in live mode against a running AetherFlow daemon
python3 tests/run_e2e.py --mode live --url http://localhost:8080

# Run all unittest regression suites in parallel
AETHERFLOW_SKIP_ENV_FILES=1 python3 tests/run_parallel_tests.py

# Run Playwright browser contracts and live WASM E2E (via e2e/ + scripts/run_embedded_e2e.sh)
bash scripts/run_embedded_e2e.sh --binary backend-rs/target/release/aetherflow-api --static-dir web/dist --playwright
```

### Exit Codes & Pass/Fail Semantics
- `0`: All executed tests passed successfully.
- `1`: One or more tests failed (or missing requirements detected in contract mode).
- `2`: Invalid CLI arguments or configuration error.

---

## 4. Feature Expected Output Derivation Matrix

| Feature | Primary Contract / Interface | Authoritative Expected Output |
| :--- | :--- | :--- |
| **F01** | `GET /api/v1/auth/fs?path=...` (`af-api` `routes.rs`) | 200 OK with `{"current_path": str, "parent_path": str, "entries": [{"name": str, "is_dir": bool, ...}]}`. Traversal (`../../etc`) -> 400/403. Outside allowed roots -> 403. |
| **F02** | `POST /api/v1/public/auth/refresh` | 200 OK with refreshed session cookie / token metadata. Exempt from CSRF or accepts `X-Requested-With: XMLHttpRequest`. Expired/invalid -> 401. |
| **F03** | `PUT /api/v1/auth/profile/password` | Password verification of `current_password`, min 8 chars for `new_password`. Success -> 200 OK. Wrong current password -> 400/401. Short password -> 400. |
| **F04** | `PUT/DELETE /api/v1/auth/profile/avatar` | PUT: Accepts image URL or base64 data URI (max 2MB) -> 200 OK. DELETE: Clears avatar -> 200 OK. Invalid scheme / oversized -> 400/413. |
| **F05** | `GET /api/v1/admin/ingress/configs` & `PUT .../apps/:appName` | GET returns `{"configs": [...]}`. PUT upserts into SQLite `app_ingress_configs` and triggers Apache2 Certbot SAN sync and Subdomain Gateway routing. Port 1-65535, valid domain format. |
| **F06** | `GET /api/v1/auth/system/topology` | 200 OK with live `nodes` and `links`. Nodes represent real daemons (API, Runner, SQLite WAL, Redis, Apache2). Zero hardcoded dummy nodes. |
| **F07** | `/run/aetherflow/runner.sock` (`/v1/sandbox`, `/v1/hosts`, `/v1/network`, `/v1/quota`) | HTTP/1.1 over UNIX domain socket, mode 0660 root:aetherflow. Max body 4096 bytes. Safe ID validation. Strict allowlist execution. |
| **F08** | Caller Refactoring (`af-services`, `af-runner`) | Zero direct `sudo` or mutating `systemctl` calls in core services. All route via `af-runner` socket (`dispatch_runner_systemctl_unix`, `/v1/*`). |
| **F09** | SQLite Migration 17 (`app_ingress_configs`) | Schema: `app_ingress_configs(app_name TEXT PRIMARY KEY, public_domain TEXT, external_access_enabled INTEGER, listen_port INTEGER, tls_enabled INTEGER, updated_at DATETIME)`. Idempotent. |
| **F10** | Peer Runtime | The API manages peer runtime startup and shutdown. The listener waits for a configured identity, and the versioned admin router serves the peer list and pairing controls. |
| **F11** | Retire Legacy Next.js Frontend | Legacy `frontend/` directory and `frontend/src/app/api/fs/route.ts` completely deleted; Playwright tests live in `e2e/` and UI lives in `frontend-rs/`. |
| **F12** | Backend Unit Tests | `cargo test --workspace --locked` in `backend-rs/` passes 100% of crates, including fs, auth, profile, ingress, and runner socket tests. |
| **F13** | Obsidian V2 CSS Foundation | `frontend-rs/styles/input.css` defines `--obs-bg-base: #000000`, `body::before` 3-orb radial aurora + base gradient, `body::after` fractal micro-grain + edge vignette. |
| **F14** | Obsidian V2 Glass Tokens | Directional specular highlight (`--obs-specular-top`), chromatic borders (`--obs-chromatic-border-*`), prism rims, 120Hz spring physics (`--obs-ease-spring-120`). |
| **F15** | Tri-Mode Navigation | Desktop expandable rail (>=1024px), tablet icon rail (768-1023px), mobile bottom dock (<768px) in `frontend-rs/crates/af-web-app/src/shell.rs` with safe-area padding and >=44px touch targets. |
| **F16** | Scroller Containment Invariant | Zero blanket `html, body { overflow-x: hidden }`. Horizontal overflow scoped via `min-w-0`, `max-w-full`, and `overflow-x-auto`. |
| **F17** | Atmosphere Controls | `frontend-rs/crates/af-web-app/src/tabs/settings/` exposes aurora intensity, static vs animated switch, micro-grain toggle, and card lift density controls. |
| **F18** | UI Primitives Redesign | `frontend-rs/crates/af-web-ui/src/primitives.rs`, `grid.rs`, and `routes/login.rs` implement Obsidian V2 tokens. |
| **F19** | Mount Bandwidth & Predictions | Mounted in `tabs/overview/mod.rs`. `CapacityPredictions` fetches real history from `/api/v1/admin/ai/predictions/history` (zero synthetic `Math.sin()` waves). |
| **F20** | Mount Metadata & DirectoryPicker | Mounted in `tabs/mediaflow.rs` and `tabs/settings/metadata.rs`. `DirectoryPicker` wired to `/api/v1/auth/fs` with cookie auth (no `localStorage` tokens). |
| **F21** | Mount ExternalAccess & Deploy | Mounted in `tabs/services/` / `tabs/marketplace/` / `tabs/network/tailscale_ingress.rs`. Deployment status listens to `/api/v1/auth/deploy/stream`. |
| **F22** | Wire Profile Controls | `tabs/settings/security.rs` wires password change (`PUT /api/v1/auth/profile/password`) and avatar change/delete (`PUT/DELETE /api/v1/auth/profile/avatar`). |
| **F23** | Real App Topology Map | `af-web-ui/src/topology.rs` & `af-web-core/src/topology.rs` render live nodes from `/api/v1/auth/system/topology` with zero hardcoded dummy nodes. |
| **F24** | Network & VPN Panel | `tabs/network/` manages WireGuard peers/keygen and Tailscale status/peers/routes. |
| **F25** | Notifications & Alerting Panel | `tabs/notifications.rs` manages notification rules and channels (with test alert trigger). |
| **F26** | Storage Quotas Panel | `tabs/quotas.rs` manages user storage quotas, usage thresholds, and manual disk usage refresh. |
| **F27** | Cluster Peer Links | `tabs/cluster/` displays peer links and supports pairing windows, comparison-code confirmation, endpoint changes, and link revocation. |
| **F28** | Modernize Debian APT Template | `setup/templates/apt.sources/debian.template` uses `https://deb.debian.org/debian` with `non-free-firmware`. |
| **F29** | Debian 13 Core OS Detection | `setup/modules/00-core.sh` supports Trixie without `VERSION_ID` and detects PHP 8.4 natively. |
| **F30** | Modernize Package Dependencies | `setup/modules/02-packages.sh` removes `software-properties-common`, updates `pcregrep` -> `pcre2-utils`, `libncurses-dev`, drops dead packages. |
| **F31** | Keyring Migration Across packages/ | Zero `apt-key` occurrences. Package scripts use `/usr/share/keyrings/*.gpg` with `[signed-by=...]`. |
| **F32** | Rust API & External WASM Build Pipeline | `scripts/build_wasm_frontend.sh --stage` + `modern_stack.sh` stage `web/dist/` alongside `aetherflow-api`, `af`, `speedtest-backend`, and `af-transcode` (`backend-rs/crates/af-api/src/embed.rs` resolves `STATIC_DIR` or executable-adjacent `web/dist`). |
| **F33** | Systemd Privilege Units | `deploy/systemd/` contains canonical `aetherflow-api.service` (`ProtectSystem=strict`, `NoNewPrivileges=yes`, user `aetherflow`) and `aetherflow-runner.service` (user `root`). |
| **F34** | Sudoers & PM2 Purge | No `/etc/sudoers.d/aetherflow` with `NOPASSWD: ALL`. No root PM2 commands. |
| **F35** | Shell Script Line Endings & Syntax | 100% of shell scripts in `setup/`, `deploy/`, `packages/` use LF line endings and pass `bash -n` syntax validation. |
| **F36** | Automated E2E Test Suite | 4-tier automated test suite covering all 37 features across category-partition, boundary, pairwise, and real-world scenarios. |
| **F37** | Full Verification & Hardening | 100% test pass across `tests/run_e2e.py`, `tests/run_parallel_tests.py`, Rust workspace tests (`backend-rs` & `frontend-rs`), and Playwright WASM E2E (`e2e/`). |

---

## 5. Verification & Continuous Integration

To run the contract and regression suites locally:
```bash
# Quick E2E contract verification (387 tests, runs in < 1 second)
python3 tests/run_e2e.py

# Parallel Python unittest regression suites
AETHERFLOW_SKIP_ENV_FILES=1 python3 tests/run_parallel_tests.py

# Live verification against running backend and runner socket
python3 tests/run_e2e.py --mode live --url http://127.0.0.1:8080 --socket /run/aetherflow/runner.sock
```
