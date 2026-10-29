# AetherFlow v3.1.7 — End-to-End Test Infrastructure Specification

**Document Version**: 3.1.7  
**Author**: teamwork_preview_test_writer (E2E Testing Track)  
**Milestone**: M0 (Testing Track Architecture & Baseline Suite)  
**Status**: APPROVED & PUBLISHED  

---

## 1. E2E Testing Track Principles & Philosophy

The AetherFlow v3.1.7 test infrastructure provides deterministic, requirement-driven verification across the entire software stack (Next.js 14 frontend, Go REST/SSE/WS backend, root privileged runner socket, SQLite WAL database, and Debian 13 systemd packaging).

### Core Principles
1. **Opaque-Box & Requirement-Driven**:
   - Every test case is derived strictly from user requirements in `ORIGINAL_REQUEST.md`, architecture contracts in `PROJECT.md`, and interface specifications.
   - Tests evaluate system behavior at public interfaces (HTTP REST endpoints, Server-Sent Events, UNIX domain sockets, filesystem outputs, static asset contracts, and CSS token systems) rather than internal private variables.
2. **Authoritative Expected Output Derivation**:
   - For every test case, expected outputs are grounded in explicit contracts (status codes, JSON schemas, cryptographic properties, sandboxing boundaries, and systemd security policies).
   - Dynamic values (timestamps, PIDs, random tokens) use deterministic structural matching and regex pattern validation.
3. **Progressive Testability & Dual-Mode Execution**:
   - **Contract & Static Code Inspection Mode (`--mode contract`)**: Evaluates code artifacts, route tables, AST/regex declarations, CSS token hierarchies, shell script line endings (`LF`), and migration files. Enables 100% of the test suite to execute and report baseline gaps in early milestones (M0-M4) without requiring daemons to be running.
   - **Live System Mode (`--mode live`)**: Executes real HTTP requests against `http://localhost:8080` (or `AETHERFLOW_API_URL`), tests live Server-Sent Events (`/api/v1/auth/deploy/stream`), and exercises the privileged runner UNIX domain socket (`/run/aetherflow/runner.sock`).
   - **Simulated Harness Mode (`--mode mock`)**: Spins up an in-process mock server adhering to all interface contracts to verify test harness logic and validate consumer integrations.
4. **Strict Isolation & Zero State Leakage**:
   - Tests are independent and idempotent. Each test initializes its own fixtures, avoids ordering dependencies, and cleans up temporary resources upon completion.
5. **Actionable Diagnostics & Zero-Facade Integrity**:
   - Tests assert real logic and error conditions. Facade tests that unconditionally pass are strictly forbidden.
   - Failures report the exact feature ID, tier, input parameters, expected contract, and observed mismatch.

---

## 2. 4-Tier Test Suite Architecture

The test suite is organized into four complementary verification tiers covering all 37 features from `PROJECT.md § Feature Inventory`:

```
========================================================================================
                                4-TIER TEST ARCHITECTURE
========================================================================================
 Tier 1: Feature Coverage (Category-Partition)
   └─ >=5 test cases per feature (F01–F37) = 185 tests
   └─ Happy-path, primary behaviors, valid inputs, expected state transitions.
----------------------------------------------------------------------------------------
 Tier 2: Boundary & Corner Cases (Adversarial Verification)
   └─ >=5 test cases per feature (F01–F37) = 185 tests
   └─ Empty inputs, path traversal, injection payloads, limits, permission boundaries.
----------------------------------------------------------------------------------------
 Tier 3: Cross-Feature Combinations (Pairwise Interoperability)
   └─ 12 multi-feature integration suites (>25 tests)
   └─ Ingress + Caddy + Hosts, Auth Refresh + Password, PathSelector + FS + MediaFlow.
----------------------------------------------------------------------------------------
 Tier 4: Real-World Application Scenarios (Operator E2E Workflows)
   └─ 5 complete end-to-end lifecycles (>15 tests)
   └─ Operator Bootstrap, App Provisioning, Multi-Tenant Quotas, Mesh VPN, Anomaly Healing.
========================================================================================
 Total Test Cases: 410+ Systematic Tests
========================================================================================
```

### Tier 1: Feature Coverage (Equivalence Classes & Happy Paths)
- **Objective**: Verify that every feature performs its intended specification under standard, valid conditions.
- **Rule**: Minimum of 5 distinct test cases per feature (F01 through F37).
- **Scope**:
  - Valid REST requests return HTTP 200/201/204 with valid JSON schema.
  - Component exports and rendering logic mount correctly without crashing.
  - Design system tokens and atmospheric styles conform to Obsidian V2 definitions.
  - Packaging scripts, APT sources, and systemd templates conform to Debian 13 specifications.

### Tier 2: Boundary & Corner Cases (Adversarial Hardening)
- **Objective**: Verify system robustness against hostile, malformed, or extreme inputs.
- **Rule**: Minimum of 5 distinct boundary test cases per feature (F01 through F37).
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
  3. `test_combo_pathselector_fs_mediaflow`: PathSelector (F01, F20) + FS Handler (F01) + MediaFlow Transcoding + Token Fixes (F20).
  4. `test_combo_quota_billing_runner`: Quotas Panel (F26) + Runner Quota Socket (F07, F08) + Billing Webhook Audit Logs (F26).
  5. `test_combo_network_wireguard_tailscale`: Network Panel (F24) + Runner Network Socket (F07, F08) + Key Generation.
  6. `test_combo_cluster_telemetry_mgmt`: Cluster Manager Startup (F10) + Cluster Panel (F27) + Worker Enrollment + Node Metrics.
  7. `test_combo_single_binary_spa_tokens`: Single-Binary Build (F32) + SPA Embedding (F32) + Obsidian CSS (F13, F14) + Static Export (F11).
  8. `test_combo_privilege_boundary_sandbox`: Systemd Privilege Units (F33) + Sudoers Purge (F34) + Caller Migration (F08) + Runner Sandboxing (F07).
  9. `test_combo_debian13_apt_packaging`: APT Template (F28) + Core OS Detection (F29) + Package Modernization (F30) + Keyring Migration (F31).
  10. `test_combo_ai_telemetry_predictions`: Predictions History (F19) + AI Bandwidth Tuning (F19) + Overview Dashboard Mounting (F19).
  11. `test_combo_deploy_sse_caddy`: External Access (F21) + Deployment SSE Stream (F21) + Caddy Dynamic Routing (F05).
  12. `test_combo_responsive_ui_containment`: Tri-Mode Dock (F15) + Scroller Containment (F16) + Touch Targets (F15) + Primitives (F18).

### Tier 4: Real-World Application Scenarios (Operator Lifecycles)
- **Objective**: Exercise complex, multi-step real-world administrator workflows from start to finish.
- **Scenarios**:
  1. `test_scenario_operator_bootstrap`: Clean system install on Debian 13 -> single binary daemon startup -> privileged runner socket binding -> unprivileged user drops capabilities -> admin login -> password update -> profile avatar -> topology verification.
  2. `test_scenario_app_ingress_provisioning`: Radarr application deployment -> dynamic Caddy upstream proxying -> external domain assignment -> `/etc/hosts` sync via privileged runner -> deployment SSE status streaming -> topology visualization.
  3. `test_scenario_multitenant_quota_enforcement`: User provisioning -> storage quota assignment via runner `setdisk` -> billing webhook notification -> quota recalculation -> boundary limit enforcement.
  4. `test_scenario_mesh_vpn_orchestration`: Operator navigates to Network & VPN panel -> generates WireGuard keypair -> enrolls peer -> advertises Tailscale subnet route via privileged runner -> live interface verification.
  5. `test_scenario_ai_anomaly_healing`: Hardware metrics collection -> AI predictions report computation (real metrics history, no sine waves) -> anomaly alert rule trigger -> notification dispatch -> automated self-healing action dispatched through runner socket.

---

## 3. Test Runner Architecture & Directory Layout

### Directory Structure
```
tests/
├── e2e/
│   ├── __init__.py
│   ├── runner.py                 # Core discovery and execution engine
│   ├── framework.py              # Test harness, assertions, contract inspector, mock server
│   ├── tier1_features/           # Tier 1: 37 feature test modules (F01–F37, >=5 tests each)
│   │   ├── __init__.py
│   │   ├── test_f01_fs_browser.py
│   │   ├── test_f02_auth_refresh.py
│   │   ├── test_f03_profile_password.py
│   │   ├── test_f04_profile_avatar.py
│   │   ├── test_f05_ingress_crud.py
│   │   ├── test_f06_system_topology.py
│   │   ├── test_f07_runner_extensions.py
│   │   ├── test_f08_caller_migration.py
│   │   ├── test_f09_migration17.py
│   │   ├── test_f10_cluster_cleanliness.py
│   │   ├── test_f11_remove_fs_route.py
│   │   ├── test_f12_backend_unit_tests.py
│   │   ├── test_f13_obsidian_css_foundation.py
│   │   ├── test_f14_obsidian_glass_tokens.py
│   │   ├── test_f15_trimode_navigation.py
│   │   ├── test_f16_scroller_containment.py
│   │   ├── test_f17_atmosphere_controls.py
│   │   ├── test_f18_ui_primitives.py
│   │   ├── test_f19_mount_overview_cards.py
│   │   ├── test_f20_mount_mediaflow_tab.py
│   │   ├── test_f21_mount_services_cards.py
│   │   ├── test_f22_wire_profile_controls.py
│   │   ├── test_f23_app_topology_map.py
│   │   ├── test_f24_network_panel.py
│   │   ├── test_f25_notifications_panel.py
│   │   ├── test_f26_quotas_panel.py
│   │   ├── test_f27_cluster_panel.py
│   │   ├── test_f28_debian_apt_template.py
│   │   ├── test_f29_debian13_os_detection.py
│   │   ├── test_f30_modernize_packages.py
│   │   ├── test_f31_keyring_migration.py
│   │   ├── test_f32_single_binary_pipeline.py
│   │   ├── test_f33_systemd_privilege_units.py
│   │   ├── test_f34_sudoers_pm2_purge.py
│   │   ├── test_f35_shell_syntax_endings.py
│   │   ├── test_f36_test_suite_coverage.py
│   │   └── test_f37_full_verification.py
│   ├── tier2_boundaries/         # Tier 2: 37 boundary test modules (B01–B37, >=5 tests each)
│   │   ├── __init__.py
│   │   └── test_boundaries_f01_to_f37.py
│   ├── tier3_pairwise/           # Tier 3: 12 cross-feature integration test suites
│   │   ├── __init__.py
│   │   └── test_pairwise_combos.py
│   └── tier4_realworld/          # Tier 4: 5 realistic application scenarios
│       ├── __init__.py
│       └── test_realworld_scenarios.py
├── run_e2e.py                    # Root entrypoint (`python tests/run_e2e.py`)
├── run_e2e.ps1                   # Native PowerShell wrapper
└── run_e2e.sh                    # Linux / WSL bash wrapper
```

### Test Invocation & CLI Interface

The test suite runs with standard zero-dependency Python 3 (works identically on Windows PowerShell, Linux, Debian 13, and WSL):

```bash
# Run all 4 tiers in contract/static verification mode (default for M0 baseline)
python tests/run_e2e.py

# Run with PowerShell wrapper
powershell -ExecutionPolicy Bypass -File tests/run_e2e.ps1

# Run with Linux/WSL wrapper
./tests/run_e2e.sh

# Filter by tier
python tests/run_e2e.py --tier 1
python tests/run_e2e.py --tier 2
python tests/run_e2e.py --tier 3
python tests/run_e2e.py --tier 4

# Filter by feature ID
python tests/run_e2e.py --feature F01
python tests/run_e2e.py --feature F05

# Run in live mode against a running AetherFlow daemon
python tests/run_e2e.py --mode live --url http://localhost:8080

# Output results to JSON or Markdown file
python tests/run_e2e.py --json-out tests/baseline_results.json
python tests/run_e2e.py --report-out TEST_READY.md
```

### Exit Codes & Pass/Fail Semantics
- `0`: All executed tests passed successfully.
- `1`: One or more tests failed (or missing requirements detected in contract mode).
- `2`: Invalid CLI arguments or configuration error.

---

## 4. Feature Expected Output Derivation Matrix

| Feature | Primary Contract / Interface | Authoritative Expected Output |
| :--- | :--- | :--- |
| **F01** | `GET /api/v1/auth/fs?path=...` & `/api/fs` | 200 OK with `{"current_path": str, "parent_path": str, "entries": [{"name": str, "is_dir": bool, ...}]}`. Traversal (`../../etc`) -> 400/403. Outside allowed roots -> 403. |
| **F02** | `POST /api/v1/auth/refresh` | 200 OK with `{"status": "success", "token": str, "expires_at": int, "user": {...}}`. Exempt from CSRF or accepts `X-Requested-With: XMLHttpRequest`. Expired/invalid -> 401. |
| **F03** | `PUT /api/v1/auth/profile/password` | Bcrypt verification of `current_password`, min 8 chars for `new_password`. Success -> 200 OK. Wrong current password -> 400/401. Short password -> 400. |
| **F04** | `PUT/DELETE /api/v1/auth/profile/avatar` | PUT: Accepts image URL or base64 data URI (max 2MB) -> 200 OK. DELETE: Clears avatar -> 200 OK. Invalid scheme / oversized -> 400/413. |
| **F05** | `GET /api/v1/admin/ingress/configs` & `PUT .../apps/:appName` | GET returns `{"configs": [...]}`. PUT upserts into SQLite `app_ingress_configs` and triggers `CaddyManager.UpdateAppRoutes()`. Port 1-65535, valid domain format. |
| **F06** | `GET /api/v1/auth/system/topology` | 200 OK with live `nodes` and `links`. Nodes represent real daemons (API, Runner, SQLite WAL, Redis, Caddy). Zero hardcoded dummy nodes (`Proxy Port 8080`, `Nginx Router`). |
| **F07** | `/run/aetherflow/runner.sock` (`/v1/sandbox`, `/v1/hosts`, `/v1/network`, `/v1/quota`) | HTTP/1.1 over UNIX domain socket, mode 0660 root:aetherflow. Max body 4096 bytes. Safe ID validation. Strict allowlist execution. |
| **F08** | Caller Refactoring (`af_heal`, `arr_injector`, etc.) | Zero direct `sudo` or mutating `systemctl` calls in 7 target services. All route via `privileged_runner.go`. |
| **F09** | SQLite Migration 17 (`app_ingress_configs`) | Schema: `app_ingress_configs(app_name TEXT PRIMARY KEY, public_domain TEXT, external_access_enabled INTEGER, listen_port INTEGER, tls_enabled INTEGER, updated_at DATETIME)`. Idempotent. |
| **F10** | Cluster Manager Startup | `backend/main.go` calls `cluster.Init()` or alias before HTTP serving. `cluster.Manager` is non-nil. Handlers return 200 instead of 503. |
| **F11** | Remove Next.js FS Route | `frontend/src/app/api/fs/route.ts` deleted. `NEXT_STATIC_EXPORT=1 npm run build` exports to `frontend/out/` without server-route conflict. |
| **F12** | Backend Unit Tests | `go test ./...` passes 100% of packages, including new fs, auth, profile, ingress, and runner socket tests. |
| **F13** | Obsidian V2 CSS Foundation | `globals.css` defines `--obs-bg-base: #000000`, `body::before` 3-orb radial aurora + base gradient (`z-index: -2`), `body::after` fractal micro-grain + edge vignette (`z-index: -1`). |
| **F14** | Obsidian V2 Glass Tokens | Directional specular highlight (`--obs-specular-top`), chromatic borders (`--obs-chromatic-border-*`), prism rims, 120Hz spring physics (`--obs-ease-spring-120`). |
| **F15** | Tri-Mode Navigation | Desktop expandable rail (>=1024px), tablet icon rail (768-1023px), mobile bottom dock (<768px, `md:hidden`) with safe-area padding and >=44px touch targets. |
| **F16** | Scroller Containment Invariant | Zero blanket `html, body { overflow-x: hidden }`. Horizontal overflow scoped via `min-w-0`, `max-w-full`, and `overflow-x-auto`. |
| **F17** | Atmosphere Controls | `DashboardSettingsTab.tsx` exposes aurora intensity, static vs animated switch, micro-grain toggle, and card lift density controls. |
| **F18** | UI Primitives Redesign | `Card`, `Button`, `Input`, `Modal`, `DataGrid`, `login/page.tsx`, and `oauth/consent/page.tsx` upgraded to Obsidian V2 tokens. |
| **F19** | Mount Bandwidth & Predictions | Mounted in `OverviewTab.tsx`. `PredictionsCard` fetches real history from `/api/v1/admin/ai/predictions/history` (zero `Math.sin()` fake sine waves). |
| **F20** | Mount MetadataTab & PathSelector | Mounted in `MediaFlowTab.tsx`. `PathSelector` wired to `/api/v1/auth/fs`. `MediaFlowTab` uses `apiFetch` with cookie auth (no `localStorage.getItem('token')`). |
| **F21** | Mount ExternalAccessCard & Deploy | Mounted in `ServicesTab.tsx` / `MarketplaceTab.tsx`. `useIngressStore.ts` wired. Deployment status listens to `/api/v1/auth/deploy/stream`. |
| **F22** | Wire Profile Controls | `ProfileTab.tsx` wires password change modal (`PUT /api/v1/auth/profile/password`) and avatar change/delete (`PUT/DELETE /api/v1/auth/profile/avatar`). |
| **F23** | Real App Topology Map | `AppTopologyMap.tsx` renders live nodes from `/api/v1/auth/system/topology`. 4 hardcoded dummy nodes removed. |
| **F24** | Network & VPN Panel | `NetworkTab.tsx` manages WireGuard peers/keygen and Tailscale status/peers/routes. |
| **F25** | Notifications & Alerting Panel | `NotificationsSettingsTab.tsx` manages notification rules and channels (with test alert trigger). |
| **F26** | Quotas & Billing Panel | `QuotasBillingTab.tsx` manages user storage quotas and lists billing webhook audit logs. |
| **F27** | Cluster Nodes Panel | `ClusterTab.tsx` displays node telemetry, worker enrollment join tokens, and node removal. |
| **F28** | Modernize Debian APT Template | `setup/templates/apt.sources/debian.template` updated to `https://deb.debian.org/debian/` with `non-free-firmware`. |
| **F29** | Debian 13 Core OS Detection | `setup/modules/00-core.sh` supports Trixie without `VERSION_ID` and detects PHP 8.4 natively. |
| **F30** | Modernize Package Dependencies | `setup/modules/02-packages.sh` removes `software-properties-common`, updates `pcregrep` -> `pcre2-utils`, `libncurses-dev`, drops dead packages. |
| **F31** | Keyring Migration Across packages/ | Zero `apt-key` occurrences. All 7 package scripts use `/usr/share/keyrings/*.gpg` with `[signed-by=...]`. |
| **F32** | Single-Binary Build Pipeline | `modern_stack.sh` & `05-finalize.sh` export static SPA, copy into `backend/web/dist/`, and compile single binary `aetherflow-api`. |
| **F33** | Systemd Privilege Units | `setup/templates/sysd/` contains `aetherflow-api.template` (`ProtectSystem=strict`, `NoNewPrivileges=yes`, user `aetherflow`) and `aetherflow-runner.template` (user `root`). |
| **F34** | Sudoers & PM2 Purge | No `/etc/sudoers.d/aetherflow` with `NOPASSWD: ALL`. No root PM2 commands. |
| **F35** | Shell Script Line Endings & Syntax | 100% of shell scripts in `setup/`, `deploy/`, `packages/` use LF line endings and pass `bash -n` syntax validation. |
| **F36** | Automated E2E Test Suite | 4-tier automated test suite covering all 37 features across category-partition, boundary, pairwise, and real-world scenarios. |
| **F37** | Full Verification & Hardening | 100% test pass across E2E test runner, unit tests (`go test`, `npm test`), static export, single binary compilation, and socket smoke tests. |

---

## 5. Verification & Continuous Integration

To run this test suite in CI/CD or local development:
```bash
# Quick local contract verification (runs in < 5 seconds)
python tests/run_e2e.py

# Full verification against running backend and runner socket
python tests/run_e2e.py --mode live --url http://127.0.0.1:8080 --socket /run/aetherflow/runner.sock
```
