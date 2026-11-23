# AetherFlow v4.0.0 — Static Contract Verification Report

**Test Mode**: `CONTRACT` (static source & interface inspection via `tests/run_e2e.py --mode contract`)  
**Verified Snapshot**: `2026-11-23` (baseline commit `447e04fe`)  
**Contract Suite Size**: **387 Static Contract Checks**  
**Scope Notice**: This baseline snapshot covers the offline static contract harness only—not live full-stack runtime execution, browser E2E, or privileged KVM guest certification. **25** legacy checks across **8** Tier 1/2 files remain unconditional `self.assert_true(True, ...)` placeholder stubs ([TEST_INFRA.md](./TEST_INFRA.md)); live verification is tracked separately by the Rust workspace, Playwright, streaming, release-smoke, and VM drill suites below.

## 1. Test Execution Commands

```bash
# Run the 387-check static contract inspection harness across all 4 tiers
python3 tests/run_e2e.py --mode contract

# Run with bash wrapper on Linux / WSL
./tests/run_e2e.sh

# Run Python unittest regression suites in parallel
AETHERFLOW_SKIP_ENV_FILES=1 python3 tests/run_parallel_tests.py
```

## 2. Static Contract Breakdown by Tier

| Tier | Verification Scope (Contract Mode) | Total Checks | Passed | Gaps | Pass Rate |
| :--- | :--- | :---: | :---: | :---: | :---: |
| Tier 1 | Feature Contract Inspection (`F01`–`F37`) | 185 | 185* | 0* | 100.0%* |
| Tier 2 | Boundary & Hardening Contract Inspection (`F01`–`F37`) | 185 | 185* | 0* | 100.0%* |
| Tier 3 | Cross-Feature Pairwise Contract Checks | 12 | 12 | 0 | 100.0% |
| Tier 4 | Operator Scenario Contract Checklists (static / read-only in live mode) | 5 | 5 | 0 | 100.0% |
| **Total** | **Static Contract Inspection (`--mode contract`)** | **387** | **387**\* | **0**\* | **100.0%**\* |

*\*Includes 25 unconditional `self.assert_true(True, ...)` placeholder stubs across 8 Tier 1/2 files (see [TEST_INFRA.md](./TEST_INFRA.md)); 362 checks assert real source/contract predicates.*

## 3. Feature Contract Checklist (`F01`–`F37`)

| Feature ID | Description | Domain | Contract Status |
| :--- | :--- | :--- | :---: |
| F01 | Rust Directory Browser Handler | Backend API | PASSED\* |
| F02 | Auth Session Refresh | Backend API | PASSED\* |
| F03 | Profile Password Mutation | Backend API | PASSED\* |
| F04 | Profile Avatar Mutation | Backend API | PASSED |
| F05 | Ingress Configuration CRUD | Backend API | PASSED |
| F06 | System Topology Endpoint | Backend API | PASSED\* |
| F07 | Privileged Runner Extensions | Backend Core | PASSED |
| F08 | Privileged Caller Migration | Backend Core | PASSED |
| F09 | SQLite Migration 17 | Backend Core | PASSED |
| F10 | Cluster Manager Startup Cleanliness | Backend Core | PASSED |
| F11 | Retire Legacy Next.js Frontend | Backend Core | PASSED |
| F12 | Backend Unit & Integration Tests | Backend Core | PASSED\* |
| F13 | Obsidian V2 CSS Foundation | Obsidian UI | PASSED\* |
| F14 | Obsidian V2 Glass & Chromatic Tokens | Obsidian UI | PASSED |
| F15 | Tri-Mode Navigation Architecture | Obsidian UI | PASSED |
| F16 | Scroller Containment Invariant | Obsidian UI | PASSED\* |
| F17 | Atmosphere Tuning Controls | Obsidian UI | PASSED\* |
| F18 | UI Primitives Redesign | Obsidian UI | PASSED |
| F19 | Mount Bandwidth & Predictions Cards | Dashboard Panels | PASSED\* |
| F20 | Mount Metadata & DirectoryPicker | Dashboard Panels | PASSED |
| F21 | Mount ExternalAccess & DeploymentStatus | Dashboard Panels | PASSED |
| F22 | Wire Profile Controls | Dashboard Panels | PASSED\* |
| F23 | Real App Topology Map | Dashboard Panels | PASSED |
| F24 | Network & VPN Operator Panel | Dashboard Panels | PASSED |
| F25 | Notifications & Alerting Panel | Dashboard Panels | PASSED\* |
| F26 | Storage Quotas Panel | Dashboard Panels | PASSED |
| F27 | Cluster Nodes Panel | Dashboard Panels | PASSED |
| F28 | Modernize Debian APT Template | Packaging & Pipeline | PASSED |
| F29 | Debian 13 Core OS Detection | Packaging & Pipeline | PASSED |
| F30 | Modernize Package Dependencies | Packaging & Pipeline | PASSED\* |
| F31 | Keyring Migration Across `packages/` | Packaging & Pipeline | PASSED\* |
| F32 | Rust API & External WASM Build Pipeline | Packaging & Pipeline | PASSED\* |
| F33 | Systemd Privilege Boundary Units | Packaging & Pipeline | PASSED |
| F34 | Sudoers & PM2 Purge | Packaging & Pipeline | PASSED\* |
| F35 | Shell Script Line Endings & Syntax | Packaging & Pipeline | PASSED\* |
| F36 | Automated Contract Test Suite | Test Harness | PASSED\* |
| F37 | Full Verification & Hardening | Verification | PASSED\* |

*\*Rows marked `PASSED*` include one or more legacy unconditional `self.assert_true(True, ...)` placeholder stubs in their Tier 1/2 contract suite (25 stubs total across 18 features).*

## 4. Runtime, Browser & Host Verification Suites

- **Backend, CLI & Plugin SDK (`backend-rs/`, `plugins/sdk-template-rust/backend/`)**: Verified via `cargo test --workspace --locked`, `cargo clippy -- -D warnings`, `cargo audit`/`cargo deny`, and `tests/test_zero_go_cutover.py`.
- **WASM Frontend & Browser E2E (`frontend-rs/`, `e2e/`)**: Verified via `cargo test --manifest-path frontend-rs/Cargo.toml --workspace --locked`, `scripts/build_wasm_frontend.sh --stage`, and Playwright (`scripts/run_embedded_e2e.sh --playwright`, which defaults `E2E_PLAYWRIGHT_SPECS` to `[.]live[.]spec[.]ts$` and runs `embedded.live.spec.ts` unless overridden to include `login.spec.ts`, `navigation.spec.ts`, `marketplace.install.spec.ts`, and `visual.spec.ts`).
- **Streaming History Gate**: Verified via `bash scripts/validate-streaming.sh --scoped` and `--integrated` ([docs/streaming-validation.md](../docs/streaming-validation.md)).
- **Packaging, Shell Hygiene & Release Lifecycle (`setup/`, `packages/`, `deploy/`)**: Verified via `tests/run_parallel_tests.py`, `tests/check_shell_hygiene.py`, and `bash scripts/smoke_v4_release_lifecycle.sh`.
- **Privileged, Lifecycle, Native-Package & 4-OS KVM Drills**: Verified inside disposable QEMU/KVM guests via `scripts/v4_vm_matrix.py`, `scripts/v4_lifecycle_guest_drills.py`, `scripts/v4_privileged_guest_drills.py`, and `scripts/v4_native_package_guest_drills.py`.
