# AetherFlow Codebase Dependency, Workflow & Probe Audit (2026-11-13)

> **Historical Point-in-Time Snapshot (2026-11-13, pre-Zero-Go cutover)**: This document preserves the `nightly` (`#110`) dependency and workflow audit recorded immediately before the v4.0.0 Zero-Go Consolidation & Cutover. Subsequent to this snapshot, `backend/`, `plugins/sdk-template/`, `packages/package/assets/librespeed/backend-patches/`, and all Go workflow steps were decommissioned in favor of the pure-Rust 12-crate workspace (`backend-rs/`).

This audit records toolchain, dependency, workflow, installer, and version-probe alignment updates prepared for the `nightly` branch (`#110`).

## 1. Rust Control Plane (`backend-rs/`)

- **Toolchain verified**: `rustc 1.100.0 (0ef1bc386 2026-11-09)`.
- **Manifest hygiene**:
  - Removed unused `thiserror` workspace dependency from `backend-rs/crates/af-db/Cargo.toml`.
  - Removed unused `anyhow` and `tracing` workspace dependencies from `backend-rs/crates/af-host/Cargo.toml`.
  - Regenerated `backend-rs/Cargo.lock` (`--locked` builds and Clippy verified with zero warnings on release-critical crates `-p af-models -p af-host -p af-release -p af-cli`).

## 2. Legacy Go Service (`backend/`)

- **Toolchain bump**: Updated `backend/go.mod` `go` directive from `1.26.10` to `1.26.11`.
- **Vulnerability & test posture**: Verified clean under `govulncheck ./...` (`0` vulnerabilities) and `go test ./... -count=1`.

## 3. GitHub Actions Workflows (`.github/workflows/`)

Updated `ci.yml`, `release.yml`, `security.yml`, and `deploy-pages.yml` off deprecated Node 20 action majors onto current action releases, and bumped Gitleaks:

| Action / Tool | Previous | Updated | Workflows |
|---|---|---|---|
| `actions/checkout` | `@v4` | `@v7` | `ci.yml`, `release.yml`, `security.yml`, `deploy-pages.yml` |
| `actions/setup-node` | `@v4` | `@v7` | `ci.yml`, `release.yml`, `deploy-pages.yml` |
| `actions/upload-artifact` | `@v4` | `@v7` | `ci.yml` |
| `actions/download-artifact` | `@v4` | `@v8` | `ci.yml` |
| `actions/setup-go` | `@v5` | `@v7` | `ci.yml`, `security.yml` |
| `actions/configure-pages` | `v5` (prior) | `@v6` | `deploy-pages.yml` |
| `actions/upload-pages-artifact` | `v3`/`v4` (prior) | `@v5` | `deploy-pages.yml` |
| `actions/deploy-pages` | `v4` (prior) | `@v5` | `deploy-pages.yml` |
| `actions/attest-build-provenance` | `@v2`/`@v3` (prior) | `@v4` | `release.yml` |
| `gitleaks` (`GITLEAKS_VERSION`) | `8.24.x` (prior) | `8.30.1` | `release.yml`, `security.yml` |

Toolchains pinned in workflows (`dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`, `taiki-e/install-action@v2`, Node `24.22.2` / `22.12.0` / `22`, `go-version-file: backend/go.mod`) were preserved.

## 4. Frontend (`frontend/`)

- **Semver-compatible dependency updates** (`frontend/package.json` & `frontend/package-lock.json`, `npm audit`: `0` vulnerabilities):
  - Runtime: `next` `16.4.6`, `@tanstack/react-virtual` `^3.14.26`, `d3` `^7.9.2`, `framer-motion` `^12.43.0`, `marked` `^18.2.0`, `next-intl` `^4.15.1`, `recharts` `^3.10.1`, `swr` `^2.5.1`, `tailwind-merge` `^3.7.0`, `zustand` `^5.1.0`.
  - Development: `eslint-config-next` `16.4.6`, `@playwright/test` pinned at `1.59.1`, `@tailwindcss/postcss` / `tailwindcss` `^4.3.5`, `@testing-library/react` `^16.3.3`, `@testing-library/user-event` `^14.6.10`, `@types/node` `^20.19.43`, `@types/react` / `@types/react-dom` `^19.3.0`, `jest-environment-jsdom` `^30.5.2`, `undici` `^8.12.4`.
- **UI polish**:
  - Updated `FileshareTab.tsx` streaming caption to `5 MiB Chunk Streaming · 50 MiB Max` with unit test assertion.
  - Bounded all four Recharts `<Tooltip />` overlays in `StreamingTab.tsx` within chart viewboxes and `calc(100vw - 32px)` wrapping styles.

## 5. Package Probes, Installers & Test Hygiene

- **Control-plane version probes** (`backend-rs/crates/af-services/src/workers.rs` & `backend/config/package_automation.json`):
  - Added `"-c", "safe.directory=*"` to `probe_live_git_version` and restricted generic git HEAD discovery strictly to `update_source == "git"` packages.
  - Added `apt_receipt_matches_live_debian_revision` so Debian revision suffixes and epoch prefixes on apt packages reconcile against `.af-version` receipts while rejecting mismatched versions or prerelease suffixes.
  - Updated `version_command` probes for 13 packages (`sonarr`, `radarr`, `lidarr`, `readarr`, `prowlarr`, `tautulli`, `flaresolverr`, `recyclarr`, `kavita`, `calibreweb`, `librespeed`, `znc`, `dispatcharr`) while preserving the `piped` and `invidious` command contracts.
- **Installer & teardown hardening** (`packages/common.sh`, `packages/youtube-common.sh`, `installpackage-kasmvnc`, `installpackage-listenarr`):
  - Tightened `systemd_unit_inactive` so `failed` units require `MainPID == 0`, and guarded bare `$LOGFILE` redirections with `${LOGFILE:-/dev/null}`.
  - Hardened `installpackage-kasmvnc` TLS credential provisioning (regular `0600` files rather than symlinks), directory symlink checks before `validate_config_paths`, and `set +e` rollback ordering so `af_cleanup_job_scratch` runs after `cleanup_state_transaction`.
  - Normalized `installpackage-listenarr` `jq` queries onto single lines so installer AST/hygiene checks remain unambiguous.
- **Python test hygiene**: Closed `sqlite3.connect` handles explicitly with `contextlib.closing(...)` across 7 test modules (`ResourceWarning`-clean under `-W default`) and updated mock `systemctl` / `AF_JOB_SCRATCH_DIR` fixtures to match hardened `common.sh` rollback verification.
