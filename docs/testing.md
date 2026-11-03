# Testing AetherFlow

AetherFlow v4.0.0 verification spans four layers: the **11-crate Rust control plane (`backend-rs`)**, the **Next.js 16 (Obsidian V2) frontend (`frontend`)**, the **Python release/marketplace/hygiene regression suites (`tests`)**, and **Playwright E2E browser tests**.

---

## Prerequisites

Ensure your development machine has:
- **Rust Toolchain (`stable`)**: `cargo` and `rustc` (plus `mold`, `clang`, `pkg-config`, and `libssl-dev` on Linux).
- **Node.js 22+ & npm**: For building the Next.js 16 static export and running Jest/Playwright tests.
- **Python 3.10+**: For running release-manager, installer, and shell hygiene regression tests.

---

## 1. Rust Control Plane Workspace Tests (`backend-rs`)

The 11-crate Rust workspace (`af-models`, `af-files`, `af-db`, `af-hardware`, `af-runner`, `af-release`, `af-host`, `af-cli`, `af-services`, `af-api`, `af-streaming-tests`) contains comprehensive unit, security, and contract tests.

```bash
# Ensure the embedded SPA directory exists if frontend has not been built yet
mkdir -p backend/web/dist

# Run all tests across the 11-crate Rust workspace
cd backend-rs
JWT_SECRET="ci-test-secret-exactly-32bytes!!" \
AES_MASTER_KEY="ci-test-aes-key-exactly-32bytes!" \
ALLOWED_HOSTS="localhost:8080,127.0.0.1:8080" \
cargo test --workspace --locked
```

### Targeting Specific Subsystems
```bash
# Test the HTTP/WS API, auth, McBrowser routes, and Subdomain Gateway
cargo test -p af-api

# Test the privileged UNIX socket runner and 15 declarative package recipes
cargo test -p af-runner

# Test Native McBrowser capability-scoped filesystem operations
cargo test -p af-files

# Test the atomic release engine, WAL-safe snapshots, and rollback recovery
cargo test -p af-release

# Test WAL-safe backups, versioned manifests, and staged restores
cargo test -p af-host

# Test the unified 'af' administrative CLI and 14-step provisioner
cargo test -p af-cli

# Test canonical streaming playback history, reconciliation, and portability
cargo test -p af-streaming-tests
```

---

## 2. Frontend Lint, Unit Tests & Static Export (`frontend`)

```bash
# Install root workspace dependencies
npm ci

# Run ESLint, Jest unit tests, and build the Next.js static export
cd frontend
npm run lint
npm run test:ci
NEXT_STATIC_EXPORT=1 npm run build
```

---

## 3. Release, Marketplace & Shell Hygiene Suites (`tests`)

```bash
# Verify shell syntax and hygiene across all 260+ installer and lifecycle scripts
python3 tests/check_shell_hygiene.py

# Run release workflow, release manager, and Rust build tool regression tests
python3 -m unittest discover -s tests -p 'test_release*.py' -v
python3 -m unittest discover -s tests -p 'test_rust_build_tools.py' -v

# Run Marketplace package lifecycle & safe update regression tests
python3 -m unittest discover -s tests -p 'test_marketplace*.py' -v
python3 -m unittest discover -s tests -p 'test_palate_installer.py' -v
python3 -m unittest discover -s tests -p 'test_maintainerr_installer.py' -v
python3 -m unittest discover -s tests -p 'test_jellyseerr_installer.py' -v
python3 -m unittest discover -s tests -p 'test_youtube_packages.py' -v

# Run the 4-tier E2E contract verification harness
python3 tests/run_e2e.py --mode contract
```

---

## 4. Full Production Single-Binary Build (`scripts/build_gold.sh`)

To execute the complete end-to-end production pipeline locally (Next.js static export $\to$ `backend/web/dist` staging $\to$ Rust workspace tests $\to$ `aetherflow-api` + `af` release compilation $\to$ `.tar.gz` + `SHA256SUMS`):

```bash
bash scripts/build_gold.sh
```
