# Testing AetherFlow

AetherFlow verification spans the **Rust control plane (`backend-rs`)**, the **Rust WASM dashboard (`frontend-rs`)**, the **Python release, marketplace, and Zero-Go regression suites (`tests`)**, and **Playwright E2E browser tests** retained under `frontend/tests/e2e`.

---

## Prerequisites

Ensure your development machine has:
- **Rust 1.99.1**: Selected by `rust-toolchain.toml`, with `cargo`, `rustc`, Clippy, rustfmt, and the WASM target (plus `mold`, `clang`, `pkg-config`, and `libssl-dev` on Linux).
- **Node.js >=22.19.0 & npm**: For running the Playwright browser harness. CI uses Node 24. The production dashboard is built with Rust and Trunk.
- **Python 3.10+**: For running release-manager, installer, and shell hygiene regression tests.

---

## 1. Rust Control Plane Workspace Tests (`backend-rs`)

The 12-crate pure-Rust workspace (`af-models`, `af-files`, `af-db`, `af-hardware`, `af-runner`, `af-release`, `af-host`, `af-cli`, `af-services`, `af-api`, `af-librespeed`, `af-streaming-tests`) contains comprehensive unit, security, and contract tests.

```bash
# Run all tests across the 12-crate Rust control plane
cd backend-rs
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --no-deps -p af-models -p af-host -p af-release -p af-cli -p af-librespeed --all-targets --locked -- -D warnings

# Run all tests across the 12-crate pure-Rust workspace
JWT_SECRET="ci-test-secret-exactly-32bytes!!" \
AES_MASTER_KEY="ci-test-aes-key-exactly-32bytes!" \
ALLOWED_HOSTS="localhost:8080,127.0.0.1:8080" \
cargo test --workspace --locked -- --test-threads=1
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

## 2. WASM Frontend Checks (`frontend-rs`)

```bash
bash scripts/install_wasm_build_tools.sh --ensure
cargo fmt --manifest-path frontend-rs/Cargo.toml --all -- --check
cargo test --manifest-path frontend-rs/Cargo.toml --workspace --locked
cargo clippy --manifest-path frontend-rs/Cargo.toml --workspace --all-targets --locked -- -D warnings
cargo clippy --manifest-path frontend-rs/Cargo.toml --workspace --target wasm32-unknown-unknown --locked -- -D warnings
python3 scripts/finalize_wasm_assets.py --self-test
bash scripts/build_wasm_frontend.sh --stage
```

Native tests exercise shared algorithms and state policies; they do not establish browser DOM behavior. Run the live and fixture-based browser suites against the built WASM application. The old `frontend/src` remains a reference and does not supply release assets.

---

## 3. Release, Marketplace & Shell Hygiene Suites (`tests`)

```bash
# Verify shell syntax and hygiene across all 260+ installer and lifecycle scripts
python3 tests/check_shell_hygiene.py

# Run release workflow, Zero-Go cutover, release manager, and Rust build tool regression tests
python3 -m unittest discover -s tests -p 'test_zero_go_cutover.py' -v
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

## 4. Production Release Bundle (`scripts/build_gold.sh`)

The production pipeline builds the WASM interface, runs Rust checks, and packages `aetherflow-api`, `af`, and `speedtest-backend` with external `web/dist` files and `SHA256SUMS`:

```bash
bash scripts/build_gold.sh
```

## 5. Browser Verification Against Runtime Assets

Install the root npm workspace dependencies and the Chromium, Firefox, and WebKit engines with a supported Node.js runtime. Test the release layout with the API binary and its external UI directory:

```sh
npm ci --ignore-scripts
npm exec --workspace frontend -- playwright install --with-deps chromium firefox webkit
bash scripts/run_embedded_e2e.sh \
  --binary /path/to/release/aetherflow-api \
  --static-dir /path/to/release/web/dist \
  --port 18080 --playwright
```

The historical harness filename is retained for compatibility. The default run uses disposable state and leaves the privileged runner disabled. `embedded.live.spec.ts` exercises real authentication, persistence, and file operations. The parity, login, dashboard, and visual tests use deterministic API fixtures while executing the served WASM application. Run those separately with `E2E_PLAYWRIGHT_SPECS` to preserve that distinction in reports.

The browser configuration requires `PLAYWRIGHT_BASE_URL` pointing to a Rust API with a built WASM bundle. The harness supplies it; there is no automatic Next.js development server. All three engines run functional tests. Screenshot baselines run on Chromium. Fixture tests block service workers to keep network interception deterministic; the separate live cache test enables a real service worker and checks that authenticated responses stay out of CacheStorage. Worker fault tests transfer actual upload buffers, then simulate a crash or timeout and verify every resulting chunk checksum.

The Python compatibility harness includes source inspections as well as HTTP checks; its aggregate count is not a count of live browser tests. Native unit tests, mocked browser contracts, live browser tests, and privileged/VM tests must be reported separately.
