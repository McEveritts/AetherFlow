# Testing AetherFlow

AetherFlow verification spans the **Rust control plane (`backend-rs`, 11 crates)**, the **Rust WASM dashboard (`frontend-rs`, 4 crates)**, the **Rust Plugin SDK (`plugins/sdk-template-rust/backend`)**, the **Python release, marketplace, and hygiene regression suites (`tests/`)**, and **Playwright browser tests (`e2e/`)**.

---

## Prerequisites

Ensure your development environment provides:

- **Rust `1.99.1`**: Selected automatically via `rust-toolchain.toml`, with `cargo`, `rustc`, `clippy`, `rustfmt`, and the `wasm32-unknown-unknown` target. On Linux, `backend-rs/.cargo/config.toml` configures `-fuse-ld=mold` for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` (install `mold` for direct `cargo test` inside `backend-rs/`, override with `RUSTFLAGS=""`, or rely on `build_gold.sh`'s automatic `bfd` fallback), alongside `pkg-config` and `libssl-dev`.
- **Node.js `24.22.2` (`.nvmrc`; minimum `>= 22.19.0`) & `npm`**: Required for the Playwright E2E harness (`e2e/`). The dashboard itself compiles via Rust and Trunk.
- **Python 3.10+**: Required for release-manager, installer, shell hygiene, and VM guest drill test suites.

---

## 1. Rust Control Plane & Plugin SDK Tests (`backend-rs`, `plugins/`)

The 11-crate workspace (`af-models`, `af-files`, `af-db`, `af-hardware`, `af-runner`, `af-release`, `af-host`, `af-cli`, `af-services`, `af-api`, `af-librespeed`) contains unit, security, and HTTP/IPC contract tests.

```bash
cd backend-rs

# Lint the entire workspace (CI also runs a targeted --no-deps pass on core library/CLI crates)
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --no-deps -p af-models -p af-host -p af-release -p af-cli -p af-librespeed --all-targets --locked -- -D warnings

# Run all backend workspace tests serially
# (--test-threads=1 prevents process-global SQLite/env collisions;
#  AETHERFLOW_DISABLE_BACKGROUND_WORKERS=1 keeps periodic background loops off during tests)
JWT_SECRET="ci-test-secret-exactly-32bytes!!" \
AES_MASTER_KEY="ci-test-aes-key-exactly-32bytes!" \
ALLOWED_HOSTS="localhost:8080,127.0.0.1:8080" \
AETHERFLOW_DISABLE_BACKGROUND_WORKERS=1 \
cargo test --workspace --locked -- --test-threads=1
```

### Targeting Specific Subsystems & Plugin SDK

Run from `backend-rs/` (from Section 1 above):

```bash
# HTTP/WS API, auth, McBrowser, Subdomain Gateway, and streaming contracts
# (Supply the same JWT_SECRET, AES_MASTER_KEY, ALLOWED_HOSTS, and
#  AETHERFLOW_DISABLE_BACKGROUND_WORKERS=1 env vars shown above)
JWT_SECRET="ci-test-secret-exactly-32bytes!!" \
AES_MASTER_KEY="ci-test-aes-key-exactly-32bytes!" \
ALLOWED_HOSTS="localhost:8080,127.0.0.1:8080" \
AETHERFLOW_DISABLE_BACKGROUND_WORKERS=1 \
cargo test -p af-api -- --test-threads=1

# Privileged Unix socket runner and 9 opt-in declarative package recipes
cargo test -p af-runner

# Capability-scoped McBrowser filesystem confinement
cargo test -p af-files

# Atomic release engine, WAL-safe snapshots, and rollback recovery
cargo test -p af-release

# WAL-safe backups, manifests, and staged restores
cargo test -p af-host

# Unified 'af' administrative CLI and 34-step provisioner (14 Rust-native + 20 retained shell)
cargo test -p af-cli

# Rust Plugin SDK template (standalone workspace)
cd ../plugins/sdk-template-rust/backend
cargo clippy --all-targets -- -D warnings
cargo test
cd ../../..
```

---

## 2. WASM Frontend Checks (`frontend-rs`)

Run from the repository root:

```bash
bash scripts/install_wasm_build_tools.sh --ensure
cargo fmt --manifest-path frontend-rs/Cargo.toml --all -- --check
cargo test --manifest-path frontend-rs/Cargo.toml --workspace --locked
cargo clippy --manifest-path frontend-rs/Cargo.toml --workspace --all-targets --locked -- -D warnings
cargo clippy --manifest-path frontend-rs/Cargo.toml --workspace --target wasm32-unknown-unknown --locked -- -D warnings
python3 scripts/finalize_wasm_assets.py --self-test
bash scripts/build_wasm_frontend.sh --stage
```

CI supply-chain gates also run `cargo audit` and `cargo deny check` across all three Rust workspaces: `backend-rs/`, `frontend-rs/`, and `plugins/sdk-template-rust/backend/`.

Native Rust tests exercise shared algorithms and state policies; they do not verify browser DOM rendering. Run Playwright against the built WASM assets staged in `web/dist/`.

---

## 3. Release, Marketplace & Shell Hygiene Suites (`tests/`)

```bash
# Verify bash -n syntax, zero active apt-key invocations, and zero NOPASSWD: ALL sudoers rules
# across setup/, deploy/, packages/, scripts/, and bin/ (LF line endings are checked by tests/run_e2e.py --mode contract)
python3 tests/check_shell_hygiene.py

# Run all Python unittest suites in parallel (CI default; AETHERFLOW_SKIP_ENV_FILES=1
# prevents test subprocesses from reading host /etc/aetherflow/aetherflow.env or credentials)
AETHERFLOW_SKIP_ENV_FILES=1 python3 tests/run_parallel_tests.py

# Or run targeted suites individually (export AETHERFLOW_SKIP_ENV_FILES=1 on installed hosts):
export AETHERFLOW_SKIP_ENV_FILES=1
python3 -m unittest discover -s tests -p 'test_zero_go_cutover.py' -v
python3 -m unittest discover -s tests -p 'test_release*.py' -v
python3 -m unittest discover -s tests -p 'test_rust_build_tools.py' -v
python3 -m unittest discover -s tests -p 'test_marketplace*.py' -v
python3 -m unittest discover -s tests -p 'test_palate_installer.py' -v
python3 -m unittest discover -s tests -p 'test_maintainerr_installer.py' -v
python3 -m unittest discover -s tests -p 'test_jellyseerr_installer.py' -v
python3 -m unittest discover -s tests -p 'test_youtube_packages.py' -v

# Run the 4-tier static E2E contract inspection harness (see tests/TEST_INFRA.md)
python3 tests/run_e2e.py --mode contract

# Local release-lifecycle smoke script (non-privileged temporary staging)
bash scripts/smoke_v4_release_lifecycle.sh
```

---

## 4. Production Release Bundle (`scripts/build_gold.sh`)

`scripts/build_gold.sh` builds the WASM frontend, runs locked Rust tests for `backend-rs` and `frontend-rs`, and packages `aetherflow-api`, `bin/af`, `bin/speedtest-backend`, external `web/dist/`, `config/`, `deploy/`, `packages/`, `plugins/telemetry-inspector/`, `.version`, and `SHA256SUMS` into `dist/gold/<version>/` (overridable via `OUTPUT_DIR`):

```bash
bash scripts/build_gold.sh
```

---

## 5. Browser Verification Against Runtime Assets (`e2e/`)

Install workspace npm dependencies at the repository root and install the Chromium, Firefox, and WebKit browser engines inside `e2e/` (matching `.github/workflows/ci.yml`), then launch the isolated Rust API + Playwright runner:

```bash
npm ci
(cd e2e && npx playwright install --with-deps chromium firefox webkit)

# Build the debug API binary if you have not already packaged dist/gold/<version>/
cargo build --manifest-path backend-rs/Cargo.toml --locked --bin aetherflow-api

# Run the default live Playwright spec (embedded.live.spec.ts) against a built binary and staged web/dist
# (e.g., dist/gold/<version>/linux-amd64/aetherflow-api + .../web/dist, or backend-rs/target/debug/aetherflow-api + web/dist)
bash scripts/run_embedded_e2e.sh \
  --binary backend-rs/target/debug/aetherflow-api \
  --static-dir web/dist \
  --port 18080 --playwright

# Pass a non-empty E2E_PLAYWRIGHT_SPECS override (paths relative to e2e/; note "" falls back to [.]live[.]spec[.]ts$)
# to run fixture-backed/visual specs (or E2E_PLAYWRIGHT_SPECS="tests/e2e" for all 5 specs)
E2E_PLAYWRIGHT_SPECS="tests/e2e/login.spec.ts tests/e2e/navigation.spec.ts tests/e2e/marketplace.install.spec.ts tests/e2e/visual.spec.ts" \
bash scripts/run_embedded_e2e.sh \
  --binary backend-rs/target/debug/aetherflow-api \
  --static-dir web/dist \
  --port 18080 --playwright
```

`scripts/run_embedded_e2e.sh` runs against disposable temporary state and unconditionally keeps the privileged runner disabled (`--with-runner` exits `2`).

### Playwright Spec Breakdown

- **Live E2E (`embedded.live.spec.ts`)**: Exercises real authentication, SQLite persistence, McBrowser operations, standalone WASM worker SHA-256 hashing (`Sha256ChunkTransfer` on `'abc'`), cross-tab account-switch upload cancellation on an injected `403 CSRF_INVALID` (`retryCount === 0`), and live service-worker cache boundary tests (verifying authenticated responses stay out of `CacheStorage`).
- **Deterministic API-fixture contract & visual specs**: `login.spec.ts`, `navigation.spec.ts`, `marketplace.install.spec.ts`, and `visual.spec.ts` run the real compiled WASM UI against mocked API responses (blocking service workers so route interception stays deterministic).
- **Spec selection (`E2E_PLAYWRIGHT_SPECS`)**: `scripts/run_embedded_e2e.sh` defaults `E2E_PLAYWRIGHT_SPECS` via `${E2E_PLAYWRIGHT_SPECS:-[.]live[.]spec[.]ts$}`, so `--playwright` runs **only** `embedded.live.spec.ts` when unset or empty (`""`). Pass a non-empty list of spec paths relative to `e2e/` (or `E2E_PLAYWRIGHT_SPECS="tests/e2e"` / `"[.]spec[.]ts$"` for all 5 specs) to run fixture-contract and visual suites.

`e2e/playwright.config.ts` requires `PLAYWRIGHT_BASE_URL` pointing to a running Rust API serving `web/dist` (supplied automatically by `run_embedded_e2e.sh`). Chromium, Firefox, and WebKit all run functional specs; `visual.spec.ts` runs on Chromium only.

> [!NOTE]
> Report native Rust unit tests, static Python contract checks (`tests/run_e2e.py --mode contract`), fixture-mocked Playwright specs, live `embedded.live.spec.ts` runs, and privileged QEMU/KVM VM drills separately—never merge static inspection counts into live browser or host pass totals.

---

## 6. Specialized Validation & Guest Drill Runbooks

Shared VM/guest helper modules live under `scripts/lib/` (`vm_guest_common.py`, `vm_lifecycle_evaluators.py`, `vm_matrix_helpers.py`, `vm_remote_engine.py`).

- **[Static Contract Infrastructure (`tests/TEST_INFRA.md`)](../tests/TEST_INFRA.md)** & **[Static Contract Report (`tests/TEST_READY.md`)](../tests/TEST_READY.md)**: 4-tier offline contract inspection harness (`tests/run_e2e.py --mode contract`) and baseline summary.
- **[Playwright E2E Suite (`e2e/tests/e2e/README.md`)](../e2e/tests/e2e/README.md)**: Live and fixture-mocked browser verification specs.
- **[Streaming Validation Gate](./streaming-validation.md)**: Scoped and integrated streaming verification via `scripts/validate-streaming.sh`.
- **[Clean-Host KVM Matrix Testing](./v4-clean-host-testing.md)**: Four-OS QEMU/KVM clean-host bootstrap, upgrade, and rollback drills (`scripts/v4_vm_matrix.py`).
- **[Lifecycle & Self-Update Guest Drills](./v4-lifecycle-testing.md)**: Disposable guest drills for transient-unit self-updates and rollback recovery (`scripts/v4_lifecycle_guest_drills.py`).
- **[Privileged Guest Drills](./v4-privileged-testing.md)**: Disposable guest drills for `af-runner` socket authorization, live WAL backups, and quiesced restores (`scripts/v4_privileged_guest_drills.py`).
- **[Native Package Guest Drills](./v4-native-package-testing.md)**: Clean-guest lifecycle verification for native Rust package recipes (`scripts/v4_native_package_guest_drills.py`).
