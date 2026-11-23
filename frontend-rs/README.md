# AetherFlow WASM Frontend

The production dashboard uses Rust and Leptos. Trunk builds the application and its dedicated WASM workers; Tailwind produces the stylesheet. The Playwright browser test harness lives in `e2e/`. CI and release builds use `frontend-rs/` (`cargo test --manifest-path frontend-rs/Cargo.toml --workspace --locked` and `bash scripts/build_wasm_frontend.sh --stage`) for the dashboard. The separate marketing site remains in `apps/website/`.

## Workspace Crates

| Crate | Responsibility |
| :--- | :--- |
| `af-web-app` | Application shell, authentication, public routes, and sixteen dashboard tabs. |
| `af-web-core` | API and WebSocket policies, locale catalogs, drafts, and shared algorithms. |
| `af-web-ui` | Accessible controls, tables, editor, charts, and topology views. |
| `af-web-worker` | Background search, sorting, hashing, and upload work. |

## Build and Verification

Run commands from the repository root:

```bash
bash scripts/install_wasm_build_tools.sh --ensure
cargo fmt --manifest-path frontend-rs/Cargo.toml --all -- --check
cargo test --manifest-path frontend-rs/Cargo.toml --workspace --locked
cargo clippy --manifest-path frontend-rs/Cargo.toml --workspace --all-targets --locked -- -D warnings
cargo clippy --manifest-path frontend-rs/Cargo.toml --workspace --target wasm32-unknown-unknown --locked -- -D warnings
bash scripts/build_wasm_frontend.sh --stage
```

`scripts/install_wasm_build_tools.sh` verifies pinned tool downloads and installs the `wasm32-unknown-unknown` target. During `scripts/build_wasm_frontend.sh`, `scripts/finalize_wasm_assets.py` externalizes bootstrap JavaScript, validates integrity references, strips development metadata, and publishes lazy locale catalogs, while `cargo run --manifest-path frontend-rs/Cargo.toml --release --locked -p af-web-core --example compress-assets` generates the Brotli (`.br`) sidecars for `.wasm`, `.js`, `.css`, `.json`, and `.svg` assets. Generated assets live in `frontend-rs/dist/`; `--stage` publishes the runtime bundle to `web/dist/`.

## Release Artifact Layout

The packaged release layout keeps the UI assets separate from the API and companion binaries (`scripts/build_gold.sh`, `.github/workflows/release.yml`):

```text
release/
  aetherflow-api
  .version
  bin/
    af
    speedtest-backend
  config/
  deploy/
  packages/
  plugins/
    telemetry-inspector/
  web/dist/
    index.html
    af-web-app-<hash>.js
    af-web-app_bg-<hash>.wasm
    ... workers, styles, locales, icons, and .br sidecars
```

`aetherflow-api` reads `web/dist` beside its executable by default. Set `STATIC_DIR` to an explicit asset directory for development or a separately managed bundle; an invalid override returns an unavailable-frontend response rather than falling back to another directory. Backend compilation and API unit tests do not require a built frontend.

## Embedded Local E2E Harness

For a local API executable, set `STATIC_DIR="$PWD/frontend-rs/dist"` with your standard API environment. To test a packaged release layout in isolated temporary state:

```bash
bash scripts/run_embedded_e2e.sh \
  --binary /path/to/release/aetherflow-api \
  --static-dir /path/to/release/web/dist \
  --port 18080 --playwright
```

`scripts/run_embedded_e2e.sh` retains its historical filename and unconditionally keeps the privileged runner disabled (`--with-runner` exits with code `2`). By default, `--playwright` sets `E2E_PLAYWRIGHT_SPECS` to `[.]live[.]spec[.]ts$`, running only `e2e/tests/e2e/embedded.live.spec.ts` against a disposable SQLite database; pass a non-empty override (for example `E2E_PLAYWRIGHT_SPECS="tests/e2e"` or `E2E_PLAYWRIGHT_SPECS="[.]spec[.]ts$"`, since Bash `${VAR:-default}` treats `""` as unset) to run the fixture-backed and visual specs (`login.spec.ts`, `navigation.spec.ts`, `marketplace.install.spec.ts`, and `visual.spec.ts`). See [`docs/testing.md`](../docs/testing.md) for the full verification boundary.

## Reproducibility

To compare two clean builds, run the verifier with the pinned Rust compiler and WASM tools using a **nonexistent** canonical build path outside the checkout (the script rejects any pre-existing directory, including an empty one, and any pre-existing `<canonical>.cargo-home`):

```bash
python3 scripts/verify_wasm_reproducibility.py \
  --canonical-path "$HOME/.cache/af-repro/workspace" \
  --output "$HOME/.cache/af-repro/run-001"
```

The verifier retains both complete outputs and logs, isolates Cargo's dependency cache, and compares every asset and compression sidecar by building fresh source and target trees sequentially at the same absolute path. Equality holds for the recorded host, toolchain, libraries, and canonical path; separate checkout paths can produce different WASM bytes despite path remapping. Reuse the same `--canonical-path` across runs and supply a fresh `--output` directory each time.
