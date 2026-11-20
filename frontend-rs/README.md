# AetherFlow WASM frontend

The production dashboard uses Rust and Leptos. Trunk builds the application and its dedicated WASM workers; Tailwind produces the stylesheet. The Playwright browser test harness lives in `e2e/`. CI and release builds use `frontend-rs/` (`cargo test --manifest-path frontend-rs/Cargo.toml --workspace --locked` and `bash scripts/build_wasm_frontend.sh --stage`) for the dashboard. The separate marketing site remains in `apps/website/`.

| Crate | Responsibility |
| --- | --- |
| `af-web-app` | Application shell, authentication, public routes, and sixteen dashboard tabs. |
| `af-web-core` | API and WebSocket policies, locale catalogs, drafts, and shared algorithms. |
| `af-web-ui` | Accessible controls, tables, editor, charts, and topology views. |
| `af-web-worker` | Background search, sorting, hashing, and upload work. |

Run commands from the repository root:

```sh
bash scripts/install_wasm_build_tools.sh --ensure
cargo fmt --manifest-path frontend-rs/Cargo.toml --all -- --check
cargo test --manifest-path frontend-rs/Cargo.toml --workspace --locked
cargo clippy --manifest-path frontend-rs/Cargo.toml --workspace --all-targets --locked -- -D warnings
cargo clippy --manifest-path frontend-rs/Cargo.toml --workspace --target wasm32-unknown-unknown --locked -- -D warnings
bash scripts/build_wasm_frontend.sh --stage
```

The installer verifies pinned tool downloads and installs the `wasm32-unknown-unknown` target. The build finalizer externalizes bootstrap JavaScript, checks integrity references, strips development metadata, publishes lazy locale catalogs, and creates compressed sidecars. Generated assets live in `frontend-rs/dist/`; staging publishes the runtime bundle to `web/dist/`.

The release layout keeps the UI separate from the API executable:

```text
release/
  aetherflow-api
  af
  web/dist/
    index.html
    af-web-app-<hash>.js
    af-web-app_bg-<hash>.wasm
    ... workers, styles, locales, icons, and compressed sidecars
```

The API reads `web/dist` beside its executable by default. Set `STATIC_DIR` to an explicit asset directory for development or a separately managed bundle. An invalid override produces an unavailable-frontend response; it does not select another bundle. Backend compilation and API tests do not need a frontend build.

For a local API executable, use `STATIC_DIR="$PWD/frontend-rs/dist"` with the usual API configuration. To test the packaged application in isolated temporary state:

```sh
bash scripts/run_embedded_e2e.sh \
  --binary /path/to/release/aetherflow-api \
  --static-dir /path/to/release/web/dist \
  --port 18080 --playwright
```

The harness retains its historical filename. Its default mode does not start the privileged runner. Live browser tests exercise the actual API and a disposable SQLite database; the parity and visual suites use deterministic API fixtures while running the real WASM interface. See [testing.md](../docs/testing.md) for the verification boundary.

To compare two clean builds, use the pinned Rust compiler and WASM tools with an empty build path outside the checkout:

```sh
python3 scripts/verify_wasm_reproducibility.py \
  --canonical-path "$HOME/.cache/af-repro/workspace" \
  --output "$HOME/.cache/af-repro/run-001"
```

The verifier retains both complete outputs and logs, isolates Cargo's dependency cache, and compares every asset and compression sidecar. It builds fresh source and target trees in sequence at the same absolute path. Equality applies to the recorded host, toolchain, libraries, and paths; separate checkout paths have produced different application WASM despite path remapping. Use the same canonical path for later runs and a new output directory each time.
