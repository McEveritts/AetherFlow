# Playwright E2E Suite

Browser verification for the 4-crate Leptos Rust WebAssembly dashboard (`frontend-rs/`) served by the pure-Rust `aetherflow-api` control plane (`web/dist/`).

## Test Suites (39 Specs Total)

`e2e/tests/e2e/` contains **39** Playwright spec files split into live API integration specs and deterministic fixture-backed/visual/accessibility specs:

- **Live E2E (`8` `*.live.spec.ts` specs)**:
  - `embedded.live.spec.ts`: Core end-to-end verification against a live `aetherflow-api` and disposable SQLite database (authentication, persistence, McBrowser operations, standalone WASM worker SHA-256 hashing of `'abc'` via `Sha256ChunkTransfer`, cross-tab account-switch upload cancellation on injected `403 CSRF_INVALID`, and live service-worker cache-boundary checks).
  - `wasm.body.live.spec.ts`, `wasm.cache.live.spec.ts`, `wasm.custom-resources-body.live.spec.ts`, `wasm.persistence.live.spec.ts`, `wasm.share-body.live.spec.ts`, `wasm.upload.live.spec.ts`, `wasm.worker.live.spec.ts`: Focused live-backend suites covering HTTP body streaming, service-worker caching, custom resources, persistence, share links, resumable uploads, and dedicated WASM workers.
- **Deterministic API-Fixture Functional, Parity & Accessibility Specs (`30` specs)**:
  - **Core & Auth**: `core.spec.ts`, `login.spec.ts`, `oauth.spec.ts`, `navigation.spec.ts`, `websocket.spec.ts`, `wasm.navigation.spec.ts`, `wasm.session.spec.ts`, `wasm.recovery.spec.ts`, `wasm.users.spec.ts`.
  - **Peer Clustering & Server Switching**: `wasm.cluster.spec.ts` (pairing, grants, NFSv4.2 storage, distributed Jellyfin transcoding) and `wasm.peer-switching.spec.ts` (active-server switcher, `SERVER_EPOCH`/`AreaFence`, scoped proxy requests).
  - **Dashboard Tabs, Parity & Accessibility**: `marketplace.install.spec.ts`, `wasm.a11y.spec.ts` (`axe-core` accessibility & keyboard-focus checks), `wasm.overview.spec.ts`, `wasm.operator-parity.spec.ts`, `wasm.parity.spec.ts`, `wasm.mcbrowser-parity.spec.ts`, `wasm.display.spec.ts`, `wasm.history.spec.ts`, `wasm.portability.spec.ts`, `wasm.notifications.spec.ts`, `wasm.oidc-device-inbox.spec.ts`, `wasm.quotas.spec.ts`, `wasm.resources.spec.ts`, `wasm.custom-resources.spec.ts`, `wasm.settings.spec.ts`, `wasm.share.spec.ts`, `wasm.telemetry.spec.ts`, `wasm.worker.spec.ts`, `wasm.workflows.spec.ts`.
- **Visual Regression Suite (`1` spec)**:
  - `visual.spec.ts`: Chromium screenshot baseline checks (`@visual`) for the login shell and Marketplace grid.

## Browser Matrix

`e2e/playwright.config.ts` defines three projects (sharded in `.github/workflows/ci.yml`):

- **`chromium`**: Runs all functional specs and `visual.spec.ts` screenshot baselines.
- **`firefox`**: Runs functional specs (`visual.spec.ts` ignored).
- **`webkit`**: Runs functional specs (`visual.spec.ts` ignored).

## Running the Suite

`e2e/playwright.config.ts` requires `PLAYWRIGHT_BASE_URL` pointing to a running `aetherflow-api` serving a staged `web/dist` bundle (there is no Node.js dev server).

### Recommended: Automated Isolated Rust API + Playwright Runner

From the repository root:

```bash
npm ci
(cd e2e && npx playwright install --with-deps chromium firefox webkit)

# Default: runs the 8 *.live.spec.ts specs (E2E_PLAYWRIGHT_SPECS defaults via :- to [.]live[.]spec[.]ts$)
bash scripts/run_embedded_e2e.sh \
  --binary /path/to/release/aetherflow-api \
  --static-dir /path/to/release/web/dist \
  --port 18080 --playwright

# Run all 39 specs (pass a non-empty filter/path relative to e2e/; empty "" falls back to [.]live[.]spec[.]ts$)
E2E_PLAYWRIGHT_SPECS="tests/e2e" bash scripts/run_embedded_e2e.sh \
  --binary /path/to/release/aetherflow-api \
  --static-dir /path/to/release/web/dist \
  --port 18080 --playwright

# Run targeted fixture specs (for example Peer Clustering, server switching, and accessibility)
E2E_PLAYWRIGHT_SPECS="tests/e2e/wasm.cluster.spec.ts tests/e2e/wasm.peer-switching.spec.ts tests/e2e/wasm.a11y.spec.ts" \
bash scripts/run_embedded_e2e.sh \
  --binary /path/to/release/aetherflow-api \
  --static-dir /path/to/release/web/dist \
  --port 18080 --playwright
```

### Direct Playwright & npm Scripts Inside `e2e/`

With an isolated Rust API already serving `web/dist` (note: `npm run test:e2e` includes `*.live.spec.ts`, which require harness-injected environment variables from `scripts/run_embedded_e2e.sh --playwright`; against a standalone server, invoke fixture-backed specs explicitly):

```bash
cd e2e
PLAYWRIGHT_BASE_URL=http://127.0.0.1:18080 npx playwright test \
  tests/e2e/login.spec.ts tests/e2e/navigation.spec.ts tests/e2e/wasm.cluster.spec.ts tests/e2e/wasm.a11y.spec.ts
PLAYWRIGHT_BASE_URL=http://127.0.0.1:18080 npm run test:e2e:visual
PLAYWRIGHT_BASE_URL=http://127.0.0.1:18080 npm run test:e2e:update
npm run typecheck
```

## Notes

- Fixture-backed specs intercept API routes via `e2e/tests/e2e/support/mockAetherFlow.ts` and block service workers (`serviceWorkers: 'block'` in `e2e/playwright.config.ts`) so rendering stays deterministic. The `*.live.spec.ts` suites exercise the live Rust API without general API mocking, using targeted `page.route` fault injection only for specific fault-tolerance tests (such as cross-tab `403 CSRF_INVALID` upload cancellation) and enabling service workers explicitly in `wasm.cache.live.spec.ts`.
- Refresh Chromium visual baselines with `npm run test:e2e:update` inside `e2e/` before updating visual expectations in CI.
