# Playwright E2E Suite

Browser verification for the Leptos Rust WebAssembly dashboard (`frontend-rs/`) served by the pure-Rust `aetherflow-api` control plane.

## Test Suites

- **Live E2E**:
  - `embedded.live.spec.ts`: Exercises the live Rust API against a disposable SQLite database (authentication, persistence, McBrowser operations, standalone WASM worker SHA-256 hashing of `'abc'` via `Sha256ChunkTransfer`, cross-tab account-switch upload cancellation on an injected `403 CSRF_INVALID`, and live service-worker cache-boundary checks).
- **Deterministic API-Fixture Functional Specs**:
  - `login.spec.ts`: Initial setup and local login flows.
  - `navigation.spec.ts`: Dashboard tab navigation.
  - `marketplace.install.spec.ts`: Install-loop regression for Marketplace cards and toast notifications.
- **Visual Regression Suite**:
  - `visual.spec.ts`: Obsidian V2 glassmorphism snapshot checks (`@visual`) for the login shell and Marketplace grid.

## Browser Matrix

`e2e/playwright.config.ts` defines three projects:

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

# Default: runs only embedded.live.spec.ts (E2E_PLAYWRIGHT_SPECS defaults via :- to [.]live[.]spec[.]ts$)
bash scripts/run_embedded_e2e.sh \
  --binary /path/to/release/aetherflow-api \
  --static-dir /path/to/release/web/dist \
  --port 18080 --playwright

# Run all 5 specs (pass a non-empty filter/path relative to e2e/; empty "" falls back to [.]live[.]spec[.]ts$)
E2E_PLAYWRIGHT_SPECS="tests/e2e" bash scripts/run_embedded_e2e.sh \
  --binary /path/to/release/aetherflow-api \
  --static-dir /path/to/release/web/dist \
  --port 18080 --playwright
```

### Direct Playwright & npm Scripts Inside `e2e/`

With an isolated Rust API already serving `web/dist` (note: `npm run test:e2e` includes `embedded.live.spec.ts`, which requires harness-injected environment variables from `scripts/run_embedded_e2e.sh --playwright`; against a standalone server, invoke the fixture-backed specs explicitly):

```bash
cd e2e
PLAYWRIGHT_BASE_URL=http://127.0.0.1:18080 npx playwright test \
  tests/e2e/login.spec.ts tests/e2e/navigation.spec.ts tests/e2e/marketplace.install.spec.ts
PLAYWRIGHT_BASE_URL=http://127.0.0.1:18080 npm run test:e2e:visual
PLAYWRIGHT_BASE_URL=http://127.0.0.1:18080 npm run test:e2e:update
npm run typecheck
```

## Notes

- Fixture-based specs (`login.spec.ts`, `navigation.spec.ts`, `marketplace.install.spec.ts`, `visual.spec.ts`) intercept API routes in Playwright and set `window.__AF_DISABLE_WS__` (with service workers blocked) so rendering stays deterministic. `embedded.live.spec.ts` exercises the live Rust API without general API mocking, using targeted `page.route` fault injection only for the cross-tab `403 CSRF_INVALID` upload-cancellation test (and `route.continue()` delays for concurrency timing).
- Refresh Chromium visual baselines with `npm run test:e2e:update` inside `e2e/` before updating visual expectations in CI.
