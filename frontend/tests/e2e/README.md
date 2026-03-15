# Playwright Suite

Functional coverage:
- `login.spec.ts`: initial setup and standard local login
- `navigation.spec.ts`: dashboard tab navigation
- `marketplace.install.spec.ts`: install-loop regression for marketplace cards and toast flow

Visual coverage:
- `visual.spec.ts`: glassmorphism regression snapshots for the login shell and marketplace grid
- Projects in `playwright.config.ts` include Chromium, Firefox, and WebKit plus 2x device-scale-factor runs to catch high-DPI blur and border drift

Usage:
- `npm run test:e2e`
- `npm run test:e2e:update`

Notes:
- Tests mock the Go API and disable the live WebSocket path with `window.__AF_DISABLE_WS__` so rendering stays deterministic.
- Generate or refresh visual baselines with `npm run test:e2e:update` before using the visual suite in CI.
