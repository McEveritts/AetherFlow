# Dashboard Screenshot & Annotated Guide Generation (`scripts/docs/`)

Generates deterministic **1440p (`2560x1440`, `deviceScaleFactor: 1`)** screenshots of the real AetherFlow v4.0.0 Leptos/WASM dashboard in both **dark** and **light** themes (`docs/assets/screenshots/{dark,light}/*.png`), the `1280x640` social-preview crop (`docs/assets/screenshots/social-crop.png`), and **33 annotated step-by-step guide images** across 11 operator workflows (`docs/assets/guides/<guide>/<NN>-<step>.png`).

All captured data is 100% synthetic (RFC 5737 / CGNAT / ULA IPs, `*.example.com` hostnames, fictional users, deterministic SHA-256 fake keys) served via Playwright route interception against an ephemeral local static HTTP server hosting `web/dist`. No live backend, database, or real server telemetry is touched.

## Prerequisites

- Node.js 22+ with Playwright installed (`npm ci` at repo root, or `PLAYWRIGHT_MODULE_PATH` set).
- Playwright Chromium browser installed (`npx --workspace @aetherflow/e2e playwright install chromium`).
- Either a built `web/dist/` directory (`./scripts/build_wasm_frontend.sh`) **or** `gh` CLI authenticated to download the prebuilt `v4.0.0` release bundle (`aetherflow-linux-amd64.tar.gz`).
- ImageMagick (`convert`) for generating `social-crop.png` and PNG8 optimization (`oxipng` / `pngquant` are used automatically when installed).

## Full-Tab Screenshots (Dark & Light)

Captures all 16 `TabId::ALL` dashboard tabs plus the `Security & 2FA` settings subtab (17 views × 2 themes = **34 PNGs**) plus `social-crop.png`:

```bash
# Regenerate all 34 dark + light screenshots and social-crop.png
node scripts/docs/capture_screenshots.mjs

# Capture a single theme only (dark | light | both)
node scripts/docs/capture_screenshots.mjs --theme dark
node scripts/docs/capture_screenshots.mjs --theme light

# Use an already extracted web/dist bundle
node scripts/docs/capture_screenshots.mjs --dist /path/to/web/dist

# Regenerate specific tabs only
node scripts/docs/capture_screenshots.mjs --theme both --tabs overview,inbox,mediaflow,quotas

# Override release tag or output directory
node scripts/docs/capture_screenshots.mjs --release v4.0.0 --out docs/assets/screenshots
```

Output structure:
- `docs/assets/screenshots/dark/<view>.png` — 17 dark-theme views (`2560x1440`)
- `docs/assets/screenshots/light/<view>.png` — 17 light-theme views (`2560x1440`, driven by the real `aetherflow-theme = "light"` theme via `html[data-theme="light"]`)
- `docs/assets/screenshots/social-crop.png` — `1280x640` top crop of `dark/overview.png`

Valid `<view>` names:
`overview`, `inbox`, `services`, `marketplace`, `mcbrowser`, `fileshare`, `streaming`, `mediaflow`, `flowai`, `network`, `cluster`, `users`, `audit`, `settings`, `notifications`, `quotas`, `security`.

## Annotated Step-by-Step Guide Screenshots

Drives real multi-step workflows (opening modals, pasting pairing strings, generating client WireGuard keypairs, enrolling TOTP authenticators, editing TOML configs in McBrowser, switching to remote peers), injects a non-destructive SVG/HTML callout overlay (subtle dark dimming mask, 3px indigo-to-fuchsia highlight rings, numbered circular badges, and short connector arrows), crops to the relevant UI context, and optimizes each PNG below 600 KiB:

```bash
# Regenerate all 33 annotated guide images (11 guides)
node scripts/docs/capture_guides.mjs

# Or invoke through capture_screenshots.mjs --guides
node scripts/docs/capture_screenshots.mjs --guides

# Use an already extracted web/dist bundle
node scripts/docs/capture_guides.mjs --dist /path/to/web/dist

# Regenerate specific guides or individual steps
node scripts/docs/capture_guides.mjs --guides quickstart,marketplace
node scripts/docs/capture_guides.mjs --guides peer-pairing/02-open-window,network/02-wireguard-qr
```

Included guides (33 steps total):
1. `quickstart` (`01-sign-in`, `02-overview-tour`, `03-marketplace-install`)
2. `marketplace` (`01-find-app`, `02-install`, `03-progress`, `04-update`, `05-external-access`)
3. `peer-pairing` (`01-allow-server`, `02-open-window`, `03-pair-with-server`, `04-verify-codes`, `05-linked`)
4. `peer-grants` (`01-grants-editor`, `02-manage-server`, `03-identity-bar`)
5. `peer-storage` (`01-share-folder`, `02-transcode`)
6. `self-update` (`01-system-updates`, `02-progress`)
7. `flowai` (`01-providers`, `02-ask`, `03-proposal`, `04-approve`)
8. `mcbrowser` (`01-upload`, `02-share`, `03-edit`)
9. `network` (`01-wireguard-add-peer`, `02-wireguard-qr`, `03-tailscale`)
10. `security` (`01-enable-2fa`, `02-sessions`)
11. `backups` (`01-backups`)

## Notes

- `scripts/docs/` is intentionally outside Playwright's CI `testDir` (`e2e/tests/e2e`) so documentation capture scripts never run during CI test suites.
- Every run closes Chromium, shuts down its ephemeral loopback HTTP server, and removes any temporary release extraction directory automatically.
