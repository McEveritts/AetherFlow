# AetherFlow Unified Flat Surface & Control System

*   **Author:** Donovan Everitt
*   **Status:** In Review
*   **Date:** 2026-11-25

--------------------------------------------------------------------------------

## Overview

AetherFlow is a self-hosted server management platform whose web interface is built as a Rust WebAssembly (WASM) single-page application covering 16 authenticated dashboard tabs and 4 standalone routes (login, public file sharing, OAuth consent, and OAuth device verification). Today, that interface splits across two incompatible visual languages on the same screens: the top section of the System Pulse overview page uses flat, borderless bands separated by thin 1-pixel dividers, while the rest of the application wraps panels, dialogs, popovers, and controls in translucent, blurred chromatic glass boxes inherited from the earlier Obsidian V2 theme.

This design replaces Obsidian V2 chromatic glass across the entire web application with one unified, dark- and light-theme-aware flat surface and control system. Inline pages use two complementary visual tiers—borderless hairline canvas bands for headers, disclosures, and metric strips, paired with quiet flat matte cards for grouped sections, charts, forms, and peer tiles—while floating overlays (modals, drawers, header popovers, and toast notifications) and persistent shell navigation chrome use solid opaque surfaces. All interactive controls flatten to match, card hover lift and legacy atmosphere effects (aurora background and tactile grain) are retired cleanly, and automated continuous integration (CI) checks prevent chromatic glass, blur, or unthemed styling from returning.

## The Problem

AetherFlow's current styling creates four concrete user and engineering failures:

1. **Visual clash and chrome clutter across tabs**: On System Pulse, borderless flat telemetry columns sit directly above glowing cyan-indigo-fuchsia glass cards for Live Telemetry, Storage Partitions, and GPU Accelerators. Across all 16 tabs and 4 standalone routes, 75 card-component sections plus 16 direct glass containers compete for visual attention with blurred backgrounds, masked rainbow edge rings, heavy drop shadows, and hover lift animations—including on static read-only sections and touch scroll gestures where cards shrink when tapped.
2. **Broken floating overlays and hidden blur leaks**: Floating popovers and toasts reuse the same card class as inline panels without guaranteed opaque backgrounds, and coarse-pointer (touchscreen) stylesheets re-inject backdrop blur even if base card blur is removed. Persistent chrome bars (sidebar, header, mobile dock, and sticky table headers) also apply backdrop blur over live-updating telemetry charts, causing avoidable compositing work on high-refresh displays and software renderers.
3. **Broken light theme and contrast regressions**: Flat hairline surfaces hardcode translucent white borders that disappear on light backgrounds. Light mode relies on patchy, duplicated override blocks and dark-to-light Tailwind utility inversions that omit active classes—leaving dark-on-dark payload previews in the approval inbox, low-contrast degraded server banners, grayed-out destructive buttons in Cluster management, and sub-3:1 input borders. Meanwhile, the Settings atmosphere controls (`Aurora opacity`, `Aurora animation`, and `Tactile grain`) are silent no-ops in light mode, and clicking reset forcibly switches light-mode users back to dark mode.
4. **No enforceable design boundary in CI**: Legacy glass classes (`.glass-card`, `.glass-button`, `.glass-input`) remain the default vocabulary in templates, obsolete glass rules remain in the stylesheet to be copy-pasted, and the existing static design-contract test suite checks for Obsidian V2 glass tokens rather than flat invariants—and is not run in GitHub Actions CI.

## Goals

*   **Unified zero-glass surface system**: Establish a strict 2+1 flat surface hierarchy—Tier 1 Borderless Hairline Canvas, Tier 2 Quiet Flat Card, and Tier 3 Crisp Opaque Overlays plus opaque persistent shell chrome—across all 16 authenticated tabs, all 4 standalone routes (`/login`, `/share`, `/oauth/consent`, `/oauth/device`), and the application brand mark, with zero chromatic glass rims and zero CSS `backdrop-filter` blur anywhere in desktop, mobile, or touch viewports.
*   **Cohesive flat interactive controls**: Flatten buttons (primary, secondary, destructive, success, disabled, and focus-visible states), text inputs, checkboxes, tab pills, and active sidebar indicators so controls match the matte surface hierarchy without gradients, specular borders, glow shadows, hover scale jumps, or `pointer-events: none` hiding permission-block tooltips on disabled actions.
*   **Semantic `.af-*` naming via safe staged migration**: Rename legacy `.glass-*` and `.obs-tab-pill` classes to semantic `.af-*` flat identifiers across bounded, buildable commits using temporary flat CSS aliases that are deleted on the final commit, coordinating Tier 3 overlay classes (`.af-modal`, `.af-popover`, `.af-toast`, `.af-toast-error`) directly with the in-flight overlay fix branch (`fix/overlay-glass-effect`).
*   **Complete dark and light theme parity (WCAG AA)**: Replace hardcoded dark borders, inverted literal color names, and patchy `.light` override blocks with one polarity-scoped semantic token contract (`:root` dark and `html[data-theme="light"]`) meeting WCAG 2.1 AA contrast (`>= 4.5:1` normal text, `>= 3:1` UI control boundaries and focus rings) across all 16 tabs, all 4 standalone routes, and the self-contained light/dark code editor (`McBrowserCodeEditor`), while keeping mobile and touch-mode targets `>= 44px` and keeping `<meta name="theme-color">` synchronized with the active theme.
*   **Clean retirement of card hover lift and legacy atmosphere effects**: Remove `Card hover lift`, touch card-press scaling, `Aurora opacity`, `Aurora animation`, and `Tactile grain` across CSS, application state, cross-tab storage synchronization, Settings UI, and all 6 localization catalogs (`en`, `de`, `dk`, `es`, `fr`, `zh`) while passively tolerating pre-existing browser `localStorage` entries during upgrades and rollbacks.
*   **Incremental CI drift prevention**: Publish a canonical surface taxonomy guide (`docs/design-system.md`) and enforce flat-design invariants starting in Commit 1 via a ratcheted Rust static contract test inside `cargo test --workspace` (executed by GitHub Actions CI), Playwright computed-style assertions across dark, light, and coarse-pointer viewports, and updated 4-tier static contract tests—locking to zero `.glass-*` classes and zero `backdrop-filter` rules on the final commit.

## Non-Goals

*   Changing backend REST APIs, WebSocket telemetry payloads, authentication flows, or Rust server logic in `backend-rs` (existing Content Security Policy `style-src 'self'` and immutable `compiled-<hash>.css` caching headers remain unchanged).
*   Redesigning page information architecture, tab navigation structure, charting libraries, or feature workflows inside individual tabs.
*   Renaming `frontend-rs/styles/input.css` or its generated output `frontend-rs/styles/compiled.css`, which are bound to the Trunk build pipeline and service-worker immutable cache rules.
*   Wiping or mutating unrelated user preferences stored in browser `localStorage` on upgrade.
*   Introducing third-party CSS linter toolchains (such as Stylelint) when Rust workspace tests and Playwright already run in CI.

## Open Questions

*   **Documentation screenshot refresh timing**: Regenerating the 67+ dark/light README screenshots and annotated operator-guide captures (`scripts/docs/capture_screenshots.mjs` and `scripts/docs/capture_guides.mjs`) produces large binary diffs. Should screenshot regeneration ship as the final commit in the implementation pull request or in an immediate follow-up documentation pull request?

## Critical User Journeys (CUJs)

### CUJ 1: Switching Between Dark and Light Themes Across Dashboard Tabs and Standalone Routes

*   **Given**: An operator is signed into AetherFlow (or viewing `/login`, `/share`, `/oauth/consent`, or `/oauth/device`) on either a desktop viewport (`1440px`) or a mobile viewport (`390px`), with tabs containing hairline telemetry strips, flat cards, nested detail rows, destructive actions, and badges.
*   **When**: The operator toggles between Dark and Light themes in the shell or Settings.
*   **Then**: Every Tier 1 hairline divider, Tier 2 flat card, Tier 3 opaque overlay, button tone (including destructive Cluster actions), input border, scrollbar, and browser `theme-color` metadata switches immediately via semantic tokens with zero unreadable dark-on-dark surfaces, zero invisible white-on-white hairlines, zero `backdrop-filter` blur, and zero WCAG AA accessibility violations.

### CUJ 2: Opening Floating Overlays and Independent Code-Editor Themes Over Live Content

*   **Given**: An operator is scrolling a dense data table, live telemetry chart, or file directory in either Dark or Light theme.
*   **When**: The operator opens a modal dialog, side drawer, header transfers popover, header account menu, toast notification, or switches the McBrowser code editor to the opposite light/dark polarity (`data-editor-tone`).
*   **Then**: Every floating overlay renders with an opaque background, crisp neutral border, zero chromatic rim, and zero hover/tap translucency or shift; the code editor switches toolbar buttons, inputs, and code panes instantly without mid-transition contrast drops, preserving `>= 4.5:1` contrast in both cross-polarity combinations.

### CUJ 3: Upgrading an Existing Browser Profile with Legacy Atmosphere and Card-Lift Preferences

*   **Given**: A returning user's browser `localStorage` contains legacy Obsidian V2 keys (`aetherflow-card-lift="-6"`, `aetherflow-aurora-opacity="0.85"`, `aetherflow-aurora-animation="true"`, `aetherflow-grain-display="false"`, and `aetherflow-system-storage` JSON containing `cardLift`, `auroraOpacity`, `auroraAnimation`, and `grainDisplay`) alongside active preferences (`theme`, `language`, `highRefreshMode`, `touchMode`, `reducedMotion`).
*   **When**: The user loads the upgraded flat AetherFlow application, inspects Settings, changes an unrelated display setting, and reloads the page.
*   **Then**: All surviving preferences hydrate without error, `<html>` emits no `data-card-lift`, `data-aurora-opacity`, `data-aurora-animation`, or `data-grain` attributes and no inline `style` attribute, retired controls are absent from Settings across all 6 locales, cards show zero hover lift or touch-press shrink, and untouched legacy storage fields do not cause crashes if rolled back.

### CUJ 4: Blocking Surface Drift in Continuous Integration

*   **Given**: A contributor or automated agent opens a pull request that introduces a Tailwind `backdrop-blur` class in Rust markup, a CSS `backdrop-filter` or chromatic gradient rim in `input.css`, a legacy `.glass-*` class after the final ratchet lock, or a new dark-only semantic token missing its light-theme counterpart.
*   **When**: Automated CI runs `cargo test --workspace` and the Playwright embedded-contracts suite across dark, light, and coarse-pointer profiles.
*   **Then**: The build fails deterministically with a diagnostic naming the violated design rule, the offending file and line or token, and the canonical `.af-*` surface class or token to use instead.

## Technical Plan (Architecture)

### 1. Polarity-Scoped Semantic Token Architecture & Tailwind v4 Layering

Instead of duplicating per-component light-mode overrides (`.light .glass-card`, `.light .glass-button`) and inverting literal color tokens (`--obs-white` redefined to dark navy), all visual styling is split into two layers inside `frontend-rs/styles/input.css`:

1. **Immutable Palette Primitives**: Raw brand and status color stops that never invert across themes.
2. **Semantic Role Tokens (`--af-*`)**: Surface fills (`--af-bg-canvas`, `--af-bg-chrome`, `--af-surface-card`, `--af-surface-card-hover`, `--af-surface-inset`, `--af-surface-overlay`), borders (`--af-border-hairline`, `--af-border-card`, `--af-border-control`, `--af-border-overlay`), text roles (`--af-fg-primary`, `--af-fg-secondary`, `--af-fg-muted`, `--af-fg-on-accent`), interactive control states (`--af-control-bg`, `--af-control-bg-hover`, `--af-control-disabled-bg`, `--af-control-disabled-fg`, `--af-accent-bg`, `--af-accent-bg-hover`, `--af-danger-*`, `--af-success-*`, `--af-tab-active-*`, `--af-nav-active-*`), focus rings (`--af-focus-ring`), and neutral overlay elevation (`--af-shadow-overlay`, `--af-backdrop-scrim`).

Every component class is written **once** against `--af-*` tokens inside Tailwind v4's `@layer components` block. Polarity switches solely by swapping the `--af-*` token table at three bounded scopes:
* `:root` (default dark theme, paired with `data-theme="dark"` on `index.html` for consistent first paint).
* `html[data-theme="light"]` (canonical light theme selector; legacy `.light` component overrides are retired, and `apply_theme_dom` also synchronizes `<meta name="theme-color">`).
* `.af-editor[data-editor-tone="light"|"dark"]` (scoped semantic control token overrides for `McBrowserCodeEditor`, preserving opaque `rgb(...)` backgrounds and instant zero-transition polarity switches required by `wasm.mcbrowser-parity.spec.ts`).

Semantic surface, hairline, and text tokens are also exposed through Tailwind v4's `@theme inline` block so Rust views can compose standard utility spacing and semantic borders (`border-hairline`, `bg-surface-inset`) without dark-only `border-white/10` or `bg-slate-950/80` hacks. Placing all surface and control base rules inside `@layer components` eliminates the current CSS cascade bug where unlayered component styles silently override Tailwind `@layer utilities` modifiers.

```text
  +-------------------------------------------------------------------------+
  |              frontend-rs/styles/input.css (Single Source)               |
  |                                                                         |
  |  1. @theme inline  ---> exposes semantic utilities to Tailwind v4       |
  |  2. Token Tables   ---> :root (dark) | html[data-theme="light"]         |
  |                         .af-editor[data-editor-tone="light"|"dark"]     |
  |  3. @layer components                                                   |
  |     +-- Tier 1 Canvas:  .af-canvas-section, .af-hairline-grid           |
  |     +-- Tier 2 Card:    .af-card, .af-card-interactive, .af-surface-inset
  |     +-- Tier 3 Overlay: .af-modal, .af-popover, .af-toast, .af-toast-err|
  |     +-- Shell Chrome:   .af-sidebar, .af-header, .af-mobile-dock, thead |
  |     +-- Flat Controls:  .af-btn*, .af-input, .obs-checkbox, .af-tab-pill|
  |     +-- [Commits 1-4]   Temporary flat .glass-* selector aliases        |
  +-----------------------------------+-------------------------------------+
                                      |
                         Trunk pre_build (Tailwind v4.3.5)
                                      v
  +-------------------------------------------------------------------------+
  |          frontend-rs/styles/compiled.css -> compiled-<hash>.css         |
  |  Served immutable (sw.js + embed.rs); zero inline styles (CSP 'self')   |
  +-----------------------------------+-------------------------------------+
                                      |
            +-------------------------+-------------------------+
            v                                                   v
  +-------------------------+                     +-------------------------+
  | Static CI Drift Gate    |                     | Runtime CI E2E Gate     |
  | (cargo test --workspace)|                     | (Playwright 3-browser)  |
  | - Zero backdrop-filter  |                     | - Dark/Light/Touch DOM  |
  | - Zero chromatic tokens |                     | - backdropFilter=none   |
  | - 100% dark/light token |                     | - card transform=none   |
  |   parity check          |                     | - overlay alpha=1       |
  | - Shrinking .glass-*    |                     | - axe-core WCAG AA      |
  |   ratchet -> 0 (Commit5)|                     | - Editor tone contrast  |
  +-------------------------+                     +-------------------------+
```

### 2. Surface Decision Table & Page Layout Grammar

To eliminate ad-hoc styling across 16 tabs and 4 standalone routes, every UI container maps to one explicit tier (documented permanently in `docs/design-system.md`):

| Tier / Role | Canonical Classes | Use When | Do Not Use When |
| :--- | :--- | :--- | :--- |
| **Tier 1: Borderless Hairline Canvas** | `.af-canvas-section`, `.af-hairline-grid` | Page intro headers, collapsible `<details>` disclosures, and top-level KPI / system vital strips (System Pulse vitals, Inbox summary strip, Audit summary strip). | Multi-field settings forms, dense peer-action grids, or floating popups. |
| **Tier 2: Quiet Flat Card (Static / Interactive)** | `.af-card` (via `ObsCard`), `.af-card-interactive` | Bounded work modules, historical charts, forms, peer tiles, data tables, and standalone route forms (`/login`, `/share`, `/oauth/consent`, `/oauth/device`). | Floating overlays, page headers, or nested inside another `.af-card`. |
| **Card-Interior Sub-Group** | `.af-surface-inset` or internal hairline dividers / `.af-hairline-grid` | Sub-summaries or multi-plot sub-cells inside an `.af-card` (Storage Pool Summary, Capacity Predictions, service rows, topology list items, AI Chat history rows). | Never nest `.af-card` inside `.af-card` (forbids card-in-card double-border noise). |
| **Tier 3: Crisp Opaque Overlays** | `.af-modal`, `.af-drawer`, `.af-popover`, `.af-toast`, `.af-toast-error` | Modals, slide-over drawers, header dropdown popovers, and toast alerts floating over scrolling page content. | Inline page sections; never combined with `.af-card` or `.glass-card`. |
| **Persistent Shell Chrome** | `.af-sidebar`, `.af-header`, `.af-mobile-dock`, sticky `DataGrid thead` | Fixed/sticky navigation bars and sticky table headers framing the main canvas. | Never uses `backdrop-filter` or translucent blur. |

**Container-Owned Hairline Grid (`.af-hairline-grid`)**: Replaces ~140 lines of unused/brittle `:nth-child` media-query border math (`.obs-metric-strip`, `.obs-vitals-grid`) with a single responsive CSS grid container using `overflow: clip` (preserving the F16 scroller-containment invariant with zero root `overflow-x: hidden`) and `-1px` child top/left borders. Any dynamic column count (`immersive_overview` 2-column vs. 4-column, conditional GPU panels, 2-to-4 responsive KPI strips) renders unbroken 1px interior hairlines in both themes automatically.

**Coordination with `fix/overlay-glass-effect`**: Builds directly on the sibling overlay branch's `.af-popover`, `.af-toast`, `.af-toast-error`, and opaque `.af-modal` contract and Playwright overlay hover tests. Once Commit 2 updates `Modal` in `af-web-ui/src/primitives.rs` and the Tier-1 contract `T1_F18_04`, the temporary `glass-card` class on `<dialog>` is removed so overlays share zero CSS rules with inline cards.

**Static vs. Interactive Card Affordance**: Default `.af-card` containers are strictly static—zero hover transform lift, zero border flash on hover, and zero touch `:active` scale shrink. Genuinely clickable cards/tiles (such as AI Chat provider selectors and clickable service rows) opt into `.af-card-interactive`, which provides a pointer cursor, a stepped neutral fill/border hover state, and a high-contrast `:focus-visible` ring.

### 3. Cohesive Flat Controls, Brand Mark & Accessibility

* **Buttons**: Standardize one flat control grammar across `.af-btn` (stepped neutral matte fill + `>= 3:1` control border so secondary buttons separate cleanly from flat cards in both dark and light themes), `.af-btn-primary` (solid flat indigo accent fill + `>= 4.5:1` white text, zero fuchsia gradient, zero glow shadow, zero hover scale jump), and theme-aware semantic tones (`[data-tone="danger"|"success"|"primary"]`) driven by semantic tokens so light mode never clobbers destructive Cluster buttons. Expose explicit danger styling on `Button` and `ConfirmDialog` in `af-web-ui` rather than ad-hoc utility classes.
* **Disabled Controls**: Replace blanket `opacity: 0.45; pointer-events: none;` with dedicated semantic disabled surface, border, and text tokens plus `cursor: not-allowed` so permission-block `title` tooltips remain accessible on hover.
* **Tab Pills, Segmented Filters & Navigation**: Remove `!important` from active tab pills; visually distinguish `TabsBar` tablists and segmented chart-filter groups (`.af-tab-pill` inside a crisp flat segmented track or outlined pill border so inactive buttons read as interactive controls) from cross-route navigation shortcuts in Settings (rendered as secondary links/buttons instead of tab pills). Flatten `.af-nav-active` to a clean theme-aware fill plus crisp accent indicator working in both expanded (238px) and collapsed icon-rail (84px) states.
* **Inputs, Checkboxes & Touch Targets**: Upgrade `.af-input` borders to `>= 3:1` contrast in both themes and standardize a `2px` high-contrast `:focus-visible` ring across inputs, buttons, tab panels, and `<summary>` triggers. Apply `.obs-checkbox` consistently in `DraftCheck` (`settings/forms.rs`). Delete the coarse-pointer `backdrop-filter: blur(12px)` re-injection and fix the mobile header `36px` height override so Touch Mode and coarse-pointer controls maintain `>= 44px` hit areas without violating the `<= 104px` mobile header budget (`wasm.parity.spec.ts`).
* **Brand Mark & Status Beacons**: Remove `.obs-brand-logo::before`'s blurred three-color aura and `.obs-brand-mark`'s neon drop-shadows, and flatten `.obs-beacon-*` status indicators to crisp solid dots with subtle neutral rings.

### 4. Retiring Card Hover Lift & Legacy Atmosphere State

Card hover lift (`card_lift`), background aurora (`aurora_opacity`, `aurora_animation`), and tactile grain (`grain_display`) are retired completely:

* Remove `body::before` aurora gradients, `body::after` fractal SVG noise + dark edge vignette, `@keyframes obs-aurora-shift`, the 22 quantized `html[data-aurora-opacity=*]` rules, and all `html[data-card-lift=*]` / `--obs-card-lift` rules from `input.css`.
* Remove the four signals, normalizers, setters, `data-*` root attribute writes, cross-tab `storage` event handlers (`session.rs`), and the Settings `Atmosphere` UI block (`settings/mod.rs`), replacing any remaining reset button with a scoped display reset that never overwrites the user's selected theme.
* Update all 6 localization catalogs (`en`, `de`, `dk`, `es`, `fr`, `zh`) atomically—deleting retired keys and rewording `Settings.reducedMotionActiveHint` so reduced-motion copy no longer references card hover lift or aurora animation.
* **Passive Storage Cushioning (Upgrade & Rollback Safety)**: Stop reading or writing `aetherflow-card-lift`, `aetherflow-aurora-*`, `aetherflow-grain*`, and the corresponding fields in `aetherflow-system-storage`. Because `legacy_storage_envelope` parses `aetherflow-system-storage` as an open JSON object, returning browsers hydrate cleanly without errors, and existing dormant keys are preserved untouched so downgrading to a prior release remains safe.

### 5. Staged Multi-Commit Rename & Incremental Drift Prevention

To execute the semantic rename (`.glass-*` → `.af-*`) cleanly while bounding PR review load and avoiding merge conflicts with parallel branches, the migration runs across five buildable commits with drift prevention enforced from Commit 1:

1. **Commit 1 — Semantic Token Foundation, Flat CSS, Temporary Aliases & Phase-1 CI Ratchet**: Introduce `--af-*` dark/light tokens, `@layer components` `.af-*` surface and control classes, `.af-hairline-grid`, temporary flat `.glass-*` aliases pointing to those same rules, purge all `backdrop-filter`/chromatic/lift/aurora/grain/brand-halo rules, fix light-mode contrast gaps, and land the Rust static contract `#[test]` in `frontend-rs` (running in `ci.yml` `frontend-rs-checks`) enforcing zero `backdrop-filter`, zero chromatic/lift tokens, 100% `:root` ↔ `html[data-theme="light"]` `--af-*` token parity, and a bounded ratchet list of unmigrated `.glass-*` template files.
2. **Commit 2 — Core Primitives, Shell Chrome, Code Editor & Public Routes**: Migrate `af-web-ui` (`primitives.rs`, `grid.rs`, `editor.rs`, `topology.rs`), `shell.rs` (including header `backdrop-blur-xl` removal and overlay unification with `fix/overlay-glass-effect`), and all 4 public routes (`/login`, `/share`, `/oauth/consent`, `/oauth/device`) onto `.af-*`. Remove temporary `glass-card` from `<Modal>`, move `.af-editor[data-editor-tone]` to semantic token overrides, and shrink the CI ratchet allowlist.
3. **Commits 3–4 — Feature Tabs Migration (Two Bounded Batches)**: Migrate all 16 authenticated tabs to `.af-*`, move Inbox and Audit KPI strips to `.af-hairline-grid`, flatten card-in-card nesting (Storage Pool Summary, Capacity Predictions, Services tiles, Cluster peers, AI Chat history), replace dark-only `bg-slate-950/80` / `bg-white/[0.02]` / `border-white/15` utilities with semantic classes, and shrink the CI ratchet allowlist on each commit.
4. **Commit 5 — State & i18n Cleanup, Legacy Alias Deletion, Final Ratchet Lock & Test Suites**: Retire `card_lift` and atmosphere state across `preferences.rs`, `state.rs`, `session.rs`, `settings/mod.rs`, and all 6 catalogs; delete the temporary `.glass-*` CSS aliases completely; lock the Rust CI drift gate to **zero `.glass-*` occurrences anywhere in CSS or Rust**; update Playwright (`wasm.display.spec.ts`, `wasm.oidc-device-inbox.spec.ts`, `wasm.mcbrowser-parity.spec.ts`, `visual.spec.ts`) with dark/light/coarse-pointer flat computed-style checks; and update all 4 tiers of `tests/e2e/` static contracts without stub assertions (`T1_F37_04`).
5. **Commit 6 (or Follow-up Docs PR) — Design System Guide & Visual Captures**: Publish `docs/design-system.md` (linked from `docs/architecture.md`, `input.css`, and `af-web-ui/src/lib.rs`) and regenerate documentation screenshots and guides (`capture_screenshots.mjs`, `capture_guides.mjs`).

### 6. Architectural Risks & Mitigations

* **Cascade shifts when moving component styles into `@layer components`**: Moving `.af-card` and `.af-btn` into `@layer components` allows existing Tailwind utilities on templates (previously silently ignored) to take effect. *Mitigation*: Audit all template call sites mixing surface/button classes with Tailwind border, background, or padding utilities during Commits 2–4 and verify across `wasm.a11y.spec.ts` and `wasm.parity.spec.ts`.
* **`overflow: clip` clipping focus rings inside `.af-hairline-grid`**: Interactive elements positioned flush against a clipped grid edge can lose outer focus outlines. *Mitigation*: Apply internal cell padding (`>= 12px`) and `outline-offset: -2px` on flush interactive grid children, verified via keyboard focus inspection.
* **Merge friction with `fix/overlay-glass-effect`**: Both efforts touch `input.css`, `shell.rs`, and `wasm.parity.spec.ts`. *Mitigation*: Rebase onto or mirror `fix/overlay-glass-effect`'s `.af-popover`, `.af-toast`, `.af-toast-error`, and `.af-modal` class names directly so Commit 1–2 merges cleanly without conflicting overlay contracts.
* **Layout geometry regressions on constrained viewports**: Adjusting padding, borders, or mobile header touch targets (`>= 44px`) can break `wasm.parity.spec.ts` assertions (all 16 sidebar tabs + logout fitting inside `1024x768` without scroll; mobile header height `<= 104px` at `390x844`). *Mitigation*: Preserve existing sidebar vertical rhythm and mobile two-row header compactness while adjusting icon/control hit targets, gated by Playwright `wasm.parity.spec.ts` across all 3 browser engines.
* **Code-editor instant polarity switching**: Changing control transitions or class names inside `.af-editor` could violate `wasm.mcbrowser-parity.spec.ts`'s zero-animation and opaque-`rgb` contrast contract. *Mitigation*: Keep `transition-property` excluding `color` and `background-color` inside `.af-editor` and keep editor control fills 100% opaque in both tones.

## Alternatives Considered

### Alternative A: Three-Tier Hybrid Retaining Chromatic Glass in Select Locations

*   **Pros**: Keeps the Obsidian V2 signature glass aesthetic on standalone hero surfaces (such as `/login`) or modal overlays while flattening content tabs.
*   **Cons**: Forces every future contributor and automated agent to judge whether a new panel qualifies for chromatic glass, perpetuates `backdrop-filter` and masked `::after` rim CSS machinery, and leaves visual inconsistency between flat tabs and chromatic overlays.
*   **Reason for Rejection**: Rejected by author: chromatic glass does not fit the unified flat visual direction, and maintaining three surface languages creates recurring drift risk across tabs.

### Alternative B: Pure Borderless Hairline Canvas Everywhere (No Card Containers)

*   **Pros**: Maximum openness across all pages with only one inline container style to maintain.
*   **Cons**: Dense peer-item grids (Services, Marketplace, Inbox approvals) and multi-section Settings forms lose clear visual containment between adjacent groups and controls, particularly on wide desktop viewports.
*   **Reason for Rejection**: Rejected by author: pairing Borderless Hairline Canvas (for headers, disclosures, and vital/KPI strips) with Quiet Flat Cards (for grouped charts, forms, and peer tiles) keeps both calm visual rhythm and clear object grouping.

### Alternative C: Flattening Cards Only While Leaving Buttons, Inputs, and Navigation Controls in Chromatic Glass

*   **Pros**: Narrower CSS change limited to container classes; avoids updating button, tab-pill, and navigation selectors or `.af-editor` button overrides.
*   **Cons**: Glossy fuchsia-gradient primary buttons, blurred secondary buttons, and chromatic active sidebar tabs visibly clash against flat matte cards and hairline bands.
*   **Reason for Rejection**: Rejected by author: mismatched controls undermine visual cohesion across the application.

### Alternative D: Permanently Keeping `.glass-*` Class Names as Flat Compatibility Aliases

*   **Pros**: Limits the change to ~10 files, avoids editing 39 tab/route files and E2E selectors (`wasm.oidc-device-inbox.spec.ts`, `wasm.mcbrowser-parity.spec.ts`), and minimizes merge conflicts.
*   **Cons**: Leaves literal `glass-card`, `glass-button`, and `glass-input` identifiers in every Rust template permanently, misleading future contributors into treating flat surfaces as glass containers and weakening static drift checks to property-only bans.
*   **Reason for Rejection**: Rejected by author: permanent `glass-*` naming conflicts with a zero-glass design system. Instead, the semantic `.af-*` rename is spread across five staged, buildable commits using temporary flat aliases that are deleted on Commit 5 so review load and merge risk stay bounded while achieving clean final naming.

### Alternative E: Keeping Background Aurora and Tactile Grain (or Replacing Them with a Dual-Theme Ambiance Toggle)

*   **Pros**: Preserves an existing Settings customization block and avoids removing legacy atmosphere preferences and tests.
*   **Cons**: Both `Aurora opacity` and `Tactile grain` are currently non-functional no-ops in light mode, `body::after` bundles a dark edge vignette and SVG fractal noise that muddy 1px canvas hairlines, `reset_atmosphere_defaults` unexpectedly switches light users back to dark mode, and two full-viewport fixed compositor layers remain active unnecessarily.
*   **Reason for Rejection**: Rejected by author: decorative aurora and grain effects are unnecessary in the flat design system and add maintenance and compositor overhead without matching light or dark flat surfaces.

### Alternative F: Adding an External CSS Linter Toolchain (Stylelint) for Drift Prevention

*   **Pros**: Off-the-shelf CSS AST rule engine with rich community plugin ecosystem.
*   **Cons**: Introduces Node/Stylelint configuration, dependency updates, and a separate CI job for a workspace that compiles a single CSS input file (`frontend-rs/styles/input.css`) and cannot inspect Rust RSX templates for Tailwind `backdrop-blur` or `.glass-*` regressions.
*   **Reason for Rejection**: Rejected during Goldfish review (`egm-zoom-out`, `egm-implementation-readiness`): a lightweight Rust static contract test inside `cargo test --workspace` (already run by GitHub Actions CI) inspects both `input.css` and `crates/**/*.rs` with zero new build dependencies, complemented by Playwright computed-style assertions.

### Alternative G: Destructive `localStorage` Cleanup or Permanent `data-card-lift="0"` Tombstone

*   **Pros**: Either erases obsolete browser storage keys immediately or keeps existing `data-card-lift` attribute contracts present.
*   **Cons**: Deleting legacy keys breaks preference preservation if an operator rolls back to a prior release; keeping a permanent `data-card-lift="0"` tombstone leaves dead state plumbing in `preferences.rs`, `state.rs`, and `input.css`.
*   **Reason for Rejection**: Rejected during Goldfish review (`egm-zoom-out`, `egm-inventive-catalyst`): `legacy_storage_envelope` already parses `aetherflow-system-storage` as an open JSON object, so passively ignoring retired keys on read keeps both upgrade and rollback safe with zero migration code.

--------------------------------------------------------------------------------

## Non-Functional Requirements

*   **Security & Privacy**:
    *   Preserve strict Content Security Policy `style-src 'self'` (zero inline `style="..."` attributes on `<html>`, dialogs, or components, and zero inline `<style>`/`<script>` tags). All theme, density, touch-mode, and reduced-motion states remain driven exclusively by root `data-*` attributes and external `compiled.css` rules.
    *   Removing `body::after`'s SVG `feTurbulence` noise eliminates one embedded `data:image/svg+xml` URI from CSS; keep Markdown sanitizer regression coverage (`af-web-core/src/markdown.rs`) asserting that user-authored Markdown cannot inject `.af-card`, `.af-modal`, `.af-popover`, or `.af-toast` overlay classes.
*   **Performance & Rendering Efficiency**:
    *   Eliminating `backdrop-filter: blur(12px..24px)` across cards, controls, coarse-pointer media queries, sidebar, header, mobile dock, and `DataGrid` sticky headers—and deleting the two fixed `100vw x 100vh` `body::before`/`body::after` layers—removes continuous full-edge compositing overhead during 120Hz scrolling, software rendering, and live WebSocket telemetry updates.
    *   Retaining `styles/input.css` → `styles/compiled.css` preserves Trunk file-hashing (`compiled-<hash>.css`), 1-year immutable asset caching (`embed.rs`, `sw.js`), and automatic service-worker cache rotation via `finalize_wasm_assets.py`.
*   **Accessibility & Responsive Invariants**:
    *   Pass `axe-core` WCAG 2.0/2.1/2.2 AA scans (`wasm.a11y.spec.ts`) across all 16 tabs × Dark and Light themes × desktop (`1440px`) and mobile (`390px`), plus `>= 3:1` interactive control borders and `:focus-visible` rings, `>= 4.5:1` cross-polarity contrast with zero color/background transitions inside `.af-editor`, `>= 44px` hit areas in Touch Mode / coarse-pointer viewports, and preserved sidebar fit (`1024x768`) and mobile header height (`<= 104px` at `390x844`).
*   **Rollout & Rollback**:
    *   Each of the five commits compiles, passes `cargo test --workspace`, and renders the entire app coherently via temporary flat `.glass-*` CSS aliases until Commit 5 deletes them.
    *   Rollback to the prior release is safe because retired preference keys (`aetherflow-card-lift`, `aetherflow-aurora-*`, `aetherflow-grain*`, and matching fields in `aetherflow-system-storage`) are ignored passively without destructive deletion, and `index.html`/`sw.js` are served `no-cache` so browsers pick up rolled-back asset hashes on reload.

--------------------------------------------------------------------------------

### Additional Resources

*   [Architecture Overview](../architecture.md)
*   [Testing Guide](../testing.md)
*   [Peer Clustering Design](./peer-clustering.md)
*   [V4 Post-EGM Hardening Program](./v4-post-egm-hardening-program.md)

### Future Improvements

*   **Typed Layout Primitives**: Once the `.af-*` class foundation is stable, optionally extract shared `PageHeader`, `KpiStrip`, and `DisclosureSection` components in `af-web-ui/src/primitives.rs` to eliminate boilerplate across new tabs.
*   **Complete Removal of Legacy Tailwind Dark-Utility Shims**: As individual tabs are edited in future feature work, replace remaining raw `border-white/*`, `bg-white/*`, and `text-slate-*` utilities with Tailwind v4 semantic utilities (`border-hairline`, `bg-surface-inset`, `text-fg-muted`) until the transitional light-theme utility remap block in `input.css` shrinks to zero.

--------------------------------------------------------------------------------

## Detailed Implementation Plan

### Pre-Determined Design Specifications (Zero-Decision Contract)

#### A. Dark & Light Semantic Token Table (`frontend-rs/styles/input.css`)

All surface and control rules consume only these semantic custom properties. `--obs-bg-base` is preserved as an alias to `var(--af-bg-canvas)` for `T4_SCENARIO_01` and external consumer compatibility. Every foreground/background pair is pre-verified against WCAG 2.1 AA (`>= 4.5:1` text, `>= 3.0:1` UI boundaries and focus rings).

| Semantic Token | `:root` (Dark) | `html[data-theme="light"]` | Role / Verified Contrast |
| :--- | :--- | :--- | :--- |
| `--af-bg-canvas` | `#07090e` | `#f4f6fa` | Page canvas foundation (`meta[name="theme-color"]` syncs to this value) |
| `--af-bg-chrome` | `#090c14` | `#f8fafc` | Opaque persistent shell chrome (`.af-sidebar`, `.af-header`, `.af-mobile-dock`, `DataGrid thead`) |
| `--af-surface-card` | `#0d111a` | `#ffffff` | Tier 2 Quiet Flat Card matte fill |
| `--af-surface-card-hover` | `#121826` | `#f8fafc` | Hover fill exclusively for opt-in `.af-card-interactive` tiles |
| `--af-surface-inset` | `#0a0d15` | `#eef2f7` | Recessed sub-surface well inside `.af-card` (Storage Pool Summary, Capacity cells, payload logs) |
| `--af-surface-overlay` | `#111624` | `#ffffff` | Tier 3 100% opaque overlay fill (`.af-modal`, `.af-popover`, `.af-toast`) |
| `--af-border-hairline` | `#232d42` | `#cbd5e1` | Tier 1 canvas section rules, `.af-hairline-grid` interior dividers, chrome dividers |
| `--af-border-card` | `#232d42` | `#cfd9e6` | Tier 2 `.af-card` 1px neutral border |
| `--af-border-card-hover` | `#3b4b6b` | `#94a3b8` | Hover border exclusively for `.af-card-interactive` |
| `--af-border-overlay` | `#33415c` | `#cbd5e1` | Tier 3 crisp overlay border |
| `--af-border-control` | `#5f7191` | `#64748b` | Interactive border for `.af-btn`, `.af-input`, `.obs-checkbox` (`3.45–3.83:1` dark, `4.34–4.76:1` light) |
| `--af-border-control-hover` | `#8093b5` | `#475569` | Hover border for neutral interactive controls |
| `--af-fg-primary` | `#f1f5f9` | `#0f172a` | Primary text (`17.24:1` dark card, `17.85:1` light card) |
| `--af-fg-secondary` | `#cbd5e1` | `#334155` | Secondary labels (`12.72:1` dark, `10.35:1` light) |
| `--af-fg-muted` | `#94a3b8` | `#475569` | Muted metadata & timestamps (`7.04–7.36:1` dark, `6.74–7.58:1` light) |
| `--af-fg-on-accent` | `#ffffff` | `#ffffff` | Inverse text on solid accent buttons (never inverted) |
| `--af-control-bg` | `#151c2c` | `#f1f5f9` | Neutral secondary button fill (`.af-btn`) |
| `--af-control-bg-hover` | `#1d263b` | `#e2e8f0` | Hover fill for `.af-btn` |
| `--af-input-bg` | `#0a0e18` | `#ffffff` | Form input / select fill (`.af-input`) |
| `--af-input-bg-focus` | `#0d1220` | `#ffffff` | Focused `.af-input` fill |
| `--af-control-disabled-bg` | `#101521` | `#f1f5f9` | Disabled button/input fill (without `pointer-events: none`) |
| `--af-control-disabled-border` | `#2a3347` | `#cbd5e1` | Disabled button/input border |
| `--af-control-disabled-fg` | `#73849c` | `#526277` | Disabled button/input text (`4.79:1` dark, `5.68:1` light) |
| `--af-accent-bg` | `#4f46e5` | `#4338ca` | Primary solid button fill (`.af-btn-primary`, `6.29:1` dark, `7.90:1` light) |
| `--af-accent-bg-hover` | `#4338ca` | `#3730a3` | Primary button hover fill (`7.90:1` dark, `9.93:1` light) |
| `--af-accent-border` | `#6366f1` | `#4338ca` | Primary button border |
| `--af-danger-bg` | `#3b121c` | `#fff1f2` | Destructive button & error toast/banner tint |
| `--af-danger-bg-hover` | `#4f1725` | `#ffe4e6` | Destructive button hover fill |
| `--af-danger-border` | `#e11d48` | `#be123c` | Destructive border (`4.02:1` dark, `6.29:1` light) |
| `--af-danger-fg` | `#fecdd3` | `#9f1239` | Destructive label (`11.55:1` dark, `7.30:1` light) |
| `--af-success-bg` | `#0b3328` | `#ecfdf5` | Success button tint |
| `--af-success-bg-hover` | `#104435` | `#d1fae5` | Success button hover fill |
| `--af-success-border` | `#10b981` | `#047857` | Success border (`7.44:1` dark, `5.48:1` light) |
| `--af-success-fg` | `#d1fae5` | `#065f46` | Success label (`12.19:1` dark, `7.29:1` light) |
| `--af-warning-bg` | `#332208` | `#fffbeb` | Warning banner fill |
| `--af-warning-border` | `#d97706` | `#b45309` | Warning banner border |
| `--af-warning-fg` | `#fde68a` | `#854d0e` | Warning text (`12.28:1` dark, `6.61:1` light) |
| `--af-tab-active-bg` | `#1e2447` | `#eef2ff` | Active `.af-tab-pill-active` fill |
| `--af-tab-active-border` | `#6366f1` | `#4f46e5` | Active `.af-tab-pill-active` border (`4.23:1` dark, `6.29:1` light) |
| `--af-tab-active-fg` | `#e0e7ff` | `#312e81` | Active `.af-tab-pill-active` text (`12.19:1` dark, `10.22:1` light) |
| `--af-nav-active-bg` | `#19213d` | `#e0e7ff` | Active `.af-nav-active` sidebar background |
| `--af-nav-active-border` | `#4f46e5` | `#818cf8` | Active `.af-nav-active` border / indicator |
| `--af-nav-active-fg` | `#e0e7ff` | `#312e81` | Active `.af-nav-active` label (`12.85:1` dark, `9.27:1` light) |
| `--af-focus-ring` | `#818cf8` | `#4338ca` | `2px solid` `:focus-visible` outline (`6.05–6.33:1` dark, `7.30–7.90:1` light) |
| `--af-shadow-overlay` | `0 18px 48px rgba(0, 0, 0, 0.55)` | `0 14px 36px rgba(15, 23, 42, 0.14)` | Neutral elevation shadow strictly for Tier 3 overlays |
| `--af-backdrop-scrim` | `rgba(2, 6, 23, 0.72)` | `rgba(15, 23, 42, 0.42)` | `<dialog>::backdrop` scrim |

#### B. Canonical Class Rename & Surface Mapping Contract

| Legacy Identifier | Canonical Identifier | Layer & Behavior |
| :--- | :--- | :--- |
| `.glass-card` | `.af-card` (static) / `.af-card-interactive` (clickable) | `@layer components`; `1px solid var(--af-border-card)`, `var(--af-surface-card)`, `border-radius: 0.75rem`, zero blur/shadow/lift/`::after`/touch-scale |
| `.glass-button` | `.af-btn` (+ `[data-tone="danger"|"success"|"primary"]`) | `@layer components`; flat matte fill + `1px solid var(--af-border-control)`, `min-height: 40px` (`44px` coarse/touch), no `pointer-events: none` when disabled |
| `.glass-button-primary` | `.af-btn-primary` | `@layer components`; solid `var(--af-accent-bg)`, white text, zero gradient/glow/hover-scale |
| `.glass-input` | `.af-input` | `@layer components`; flat `var(--af-input-bg)`, `1px solid var(--af-border-control)`, `2px` `--af-focus-ring` focus state |
| `.obs-tab-pill`, `.obs-tab-pill-active` | `.af-tab-pill`, `.af-tab-pill-active` | `@layer components`; subtle neutral outline on inactive pills, solid token active state, zero `!important` |
| `.obs-telemetry-surface`, `.obs-canvas-section` | `.af-canvas-section` | `@layer components`; transparent fill, `border-bottom: 1px solid var(--af-border-hairline)`, zero blur/radius/shadow |
| `.obs-metric-strip`, `.obs-vitals-grid` | `.af-hairline-grid` | `@layer components`; `overflow: clip`, bottom hairline + `-1px` child top/left hairlines for any column count |
| Ad-hoc `bg-white/[0.02]` / `bg-slate-950/80` wells | `.af-surface-inset` | `@layer components`; `var(--af-surface-inset)`, `1px solid var(--af-border-hairline)`, `border-radius: 0.5rem` |
| `.af-modal glass-card`, `.glass-card` popovers/toasts | `.af-modal`, `.af-popover`, `.af-toast`, `.af-toast-error` | `@layer components`; aligned with `fix/overlay-glass-effect`; 100% opaque `var(--af-surface-overlay)`, `1px solid var(--af-border-overlay)`, `var(--af-shadow-overlay)`, zero `.af-card`/`.glass-card` |
| `.glass-panel`, `.glass-hero`, `.obs-sidebar-surface`, `.obs-vital-*`, `#__next`, `.prototype-scroller` | *Deleted* | Dead legacy Obsidian V2 / Next.js classes purged in Commit 1 |
| `.obs-checkbox`, `.obs-scroller`, `.obs-touch-pills`, `.obs-beacon-*`, `.obs-brand-logo`, `.obs-brand-mark` | *Retained (flattened)* | Non-glass behavioral/brand classes kept to avoid gratuitous churn; brand blur halo/drop-shadow and beacon neon glows removed; `obs-checkbox` added to `DraftCheck` |

#### C. Rust Static CI Drift-Prevention Contract (`frontend-rs/crates/af-web-ui/tests/design_contract.rs`)

Runs automatically in GitHub Actions `.github/workflows/ci.yml` (`frontend-rs-checks` job via `cargo test --workspace`):
1. **CSS Forbidden Patterns** (scans comment-stripped `frontend-rs/styles/input.css`): rejects `backdrop-filter`, `-webkit-backdrop-filter`, `mask-composite`, `-webkit-mask-composite`, `--obs-chromatic-`, `--obs-specular-`, `--obs-card-lift`, `data-card-lift`, `data-aurora-opacity`, `data-aurora-animation`, `data-grain`, `obs-aurora-shift`, `fractalNoise`, `scale3d(1.025`, unlayered `.af-card`/`.af-btn`/`.af-input`/`.af-canvas-section`/`.af-overlay` declarations, `.light ` component selectors outside the root token block, and raw `rgba(255, 255, 255, 0.06)` / `0.07` hardcoded hairlines.
2. **Dark/Light Token Parity**: Parses every `--af-*` custom property defined in `:root` and asserts 100% presence in `html[data-theme="light"]`, reporting missing tokens by exact name.
3. **Rust Source Forbidden Patterns** (scans all `.rs` files under `frontend-rs/crates/{af-web-ui,af-web-app}/src/`): rejects `backdrop-blur`, `backdrop-saturate`, `af-modal glass-card`, `af-modal af-card`, and retired dead classes (`glass-panel`, `glass-hero`, `obs-sidebar-surface`, `obs-metric-strip`, `obs-vitals-grid`).
4. **Shrinking `.glass-*` Ratchet**: Checks every `.rs` file for `glass-card`, `glass-button`, `glass-button-primary`, `glass-input`, `obs-tab-pill`, `obs-telemetry-surface` against an explicit per-commit allowlist constant (`LEGACY_CLASS_ALLOWLIST`):
   * Commit 1: exact 59 unmigrated files; rejects any newly added file using legacy names.
   * Commit 2: removes `af-web-ui/*`, `shell.rs`, and `routes/*` from allowlist (50 files remaining).
   * Commit 3: removes Batch A tabs (`overview/*`, `services/*`, `marketplace/*`, `inbox.rs`, `audit.rs`, `settings/*`, `l10n.rs`, `notifications.rs`, `users.rs`, `quotas.rs`; 28 files remaining).
   * Commit 4: removes Batch B tabs (`cluster/*`, `network/*`, `fileshare/*`, `mcbrowser/*`, `streaming/*`, `mediaflow.rs`, `ai_chat.rs`; 0 template files remaining).
   * Commit 5: deletes `LEGACY_CLASS_ALLOWLIST` and temporary `.glass-*` CSS aliases completely, locking CI to **zero** legacy `.glass-*` / `obs-tab-pill` / `obs-telemetry-surface` occurrences across both `input.css` and `crates/` (with an explicit test-fixture exception only for `af-web-core/src/markdown.rs`'s HTML-class sanitizer test).
5. **Diagnostic Format**: Every assertion failure prints: violated rule name, offending `file:line` (or token name), and the canonical `.af-*` class or token replacement referencing `docs/design-system.md`.

---

### Target Files to Create/Modify (Grouped by Staged Commit)

#### Commit 1 — Semantic Token Foundation, Flat CSS, Temporary Aliases & Initial CI Drift Gate

##### 1. `frontend-rs/styles/input.css` (Modify)
*   **Type / Scope**: Global Tailwind v4 & Design System Stylesheet
*   **Proposed Changes**:
    *   Register semantic surface, hairline, and text utilities in `@theme inline`.
    *   Declare the complete `:root` (dark) and single `html[data-theme="light"]` semantic `--af-*` token tables from Section A above (retaining `--obs-bg-base: var(--af-bg-canvas)` alias); remove literal `--obs-white` inversion and duplicate `.light` blocks.
    *   Delete `body::before` aurora, `body::after` grain/vignette, `@keyframes obs-aurora-shift`, quantized `html[data-aurora-opacity=*]`, `html[data-aurora-animation=*]`, `html[data-grain=*]`, and `html[data-card-lift=*]` selectors; set `html`/`body` background cleanly to `var(--af-bg-canvas)` and text to `var(--af-fg-primary)`.
    *   Define all flat Tier 1 (`.af-canvas-section`, `.af-hairline-grid`), Tier 2 (`.af-card`, `.af-card-interactive`, `.af-surface-inset`), Tier 3 opaque overlays (`.af-modal`, `.af-drawer`, `.af-popover`, `.af-toast`, `.af-toast-error`, preserving compatibility with `fix/overlay-glass-effect`), opaque persistent chrome (`.af-sidebar`, `.af-header`, `.af-mobile-dock`), and flat controls (`.af-btn`, `.af-btn[data-tone="danger"|"success"|"primary"]`, `.af-btn-primary`, `.af-input`, `.af-tab-pill`, `.af-tab-pill-active`, `.af-nav-active`, `.obs-checkbox`) inside `@layer components` with zero `backdrop-filter`, zero chromatic gradients, zero `!important`, zero hover lift/scale, and semantic disabled states without `pointer-events: none`.
    *   Temporarily attach `.glass-card`, `.glass-button`, `.glass-button-primary`, `.glass-input`, `.obs-tab-pill`, `.obs-tab-pill-active`, and `.obs-telemetry-surface` as grouped selector aliases on those exact flat `@layer components` rules (deleted in Commit 5).
    *   Delete dead Obsidian V2 / Next.js rules (`.glass-panel`, `.glass-hero`, `.obs-sidebar-surface`, `.obs-metric-strip`, `.obs-vitals-grid`, `.obs-vital-*`, `#__next`, `.prototype-scroller`), delete coarse-pointer `backdrop-filter: blur(12px)` and `.glass-card:active` scale rules, fix mobile header `36px` button regression so Touch Mode / coarse pointers hold `>= 44px` within the `<= 104px` mobile header budget, flatten `.obs-brand-logo`/`.obs-brand-mark` and `.obs-beacon-*`, add light-theme scrollbar and warning/danger banner tokens, close remaining utility remap gaps (`bg-slate-950/80`, `bg-slate-950/60`, `bg-white/[0.02]`, `bg-white/[0.04]`, `border-white/15`, `divide-white/[0.06]`, `hover:bg-white/5`, `text-rose-200`, `text-indigo-100`, `text-amber-100`, `text-purple-300`, `bg-amber-950/30`), and refactor `.af-editor[data-editor-tone="light"|"dark"]` to override semantic `--af-*` control tokens while keeping 100% opaque backgrounds and zero `color`/`background-color` transitions.

##### 2. `frontend-rs/index.html` and `frontend-rs/public/manifest.json` (Modify)
*   **Type / Scope**: SPA Shell HTML & PWA Manifest
*   **Proposed Changes**: Add `data-theme="dark"` onto `<html lang="en" class="dark" data-theme="dark">` in `index.html` so first-paint theme matches runtime; align `manifest.json` `background_color` (`#07090e`) and `theme_color` (`#4f46e5`) with the dark canvas and accent tokens.

##### 3. `frontend-rs/crates/af-web-ui/tests/design_contract.rs` (Create)
*   **Type / Scope**: Rust Static CI Drift-Prevention Contract Test
*   **Proposed Changes**: Implement the 5 static contract tests specified in Section C above (`css_forbids_glass_and_legacy_atmosphere_rules`, `semantic_tokens_have_complete_dark_light_parity`, `rust_templates_forbid_blur_and_dead_classes`, `legacy_glass_class_ratchet_matches_allowlist`, `overlays_never_combine_with_card_classes`), seeded with Commit 1's exact allowlist so CI enforces zero-glass and token parity immediately.

---

#### Commit 2 — Core Primitives, Shell Chrome, Code Editor & All 4 Standalone Routes

##### 4. `frontend-rs/crates/af-web-ui/src/primitives.rs` (Modify)
*   **Type / Scope**: Shared Leptos UI Primitives
*   **Proposed Changes**:
    *   Update `ObsCard` to emit `<section class="af-card p-5 min-w-0 max-w-full">` (optional prop `interactive: bool` emitting `af-card-interactive`).
    *   Update `Button` to accept optional `tone: String` (`"primary"`, `"danger"`, `"success"`, or neutral default) emitting `.af-btn-primary` or `.af-btn` + `data-tone`, replacing raw class concatenation.
    *   Update `Modal` to emit `<dialog class="af-modal min-w-0 max-w-full">` (removing `glass-card`), update its close button to `af-btn px-3 min-w-10 min-h-10`, and update `ConfirmDialog` to support optional `danger: bool` using `.af-btn[data-tone="danger"]` alongside `.af-btn` / `.af-btn-primary`.
    *   Update `TabsBar` to emit `.af-tab-pill` / `.af-tab-pill-active`, update `TabPanel` to remove `focus:outline-none` in favor of visible `:focus-visible` ring, and update `SearchInput` to use `.af-input`.
    *   Add unit test assertions in `primitives.rs` verifying `Button` tone classes and `Modal` absence of `glass-card`.

##### 5. `frontend-rs/crates/af-web-ui/src/grid.rs`, `editor.rs`, `topology.rs`, and `lib.rs` (Modify)
*   **Type / Scope**: Shared DataGrid, Code Editor, Topology Map, and Crate Header
*   **Proposed Changes**:
    *   `grid.rs`: Remove `backdrop-blur` from sticky `<thead>` and bind it to `bg-[var(--af-bg-chrome)] border-b border-[var(--af-border-hairline)]`.
    *   `editor.rs`: Replace all `.glass-button`, `.glass-button-primary`, and `.glass-input` usages inside `McBrowserCodeEditor` toolbar/find bar with `.af-btn`, `.af-btn-primary`, and `.af-input`.
    *   `topology.rs`: Replace nested `<ObsCard>` per service node inside list view with `.af-surface-inset` rows inside an `.af-hairline-grid` (eliminating card-in-card nesting inside Overview's Service Health card).
    *   `lib.rs`: Update crate doc comment from `Obsidian V2` to reference `docs/design-system.md`.

##### 6. `frontend-rs/crates/af-web-app/src/shell.rs` (Modify)
*   **Type / Scope**: Application Shell, Header, Sidebar, Popovers & Toasts
*   **Proposed Changes**: Remove Tailwind `backdrop-blur-xl` from `<header class="af-header">`, confirm `header-transfers-popover` and `header-account-menu` use `.af-popover` and `ToastContainer` uses `.af-toast` / `.af-toast-error` (harmonized with `fix/overlay-glass-effect`), migrate shell buttons/inputs/selects to `.af-btn` / `.af-btn-primary` / `.af-input`, replace dark-only `hover:bg-white/5` on account menu items with semantic hover styling, and keep `Escape` dismissal for popovers.

##### 7. `frontend-rs/crates/af-web-app/src/routes/{login.rs, share.rs, consent.rs, device.rs}` (Modify)
*   **Type / Scope**: All 4 Standalone Public/Auth Routes
*   **Proposed Changes**: Replace all `.glass-card`, `.glass-button`, `.glass-button-primary`, and `.glass-input` classes with `.af-card`, `.af-btn`, `.af-btn-primary`, and `.af-input`; give Login's MFA/recovery toggle button a proper minimum hit target and underline/hover state; replace `share.rs` `<pre class="glass-card">` preview with `<pre class="af-card ...">`; update `design_contract.rs` ratchet allowlist to remove all Commit 2 files.

---

#### Commit 3 — Feature Tabs Migration Batch A (Core Operations & System Management)

##### 8. `frontend-rs/crates/af-web-app/src/tabs/overview/{mod.rs, widgets.rs}` (Modify)
*   **Type / Scope**: System Pulse Overview Tab & Telemetry Widgets
*   **Proposed Changes**:
    *   Migrate `.obs-telemetry-surface` disclosures and vital strips to `.af-canvas-section` inside `.af-hairline-grid` (removing redundant `border-b border-white/10`), migrate series/window filter buttons to `.af-tab-pill` / `.af-tab-pill-active` inside a subtle segmented container, migrate buttons/selects to `.af-btn` / `.af-btn-primary` / `.af-input`, and give inline `Retry` buttons and `<summary>` triggers proper hit targets and focus rings.
    *   Flatten nested card-in-card sub-blocks inside `StorageGpuTelemetry` (`Storage Pool Summary`, replacing `bg-white/[0.02]` rounded border box with `.af-surface-inset`) and `CapacityPredictions` (replacing `obs-telemetry-surface border border-white/10 rounded-xl` with `.af-surface-inset` inside `.af-hairline-grid`).
    *   Update `Gauge` amber threshold fill (`fill-amber-500` or semantic warning fill) to maintain contrast on light backgrounds.

##### 9. `frontend-rs/crates/af-web-app/src/tabs/{inbox.rs, audit.rs}` (Modify)
*   **Type / Scope**: Approval Inbox & Audit Log Tabs
*   **Proposed Changes**:
    *   Convert `inbox.rs` 4-item KPI summary strip (formerly 4 raw `.glass-card` divs) and `audit.rs` 4-item KPI summary strip (formerly 4 `<ObsCard>`s) into Tier 1 `.af-hairline-grid` bands; hoist `audit.rs` page heading out of `<ObsCard>` into a Tier 1 `.af-canvas-section` header.
    *   Downgrade repeated per-row `Inspect action` buttons in `inbox.rs` from `.af-btn-primary` to `.af-btn` (keeping `Approve & Execute` inside the modal as the single primary CTA), switch `Reject` to `.af-btn[data-tone="danger"]`, replace `bg-slate-950/80` payload boxes and nested modal detail cards with `.af-surface-inset`, and replace remaining `.glass-*` classes with `.af-*`.

##### 10. `frontend-rs/crates/af-web-app/src/tabs/services/{mod.rs, logs.rs}` and `tabs/marketplace/{mod.rs, catalog.rs, sandbox.rs}` (Modify)
*   **Type / Scope**: Services & Marketplace Tabs
*   **Proposed Changes**: Migrate all `.glass-card`, `.glass-button*`, `.glass-input`, and `.obs-tab-pill*` usages to `.af-*`; eliminate card-in-card nesting in `services/mod.rs` by converting `.af-service-tile` inside `<ObsCard>` to `.af-surface-inset` (or hoisting the outer group to a Tier 1 `.af-canvas-section` header above `.af-card` tiles); replace `bg-white/[0.04]` and `divide-white/[0.06]` with semantic tokens.

##### 11. `frontend-rs/crates/af-web-app/src/tabs/settings/{mod.rs, forms.rs, backups_oidc.rs, metadata.rs, oidc.rs, providers.rs, security.rs, updates.rs}`, `tabs/l10n.rs`, `tabs/notifications.rs`, `tabs/users.rs`, and `tabs/quotas.rs` (Modify)
*   **Type / Scope**: Settings, Localization Wrappers, Notifications, Users & Quotas Tabs
*   **Proposed Changes**:
    *   Migrate all `.glass-*` and `.obs-tab-pill*` classes to `.af-*`; change Settings cross-route shortcut pills (`Notifications`, `McBrowser Policy` in `settings/mod.rs`) from tab pills to `.af-btn` links; add `class="obs-checkbox"` to `DraftCheck` in `settings/forms.rs`; hoist `users.rs` page heading out of `<ObsCard>` to a Tier 1 header; replace ad-hoc `text-rose-300` destructive buttons with `.af-btn[data-tone="danger"]`; replace `bg-amber-950/30` reduced-motion status hint with semantic warning banner styling.
    *   Update `design_contract.rs` ratchet allowlist to remove all Commit 3 files.

---

#### Commit 4 — Feature Tabs Migration Batch B (Cluster, Network, Files, Media & AI)

##### 12. `frontend-rs/crates/af-web-app/src/tabs/cluster/{mod.rs, grants.rs, pairing.rs, peers.rs, storage.rs, transcode.rs}` (Modify)
*   **Type / Scope**: Peer Clustering Subviews
*   **Proposed Changes**: Migrate all `.glass-*` and `.obs-tab-pill*` classes to `.af-*`; hoist `cluster/mod.rs` page header to Tier 1 `.af-canvas-section`; replace nested `bg-white/5` peer cards (`peers.rs`) and nested storage/pairing boxes with `.af-surface-inset`; verify `[data-tone="danger"]` buttons (`Revoke Link`, `Close Window`, `Close All Windows`) render cleanly in both dark and light modes; replace active remote-server button border overrides with explicit semantic classes.

##### 13. `frontend-rs/crates/af-web-app/src/tabs/network/{mod.rs, tailscale.rs, tailscale_ingress.rs, wireguard.rs}` (Modify)
*   **Type / Scope**: Network & VPN Tabs
*   **Proposed Changes**: Migrate all `.glass-*` and `.obs-tab-pill*` classes to `.af-*`.

##### 14. `frontend-rs/crates/af-web-app/src/tabs/fileshare/{local_storage.rs, policy_audit.rs, shares.rs}` and `tabs/mcbrowser/{mod.rs, actions.rs, editor.rs, events.rs, helpers.rs, policy_audit.rs, toolbar.rs, transfers.rs}` (Modify)
*   **Type / Scope**: File Sharing & McBrowser File Manager Tabs
*   **Proposed Changes**: Migrate all `.glass-*` and `.obs-tab-pill*` classes to `.af-*`; replace `bg-slate-950/60`, `bg-white/[0.02]`, and `border-white/15` dropzone/preview utilities in `mcbrowser/mod.rs` with semantic `.af-surface-inset` / hairline utilities.

##### 15. `frontend-rs/crates/af-web-app/src/tabs/streaming/{mod.rs, administration.rs, analytics.rs, connections.rs, history.rs, imports.rs, live.rs, portability.rs, reconciliation.rs}`, `tabs/mediaflow.rs`, and `tabs/ai_chat.rs` (Modify)
*   **Type / Scope**: Streaming, MediaFlow & AI Chat Tabs
*   **Proposed Changes**:
    *   Migrate all `.glass-*` and `.obs-tab-pill*` classes to `.af-*`; replace `bg-white/[0.02]` sub-boxes in `streaming/analytics.rs` with `.af-surface-inset`.
    *   In `ai_chat.rs`, migrate the 6 provider selector buttons (`<button class="glass-card ...">`) to `.af-card-interactive` and migrate nested conversation history items (`<div class="glass-card ...">` inside `<ObsCard>`) to `.af-surface-inset` interactive rows (eliminating card-in-card nesting).
    *   Update `design_contract.rs` ratchet allowlist to empty (`&[]`, 0 remaining template files).

---

#### Commit 5 — State/Atmosphere Retirement, 6-Locale i18n, Legacy Alias Removal, Final Ratchet Lock & Test Suites

##### 16. `frontend-rs/crates/af-web-app/src/state/{preferences.rs, session.rs, tests.rs}` and `frontend-rs/crates/af-web-app/src/state.rs` (Modify)
*   **Type / Scope**: Application Preferences State, Cross-Tab Sync & Rust Unit Tests
*   **Proposed Changes**:
    *   Delete `card_lift`, `aurora_opacity`, `aurora_animation`, and `grain_display` fields from `HydratedPreferences` and `AppContext`, delete their normalizers (`quantize_aurora_opacity_pct`, `normalize_aurora_opacity_pct`, `format_aurora_opacity_unit`, `normalize_card_lift`), setters, `data-card-lift`/`data-aurora-opacity`/`data-aurora-animation`/`data-grain` DOM writes in `apply_display_preferences_dom`, and cross-tab `storage` listeners in `session.rs`.
    *   Remove `reset_atmosphere_defaults` (which forcibly reset `theme = "dark"`); if a display-reset button is retained for cadence/touch/reduced-motion, scope it strictly to those surviving settings without overwriting `theme`.
    *   Update `apply_theme_dom` (`preferences.rs`) to also update `document.querySelector('meta[name="theme-color"]')` to `#07090e` (dark) or `#f4f6fa` (light) via attribute-only DOM call (CSP-safe).
    *   Stop writing `cardLift`, `auroraOpacity`, `auroraAnimation`, and `grainDisplay` in `sync_legacy_system_storage()` (`state.rs`) while preserving unrecognized existing JSON fields intact for rollback safety.
    *   Update `state/tests.rs` to remove obsolete normalizer/attribute assertions and add `legacy_retired_atmosphere_and_card_lift_keys_are_ignored_safely`, proving pre-seeded `aetherflow-card-lift`, `aetherflow-aurora-*`, `aetherflow-grain*`, and `aetherflow-system-storage` envelopes hydrate active preferences without error.

##### 17. `frontend-rs/crates/af-web-app/src/tabs/settings/mod.rs` and `frontend-rs/crates/af-web-core/catalogs/{en, de, dk, es, fr, zh}.json` (Modify)
*   **Type / Scope**: Settings Display Panel & All 6 Localization Catalogs
*   **Proposed Changes**:
    *   Remove the `Atmosphere & Surface Physics` subsection (`#settings-aurora-opacity`, `#settings-aurora-animation`, `#settings-grain-display`, `#settings-card-lift`, and `Reset atmosphere defaults`) from `settings/mod.rs`.
    *   Atomically across all 6 JSON catalogs (`en`, `de`, `dk`, `es`, `fr`, `zh`): remove retired keys (`Settings.atmosphereTitle`, `Settings.auroraOpacity`, `Settings.auroraOpacityDescription`, `Settings.auroraAnimation`, `Settings.auroraAnimationDescription`, `Settings.grainDisplay`, `Settings.grainDisplayDescription`, `Settings.cardLift`, `Settings.cardLiftDescription`, `"Reset atmosphere defaults"`), and reword `Settings.reducedMotionActiveHint` and `Settings.highRefreshDescription` in all 6 languages so they no longer reference aurora animation or card hover lift (retaining `~2,712` leaf keys, well above the `>= 1,650` guard in `af-web-core/src/i18n.rs`).

##### 18. `frontend-rs/styles/input.css`, `frontend-rs/crates/af-web-ui/tests/design_contract.rs`, and `frontend-rs/crates/af-web-core/src/markdown.rs` (Modify)
*   **Type / Scope**: Final Alias Deletion, Ratchet Lock & Sanitizer Defense-in-Depth
*   **Proposed Changes**:
    *   Delete the temporary `.glass-card`, `.glass-button`, `.glass-button-primary`, `.glass-input`, `.obs-tab-pill`, `.obs-tab-pill-active`, and `.obs-telemetry-surface` aliases from `input.css`.
    *   Remove `LEGACY_CLASS_ALLOWLIST` from `design_contract.rs` so any occurrence of `.glass-*`, `obs-tab-pill`, or `obs-telemetry-surface` anywhere in `input.css` or `crates/` fails `cargo test --workspace` immediately.
    *   Expand `markdown_classes_cannot_impersonate_application_overlays` in `af-web-core/src/markdown.rs` to also assert stripping of `af-card`, `af-popover`, and `af-toast` alongside `af-modal`.

##### 19. `e2e/tests/e2e/{wasm.display.spec.ts, wasm.parity.spec.ts, wasm.mcbrowser-parity.spec.ts, wasm.oidc-device-inbox.spec.ts, visual.spec.ts}` and `e2e/tests/e2e/support/mockAetherFlow.ts` (Modify)
*   **Type / Scope**: Playwright Cross-Browser E2E & Visual Regression Specs
*   **Proposed Changes**:
    *   `wasm.display.spec.ts`: Update assertions for retired card-lift/aurora/grain controls; add legacy `localStorage` tolerance check (pre-seeding retired keys and asserting zero `data-card-lift`/`data-aurora-*`/`data-grain` attributes and `html[style] == null`); update the 6-locale settings check to verify surviving localized labels (`Settings.highRefreshMode` + `Settings.reducedMotion`); add runtime flat-design computed-style assertions across **Dark, Light, and Coarse-Pointer Mobile** on `/`, `/login`, `/share`, `/oauth/consent`, and `/oauth/device` confirming `backdropFilter === "none"`, card `::after` `content === "none"`, zero hover/active `transform` on `.af-card`, opaque alpha `=== 1` on `.af-modal`/`.af-popover`/`.af-toast`, distinct light-mode danger button styling, and synchronized `meta[name="theme-color"]`.
    *   `wasm.oidc-device-inbox.spec.ts`: Update `section.glass-card` locators (`L221, L234`) to `section.af-card`.
    *   `wasm.mcbrowser-parity.spec.ts`: Update `.af-editor-toolbar button.glass-button` / `select.glass-input` locators (`L206-207`) to `.af-editor-toolbar button.af-btn` / `select.af-input`, preserving opaque `rgb(...)`, `>= 4.5:1` cross-polarity contrast, and zero color/background animation checks.
    *   `wasm.parity.spec.ts`: Retain `1024x768` sidebar fit, `390x844` mobile header height `<= 104px`, and overlay hover opacity checks (coordinated with `fix/overlay-glass-effect`).
    *   `visual.spec.ts` & `support/mockAetherFlow.ts`: Update screenshot baseline names to `login-flat-shell.png` and `marketplace-flat-cards.png` (removing stale `glass` snapshot names and copy) and regenerate Linux Chromium PNG baselines.

##### 20. `tests/e2e/tier1_features/test_f13_to_f18_obsidian_design.py`, `tests/e2e/tier2_boundaries/test_boundaries_obsidian.py`, `tests/e2e/tier3_pairwise/test_pairwise_combos.py`, `tests/e2e/tier4_realworld/test_realworld_scenarios.py`, and `tests/TEST_INFRA.md` (Modify)
*   **Type / Scope**: 4-Tier Python Design-Contract Verification Suite
*   **Proposed Changes**: Replace Obsidian V2 chromatic/aurora/card-lift positive checks across Tiers 1–4 with genuine positive + negative flat design-contract assertions (verifying `--af-*` dark/light token parity, `@layer components`, zero `backdrop-filter`/chromatic/lift tokens, `.af-card`/`.af-btn`/`.af-btn-primary`/`.af-input`/`.af-modal` without `glass-card`, and zero stub assertions per `T1_F37_04`). Update `T3_COMBO_07` (`test_pairwise_combos.py`) from checking `--obs-chromatic-edge-gradient` to verifying flat dark/light token parity + zero blur, and preserve `T4_SCENARIO_01` (`test_realworld_scenarios.py`) via `--obs-bg-base` alias. Update `tests/TEST_INFRA.md` F13–F18 descriptions.

---

#### Commit 6 (or Follow-Up Documentation PR per Open Question) — Canonical Guide & Visual Captures

##### 21. `docs/design-system.md` (Create), `docs/architecture.md` (Modify), `README.md` (Modify), and `docs/assets/{screenshots,guides}/**/*.png` (Modify — Generated Captures)
*   **Type / Scope**: Developer Design Contract Documentation & Generated Visual Assets
*   **Proposed Changes**:
    *   Create `docs/design-system.md` containing the canonical Surface Decision Table, Page Layout Grammar, Dark/Light `--af-*` token specification, anti-nesting rules, and CI drift-prevention instructions; link it from `docs/architecture.md`.
    *   Update `README.md` prose removing obsolete "Obsidian V2 glass" references, regenerate dark/light 1440p screenshots and annotated guide steps from the freshly built `web/dist`, and bump the `?v=` image cache-buster query string.

---

### Verification Plan

Every commit in the 5-commit sequence must pass Steps 1–2 locally and in CI before advancing to the next commit; Steps 3–6 certify the complete migration before merge:

*   **Compilation & Rust Unit / Static Drift-Contract Tests** (Commits 1–5):
    *   `cd frontend-rs && cargo test --workspace` — verifies `design_contract.rs` (zero `backdrop-filter`, zero chromatic/lift tokens, 100% `:root` ↔ `html[data-theme="light"]` `--af-*` token parity, shrinking `.glass-*` ratchet locking to 0 on Commit 5), `state/tests.rs` (legacy `localStorage` tolerance), `af-web-core/src/i18n.rs` + `catalog_tests.rs` (6-locale exact parity and RSX key scan), `primitives.rs` tests, and `markdown.rs` sanitizer tests.
*   **Production WASM + Tailwind v4.3.5 Bundle Build** (Commits 1–5):
    *   `bash scripts/build_wasm_frontend.sh` — runs Trunk + pinned Tailwind CLI v4.3.5 (`styles/input.css` → `styles/compiled.css`), runs `scripts/finalize_wasm_assets.py`, verifies zero inline `<script>` tags, stamps `sw.js` `__BUILD_HASH__`, and stages `web/dist` with hashed `compiled-<hash>.css` and compressed locale catalogs.
*   **4-Tier Python Contract Suite** (Commit 5):
    *   `python3 tests/run_e2e.py --mode contract` — verifies all updated F13–F18 Tier 1, B13–B18 Tier 2, `T3_COMBO_07` Tier 3, `T4_SCENARIO_01` Tier 4, and `T1_F37_04` anti-stub checks pass with zero failures.
*   **Cross-Browser Embedded Playwright Suite (Chromium, Firefox, WebKit)** (Commits 1, 2, 5):
    *   `bash scripts/run_embedded_e2e.sh` — executes:
        *   `wasm.display.spec.ts` (dark/light/coarse-pointer flat computed-style checks, zero `backdropFilter`, zero card hover/active transform, opaque overlays, `meta[name="theme-color"]`, legacy `localStorage` tolerance, zero `html[style]` CSP compliance, 6-locale labels).
        *   `wasm.a11y.spec.ts` (`axe-core` WCAG 2.0/2.1/2.2 AA across all 16 tabs × Dark & Light themes × `1440px` & `390px` viewports — zero serious/critical violations).
        *   `wasm.parity.spec.ts` (`1024x768` sidebar fit without scroll, `390x844` mobile header `<= 104px`, overlay hover opacity regression checks).
        *   `wasm.mcbrowser-parity.spec.ts` (`.af-editor[data-editor-tone]` cross-polarity opaque `rgb(...)`, `>= 4.5:1` contrast, zero `color`/`background-color` animations).
        *   `wasm.oidc-device-inbox.spec.ts` (Inbox `.af-card` approval workflow + OIDC device/consent routes).
*   **Visual Baselines & Documentation Captures** (Commit 5 / Commit 6):
    *   `cd e2e && PLAYWRIGHT_BASE_URL=<local-server> npm run test:e2e:update` (Linux Chromium) to refresh `login-flat-shell.png` and `marketplace-flat-cards.png`, followed by a clean `npx playwright test e2e/tests/e2e/visual.spec.ts` pass.
    *   `node scripts/docs/capture_screenshots.mjs --dist web/dist` and `node scripts/docs/capture_guides.mjs --dist web/dist` (once Open Question #1 confirms same-PR vs. follow-up docs PR).

--------------------------------------------------------------------------------

<!-- Provenance: Indicates initial structural drafting via EGM. -->

*Drafted with EGM*
