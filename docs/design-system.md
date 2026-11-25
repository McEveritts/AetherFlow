# AetherFlow Design System

AetherFlow's Leptos WebAssembly dashboard (`frontend-rs/`) uses a **Unified Flat Surface & Control System** across all 16 authenticated dashboard tabs and all 4 standalone routes (`/login`, `/share`, `/oauth/consent`, `/oauth/device`). All visual styling is defined in a single Tailwind v4 stylesheet ([`frontend-rs/styles/input.css`](../frontend-rs/styles/input.css)) and shared UI primitives ([`frontend-rs/crates/af-web-ui/`](../frontend-rs/crates/af-web-ui/src/primitives.rs)).

---

## Core Principles

1. **Zero glassmorphism**: Zero `backdrop-filter` blur, zero chromatic gradient rims, zero specular overlays, and zero background aurora or fractal-noise layers across desktop, mobile, and touch viewports.
2. **One polarity-scoped semantic token contract**: Every surface, border, text role, and control state is authored once inside Tailwind v4's `@layer components` using `--af-*` custom properties. Polarity switches strictly via `:root` (default dark), `html[data-theme="light"]`, and `.af-editor[data-editor-tone="light"|"dark"]`.
3. **Calm, static surfaces**: Default inline containers are flat matte surfaces separated by 1px neutral hairlines with zero hover lift, zero border flashes, and zero touch-press scale shrink. Only explicitly clickable containers opt into `.af-card-interactive`.
4. **Strict CSP (`style-src 'self'`)**: Theme, display cadence, touch mode, reduced motion, and layout density are controlled exclusively via `data-*` attributes on `<html>` and external hashed CSS (`compiled-<hash>.css`) with zero inline `style="..."` attributes.
5. **WCAG 2.1 AA by construction**: Every dark and light foreground/background pair satisfies `>= 4.5:1` contrast for normal text and `>= 3.0:1` for interactive control borders and `:focus-visible` focus rings.

---

## The 2+1 Flat Surface Hierarchy

Every container in the UI maps to one explicit surface tier (plus opaque shell navigation chrome):

| Tier / Role | Canonical Classes | Rust Primitive / Usage | Use When | Do Not Use When |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1: Borderless Hairline Canvas** | `.af-canvas-section`, `.af-hairline-grid` | Raw semantic HTML (`<section>`, `<details>`, metric strips) | Page intro headers, collapsible disclosures, and top-level KPI / system vital strips (System Pulse vitals, Inbox summary, Audit summary). | Multi-field settings forms, dense peer-action grids, or floating popups. |
| **Tier 2: Quiet Flat Card** | `.af-card` (static), `.af-card-interactive` (clickable) | `<ObsCard>` / `<ObsCard interactive=true>` | Bounded work modules, charts, forms, peer tiles, data tables, and standalone route forms (`/login`, `/share`, `/oauth/consent`, `/oauth/device`). | Floating overlays, top-level page headers, or nested inside another `.af-card`. |
| **Card-Interior Sub-Group** | `.af-surface-inset` or internal `.af-hairline-grid` | Recessed sub-well inside `<ObsCard>` | Sub-summaries, multi-plot sub-cells, log/payload previews, service rows, topology list items, and AI Chat history rows inside an `.af-card`. | Never nest `.af-card` inside `.af-card`. |
| **Tier 3: Crisp Opaque Overlays** | `.af-modal`, `.af-drawer .af-modal`, `.af-popover`, `.af-toast`, `.af-toast-error` | `<Modal>`, `<Drawer>`, `<ConfirmDialog>`, shell popovers & toasts | Modals, slide-over drawers, header dropdown popovers, and toast alerts floating over scrolling page content. | Inline page sections; never combined with `.af-card`. |
| **Persistent Shell Chrome** | `.af-sidebar`, `.af-header`, `.af-mobile-dock`, sticky `.af-grid thead` | `shell.rs`, `grid.rs` | Fixed/sticky navigation bars and sticky table headers framing the canvas. | Never applies `backdrop-filter` or translucency. |

### Tier 1 Details: `.af-canvas-section` & `.af-hairline-grid`

- `.af-canvas-section` renders transparent over `--af-bg-canvas` with a single `1px solid var(--af-border-hairline)` bottom divider and zero border-radius or shadow.
- `.af-hairline-grid` renders a responsive CSS grid with `overflow: clip` (preserving the F16 scroller-containment invariant without root `overflow-x: hidden`) and `-1px` child top/left borders (`margin-top: -1px; margin-left: -1px; border-top/left: 1px solid var(--af-border-hairline)`). Any dynamic column count renders clean 1px interior hairlines automatically in both themes. Flush focusable grid children use `outline-offset: -2px` so focus outlines are never clipped.

### Tier 2 Details: `.af-card`, `.af-card-interactive`, `.af-surface-inset`

- `.af-card` uses `background-color: var(--af-surface-card)`, `border: 1px solid var(--af-border-card)`, `border-radius: var(--obs-radius-xl)` (`0.75rem`), `box-shadow: none`, and `transform: none` (`::after { content: none }`). It never lifts, shifts, or flashes on hover or touch press.
- `.af-card-interactive` opts genuinely clickable cards (such as AI Chat provider selectors) into `cursor: pointer`, a stepped fill/border hover state (`--af-surface-card-hover` / `--af-border-card-hover` under `@media (hover: hover) and (pointer: fine)`), and a `2px solid var(--af-focus-ring)` `:focus-visible` outline.
- `.af-surface-inset` provides a recessed well (`var(--af-surface-inset)`, `1px solid var(--af-border-hairline)`, `0.5rem` radius) for grouped content inside an `.af-card` without double-card borders.

### Tier 3 Details: Opaque Floating Overlays

- `.af-modal`, `.af-popover`, and `.af-toast` (plus `.af-toast-error` / `[role="alert"]`) render with a **100% opaque** `var(--af-surface-overlay)` fill (`#111624` dark, `#ffffff` light), `1px solid var(--af-border-overlay)`, `var(--af-shadow-overlay)`, `transform: none`, and `transition: none`.
- Hovering or tapping an overlay never alters its background opacity, border color, shadow, or transform.
- `.af-drawer .af-modal` docks flush to the viewport edge with `border-radius: 0` and `100dvh` height.
- `<dialog>::backdrop` uses `var(--af-backdrop-scrim)`.

---

## Flat Interactive Controls

All interactive controls live inside `@layer components` in `frontend-rs/styles/input.css` so Tailwind spacing and layout utilities compose cleanly without `!important` conflicts.

| Control | Canonical Classes / Attributes | Visual & Accessibility Contract |
| :--- | :--- | :--- |
| **Secondary Button** | `.af-btn` (`<Button>`) | Flat matte fill (`--af-control-bg`), `1px solid var(--af-border-control)` (`>= 3.4:1` dark, `>= 4.3:1` light), `min-height: 40px` (`44px` in Touch Mode / coarse pointer). |
| **Primary Button** | `.af-btn-primary` or `.af-btn[data-tone="primary"]` (`<Button primary=true>`) | Solid flat indigo (`--af-accent-bg`) with `#ffffff` text (`6.29:1` dark, `7.90:1` light), flat `--af-accent-bg-hover` hover fill, zero gradient, zero glow shadow, zero scale transform. |
| **Destructive / Success Button** | `.af-btn[data-tone="danger"]`, `.af-btn[data-tone="success"]` (`<Button tone="danger">`, `<ConfirmDialog danger=true>`) | Polarity-scoped tinted fill, crisp semantic border, and high-contrast label (`11.55:1` / `7.30:1` danger; `12.19:1` / `7.29:1` success). |
| **Disabled Controls** | `.af-btn:disabled`, `.af-btn-primary:disabled`, `.af-input:disabled`, `.obs-checkbox:disabled` (and `[aria-disabled="true"]`) | Dedicated semantic disabled tokens (`--af-control-disabled-bg`, `--af-control-disabled-border`, `--af-control-disabled-fg`) with `opacity: 1` and `cursor: not-allowed`. **Never** sets `pointer-events: none` so permission-block `title` tooltips remain hoverable. |
| **Text Input / Select** | `.af-input` (`<SearchInput>`) | Recessed flat `--af-input-bg` fill, `1px solid var(--af-border-control)`, `min-height: 40px`, `--af-focus-ring` focus border + `2px` `:focus-visible` ring. |
| **Tab Pills** | `.af-tab-pill`, `.af-tab-pill-active` (`<TabsBar>`) | Outlined pill (`1px solid var(--af-border-hairline)`), `min-height: 36px` (desktop) / `44px` (Touch Mode / coarse pointer), active state driven by `--af-tab-active-*` with zero `!important`. Cross-route shortcuts (e.g., Settings → Notifications / McBrowser Policy) use `.af-btn`, not tab pills. |
| **Checkbox** | `.obs-checkbox` | Custom flat `1.125rem` square using `--af-input-bg`, `--af-border-control`, and `--af-accent-bg` checked fill with crisp SVG checkmark and `2px` `--af-focus-ring`. |
| **Active Sidebar Nav** | `.af-nav-button.af-nav-active` | Clean `--af-nav-active-bg` fill, `--af-nav-active-border` border + `inset 3px 0 0` left bar, and `--af-nav-active-fg` text across both `84px` icon rail and `238px` expanded sidebar. |
| **Brand Mark & Beacons** | `.obs-brand-logo`, `.obs-brand-mark`, `.obs-beacon-{live,reconnecting,danger,offline}` | Flat logo container with zero blur halo or drop-shadow; 10px solid status dots with `2px` `--af-bg-chrome` ring (no neon glow). |
| **Code Editor Themes** | `.af-editor[data-editor-tone="light"\|"dark"]` | Scoped semantic control token overrides on `.af-btn`, `.af-btn-primary`, and `.af-input` with 100% opaque `rgb(...)` backgrounds, `>= 4.5:1` cross-polarity contrast, and `transition-property: border-color` (excluding `color` and `background-color` so tone switches happen atomically). |

### Responsive & Touch-Target Budgets

- **Coarse pointer / Touch Mode (`html[data-touch-mode="true"]` or `@media (pointer: coarse), (hover: none)`)**: Enforces `min-height: 44px` on buttons, tab pills, inputs, and mobile header controls without re-introducing blur or touch scale transforms.
- **Mobile header (`390x844`)**: Compact two-row grid staying within `<= 104px` total height even with `44px` touch targets active.
- **Desktop sidebar (`1024x768`)**: All 16 navigation tabs plus logout fit without vertical sidebar overflow (`@media (max-height: 860px)` compact rhythm).

---

## Semantic Token Reference (`--af-*`)

All `--af-*` tokens are declared in `:root` (dark) and mirrored 1:1 in `html[data-theme="light"]` in `frontend-rs/styles/input.css`. `--obs-bg-base` is retained as a compatibility alias to `var(--af-bg-canvas)`.

### Surfaces & Borders

| Semantic Token | `:root` (Dark) | `html[data-theme="light"]` | Role / Verified Contrast |
| :--- | :--- | :--- | :--- |
| `--af-bg-canvas` | `#07090e` | `#f4f6fa` | Page canvas foundation (`--obs-bg-base` alias) |
| `--af-bg-chrome` | `#090c14` | `#f8fafc` | Opaque persistent chrome (`.af-sidebar`, `.af-header`, `.af-mobile-dock`, `thead`) |
| `--af-surface-card` | `#0d111a` | `#ffffff` | Tier 2 Quiet Flat Card matte fill |
| `--af-surface-card-hover` | `#121826` | `#f8fafc` | Hover fill exclusively for opt-in `.af-card-interactive` |
| `--af-surface-inset` | `#0a0d15` | `#eef2f7` | Recessed sub-surface well inside `.af-card` |
| `--af-surface-overlay` | `#111624` | `#ffffff` | Tier 3 100% opaque overlay fill (`.af-modal`, `.af-popover`, `.af-toast`) |
| `--af-border-hairline` | `#232d42` | `#cbd5e1` | Tier 1 canvas rules, `.af-hairline-grid` dividers, chrome borders |
| `--af-border-card` | `#232d42` | `#cfd9e6` | Tier 2 `.af-card` 1px border |
| `--af-border-card-hover` | `#3b4b6b` | `#94a3b8` | Hover border exclusively for `.af-card-interactive` |
| `--af-border-overlay` | `#33415c` | `#cbd5e1` | Tier 3 crisp overlay border |
| `--af-border-control` | `#5f7191` | `#64748b` | Interactive control border (`3.45–3.83:1` dark, `4.34–4.76:1` light) |
| `--af-border-control-hover` | `#8093b5` | `#475569` | Hover border for neutral controls |

### Typography, Controls & Semantic Tones

| Semantic Token | `:root` (Dark) | `html[data-theme="light"]` | Role / Verified Contrast |
| :--- | :--- | :--- | :--- |
| `--af-fg-primary` | `#f1f5f9` | `#0f172a` | Primary text (`17.24:1` dark card, `17.85:1` light card) |
| `--af-fg-secondary` | `#cbd5e1` | `#334155` | Secondary labels (`12.72:1` dark, `10.35:1` light) |
| `--af-fg-muted` | `#94a3b8` | `#475569` | Muted metadata & timestamps (`7.04–7.36:1` dark, `6.74–7.58:1` light) |
| `--af-fg-on-accent` | `#ffffff` | `#ffffff` | Text on solid accent buttons (never inverted) |
| `--af-control-bg` | `#151c2c` | `#f1f5f9` | Secondary `.af-btn` fill |
| `--af-control-bg-hover` | `#1d263b` | `#e2e8f0` | Secondary `.af-btn` hover fill |
| `--af-input-bg` | `#0a0e18` | `#ffffff` | Form `.af-input` / `.obs-checkbox` fill |
| `--af-input-bg-focus` | `#0d1220` | `#ffffff` | Focused `.af-input` fill |
| `--af-control-disabled-bg` | `#101521` | `#f1f5f9` | Disabled button/input fill |
| `--af-control-disabled-border` | `#2a3347` | `#cbd5e1` | Disabled button/input border |
| `--af-control-disabled-fg` | `#73849c` | `#526277` | Disabled label (`4.79:1` dark, `5.68:1` light — WCAG AA even during state transitions) |
| `--af-accent-bg` | `#4f46e5` | `#4338ca` | Primary `.af-btn-primary` fill (`6.29:1` dark, `7.90:1` light) |
| `--af-accent-bg-hover` | `#4338ca` | `#3730a3` | Primary hover fill (`7.90:1` dark, `9.93:1` light) |
| `--af-accent-border` | `#6366f1` | `#4338ca` | Primary button border |
| `--af-danger-bg` / `-hover` | `#3b121c` / `#4f1725` | `#fff1f2` / `#ffe4e6` | Destructive button & danger banner fill |
| `--af-danger-border` / `-fg` | `#e11d48` / `#fecdd3` | `#be123c` / `#9f1239` | Destructive border (`4.02:1` / `6.29:1`) & label (`11.55:1` / `7.30:1`) |
| `--af-success-bg` / `-hover` | `#0b3328` / `#104435` | `#ecfdf5` / `#d1fae5` | Success button fill |
| `--af-success-border` / `-fg` | `#10b981` / `#d1fae5` | `#047857` / `#065f46` | Success border (`7.44:1` / `5.48:1`) & label (`12.19:1` / `7.29:1`) |
| `--af-warning-bg` / `-border` / `-fg` | `#332208` / `#d97706` / `#fde68a` | `#fffbeb` / `#b45309` / `#854d0e` | Warning banner tokens (`12.28:1` dark, `6.61:1` light) |
| `--af-tab-active-bg` / `-border` / `-fg` | `#1e2447` / `#6366f1` / `#e0e7ff` | `#eef2ff` / `#4f46e5` / `#312e81` | Active `.af-tab-pill-active` (`12.19:1` dark, `10.22:1` light) |
| `--af-nav-active-bg` / `-border` / `-fg` | `#19213d` / `#4f46e5` / `#e0e7ff` | `#e0e7ff` / `#4f46e5` / `#312e81` | Active `.af-nav-active` (`12.85:1` dark, `9.27:1` light; border `5.10:1` light) |
| `--af-focus-ring` | `#818cf8` | `#4338ca` | `2px solid` `:focus-visible` outline (`6.05–6.33:1` dark, `7.30–7.90:1` light) |
| `--af-shadow-overlay` | `0 18px 48px rgba(0, 0, 0, 0.55)` | `0 14px 36px rgba(15, 23, 42, 0.14)` | Neutral elevation strictly for Tier 3 overlays |
| `--af-backdrop-scrim` | `rgba(2, 6, 23, 0.72)` | `rgba(15, 23, 42, 0.42)` | `<dialog>::backdrop` scrim |

### Chrome, Charts & Topology Tokens

| Semantic Token | `:root` (Dark) | `html[data-theme="light"]` | Role |
| :--- | :--- | :--- | :--- |
| `--af-scrollbar-track` / `-thumb` / `-hover` | `#0a0e18` / `#2a3650` / `#435478` | `#e2e8f0` / `#94a3b8` / `#64748b` | Theme-aware thin scrollbars |
| `--af-progress-track` / `-fill` | `#1e293b` / `#6366f1` | `#e2e8f0` / `#4338ca` | Native `<progress>` bars |
| `--af-chart-stroke` / `-area-fill` / `-hover-stroke` | `#818cf8` / `rgba(129, 140, 248, 0.16)` / `#c4b5fd` | `#4f46e5` / `rgba(79, 70, 229, 0.14)` / `#6d28d9` | Time-series telemetry plots |
| `--af-chart-grid` / `-axis-text` | `rgba(148, 163, 184, 0.22)` / `#94a3b8` | `rgba(71, 85, 105, 0.30)` / `#475569` | Plot gridlines & axis labels |
| `--af-topo-{core,active,stopped,exception,edge}` | `#a78bfa`, `#34d399`, `#94a3b8`, `#fb7185`, `rgba(148, 163, 184, 0.35)` | `#6d28d9`, `#047857`, `#475569`, `#be123c`, `#64748b` | Live topology graph nodes & edges |

### Tailwind v4 Semantic Utilities (`@theme inline`)

`@theme inline` in `frontend-rs/styles/input.css` exposes these tokens directly as Tailwind utilities (`bg-canvas`, `bg-chrome`, `bg-surface-card`, `bg-surface-card-hover`, `bg-surface-inset`, `bg-surface-overlay`, `border-hairline`, `border-card-border`, `border-control-border`, `border-overlay-border`, `text-fg-primary`, `text-fg-secondary`, `text-fg-muted`, `text-fg-on-accent`, `bg-accent-bg`, `bg-danger-bg`, `text-danger-fg`, `bg-success-bg`, `text-success-fg`, `bg-warning-bg`, `text-warning-fg`). Prefer these semantic utilities over raw dark-only `border-white/*`, `bg-white/*`, or `bg-slate-950/*` classes in new templates.

---

## Anti-Patterns & Forbidden Rules

Do **not** introduce any of the following in CSS or Leptos RSX templates:

- **No blur or glass effects**: Never use `backdrop-filter`, `-webkit-backdrop-filter`, Tailwind `backdrop-blur*`, or `backdrop-saturate*`.
- **No chromatic rims or atmosphere layers**: Never use `mask-composite`, `--obs-chromatic-*`, `--obs-specular-*`, `body::before` aurora gradients, `obs-aurora-shift`, or `body::after` SVG `fractalNoise`.
- **No hover lift or touch shrink**: Never animate `transform: translateY(...)` on `.af-card:hover`, `scale3d(1.025, ...)` on `.af-btn-primary:hover`, or shrink cards on `:active`.
- **No card-in-card nesting**: Never place `<ObsCard>` or `.af-card` inside another `.af-card`. Use `.af-surface-inset` or `.af-hairline-grid` for sub-groups.
- **No overlay + card mixing**: Never combine `.af-modal`, `.af-drawer`, `.af-popover`, or `.af-toast` with `.af-card` or `.glass-card`.
- **No legacy class names**: Never reference `.glass-card`, `.glass-button`, `.glass-button-primary`, `.glass-input`, `.obs-tab-pill`, `.obs-telemetry-surface`, `.glass-panel`, `.glass-hero`, `.obs-sidebar-surface`, `.obs-metric-strip`, or `.obs-vitals-grid`.
- **No `.light ` component overrides**: Never author `.light ...` or `html.light` selectors; all light-theme overrides belong under `html[data-theme="light"]`.
- **No `pointer-events: none` on disabled buttons**: Keep `cursor: not-allowed` with `--af-control-disabled-*` so hover tooltips explaining permission blocks remain readable.
- **No inline styles or blanket root overflow clipping**: Never emit `style="..."` (violates CSP `style-src 'self'`) and never set `overflow-x: hidden` on `html` or `body` (violates F16 scroller containment).

---

## CI Enforcement & Verification

Flat-design invariants are enforced automatically at three layers:

1. **Rust Static Drift Gate (`frontend-rs/crates/af-web-ui/tests/design_contract.rs`)** — runs in GitHub Actions via `cargo test --workspace`:
   - `css_forbids_glass_and_legacy_atmosphere_rules`: Rejects `backdrop-filter`, `mask-composite`, chromatic/specular/card-lift/aurora/grain tokens, `.light ` selectors, legacy `.glass-*`/`.obs-tab-pill`/`.obs-telemetry-surface` selectors, and unlayered base component declarations outside `@layer components`.
   - `semantic_tokens_have_complete_dark_light_parity`: Enforces 100% 1:1 `--af-*` token parity between `:root` and `html[data-theme="light"]`.
   - `rust_templates_forbid_blur_and_dead_classes`: Scans `frontend-rs/crates/{af-web-ui,af-web-app}/src/**/*.rs` for `backdrop-blur`, `backdrop-saturate`, and retired classes.
   - `rust_templates_forbid_legacy_glass_classes`: Permanently locks Rust templates to zero `.glass-*`, `.obs-tab-pill`, and `.obs-telemetry-surface` occurrences.
   - `overlays_never_combine_with_card_classes`: Prevents Tier 3 overlays from combining with Tier 2 card classes.
2. **Playwright Cross-Browser Runtime & A11y Suites (`e2e/tests/e2e/`)**:
   - `wasm.display.spec.ts`: Verifies zero `backdropFilter`, zero static `.af-card` hover transform/shadow change, dark/light computed `--af-*` tokens & `meta[name="theme-color"]` sync, Touch Mode `>= 44px` controls within `<= 104px` mobile header, CSP-safe `html[style] === null`, legacy `localStorage` passive tolerance, and 6-locale labels.
   - `wasm.parity.spec.ts` & `wasm.mcbrowser-parity.spec.ts`: Verifies opaque overlays on hover in dark and light themes, `1024x768` sidebar fit, `390x844` mobile header height, and `.af-editor[data-editor-tone]` cross-polarity `>= 4.5:1` contrast with zero color/background transitions.
   - `wasm.a11y.spec.ts` & `visual.spec.ts`: Runs `axe-core` WCAG AA scans across all 16 tabs in dark/light desktop/mobile viewports and visual regression baselines (`login-flat-shell.png`, `marketplace-flat-cards.png`).
3. **4-Tier Python Contract Suite (`python3 tests/run_e2e.py --mode contract`)**:
   - Verifies F13–F18 Tier 1 feature contracts, B13–B18 Tier 2 adversarial boundaries (including computed dark/light WCAG contrast ratios), `T3_COMBO_07` WASM and flat variable interoperability, `T4_SCENARIO_01` operator onboarding scenario coverage, and `T1_F37_04` zero-stub assertion enforcement.
