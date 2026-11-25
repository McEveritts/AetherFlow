"""
Tier 2: Boundary & Corner Cases (Adversarial Verification)
Features:
- B13: Flat Foundation Boundaries
- B14: Semantic Surface & Control Token Boundaries
- B15: Tri-Mode Navigation Boundaries
- B16: Scroller Containment Boundaries
- B17: Display & Input Preference Boundaries
- B18: Flat UI Primitives Boundaries
"""

import re
from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

INPUT_CSS = "frontend-rs/styles/input.css"
SHELL_RS = "frontend-rs/crates/af-web-app/src/shell.rs"
STATE_RS = "frontend-rs/crates/af-web-app/src/state.rs"
PREFS_RS = "frontend-rs/crates/af-web-app/src/state/preferences.rs"
AUDIT_RS = "frontend-rs/crates/af-web-app/src/tabs/audit.rs"
PRIMITIVES_RS = "frontend-rs/crates/af-web-ui/src/primitives.rs"
GRID_RS = "frontend-rs/crates/af-web-ui/src/grid.rs"
CONSENT_RS = "frontend-rs/crates/af-web-app/src/routes/consent.rs"


def _strip_css_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css or "", flags=re.DOTALL)


def _extract_css_block(css: str, selector_pattern: str) -> str:
    match = re.search(rf"{selector_pattern}\s*\{{([^}}]*)\}}", css, flags=re.DOTALL)
    return match.group(1) if match else ""


def _hex_contrast_ratio(fg_hex: str, bg_hex: str) -> float:
    def rel_lum(hex_str: str) -> float:
        rgb = [int(hex_str[i:i + 2], 16) / 255.0 for i in (0, 2, 4)]
        lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]

    l1, l2 = rel_lum(fg_hex), rel_lum(bg_hex)
    return (max(l1, l2) + 0.05) / (min(l1, l2) + 0.05)


class TestB13TextContrastRatioCompliant(TestCase):
    def __init__(self):
        super().__init__("T2_B13_01", "F13", 2, "Dark and light primary text tokens against --af-bg-canvas satisfy WCAG AA (>= 4.5:1)")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        root_block = _extract_css_block(css, r":root")
        light_block = _extract_css_block(css, r'html\[data-theme="light"\]')

        for label, block in (("dark", root_block), ("light", light_block)):
            fg = re.search(r"--af-fg-primary\s*:\s*#([0-9a-fA-F]{6})\s*;", block)
            bg = re.search(r"--af-bg-canvas\s*:\s*#([0-9a-fA-F]{6})\s*;", block)
            self.assert_true(
                bool(fg and bg),
                f"B13: input.css {label} theme must define hex --af-fg-primary and --af-bg-canvas",
            )
            ratio = _hex_contrast_ratio(fg.group(1), bg.group(1))
            self.assert_true(
                ratio >= 4.5,
                f"B13: {label} primary text contrast against canvas must be >= 4.5:1 (got {ratio:.2f}:1)",
            )


class TestB13BodyPointerEventsNotBlocked(TestCase):
    def __init__(self):
        super().__init__("T2_B13_02", "F13", 2, "Flat component rules live inside @layer components without blocking body pseudo-layers")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(
            "@layer components" in css
            and ".af-card" in css
            and ".af-btn" in css
            and ".af-input" in css
            and ".af-modal" in css,
            "B13: input.css must contain canonical flat component rules inside @layer components",
        )
        self.assert_not_in("body::before", css, "B13: retired body::before layer must not exist")
        self.assert_not_in("body::after", css, "B13: retired body::after layer must not exist")


class TestB13NegativeZIndexStacking(TestCase):
    def __init__(self):
        super().__init__("T2_B13_03", "F13", 2, "input.css forbids backdrop-filter, mask-composite rims, and retired data-card-lift rules")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(bool(css), "B13: input.css must be readable")
        self.assert_not_in("backdrop-filter", css, "B13: backdrop-filter is forbidden in the flat design system")
        self.assert_not_in("mask-composite", css, "B13: mask-composite chromatic rims are forbidden")
        self.assert_not_in("data-card-lift", css, "B13: retired data-card-lift selectors must be removed")
        self.assert_not_in(".light ", css, "B13: legacy .light component overrides must be replaced by html[data-theme=\"light\"]")


class TestB13OpaqueWrapperDivsPurged(TestCase):
    def __init__(self):
        super().__init__("T2_B13_04", "F13", 2, "Shell root avoids hardcoded dark bg-slate-950 wrapper and backdrop-blur classes")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        shell = inspector.read_file(SHELL_RS)
        self.assert_true(bool(shell), "B13: shell.rs must exist")
        self.assert_not_in("min-h-screen bg-slate-950", shell or "", "B13: shell.rs must not use hardcoded dark bg-slate-950 wrapper")
        self.assert_not_in("backdrop-blur", shell or "", "B13: shell.rs must not apply backdrop-blur on persistent chrome")


class TestB13PrintStylesDegradeCleanly(TestCase):
    def __init__(self):
        super().__init__("T2_B13_05", "F13", 2, "Print media query degrades cleanly without animations or background images")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS) or ""
        self.assert_true(
            "@media print" in css and "background-image: none" in css and "animation: none" in css,
            "B13: input.css must declare @media print rules disabling background images and animations",
        )


class TestB14PrefersReducedMotionRespected(TestCase):
    def __init__(self):
        super().__init__("T2_B14_01", "F14", 2, "prefers-reduced-motion and data-reduced-motion suppress transitions and animations")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(
            "prefers-reduced-motion" in css
            and 'html[data-reduced-motion="true"]' in css
            and "transition: none" in css,
            "B14: input.css must define prefers-reduced-motion and data-reduced-motion suppression blocks",
        )


class TestB14CardLiftCausesNoLayoutShift(TestCase):
    def __init__(self):
        super().__init__("T2_B14_02", "F14", 2, "Static .af-card enforces transform: none with zero hover translateY lift")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        card_block = _extract_css_block(css, r"\.af-card[^{]*")
        self.assert_true(
            "transform: none;" in card_block and "box-shadow: none;" in card_block,
            "B14: static .af-card must enforce transform: none and box-shadow: none",
        )
        self.assert_false(
            bool(re.search(r"\.af-card:hover\s*\{[^}]*translate", css, flags=re.DOTALL)),
            "B14: .af-card must not apply hover translateY/translate3d lift",
        )


class TestB14GlassSpecularBorderThickness(TestCase):
    def __init__(self):
        super().__init__("T2_B14_03", "F14", 2, "Flat cards and hairline grids enforce crisp 1px semantic borders")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(
            "border: 1px solid var(--af-border-card)" in css
            and "1px solid var(--af-border-hairline)" in css,
            "B14: flat surfaces and hairline grids must use 1px semantic hairline tokens",
        )


class TestB14FocusVisibleOutlinesRetained(TestCase):
    def __init__(self):
        super().__init__("T2_B14_04", "F14", 2, "Interactive flat controls retain accessible 2px :focus-visible outlines")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(
            ":focus-visible" in css and "outline: 2px solid var(--af-focus-ring)" in css,
            "B14: input.css must define 2px --af-focus-ring :focus-visible outlines",
        )


class TestB14GlassDarkWellsRecessed(TestCase):
    def __init__(self):
        super().__init__("T2_B14_05", "F14", 2, "Flat inputs, buttons, and inset wells consume semantic surface/control tokens")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(
            "var(--af-input-bg)" in css
            and "var(--af-control-bg)" in css
            and "var(--af-surface-inset)" in css,
            "B14: flat inputs, secondary buttons, and inset wells must consume semantic tokens",
        )


class TestB15TouchTargetsMinimum44Pixels(TestCase):
    def __init__(self):
        super().__init__("T2_B15_01", "F15", 2, "Touch target rules strictly enforce min-height of 44px")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "min-height: 44px" in css), "B15: Touch targets must specify 44px minimum")


class TestB15MobileDrawerBackdropClickCloses(TestCase):
    def __init__(self):
        super().__init__("T2_B15_02", "F15", 2, "Closing mobile navigation drawer resets context.mobile_open cleanly")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        shell = inspector.read_file(SHELL_RS)
        self.assert_true(bool(shell and "context.mobile_open.set(false)" in shell and "<Drawer open=context.mobile_open" in shell), "B15: Mobile drawer must handle close state")


class TestB15ResponsiveBreakpointZeroHydrationError(TestCase):
    def __init__(self):
        super().__init__("T2_B15_03", "F15", 2, "Tri-mode layout uses CSS media queries to avoid layout flicker")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS) or ""
        self.assert_true(
            bool(re.search(r"@media\s*\(\s*max-width\s*:\s*767px\s*\)", css)),
            "B15: Navigation must rely on CSS media queries for responsive modes",
        )


class TestB15ActiveNavigationIndicatorVisible(TestCase):
    def __init__(self):
        super().__init__("T2_B15_04", "F15", 2, "Active route or tab displays distinct visual highlight across all modes")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        shell = inspector.read_file(SHELL_RS)
        self.assert_true(bool(shell and "af-nav-active" in shell and 'aria-current' in shell), "B15: Active tab indicator must be implemented")


class TestB15DockDoesNotObscureBottomContent(TestCase):
    def __init__(self):
        super().__init__("T2_B15_05", "F15", 2, "Mobile layout applies bottom padding to prevent dock from obscuring content")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS) or ""
        shell = inspector.read_file(SHELL_RS) or ""
        has_dock_padding = bool(
            re.search(
                r"\.af-tab-content\s*\{\s*padding-bottom:\s*calc\(88px\s*\+\s*env\(safe-area-inset-bottom\)\);\s*\}",
                css,
            )
        )
        self.assert_true(
            has_dock_padding and "pb-8" in shell,
            "B15: Main content must include bottom padding for mobile dock",
        )


class TestB16ExtremelyLongStringsWrapped(TestCase):
    def __init__(self):
        super().__init__("T2_B16_01", "F16", 2, "Long hashes or URLs use break-all or truncate to prevent horizontal blowouts")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        audit = inspector.read_file(AUDIT_RS)
        self.assert_true(bool(audit and "break-all" in audit), "B16: Wide strings in audit payloads must wrap with break-all")


class TestB16NestedFlexContainersDeclareMinWZero(TestCase):
    def __init__(self):
        super().__init__("T2_B16_02", "F16", 2, "Deep flex child containers declare min-w-0")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        shell = inspector.read_file(SHELL_RS)
        self.assert_true(bool(shell and "min-w-0" in shell), "B16: Flex items must declare min-w-0")


class TestB16StickyHeadersRetainedDuringHorizontalScroll(TestCase):
    def __init__(self):
        super().__init__("T2_B16_03", "F16", 2, "DataGrid and tables preserve sticky header alignment")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        grid = inspector.read_file(GRID_RS)
        self.assert_true(bool(grid and "sticky" in grid and "<thead" in grid), "B16: Table headers must maintain sticky alignment")


class TestB16MobileViewportZeroHorizontalShake(TestCase):
    def __init__(self):
        super().__init__("T2_B16_04", "F16", 2, "Body width is constrained to 100% without horizontal canvas shaking")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and ("max-width: 100%" in css or "width: 100%" in css)), "B16: Root layout must prevent horizontal blowout")


class TestB16TouchScrollPhysicsEnabled(TestCase):
    def __init__(self):
        super().__init__("T2_B16_05", "F16", 2, "Horizontal scroll containers use smooth touch scrolling")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS) or ""
        self.assert_true(
            "overflow-x: auto;" in css and "-webkit-overflow-scrolling: touch;" in css,
            "B16: input.css must define horizontal scroll containers with smooth touch scrolling",
        )


class TestB17ZeroPercentAuroraOpacity(TestCase):
    def __init__(self):
        super().__init__("T2_B17_01", "F17", 2, "Theme preference normalizer bounds unknown values cleanly to system/light/dark")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        prefs = inspector.read_file(PREFS_RS) or ""
        self.assert_true(
            "fn normalize_theme(" in prefs
            and '"system" => "system"' in prefs
            and '"light" => "light"' in prefs
            and '_ => "dark"' in prefs,
            "B17: preferences.rs must normalize theme preferences cleanly to system/light/dark",
        )


class TestB17HundredPercentAuroraOpacity(TestCase):
    def __init__(self):
        super().__init__("T2_B17_02", "F17", 2, "High refresh cadence normalizer bounds unknown values cleanly to 120hz/standard/auto")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        prefs = inspector.read_file(PREFS_RS) or ""
        self.assert_true(
            "pub fn normalize_high_refresh_mode(" in prefs
            and '"120hz"' in prefs
            and '"standard"' in prefs
            and '_ => "auto"' in prefs
            and "pub fn resolve_high_refresh_active(" in prefs,
            "B17: preferences.rs must normalize and resolve high-refresh cadence bounds",
        )


class TestB17CorruptedLocalStorageFallback(TestCase):
    def __init__(self):
        super().__init__("T2_B17_03", "F17", 2, "Corrupted or legacy aetherflow-system-storage envelopes fall back cleanly without errors")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        prefs = inspector.read_file(PREFS_RS) or ""
        self.assert_true(
            "fn legacy_storage_envelope(" in prefs
            and "fn hydrate_preferences_with" in prefs
            and "pub fn normalize_touch_mode(" in prefs
            and "aetherflow-system-storage" in prefs
            and "unwrap_or" in prefs,
            "B17: preferences.rs must safely hydrate active preferences and passively ignore unknown legacy keys",
        )


class TestB17HighFrequencyToggleNoMemoryLeak(TestCase):
    def __init__(self):
        super().__init__("T2_B17_04", "F17", 2, "Rapidly toggling reduced motion or display cadence leaks no timers or listeners")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        state = inspector.read_file(STATE_RS) or ""
        self.assert_true(
            "pub fn set_reduced_motion(" in state
            and "pub fn set_high_refresh_mode(" in state
            and "pub fn set_touch_mode(" in state,
            "B17: state.rs must expose reactive display & input preference setters",
        )
        for fn_sig in ("pub fn set_reduced_motion(", "pub fn set_high_refresh_mode(", "pub fn set_touch_mode("):
            start = state.index(fn_sig)
            snippet = state[start:start + 500]
            self.assert_not_in("set_interval", snippet, f"B17: {fn_sig} must not register leaked timers")
            self.assert_not_in("add_event_listener", snippet, f"B17: {fn_sig} must not register leaked listeners")


class TestB17ResetToDefaultsRestoresObsidianTokens(TestCase):
    def __init__(self):
        super().__init__("T2_B17_05", "F17", 2, "Theme DOM sync updates meta[name=theme-color] and retires reset_atmosphere_defaults")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        state = inspector.read_file(STATE_RS) or ""
        prefs = inspector.read_file(PREFS_RS) or ""
        self.assert_true(
            "pub fn toggle_theme(" in state
            and "pub fn set_theme(" in state
            and "pub fn apply_theme_dom(" in prefs
            and "theme-color" in prefs,
            "B17: theme state must synchronize document theme and meta[name=theme-color]",
        )
        self.assert_not_in(
            "reset_atmosphere_defaults",
            state,
            "B17: retired reset_atmosphere_defaults handler must be removed from state.rs",
        )


class TestB18DisabledButtonState(TestCase):
    def __init__(self):
        super().__init__("T2_B18_01", "F18", 2, "Disabled .af-btn uses semantic tokens and cursor: not-allowed without pointer-events: none")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        block = _extract_css_block(css, r"\.af-btn:disabled[^{]*")
        self.assert_true(
            bool(block and "cursor: not-allowed" in block and "--af-control-disabled-bg" in block),
            "B18: input.css must style disabled .af-btn with semantic disabled tokens and cursor: not-allowed",
        )
        self.assert_not_in(
            "pointer-events: none",
            block,
            "B18: disabled .af-btn must not set pointer-events: none so permission tooltips remain accessible",
        )


class TestB18ModalFocusTrapAndEscape(TestCase):
    def __init__(self):
        super().__init__("T2_B18_02", "F18", 2, "Modal traps tab focus and closes upon pressing Escape key")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        primitives = inspector.read_file(PRIMITIVES_RS)
        self.assert_true(
            bool(primitives and "dialog_focusable_elements" in primitives and 'event.key() == "Escape"' in primitives),
            "B18: Modal must trap Tab focus and handle Escape key",
        )


class TestB18InputErrorStateContrast(TestCase):
    def __init__(self):
        super().__init__("T2_B18_03", "F18", 2, "Flat .af-input focus, focus-visible, and disabled states maintain clear border contrast")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(
            bool(
                ".af-input:focus" in css
                and ".af-input:focus-visible" in css
                and ".af-input:disabled" in css
            ),
            "B18: input.css must style .af-input focus, focus-visible, and disabled states",
        )


class TestB18ConsentPageUsesGlassContainers(TestCase):
    def __init__(self):
        super().__init__("T2_B18_04", "F18", 2, "OAuth consent page renders inside ObsCard with flat .af-btn-primary and .af-input controls")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        consent = inspector.read_file(CONSENT_RS) or ""
        has_surface = "ObsCard" in consent and "af-btn-primary" in consent and "af-input" in consent
        self.assert_true(has_surface, "B18: OAuth consent route must use ObsCard, af-btn-primary, and af-input")
        self.assert_not_in("glass-", consent, "B18: OAuth consent route must not retain legacy glass-* classes")


class TestB18DataGridEmptyStateMessage(TestCase):
    def __init__(self):
        super().__init__("T2_B18_05", "F18", 2, "DataGrid with zero rows renders friendly empty state rather than blank box")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        grid = inspector.read_file(GRID_RS)
        self.assert_true(bool(grid and "EmptyState" in grid and "Grid.noMatchingRows" in grid), "B18: DataGrid must handle empty data rows")


def get_tests():
    return [
        TestB13TextContrastRatioCompliant(), TestB13BodyPointerEventsNotBlocked(), TestB13NegativeZIndexStacking(), TestB13OpaqueWrapperDivsPurged(), TestB13PrintStylesDegradeCleanly(),
        TestB14PrefersReducedMotionRespected(), TestB14CardLiftCausesNoLayoutShift(), TestB14GlassSpecularBorderThickness(), TestB14FocusVisibleOutlinesRetained(), TestB14GlassDarkWellsRecessed(),
        TestB15TouchTargetsMinimum44Pixels(), TestB15MobileDrawerBackdropClickCloses(), TestB15ResponsiveBreakpointZeroHydrationError(), TestB15ActiveNavigationIndicatorVisible(), TestB15DockDoesNotObscureBottomContent(),
        TestB16ExtremelyLongStringsWrapped(), TestB16NestedFlexContainersDeclareMinWZero(), TestB16StickyHeadersRetainedDuringHorizontalScroll(), TestB16MobileViewportZeroHorizontalShake(), TestB16TouchScrollPhysicsEnabled(),
        TestB17ZeroPercentAuroraOpacity(), TestB17HundredPercentAuroraOpacity(), TestB17CorruptedLocalStorageFallback(), TestB17HighFrequencyToggleNoMemoryLeak(), TestB17ResetToDefaultsRestoresObsidianTokens(),
        TestB18DisabledButtonState(), TestB18ModalFocusTrapAndEscape(), TestB18InputErrorStateContrast(), TestB18ConsentPageUsesGlassContainers(), TestB18DataGridEmptyStateMessage()
    ]
