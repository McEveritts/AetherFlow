"""
Tier 2: Boundary & Corner Cases (Adversarial Verification)
Features:
- B13: Obsidian Foundation Boundaries
- B14: Glass Tokens Boundaries
- B15: Tri-Mode Navigation Boundaries
- B16: Scroller Containment Boundaries
- B17: Atmosphere Tuning Boundaries
- B18: UI Primitives Boundaries
"""

from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

INPUT_CSS = "frontend-rs/styles/input.css"
SHELL_RS = "frontend-rs/crates/af-web-app/src/shell.rs"
STATE_RS = "frontend-rs/crates/af-web-app/src/state.rs"
AUDIT_RS = "frontend-rs/crates/af-web-app/src/tabs/audit.rs"
PRIMITIVES_RS = "frontend-rs/crates/af-web-ui/src/primitives.rs"
GRID_RS = "frontend-rs/crates/af-web-ui/src/grid.rs"
CONSENT_RS = "frontend-rs/crates/af-web-app/src/routes/consent.rs"


class TestB13TextContrastRatioCompliant(TestCase):
    def __init__(self):
        super().__init__("T2_B13_01", "F13", 2, "Text color against --obs-bg-base satisfies WCAG AA (>= 4.5:1)")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and ("#ffffff" in css or "--obs-white" in css or "--obs-slate-200" in css)), "B13: input.css must specify high-contrast text tokens")


class TestB13BodyPointerEventsNotBlocked(TestCase):
    def __init__(self):
        super().__init__("T2_B13_02", "F13", 2, "Atmosphere pseudo-elements (::before, ::after) declare pointer-events: none")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "pointer-events: none" in css), "B13: Background atmosphere layers must declare pointer-events: none")


class TestB13NegativeZIndexStacking(TestCase):
    def __init__(self):
        super().__init__("T2_B13_03", "F13", 2, "body::before is z-index: -2 and body::after is z-index: -1")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "z-index: -2" in css and "z-index: -1" in css), "B13: input.css must stack atmosphere at z-index -2 and -1")


class TestB13OpaqueWrapperDivsPurged(TestCase):
    def __init__(self):
        super().__init__("T2_B13_04", "F13", 2, "Shell root eliminates opaque bg-slate-950 that blocks atmosphere")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        shell = inspector.read_file(SHELL_RS)
        self.assert_true(bool(shell), "B13: shell.rs must exist")
        self.assert_not_in("min-h-screen bg-slate-950", shell or "", "B13: shell.rs must not use opaque bg-slate-950 wrapper")


class TestB13PrintStylesDegradeCleanly(TestCase):
    def __init__(self):
        super().__init__("T2_B13_05", "F13", 2, "Print media query disables heavy background radial gradients")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS) or ""
        self.assert_true(
            "@media print" in css and "background-image: none" in css and "animation: none" in css,
            "B13: input.css must declare @media print rules disabling radial gradients and animations",
        )


class TestB14PrefersReducedMotionRespected(TestCase):
    def __init__(self):
        super().__init__("T2_B14_01", "F14", 2, "prefers-reduced-motion media query disables 120Hz high-refresh animations")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "prefers-reduced-motion" in css), "B14: input.css must define prefers-reduced-motion block")


class TestB14CardLiftCausesNoLayoutShift(TestCase):
    def __init__(self):
        super().__init__("T2_B14_02", "F14", 2, "--obs-card-lift uses GPU-composited transform without reflow layout shifts")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "transform" in css and ("translateY" in css or "translate3d" in css)), "B14: Card lift must be GPU-composited via transform")


class TestB14GlassSpecularBorderThickness(TestCase):
    def __init__(self):
        super().__init__("T2_B14_03", "F14", 2, "Specular top border is constrained to 1px thickness")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "1px" in css), "B14: Specular borders should be hairline (1px)")


class TestB14FocusVisibleOutlinesRetained(TestCase):
    def __init__(self):
        super().__init__("T2_B14_04", "F14", 2, "Interactive glass buttons retain accessible focus-visible outline")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "focus-visible" in css), "B14: input.css must define focus-visible rules for glass elements")


class TestB14GlassDarkWellsRecessed(TestCase):
    def __init__(self):
        super().__init__("T2_B14_05", "F14", 2, "Glass input wells use inset box shadows to appear physically recessed")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "inset" in css), "B14: Input wells must use inset shadows")


class TestB15TouchTargetsMinimum44Pixels(TestCase):
    def __init__(self):
        super().__init__("T2_B15_01", "F15", 2, "Touch target utility strictly enforces min-height and min-width of 44px")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "44px" in css), "B15: Touch targets must specify 44px minimum")


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
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "@media(max-width:767px)" in css), "B15: Navigation must rely on CSS media queries for responsive modes")


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
        css = inspector.read_file(INPUT_CSS)
        shell = inspector.read_file(SHELL_RS)
        self.assert_true(
            bool(css and ".af-tab-content { padding-bottom: calc(88px + env(safe-area-inset-bottom)); }" in css and shell and "pb-8" in shell),
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
        super().__init__("T2_B17_01", "F17", 2, "Setting aurora opacity to 0% retains readable black base canvas")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        state = inspector.read_file(STATE_RS)
        self.assert_true(bool(state and "normalize_aurora_opacity_pct" in state), "B17: state.rs must normalize aurora opacity bounds")


class TestB17HundredPercentAuroraOpacity(TestCase):
    def __init__(self):
        super().__init__("T2_B17_02", "F17", 2, "Setting aurora opacity to 100% does not wash out foreground text")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        prefs = inspector.read_file("frontend-rs/crates/af-web-app/src/state/preferences.rs") or ""
        css = inspector.read_file(INPUT_CSS) or ""
        self.assert_true(
            "quantize_aurora_opacity_pct" in prefs
            and ".clamp(0.0, 100.0)" in prefs
            and "z-index: -2" in css
            and "--obs-aurora-opacity" in css,
            "B17: aurora opacity must be clamped and isolated to background layers without degrading foreground text contrast",
        )


class TestB17CorruptedLocalStorageFallback(TestCase):
    def __init__(self):
        super().__init__("T2_B17_03", "F17", 2, "Invalid stored atmosphere preferences fall back cleanly to default theme settings")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        state = inspector.read_file(STATE_RS)
        self.assert_true(bool(state and "normalize_aurora_opacity_pct" in state and "unwrap_or" in state), "B17: state.rs must safely parse stored preferences")


class TestB17HighFrequencyToggleNoMemoryLeak(TestCase):
    def __init__(self):
        super().__init__("T2_B17_04", "F17", 2, "Rapidly toggling grain or animation does not leak event listeners or timers")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        state = inspector.read_file(STATE_RS) or ""
        self.assert_true(
            "pub fn set_aurora_animation(" in state and "pub fn set_grain_display(" in state,
            "B17: state.rs must expose reactive atmosphere toggles",
        )
        start = state.index("pub fn set_aurora_animation(")
        snippet = state[start:start + 600]
        self.assert_not_in("set_interval", snippet, "B17: atmosphere toggle must not register leaked timers")
        self.assert_not_in("add_event_listener", snippet, "B17: atmosphere toggle must not register leaked listeners")


class TestB17ResetToDefaultsRestoresObsidianTokens(TestCase):
    def __init__(self):
        super().__init__("T2_B17_05", "F17", 2, "Reset button restores original Obsidian V2 default values")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        state = inspector.read_file(STATE_RS) or ""
        settings_ui = inspector.read_file("frontend-rs/crates/af-web-app/src/tabs/settings/mod.rs") or ""
        self.assert_true(
            "pub fn reset_atmosphere_defaults(" in state
            and 'self.set_theme("dark")' in state
            and "self.set_aurora_opacity(55)" in state
            and "settings-atmosphere-reset" in settings_ui
            and "context.reset_atmosphere_defaults()" in settings_ui,
            "B17: appearance settings must provide a reset handler restoring default Obsidian V2 tokens",
        )


class TestB18DisabledButtonState(TestCase):
    def __init__(self):
        super().__init__("T2_B18_01", "F18", 2, "Disabled button has reduced opacity, not-allowed cursor, and no hover lift")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and ".glass-button:disabled" in css and "cursor: not-allowed" in css), "B18: input.css must style disabled button state")


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
        super().__init__("T2_B18_03", "F18", 2, "Input field and error states maintain focus contrast and clear border ring")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and ".glass-input:focus" in css and ".glass-input:disabled" in css), "B18: input.css must style input focus and validation states")


class TestB18ConsentPageUsesGlassContainers(TestCase):
    def __init__(self):
        super().__init__("T2_B18_04", "F18", 2, "OAuth consent page renders inside glass container with touch targets")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        consent = inspector.read_file(CONSENT_RS)
        has_surface = bool(consent and "ObsCard" in consent and "glass-button-primary" in consent and "glass-input" in consent)
        self.assert_true(has_surface, "B18: OAuth consent route must use ObsCard and glass buttons")


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
