"""
Tier 1: Feature Coverage (Category-Partition & Happy Paths)
Features:
- F13: Unified Flat Canvas Foundation
- F14: Semantic Flat Surface & Control Tokens
- F15: Tri-Mode Navigation Architecture
- F16: Scroller Containment Invariant
- F17: Display & Input Controls
- F18: Flat UI Primitives
"""

import re
from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

INPUT_CSS = "frontend-rs/styles/input.css"
SHELL_RS = "frontend-rs/crates/af-web-app/src/shell.rs"
STATE_RS = "frontend-rs/crates/af-web-app/src/state.rs"
AUDIT_RS = "frontend-rs/crates/af-web-app/src/tabs/audit.rs"
SETTINGS_RS = "frontend-rs/crates/af-web-app/src/tabs/settings/mod.rs"
PRIMITIVES_RS = "frontend-rs/crates/af-web-ui/src/primitives.rs"
GRID_RS = "frontend-rs/crates/af-web-ui/src/grid.rs"
LOGIN_RS = "frontend-rs/crates/af-web-app/src/routes/login.rs"


def _strip_css_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css or "", flags=re.DOTALL)


def _extract_css_block(css: str, selector_pattern: str) -> str:
    match = re.search(rf"{selector_pattern}\s*\{{([^}}]*)\}}", css, flags=re.DOTALL)
    return match.group(1) if match else ""


class TestF13PureBlackFoundation(TestCase):
    def __init__(self):
        super().__init__("T1_F13_01", "F13", 1, "input.css defines dark and light flat canvas foundation tokens with --obs-bg-base alias")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        root_block = _extract_css_block(css, r":root")
        light_block = _extract_css_block(css, r'html\[data-theme="light"\]')
        dark_match = re.search(r"--af-bg-canvas\s*:\s*#([0-9a-fA-F]{6})\s*;", root_block)
        light_match = re.search(r"--af-bg-canvas\s*:\s*#([0-9a-fA-F]{6})\s*;", light_block)
        self.assert_true(
            bool(
                dark_match
                and light_match
                and "--obs-bg-base: var(--af-bg-canvas);" in root_block
                and "var(--af-bg-canvas)" in css
            ),
            "F13: input.css must define dark and light --af-bg-canvas tokens and retain --obs-bg-base alias",
        )
        dark_channels = [int(dark_match.group(1)[offset:offset + 2], 16) for offset in (0, 2, 4)]
        light_channels = [int(light_match.group(1)[offset:offset + 2], 16) for offset in (0, 2, 4)]
        self.assert_true(max(dark_channels) <= 48, "F13: dark --af-bg-canvas foundation must remain dark")
        self.assert_true(min(light_channels) >= 220, "F13: light --af-bg-canvas foundation must remain light")


class TestF13BodyBeforeAuroraGradients(TestCase):
    def __init__(self):
        super().__init__("T1_F13_02", "F13", 1, "input.css eliminates retired body::before aurora gradients and keyframes")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(bool(css), "F13: input.css must be readable")
        self.assert_not_in("body::before", css, "F13: retired body::before aurora layer must be absent")
        self.assert_not_in("obs-aurora-shift", css, "F13: retired obs-aurora-shift keyframes must be absent")
        self.assert_not_in("data-aurora-opacity", css, "F13: retired data-aurora-opacity selectors must be absent")
        self.assert_not_in("data-aurora-animation", css, "F13: retired data-aurora-animation selectors must be absent")


class TestF13BodyAfterMicroGrain(TestCase):
    def __init__(self):
        super().__init__("T1_F13_03", "F13", 1, "input.css eliminates retired body::after tactile grain and SVG fractalNoise")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(bool(css), "F13: input.css must be readable")
        self.assert_not_in("body::after", css, "F13: retired body::after grain layer must be absent")
        self.assert_not_in("fractalNoise", css, "F13: retired SVG fractalNoise texture must be absent")
        self.assert_not_in("data-grain", css, "F13: retired data-grain selectors must be absent")


class TestF13HardwareAcceleratedAtmosphere(TestCase):
    def __init__(self):
        super().__init__("T1_F13_04", "F13", 1, "input.css forbids backdrop-filter blur across desktop, mobile, and touch rules")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(bool(css), "F13: input.css must be readable")
        self.assert_not_in("backdrop-filter", css, "F13: input.css must contain zero backdrop-filter declarations")
        self.assert_not_in("-webkit-backdrop-filter", css, "F13: input.css must contain zero -webkit-backdrop-filter declarations")


class TestF13TransparentBodyCanvas(TestCase):
    def __init__(self):
        super().__init__("T1_F13_05", "F13", 1, "html and body apply solid flat canvas background and primary foreground tokens")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        html_block = _extract_css_block(css, r"\bhtml")
        body_block = _extract_css_block(css, r"\bbody")
        self.assert_true(
            "background-color: var(--af-bg-canvas);" in html_block
            and "color: var(--af-fg-primary);" in html_block
            and "background-color: var(--af-bg-canvas);" in body_block
            and "background-image: none;" in body_block
            and "color: var(--af-fg-primary);" in body_block,
            "F13: html and body must apply solid --af-bg-canvas fill with --af-fg-primary text and background-image: none",
        )


class TestF14SpecularTopBorderToken(TestCase):
    def __init__(self):
        super().__init__("T1_F14_01", "F14", 1, "Semantic --af-* surface, hairline, and control tokens replace specular glass tokens")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        root_block = _extract_css_block(css, r":root")
        light_block = _extract_css_block(css, r'html\[data-theme="light"\]')
        required_tokens = (
            "--af-surface-card:",
            "--af-surface-inset:",
            "--af-surface-overlay:",
            "--af-border-hairline:",
            "--af-border-card:",
            "--af-border-control:",
            "--af-control-bg:",
            "--af-accent-bg:",
        )
        for token in required_tokens:
            self.assert_true(
                token in root_block and token in light_block,
                f"F14: input.css must define {token} in both :root and html[data-theme=\"light\"]",
            )
        self.assert_not_in("--obs-specular-", css, "F14: retired --obs-specular-* tokens must be removed")


class TestF14ChromaticEdgeGradientToken(TestCase):
    def __init__(self):
        super().__init__("T1_F14_02", "F14", 1, "Flat components live in @layer components with @theme inline and zero chromatic edge tokens")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(
            "@layer components" in css and "@theme inline" in css,
            "F14: input.css must define @theme inline and @layer components",
        )
        self.assert_not_in("--obs-chromatic-", css, "F14: retired --obs-chromatic-* tokens must be removed")
        self.assert_not_in("mask-composite", css, "F14: chromatic mask-composite rims must be removed")


class TestF14HighRefreshSpringTiming(TestCase):
    def __init__(self):
        super().__init__("T1_F14_03", "F14", 1, "--obs-ease-spring-120 high refresh curve and cadence duration tokens are defined")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(
            "--obs-ease-spring-120" in css
            and "--obs-duration-fast" in css
            and "--obs-duration-card" in css
            and 'html[data-high-refresh="true"]' in css,
            "F14: input.css must define --obs-ease-spring-120 and high-refresh duration tokens",
        )


class TestF14GlassCardUtilityClass(TestCase):
    def __init__(self):
        super().__init__("T1_F14_04", "F14", 1, ".af-card flat surface class renders matte fill and 1px hairline without hover lift")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(
            ".af-card" in css
            and ".af-card-interactive" in css
            and ".af-surface-inset" in css
            and "background-color: var(--af-surface-card);" in css
            and "border: 1px solid var(--af-border-card);" in css,
            "F14: input.css must define flat .af-card, .af-card-interactive, and .af-surface-inset classes",
        )
        self.assert_not_in("--obs-card-lift", css, "F14: retired --obs-card-lift token must be removed")
        self.assert_not_in("data-card-lift", css, "F14: retired data-card-lift selector must be removed")


class TestF14GlassButtonPrimaryGradient(TestCase):
    def __init__(self):
        super().__init__("T1_F14_05", "F14", 1, ".af-btn-primary uses solid flat indigo fill without chromatic gradients or hover scale")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(
            ".af-btn-primary" in css
            and ".af-btn" in css
            and '.af-btn[data-tone="danger"]' in css
            and "background-color: var(--af-accent-bg);" in css,
            "F14: input.css must define flat .af-btn, .af-btn-primary, and semantic tone variants",
        )
        self.assert_not_in("scale3d(1.025", css, "F14: .af-btn-primary must not use glossy hover scale transforms")


class TestF15MobileBottomDockDefined(TestCase):
    def __init__(self):
        super().__init__("T1_F15_01", "F15", 1, "Mobile bottom dock component is rendered in shell.rs and styled in input.css")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        shell = inspector.read_file(SHELL_RS)
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(
            bool(shell and "af-mobile-dock" in shell and css and ".af-mobile-dock" in css and "position: fixed" in css),
            "F15: Mobile bottom dock must be implemented in shell.rs and input.css",
        )


class TestF15DesktopExpandableRail(TestCase):
    def __init__(self):
        super().__init__("T1_F15_02", "F15", 1, "Desktop sidebar expands from icon rail to full navigation panel")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        shell = inspector.read_file(SHELL_RS)
        css = inspector.read_file(INPUT_CSS)
        has_rail = bool(
            shell
            and css
            and "af-sidebar-expanded" in shell
            and "aria-expanded=move || pinned.get().to_string()" in shell
            and "/img/aetherflow-mark.svg" in shell
            and ".af-sidebar {" in css
            and ".af-sidebar-expanded {" in css
        )
        self.assert_true(has_rail, "F15: Sidebar must expose the logo toggle and distinct collapsed/expanded desktop widths")


class TestF15TouchTargetEnforcement(TestCase):
    def __init__(self):
        super().__init__("T1_F15_03", "F15", 1, "Mobile navigation items enforce min 44px touch targets")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        has_touch = bool(css and ("obs-touch-target" in css or "min-height: 44px" in css))
        self.assert_true(has_touch, "F15: Mobile navigation items must enforce >=44px touch targets")


class TestF15ConnectionStatusBeacons(TestCase):
    def __init__(self):
        super().__init__("T1_F15_04", "F15", 1, "obs-beacon-* utility classes style live/reconnecting/danger beacons")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "obs-beacon" in css), "F15: input.css must define obs-beacon-* status indicators")


class TestF15SafeAreaInsetPadding(TestCase):
    def __init__(self):
        super().__init__("T1_F15_05", "F15", 1, "Mobile dock applies safe-area-inset-bottom padding")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "safe-area-inset-bottom" in css), "F15: Mobile dock must account for safe-area-inset-bottom")


class TestF16ZeroBlanketOverflowHidden(TestCase):
    def __init__(self):
        super().__init__("T1_F16_01", "F16", 1, "Zero blanket 'overflow-x: hidden' on html or body tags in input.css")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css), "F16: input.css must be readable")
        clean_css = _strip_css_comments(css or "")
        pattern = re.compile(r'(html|body)\s*\{[^}]*overflow-x:\s*hidden', re.IGNORECASE)
        self.assert_false(bool(pattern.search(clean_css)), "F16: input.css must not violate scroller containment with overflow-x: hidden on html/body")


class TestF16LayoutUsesMinWZero(TestCase):
    def __init__(self):
        super().__init__("T1_F16_02", "F16", 1, "Main content area uses min-w-0 to prevent flex item blowout")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        shell = inspector.read_file(SHELL_RS)
        self.assert_true(bool(shell and "min-w-0" in shell), "F16: Main shell layout must declare min-w-0 on flex containers")


class TestF16AuditTabScopedOverflow(TestCase):
    def __init__(self):
        super().__init__("T1_F16_03", "F16", 1, "Audit tab scopes wide tables and payloads inside DataGrid / overflow-auto")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        audit_code = inspector.read_file(AUDIT_RS)
        self.assert_true(bool(audit_code and "<DataGrid" in audit_code and "overflow-auto" in audit_code), "F16: Audit tab must manage horizontal scroll via DataGrid and overflow-auto")


class TestF16DataGridScrollerContainment(TestCase):
    def __init__(self):
        super().__init__("T1_F16_04", "F16", 1, "DataGrid primitive encapsulates wide tabular layouts")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        grid_code = inspector.read_file(GRID_RS)
        self.assert_true(bool(grid_code and "obs-scroller" in grid_code and "min-w-0" in grid_code), "F16: DataGrid must contain horizontal table overflow")


class TestF16NoRootPageClipping(TestCase):
    def __init__(self):
        super().__init__("T1_F16_05", "F16", 1, "shell.rs root container does not truncate sticky headers with overflow-hidden")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        shell_code = inspector.read_file(SHELL_RS)
        self.assert_true(bool(shell_code and "af-shell" in shell_code), "F16: shell.rs must be readable")


class TestF17AuroraIntensityControl(TestCase):
    def __init__(self):
        super().__init__("T1_F17_01", "F17", 1, "Settings tab exposes high-refresh cadence control and retires aurora opacity")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        settings = inspector.read_file(SETTINGS_RS) or ""
        self.assert_true(
            "settings-high-refresh-mode" in settings,
            "F17: Settings tab must expose settings-high-refresh-mode cadence control",
        )
        self.assert_not_in(
            "settings-aurora-opacity",
            settings,
            "F17: retired settings-aurora-opacity control must be removed from settings/mod.rs",
        )


class TestF17AnimationToggleControl(TestCase):
    def __init__(self):
        super().__init__("T1_F17_02", "F17", 1, "Settings tab exposes touch mode control and retires aurora animation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        settings = inspector.read_file(SETTINGS_RS) or ""
        self.assert_true(
            "settings-touch-mode" in settings,
            "F17: Settings tab must expose settings-touch-mode control",
        )
        self.assert_not_in(
            "settings-aurora-animation",
            settings,
            "F17: retired settings-aurora-animation control must be removed from settings/mod.rs",
        )


class TestF17MicroGrainToggleControl(TestCase):
    def __init__(self):
        super().__init__("T1_F17_03", "F17", 1, "Settings tab exposes reduced-motion control and retires tactile grain")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        settings = inspector.read_file(SETTINGS_RS) or ""
        self.assert_true(
            'id="settings-reduced-motion"' in settings
            and "settings-reduced-motion-hint" in settings
            and "set_reduced_motion" in settings,
            "F17: Settings tab must expose settings-reduced-motion checkbox and reduced-motion status hint",
        )
        self.assert_not_in(
            "settings-grain-display",
            settings,
            "F17: retired settings-grain-display control must be removed from settings/mod.rs",
        )


class TestF17CardLiftDensityControl(TestCase):
    def __init__(self):
        super().__init__("T1_F17_04", "F17", 1, "Settings tab provides immersive layout density control and retires card hover lift")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        settings = inspector.read_file(SETTINGS_RS) or ""
        self.assert_true(
            "immersive_overview" in settings,
            "F17: Settings tab must provide immersive_overview layout density control",
        )
        self.assert_not_in(
            "settings-card-lift",
            settings,
            "F17: retired settings-card-lift control must be removed from settings/mod.rs",
        )


class TestF17AtmosphereSettingsPersistence(TestCase):
    def __init__(self):
        super().__init__("T1_F17_05", "F17", 1, "Display, theme, and touch preferences persist in localStorage via state.rs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        state = inspector.read_file(STATE_RS) or ""
        self.assert_true(
            "aetherflow-theme" in state
            and "aetherflow-high-refresh-mode" in state
            and "aetherflow-touch-mode" in state
            and "storage_set" in state,
            "F17: Display, theme, and touch preferences must persist in localStorage via storage_set",
        )
        self.assert_not_in(
            'storage_set("aetherflow-aurora-opacity"',
            state,
            "F17: retired aetherflow-aurora-opacity writes must be removed from state.rs",
        )
        self.assert_not_in(
            "set_aurora_opacity",
            state,
            "F17: retired set_aurora_opacity setter must be removed from state.rs",
        )
        self.assert_not_in(
            "set_card_lift",
            state,
            "F17: retired set_card_lift setter must be removed from state.rs",
        )


class TestF18CardPrimitiveUpgraded(TestCase):
    def __init__(self):
        super().__init__("T1_F18_01", "F18", 1, "ObsCard primitive renders flat .af-card surface without legacy glass classes")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        primitives = inspector.read_file(PRIMITIVES_RS) or ""
        self.assert_true(
            "pub fn ObsCard" in primitives and "af-card" in primitives and "af-card-interactive" in primitives,
            "F18: ObsCard must emit flat .af-card / .af-card-interactive classes",
        )
        self.assert_not_in("glass-card", primitives, "F18: primitives.rs must not emit legacy glass-card")


class TestF18ButtonPrimitiveUpgraded(TestCase):
    def __init__(self):
        super().__init__("T1_F18_02", "F18", 1, "Button primitive variants use flat .af-btn and .af-btn-primary with semantic tones")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        primitives = inspector.read_file(PRIMITIVES_RS) or ""
        self.assert_true(
            "pub fn Button" in primitives
            and "af-btn-primary" in primitives
            and "af-btn " in primitives
            and "data-tone" in primitives,
            "F18: Button must emit flat .af-btn, .af-btn-primary, and semantic data-tone attributes",
        )
        self.assert_not_in("glass-button", primitives, "F18: primitives.rs must not emit legacy glass-button")


class TestF18InputPrimitiveRecessedWell(TestCase):
    def __init__(self):
        super().__init__("T1_F18_03", "F18", 1, "SearchInput and .af-input render flat control surface with focus styling")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        primitives = inspector.read_file(PRIMITIVES_RS) or ""
        css = _strip_css_comments(inspector.read_file(INPUT_CSS) or "")
        self.assert_true(
            "af-input" in primitives and ".af-input:focus" in css,
            "F18: SearchInput and input.css must implement flat .af-input and .af-input:focus styling",
        )
        self.assert_not_in("glass-input", primitives, "F18: primitives.rs must not emit legacy glass-input")


class TestF18ModalPrimitiveGlassPanel(TestCase):
    def __init__(self):
        super().__init__("T1_F18_04", "F18", 1, "Modal primitive renders opaque .af-modal dialog without glass-card or af-card")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        primitives = inspector.read_file(PRIMITIVES_RS) or ""
        self.assert_true(
            "pub fn Modal" in primitives and "af-modal min-w-0 max-w-full" in primitives,
            "F18: Modal must render opaque .af-modal dialog",
        )
        self.assert_not_in("af-modal glass-card", primitives, "F18: Modal must not combine .af-modal with glass-card")
        self.assert_not_in("af-modal af-card", primitives, "F18: Modal must not combine .af-modal with af-card")


class TestF18LoginPageObsidianStyling(TestCase):
    def __init__(self):
        super().__init__("T1_F18_05", "F18", 1, "login.rs renders flat .af-card surface with flattened brand mark")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        login = inspector.read_file(LOGIN_RS) or ""
        self.assert_true(
            "af-card" in login and "obs-brand-logo" in login,
            "F18: login.rs must render flat .af-card surface and obs-brand-logo",
        )
        self.assert_not_in("glass-card", login, "F18: login.rs must not use legacy glass-card")


def get_tests():
    return [
        TestF13PureBlackFoundation(), TestF13BodyBeforeAuroraGradients(), TestF13BodyAfterMicroGrain(), TestF13HardwareAcceleratedAtmosphere(), TestF13TransparentBodyCanvas(),
        TestF14SpecularTopBorderToken(), TestF14ChromaticEdgeGradientToken(), TestF14HighRefreshSpringTiming(), TestF14GlassCardUtilityClass(), TestF14GlassButtonPrimaryGradient(),
        TestF15MobileBottomDockDefined(), TestF15DesktopExpandableRail(), TestF15TouchTargetEnforcement(), TestF15ConnectionStatusBeacons(), TestF15SafeAreaInsetPadding(),
        TestF16ZeroBlanketOverflowHidden(), TestF16LayoutUsesMinWZero(), TestF16AuditTabScopedOverflow(), TestF16DataGridScrollerContainment(), TestF16NoRootPageClipping(),
        TestF17AuroraIntensityControl(), TestF17AnimationToggleControl(), TestF17MicroGrainToggleControl(), TestF17CardLiftDensityControl(), TestF17AtmosphereSettingsPersistence(),
        TestF18CardPrimitiveUpgraded(), TestF18ButtonPrimitiveUpgraded(), TestF18InputPrimitiveRecessedWell(), TestF18ModalPrimitiveGlassPanel(), TestF18LoginPageObsidianStyling()
    ]
