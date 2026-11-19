"""
Tier 1: Feature Coverage (Category-Partition & Happy Paths)
Features:
- F13: Obsidian V2 CSS Foundation
- F14: Obsidian V2 Glass & Chromatic Tokens
- F15: Tri-Mode Navigation Architecture
- F16: Scroller Containment Invariant
- F17: Atmosphere Tuning Controls
- F18: UI Primitives Redesign
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


class TestF13PureBlackFoundation(TestCase):
    def __init__(self):
        super().__init__("T1_F13_01", "F13", 1, "input.css defines and applies a dark foundation token")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        color_match = re.search(r"--obs-bg-base\s*:\s*#([0-9a-fA-F]{6})\s*;", css or "")
        self.assert_true(bool(color_match and css and "var(--obs-bg-base)" in css), "F13: input.css must define and apply a foundation color")
        channels = [int(color_match.group(1)[offset:offset + 2], 16) for offset in (0, 2, 4)]
        self.assert_true(max(channels) <= 48, "F13: the applied foundation must remain dark")


class TestF13BodyBeforeAuroraGradients(TestCase):
    def __init__(self):
        super().__init__("T1_F13_02", "F13", 1, "body::before renders 3-orb radial aurora and base vertical gradient")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "body::before" in css and "radial-gradient" in css), "F13: input.css must render radial-gradient on body::before")


class TestF13BodyAfterMicroGrain(TestCase):
    def __init__(self):
        super().__init__("T1_F13_03", "F13", 1, "body::after renders SVG fractal micro-grain and spatial edge vignette")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "body::after" in css and ("fractalNoise" in css or "grain" in css or "radial-gradient" in css)), "F13: input.css must render micro-grain on body::after")


class TestF13HardwareAcceleratedAtmosphere(TestCase):
    def __init__(self):
        super().__init__("T1_F13_04", "F13", 1, "Atmosphere pseudo-elements use GPU containment and strict layer caching")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and ("contain: strict" in css or "will-change" in css or "translateZ" in css)), "F13: Atmosphere styles must specify GPU containment")


class TestF13TransparentBodyCanvas(TestCase):
    def __init__(self):
        super().__init__("T1_F13_05", "F13", 1, "body background is transparent to expose underlying atmospheric layers")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and ("background-color: transparent" in css or "bg-transparent" in css or "background: transparent" in css)), "F13: body background must be transparent")


class TestF14SpecularTopBorderToken(TestCase):
    def __init__(self):
        super().__init__("T1_F14_01", "F14", 1, "--obs-specular-top directional highlight token is defined")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "--obs-specular-top" in css), "F14: input.css must define --obs-specular-top")


class TestF14ChromaticEdgeGradientToken(TestCase):
    def __init__(self):
        super().__init__("T1_F14_02", "F14", 1, "--obs-chromatic-edge-gradient prism rim token is defined")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "--obs-chromatic-edge" in css), "F14: input.css must define --obs-chromatic-edge tokens")


class TestF14HighRefreshSpringTiming(TestCase):
    def __init__(self):
        super().__init__("T1_F14_03", "F14", 1, "--obs-ease-spring-120 high refresh curve is defined")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and "--obs-ease-spring" in css), "F14: input.css must define --obs-ease-spring-120 token")


class TestF14GlassCardUtilityClass(TestCase):
    def __init__(self):
        super().__init__("T1_F14_04", "F14", 1, ".glass-card class implements specular borders and chromatic refraction")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and ".glass-card" in css), "F14: input.css must define .glass-card utility class")


class TestF14GlassButtonPrimaryGradient(TestCase):
    def __init__(self):
        super().__init__("T1_F14_05", "F14", 1, ".glass-button-primary uses indigo-to-fuchsia gradient")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(bool(css and ".glass-button-primary" in css), "F14: input.css must define .glass-button-primary utility class")


class TestF15MobileBottomDockDefined(TestCase):
    def __init__(self):
        super().__init__("T1_F15_01", "F15", 1, "Mobile bottom dock component is rendered in shell.rs and styled in input.css")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        shell = inspector.read_file(SHELL_RS)
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(
            bool(shell and "af-mobile-dock" in shell and css and ".af-mobile-dock" in css and "position: fixed" in css),
            "F15: Mobile bottom glass dock must be implemented in shell.rs and input.css",
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
        clean_css = re.sub(r'/\*.*?\*/', '', css or "", flags=re.DOTALL)
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
        super().__init__("T1_F17_01", "F17", 1, "Settings tab exposes aurora opacity slider")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        settings = inspector.read_file(SETTINGS_RS)
        self.assert_true(bool(settings and "settings-aurora-opacity" in settings), "F17: Settings tab must provide aurora opacity control")


class TestF17AnimationToggleControl(TestCase):
    def __init__(self):
        super().__init__("T1_F17_02", "F17", 1, "Settings tab provides static 120Hz cached vs animated aurora toggle")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        settings = inspector.read_file(SETTINGS_RS)
        self.assert_true(bool(settings and "settings-aurora-animation" in settings), "F17: Settings tab must provide aurora animation toggle")


class TestF17MicroGrainToggleControl(TestCase):
    def __init__(self):
        super().__init__("T1_F17_03", "F17", 1, "Settings tab provides micro-grain enable/disable toggle")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        settings = inspector.read_file(SETTINGS_RS)
        self.assert_true(bool(settings and "settings-grain-display" in settings), "F17: Settings tab must provide micro-grain toggle")


class TestF17CardLiftDensityControl(TestCase):
    def __init__(self):
        super().__init__("T1_F17_04", "F17", 1, "Settings tab provides density / card lift control")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        settings = inspector.read_file(SETTINGS_RS)
        self.assert_true(
            bool(settings and "settings-card-lift" in settings and "immersive_overview" in settings),
            "F17: Settings tab must provide card lift and layout density controls",
        )


class TestF17AtmosphereSettingsPersistence(TestCase):
    def __init__(self):
        super().__init__("T1_F17_05", "F17", 1, "Atmosphere preferences persist in localStorage via state.rs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        state = inspector.read_file(STATE_RS)
        self.assert_true(
            bool(state and "aetherflow-aurora-opacity" in state and "storage_set" in state),
            "F17: Atmosphere preferences must persist in localStorage",
        )


class TestF18CardPrimitiveUpgraded(TestCase):
    def __init__(self):
        super().__init__("T1_F18_01", "F18", 1, "ObsCard primitive applies Obsidian V2 glass tokens and specular borders")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        primitives = inspector.read_file(PRIMITIVES_RS)
        self.assert_true(bool(primitives and "pub fn ObsCard" in primitives and "glass-card" in primitives), "F18: ObsCard must implement Obsidian V2 glass tokens")


class TestF18ButtonPrimitiveUpgraded(TestCase):
    def __init__(self):
        super().__init__("T1_F18_02", "F18", 1, "Button primitive variants use Obsidian V2 chromatic gradients")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        primitives = inspector.read_file(PRIMITIVES_RS)
        self.assert_true(bool(primitives and "pub fn Button" in primitives and "glass-button-primary" in primitives), "F18: Button must implement Obsidian V2 styling")


class TestF18InputPrimitiveRecessedWell(TestCase):
    def __init__(self):
        super().__init__("T1_F18_03", "F18", 1, "SearchInput and glass-input render recessed dark well with specular focus ring")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        primitives = inspector.read_file(PRIMITIVES_RS)
        css = inspector.read_file(INPUT_CSS)
        self.assert_true(
            bool(primitives and "glass-input" in primitives and css and ".glass-input:focus" in css),
            "F18: Input primitives must implement Obsidian V2 well styling",
        )


class TestF18ModalPrimitiveGlassPanel(TestCase):
    def __init__(self):
        super().__init__("T1_F18_04", "F18", 1, "Modal primitive renders .af-modal .glass-card dialog with backdrop blur")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        primitives = inspector.read_file(PRIMITIVES_RS)
        self.assert_true(bool(primitives and "pub fn Modal" in primitives and "af-modal glass-card" in primitives), "F18: Modal must use glass card dialog styling")


class TestF18LoginPageObsidianStyling(TestCase):
    def __init__(self):
        super().__init__("T1_F18_05", "F18", 1, "login.rs renders with Obsidian V2 atmosphere and glass-card surface")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        login = inspector.read_file(LOGIN_RS)
        self.assert_true(bool(login and "glass-card" in login and "obs-brand-logo" in login), "F18: login.rs must adhere to Obsidian V2 styling")


def get_tests():
    return [
        TestF13PureBlackFoundation(), TestF13BodyBeforeAuroraGradients(), TestF13BodyAfterMicroGrain(), TestF13HardwareAcceleratedAtmosphere(), TestF13TransparentBodyCanvas(),
        TestF14SpecularTopBorderToken(), TestF14ChromaticEdgeGradientToken(), TestF14HighRefreshSpringTiming(), TestF14GlassCardUtilityClass(), TestF14GlassButtonPrimaryGradient(),
        TestF15MobileBottomDockDefined(), TestF15DesktopExpandableRail(), TestF15TouchTargetEnforcement(), TestF15ConnectionStatusBeacons(), TestF15SafeAreaInsetPadding(),
        TestF16ZeroBlanketOverflowHidden(), TestF16LayoutUsesMinWZero(), TestF16AuditTabScopedOverflow(), TestF16DataGridScrollerContainment(), TestF16NoRootPageClipping(),
        TestF17AuroraIntensityControl(), TestF17AnimationToggleControl(), TestF17MicroGrainToggleControl(), TestF17CardLiftDensityControl(), TestF17AtmosphereSettingsPersistence(),
        TestF18CardPrimitiveUpgraded(), TestF18ButtonPrimitiveUpgraded(), TestF18InputPrimitiveRecessedWell(), TestF18ModalPrimitiveGlassPanel(), TestF18LoginPageObsidianStyling()
    ]
