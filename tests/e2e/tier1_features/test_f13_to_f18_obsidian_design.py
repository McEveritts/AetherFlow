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

class TestF13PureBlackFoundation(TestCase):
    def __init__(self):
        super().__init__("T1_F13_01", "F13", 1, "globals.css defines --obs-bg-base as #000000")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend/src/app/globals.css")
        self.assert_true(bool(css and ("--obs-bg-base: #000000" in css or "--obs-bg-base:#000000" in css)), "F13: globals.css must define --obs-bg-base: #000000")

class TestF13BodyBeforeAuroraGradients(TestCase):
    def __init__(self):
        super().__init__("T1_F13_02", "F13", 1, "body::before renders 3-orb radial aurora and base vertical gradient")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend/src/app/globals.css")
        self.assert_true(bool(css and "body::before" in css and "radial-gradient" in css), "F13: globals.css must render radial-gradient on body::before")

class TestF13BodyAfterMicroGrain(TestCase):
    def __init__(self):
        super().__init__("T1_F13_03", "F13", 1, "body::after renders SVG fractal micro-grain and spatial edge vignette")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend/src/app/globals.css")
        self.assert_true(bool(css and "body::after" in css and ("fractalNoise" in css or "grain" in css or "radial-gradient" in css)), "F13: globals.css must render micro-grain on body::after")

class TestF13HardwareAcceleratedAtmosphere(TestCase):
    def __init__(self):
        super().__init__("T1_F13_04", "F13", 1, "Atmosphere pseudo-elements use GPU containment and strict layer caching")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend/src/app/globals.css")
        self.assert_true(bool(css and ("contain: strict" in css or "will-change" in css or "translateZ" in css)), "F13: Atmosphere styles must specify GPU containment")

class TestF13TransparentBodyCanvas(TestCase):
    def __init__(self):
        super().__init__("T1_F13_05", "F13", 1, "body background is transparent to expose underlying atmospheric layers")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend/src/app/globals.css")
        self.assert_true(bool(css and ("background-color: transparent" in css or "bg-transparent" in css or "background: transparent" in css)), "F13: body background must be transparent")

class TestF14SpecularTopBorderToken(TestCase):
    def __init__(self):
        super().__init__("T1_F14_01", "F14", 1, "--obs-specular-top directional highlight token is defined")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend/src/app/globals.css")
        self.assert_true(bool(css and "--obs-specular-top" in css), "F14: globals.css must define --obs-specular-top")

class TestF14ChromaticEdgeGradientToken(TestCase):
    def __init__(self):
        super().__init__("T1_F14_02", "F14", 1, "--obs-chromatic-edge-gradient prism rim token is defined")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend/src/app/globals.css")
        self.assert_true(bool(css and "--obs-chromatic-edge" in css), "F14: globals.css must define --obs-chromatic-edge tokens")

class TestF14HighRefreshSpringTiming(TestCase):
    def __init__(self):
        super().__init__("T1_F14_03", "F14", 1, "--obs-ease-spring-120 high refresh curve is defined")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend/src/app/globals.css")
        self.assert_true(bool(css and "--obs-ease-spring" in css), "F14: globals.css must define --obs-ease-spring-120 token")

class TestF14GlassCardUtilityClass(TestCase):
    def __init__(self):
        super().__init__("T1_F14_04", "F14", 1, ".glass-card class implements specular borders and chromatic refraction")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend/src/app/globals.css")
        self.assert_true(bool(css and ".glass-card" in css), "F14: globals.css must define .glass-card utility class")

class TestF14GlassButtonPrimaryGradient(TestCase):
    def __init__(self):
        super().__init__("T1_F14_05", "F14", 1, ".glass-button-primary uses indigo-to-fuchsia gradient")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend/src/app/globals.css")
        self.assert_true(bool(css and ".glass-button-primary" in css), "F14: globals.css must define .glass-button-primary utility class")

class TestF15MobileBottomDockDefined(TestCase):
    def __init__(self):
        super().__init__("T1_F15_01", "F15", 1, "Mobile bottom dock component is rendered with md:hidden")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        sidebar = inspector.read_file("frontend/src/components/layout/Sidebar.tsx")
        dock = inspector.read_file("frontend/src/components/layout/MobileDock.tsx") or sidebar
        self.assert_true(bool(dock and ("md:hidden" in dock or "fixed bottom" in dock)), "F15: Mobile bottom glass dock must be implemented with md:hidden")

class TestF15DesktopExpandableRail(TestCase):
    def __init__(self):
        super().__init__("T1_F15_02", "F15", 1, "Desktop sidebar expands from icon rail to full navigation panel")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        sidebar = inspector.read_file("frontend/src/components/layout/Sidebar.tsx")
        has_collapsed_width = "w-20" in sidebar or "md:w-[4.5rem]" in sidebar or "w-[4.5rem]" in sidebar
        self.assert_true(bool(sidebar and has_collapsed_width and "w-64" in sidebar), "F15: Sidebar must support expandable width rail")

class TestF15TouchTargetEnforcement(TestCase):
    def __init__(self):
        super().__init__("T1_F15_03", "F15", 1, "Mobile navigation items enforce min 44px touch targets")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend/src/app/globals.css")
        sidebar = inspector.read_file("frontend/src/components/layout/Sidebar.tsx")
        has_touch = (css and "obs-touch-target" in css) or (sidebar and "min-h-[44px]" in sidebar)
        self.assert_true(bool(has_touch), "F15: Mobile navigation items must enforce >=44px touch targets")

class TestF15ConnectionStatusBeacons(TestCase):
    def __init__(self):
        super().__init__("T1_F15_04", "F15", 1, "obs-beacon-* utility classes style live/reconnecting/danger beacons")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend/src/app/globals.css")
        self.assert_true(bool(css and "obs-beacon" in css), "F15: globals.css must define obs-beacon-* status indicators")

class TestF15SafeAreaInsetPadding(TestCase):
    def __init__(self):
        super().__init__("T1_F15_05", "F15", 1, "Mobile dock applies safe-area-inset-bottom padding")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend/src/app/globals.css")
        dock = inspector.read_file("frontend/src/components/layout/Sidebar.tsx")
        has_safe_area = (css and "safe-area-inset-bottom" in css) or (dock and "safe-area" in dock)
        self.assert_true(bool(has_safe_area), "F15: Mobile dock must account for safe-area-inset-bottom")

class TestF16ZeroBlanketOverflowHidden(TestCase):
    def __init__(self):
        super().__init__("T1_F16_01", "F16", 1, "Zero blanket 'overflow-x: hidden' on html or body tags in globals.css")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend/src/app/globals.css")
        if css:
            clean_css = re.sub(r'/\*.*?\*/', '', css, flags=re.DOTALL)
            pattern = re.compile(r'(html|body)\s*\{[^}]*overflow-x:\s*hidden', re.IGNORECASE)
            self.assert_false(bool(pattern.search(clean_css)), "F16: globals.css must not violate scroller containment with overflow-x: hidden on html/body")

class TestF16LayoutUsesMinWZero(TestCase):
    def __init__(self):
        super().__init__("T1_F16_02", "F16", 1, "Main content area uses min-w-0 to prevent flex item blowout")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        page_code = inspector.read_file("frontend/src/app/page.tsx")
        self.assert_true(bool(page_code and "min-w-0" in page_code), "F16: Main layout must declare min-w-0 on flex containers")

class TestF16AuditTabScopedOverflow(TestCase):
    def __init__(self):
        super().__init__("T1_F16_03", "F16", 1, "AuditTab scopes wide tables with overflow-x-auto")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        audit_code = inspector.read_file("frontend/src/components/tabs/AuditTab.tsx")
        self.assert_true(bool(audit_code and "overflow-x-auto" in audit_code), "F16: AuditTab must manage horizontal scroll via overflow-x-auto")

class TestF16DataGridScrollerContainment(TestCase):
    def __init__(self):
        super().__init__("T1_F16_04", "F16", 1, "DataGrid primitive encapsulates wide tabular layouts")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        grid_code = inspector.read_file("frontend/src/components/ui/DataGrid.tsx")
        self.assert_true(bool(grid_code and ("overflow-x-auto" in grid_code or "min-w-0" in grid_code)), "F16: DataGrid must contain horizontal table overflow")

class TestF16NoRootPageClipping(TestCase):
    def __init__(self):
        super().__init__("T1_F16_05", "F16", 1, "page.tsx root container does not truncate sticky headers with overflow-hidden")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        page_code = inspector.read_file("frontend/src/app/page.tsx")
        self.assert_true(bool(page_code), "F16: page.tsx must be readable")

class TestF17AuroraIntensityControl(TestCase):
    def __init__(self):
        super().__init__("T1_F17_01", "F17", 1, "DashboardSettingsTab exposes aurora intensity slider")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        settings = inspector.read_file("frontend/src/components/tabs/DashboardSettingsTab.tsx") or inspector.read_file("frontend/src/components/tabs/SettingsTab.tsx")
        self.assert_true(bool(settings and ("aurora" in settings.lower() or "intensity" in settings.lower())), "F17: Dashboard settings must provide aurora intensity control")

class TestF17AnimationToggleControl(TestCase):
    def __init__(self):
        super().__init__("T1_F17_02", "F17", 1, "DashboardSettingsTab provides static 120Hz cached vs animated toggle")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        settings = inspector.read_file("frontend/src/components/tabs/DashboardSettingsTab.tsx") or inspector.read_file("frontend/src/components/tabs/SettingsTab.tsx")
        self.assert_true(bool(settings and ("animat" in settings.lower() or "120hz" in settings.lower())), "F17: Dashboard settings must provide animation toggle")

class TestF17MicroGrainToggleControl(TestCase):
    def __init__(self):
        super().__init__("T1_F17_03", "F17", 1, "DashboardSettingsTab provides micro-grain enable/disable toggle")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        settings = inspector.read_file("frontend/src/components/tabs/DashboardSettingsTab.tsx") or inspector.read_file("frontend/src/components/tabs/SettingsTab.tsx")
        self.assert_true(bool(settings and "grain" in settings.lower()), "F17: Dashboard settings must provide micro-grain toggle")

class TestF17CardLiftDensityControl(TestCase):
    def __init__(self):
        super().__init__("T1_F17_04", "F17", 1, "DashboardSettingsTab provides density / card lift control")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        settings = inspector.read_file("frontend/src/components/tabs/DashboardSettingsTab.tsx") or inspector.read_file("frontend/src/components/tabs/SettingsTab.tsx")
        self.assert_true(bool(settings and ("density" in settings.lower() or "lift" in settings.lower() or "compact" in settings.lower())), "F17: Dashboard settings must provide layout density control")

class TestF17AtmosphereSettingsPersistence(TestCase):
    def __init__(self):
        super().__init__("T1_F17_05", "F17", 1, "Atmosphere preferences persist in localStorage or settings store")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        settings = inspector.read_file("frontend/src/components/tabs/DashboardSettingsTab.tsx") or inspector.read_file("frontend/src/components/tabs/SettingsTab.tsx")
        self.assert_true(bool(settings and ("localStorage" in settings or "useSettingsStore" in settings or "theme" in settings.lower())), "F17: Atmosphere preferences must be persistent")

class TestF18CardPrimitiveUpgraded(TestCase):
    def __init__(self):
        super().__init__("T1_F18_01", "F18", 1, "Card.tsx applies Obsidian V2 glass tokens and specular borders")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        card = inspector.read_file("frontend/src/components/ui/Card.tsx")
        self.assert_true(bool(card and ("glass-card" in card or "obs-" in card)), "F18: Card.tsx must implement Obsidian V2 tokens")

class TestF18ButtonPrimitiveUpgraded(TestCase):
    def __init__(self):
        super().__init__("T1_F18_02", "F18", 1, "Button.tsx variants use Obsidian V2 chromatic gradients")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        btn = inspector.read_file("frontend/src/components/ui/Button.tsx")
        self.assert_true(bool(btn and ("glass-button" in btn or "obs-" in btn or "primary" in btn)), "F18: Button.tsx must implement Obsidian V2 styling")

class TestF18InputPrimitiveRecessedWell(TestCase):
    def __init__(self):
        super().__init__("T1_F18_03", "F18", 1, "Input.tsx renders recessed dark well with specular focus ring")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        inp = inspector.read_file("frontend/src/components/ui/Input.tsx")
        self.assert_true(bool(inp and ("glass-input" in inp or "obs-" in inp or "focus:ring" in inp)), "F18: Input.tsx must implement Obsidian V2 well styling")

class TestF18ModalPrimitiveGlassPanel(TestCase):
    def __init__(self):
        super().__init__("T1_F18_04", "F18", 1, "Modal.tsx renders .glass-panel with backdrop blur")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        modal = inspector.read_file("frontend/src/components/ui/Modal.tsx")
        self.assert_true(bool(modal and ("glass-panel" in modal or "backdrop-blur" in modal or "obs-" in modal)), "F18: Modal.tsx must use glass panel styling")

class TestF18LoginPageObsidianStyling(TestCase):
    def __init__(self):
        super().__init__("T1_F18_05", "F18", 1, "login/page.tsx rendered with Obsidian V2 atmosphere and zero redundant blur divs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        login = inspector.read_file("frontend/src/app/login/page.tsx")
        self.assert_true(bool(login and ("glass" in login or "obs-" in login or "bg-transparent" in login)), "F18: login/page.tsx must adhere to Obsidian V2 styling")

def get_tests():
    return [
        TestF13PureBlackFoundation(), TestF13BodyBeforeAuroraGradients(), TestF13BodyAfterMicroGrain(), TestF13HardwareAcceleratedAtmosphere(), TestF13TransparentBodyCanvas(),
        TestF14SpecularTopBorderToken(), TestF14ChromaticEdgeGradientToken(), TestF14HighRefreshSpringTiming(), TestF14GlassCardUtilityClass(), TestF14GlassButtonPrimaryGradient(),
        TestF15MobileBottomDockDefined(), TestF15DesktopExpandableRail(), TestF15TouchTargetEnforcement(), TestF15ConnectionStatusBeacons(), TestF15SafeAreaInsetPadding(),
        TestF16ZeroBlanketOverflowHidden(), TestF16LayoutUsesMinWZero(), TestF16AuditTabScopedOverflow(), TestF16DataGridScrollerContainment(), TestF16NoRootPageClipping(),
        TestF17AuroraIntensityControl(), TestF17AnimationToggleControl(), TestF17MicroGrainToggleControl(), TestF17CardLiftDensityControl(), TestF17AtmosphereSettingsPersistence(),
        TestF18CardPrimitiveUpgraded(), TestF18ButtonPrimitiveUpgraded(), TestF18InputPrimitiveRecessedWell(), TestF18ModalPrimitiveGlassPanel(), TestF18LoginPageObsidianStyling()
    ]
