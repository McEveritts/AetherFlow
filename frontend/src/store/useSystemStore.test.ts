import { useSystemStore } from "@/store/useSystemStore";

describe("useSystemStore", () => {
  beforeEach(() => {
    useSystemStore.setState({
      theme: "system",
      language: "en",
      activeTab: "overview",
      isSidebarHovered: false,
      isMobileMenuOpen: false,
      highRefreshMode: "auto",
      detectedRefreshRate: 60,
      touchMode: "auto",
      detectedTouchDevice: false,
      hapticFeedback: true,
      isCommandPaletteOpen: false,
    });
  });

  it("switches active tab and closes mobile menu", () => {
    useSystemStore.getState().setIsMobileMenuOpen(true);
    useSystemStore.getState().setActiveTab("services");

    const state = useSystemStore.getState();
    expect(state.activeTab).toBe("services");
    expect(state.isMobileMenuOpen).toBe(false);
  });

  it("updates persisted preferences", () => {
    useSystemStore.getState().setTheme("dark");
    useSystemStore.getState().setLanguage("fr");

    const state = useSystemStore.getState();
    expect(state.theme).toBe("dark");
    expect(state.language).toBe("fr");
  });

  it("updates Obsidian V2 atmosphere parameters", () => {
    useSystemStore.getState().setAuroraOpacity(0.85);
    useSystemStore.getState().setAuroraAnimation(true);
    useSystemStore.getState().setGrainDisplay(false);
    useSystemStore.getState().setCardLift(-6);

    const state = useSystemStore.getState();
    expect(state.auroraOpacity).toBe(0.85);
    expect(state.auroraAnimation).toBe(true);
    expect(state.grainDisplay).toBe(false);
    expect(state.cardLift).toBe(-6);
  });

  it("updates 120Hz high-refresh and touchscreen engine state", () => {
    useSystemStore.getState().setHighRefreshMode("120hz");
    useSystemStore.getState().setDetectedRefreshRate(120);
    useSystemStore.getState().setTouchMode("enabled");
    useSystemStore.getState().setDetectedTouchDevice(true);
    useSystemStore.getState().setHapticFeedback(false);
    useSystemStore.getState().setIsCommandPaletteOpen(true);

    const state = useSystemStore.getState();
    expect(state.highRefreshMode).toBe("120hz");
    expect(state.detectedRefreshRate).toBe(120);
    expect(state.touchMode).toBe("enabled");
    expect(state.detectedTouchDevice).toBe(true);
    expect(state.hapticFeedback).toBe(false);
    expect(state.isCommandPaletteOpen).toBe(true);
  });
});
