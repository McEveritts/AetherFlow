import { useSystemStore } from "@/store/useSystemStore";

describe("useSystemStore", () => {
  beforeEach(() => {
    useSystemStore.setState({
      theme: "system",
      language: "en",
      activeTab: "overview",
      isSidebarHovered: false,
      isMobileMenuOpen: false,
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
});
