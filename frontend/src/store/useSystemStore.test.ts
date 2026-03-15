import { useSystemStore } from "@/store/useSystemStore";

describe("useSystemStore", () => {
  beforeEach(() => {
    useSystemStore.setState({
      theme: "system",
      language: "en",
      activeTab: "overview",
      isSidebarHovered: false,
      isMobileMenuOpen: false,
      activeTasks: [],
    });
  });

  it("switches active tab and closes mobile menu", () => {
    useSystemStore.getState().setIsMobileMenuOpen(true);
    useSystemStore.getState().setActiveTab("services");

    const state = useSystemStore.getState();
    expect(state.activeTab).toBe("services");
    expect(state.isMobileMenuOpen).toBe(false);
  });

  it("manages background tasks lifecycle", () => {
    useSystemStore.getState().addTask({ id: "task-1", description: "Install app", progress: 10 });
    useSystemStore.getState().updateTaskProgress("task-1", 55);

    let state = useSystemStore.getState();
    expect(state.activeTasks).toHaveLength(1);
    expect(state.activeTasks[0].progress).toBe(55);

    useSystemStore.getState().removeTask("task-1");
    state = useSystemStore.getState();
    expect(state.activeTasks).toHaveLength(0);
  });

  it("updates persisted preferences", () => {
    useSystemStore.getState().setTheme("dark");
    useSystemStore.getState().setLanguage("fr");

    const state = useSystemStore.getState();
    expect(state.theme).toBe("dark");
    expect(state.language).toBe("fr");
  });
});
