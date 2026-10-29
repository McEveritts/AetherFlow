import { render, screen, act } from "@testing-library/react";
import ThemeProvider from "@/components/layout/ThemeProvider";
import { useSystemStore } from "@/store/useSystemStore";

describe("ThemeProvider - Obsidian V2 Atmosphere & 120Hz/Touch Synchronization", () => {
  beforeEach(() => {
    useSystemStore.setState({
      theme: "dark",
      language: "en",
      auroraOpacity: 0.7,
      auroraAnimation: true,
      grainDisplay: true,
      cardLift: -4,
      highRefreshMode: "auto",
      detectedRefreshRate: 60,
      touchMode: "auto",
      detectedTouchDevice: false,
    });
  });

  it("synchronizes Obsidian atmosphere CSS variables to root element", () => {
    render(
      <ThemeProvider>
        <div data-testid="child">App Content</div>
      </ThemeProvider>
    );

    expect(screen.getByTestId("child")).toBeInTheDocument();

    const root = document.documentElement;
    expect(root.style.getPropertyValue("--obs-aurora-opacity")).toBe("0.7");
    expect(root.style.getPropertyValue("--obs-aurora-animation")).toContain("obs-aurora-shift");
    expect(root.style.getPropertyValue("--obs-grain-display")).toBe("block");
    expect(root.style.getPropertyValue("--obs-card-lift")).toBe("-4px");
  });

  it("updates root CSS variables when store updates", () => {
    const { rerender } = render(
      <ThemeProvider>
        <div>Content</div>
      </ThemeProvider>
    );

    act(() => {
      useSystemStore.getState().setAuroraOpacity(0.3);
      useSystemStore.getState().setAuroraAnimation(false);
      useSystemStore.getState().setGrainDisplay(false);
    });

    rerender(
      <ThemeProvider>
        <div>Content</div>
      </ThemeProvider>
    );

    const root = document.documentElement;
    expect(root.style.getPropertyValue("--obs-aurora-opacity")).toBe("0.3");
    expect(root.style.getPropertyValue("--obs-aurora-animation")).toBe("none");
    expect(root.style.getPropertyValue("--obs-grain-display")).toBe("none");
  });

  it("synchronizes 120Hz high-refresh and touch mode dataset attributes and duration tokens", () => {
    const { rerender } = render(
      <ThemeProvider>
        <div>Content</div>
      </ThemeProvider>
    );

    const root = document.documentElement;
    expect(root.dataset.highRefresh).toBe("false");
    expect(root.dataset.touchMode).toBe("false");

    act(() => {
      useSystemStore.getState().setHighRefreshMode("120hz");
      useSystemStore.getState().setTouchMode("enabled");
    });

    rerender(
      <ThemeProvider>
        <div>Content</div>
      </ThemeProvider>
    );

    expect(root.dataset.highRefresh).toBe("true");
    expect(root.dataset.touchMode).toBe("true");
    expect(root.style.getPropertyValue("--obs-duration-fast")).toBe("110ms");
    expect(root.style.getPropertyValue("--obs-duration-card")).toBe("150ms");
  });
});
