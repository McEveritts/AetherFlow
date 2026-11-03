import React, { Profiler } from "react";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import { useSystemStore } from "@/store/useSystemStore";
import { useConnectionStore } from "@/store/useConnectionStore";

// Mock AuthContext
jest.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: { id: 1, username: "admin", role: "admin" },
    logout: jest.fn(),
  }),
}));

jest.mock("@/contexts/ToastContext", () => ({
  useToast: () => ({
    toasts: [],
    toggleDrawer: jest.fn(),
    addToast: jest.fn(),
  }),
}));

describe("Sidebar - Tri-Mode Navigation Architecture & Touch/120Hz Support", () => {
  beforeEach(() => {
    useSystemStore.setState({
      activeTab: "overview",
      isSidebarHovered: false,
      isMobileMenuOpen: false,
      hapticFeedback: false,
    });
    useConnectionStore.setState({
      connectionState: "CONNECTED",
    });
  });

  it("renders mobile bottom glass dock with >= 44px touch targets", () => {
    render(<Sidebar />);

    const mobileNav = screen.getByRole("navigation", { name: "Mobile Bottom Navigation" });
    expect(mobileNav).toBeInTheDocument();
    expect(mobileNav).toHaveClass("md:hidden");
    expect(mobileNav).toHaveClass("fixed");
    expect(mobileNav).toHaveClass("bottom-0");

    // Check dock buttons have obs-touch-target-standard
    const dockButtons = mobileNav.querySelectorAll("button");
    expect(dockButtons.length).toBeGreaterThanOrEqual(4);
    dockButtons.forEach((btn) => {
      expect(btn).toHaveClass("obs-touch-target-standard");
    });
  });

  it("switches active tab when mobile dock item is clicked", () => {
    render(<Sidebar />);

    const mobileNav = screen.getByRole("navigation", { name: "Mobile Bottom Navigation" });
    const servicesBtn = within(mobileNav).getByRole("button", { name: /services/i });
    fireEvent.click(servicesBtn);

    expect(useSystemStore.getState().activeTab).toBe("services");
  });

  it("opens mobile drawer when More button is clicked and closes on swipe-left gesture", () => {
    render(<Sidebar />);

    const moreBtn = screen.getByRole("button", { name: /toggle navigation drawer/i });
    fireEvent.click(moreBtn);

    expect(useSystemStore.getState().isMobileMenuOpen).toBe(true);
    const closeBtn = screen.getByRole("button", { name: /close navigation drawer/i });
    expect(closeBtn).toBeInTheDocument();

    const drawerAside = document.querySelector("aside")!;
    fireEvent.touchStart(drawerAside, { touches: [{ clientX: 200 }] });
    fireEvent.touchEnd(drawerAside, { changedTouches: [{ clientX: 100 }] });

    expect(useSystemStore.getState().isMobileMenuOpen).toBe(false);
  });

  it("allows touch/tablet users to expand and collapse the sidebar via tap toggle buttons", () => {
    render(<Sidebar />);

    expect(useSystemStore.getState().isSidebarHovered).toBe(false);

    const expandBtns = screen.getAllByRole("button", { name: /expand sidebar/i });
    expect(expandBtns.length).toBeGreaterThanOrEqual(1);
    fireEvent.click(expandBtns[0]);

    expect(useSystemStore.getState().isSidebarHovered).toBe(true);

    const collapseBtns = screen.getAllByRole("button", { name: /collapse sidebar/i });
    fireEvent.click(collapseBtns[0]);

    expect(useSystemStore.getState().isSidebarHovered).toBe(false);
  });

  it("displays the connection status beacon", () => {
    render(<Sidebar />);

    const beacon = document.querySelector(".obs-beacon-live");
    expect(beacon).toBeInTheDocument();
  });

  it("includes network and cluster in bottom navigation for admin user", () => {
    render(<Sidebar />);

    const networkBtns = screen.getAllByRole("button", { name: /network/i });
    expect(networkBtns.length).toBeGreaterThan(0);

    const clusterBtns = screen.getAllByRole("button", { name: /cluster/i });
    expect(clusterBtns.length).toBeGreaterThan(0);
  });

  it("keeps the desktop in-flow spacer width fixed at 4.5rem while the fixed rail expands on hover", () => {
    const { container } = render(<Sidebar />);

    const desktopAside = container.querySelector("aside")!;
    const desktopSpacer = desktopAside.parentElement!;

    expect(desktopSpacer).toHaveClass("md:w-[4.5rem]");
    expect(desktopSpacer).not.toHaveClass("md:w-64");
    expect(desktopSpacer).not.toHaveClass("obs-gpu-120hz-rail");
    expect(desktopAside).toHaveClass("md:w-[4.5rem]");

    fireEvent.mouseEnter(desktopAside);

    expect(useSystemStore.getState().isSidebarHovered).toBe(true);
    expect(desktopSpacer).toHaveClass("md:w-[4.5rem]");
    expect(desktopSpacer).not.toHaveClass("md:w-64");
    expect(desktopAside).toHaveClass("md:w-64");

    fireEvent.mouseLeave(desktopAside);

    expect(useSystemStore.getState().isSidebarHovered).toBe(false);
    expect(desktopSpacer).toHaveClass("md:w-[4.5rem]");
    expect(desktopAside).toHaveClass("md:w-[4.5rem]");
  });

  it("does not re-render Sidebar or Header when lastMessageAt updates, but updates on displayed connection fields", () => {
    let sidebarCommits = 0;
    let headerCommits = 0;

    render(
      <>
        <Profiler id="sidebar" onRender={() => { sidebarCommits += 1; }}>
          <Sidebar />
        </Profiler>
        <Profiler id="header" onRender={() => { headerCommits += 1; }}>
          <Header />
        </Profiler>
      </>
    );

    const initialSidebarCommits = sidebarCommits;
    const initialHeaderCommits = headerCommits;

    act(() => {
      useConnectionStore.getState().setLastMessageAt(1700000000000);
      useConnectionStore.getState().setLastMessageAt(1700000001000);
      useSystemStore.getState().setAuroraOpacity(0.4);
    });

    expect(sidebarCommits).toBe(initialSidebarCommits);
    expect(headerCommits).toBe(initialHeaderCommits);

    act(() => {
      useConnectionStore.getState().setConnectionState("RECONNECTING");
      useConnectionStore.getState().setReconnectAttempt(2);
    });

    expect(sidebarCommits).toBeGreaterThan(initialSidebarCommits);
    expect(headerCommits).toBeGreaterThan(initialHeaderCommits);
    expect(screen.getByText("Reconnecting (2)")).toBeInTheDocument();
  });
});
