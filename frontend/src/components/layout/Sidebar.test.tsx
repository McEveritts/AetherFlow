import React, { Profiler } from "react";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import { useSystemStore } from "@/store/useSystemStore";
import { useConnectionStore, ConnectionState } from "@/store/useConnectionStore";

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

describe("Sidebar - Persistent Navigation Architecture, Collapse, and Accessibility", () => {
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

    const dockButtons = mobileNav.querySelectorAll("button");
    expect(dockButtons.length).toBeGreaterThanOrEqual(4);
    dockButtons.forEach((buttonElement) => {
      expect(buttonElement).toHaveClass("obs-touch-target-standard");
    });
  });

  it("switches active tab when mobile dock item is clicked", () => {
    render(<Sidebar />);

    const mobileNav = screen.getByRole("navigation", { name: "Mobile Bottom Navigation" });
    const servicesBtn = within(mobileNav).getByRole("button", { name: /services/i });
    fireEvent.click(servicesBtn);

    expect(useSystemStore.getState().activeTab).toBe("services");
  });

  it("renders labeled Overview, Services, and Streaming access in mobile bottom dock", () => {
    render(<Sidebar />);

    const mobileNav = screen.getByRole("navigation", { name: "Mobile Bottom Navigation" });
    expect(within(mobileNav).getByRole("button", { name: /overview/i })).toBeInTheDocument();
    expect(within(mobileNav).getByRole("button", { name: /services/i })).toBeInTheDocument();
    expect(within(mobileNav).getByRole("button", { name: /streaming/i })).toBeInTheDocument();
    expect(within(mobileNav).getByRole("button", { name: /toggle navigation drawer/i })).toBeInTheDocument();
    expect(within(mobileNav).getByText("Menu")).toBeInTheDocument();
  });

  it("opens mobile drawer when Menu toggle is clicked and closes on swipe-left gesture", () => {
    render(<Sidebar />);

    const menuToggle = screen.getByRole("button", { name: /toggle navigation drawer/i });
    expect(menuToggle).toHaveAttribute("aria-expanded", "false");
    expect(menuToggle).toHaveAttribute("aria-controls", "mobile-navigation-drawer");
    expect(menuToggle).toHaveAttribute("aria-haspopup", "dialog");

    fireEvent.click(menuToggle);

    expect(useSystemStore.getState().isMobileMenuOpen).toBe(true);
    expect(menuToggle).toHaveAttribute("aria-expanded", "true");

    const drawerDialog = screen.getByRole("dialog", { name: "Navigation Menu" });
    expect(drawerDialog).toBeInTheDocument();
    expect(drawerDialog).toHaveAttribute("aria-modal", "true");

    const closeBtn = screen.getByRole("button", { name: /close navigation drawer/i });
    expect(closeBtn).toBeInTheDocument();

    fireEvent.touchStart(drawerDialog, { touches: [{ clientX: 200 }] });
    fireEvent.touchEnd(drawerDialog, { changedTouches: [{ clientX: 100 }] });

    expect(useSystemStore.getState().isMobileMenuOpen).toBe(false);
  });

  it("closes mobile drawer when visible Close button is clicked", () => {
    useSystemStore.setState({ isMobileMenuOpen: true });
    render(<Sidebar />);

    const closeBtn = screen.getByRole("button", { name: /close navigation drawer/i });
    expect(closeBtn).toBeInTheDocument();
    fireEvent.click(closeBtn);

    expect(useSystemStore.getState().isMobileMenuOpen).toBe(false);
  });

  it("closes mobile drawer when Escape key is pressed", () => {
    useSystemStore.setState({ isMobileMenuOpen: true });
    render(<Sidebar />);

    expect(screen.getByRole("dialog", { name: "Navigation Menu" })).toBeInTheDocument();
    fireEvent.keyDown(window, { key: "Escape" });

    expect(useSystemStore.getState().isMobileMenuOpen).toBe(false);
  });

  it("renders a persistent labeled sidebar on desktop around 208px width with product mark and name", () => {
    const { container } = render(<Sidebar />);

    const desktopAside = container.querySelector("aside")!;
    const desktopSpacer = desktopAside.parentElement!;

    expect(desktopSpacer).toHaveClass("md:w-52");
    expect(desktopAside).toHaveClass("md:w-52");

    expect(screen.getByText("AetherFlow")).toBeInTheDocument();
    expect(screen.getByText("Nexus OS")).toBeInTheDocument();
    expect(screen.getByAltText("AetherFlow Logo")).toBeInTheDocument();
  });

  it("does not depend on hover for essential labels", () => {
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector("aside")!;

    expect(within(desktopAside).getByText("Workspace")).toBeInTheDocument();
    expect(within(desktopAside).getByText("System")).toBeInTheDocument();

    expect(within(desktopAside).getByRole("button", { name: "Overview" })).toBeInTheDocument();
    expect(within(desktopAside).getByRole("button", { name: "Services" })).toBeInTheDocument();
    expect(within(desktopAside).getByRole("button", { name: "Settings" })).toBeInTheDocument();
  });

  it("allows collapsing to compact rail and expanding back via accessible toggle button", () => {
    const { container } = render(<Sidebar />);

    const desktopAside = container.querySelector("aside")!;
    const desktopSpacer = desktopAside.parentElement!;

    expect(desktopSpacer).toHaveClass("md:w-52");

    const collapseButton = screen.getByRole("button", { name: /collapse sidebar/i });
    expect(collapseButton).toBeInTheDocument();
    fireEvent.click(collapseButton);

    expect(desktopSpacer).toHaveClass("md:w-16");
    expect(desktopAside).toHaveClass("md:w-16");

    const expandButton = screen.getByRole("button", { name: /expand sidebar/i });
    expect(expandButton).toBeInTheDocument();
    fireEvent.click(expandButton);

    expect(desktopSpacer).toHaveClass("md:w-52");
    expect(desktopAside).toHaveClass("md:w-52");
  });

  it("marks the active item with aria-current page and single indigo indicator", () => {
    useSystemStore.setState({ activeTab: "services" });
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector("aside")!;

    const activeServicesBtn = within(desktopAside).getByRole("button", { name: "Services" });
    expect(activeServicesBtn).toHaveAttribute("aria-current", "page");
    expect(activeServicesBtn).toHaveClass("border-indigo-500/30");
  });

  it("ensures all interactive navigation controls meet >= 40px touch and click target requirement", () => {
    const { container } = render(<Sidebar />);

    const desktopAside = container.querySelector("aside")!;
    const allButtons = desktopAside.querySelectorAll("button");

    allButtons.forEach((buttonElement) => {
      const className = buttonElement.className;
      const satisfiesMinDimension = className.includes("min-h-[40px]") || className.includes("h-10");
      expect(satisfiesMinDimension).toBe(true);
    });
  });

  it("displays the connection status beacon", () => {
    render(
      <>
        <Header />
        <Sidebar />
      </>
    );

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
    expect(screen.getAllByText("Reconnecting (2)").length).toBeGreaterThan(0);
  });

  it("renders Header with accessible mobile toggle, responsive title, and hidden secondary breadcrumb segment", () => {
    render(<Header />);

    const menuButton = screen.getByRole("button", { name: "Toggle Menu" });
    expect(menuButton).toHaveAttribute("aria-expanded", "false");
    expect(menuButton).toHaveAttribute("aria-controls", "mobile-navigation-drawer");

    const breadcrumbNav = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(breadcrumbNav).toBeInTheDocument();
    expect(within(breadcrumbNav).getByText("AetherFlow")).toHaveClass("hidden", "md:inline");

    const secondarySegment = within(breadcrumbNav).getByText("Workspace");
    expect(secondarySegment).toHaveClass("hidden", "md:inline");

    const pageHeading = screen.getByRole("heading", { level: 1 });
    expect(pageHeading).toHaveTextContent("Overview");
    expect(pageHeading).toHaveClass("truncate");
  });

  it("renders mobile Menu dock button as symmetric icon-over-label stack without notification lookalikes", () => {
    render(<Sidebar />);

    const mobileNav = screen.getByRole("navigation", { name: "Mobile Bottom Navigation" });
    const menuButton = within(mobileNav).getByRole("button", { name: "Toggle Navigation Drawer" });
    expect(menuButton).toBeInTheDocument();
    expect(menuButton).toHaveClass("obs-touch-target-standard");
    expect(within(menuButton).getByText("Menu")).toBeInTheDocument();
    expect(within(menuButton).queryByText(/^[0-9]+$/)).not.toBeInTheDocument();

    const menuIcon = menuButton.querySelector(".p-1 svg");
    expect(menuIcon).toBeInTheDocument();

    expect(within(menuButton).queryByText("Online")).not.toBeInTheDocument();
    expect(menuButton.querySelector(".obs-beacon-live")).not.toBeInTheDocument();

    fireEvent.click(menuButton);
    const drawerDialog = screen.getByRole("dialog", { name: "Navigation Menu" });
    expect(drawerDialog).toBeInTheDocument();
    expect(drawerDialog.querySelector(".obs-beacon-live")).toBeInTheDocument();
    expect(within(drawerDialog).getByText("CONNECTED")).toBeInTheDocument();
  });

  it("renders explicit connection states and beacons in shared mobile Header across all canonical states without truncation", () => {
    const canonicalCases = [
      { state: "CONNECTING", label: "Connecting...", beaconClass: "obs-beacon-reconnecting" },
      { state: "RECONNECTING", attempt: 3, label: "Reconnecting (3)", beaconClass: "obs-beacon-reconnecting" },
      { state: "FALLBACK", label: "HTTP Fallback", beaconClass: "obs-beacon-reconnecting" },
      { state: "STALE", label: "Stale Data", beaconClass: "obs-beacon-offline" },
      { state: "DEGRADED", label: "Degraded", beaconClass: "obs-beacon-reconnecting" },
      { state: "UNAUTHORIZED", label: "Unauthorized", beaconClass: "obs-beacon-danger" },
      { state: "BLOCKED", label: "Pending Approval", beaconClass: "obs-beacon-danger" },
      { state: "EMPTY", label: "Initial Setup", beaconClass: "obs-beacon-offline" },
      { state: "OFFLINE", label: "Offline", beaconClass: "obs-beacon-danger" },
      { state: "CONNECTED", label: "Connected", beaconClass: "obs-beacon-live" },
    ];

    const { rerender } = render(<Header />);

    for (const testCase of canonicalCases) {
      act(() => {
        useConnectionStore.setState({
          connectionState: testCase.state as unknown as ConnectionState,
          reconnectAttempt: testCase.attempt ?? 0,
        });
      });
      rerender(<Header />);

      const statusLabels = screen.getAllByText(testCase.label);
      expect(statusLabels.length).toBe(2);

      const mobileStatusLabel = statusLabels[0];
      const mobileContainer = mobileStatusLabel.parentElement;
      expect(mobileContainer).toHaveClass("md:hidden");
      expect(mobileContainer).toHaveClass("flex-wrap");
      expect(mobileStatusLabel).not.toHaveClass("truncate");
      expect(mobileStatusLabel).toHaveClass("break-words");
      expect(mobileStatusLabel).toHaveClass("leading-tight");

      const mobileBeacon = mobileContainer?.querySelector(`.${testCase.beaconClass}`);
      expect(mobileBeacon).toBeInTheDocument();

      const desktopStatusLabel = statusLabels[1];
      const desktopContainer = desktopStatusLabel.closest(".rounded-full");
      expect(desktopContainer).toHaveClass("hidden");
      expect(desktopContainer).toHaveClass("md:flex");

      const desktopBeacon = desktopContainer?.querySelector(`.${testCase.beaconClass}`);
      expect(desktopBeacon).toBeInTheDocument();
    }
  });
});
