import React, { Profiler } from "react";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import { useSystemStore } from "@/store/useSystemStore";
import { useConnectionStore, ConnectionState } from "@/store/useConnectionStore";
import { useTaskStore } from "@/store/useTaskStore";

let mockPendingCount = 0;

jest.mock("swr", () => ({
  __esModule: true,
  default: () => ({ data: { count: mockPendingCount } }),
}));

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
    localStorage.removeItem("aetherflow-sidebar-pinned");
    mockPendingCount = 0;
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

  it("starts as a compact desktop rail with an accessible logo and icon labels", () => {
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector<HTMLElement>("#desktop-sidebar-navigation")!;

    expect(desktopAside.parentElement).toHaveClass("md:w-[4.5rem]");
    expect(desktopAside).toHaveClass("md:w-[4.5rem]", "obs-gpu-120hz-rail");
    expect(within(desktopAside).getByRole("button", { name: "Expand Sidebar" })).toHaveAttribute("aria-expanded", "false");
    expect(within(desktopAside).getByAltText("AetherFlow Logo")).toHaveAttribute("src", "/img/aetherflow-mark.svg");
    expect(within(desktopAside).queryByText("Workspace")).not.toBeInTheDocument();
    for (const label of ["Overview", "Services", "Settings"]) {
      expect(within(desktopAside).getByRole("button", { name: label })).toBeInTheDocument();
    }
  });

  it("keeps both sidebar logos unboxed with the same luminous mark", () => {
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector<HTMLElement>("#desktop-sidebar-navigation")!;
    const desktopMark = within(desktopAside).getByAltText("AetherFlow Logo");
    const logoButton = desktopMark.closest("button")!;

    expect(logoButton).toHaveClass("obs-brand-logo");
    expect(logoButton).not.toHaveClass("border", "bg-indigo-500/10", "rounded-xl", "overflow-hidden");
    expect(desktopMark).toHaveClass("obs-brand-mark", "w-8", "h-8");
    expect(desktopAside.querySelector(".obs-sidebar-surface")).toBeInTheDocument();
    expect(desktopAside.querySelector(".inset-x-0.top-0.h-px")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /toggle navigation drawer/i }));
    const mobileDrawer = screen.getByRole("dialog", { name: "Navigation Menu" });
    const mobileMark = within(mobileDrawer).getByAltText("AetherFlow Logo");

    expect(mobileDrawer).toHaveClass("obs-sidebar-surface");
    expect(mobileDrawer).not.toHaveClass("glass-panel", "shadow-2xl");
    expect(mobileMark).toHaveClass("obs-brand-mark", "w-8", "h-8");
    expect(mobileMark.parentElement).toHaveClass("obs-brand-logo");
    expect(mobileMark.parentElement).not.toHaveClass("border", "bg-indigo-500/10", "rounded-xl");
  });

  it("uses only a right sidebar hairline and layers the aura directly behind the SVG", () => {
    const stylesheet = readFileSync(join(__dirname, "../../app/globals.css"), "utf8");
    const sidebarSurface = stylesheet.match(/\.obs-sidebar-surface\s*\{([^}]+)\}/)?.[1];
    const logoSurface = stylesheet.match(/\.obs-brand-logo\s*\{([^}]+)\}/)?.[1];
    const logoAura = stylesheet.match(/\.obs-brand-logo::before\s*\{([^}]+)\}/)?.[1];
    const logoMark = stylesheet.match(/\.obs-brand-mark\s*\{([^}]+)\}/)?.[1];

    expect(sidebarSurface).toContain("border: 0;");
    expect(sidebarSurface).toContain("border-right: 1px solid rgba(255, 255, 255, 0.07);");
    expect(sidebarSurface).toContain("box-shadow: none;");
    expect(sidebarSurface).not.toMatch(/border-(top|left|bottom):|obs-chromatic-inset/);
    expect(logoSurface).toContain("overflow: visible;");
    expect(logoSurface).toContain("background: transparent;");
    expect(logoSurface).toContain("border: 0;");
    expect(logoAura?.match(/radial-gradient/g)).toHaveLength(3);
    expect(logoAura).toContain("filter: blur(10px);");
    expect(logoAura).toContain("pointer-events: none;");
    expect(logoMark).toContain("drop-shadow(0 0 12px rgba(99, 102, 241, 0.85))");
    expect(logoMark).toContain("drop-shadow(0 0 24px rgba(56, 189, 248, 0.55))");
  });

  it("expands the docked spacer with the sidebar on hover and collapses both on leave", () => {
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector<HTMLElement>("#desktop-sidebar-navigation")!;

    fireEvent.mouseEnter(desktopAside);
    expect(useSystemStore.getState().isSidebarHovered).toBe(true);
    expect(desktopAside).toHaveClass("md:w-64");
    expect(desktopAside.parentElement).toHaveClass("md:w-64");
    expect(within(desktopAside).getByText("AetherFlow")).toBeInTheDocument();
    expect(within(desktopAside).getByText("Workspace")).toBeInTheDocument();
    expect(within(desktopAside).getByText("System")).toBeInTheDocument();

    fireEvent.mouseLeave(desktopAside);
    expect(useSystemStore.getState().isSidebarHovered).toBe(false);
    expect(desktopAside).toHaveClass("md:w-[4.5rem]");
    expect(desktopAside.parentElement).toHaveClass("md:w-[4.5rem]");
  });

  it("shows the glowing emerald Nexus OS status dot only in the expanded desktop header", () => {
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector<HTMLElement>("#desktop-sidebar-navigation")!;

    expect(within(desktopAside).queryByText("Nexus OS")).not.toBeInTheDocument();
    fireEvent.mouseEnter(desktopAside);
    expect(within(desktopAside).getByText("AetherFlow")).toHaveClass("text-base");
    const statusLabel = within(desktopAside).getByText("Nexus OS");
    expect(statusLabel.parentElement).toHaveClass("flex", "items-center", "gap-1.5", "mt-0.5");
    expect(statusLabel.previousElementSibling).toHaveClass("w-1.5", "h-1.5", "rounded-full", "bg-emerald-400", "shadow-[0_0_6px_#34d399]", "shrink-0");
    fireEvent.mouseLeave(desktopAside);
    expect(within(desktopAside).queryByText("Nexus OS")).not.toBeInTheDocument();
  });

  it("pins with the logo when collapsed and immediately collapses when expanded without navigating", async () => {
    const user = userEvent.setup({ skipHover: true });
    useSystemStore.setState({ activeTab: "services" });
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector<HTMLElement>("#desktop-sidebar-navigation")!;
    const logoButton = within(desktopAside).getByRole("button", { name: "Expand Sidebar" });

    expect(logoButton).toHaveAttribute("aria-controls", "desktop-sidebar-navigation");
    expect(logoButton).toHaveClass("focus-visible:ring-2");
    expect(logoButton).toHaveAttribute("aria-pressed", "false");
    await user.click(logoButton);
    expect(logoButton).toHaveAttribute("aria-expanded", "true");
    expect(logoButton).toHaveAttribute("aria-pressed", "true");
    expect(desktopAside.parentElement).toHaveClass("md:w-64");
    fireEvent.mouseLeave(desktopAside);
    expect(desktopAside).toHaveClass("md:w-64");

    await user.click(logoButton);
    expect(logoButton).toHaveAttribute("aria-expanded", "false");
    expect(logoButton).toHaveAttribute("aria-pressed", "false");
    expect(desktopAside).toHaveClass("md:w-[4.5rem]");
    expect(desktopAside.parentElement).toHaveClass("md:w-[4.5rem]");
    expect(useSystemStore.getState().isSidebarHovered).toBe(false);
    expect(within(desktopAside).getByRole("button", { name: "Services" })).toHaveAttribute("aria-current", "page");
    expect(useSystemStore.getState().activeTab).toBe("services");
  });

  it("keeps the logo keyboard-focusable and supports Enter and Space to pin and collapse", async () => {
    const user = userEvent.setup();
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector<HTMLElement>("#desktop-sidebar-navigation")!;
    const logoButton = within(desktopAside).getByRole("button", { name: "Expand Sidebar" });

    act(() => logoButton.focus());
    expect(logoButton).toHaveFocus();
    expect(logoButton).toHaveAttribute("aria-expanded", "true");
    expect(desktopAside.parentElement).toHaveClass("md:w-64");
    await user.keyboard("{Enter}");
    expect(logoButton).toHaveAttribute("aria-expanded", "true");
    fireEvent.mouseLeave(desktopAside);
    expect(desktopAside).toHaveClass("md:w-64");
    expect(desktopAside.parentElement).toHaveClass("md:w-64");
    await user.keyboard(" ");
    expect(logoButton).toHaveAttribute("aria-expanded", "false");
    expect(desktopAside.parentElement).toHaveClass("md:w-[4.5rem]");
    expect(logoButton).toHaveFocus();
    expect(useSystemStore.getState().activeTab).toBe("overview");
  });

  it("pins a hovered sidebar with a normal logo click and persists the pin preference", async () => {
    const user = userEvent.setup();
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector<HTMLElement>("#desktop-sidebar-navigation")!;
    await user.hover(desktopAside);
    await user.click(within(desktopAside).getByRole("button", { name: "Pin Sidebar" }));
    await user.unhover(desktopAside);
    expect(desktopAside).toHaveClass("md:w-64");
    expect(desktopAside.parentElement).toHaveClass("md:w-64");
    expect(localStorage.getItem("aetherflow-sidebar-pinned")).toBe("true");
    await user.click(within(desktopAside).getByRole("button", { name: "Unpin and collapse sidebar" }));
    expect(desktopAside).toHaveClass("md:w-[4.5rem]");
    expect(localStorage.getItem("aetherflow-sidebar-pinned")).toBe("false");
    expect(within(desktopAside).getByRole("button", { name: "Expand Sidebar" })).toHaveFocus();
  });

  it("restores a saved pin without expanding fresh visits by default", () => {
    localStorage.setItem("aetherflow-sidebar-pinned", "true");
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector<HTMLElement>("#desktop-sidebar-navigation")!;
    expect(desktopAside).toHaveClass("md:w-64");
    expect(desktopAside.parentElement).toHaveClass("md:w-64");
    expect(within(desktopAside).getByRole("button", { name: "Collapse Sidebar" })).toHaveAttribute("aria-expanded", "true");
  });

  it("still pins locally when saving the pin preference is unavailable", () => {
    const originalSetItem = Storage.prototype.setItem;
    const writePreference = jest.spyOn(Storage.prototype, "setItem").mockImplementation(function (this: Storage, key: string, value: string) {
      if (key === "aetherflow-sidebar-pinned") throw new DOMException("Pin preference is unavailable", "SecurityError");
      originalSetItem.call(this, key, value);
    });
    try {
      const { container } = render(<Sidebar />);
      const desktopAside = container.querySelector<HTMLElement>("#desktop-sidebar-navigation")!;
      fireEvent.click(within(desktopAside).getByRole("button", { name: "Expand Sidebar" }));
      fireEvent.mouseLeave(desktopAside);
      expect(desktopAside.parentElement).toHaveClass("md:w-64");
      fireEvent.click(within(desktopAside).getByRole("button", { name: "Collapse Sidebar" }));
      expect(desktopAside.parentElement).toHaveClass("md:w-[4.5rem]");
    } finally {
      writePreference.mockRestore();
    }
  });

  it("reveals labels throughout keyboard navigation and collapses when focus leaves the unpinned rail", () => {
    const { container } = render(<><Sidebar /><button type="button">Outside sidebar</button></>);
    const desktopAside = container.querySelector<HTMLElement>("#desktop-sidebar-navigation")!;
    act(() => within(desktopAside).getByRole("button", { name: "Services" }).focus());
    expect(desktopAside).toHaveClass("md:w-64");
    expect(desktopAside.parentElement).toHaveClass("md:w-64");
    expect(within(desktopAside).getByText("Services")).toBeInTheDocument();
    act(() => within(desktopAside).getByRole("button", { name: "Settings" }).focus());
    expect(desktopAside).toHaveClass("md:w-64");
    expect(desktopAside.parentElement).toHaveClass("md:w-64");
    act(() => screen.getByRole("button", { name: "Outside sidebar" }).focus());
    expect(desktopAside).toHaveClass("md:w-[4.5rem]");
    expect(desktopAside.parentElement).toHaveClass("md:w-[4.5rem]");
  });

  it("offers a discoverable keyboard-accessible pin control while hover-expanded", () => {
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector<HTMLElement>("#desktop-sidebar-navigation")!;
    fireEvent.mouseEnter(desktopAside);
    const pinButton = within(desktopAside).getByRole("button", { name: "Pin sidebar open" });
    expect(pinButton).toHaveClass("obs-touch-target-standard");
    expect(pinButton).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(pinButton);
    expect(within(desktopAside).getByRole("button", { name: "Unpin and collapse sidebar" })).toHaveAttribute("aria-pressed", "true");
    fireEvent.mouseLeave(desktopAside);
    expect(desktopAside.parentElement).toHaveClass("md:w-64");
  });

  it("shows pending inbox counts in the collapsed rail, expanded navigation, and mobile drawer", () => {
    mockPendingCount = 3;
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector<HTMLElement>("#desktop-sidebar-navigation")!;
    const inboxButton = within(desktopAside).getByRole("button", { name: "Approval Inbox" });
    expect(within(inboxButton).getByText("3")).toBeInTheDocument();
    fireEvent.mouseEnter(desktopAside);
    expect(within(inboxButton).getByText("3")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Toggle Navigation Drawer" }));
    const drawer = screen.getByRole("dialog", { name: "Navigation Menu" });
    expect(within(drawer).getByText("3")).toBeInTheDocument();
  });

  it("traps mobile drawer focus and restores the trigger on Escape", async () => {
    const user = userEvent.setup();
    render(<Sidebar />);
    const menuButton = screen.getByRole("button", { name: "Toggle Navigation Drawer" });
    await user.click(menuButton);
    const drawer = screen.getByRole("dialog", { name: "Navigation Menu" });
    const closeButton = within(drawer).getByRole("button", { name: "Close Navigation Drawer" });
    await waitFor(() => expect(closeButton).toHaveFocus());
    await user.keyboard("{Shift>}{Tab}{/Shift}");
    expect(within(drawer).getByRole("button", { name: "Log Out" })).toHaveFocus();
    await user.keyboard("{Tab}");
    expect(closeButton).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(menuButton).toHaveFocus();
  });

  it("marks the active item with aria-current page and single indigo indicator", () => {
    useSystemStore.setState({ activeTab: "services" });
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector("aside")!;

    const activeServicesBtn = within(desktopAside).getByRole("button", { name: "Services" });
    expect(activeServicesBtn).toHaveAttribute("aria-current", "page");
    expect(activeServicesBtn).toHaveClass("border-indigo-500/40", "from-indigo-500/25", "to-fuchsia-500/20");
    expect(activeServicesBtn.querySelector("span.absolute")).toHaveClass("shadow-[0_0_8px_#6366f1]");
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

  it("links Header disclosures and returns focus on Escape without trapping Tab", () => {
    useTaskStore.setState({ tasks: [{ id: "task-one", title: "Backup", progress: 30, status: "running", type: "backup" }] });
    render(<Header />);
    const taskTrigger = screen.getByRole("button", { name: "Background Tasks" });
    fireEvent.click(taskTrigger);
    expect(taskTrigger).toHaveAttribute("aria-expanded", "true");
    expect(document.getElementById(taskTrigger.getAttribute("aria-controls") || "")).toHaveTextContent("Backup");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(taskTrigger).toHaveAttribute("aria-expanded", "false");
    expect(document.activeElement).toBe(taskTrigger);

    const userTrigger = screen.getByRole("button", { name: "User Menu" });
    fireEvent.click(userTrigger);
    expect(userTrigger).toHaveAttribute("aria-expanded", "true");
    const panel = document.getElementById(userTrigger.getAttribute("aria-controls") || "");
    expect(panel).toHaveTextContent("Sign Out");
    const tabEvent = new KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true });
    document.dispatchEvent(tabEvent);
    expect(tabEvent.defaultPrevented).toBe(false);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(userTrigger).toHaveAttribute("aria-expanded", "false");
    expect(document.activeElement).toBe(userTrigger);
    useTaskStore.setState({ tasks: [] });
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

  it("maintains honest aria-pressed state alongside aria-expanded on primary logo toggle", async () => {
    const user = userEvent.setup({ skipHover: true });
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector<HTMLElement>("#desktop-sidebar-navigation")!;
    const logoButton = within(desktopAside).getByRole("button", { name: "Expand Sidebar" });

    expect(logoButton).toHaveAttribute("aria-expanded", "false");
    expect(logoButton).toHaveAttribute("aria-pressed", "false");

    await user.click(logoButton);
    expect(logoButton).toHaveAttribute("aria-expanded", "true");
    expect(logoButton).toHaveAttribute("aria-pressed", "true");

    await user.click(logoButton);
    expect(logoButton).toHaveAttribute("aria-expanded", "false");
    expect(logoButton).toHaveAttribute("aria-pressed", "false");
  });

  it("applies shared dock height variable to mobile navigation dock", () => {
    render(<Sidebar />);
    const mobileNav = screen.getByRole("navigation", { name: "Mobile Bottom Navigation" });
    expect(mobileNav).toHaveClass("h-[var(--obs-shell-bottom-dock-height,4rem)]");
  });

  it("conveys current location on secondary tabs through mobile Menu dock slot and keeps drawer aria-current honest", () => {
    useSystemStore.setState({ activeTab: "settings" });
    render(<Sidebar />);

    const mobileNavigation = screen.getByRole("navigation", { name: "Mobile Bottom Navigation" });
    const menuButton = within(mobileNavigation).getByRole("button", { name: "Toggle Navigation Drawer" });
    expect(menuButton).toHaveAttribute("aria-current", "page");
    expect(menuButton).toHaveClass("text-indigo-400");
    expect(menuButton.querySelector("span.bg-indigo-500")).toBeInTheDocument();

    for (const primaryName of ["Overview", "Services", "Streaming"]) {
      const primaryButton = within(mobileNavigation).getByRole("button", { name: new RegExp(primaryName, "i") });
      expect(primaryButton).not.toHaveAttribute("aria-current");
    }

    fireEvent.click(menuButton);
    const mobileDrawer = screen.getByRole("dialog", { name: "Navigation Menu" });
    const activeSettingsButton = within(mobileDrawer).getByRole("button", { name: "Settings" });
    expect(activeSettingsButton).toHaveAttribute("aria-current", "page");

    const nonActiveDrawerButtons = within(mobileDrawer).getAllByRole("button").filter((buttonElement) => buttonElement !== activeSettingsButton);
    nonActiveDrawerButtons.forEach((buttonElement) => {
      expect(buttonElement).not.toHaveAttribute("aria-current", "page");
    });
  });

  it("shows left-pointing collapse chevron whenever desktop rail is visually expanded by keyboard focus", () => {
    const { container } = render(<Sidebar />);
    const desktopAside = container.querySelector<HTMLElement>("#desktop-sidebar-navigation")!;
    const servicesButton = within(desktopAside).getByRole("button", { name: "Services" });

    act(() => {
      servicesButton.focus();
    });

    expect(desktopAside.parentElement).toHaveClass("md:w-64");
    const chevronButton = within(desktopAside).getByRole("button", { name: "Pin sidebar open" });
    expect(chevronButton).toHaveAttribute("aria-pressed", "false");
    const chevronIcon = chevronButton.querySelector("svg.lucide-chevron-left");
    expect(chevronIcon).toBeInTheDocument();
    expect(chevronButton.querySelector("svg.lucide-chevron-right")).toBeNull();
  });
});
