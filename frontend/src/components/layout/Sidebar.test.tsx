import { fireEvent, render, screen, within } from "@testing-library/react";
import Sidebar from "@/components/layout/Sidebar";
import { useSystemStore } from "@/store/useSystemStore";
import { useConnectionStore } from "@/store/useConnectionStore";

// Mock AuthContext
jest.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: { id: 1, username: "admin", role: "admin" },
    logout: jest.fn(),
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
});
