import React from "react";
import { act, render, screen } from "@testing-library/react";
import Dashboard from "@/app/page";
import { useSystemStore } from "@/store/useSystemStore";
import { emptyHistory } from "@/store/useHistoryStore";

jest.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({ user: { id: 1, username: "admin", role: "admin" } }),
}));

jest.mock("next/dynamic", () => {
  return function mockDynamic(loader: () => Promise<{ default: React.ComponentType<Record<string, unknown>> }>) {
    const fnString = loader.toString();
    if (fnString.includes("OverviewTab")) {
      return function DynamicOverviewTab(props: Record<string, unknown>) {
        const mod = jest.requireMock("@/components/tabs/OverviewTab");
        const Component = mod.default || mod;
        return <Component {...props} />;
      };
    }
    if (fnString.includes("ServicesTab")) {
      return function DynamicServicesTab() {
        return <div data-testid="services-tab">Services Tab Content</div>;
      };
    }
    if (fnString.includes("MarketplaceTab")) {
      return function DynamicMarketplaceTab() {
        return <div data-testid="marketplace-tab">Marketplace Tab Content</div>;
      };
    }
    if (fnString.includes("SettingsTab")) {
      return function DynamicSettingsTab() {
        return <div data-testid="settings-tab">Settings Tab Content</div>;
      };
    }
    return function DynamicFallbackTab() {
      return <div data-testid="other-tab">Other Tab</div>;
    };
  };
});

jest.mock("@/components/layout/Sidebar", () => {
  return function MockSidebar() {
    return <div data-testid="sidebar">Sidebar</div>;
  };
});

jest.mock("@/components/layout/Header", () => {
  return function MockHeader() {
    return <div data-testid="header">Header</div>;
  };
});

jest.mock("@/components/layout/GlobalBanners", () => {
  return function MockGlobalBanners() {
    return <div data-testid="global-banners">Banners</div>;
  };
});

jest.mock("@/components/layout/OnboardingWizard", () => {
  return function MockOnboardingWizard() {
    return <div data-testid="onboarding-wizard">Onboarding</div>;
  };
});

jest.mock("@/components/layout/SkeletonBox", () => ({
  OverviewSkeleton: function MockOverviewSkeleton() {
    return <div data-testid="overview-skeleton">Loading Overview</div>;
  },
}));

jest.mock("@/components/tabs/OverviewTab", () => {
  return function MockOverviewTab() {
    return <div data-testid="overview-tab">Overview Tab Content</div>;
  };
});

const mockUseMetrics = jest.fn();
jest.mock("@/hooks/useMetrics", () => ({
  useMetrics: () => mockUseMetrics(),
}));

jest.mock("swr", () => ({
  __esModule: true,
  default: jest.fn(() => ({
    data: { setupCompleted: true },
    mutate: jest.fn(),
  })),
  mutate: jest.fn(),
}));

describe("Dashboard telemetry decoupling and tab loading gates", () => {
  beforeEach(() => {
    mockUseMetrics.mockReset();
    useSystemStore.setState({ activeTab: "overview" });
  });

  it("renders non-telemetry tabs immediately without calling useMetrics or blocking on missing telemetry", () => {
    mockUseMetrics.mockReturnValue({
      metrics: null,
      hardware: null,
      history: emptyHistory,
      isLoading: true,
      isError: false,
      connectionState: "CONNECTING",
    });

    useSystemStore.setState({ activeTab: "services" });
    const { rerender } = render(<Dashboard />);

    expect(screen.getByTestId("services-tab")).toBeInTheDocument();
    expect(screen.queryByText(/Establishing Nexus Link/i)).not.toBeInTheDocument();
    expect(mockUseMetrics).not.toHaveBeenCalled();

    mockUseMetrics.mockReturnValue({
      metrics: null,
      hardware: null,
      history: emptyHistory,
      isLoading: false,
      isError: true,
      connectionState: "DISCONNECTED",
    });

    act(() => useSystemStore.setState({ activeTab: "marketplace" }));
    rerender(<Dashboard />);

    expect(screen.getByTestId("marketplace-tab")).toBeInTheDocument();
    expect(screen.queryByText(/System Offline/i)).not.toBeInTheDocument();
    expect(mockUseMetrics).not.toHaveBeenCalled();
  });

  it("scopes loading skeleton and connection error states to the Overview tab", () => {
    mockUseMetrics.mockReturnValue({
      metrics: null,
      hardware: null,
      history: emptyHistory,
      isLoading: true,
      isError: false,
      connectionState: "CONNECTING",
    });

    useSystemStore.setState({ activeTab: "overview" });
    const { rerender } = render(<Dashboard />);

    expect(screen.getByTestId("overview-skeleton")).toBeInTheDocument();
    expect(mockUseMetrics).toHaveBeenCalled();

    mockUseMetrics.mockReturnValue({
      metrics: null,
      hardware: null,
      history: emptyHistory,
      isLoading: false,
      isError: true,
      connectionState: "DISCONNECTED",
    });

    rerender(<Dashboard />);
    expect(screen.getByText("System Offline")).toBeInTheDocument();

    mockUseMetrics.mockReturnValue({
      metrics: {
        cpu_usage: 24.5,
        cpu_freq_mhz: 3600,
        per_core_cpu: [20, 29],
        memory: { used: 8, total: 32 },
        swap: { used: 0, total: 8 },
        disks: [],
        disk_io: { read_bytes_sec: 0, write_bytes_sec: 0 },
        network: { up: "1.0 MB/s", down: "2.0 MB/s", active_connections: 4 },
        total_net_bytes: { rx: 1024, tx: 2048 },
        load_average: [0.3, 0.2, 0.1],
        uptime: "2d 4h",
        processes: [],
        gpus: [],
        services: {},
      },
      hardware: null,
      history: emptyHistory,
      isLoading: false,
      isError: false,
      connectionState: "CONNECTED",
    });

    rerender(<Dashboard />);
    expect(screen.getByTestId("overview-tab")).toBeInTheDocument();
  });
});
