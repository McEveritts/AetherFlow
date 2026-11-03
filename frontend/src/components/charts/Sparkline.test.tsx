import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import Sparkline from "@/components/charts/Sparkline";
import OverviewTab from "@/components/tabs/OverviewTab";
import { SystemMetrics, MetricsHistory } from "@/types/dashboard";

const renderedChartFrames: Array<Array<{ name: string; val1: number; val2?: number }>> = [];

jest.mock("recharts", () => ({
  ResponsiveContainer: function MockResponsiveContainer({ children }: { children: React.ReactNode }) {
    return <div data-testid="responsive-container">{children}</div>;
  },
  AreaChart: function MockAreaChart({
    data,
    children,
  }: {
    data: Array<{ name: string; val1: number; val2?: number }>;
    children: React.ReactNode;
  }) {
    renderedChartFrames.push(data);
    return (
      <div data-testid="area-chart" data-points={JSON.stringify(data)}>
        {children}
      </div>
    );
  },
  Area: function MockArea() {
    return <div data-testid="area-series" />;
  },
  Tooltip: function MockTooltip() {
    return null;
  },
}));

let cpuWidgetRenderCount = 0;
jest.mock("@/components/widgets/CpuWidget", () => {
  return function MockCpuWidget({ cpuData, history }: { cpuData: { usage: number; cores: number[] }; history: MetricsHistory }) {
    cpuWidgetRenderCount += 1;
    return (
      <div data-testid="cpu-widget">
        {cpuData.usage}:{history.cpu.join(",")}:{cpuData.cores.join(",")}
      </div>
    );
  };
});

jest.mock("@/components/widgets/MemoryWidget", () => function MockMemoryWidget() {
  return <div data-testid="memory-widget" />;
});
jest.mock("@/components/widgets/NetworkWidget", () => function MockNetworkWidget() {
  return <div data-testid="network-widget" />;
});
jest.mock("@/components/widgets/DiskIOWidget", () => function MockDiskIOWidget() {
  return <div data-testid="disk-io-widget" />;
});
jest.mock("@/components/widgets/ProcessWidget", () => function MockProcessWidget() {
  return <div data-testid="process-widget" />;
});
jest.mock("@/components/widgets/StorageWidget", () => function MockStorageWidget() {
  return <div data-testid="storage-widget" />;
});
jest.mock("@/components/widgets/AppTopologyMap", () => function MockAppTopologyMap() {
  return <div data-testid="topology-widget" />;
});
jest.mock("@/components/widgets/GpuWidget", () => function MockGpuWidget() {
  return <div data-testid="gpu-widget" />;
});
jest.mock("@/components/widgets/DataUsageHistoryWidget", () => function MockDataUsageHistoryWidget() {
  return <div data-testid="data-usage-widget" />;
});
jest.mock("@/components/cards/BandwidthCard", () => function MockBandwidthCard() {
  return <div data-testid="bandwidth-card" />;
});
jest.mock("@/components/cards/PredictionsCard", () => function MockPredictionsCard() {
  return <div data-testid="predictions-card" />;
});

function buildMetrics(cores: number[], usage = 25): SystemMetrics {
  return {
    cpu_usage: usage,
    cpu_freq_mhz: 3600,
    per_core_cpu: cores,
    memory: { used: 8, total: 32 },
    swap: { used: 0, total: 8 },
    disk_space: { used: 256, total: 1024, free: 768 },
    is_windows: false,
    disks: [],
    disk_io: { read_bytes_sec: 0, write_bytes_sec: 0 },
    network: { up: "1 MB/s", down: "2 MB/s", active_connections: 5 },
    total_net_bytes: { rx: 1000, tx: 2000 },
    load_average: [0.2, 0.2, 0.2],
    uptime: "1d",
    processes: [],
    gpus: [],
    services: {},
  };
}

describe("Sparkline hover freeze and OverviewTab CPU widget memoization", () => {
  beforeEach(() => {
    renderedChartFrames.length = 0;
    cpuWidgetRenderCount = 0;
  });

  it("updates chart series when history changes and freezes work during hover until mouse leave", () => {
    const { container, rerender } = render(<Sparkline data={[10.123, 20.456]} />);
    const rootElement = container.firstElementChild!;

    expect(renderedChartFrames).toHaveLength(1);
    expect(renderedChartFrames[0]).toEqual([
      { name: "P0", val1: 10.12, val2: undefined },
      { name: "P1", val1: 20.46, val2: undefined },
    ]);

    rerender(<Sparkline data={[10.123, 20.456, 30.789]} />);
    expect(renderedChartFrames).toHaveLength(2);
    expect(renderedChartFrames[1]).toEqual([
      { name: "P0", val1: 10.12, val2: undefined },
      { name: "P1", val1: 20.46, val2: undefined },
      { name: "P2", val1: 30.79, val2: undefined },
    ]);

    fireEvent.mouseEnter(rootElement);
    const framesBeforeHoveredUpdate = renderedChartFrames.length;

    rerender(<Sparkline data={[10.123, 20.456, 30.789, 45.5]} />);
    expect(renderedChartFrames).toHaveLength(framesBeforeHoveredUpdate);
    expect(screen.getByTestId("area-chart")).toHaveAttribute(
      "data-points",
      JSON.stringify([
        { name: "P0", val1: 10.12 },
        { name: "P1", val1: 20.46 },
        { name: "P2", val1: 30.79 },
      ])
    );

    fireEvent.mouseLeave(rootElement);
    expect(renderedChartFrames).toHaveLength(framesBeforeHoveredUpdate + 1);
    expect(renderedChartFrames[renderedChartFrames.length - 1]).toEqual([
      { name: "P0", val1: 10.12, val2: undefined },
      { name: "P1", val1: 20.46, val2: undefined },
      { name: "P2", val1: 30.79, val2: undefined },
      { name: "P3", val1: 45.5, val2: undefined },
    ]);
  });

  it("avoids re-rendering MemoCpuWidget on cloned core arrays with unchanged history, but re-renders when history or core values change", () => {
    const sharedCpuHistory = [25, 25];
    const firstHistory: MetricsHistory = {
      cpu: sharedCpuHistory,
      memory: [25, 25],
      netDown: [0, 0],
      netUp: [0, 0],
      diskRead: [0, 0],
      diskWrite: [0, 0],
      timestamps: [1, 2],
    };

    const { rerender } = render(
      <OverviewTab metrics={buildMetrics([20, 30], 25)} hardware={null} history={firstHistory} />
    );
    expect(cpuWidgetRenderCount).toBe(1);

    const secondHistorySameCpuSeries: MetricsHistory = {
      ...firstHistory,
      memory: [26, 26],
    };
    rerender(
      <OverviewTab metrics={buildMetrics([20, 30], 25)} hardware={null} history={secondHistorySameCpuSeries} />
    );
    expect(cpuWidgetRenderCount).toBe(1);

    const thirdHistoryUpdatedCpuSeries: MetricsHistory = {
      ...firstHistory,
      cpu: [25, 25, 28],
    };
    rerender(
      <OverviewTab metrics={buildMetrics([20, 30], 25)} hardware={null} history={thirdHistoryUpdatedCpuSeries} />
    );
    expect(cpuWidgetRenderCount).toBe(2);

    rerender(
      <OverviewTab metrics={buildMetrics([20, 35], 25)} hardware={null} history={thirdHistoryUpdatedCpuSeries} />
    );
    expect(cpuWidgetRenderCount).toBe(3);
  });
});
