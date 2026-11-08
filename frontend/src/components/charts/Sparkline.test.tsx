import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import Sparkline, {
  buildChartData,
  computeTimeContext,
  formatTimeEndpoint,
  validateTimestampsAlignment,
  computeEffectiveXDomain,
  computeEffectiveDomain,
} from "@/components/charts/Sparkline";
import OverviewTab from "@/components/tabs/OverviewTab";
import { SystemMetrics, MetricsHistory } from "@/types/dashboard";
import { apiFetch } from "@/lib/fetcher";

const renderedChartFrames: Array<Array<{ name: string; index?: number; val1?: number; val2?: number; timestamp?: number; timeLabel?: string }>> = [];
const renderedYAxisDomains: Array<[number, number] | undefined> = [];
const renderedXAxisProps: Array<{ dataKey?: string; type?: string; domain?: [number, number]; hide?: boolean }> = [];

jest.mock("@/lib/fetcher", () => ({ apiFetch: jest.fn() }));

jest.mock("recharts", () => ({
  ResponsiveContainer: function MockResponsiveContainer({ children }: { children: React.ReactNode }) {
    return <div data-testid="responsive-container">{children}</div>;
  },
  AreaChart: function MockAreaChart({
    data,
    children,
  }: {
    data: Array<{ name: string; index?: number; val1?: number; val2?: number; timestamp?: number; timeLabel?: string }>;
    children: React.ReactNode;
  }) {
    renderedChartFrames.push(data);
    return (
      <svg data-testid="area-chart" data-points={JSON.stringify(data)}>
        {children}
      </svg>
    );
  },
  Area: function MockArea({
    dataKey,
    dot,
    stroke,
  }: {
    dataKey?: string;
    dot?: boolean | object;
    stroke?: string;
  }) {
    return (
      <g
        data-testid="area-series"
        data-key={dataKey}
        data-stroke={stroke}
        data-has-dot={String(Boolean(dot))}
        data-dot={typeof dot === "object" ? JSON.stringify(dot) : String(dot)}
      />
    );
  },
  YAxis: function MockYAxis({ domain }: { domain?: [number, number] }) {
    renderedYAxisDomains.push(domain);
    return <g data-testid="y-axis" data-domain={JSON.stringify(domain)} />;
  },
  XAxis: function MockXAxis({ dataKey, type, domain, hide }: { dataKey?: string; type?: string; domain?: [number, number]; hide?: boolean }) {
    renderedXAxisProps.push({ dataKey, type, domain, hide });
    return (
      <g
        data-testid="x-axis"
        data-key={dataKey}
        data-type={type}
        data-domain={JSON.stringify(domain)}
        data-hide={String(hide)}
      />
    );
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

describe("Forecast cards and mini sparkline integration", () => {
  const PredictionsCard = jest.requireActual<typeof import("@/components/cards/PredictionsCard")>("@/components/cards/PredictionsCard").default;
  const BandwidthCard = jest.requireActual<typeof import("@/components/cards/BandwidthCard")>("@/components/cards/BandwidthCard").default;

  beforeEach(() => jest.mocked(apiFetch).mockReset());

  it("renders four bounded mini trends and hairline rows without nested dark wells", async () => {
    const report = {
      trend_summary: "Capacity remains within normal bounds.",
      cpu_trend: "increasing",
      memory_trend: "stable",
      disk_io_trend: "decreasing",
      network_trend: "critical",
      warnings: [],
      recommendations: ["Review network saturation."],
      predicted_bottleneck: "network",
      confidence_score: 0.9,
    };
    const history = [10, 20, 30].map((value, index) => ({
      id: index,
      timestamp: String(index),
      cpu_avg: value,
      mem_used_gb: value,
      mem_total_gb: 64,
      disk_read_bps: value,
      disk_write_bps: value,
      net_rx_bytes: value,
      net_tx_bytes: value,
    }));
    jest.mocked(apiFetch).mockImplementation(async input => ({
      ok: true,
      json: async () => String(input).includes("history") ? history : report,
    } as Response));
    const { container } = render(<PredictionsCard />);
    await screen.findByText("Bottleneck");
    expect(container.firstElementChild).toHaveClass("obs-telemetry-surface");
    expect(container.querySelector('[class*="bg-black/30"]')).toBeNull();
    expect(screen.getAllByTestId("area-chart")).toHaveLength(4);
    screen.getAllByTestId("responsive-container").forEach(chart => {
      const plot = chart.parentElement?.parentElement;
      expect(plot).toHaveStyle({ height: "32px" });
      expect(plot?.parentElement?.children).toHaveLength(1);
    });
    expect(screen.getByText("CPU").closest(".grid")).toHaveClass("grid-cols-1", "sm:grid-cols-2");
    expect(screen.queryByText(/Sample 1|3 samples/)).not.toBeInTheDocument();
    const disclosure = screen.getByRole("button", { name: "Show Forecast Details" });
    expect(disclosure).toHaveClass("min-h-[40px]", "obs-touch-target-standard");
    expect(disclosure).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(disclosure);
    expect(screen.getByText(report.trend_summary)).toBeInTheDocument();
    expect(disclosure).toHaveAttribute("aria-expanded", "true");
  });

  it("keeps bandwidth readiness and recommendations on the same glass surface", async () => {
    jest.mocked(apiFetch).mockResolvedValue({ ok: true, json: async () => ({
      recommended_upload_kbps: 1024,
      recommended_download_kbps: 2048,
      reasoning: "Leave capacity for peer discovery.",
      confidence: 0.85,
      swarm_health: "healthy",
      suggestions: [],
    }) } as Response);
    const { container } = render(<BandwidthCard />);
    expect(screen.getByText("Swarm Rate Optimizer Ready")).toBeInTheDocument();
    expect(container.firstElementChild).toHaveClass("obs-telemetry-surface");
    expect(container.querySelector('[class*="bg-black/30"]')).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Analyze" }));
    await screen.findByText("2.0 MB/s");
    expect(screen.getByText("1.0 MB/s")).toBeInTheDocument();
    expect(container.querySelector('[class*="bg-black/30"]')).toBeNull();
    expect(screen.getByRole("button", { name: "Apply Recommendations" })).toHaveClass("obs-touch-target-standard");
  });
});

describe("Sparkline component and regression coverage", () => {
  beforeEach(() => {
    renderedChartFrames.length = 0;
    renderedYAxisDomains.length = 0;
    renderedXAxisProps.length = 0;
    cpuWidgetRenderCount = 0;
  });

  it("updates chart series when history changes and freezes work during hover until mouse leave", () => {
    const { container, rerender } = render(<Sparkline data={[10.123, 20.456]} />);
    const rootElement = container.firstElementChild!;

    expect(renderedChartFrames).toHaveLength(1);
    expect(renderedChartFrames[0]).toEqual([
      { name: "P0", index: 0, val1: 10.12, val2: undefined, timestamp: undefined, timeLabel: undefined },
      { name: "P1", index: 1, val1: 20.46, val2: undefined, timestamp: undefined, timeLabel: undefined },
    ]);

    rerender(<Sparkline data={[10.123, 20.456, 30.789]} />);
    expect(renderedChartFrames).toHaveLength(2);
    expect(renderedChartFrames[1]).toEqual([
      { name: "P0", index: 0, val1: 10.12, val2: undefined, timestamp: undefined, timeLabel: undefined },
      { name: "P1", index: 1, val1: 20.46, val2: undefined, timestamp: undefined, timeLabel: undefined },
      { name: "P2", index: 2, val1: 30.79, val2: undefined, timestamp: undefined, timeLabel: undefined },
    ]);

    fireEvent.mouseEnter(rootElement);
    const framesBeforeHoveredUpdate = renderedChartFrames.length;

    rerender(<Sparkline data={[10.123, 20.456, 30.789, 45.5]} />);
    expect(renderedChartFrames).toHaveLength(framesBeforeHoveredUpdate);
    expect(screen.getByTestId("area-chart")).toHaveAttribute(
      "data-points",
      JSON.stringify([
        { name: "P0", index: 0, val1: 10.12 },
        { name: "P1", index: 1, val1: 20.46 },
        { name: "P2", index: 2, val1: 30.79 },
      ])
    );

    fireEvent.mouseLeave(rootElement);
    expect(renderedChartFrames).toHaveLength(framesBeforeHoveredUpdate + 1);
    expect(renderedChartFrames[renderedChartFrames.length - 1]).toEqual([
      { name: "P0", index: 0, val1: 10.12, val2: undefined, timestamp: undefined, timeLabel: undefined },
      { name: "P1", index: 1, val1: 20.46, val2: undefined, timestamp: undefined, timeLabel: undefined },
      { name: "P2", index: 2, val1: 30.79, val2: undefined, timestamp: undefined, timeLabel: undefined },
      { name: "P3", index: 3, val1: 45.5, val2: undefined, timestamp: undefined, timeLabel: undefined },
    ]);
  });

  it.each(["touchEnd", "touchCancel"] as const)("freezes both series and time/magnitude geometry during touch inspection until %s", (releaseEvent) => {
    const initialTimestamps = [1700000000000, 1700000001000];
    const updatedTimestamps = [1700000005000, 1700000007000, 1700000010000];
    const { container, rerender } = render(
      <Sparkline data={[10, 20]} data2={[4, 8]} timestamps={initialTimestamps} selectedWindow="5m" />
    );
    const rootElement = container.firstElementChild!;
    const initialPoints = screen.getByTestId("area-chart").getAttribute("data-points");
    const initialXDomain = screen.getByTestId("x-axis").getAttribute("data-domain");
    const initialYDomain = screen.getByTestId("y-axis").getAttribute("data-domain");

    fireEvent.touchStart(rootElement);
    rerender(<Sparkline data={[100, 200, 300]} data2={[40, 80, 120]} timestamps={updatedTimestamps} selectedWindow="5m" />);
    expect(screen.getByTestId("area-chart")).toHaveAttribute("data-points", initialPoints);
    expect(screen.getByTestId("x-axis")).toHaveAttribute("data-domain", initialXDomain);
    expect(screen.getByTestId("y-axis")).toHaveAttribute("data-domain", initialYDomain);
    expect(screen.getByText(formatTimeEndpoint(initialTimestamps[0]))).toBeInTheDocument();

    fireEvent[releaseEvent](rootElement);
    expect(screen.getByTestId("area-chart")).not.toHaveAttribute("data-points", initialPoints);
    expect(screen.getByTestId("x-axis")).not.toHaveAttribute("data-domain", initialXDomain);
    expect(screen.getByTestId("y-axis")).not.toHaveAttribute("data-domain", initialYDomain);
    expect(screen.getByText(formatTimeEndpoint(updatedTimestamps[0]))).toBeInTheDocument();
  });

  it("applies fixed 0-100 domain for percentage scale even with constant samples", () => {
    render(<Sparkline data={[14.8, 14.8, 14.8]} isPercentage={true} showMagnitudeReferences={true} />);
    const yAxisElement = screen.getByTestId("y-axis");
    expect(yAxisElement).toHaveAttribute("data-domain", JSON.stringify([0, 100]));
    expect(screen.getByText("100%")).toBeInTheDocument();
    expect(screen.getByText("50%")).toBeInTheDocument();
    expect(screen.getByText("0%")).toBeInTheDocument();
  });

  it("computes shared zero-based domain with sensible headroom encompassing both series", () => {
    render(<Sparkline data={[1000, 2000]} data2={[500, 3000]} unit="B/s" showMagnitudeReferences={true} />);
    const yAxisElement = screen.getByTestId("y-axis");
    expect(yAxisElement).toHaveAttribute("data-domain", JSON.stringify([0, 3450]));
    expect(screen.getByText("3.4 KB/s")).toBeInTheDocument();
    expect(screen.getByText("0 B/s")).toBeInTheDocument();
  });

  it("handles zero samples, single samples, and explicit yDomain safely", () => {
    expect(computeEffectiveDomain([], undefined, true)).toEqual([0, 100]);
    expect(computeEffectiveDomain([42], undefined, true)).toEqual([0, 100]);
    expect(computeEffectiveDomain([10, 20], undefined, false, [0, 50])).toEqual([0, 50]);

    const { rerender } = render(<Sparkline data={[]} isPercentage={true} />);
    expect(screen.getByText("Collecting · 0 samples")).toBeInTheDocument();
    expect(screen.queryByTestId("y-axis")).not.toBeInTheDocument();

    rerender(<Sparkline data={[42]} isPercentage={true} />);
    expect(screen.getByText("Collecting · 1 sample")).toBeInTheDocument();
    expect(screen.queryByTestId("y-axis")).not.toBeInTheDocument();

    rerender(<Sparkline data={[10, 20]} yDomain={[0, 50]} />);
    expect(screen.getByTestId("y-axis")).toHaveAttribute("data-domain", JSON.stringify([0, 50]));
  });

  it("renders real sample and time context when provided", () => {
    render(<Sparkline data={[10, 20, 30]} timeContext="30 samples (30s)" isPercentage={true} />);
    expect(screen.getByText("30 samples (30s)")).toBeInTheDocument();
  });

  it("uses content-driven height and a dedicated legible magnitude gutter outside the plot", () => {
    const { container } = render(
      <Sparkline
        data={[100, 200]}
        data2={[50, 150]}
        label="Down"
        label2="Up"
        currentValue="200 B/s"
        currentValue2="150 B/s"
        timeContext="60 samples (60s)"
        height={80}
        showMagnitudeReferences={true}
        unit="B/s"
      />
    );

    const rootElement = container.firstElementChild as HTMLElement;
    expect(rootElement.style.height).toBe("");
    expect(rootElement).toHaveClass("flex-col");

    const chartRow = screen.getByTestId("responsive-container").parentElement?.parentElement as HTMLElement;
    expect(chartRow.style.height).toBe("80px");

    const timeContextElement = screen.getByText("60 samples (60s)");
    expect(timeContextElement).toHaveClass("text-xs", "text-slate-400");

    const downLabelElement = screen.getByText("Down");
    expect(downLabelElement).toHaveClass("text-xs");
    expect(screen.getByText("200 B/s")).toHaveClass("sr-only");
    expect(screen.getByText("150 B/s")).toHaveClass("sr-only");

    const magnitudeReferences = screen.getByText("230 B/s").parentElement;
    expect(magnitudeReferences).toHaveClass("shrink-0", "text-xs", "text-slate-300", "font-mono");
    expect(magnitudeReferences).not.toHaveClass("absolute");
    expect(chartRow).toHaveClass("flex", "gap-2");
    expect(rootElement).not.toHaveClass("border", "bg-slate-950/60");
    expect(screen.getByText("230 B/s")).toBeInTheDocument();
    expect(screen.getByText("115 B/s")).toBeInTheDocument();
    expect(screen.getByText("0 B/s")).toBeInTheDocument();
  });

  it("keeps mini trends within their plot height without metadata, endpoints, or magnitude strips", () => {
    const { container } = render(
      <Sparkline data={[10, 30, 20]} height={32} variant="mini" label="CPU trend" showMagnitudeReferences />
    );
    const rootElement = container.firstElementChild as HTMLElement;
    expect(rootElement.children).toHaveLength(1);
    expect(rootElement.firstElementChild).toHaveStyle({ height: '32px' });
    expect(screen.getByTestId('area-chart')).toBeInTheDocument();
    expect(screen.queryByText(/Sample 1|Sample 3|CPU trend|3 samples/)).not.toBeInTheDocument();
  });

  it.each([{ data: [] }, { data: [10] }])("keeps sparse mini trends honest and bounded for $data", ({ data }) => {
    const { container } = render(<Sparkline data={data} height={32} variant="mini" />);
    expect(container.firstElementChild).toHaveStyle({ height: '32px' });
    expect(screen.getByText(/Collecting/)).toHaveClass('sr-only');
    expect(screen.queryByTestId('area-chart')).not.toBeInTheDocument();
  });

  it("keeps shared mature history metadata available to screen readers without repeating it visually", () => {
    render(<Sparkline data={[10, 30]} timestamps={[1000, 4000]} selectedWindow="5m" hasSharedSummary />);
    const metadata = screen.getByText('2 samples (3s span of 5m max)');
    expect(metadata).toHaveClass('sr-only');
    expect(metadata.parentElement).toHaveClass('sr-only');
    expect(screen.getByTestId('area-chart')).toBeInTheDocument();
  });

  it("encodes honest sparse data without fabricating zeros or duplicate points", () => {
    expect(buildChartData([])).toEqual([]);
    expect(buildChartData([42])).toEqual([
      { name: "P0", index: 0, val1: 42, val2: undefined, timestamp: undefined, timeLabel: undefined },
    ]);
  });

  it("enforces numeric time XAxis with collected-span domain on irregular timestamps without misaligned time labels", () => {
    const irregularTimestamps = [1710000000000, 1710000010000, 1710000060000];
    render(<Sparkline data={[10, 20, 30]} timestamps={irregularTimestamps} selectedWindow="5m" />);

    const xAxisElement = screen.getByTestId("x-axis");
    expect(xAxisElement).toHaveAttribute("data-key", "timestamp");
    expect(xAxisElement).toHaveAttribute("data-type", "number");
    expect(xAxisElement).toHaveAttribute(
      "data-domain",
      JSON.stringify([1710000000000, 1710000060000])
    );
    expect(xAxisElement).toHaveAttribute("data-hide", "true");

    expect(screen.getByText("3 samples (1m span of 5m max)")).toBeInTheDocument();
    expect(screen.getByText(formatTimeEndpoint(1710000000000))).toBeInTheDocument();
    expect(screen.getByText("1m span")).toBeInTheDocument();
    expect(screen.getByText(formatTimeEndpoint(1710000060000))).toBeInTheDocument();
    expect(screen.queryByText(/Now/)).not.toBeInTheDocument();
  });

  it("renders compact content-driven collecting summary for degenerate time-coordinate datasets without drawing empty plot canvas or axes", () => {
    const identicalTimestamp = 1710000000000;
    const identicalTimestamps = [identicalTimestamp, identicalTimestamp];
    const { rerender } = render(
      <Sparkline
        data={[14.8, 14.8]}
        timestamps={identicalTimestamps}
        selectedWindow="5m"
      />
    );

    expect(screen.queryByTestId("x-axis")).not.toBeInTheDocument();
    expect(screen.queryByTestId("area-series")).not.toBeInTheDocument();
    expect(screen.getByText("Collecting · 2 samples · 0s span")).toBeInTheDocument();
    expect(screen.queryByText("2 samples (0s span of 5m max)")).not.toBeInTheDocument();
    expect(screen.getByText(`Observed ${formatTimeEndpoint(identicalTimestamp)} · 5m max`)).toBeInTheDocument();
    expect(screen.getAllByText(new RegExp(formatTimeEndpoint(identicalTimestamp)))).toHaveLength(1);

    rerender(
      <Sparkline
        data={[14.8, 14.8]}
        data2={[44.4, 44.4]}
        label="Download"
        label2="Upload"
        currentValue="14.8 B/s"
        currentValue2="44.4 B/s"
        timestamps={identicalTimestamps}
        selectedWindow="5m"
      />
    );

    expect(screen.getByText("Download")).toBeInTheDocument();
    expect(screen.getByText("Upload")).toBeInTheDocument();
    expect(screen.getByText("14.8 B/s")).toBeInTheDocument();
    expect(screen.getByText("44.4 B/s")).toBeInTheDocument();
    expect(screen.queryByTestId("x-axis")).not.toBeInTheDocument();
    expect(screen.queryByTestId("area-series")).not.toBeInTheDocument();

    rerender(
      <Sparkline
        data={[14.8, 20.2]}
        timestamps={[identicalTimestamp, identicalTimestamp + 10000]}
        selectedWindow="5m"
      />
    );

    const matureXAxis = screen.getByTestId("x-axis");
    expect(matureXAxis).toHaveAttribute("data-key", "timestamp");
    expect(matureXAxis).toHaveAttribute("data-type", "number");
    expect(matureXAxis).toHaveAttribute(
      "data-domain",
      JSON.stringify([identicalTimestamp, identicalTimestamp + 10000])
    );
    const normalAreaElements = screen.getAllByTestId("area-series");
    expect(normalAreaElements).toHaveLength(1);
    expect(screen.queryByText(/Collecting ·/)).not.toBeInTheDocument();
  });

  it("renders compact startup presentation for sparse history without full magnitude axes", () => {
    const { rerender } = render(
      <Sparkline
        data={[]}
        selectedWindow="5m"
        showMagnitudeReferences={true}
      />
    );
    expect(screen.getByText("Collecting · 0 samples")).toBeInTheDocument();
    expect(screen.getByText("5m max")).toBeInTheDocument();
    expect(screen.queryByText("100%")).not.toBeInTheDocument();

    rerender(
      <Sparkline
        data={[50]}
        selectedWindow="5m"
        showMagnitudeReferences={true}
      />
    );
    expect(screen.getByText("Collecting · 1 sample")).toBeInTheDocument();
    expect(screen.getByText("5m max")).toBeInTheDocument();
    expect(screen.queryByText("100%")).not.toBeInTheDocument();

    rerender(
      <Sparkline
        data={[50, 60]}
        selectedWindow="5m"
        showMagnitudeReferences={true}
        isPercentage={true}
      />
    );
    expect(screen.queryByText(/Collecting ·/)).not.toBeInTheDocument();
    expect(screen.getByText("100%")).toBeInTheDocument();
    expect(screen.getByText("50%")).toBeInTheDocument();
    expect(screen.getByText("0%")).toBeInTheDocument();
  });

  it("renders sparse history status with bounded wrapping without shrink-0 or truncation classes", () => {
    const identicalTimestamp = 1710000000000;
    render(
      <Sparkline
        data={[14.8, 14.8]}
        timestamps={[identicalTimestamp, identicalTimestamp]}
        selectedWindow="5m"
      />
    );

    const statusBanner = screen.getByTestId("sparse-history-status");
    expect(statusBanner).toBeInTheDocument();
    expect(statusBanner).not.toHaveClass("shrink-0");
    expect(statusBanner).toHaveClass("shrink");
    expect(statusBanner).toHaveClass("min-w-0");
    expect(statusBanner).toHaveClass("max-w-full");
    expect(statusBanner).toHaveClass("whitespace-normal");
    expect(statusBanner).toHaveClass("break-words");
    expect(statusBanner).not.toHaveClass("truncate");
    expect(statusBanner).not.toHaveClass("overflow-hidden");

    const textSpan = screen.getByText("Collecting · 2 samples · 0s span");
    expect(textSpan).toBeInTheDocument();
    expect(textSpan).not.toHaveClass("shrink-0");
    expect(textSpan).toHaveClass("min-w-0");
    expect(textSpan).toHaveClass("max-w-full");
    expect(textSpan).toHaveClass("whitespace-normal");
    expect(textSpan).toHaveClass("break-words");

    const metadataSpan = screen.getByTestId("sparse-history-metadata");
    expect(metadataSpan).toBeInTheDocument();
    expect(metadataSpan).not.toHaveClass("shrink-0");
    expect(metadataSpan).toHaveClass("shrink");
    expect(metadataSpan).toHaveClass("min-w-0");
    expect(metadataSpan).toHaveClass("max-w-full");
    expect(metadataSpan).toHaveClass("whitespace-normal");
    expect(metadataSpan).toHaveClass("break-words");
  });

  it("provides concise nonduplicated sparse presentation distinguishing 0 samples, 1 sample, and coincident samples with authentic observation time and no duplicate endpoints", () => {
    const sampleTimestamp = 1710000000000;
    const { rerender } = render(
      <Sparkline
        data={[]}
        selectedWindow="5m"
      />
    );
    expect(screen.getByText("Collecting · 0 samples")).toBeInTheDocument();
    expect(screen.getByText("5m max")).toBeInTheDocument();
    expect(screen.queryByText(/Observed/)).not.toBeInTheDocument();

    rerender(
      <Sparkline
        data={[25]}
        timestamps={[sampleTimestamp]}
        selectedWindow="5m"
      />
    );
    expect(screen.getByText("Collecting · 1 sample")).toBeInTheDocument();
    expect(screen.getByText(`Observed ${formatTimeEndpoint(sampleTimestamp)} · 5m max`)).toBeInTheDocument();
    expect(screen.getAllByText(new RegExp(formatTimeEndpoint(sampleTimestamp)))).toHaveLength(1);

    rerender(
      <Sparkline
        data={[25, 25]}
        timestamps={[sampleTimestamp, sampleTimestamp]}
        selectedWindow="5m"
      />
    );
    expect(screen.getByText("Collecting · 2 samples · 0s span")).toBeInTheDocument();
    expect(screen.getByText(`Observed ${formatTimeEndpoint(sampleTimestamp)} · 5m max`)).toBeInTheDocument();
    expect(screen.getAllByText(new RegExp(formatTimeEndpoint(sampleTimestamp)))).toHaveLength(1);

    rerender(
      <Sparkline
        data={[25, 35]}
        timestamps={[sampleTimestamp, sampleTimestamp + 30000]}
        selectedWindow="5m"
      />
    );
    expect(screen.queryByText(/Collecting ·/)).not.toBeInTheDocument();
    expect(screen.getByText("2 samples (30s span of 5m max)")).toBeInTheDocument();
    expect(screen.getByText("30s span")).toBeInTheDocument();
    expect(screen.getByText(formatTimeEndpoint(sampleTimestamp))).toBeInTheDocument();
    expect(screen.getByText(formatTimeEndpoint(sampleTimestamp + 30000))).toBeInTheDocument();
  });

  it("validates timestamps alignment rejecting non-increasing, non-finite, and length-mismatched arrays", () => {
    expect(validateTimestampsAlignment(3, [1000, 2000, 3000])).toEqual({
      isValid: true,
      startTimestamp: 1000,
      endTimestamp: 3000,
      spanSeconds: 2,
    });
    expect(validateTimestampsAlignment(3, [1000, 2000])).toEqual({ isValid: false });
    expect(validateTimestampsAlignment(2, [2000, 1000])).toEqual({ isValid: false });
    expect(validateTimestampsAlignment(2, [1000, NaN])).toEqual({ isValid: false });
    expect(validateTimestampsAlignment(2, [1000, Infinity])).toEqual({ isValid: false });
    expect(validateTimestampsAlignment(0, [])).toEqual({ isValid: false });

    expect(computeEffectiveXDomain(3, { isValid: true, startTimestamp: 1000, endTimestamp: 3000 })).toEqual([1000, 3000]);
    expect(computeEffectiveXDomain(1, { isValid: true, startTimestamp: 1000, endTimestamp: 1000 })).toEqual([0, 2000]);
    expect(computeEffectiveXDomain(3, { isValid: false })).toEqual([0, 2]);
    expect(computeEffectiveXDomain(1, { isValid: false })).toEqual([0, 1]);
  });

  it("falls back to sample-sequence XAxis for missing, NaN, out-of-order, or mismatched timestamps", () => {
    const { rerender } = render(<Sparkline data={[10, 20]} />);
    let xAxisElement = screen.getByTestId("x-axis");
    expect(xAxisElement).toHaveAttribute("data-key", "index");
    expect(xAxisElement).toHaveAttribute("data-type", "number");
    expect(xAxisElement).toHaveAttribute("data-domain", JSON.stringify([0, 1]));
    expect(screen.getByText("Sample 1")).toBeInTheDocument();
    expect(screen.getByText("Sample 2")).toBeInTheDocument();
    expect(screen.getByText("2 samples (sequence)")).toBeInTheDocument();
    expect(screen.queryByText(/Now/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Start/)).not.toBeInTheDocument();

    rerender(<Sparkline data={[10, 20, 30]} timestamps={[1710000000000, 1710000010000]} />);
    xAxisElement = screen.getByTestId("x-axis");
    expect(xAxisElement).toHaveAttribute("data-key", "index");
    expect(xAxisElement).toHaveAttribute("data-domain", JSON.stringify([0, 2]));
    expect(screen.getByText("3 samples (sample sequence)")).toBeInTheDocument();
    expect(screen.getByText("Sample 1")).toBeInTheDocument();
    expect(screen.getByText("Sample 3")).toBeInTheDocument();
    expect(screen.getByText("3 samples (sequence)")).toBeInTheDocument();

    rerender(<Sparkline data={[10, 20]} timestamps={[1710000020000, 1710000010000]} />);
    xAxisElement = screen.getByTestId("x-axis");
    expect(xAxisElement).toHaveAttribute("data-key", "index");
    expect(xAxisElement).toHaveAttribute("data-domain", JSON.stringify([0, 1]));
    expect(screen.getByText("2 samples (sample sequence)")).toBeInTheDocument();

    rerender(<Sparkline data={[10, 20]} timestamps={[NaN, 1710000010000]} />);
    xAxisElement = screen.getByTestId("x-axis");
    expect(xAxisElement).toHaveAttribute("data-key", "index");
    expect(xAxisElement).toHaveAttribute("data-domain", JSON.stringify([0, 1]));
    expect(screen.getByText("2 samples (sample sequence)")).toBeInTheDocument();
  });

  it("handles single known sample with single observation time and single unknown sample with concise status", () => {
    const singleKnownTimestamp = 1710000000000;
    const { rerender } = render(<Sparkline data={[42]} timestamps={[singleKnownTimestamp]} />);
    expect(screen.queryByTestId("x-axis")).not.toBeInTheDocument();
    expect(screen.queryByTestId("area-series")).not.toBeInTheDocument();
    expect(screen.getByText("Collecting · 1 sample")).toBeInTheDocument();
    expect(screen.getByText(`Observed ${formatTimeEndpoint(singleKnownTimestamp)}`)).toBeInTheDocument();
    expect(screen.getAllByText(new RegExp(formatTimeEndpoint(singleKnownTimestamp)))).toHaveLength(1);
    expect(screen.queryByText("single sample")).not.toBeInTheDocument();
    expect(screen.queryByText(/Now/)).not.toBeInTheDocument();

    rerender(<Sparkline data={[42]} />);
    expect(screen.queryByTestId("x-axis")).not.toBeInTheDocument();
    expect(screen.queryByTestId("area-series")).not.toBeInTheDocument();
    expect(screen.getByText("Collecting · 1 sample")).toBeInTheDocument();
    expect(screen.queryByText("Sample 1")).not.toBeInTheDocument();
    expect(screen.queryByText("single sample")).not.toBeInTheDocument();
    expect(screen.queryByText(/Now/)).not.toBeInTheDocument();
  });

  it("encodes aligned millisecond timestamps and formats honest time endpoints", () => {
    const timestampStart = 1710000000000;
    const timestampEnd = 1710000030000;
    const chartData = buildChartData([10, 20], undefined, [timestampStart, timestampEnd]);
    expect(chartData).toHaveLength(2);
    expect(chartData[0].timestamp).toBe(timestampStart);
    expect(chartData[1].timestamp).toBe(timestampEnd);
    expect(chartData[0].name).toBe(formatTimeEndpoint(timestampStart));

    const timeContext = computeTimeContext({
      sampleCount: 2,
      timestamps: [timestampStart, timestampEnd],
      selectedWindow: "5m",
    });
    expect(timeContext).toBe("2 samples (30s span of 5m max)");
  });

  it("handles irregular timestamps and sparse single sample with selected window", () => {
    const timestampSingle = 1710000000000;
    const singleContext = computeTimeContext({
      sampleCount: 1,
      timestamps: [timestampSingle],
      selectedWindow: "15m",
    });
    expect(singleContext).toContain("1 sample");
    expect(singleContext).toContain("15m max");

    const irregularTimestamps = [1710000000000, 1710000015000, 1710000075000];
    const irregularContext = computeTimeContext({
      sampleCount: 3,
      timestamps: irregularTimestamps,
      selectedWindow: "5m",
    });
    expect(irregularContext).toBe("3 samples (1m 15s span of 5m max)");
  });

  it("falls back to sample sequence when timestamps are genuinely unknown without inventing times", () => {
    const fallbackContext = computeTimeContext({
      sampleCount: 4,
    });
    expect(fallbackContext).toBe("4 samples (sample sequence)");

    const zeroContext = computeTimeContext({
      sampleCount: 0,
      selectedWindow: "5m",
    });
    expect(zeroContext).toBe("0 samples (5m max)");
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

    const fourthHistoryUpdatedTimestamps: MetricsHistory = {
      ...thirdHistoryUpdatedCpuSeries,
      timestamps: [1, 2, 3],
    };
    rerender(
      <OverviewTab metrics={buildMetrics([20, 35], 25)} hardware={null} history={fourthHistoryUpdatedTimestamps} />
    );
    expect(cpuWidgetRenderCount).toBe(4);
  });

  it("renders quiet compact secondary status when hasSharedSummary is enabled while retaining dual-series metrics and no duplicate bookkeeping", () => {
    const coincidentTimestamp = 1710000000000;
    render(
      <Sparkline
        data={[14.8, 14.8]}
        data2={[44.4, 44.4]}
        label="Download"
        label2="Upload"
        currentValue="14.8 B/s"
        currentValue2="44.4 B/s"
        timestamps={[coincidentTimestamp, coincidentTimestamp]}
        selectedWindow="5m"
        hasSharedSummary={true}
      />
    );

    expect(screen.getByText("Download")).toBeInTheDocument();
    expect(screen.getByText("Upload")).toBeInTheDocument();
    expect(screen.getByText("14.8 B/s")).toBeInTheDocument();
    expect(screen.getByText("44.4 B/s")).toBeInTheDocument();
    expect(screen.queryByTestId("sparse-history-status")).not.toBeInTheDocument();
    expect(screen.queryByTestId("sparse-history-metadata")).not.toBeInTheDocument();
    expect(screen.queryByTestId("sparse-history-qualifier")).not.toBeInTheDocument();
    expect(screen.queryByText(/Observed/)).not.toBeInTheDocument();
    expect(screen.queryByTestId("x-axis")).not.toBeInTheDocument();
    expect(screen.queryByTestId("area-series")).not.toBeInTheDocument();
  });

  it("renders quiet local history qualifier for single-series widgets when hasSharedSummary is true", () => {
    const coincidentTimestamp = 1710000000000;
    render(
      <Sparkline
        data={[14.8, 14.8]}
        timestamps={[coincidentTimestamp, coincidentTimestamp]}
        selectedWindow="5m"
        hasSharedSummary={true}
      />
    );

    expect(screen.getByTestId("sparse-history-qualifier")).toHaveTextContent("History collecting");
    expect(screen.queryByTestId("sparse-history-status")).not.toBeInTheDocument();
    expect(screen.queryByTestId("sparse-history-metadata")).not.toBeInTheDocument();
  });

  it("formats aligned timestamp in explicit UTC across non-UTC environments", () => {
    const epochUtcTimestamp = Date.UTC(2026, 10, 7, 23, 0, 0);
    const formattedUtcString = formatTimeEndpoint(epochUtcTimestamp);
    expect(formattedUtcString).toBe("23:00:00 UTC");
    expect(formattedUtcString.endsWith(" UTC")).toBe(true);
  });
});
