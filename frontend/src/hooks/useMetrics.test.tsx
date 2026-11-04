import React, { Profiler } from "react";
import { act, render, screen, waitFor } from "@testing-library/react";
import { WebSocketProvider, useWebSocket } from "@/contexts/WebSocketContext";
import { useMetrics, useHistoryStore } from "@/hooks/useMetrics";
import { useConnectionStore } from "@/store/useConnectionStore";

let mockIsAuthenticated = true;
let mockPathname = "/";
const mockAddToast = jest.fn();

jest.mock("next/navigation", () => ({
  usePathname: () => mockPathname,
}));

jest.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    isAuthenticated: mockIsAuthenticated,
    user: { id: 1, username: "admin", role: "admin" },
  }),
}));

jest.mock("@/contexts/ToastContext", () => ({
  useToast: () => ({
    addToast: mockAddToast,
    toasts: [],
    toggleDrawer: jest.fn(),
  }),
}));

const mockApiFetch = jest.fn();
jest.mock("@/lib/fetcher", () => ({
  apiFetch: (...args: unknown[]) => mockApiFetch(...args),
}));

const mockGlobalMutate = jest.fn();
jest.mock("swr", () => ({
  __esModule: true,
  default: jest.fn(() => ({ data: null, mutate: jest.fn() })),
  mutate: (...args: unknown[]) => mockGlobalMutate(...args),
}));

class FakeWebSocket {
  static OPEN = 1;
  static instances: FakeWebSocket[] = [];
  url: string;
  readyState = FakeWebSocket.OPEN;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: ((error: unknown) => void) | null = null;
  send = jest.fn();
  close = jest.fn();

  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }
}

function AiMetricsProbe() {
  const { metrics } = useMetrics();
  return <div data-testid="ai-cpu">{metrics ? String(metrics.cpu_usage) : "none"}</div>;
}

function SecondMetricsConsumer() {
  const { history } = useMetrics();
  return <div data-testid="history-count">{String(history.cpu.length)}</div>;
}

function WebSocketConsumerProbe() {
  const { connectionState } = useWebSocket();
  return <div data-testid="ws-state">{connectionState}</div>;
}

describe("WebSocketProvider, useMetrics, and useHistoryStore transport decoupling", () => {
  const originalWebSocket = global.WebSocket;

  beforeEach(() => {
    mockIsAuthenticated = true;
    mockPathname = "/";
    mockAddToast.mockReset();
    FakeWebSocket.instances = [];
    mockGlobalMutate.mockReset();
    mockApiFetch.mockReset();
    mockApiFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ ticket: "test-ticket" }),
    });
    useConnectionStore.getState().reset();
    useHistoryStore.getState().resetHistory();
    global.WebSocket = FakeWebSocket as unknown as typeof WebSocket;
  });

  afterEach(() => {
    global.WebSocket = originalWebSocket;
  });

  it("collects history and updates Services SWR cache while Overview is inactive and feeds AiChat metrics", async () => {
    const { rerender } = render(
      <WebSocketProvider>
        <div data-testid="non-overview-shell" />
      </WebSocketProvider>
    );

    await waitFor(() => {
      expect(FakeWebSocket.instances.length).toBe(1);
    });

    const socket = FakeWebSocket.instances[0];

    act(() => {
      socket.onopen?.();
    });

    expect(useConnectionStore.getState().connectionState).toBe("CONNECTED");

    act(() => {
      socket.onmessage?.({
        data: JSON.stringify({
          type: "METRICS_UPDATE",
          data: {
            system: {
              cpu_usage: 37.5,
              memory: { used: 12, total: 24 },
              network: { down: "4 MB/s", up: "1 MB/s", active_connections: 9 },
              disk_io: { read_bytes_sec: 2048, write_bytes_sec: 1024 },
            },
            services: {
              jellyfin: { status: "running" },
            },
          },
        }),
      });
    });

    expect(useHistoryStore.getState().visibleHistory.cpu).toEqual([37.5, 37.5]);
    expect(mockGlobalMutate).toHaveBeenCalledTimes(1);
    expect(mockGlobalMutate).toHaveBeenCalledWith(
      "/api/v1/auth/services",
      { jellyfin: { status: "running" } },
      false
    );

    rerender(
      <WebSocketProvider>
        <div data-testid="non-overview-shell">
          <AiMetricsProbe />
        </div>
      </WebSocketProvider>
    );

    expect(screen.getByTestId("ai-cpu")).toHaveTextContent("37.5");
    expect(useHistoryStore.getState().visibleHistory.cpu).toEqual([37.5, 37.5]);
    expect(mockGlobalMutate).toHaveBeenCalledTimes(1);
  });

  it("deduplicates history pushes and SWR service mutations when multiple useMetrics consumers are active", async () => {
    render(
      <WebSocketProvider>
        <AiMetricsProbe />
        <SecondMetricsConsumer />
      </WebSocketProvider>
    );

    await waitFor(() => {
      expect(FakeWebSocket.instances.length).toBe(1);
    });

    const socket = FakeWebSocket.instances[0];

    act(() => {
      socket.onopen?.();
      socket.onmessage?.({
        data: JSON.stringify({
          type: "METRICS_UPDATE",
          data: {
            system: {
              cpu_usage: 51.2,
              memory: { used: 16, total: 32 },
              network: { down: "1 MB/s", up: "1 MB/s", active_connections: 3 },
              disk_io: { read_bytes_sec: 512, write_bytes_sec: 256 },
            },
            services: {
              sonarr: { status: "running" },
            },
          },
        }),
      });
    });

    expect(useHistoryStore.getState().history.cpu).toEqual([51.2, 51.2]);
    expect(mockGlobalMutate).toHaveBeenCalledTimes(1);
  });

  it("preserves known services on unknown discovery and publishes a completed empty scan", async () => {
    render(<WebSocketProvider><div /></WebSocketProvider>);
    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    const socket = FakeWebSocket.instances[0];
    const metrics = {
      cpu_usage: 25,
      memory: { used: 8, total: 32 },
      network: { down: "1 MB/s", up: "1 MB/s", active_connections: 1 },
      disk_io: { read_bytes_sec: 0, write_bytes_sec: 0 },
    };
    const sendServices = (services: Record<string, unknown> | null) => act(() => {
      socket.onmessage?.({
        data: JSON.stringify({ type: "METRICS_UPDATE", data: { system: metrics, services } }),
      });
    });

    act(() => socket.onopen?.());
    sendServices({ sonarr: { status: "running" } });
    expect(mockGlobalMutate).toHaveBeenCalledTimes(1);
    sendServices(null);
    expect(mockGlobalMutate).toHaveBeenCalledTimes(1);
    sendServices({});
    expect(mockGlobalMutate).toHaveBeenCalledTimes(2);
    expect(mockGlobalMutate).toHaveBeenLastCalledWith("/api/v1/auth/services", {}, false);
  });

  it("clears telemetry and history when the authenticated session ends", async () => {
    const { rerender } = render(<WebSocketProvider><AiMetricsProbe /></WebSocketProvider>);
    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    const socket = FakeWebSocket.instances[0];
    act(() => {
      socket.onopen?.();
      socket.onmessage?.({
        data: JSON.stringify({
          type: "METRICS_UPDATE",
          data: {
            system: {
              cpu_usage: 42,
              memory: { used: 8, total: 32 },
              network: { down: "1 MB/s", up: "1 MB/s", active_connections: 1 },
              disk_io: { read_bytes_sec: 0, write_bytes_sec: 0 },
            },
            services: { sonarr: { status: "running" } },
          },
        }),
      });
    });
    expect(screen.getByTestId("ai-cpu")).toHaveTextContent("42");
    expect(useHistoryStore.getState().history.cpu).toEqual([42, 42]);

    mockIsAuthenticated = false;
    mockPathname = "/login";
    rerender(<WebSocketProvider><AiMetricsProbe /></WebSocketProvider>);
    expect(socket.close).toHaveBeenCalled();
    expect(useHistoryStore.getState().history.cpu).toEqual([]);
    expect(screen.getByTestId("ai-cpu")).toHaveTextContent("none");

    mockIsAuthenticated = true;
    mockPathname = "/";
    rerender(<WebSocketProvider><AiMetricsProbe /></WebSocketProvider>);
    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(2));
    expect(useHistoryStore.getState().history.cpu).toEqual([]);
    expect(screen.getByTestId("ai-cpu")).toHaveTextContent("none");
  });

  it("does not re-render WebSocket context consumers when lastMessageAt changes", async () => {
    let consumerCommits = 0;

    render(
      <WebSocketProvider>
        <Profiler id="ws-consumer" onRender={() => { consumerCommits += 1; }}>
          <WebSocketConsumerProbe />
        </Profiler>
      </WebSocketProvider>
    );

    await waitFor(() => {
      expect(FakeWebSocket.instances.length).toBe(1);
    });

    const socket = FakeWebSocket.instances[0];
    act(() => {
      socket.onopen?.();
    });

    const baselineCommits = consumerCommits;

    act(() => {
      useConnectionStore.getState().setLastMessageAt(1700000005000);
      useConnectionStore.getState().setLastMessageAt(1700000006000);
    });

    expect(consumerCommits).toBe(baselineCommits);
  });

  it("hydrates persisted metrics_history on refresh and reconnect and merges with live samples without duplicates", async () => {
    const baseTs = 1_730_000_000_000;
    const persistedSnapshots = [
      {
        id: 1,
        timestamp: new Date(baseTs - 60_000).toISOString(),
        cpu_avg: 18.4,
        mem_used_gb: 8,
        mem_total_gb: 32,
        disk_read_bps: 1024,
        disk_write_bps: 512,
        net_rx_bytes: 10_000_000,
        net_tx_bytes: 5_000_000,
      },
      {
        id: 2,
        timestamp: new Date(baseTs - 45_000).toISOString(),
        cpu_avg: 22.6,
        mem_used_gb: 12,
        mem_total_gb: 32,
        disk_read_bps: 2048,
        disk_write_bps: 1024,
        net_rx_bytes: 11_500_000, // +1.5 MB over 15s = 100,000 B/s
        net_tx_bytes: 5_300_000,  // +300 KB over 15s = 20,000 B/s
      },
    ];

    mockApiFetch.mockImplementation(async (url: string) => {
      if (url.includes("/api/v1/auth/ws/ticket")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ ticket: "test-ticket" }),
        };
      }
      if (
        url.includes("/api/v1/auth/system/metrics/history") ||
        url.includes("/api/v1/admin/ai/predictions/history")
      ) {
        return {
          ok: true,
          status: 200,
          json: async () => persistedSnapshots,
        };
      }
      return { ok: false, status: 404, json: async () => ({}) };
    });

    render(
      <WebSocketProvider>
        <SecondMetricsConsumer />
      </WebSocketProvider>
    );

    await waitFor(() => {
      expect(FakeWebSocket.instances.length).toBe(1);
    });

    const socket = FakeWebSocket.instances[0];
    await act(async () => {
      socket.onopen?.();
    });

    await waitFor(() => {
      expect(useHistoryStore.getState().isHydrated).toBe(true);
    });

    expect(useHistoryStore.getState().history.cpu).toEqual([18.4, 22.6]);
    expect(useHistoryStore.getState().history.memory).toEqual([25, 37.5]);
    expect(useHistoryStore.getState().history.netDown).toEqual([0, 100000]);
    expect(useHistoryStore.getState().history.netUp).toEqual([0, 20000]);

    // Push a live sample and duplicate timestamp sample to verify merge & deduplication
    act(() => {
      useHistoryStore.getState().pushMetrics(
        {
          cpu_usage: 29.5,
          cpu_freq_mhz: 3600,
          per_core_cpu: [29.5],
          memory: { used: 16, total: 32 },
          swap: { used: 0, total: 8 },
          disk_space: { used: 100, total: 500, free: 400 },
          is_windows: false,
          disks: [],
          disk_io: { read_bytes_sec: 4096, write_bytes_sec: 2048 },
          network: { down: "2 MB/s", up: "1 MB/s", active_connections: 10 },
          total_net_bytes: { rx: 12_000_000, tx: 6_000_000 },
          load_average: [0.5, 0.4, 0.3],
          uptime: "1d",
          processes: [],
          gpus: [],
          services: {},
        },
        baseTs - 30_000
      );
      // Re-hydrating same persisted snapshots on reconnect must not duplicate points
      useHistoryStore.getState().hydrateHistory(persistedSnapshots);
    });

    expect(useHistoryStore.getState().history.cpu).toEqual([18.4, 22.6, 29.5]);
    expect(useHistoryStore.getState().history.timestamps).toEqual([
      baseTs - 60_000,
      baseTs - 45_000,
      baseTs - 30_000,
    ]);
  });

  it("supports longer time windows (1m, 5m, 15m, 1h, 6h, 24h), timestamp-based slicing, and gap handling", () => {
    const now = 1_730_050_000_000;
    const snapshots = [
      // 12 hours ago
      {
        timestamp: now - 12 * 3600_000,
        cpu_avg: 11,
        mem_used_gb: 4,
        mem_total_gb: 16,
        net_rx_bytes: 1_000_000,
        net_tx_bytes: 1_000_000,
      },
      // 2 hours ago (10h gap -> counter delta must clamp to 0 instead of spiking)
      {
        timestamp: now - 2 * 3600_000,
        cpu_avg: 22,
        mem_used_gb: 6,
        mem_total_gb: 16,
        net_rx_bytes: 500_000_000,
        net_tx_bytes: 250_000_000,
      },
      // 10 minutes ago
      {
        timestamp: now - 10 * 60_000,
        cpu_avg: 33,
        mem_used_gb: 8,
        mem_total_gb: 16,
        net_rx_bytes: 600_000_000,
        net_tx_bytes: 300_000_000,
      },
      // 3 minutes ago
      {
        timestamp: now - 3 * 60_000,
        cpu_avg: 44,
        mem_used_gb: 10,
        mem_total_gb: 16,
        net_rx_bytes: 700_000_000,
        net_tx_bytes: 350_000_000,
      },
      // Latest (now) — 3m gap since previous is > 2m GAP_THRESHOLD_MS, and only 1 point in 1m window
      {
        timestamp: now,
        cpu_avg: 55,
        mem_used_gb: 12,
        mem_total_gb: 16,
        net_rx_bytes: 701_800_000, // +1.8 MB over 180s = 10,000 B/s
        net_tx_bytes: 350_900_000, // +900 KB over 180s = 5,000 B/s
      },
    ];

    act(() => {
      useHistoryStore.getState().hydrateHistory(snapshots);
    });

    const stateAfterHydrate = useHistoryStore.getState();
    expect(stateAfterHydrate.gapCount).toBeGreaterThanOrEqual(3);
    // Counter jump across the 10-hour gap at index 1 must be clamped to 0 B/s
    expect(stateAfterHydrate.history.netDown[1]).toBe(0);
    // 180s delta (<= 300s) at index 4 computes valid rate
    expect(stateAfterHydrate.history.netDown[4]).toBe(10000);
    expect(stateAfterHydrate.history.netUp[4]).toBe(5000);

    // Default 5m window includes points at -3m and now
    expect(stateAfterHydrate.visibleHistory.cpu).toEqual([44, 55]);

    // 1m window only has `now` within [now - 60s, now], so gap handling pads it to 2 points [55, 55] for Sparkline
    act(() => useHistoryStore.getState().setTimeWindow("1m"));
    expect(useHistoryStore.getState().visibleHistory.cpu).toEqual([55, 55]);

    // 15m window includes -10m, -3m, now
    act(() => useHistoryStore.getState().setTimeWindow("15m"));
    expect(useHistoryStore.getState().visibleHistory.cpu).toEqual([33, 44, 55]);

    // 1h window still excludes -2h and -12h
    act(() => useHistoryStore.getState().setTimeWindow("1h"));
    expect(useHistoryStore.getState().visibleHistory.cpu).toEqual([33, 44, 55]);

    // 6h window includes -2h, -10m, -3m, now
    act(() => useHistoryStore.getState().setTimeWindow("6h"));
    expect(useHistoryStore.getState().visibleHistory.cpu).toEqual([22, 33, 44, 55]);

    // 24h window includes all 5 points (-12h, -2h, -10m, -3m, now)
    act(() => useHistoryStore.getState().setTimeWindow("24h"));
    expect(useHistoryStore.getState().visibleHistory.cpu).toEqual([11, 22, 33, 44, 55]);
  });
});
