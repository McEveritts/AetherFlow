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
});
