import { useRef, useEffect } from 'react';
import useSWR, { mutate as globalMutate } from 'swr';
import { useWebSocket } from '@/contexts/WebSocketContext';
import { SystemMetrics, HardwareReport, MetricsHistory } from '@/types/dashboard';
import { create } from 'zustand';

export type TimeWindow = '1m' | '5m' | '1h';

// FALLBACK: Using fixed 1800-sample cap until Retention Policy (Sample Count vs. Wall-Clock) is ratified.
const MAX_HISTORY_SIZE = 1800; // 1800 data points = 1 hour at 2s intervals
const WINDOW_SIZES: Record<TimeWindow, number> = {
    '1m': 30,    // 1 min
    '5m': 150,   // 5 min
    '1h': 1800,  // 1 hour
};

function parseSpeed(speed: string): number {
    if (!speed) return 0;
    const match = speed.match(/([\d.]+)\s*([KMGTPE]?)B\/s/i);
    if (!match) return 0;
    const val = parseFloat(match[1]);
    const unit = match[2].toUpperCase();
    const multipliers: Record<string, number> = { '': 1, 'K': 1024, 'M': 1048576, 'G': 1073741824 };
    return val * (multipliers[unit] || 1);
}

// Helper: slice history to the visible window
function sliceHistory(history: MetricsHistory, window: TimeWindow): MetricsHistory {
    const limit = WINDOW_SIZES[window];
    return {
        cpu: history.cpu.slice(-limit),
        memory: history.memory.slice(-limit),
        netDown: history.netDown.slice(-limit),
        netUp: history.netUp.slice(-limit),
        diskRead: history.diskRead.slice(-limit),
        diskWrite: history.diskWrite.slice(-limit),
        timestamps: history.timestamps.slice(-limit),
    };
}

const emptyHistory: MetricsHistory = {
    cpu: [],
    memory: [],
    netDown: [],
    netUp: [],
    diskRead: [],
    diskWrite: [],
    timestamps: [],
};

// Fix #11: Zustand store stores pre-calculated visibleHistory in state
// instead of computing it via a selector that returns a new reference
// on every call (which caused React 18's useSyncExternalStore infinite loop).
const useHistoryStore = create<{
    timeWindow: TimeWindow;
    setTimeWindow: (w: TimeWindow) => void;
    history: MetricsHistory;
    visibleHistory: MetricsHistory;
    lastPushAt: number;
    pushMetrics: (metrics: SystemMetrics) => void;
}>((set, get) => ({
    timeWindow: '5m', // Default to 5 minutes
    setTimeWindow: (w: TimeWindow) => set((state) => ({
        timeWindow: w,
        visibleHistory: sliceHistory(state.history, w),
    })),
    history: emptyHistory,
    visibleHistory: emptyHistory,
    lastPushAt: 0,
    pushMetrics: (metrics: SystemMetrics) => {
        const now = Date.now();
        if (now - get().lastPushAt < 250) return; // Throttle: max once per 250ms

        const push = (arr: number[], val: number): number[] => {
            // Optimised push to avoid memory reallocation
            const newArr = [...arr, val];
            if (newArr.length > MAX_HISTORY_SIZE) newArr.shift();
            return newArr;
        };

        set((state) => {
            const newHistory: MetricsHistory = {
                cpu: push(state.history.cpu, metrics.cpu_usage),
                memory: push(state.history.memory, metrics.memory ? (metrics.memory.used / metrics.memory.total) * 100 : 0),
                netDown: push(state.history.netDown, parseSpeed(metrics.network?.down as string)),
                netUp: push(state.history.netUp, parseSpeed(metrics.network?.up as string)),
                diskRead: push(state.history.diskRead, metrics.disk_io?.read_bytes_sec || 0),
                diskWrite: push(state.history.diskWrite, metrics.disk_io?.write_bytes_sec || 0),
                timestamps: push(state.history.timestamps, now),
            };
            return {
                lastPushAt: now,
                history: newHistory,
                visibleHistory: sliceHistory(newHistory, state.timeWindow),
            };
        });
    },
}));

export function useMetrics() {
    const { data: wsData, connectionState } = useWebSocket();
    const { data: hardware } = useSWR<HardwareReport>('/api/v1/auth/system/hardware');

    // Fix #11: Selector returns a stable pre-computed reference from state
    const visibleHistory = useHistoryStore((s) => s.visibleHistory);
    const timeWindow = useHistoryStore((s) => s.timeWindow);
    const setTimeWindow = useHistoryStore((s) => s.setTimeWindow);
    const pushMetrics = useHistoryStore((s) => s.pushMetrics);

    const metrics = wsData?.system as SystemMetrics | null;

    // Use ref to track previous metrics identity to avoid redundant pushes
    const prevMetricsRef = useRef<SystemMetrics | null>(null);

    // Push metrics to history store when WebSocket delivers new data
    useEffect(() => {
        if (metrics && metrics !== prevMetricsRef.current) {
            prevMetricsRef.current = metrics;
            pushMetrics(metrics);
        }
    }, [metrics, pushMetrics]);

    // Push fresh service status from WebSocket into the SWR cache
    // so ServicesTab updates in real-time without its own polling
    useEffect(() => {
        if (wsData?.services) {
            globalMutate('/api/v1/auth/services', wsData.services, false);
        }
    }, [wsData?.services]);

    // CONNECTING = initial connect → show skeleton
    // RECONNECTING = lost connection, trying to recover → show last-known data if available
    // FALLBACK = polling mode → show polling data
    // DEGRADED = stale data → show stale data with indicator
    // DISCONNECTED = completely dead → show error only if no cached data
    const isConnected = connectionState === 'CONNECTED' || connectionState === 'FALLBACK' || connectionState === 'DEGRADED';

    return {
        metrics,
        services: wsData?.services || null,
        hardware: hardware || null,
        history: visibleHistory, // Component consumers get the windowed slice
        timeWindow,
        setTimeWindow,
        isLoading: connectionState === 'CONNECTING' && !metrics,
        isError: connectionState === 'DISCONNECTED' && !metrics,
        connectionState,
    };
}
