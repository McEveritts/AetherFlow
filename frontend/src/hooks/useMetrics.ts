import { useRef, useEffect } from 'react';
import useSWR, { mutate as globalMutate } from 'swr';
import { useWebSocket } from '@/contexts/WebSocketContext';
import { SystemMetrics, HardwareReport, MetricsHistory } from '@/types/dashboard';
import { create } from 'zustand';

const HISTORY_SIZE = 60; // 60 data points = 2 minutes at 2s intervals

function parseSpeed(speed: string): number {
    if (!speed) return 0;
    const match = speed.match(/([\d.]+)\s*([KMGTPE]?)B\/s/i);
    if (!match) return 0;
    const val = parseFloat(match[1]);
    const unit = match[2].toUpperCase();
    const multipliers: Record<string, number> = { '': 1, 'K': 1024, 'M': 1048576, 'G': 1073741824 };
    return val * (multipliers[unit] || 1);
}

// Zustand store for metrics history — avoids React 19's setState-in-effect restriction
const useHistoryStore = create<{
    history: MetricsHistory;
    lastPushAt: number;
    pushMetrics: (metrics: SystemMetrics) => void;
}>((set, get) => ({
    history: {
        cpu: [],
        memory: [],
        netDown: [],
        netUp: [],
        diskRead: [],
        diskWrite: [],
        timestamps: [],
    },
    lastPushAt: 0,
    pushMetrics: (metrics: SystemMetrics) => {
        const now = Date.now();
        if (now - get().lastPushAt < 500) return; // Throttle: max once per 500ms

        const push = (arr: number[], val: number): number[] => {
            const newArr = [...arr, val];
            if (newArr.length > HISTORY_SIZE) newArr.shift();
            return newArr;
        };

        set((state) => ({
            lastPushAt: now,
            history: {
                cpu: push(state.history.cpu, metrics.cpu_usage),
                memory: push(state.history.memory, metrics.memory ? (metrics.memory.used / metrics.memory.total) * 100 : 0),
                netDown: push(state.history.netDown, parseSpeed(metrics.network?.down as string)),
                netUp: push(state.history.netUp, parseSpeed(metrics.network?.up as string)),
                diskRead: push(state.history.diskRead, metrics.disk_io?.read_bytes_sec || 0),
                diskWrite: push(state.history.diskWrite, metrics.disk_io?.write_bytes_sec || 0),
                timestamps: push(state.history.timestamps, now),
            },
        }));
    },
}));

export function useMetrics() {
    const { data: wsData, connectionState } = useWebSocket();
    const { data: hardware } = useSWR<HardwareReport>('/api/system/hardware');

    const history = useHistoryStore((s) => s.history);
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
            globalMutate('/api/services', wsData.services, false);
        }
    }, [wsData?.services]);

    const isConnected = connectionState === 'CONNECTED' || connectionState === 'FALLBACK';

    return {
        metrics,
        services: wsData?.services || null,
        hardware: hardware || null,
        history: history,
        isLoading: !isConnected && !metrics,
        isError: connectionState === 'RECONNECTING' && !metrics,
        connectionState,
    };
}
