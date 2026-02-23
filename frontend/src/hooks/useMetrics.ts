import { useRef, useCallback } from 'react';
import useSWR from 'swr';
import { useWebSocket } from '@/contexts/WebSocketContext';
import { SystemMetrics, HardwareReport, MetricsHistory } from '@/types/dashboard';

const fetcher = (url: string) => fetch(url).then(res => res.json());

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

export function useMetrics() {
    const { data: wsData, isConnected, error } = useWebSocket();
    const { data: hardware, error: hwError } = useSWR<HardwareReport>('/api/system/hardware', fetcher, { revalidateOnFocus: false });

    const historyRef = useRef<MetricsHistory>({
        cpu: [],
        memory: [],
        netDown: [],
        netUp: [],
        diskRead: [],
        diskWrite: [],
        timestamps: [],
    });

    const pushHistory = useCallback((metrics: SystemMetrics) => {
        const h = historyRef.current;
        const push = (arr: number[], val: number) => {
            arr.push(val);
            if (arr.length > HISTORY_SIZE) arr.shift();
        };
        push(h.cpu, metrics.cpu_usage);
        push(h.memory, metrics.memory ? (metrics.memory.used / metrics.memory.total) * 100 : 0);
        push(h.netDown, parseSpeed(metrics.network?.down as string));
        push(h.netUp, parseSpeed(metrics.network?.up as string));
        push(h.diskRead, metrics.disk_io?.read_bytes_sec || 0);
        push(h.diskWrite, metrics.disk_io?.write_bytes_sec || 0);
        push(h.timestamps, Date.now());
    }, []);

    const metrics = wsData?.system as SystemMetrics | null;
    if (metrics) {
        // Throttle history pushes to every 500ms — live values update at 100ms but sparklines don't need that much data
        const lastTs = historyRef.current.timestamps[historyRef.current.timestamps.length - 1];
        if (!lastTs || Date.now() - lastTs > 500) {
            pushHistory(metrics);
        }
    }

    return {
        metrics,
        services: wsData?.services || null,
        hardware: hardware || null,
        history: historyRef.current,
        isLoading: !isConnected && !error,
        isError: !!error,
        error
    };
}
