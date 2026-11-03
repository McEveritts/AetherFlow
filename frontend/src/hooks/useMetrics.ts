import useSWR from 'swr';
import { useWebSocket } from '@/contexts/WebSocketContext';
import { SystemMetrics, HardwareReport, MetricsHistory } from '@/types/dashboard';
import { useHistoryStore, buildFallbackHistory, TimeWindow } from '@/store/useHistoryStore';

export { useHistoryStore };
export type { TimeWindow };

export function useMetrics() {
    const { data: wsData, connectionState } = useWebSocket();
    const { data: hardware } = useSWR<HardwareReport>('/api/v1/auth/system/hardware');

    // Fix #11: Selector returns a stable pre-computed reference from state
    const visibleHistory = useHistoryStore((state) => state.visibleHistory);
    const timeWindow = useHistoryStore((state) => state.timeWindow);
    const setTimeWindow = useHistoryStore((state) => state.setTimeWindow);

    const metrics = wsData?.system as SystemMetrics | null;

    // CONNECTING = initial connect → show skeleton
    // RECONNECTING = lost connection, trying to recover → show last-known data if available
    // FALLBACK = polling mode → show polling data
    // DEGRADED = stale data → show stale data with indicator
    // DISCONNECTED = completely dead → show error only if no cached data
    const effectiveHistory: MetricsHistory = (visibleHistory.timestamps.length === 0 && metrics)
        ? buildFallbackHistory(metrics)
        : visibleHistory;

    return {
        metrics,
        services: wsData?.services || null,
        hardware: hardware || null,
        history: effectiveHistory, // Component consumers get the windowed slice
        timeWindow,
        setTimeWindow,
        isLoading: (connectionState === 'CONNECTING' || connectionState === 'CONNECTED' || connectionState === 'FALLBACK') && !metrics,
        isError: connectionState === 'DISCONNECTED' && !metrics,
        connectionState,
    };
}
