import { useWebSocket } from '@/contexts/WebSocketContext';
import { SystemMetrics } from '@/types/dashboard';

export function useMetrics() {
    const { data: wsData, isConnected, error } = useWebSocket();

    // Map the WebSocket state back to the expected properties
    // Services uses this indirectly depending on component logic 
    return {
        metrics: wsData?.system as SystemMetrics | null,
        services: wsData?.services || null,
        isLoading: !isConnected && !error,
        isError: !!error,
        error
    };
}
