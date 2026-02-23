import useSWR from 'swr';
import { useWebSocket } from '@/contexts/WebSocketContext';
import { SystemMetrics, HardwareReport } from '@/types/dashboard';

const fetcher = (url: string) => fetch(url).then(res => res.json());

export function useMetrics() {
    const { data: wsData, isConnected, error } = useWebSocket();
    const { data: hardware, error: hwError } = useSWR<HardwareReport>('/api/system/hardware', fetcher, { revalidateOnFocus: false });

    return {
        metrics: wsData?.system as SystemMetrics | null,
        services: wsData?.services || null,
        hardware: hardware || null,
        isLoading: !isConnected && !error,
        isError: !!error,
        error
    };
}

