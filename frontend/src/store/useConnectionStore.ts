import { create } from 'zustand';

export type ConnectionMode = 'websocket' | 'poll';
export type ConnectionState = 'CONNECTING' | 'CONNECTED' | 'RECONNECTING' | 'FALLBACK' | 'DEGRADED' | 'DISCONNECTED';

interface ConnectionStoreState {
    connectionState: ConnectionState;
    reconnectAttempt: number;
    lastMessageAt: number | null;
    lastTransportSwitchReason: string | null;
    
    // Polling preferences
    preferredMode: ConnectionMode;
    pollInterval: number; // in milliseconds
    dashboardDensity: 'compact' | 'immersive';
    showGpuWidget: boolean;
    showDataUsageWidget: boolean;

    // Actions
    setConnectionState: (state: ConnectionState) => void;
    setReconnectAttempt: (attempt: number) => void;
    setLastMessageAt: (timestamp: number) => void;
    setLastTransportSwitchReason: (reason: string | null) => void;
    setPreferredMode: (mode: ConnectionMode) => void;
    setPollInterval: (interval: number) => void;
    setDashboardDensity: (density: 'compact' | 'immersive') => void;
    setShowGpuWidget: (show: boolean) => void;
    setShowDataUsageWidget: (show: boolean) => void;
    reset: () => void;
}

export const useConnectionStore = create<ConnectionStoreState>()((set) => ({
    connectionState: 'CONNECTING',
    reconnectAttempt: 0,
    lastMessageAt: null,
    lastTransportSwitchReason: null,
    preferredMode: 'websocket',
    pollInterval: 5000,
    dashboardDensity: 'compact',
    showGpuWidget: true,
    showDataUsageWidget: true,

    setConnectionState: (connectionState) => set({ connectionState }),
    setReconnectAttempt: (reconnectAttempt) => set({ reconnectAttempt }),
    setLastMessageAt: (lastMessageAt) => set({ lastMessageAt }),
    setLastTransportSwitchReason: (lastTransportSwitchReason) => set({ lastTransportSwitchReason }),
    setPreferredMode: (preferredMode) => set({ preferredMode }),
    setPollInterval: (pollInterval) => set({ pollInterval }),
    setDashboardDensity: (dashboardDensity) => set({ dashboardDensity }),
    setShowGpuWidget: (showGpuWidget) => set({ showGpuWidget }),
    setShowDataUsageWidget: (showDataUsageWidget) => set({ showDataUsageWidget }),
    reset: () => set({ 
        connectionState: 'DISCONNECTED', 
        reconnectAttempt: 0, 
        lastMessageAt: null,
        lastTransportSwitchReason: null,
        preferredMode: 'websocket',
        pollInterval: 5000,
        dashboardDensity: 'compact',
        showGpuWidget: true,
        showDataUsageWidget: true
    }),
}));
