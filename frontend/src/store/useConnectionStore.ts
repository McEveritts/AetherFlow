import { create } from 'zustand';

export type ConnectionState = 'CONNECTING' | 'CONNECTED' | 'RECONNECTING' | 'FALLBACK';

interface ConnectionStoreState {
    connectionState: ConnectionState;
    reconnectAttempt: number;
    lastMessageAt: number | null;

    // Actions
    setConnectionState: (state: ConnectionState) => void;
    setReconnectAttempt: (attempt: number) => void;
    setLastMessageAt: (timestamp: number) => void;
    reset: () => void;
}

export const useConnectionStore = create<ConnectionStoreState>()((set) => ({
    connectionState: 'CONNECTING',
    reconnectAttempt: 0,
    lastMessageAt: null,

    setConnectionState: (connectionState) => set({ connectionState }),
    setReconnectAttempt: (reconnectAttempt) => set({ reconnectAttempt }),
    setLastMessageAt: (lastMessageAt) => set({ lastMessageAt }),
    reset: () => set({ connectionState: 'CONNECTING', reconnectAttempt: 0 }),
}));
