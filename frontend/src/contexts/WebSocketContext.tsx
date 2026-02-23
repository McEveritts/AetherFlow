'use client';

import React, { createContext, useContext, useEffect, useState, useRef } from 'react';
import { SystemMetrics } from '@/types/dashboard';

interface WebSocketData {
    system: SystemMetrics | null;
    services: Record<string, unknown> | null;
}

interface WebSocketContextType {
    data: WebSocketData;
    isConnected: boolean;
    error: Error | null;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

export function WebSocketProvider({ children }: { children: React.ReactNode }) {
    const [data, setData] = useState<WebSocketData>({ system: null, services: null });
    const [isConnected, setIsConnected] = useState(false);
    const [error, setError] = useState<Error | null>(null);
    const wsRef = useRef<WebSocket | null>(null);
    const reconnectTimeoutRef = useRef<NodeJS.Timeout | undefined>(undefined);

    const connect = () => {
        if (wsRef.current?.readyState === WebSocket.OPEN) return;

        const wsUrl = process.env.NEXT_PUBLIC_API_URL
            ? process.env.NEXT_PUBLIC_API_URL.replace('http', 'ws') + '/api/ws'
            : 'ws://localhost:8080/api/ws';

        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            setIsConnected(true);
            setError(null);
            console.log("WebSocket connected to AetherFlow backend");
        };

        ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                if (message.type === 'METRICS_UPDATE') {
                    setData({
                        system: message.data.system,
                        services: message.data.services
                    });
                }
            } catch (err) {
                console.error("Failed to parse websocket message", err);
            }
        };

        ws.onclose = () => {
            setIsConnected(false);
            // Attempt to reconnect after 3 seconds
            reconnectTimeoutRef.current = setTimeout(connect, 3000);
        };

        ws.onerror = (e) => {
            console.error("WebSocket encountered an error", e);
            setError(new Error("WebSocket connection failed"));
            ws.close();
        };

        wsRef.current = ws;
    };

    useEffect(() => {
        connect();
        return () => {
            if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
            if (wsRef.current) wsRef.current.close();
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return (
        <WebSocketContext.Provider value={{ data, isConnected, error }}>
            {children}
        </WebSocketContext.Provider>
    );
}

export function useWebSocket() {
    const context = useContext(WebSocketContext);
    if (context === undefined) {
        throw new Error('useWebSocket must be used within a WebSocketProvider');
    }
    return context;
}
