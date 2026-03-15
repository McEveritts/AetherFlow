'use client';

import React, { createContext, useContext, useEffect, useState, useRef, useCallback } from 'react';
import { SystemMetrics } from '@/types/dashboard';
import { useConnectionStore, ConnectionState } from '@/store/useConnectionStore';
import { useToast } from '@/contexts/ToastContext';

// ── Configuration ──────────────────────────────────────────────
const BACKOFF_BASE_MS = 1000;
const BACKOFF_MAX_MS = 30_000;
const HEARTBEAT_INTERVAL_MS = 30_000;
const HEARTBEAT_TIMEOUT_MS = 10_000;
const FALLBACK_POLL_INTERVAL_MS = 5_000;
const MAX_RECONNECT_BEFORE_FALLBACK = 3;

// ── Types ──────────────────────────────────────────────────────
interface WebSocketData {
    system: SystemMetrics | null;
    services: Record<string, unknown> | null;
}

interface WebSocketContextType {
    data: WebSocketData;
    connectionState: ConnectionState;
    reconnectAttempt: number;
    manualReconnect: () => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

// ── Helpers ────────────────────────────────────────────────────
function getBackoffDelay(attempt: number): number {
    const delay = BACKOFF_BASE_MS * Math.pow(2, attempt);
    // Add ±20% jitter to prevent thundering herd
    const jitter = delay * 0.2 * (Math.random() * 2 - 1);
    return Math.min(delay + jitter, BACKOFF_MAX_MS);
}

function buildWsUrl(): string {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return process.env.NEXT_PUBLIC_API_URL
        ? process.env.NEXT_PUBLIC_API_URL.replace('http', 'ws') + '/api/ws'
        : `${protocol}//${window.location.host}/api/ws`;
}

// ── Provider ───────────────────────────────────────────────────
export function WebSocketProvider({ children }: { children: React.ReactNode }) {
    const [data, setData] = useState<WebSocketData>({ system: null, services: null });

    // Zustand connection store — powers header badge + any external consumer
    const {
        connectionState,
        reconnectAttempt,
        setConnectionState,
        setReconnectAttempt,
        setLastMessageAt,
        reset: resetConnection,
    } = useConnectionStore();

    const { addToast } = useToast();

    // Refs survive re-renders
    const wsRef = useRef<WebSocket | null>(null);
    const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
    const heartbeatTimerRef = useRef<ReturnType<typeof setInterval> | undefined>(undefined);
    const heartbeatTimeoutRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
    const pollTimerRef = useRef<ReturnType<typeof setInterval> | undefined>(undefined);
    const attemptRef = useRef(0);                    // mirrors Zustand but non-reactive
    const hasConnectedOnceRef = useRef(false);       // suppress "restored" toast on first connect
    const isMountedRef = useRef(true);
    const isManualCloseRef = useRef(false);          // distinguish user-initiated close from error

    // ── Heartbeat ──────────────────────────────────────────────
    const clearHeartbeat = useCallback(() => {
        if (heartbeatTimerRef.current) clearInterval(heartbeatTimerRef.current);
        if (heartbeatTimeoutRef.current) clearTimeout(heartbeatTimeoutRef.current);
    }, []);

    const resetHeartbeatTimeout = useCallback(() => {
        // Called whenever we receive ANY message from the server
        if (heartbeatTimeoutRef.current) clearTimeout(heartbeatTimeoutRef.current);
        heartbeatTimeoutRef.current = setTimeout(() => {
            // No message received within deadline — connection is zombie
            console.warn('[WS] Heartbeat timeout — closing zombie connection');
            wsRef.current?.close();
        }, HEARTBEAT_TIMEOUT_MS);
    }, []);

    const startHeartbeat = useCallback(() => {
        clearHeartbeat();
        heartbeatTimerRef.current = setInterval(() => {
            if (wsRef.current?.readyState === WebSocket.OPEN) {
                wsRef.current.send(JSON.stringify({ type: 'PING' }));
                resetHeartbeatTimeout();
            }
        }, HEARTBEAT_INTERVAL_MS);
    }, [clearHeartbeat, resetHeartbeatTimeout]);

    // ── Fallback REST Polling ──────────────────────────────────
    const stopPolling = useCallback(() => {
        if (pollTimerRef.current) {
            clearInterval(pollTimerRef.current);
            pollTimerRef.current = undefined;
        }
    }, []);

    const startPolling = useCallback(() => {
        stopPolling();
        setConnectionState('FALLBACK');
        addToast('Live connection unavailable — switched to polling mode', 'info');

        const poll = async () => {
            try {
                const res = await fetch('/api/system/metrics');
                if (!res.ok) return;
                const metrics = await res.json();
                if (isMountedRef.current) {
                    setData({ system: metrics, services: null });
                    setLastMessageAt(Date.now());
                }
            } catch {
                // Silently swallow — poll will retry on next interval
            }
        };

        poll(); // immediate first poll
        pollTimerRef.current = setInterval(poll, FALLBACK_POLL_INTERVAL_MS);
    }, [stopPolling, setConnectionState, setLastMessageAt, addToast]);

    // ── Core Connect Logic ─────────────────────────────────────
    const connect = useCallback(() => {
        // Clean up any existing connection
        if (wsRef.current) {
            isManualCloseRef.current = true;
            wsRef.current.close();
            isManualCloseRef.current = false;
        }

        const stateLabel = attemptRef.current === 0 ? 'CONNECTING' : 'RECONNECTING';
        setConnectionState(stateLabel);

        const ws = new WebSocket(buildWsUrl());

        ws.onopen = () => {
            if (!isMountedRef.current) return;

            // If we were polling, stop
            stopPolling();

            const wasReconnecting = attemptRef.current > 0;
            attemptRef.current = 0;
            setReconnectAttempt(0);
            setConnectionState('CONNECTED');
            setLastMessageAt(Date.now());
            startHeartbeat();

            if (wasReconnecting && hasConnectedOnceRef.current) {
                addToast('Connection restored', 'success');
            }
            hasConnectedOnceRef.current = true;
            console.log('[WS] Connected to AetherFlow backend');
        };

        ws.onmessage = (event) => {
            if (!isMountedRef.current) return;
            setLastMessageAt(Date.now());
            resetHeartbeatTimeout();

            try {
                const message = JSON.parse(event.data);
                if (message.type === 'METRICS_UPDATE') {
                    setData({
                        system: message.data.system,
                        services: message.data.services,
                    });
                }
                // PONG and other message types are silently consumed
            } catch (err) {
                console.error('[WS] Failed to parse message', err);
            }
        };

        ws.onclose = () => {
            if (!isMountedRef.current || isManualCloseRef.current) return;

            clearHeartbeat();
            attemptRef.current += 1;
            setReconnectAttempt(attemptRef.current);

            if (attemptRef.current === 1 && hasConnectedOnceRef.current) {
                addToast('Connection lost — reconnecting...', 'info');
            }

            if (attemptRef.current >= MAX_RECONNECT_BEFORE_FALLBACK) {
                // Switch to REST polling
                startPolling();
                // Still try WS reconnect in background at max backoff interval
                reconnectTimerRef.current = setTimeout(connect, BACKOFF_MAX_MS);
            } else {
                setConnectionState('RECONNECTING');
                const delay = getBackoffDelay(attemptRef.current - 1);
                console.log(`[WS] Reconnecting in ${Math.round(delay)}ms (attempt ${attemptRef.current})`);
                reconnectTimerRef.current = setTimeout(connect, delay);
            }
        };

        ws.onerror = (e) => {
            console.error('[WS] Error', e);
            ws.close(); // triggers onclose → reconnect logic
        };

        wsRef.current = ws;
    }, [
        setConnectionState, setReconnectAttempt, setLastMessageAt,
        startHeartbeat, clearHeartbeat, resetHeartbeatTimeout,
        startPolling, stopPolling, addToast,
    ]);

    // ── Manual Reconnect (exposed to consumers) ────────────────
    const manualReconnect = useCallback(() => {
        if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
        stopPolling();
        attemptRef.current = 0;
        setReconnectAttempt(0);
        resetConnection();
        connect();
    }, [connect, stopPolling, setReconnectAttempt, resetConnection]);

    // ── Lifecycle ──────────────────────────────────────────────
    useEffect(() => {
        isMountedRef.current = true;
        connect();

        return () => {
            isMountedRef.current = false;
            isManualCloseRef.current = true;
            if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
            clearHeartbeat();
            stopPolling();
            wsRef.current?.close();
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return (
        <WebSocketContext.Provider value={{ data, connectionState, reconnectAttempt, manualReconnect }}>
            {children}
        </WebSocketContext.Provider>
    );
}

// ── Hook ───────────────────────────────────────────────────────
export function useWebSocket() {
    const context = useContext(WebSocketContext);
    if (context === undefined) {
        throw new Error('useWebSocket must be used within a WebSocketProvider');
    }
    return context;
}
