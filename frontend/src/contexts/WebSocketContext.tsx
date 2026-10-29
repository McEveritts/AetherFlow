'use client';

import React, { createContext, useContext, useEffect, useState, useRef, useCallback } from 'react';
import { usePathname } from 'next/navigation';
import { SystemMetrics } from '@/types/dashboard';
import { useConnectionStore, ConnectionState } from '@/store/useConnectionStore';
import { useToast } from '@/contexts/ToastContext';
import { useAuth } from '@/contexts/AuthContext';
import { mutate as globalMutate } from 'swr';
import { apiFetch } from '@/lib/fetcher';
import { webSocketMessageSchema, metricsUpdateDataSchema } from '@/lib/schemas';

declare global {
    interface Window {
        __AF_DISABLE_WS__?: boolean;
        __AF_EXTENDED_TIMEOUT__?: boolean;
    }
}

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

function buildWsUrl(ticket: string): string {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const base = process.env.NEXT_PUBLIC_API_URL
        ? process.env.NEXT_PUBLIC_API_URL.replace('http', 'ws') + '/api/v1/auth/ws'
        : `${protocol}//${window.location.host}/api/v1/auth/ws`;
    return `${base}?ticket=${encodeURIComponent(ticket)}`;
}

function isWebSocketDisabled(): boolean {
    return typeof window !== 'undefined' && window.__AF_DISABLE_WS__ === true;
}

// ── Provider ───────────────────────────────────────────────────
export function WebSocketProvider({ children }: { children: React.ReactNode }) {
    const [data, setData] = useState<WebSocketData>({ system: null, services: null });
    const { isAuthenticated } = useAuth();
    const pathname = usePathname();

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
    const pollInFlightRef = useRef(false);
    const transportGenRef = useRef(0);
    const attemptRef = useRef(0);                    // mirrors Zustand but non-reactive
    const hasConnectedOnceRef = useRef(false);       // suppress "restored" toast on first connect
    const isMountedRef = useRef(true);
    const isManualCloseRef = useRef(false);          // distinguish user-initiated close from error
    const lastWsPushRef = useRef<number>(0);
    
    const transportOwnerRef = useRef<'websocket' | 'poll'>('websocket');
    // FALLBACK: Use MAX aggregation semantics for dropped frames until policy is ratified
    const suppressedMetricsBufferRef = useRef<SystemMetrics | null>(null);
    // FALLBACK: Treat control-plane events as standard throttled metrics until unconditional bypass is ratified.
    const suppressedControlEventsRef = useRef<{type: string, data: unknown}[]>([]);

    // ── Heartbeat ──────────────────────────────────────────────
    const clearHeartbeat = useCallback(() => {
        if (heartbeatTimerRef.current) clearInterval(heartbeatTimerRef.current);
        if (heartbeatTimeoutRef.current) clearTimeout(heartbeatTimeoutRef.current);
    }, []);

    const resetHeartbeatTimeout = useCallback(() => {
        // Called whenever we receive ANY message from the server
        if (heartbeatTimeoutRef.current) clearTimeout(heartbeatTimeoutRef.current);
        
        // FALLBACK: Implement feature-flagged 60s timeout until liveness guarantee is confirmed
        const timeoutMs = (typeof window !== 'undefined' && window.__AF_EXTENDED_TIMEOUT__) ? 60_000 : HEARTBEAT_TIMEOUT_MS;
        
        heartbeatTimeoutRef.current = setTimeout(() => {
            // No message received within deadline — connection is zombie
            console.warn('[WS] Heartbeat timeout — closing zombie connection');
            wsRef.current?.close();
        }, timeoutMs);
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
        pollInFlightRef.current = false;
    }, []);

    const startPolling = useCallback((silent = false) => {
        // Only block fallback polling if an active WebSocket is currently OPEN
        if (
            wsRef.current?.readyState === WebSocket.OPEN &&
            transportOwnerRef.current === 'websocket' &&
            !isWebSocketDisabled()
        ) {
            return;
        }

        stopPolling();
        transportOwnerRef.current = 'poll';
        setConnectionState('FALLBACK');
        
        if (!silent) {
            addToast('Live connection unavailable — switched to fallback mode', 'info');
        }

        let pollTick = 0;
        const poll = async () => {
            if (!isMountedRef.current || transportOwnerRef.current !== 'poll') return;
            if (pollInFlightRef.current) return;
            pollInFlightRef.current = true;
            const currentTick = pollTick++;
            try {
                const shouldFetchServices = currentTick % 5 === 0;
                const [metricsRes, servicesRes] = await Promise.all([
                    apiFetch('/api/v1/auth/system/metrics'),
                    shouldFetchServices ? apiFetch('/api/v1/auth/services').catch(() => null) : Promise.resolve(null),
                ]);
                if (!metricsRes.ok || !isMountedRef.current || transportOwnerRef.current !== 'poll') return;
                const text = await metricsRes.text();
                if (!text || text.trim() === '') return;
                
                let metrics: SystemMetrics;
                try {
                    metrics = JSON.parse(text);
                } catch {
                    return;
                }

                let polledServices: Record<string, unknown> | null = null;
                if (servicesRes && servicesRes.ok) {
                    try {
                        polledServices = await servicesRes.json();
                    } catch {
                        polledServices = null;
                    }
                }
                
                if (isMountedRef.current && metrics && transportOwnerRef.current === 'poll') {
                    setData((prev) => {
                        const nextServices = polledServices ?? prev.services;
                        const mergedSystem: SystemMetrics = nextServices
                            ? { ...metrics, services: nextServices as SystemMetrics['services'] }
                            : metrics;
                        return {
                            system: mergedSystem,
                            services: nextServices,
                        };
                    });
                    setLastMessageAt(Date.now());
                }
            } catch {
                // Silently swallow transient poll errors
            } finally {
                pollInFlightRef.current = false;
            }
        };

        poll(); // immediate first poll
        pollTimerRef.current = setInterval(poll, FALLBACK_POLL_INTERVAL_MS);
    }, [stopPolling, setConnectionState, setLastMessageAt, addToast]);

    // ── Core Connect Logic ─────────────────────────────────────
    const connect = useCallback(async () => {
        if (!isMountedRef.current || isWebSocketDisabled()) {
            return;
        }

        const connectGen = ++transportGenRef.current;

        // Clean up any existing connection
        if (wsRef.current) {
            const prevWs = wsRef.current;
            wsRef.current = null;
            prevWs.close();
        }
        isManualCloseRef.current = false;

        const stateLabel = attemptRef.current === 0 ? 'CONNECTING' : 'RECONNECTING';
        setConnectionState(stateLabel);

        let wsUrl: string;
        try {
            const res = await apiFetch('/api/v1/auth/ws/ticket');
            if (!res.ok) throw new Error('Failed to fetch ticket');
            const ticketData = await res.json();
            wsUrl = buildWsUrl(ticketData.ticket);
        } catch (err) {
            if (!isMountedRef.current || connectGen !== transportGenRef.current) {
                return;
            }
            console.error('[WS] Failed to obtain connection ticket', err);
            attemptRef.current += 1;
            setReconnectAttempt(attemptRef.current);
            setConnectionState('RECONNECTING');
            const delay = getBackoffDelay(attemptRef.current - 1);
            reconnectTimerRef.current = setTimeout(connect, delay);
            return;
        }

        // Abort if transport was torn down while awaiting the WS ticket
        if (!isMountedRef.current || connectGen !== transportGenRef.current || isWebSocketDisabled()) {
            return;
        }

        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            if (!isMountedRef.current || connectGen !== transportGenRef.current) {
                ws.close();
                return;
            }

            // New connection is live — clear the manual-close flag and claim transport ownership
            isManualCloseRef.current = false;
            transportOwnerRef.current = 'websocket';

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
            if (!isMountedRef.current || connectGen !== transportGenRef.current) return;
            const now = Date.now();
            setLastMessageAt(now);
            resetHeartbeatTimeout();

            try {
                const rawMessage = JSON.parse(event.data);
                const message = webSocketMessageSchema.parse(rawMessage);
                
                lastWsPushRef.current = now;

                if (message.type === 'METRICS_UPDATE') {
                    const parsedData = metricsUpdateDataSchema.safeParse(message.data);
                    if (parsedData.success) {
                        const sysData = parsedData.data.system as unknown as SystemMetrics;
                        const incomingServices = (parsedData.data.services as Record<string, unknown> | null) ?? null;

                        setData((prev) => {
                            const nextServices = incomingServices ?? prev.services;
                            const mergedSystem: SystemMetrics = sysData && nextServices
                                ? { ...sysData, services: nextServices as SystemMetrics['services'] }
                                : sysData;
                            return {
                                system: mergedSystem,
                                services: nextServices,
                            };
                        });
                    } else {
                        console.warn('[WS] Malformed metrics payload dropped', parsedData.error.format());
                    }
                } 
                // Process current message and any queued control messages
                const eventsToProcess = [...suppressedControlEventsRef.current];
                if (['MARKETPLACE_UPDATE', 'SYSTEM_HEAL', 'ACTION_QUEUED'].includes(message.type)) {
                    eventsToProcess.push({ type: message.type, data: message.data });
                }
                suppressedControlEventsRef.current = [];

                eventsToProcess.forEach(ev => {
                    if (ev.type === 'MARKETPLACE_UPDATE') {
                        globalMutate('/api/v1/public/marketplace');
                    } else if (ev.type === 'SYSTEM_HEAL') {
                        const healData = ev.data as { service?: string, reason?: string, action?: string };
                        addToast(`Self-Healing: ${healData.action || 'Restarted'} ${healData.service || 'service'} (${healData.reason || 'unresponsive'})`, 'info');
                    } else if (ev.type === 'ACTION_QUEUED') {
                        const actionData = ev.data as { action_id?: number, classification?: string, source?: string, action?: string };
                        globalMutate('/api/v1/admin/actions/pending?status=pending');
                        addToast(`New action queued: ${actionData.action || 'Unknown'} (#${actionData.action_id || '?'})`, 'info');
                    }
                });

                // PONG and other message types are silently consumed
            } catch (err) {
                console.error('[WS] Failed to parse message', err);
            }
        };

        ws.onclose = () => {
            if (!isMountedRef.current || isManualCloseRef.current || wsRef.current !== ws || connectGen !== transportGenRef.current) return;
            wsRef.current = null;

            clearHeartbeat();
            if (isWebSocketDisabled()) {
                return;
            }

            attemptRef.current += 1;
            setReconnectAttempt(attemptRef.current);

            if (attemptRef.current === 1 && hasConnectedOnceRef.current) {
                addToast('Connection lost — reconnecting...', 'info');
            }

            setConnectionState('RECONNECTING');
            const delay = getBackoffDelay(attemptRef.current - 1);
            console.log(`[WS] Reconnecting in ${Math.round(delay)}ms (attempt ${attemptRef.current})`);
            reconnectTimerRef.current = setTimeout(connect, delay);
        };

        ws.onerror = (e) => {
            console.error('[WS] Error', e);
            ws.close(); // triggers onclose → reconnect logic
        };

        wsRef.current = ws;
    }, [
        setConnectionState, setReconnectAttempt, setLastMessageAt,
        startHeartbeat, clearHeartbeat, resetHeartbeatTimeout,
        stopPolling, addToast,
    ]);

    // ── Manual Reconnect (exposed to consumers) ────────────────
    const manualReconnect = useCallback(() => {
        if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
        stopPolling();
        attemptRef.current = 0;
        setReconnectAttempt(0);
        if (isWebSocketDisabled()) {
            transportOwnerRef.current = 'poll';
            startPolling(true);
        } else {
            transportOwnerRef.current = 'websocket';
            resetConnection();
            connect();
        }
    }, [connect, startPolling, stopPolling, setReconnectAttempt, resetConnection]);

    // ── Mount / Unmount tracking ───────────────────────────────
    useEffect(() => {
        isMountedRef.current = true;
        return () => {
            isMountedRef.current = false;
        };
    }, []);

    // ── Primary Transport Lifecycle ────────────────────────────
    useEffect(() => {
        if (!isAuthenticated || pathname === '/login') {
            transportGenRef.current += 1;
            if (reconnectTimerRef.current) {
                clearTimeout(reconnectTimerRef.current);
                reconnectTimerRef.current = undefined;
            }
            clearHeartbeat();
            stopPolling();
            if (wsRef.current) {
                isManualCloseRef.current = true;
                wsRef.current.close();
                wsRef.current = null;
            }
            return;
        }

        if (isWebSocketDisabled()) {
            transportGenRef.current += 1;
            transportOwnerRef.current = 'poll';
            useConnectionStore.getState().setLastTransportSwitchReason('WS_DISABLED');
            if (wsRef.current) {
                isManualCloseRef.current = true;
                wsRef.current.close();
                wsRef.current = null;
            }
            if (reconnectTimerRef.current) {
                clearTimeout(reconnectTimerRef.current);
                reconnectTimerRef.current = undefined;
            }
            clearHeartbeat();
            attemptRef.current = 0;
            setReconnectAttempt(0);
            startPolling(true);
            return () => {
                clearHeartbeat();
                stopPolling();
            };
        }

        transportOwnerRef.current = 'websocket';
        stopPolling();
        connect();

        return () => {
            transportGenRef.current += 1;
            isManualCloseRef.current = true;
            if (reconnectTimerRef.current) {
                clearTimeout(reconnectTimerRef.current);
                reconnectTimerRef.current = undefined;
            }
            clearHeartbeat();
            stopPolling();
            if (wsRef.current) {
                wsRef.current.close();
                wsRef.current = null;
            }
        };
    }, [isAuthenticated, pathname, connect, startPolling, stopPolling, clearHeartbeat, setReconnectAttempt]);

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
