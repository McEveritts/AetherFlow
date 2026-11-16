import React from 'react';
import { act, render } from '@testing-library/react';
import { WebSocketProvider } from './WebSocketContext';
import { useConnectionStore } from '@/store/useConnectionStore';

const mockMutate = jest.fn();
const mockAddToast = jest.fn();
const mockApiFetch = jest.fn();
let mockAuthenticated = true;

jest.mock('next/navigation', () => ({ usePathname: () => '/' }));
jest.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ isAuthenticated: mockAuthenticated }) }));
jest.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ addToast: mockAddToast }) }));
jest.mock('@/lib/fetcher', () => ({ apiFetch: (...args: unknown[]) => mockApiFetch(...args) }));
jest.mock('swr', () => ({ mutate: (...args: unknown[]) => mockMutate(...args) }));

class MockWebSocket {
    static OPEN = 1;
    static instances: MockWebSocket[] = [];
    readyState = MockWebSocket.OPEN;
    onmessage: ((event: { data: string }) => void) | null = null;
    onopen: (() => void) | null = null;
    onclose: (() => void) | null = null;
    onerror: (() => void) | null = null;
    close = jest.fn();
    send = jest.fn();
    constructor() { MockWebSocket.instances.push(this); }
    progress(status = 'updating') {
        this.onmessage?.({ data: JSON.stringify({ type: 'package:progress', package_id: 'sonarr', status }) });
    }
}

const originalWebSocket = global.WebSocket;

beforeEach(() => {
    jest.useFakeTimers();
    mockAuthenticated = true;
    mockMutate.mockReset();
    mockAddToast.mockReset();
    mockApiFetch.mockResolvedValue({ ok: true, json: async () => ({ ticket: 'fixture' }) });
    MockWebSocket.instances = [];
    global.WebSocket = MockWebSocket as unknown as typeof WebSocket;
});

afterEach(() => {
    jest.clearAllTimers();
    jest.useRealTimers();
    global.WebSocket = originalWebSocket;
});

async function mountProvider() {
    const view = render(<WebSocketProvider><div /></WebSocketProvider>);
    await act(async () => {});
    const socket = MockWebSocket.instances.at(-1);
    if (!socket) throw new Error('WebSocket was not created');
    return { view, socket };
}

it('coalesces noisy progress while keeping terminal refresh immediate', async () => {
    const { view, socket } = await mountProvider();
    act(() => { for (let index = 0; index < 20; index++) socket.progress(); });
    expect(mockMutate).not.toHaveBeenCalled();
    act(() => { jest.advanceTimersByTime(1000); });
    expect(mockMutate.mock.calls).toEqual([
        ['/api/v1/public/marketplace'], ['/api/v1/auth/services'],
    ]);
    mockMutate.mockClear();
    act(() => { for (let index = 0; index < 20; index++) socket.progress(); });
    act(() => { socket.progress('failed'); });
    expect(mockMutate).toHaveBeenCalledTimes(2);
    act(() => { jest.advanceTimersByTime(1000); });
    expect(mockMutate).toHaveBeenCalledTimes(2);
    view.unmount();
});

it('cancels delayed refreshes after logout and unmount', async () => {
    const { view, socket } = await mountProvider();
    act(() => { socket.progress(); });
    mockAuthenticated = false;
    view.rerender(<WebSocketProvider><div /></WebSocketProvider>);
    act(() => { jest.advanceTimersByTime(1000); });
    expect(mockMutate).not.toHaveBeenCalled();
    view.unmount();

    mockAuthenticated = true;
    const next = await mountProvider();
    act(() => { next.socket.progress(); });
    next.view.unmount();
    act(() => { jest.advanceTimersByTime(1000); });
    expect(mockMutate).not.toHaveBeenCalled();
});

it('switches to FALLBACK REST polling after 3 consecutive failed reconnect attempts and recovers on WS open', async () => {
    useConnectionStore.getState().reset();
    mockApiFetch.mockImplementation(async (url: unknown) => {
        if (url === '/api/v1/auth/ws/ticket') {
            return { ok: false, status: 503 };
        }
        if (url === '/api/v1/auth/system/metrics') {
            return { ok: true, text: async () => JSON.stringify({ cpu_usage: 12.5 }) };
        }
        return { ok: true, json: async () => ({}) };
    });

    const view = render(<WebSocketProvider><div /></WebSocketProvider>);
    await act(async () => {});
    // Attempt 1 failed -> RECONNECTING
    expect(useConnectionStore.getState().connectionState).toBe('RECONNECTING');

    // Advance past backoff for attempt 2
    await act(async () => { jest.advanceTimersByTime(2500); });
    expect(useConnectionStore.getState().connectionState).toBe('RECONNECTING');

    // Advance past backoff for attempt 3 -> reaches MAX_RECONNECT_BEFORE_FALLBACK (3) -> FALLBACK
    await act(async () => { jest.advanceTimersByTime(5000); });
    expect(useConnectionStore.getState().connectionState).toBe('FALLBACK');
    expect(mockApiFetch).toHaveBeenCalledWith('/api/v1/auth/system/metrics');

    // Now allow ticket fetch to succeed on the next background WS recovery probe
    mockApiFetch.mockImplementation(async (url: unknown) => {
        if (url === '/api/v1/auth/ws/ticket') {
            return { ok: true, json: async () => ({ ticket: 'recovered-ticket' }) };
        }
        if (url === '/api/v1/auth/system/metrics') {
            return { ok: true, text: async () => JSON.stringify({ cpu_usage: 10.0 }) };
        }
        return { ok: true, json: async () => ({}) };
    });

    await act(async () => { jest.advanceTimersByTime(10000); });
    const recoveredSocket = MockWebSocket.instances.at(-1);
    expect(recoveredSocket).toBeDefined();
    act(() => { recoveredSocket?.onopen?.(); });
    expect(useConnectionStore.getState().connectionState).toBe('CONNECTED');

    view.unmount();
});
