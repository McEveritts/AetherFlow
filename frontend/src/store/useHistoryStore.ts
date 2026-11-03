import { create } from 'zustand';
import { mutate as globalMutate } from 'swr';
import { SystemMetrics, MetricsHistory } from '@/types/dashboard';

export type TimeWindow = '1m' | '5m' | '1h';

const MAX_HISTORY_SIZE = 1800;
const WINDOW_SIZES: Record<TimeWindow, number> = {
    '1m': 30,
    '5m': 150,
    '1h': 1800,
};

export function roundTwo(value: number): number {
    if (!Number.isFinite(value)) return 0;
    return Number(value.toFixed(2));
}

export function parseSpeed(speed: string): number {
    if (!speed) return 0;
    const match = speed.match(/([\d.]+)\s*([KMGTPE]?)B\/s/i);
    if (!match) return 0;
    const parsedValue = parseFloat(match[1]);
    const unit = match[2].toUpperCase();
    const multipliers: Record<string, number> = { '': 1, 'K': 1024, 'M': 1048576, 'G': 1073741824 };
    return roundTwo(parsedValue * (multipliers[unit] || 1));
}

export function sliceHistory(history: MetricsHistory, timeWindow: TimeWindow): MetricsHistory {
    const limit = WINDOW_SIZES[timeWindow];
    return {
        cpu: history.cpu.slice(-limit),
        memory: history.memory.slice(-limit),
        netDown: history.netDown.slice(-limit),
        netUp: history.netUp.slice(-limit),
        diskRead: history.diskRead.slice(-limit),
        diskWrite: history.diskWrite.slice(-limit),
        timestamps: history.timestamps.slice(-limit),
    };
}

export function buildFallbackHistory(metrics: SystemMetrics): MetricsHistory {
    const memoryPercent = metrics.memory && metrics.memory.total > 0
        ? roundTwo((metrics.memory.used / metrics.memory.total) * 100)
        : 0;
    const netDownSpeed = parseSpeed(metrics.network?.down as string);
    const netUpSpeed = parseSpeed(metrics.network?.up as string);
    const diskReadSpeed = roundTwo(metrics.disk_io?.read_bytes_sec || 0);
    const diskWriteSpeed = roundTwo(metrics.disk_io?.write_bytes_sec || 0);
    const cpuPercent = roundTwo(metrics.cpu_usage);
    return {
        cpu: [cpuPercent, cpuPercent],
        memory: [memoryPercent, memoryPercent],
        netDown: [netDownSpeed, netDownSpeed],
        netUp: [netUpSpeed, netUpSpeed],
        diskRead: [diskReadSpeed, diskReadSpeed],
        diskWrite: [diskWriteSpeed, diskWriteSpeed],
        timestamps: [0, 1],
    };
}

export const emptyHistory: MetricsHistory = {
    cpu: [],
    memory: [],
    netDown: [],
    netUp: [],
    diskRead: [],
    diskWrite: [],
    timestamps: [],
};

function appendSample(items: number[], value: number): number[] {
    if (items.length === 0) return [value, value];
    const nextItems = [...items, value];
    if (nextItems.length > MAX_HISTORY_SIZE) nextItems.shift();
    return nextItems;
}

let lastPushedMetrics: SystemMetrics | null = null;
let lastSyncedServices: Record<string, unknown> | null = null;

export interface HistoryStoreState {
    timeWindow: TimeWindow;
    setTimeWindow: (timeWindow: TimeWindow) => void;
    history: MetricsHistory;
    visibleHistory: MetricsHistory;
    lastPushAt: number;
    pushMetrics: (metrics: SystemMetrics) => void;
    syncServices: (services: Record<string, unknown> | null | undefined) => void;
    resetHistory: () => void;
}

export const useHistoryStore = create<HistoryStoreState>((set, get) => ({
    timeWindow: '5m',
    setTimeWindow: (timeWindow: TimeWindow) => set((state) => ({
        timeWindow,
        visibleHistory: sliceHistory(state.history, timeWindow),
    })),
    history: emptyHistory,
    visibleHistory: emptyHistory,
    lastPushAt: 0,
    pushMetrics: (metrics: SystemMetrics) => {
        if (!metrics) return;
        const currentState = get();
        if (lastPushedMetrics === metrics && currentState.history.timestamps.length > 0) return;
        const now = Date.now();
        if (currentState.lastPushAt > 0 && now - currentState.lastPushAt < 100) {
            lastPushedMetrics = metrics;
            return;
        }
        lastPushedMetrics = metrics;

        set((state) => {
            const memoryPercent = metrics.memory && metrics.memory.total > 0
                ? roundTwo((metrics.memory.used / metrics.memory.total) * 100)
                : 0;
            const nextHistory: MetricsHistory = {
                cpu: appendSample(state.history.cpu, roundTwo(metrics.cpu_usage)),
                memory: appendSample(state.history.memory, memoryPercent),
                netDown: appendSample(state.history.netDown, parseSpeed(metrics.network?.down as string)),
                netUp: appendSample(state.history.netUp, parseSpeed(metrics.network?.up as string)),
                diskRead: appendSample(state.history.diskRead, roundTwo(metrics.disk_io?.read_bytes_sec || 0)),
                diskWrite: appendSample(state.history.diskWrite, roundTwo(metrics.disk_io?.write_bytes_sec || 0)),
                timestamps: appendSample(state.history.timestamps, now),
            };
            return {
                lastPushAt: now,
                history: nextHistory,
                visibleHistory: sliceHistory(nextHistory, state.timeWindow),
            };
        });
    },
    syncServices: (services: Record<string, unknown> | null | undefined) => {
        if (!services || lastSyncedServices === services) return;
        lastSyncedServices = services;
        globalMutate('/api/v1/auth/services', services, false);
    },
    resetHistory: () => {
        lastPushedMetrics = null;
        lastSyncedServices = null;
        set({
            timeWindow: '5m',
            history: emptyHistory,
            visibleHistory: emptyHistory,
            lastPushAt: 0,
        });
    },
}));
