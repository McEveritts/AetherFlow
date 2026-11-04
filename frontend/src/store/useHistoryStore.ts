import { create } from 'zustand';
import { mutate as globalMutate } from 'swr';
import { SystemMetrics, MetricsHistory } from '@/types/dashboard';
import { apiFetch } from '@/lib/fetcher';

export type TimeWindow = '1m' | '5m' | '15m' | '1h' | '6h' | '24h';

export const MAX_HISTORY_SIZE = 2400;
export const GAP_THRESHOLD_MS = 120_000;
const MAX_COUNTER_DELTA_GAP_MS = 300_000;
const DEDUP_WINDOW_MS = 250;
const MIN_EPOCH_TIMESTAMP_MS = 60_000;

export const WINDOW_DURATION_MS: Record<TimeWindow, number> = {
    '1m': 60_000,
    '5m': 5 * 60_000,
    '15m': 15 * 60_000,
    '1h': 60 * 60_000,
    '6h': 6 * 60 * 60_000,
    '24h': 24 * 60 * 60_000,
};

export const WINDOW_SIZES: Record<TimeWindow, number> = {
    '1m': 30,
    '5m': 150,
    '15m': 450,
    '1h': 1800,
    '6h': 2000,
    '24h': 2400,
};

export const TIME_WINDOW_OPTIONS: ReadonlyArray<{ id: TimeWindow; label: string }> = [
    { id: '1m', label: '1m' },
    { id: '5m', label: '5m' },
    { id: '15m', label: '15m' },
    { id: '1h', label: '1h' },
    { id: '6h', label: '6h' },
    { id: '24h', label: '24h' },
];

export interface PersistedMetricsSnapshot {
    id?: number;
    timestamp?: string | number;
    recorded_at?: string | number;
    cpu_avg?: number;
    cpu_usage?: number;
    mem_used_gb?: number;
    mem_total_gb?: number;
    memory_pct?: number;
    disk_read_bps?: number;
    disk_write_bps?: number;
    net_rx_bytes?: number;
    net_tx_bytes?: number;
    net_rx_mb?: number;
    net_tx_mb?: number;
    net_down_bps?: number;
    net_up_bps?: number;
    load_avg_1?: number;
    load_1m?: number;
    active_conns?: number;
}

interface InternalMetricPoint {
    timestamp: number;
    cpu: number;
    memory: number;
    netDown: number;
    netUp: number;
    diskRead: number;
    diskWrite: number;
}

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

export function parseSnapshotTimestampMs(raw: string | number | undefined): number {
    if (typeof raw === 'number') {
        if (!Number.isFinite(raw) || raw <= 0) return 0;
        return raw < 1e11 ? Math.round(raw * 1000) : Math.round(raw);
    }
    if (typeof raw === 'string') {
        const trimmed = raw.trim();
        if (!trimmed) return 0;
        const numeric = Number(trimmed);
        if (Number.isFinite(numeric) && numeric > 0) {
            return numeric < 1e11 ? Math.round(numeric * 1000) : Math.round(numeric);
        }
        const normalized = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(trimmed)
            ? `${trimmed.replace(' ', 'T')}Z`
            : trimmed;
        const parsed = Date.parse(normalized);
        return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
    }
    return 0;
}

function ensureMinimumSparklinePoints(history: MetricsHistory): MetricsHistory {
    if (history.timestamps.length !== 1) return history;
    return {
        cpu: [history.cpu[0], history.cpu[0]],
        memory: [history.memory[0], history.memory[0]],
        netDown: [history.netDown[0], history.netDown[0]],
        netUp: [history.netUp[0], history.netUp[0]],
        diskRead: [history.diskRead[0], history.diskRead[0]],
        diskWrite: [history.diskWrite[0], history.diskWrite[0]],
        timestamps: [history.timestamps[0], history.timestamps[0]],
    };
}

export function sliceHistory(history: MetricsHistory, timeWindow: TimeWindow): MetricsHistory {
    const total = history.timestamps.length;
    if (total === 0) return emptyHistory;

    const limit = WINDOW_SIZES[timeWindow] ?? WINDOW_SIZES['5m'];
    const durationMs = WINDOW_DURATION_MS[timeWindow] ?? WINDOW_DURATION_MS['5m'];
    const latestTs = history.timestamps[total - 1] ?? 0;

    let startIndex = Math.max(0, total - limit);
    if (latestTs >= MIN_EPOCH_TIMESTAMP_MS) {
        const cutoff = latestTs - durationMs;
        let tsStartIndex = total - 1;
        for (let i = 0; i < total; i++) {
            if (history.timestamps[i] >= cutoff) {
                tsStartIndex = i;
                break;
            }
        }
        startIndex = Math.max(tsStartIndex, total - limit);
    }

    const sliced: MetricsHistory = {
        cpu: history.cpu.slice(startIndex),
        memory: history.memory.slice(startIndex),
        netDown: history.netDown.slice(startIndex),
        netUp: history.netUp.slice(startIndex),
        diskRead: history.diskRead.slice(startIndex),
        diskWrite: history.diskWrite.slice(startIndex),
        timestamps: history.timestamps.slice(startIndex),
    };

    return ensureMinimumSparklinePoints(sliced);
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

function extractCanonicalPoints(history: MetricsHistory): InternalMetricPoint[] {
    const len = history.timestamps.length;
    if (len === 0) return [];
    if (
        len === 2 &&
        history.timestamps[0] === history.timestamps[1] &&
        history.cpu[0] === history.cpu[1] &&
        history.memory[0] === history.memory[1]
    ) {
        return [{
            timestamp: history.timestamps[0],
            cpu: history.cpu[0],
            memory: history.memory[0],
            netDown: history.netDown[0],
            netUp: history.netUp[0],
            diskRead: history.diskRead[0],
            diskWrite: history.diskWrite[0],
        }];
    }
    const points: InternalMetricPoint[] = [];
    for (let i = 0; i < len; i++) {
        points.push({
            timestamp: history.timestamps[i],
            cpu: history.cpu[i] ?? 0,
            memory: history.memory[i] ?? 0,
            netDown: history.netDown[i] ?? 0,
            netUp: history.netUp[i] ?? 0,
            diskRead: history.diskRead[i] ?? 0,
            diskWrite: history.diskWrite[i] ?? 0,
        });
    }
    return points;
}

function pointsToHistory(points: InternalMetricPoint[]): MetricsHistory {
    if (points.length === 0) return emptyHistory;
    const bounded = points.length > MAX_HISTORY_SIZE
        ? points.slice(-MAX_HISTORY_SIZE)
        : points;
    const raw: MetricsHistory = {
        cpu: bounded.map((p) => p.cpu),
        memory: bounded.map((p) => p.memory),
        netDown: bounded.map((p) => p.netDown),
        netUp: bounded.map((p) => p.netUp),
        diskRead: bounded.map((p) => p.diskRead),
        diskWrite: bounded.map((p) => p.diskWrite),
        timestamps: bounded.map((p) => p.timestamp),
    };
    return ensureMinimumSparklinePoints(raw);
}

function mergeAndDeduplicatePoints(
    persistedPoints: InternalMetricPoint[],
    livePoints: InternalMetricPoint[]
): { points: InternalMetricPoint[]; gapCount: number } {
    const combined = [...persistedPoints, ...livePoints].filter(
        (p) => Number.isFinite(p.timestamp) && p.timestamp > 0
    );
    if (combined.length === 0) return { points: [], gapCount: 0 };

    combined.sort((a, b) => a.timestamp - b.timestamp);

    const deduped: InternalMetricPoint[] = [];
    for (const candidate of combined) {
        if (deduped.length === 0) {
            deduped.push(candidate);
            continue;
        }
        const prev = deduped[deduped.length - 1];
        if (Math.abs(candidate.timestamp - prev.timestamp) <= DEDUP_WINDOW_MS) {
            deduped[deduped.length - 1] = candidate;
        } else {
            deduped.push(candidate);
        }
    }

    let gapCount = 0;
    for (let i = 1; i < deduped.length; i++) {
        if (deduped[i].timestamp - deduped[i - 1].timestamp > GAP_THRESHOLD_MS) {
            gapCount += 1;
        }
    }

    const bounded = deduped.length > MAX_HISTORY_SIZE
        ? deduped.slice(-MAX_HISTORY_SIZE)
        : deduped;

    return { points: bounded, gapCount };
}

export function normalizePersistedSnapshots(snapshots: PersistedMetricsSnapshot[]): InternalMetricPoint[] {
    if (!Array.isArray(snapshots) || snapshots.length === 0) return [];

    const withTs = snapshots
        .map((snap) => ({
            snap,
            timestamp: parseSnapshotTimestampMs(snap.timestamp ?? snap.recorded_at),
        }))
        .filter((item) => item.timestamp > 0)
        .sort((a, b) => a.timestamp - b.timestamp);

    const points: InternalMetricPoint[] = [];
    let prevSnap: PersistedMetricsSnapshot | null = null;
    let prevTs = 0;

    for (const { snap, timestamp } of withTs) {
        if (points.length > 0 && Math.abs(timestamp - prevTs) <= DEDUP_WINDOW_MS) {
            points.pop();
        }

        const cpu = roundTwo(snap.cpu_avg ?? snap.cpu_usage ?? 0);
        const memory = typeof snap.memory_pct === 'number'
            ? roundTwo(snap.memory_pct)
            : (snap.mem_total_gb && snap.mem_total_gb > 0)
                ? roundTwo(((snap.mem_used_gb ?? 0) / snap.mem_total_gb) * 100)
                : 0;
        const diskRead = roundTwo(snap.disk_read_bps ?? 0);
        const diskWrite = roundTwo(snap.disk_write_bps ?? 0);

        let netDown = typeof snap.net_down_bps === 'number' ? roundTwo(snap.net_down_bps) : 0;
        let netUp = typeof snap.net_up_bps === 'number' ? roundTwo(snap.net_up_bps) : 0;

        if (typeof snap.net_down_bps !== 'number' && typeof snap.net_up_bps !== 'number' && prevSnap) {
            const dtMs = timestamp - prevTs;
            if (dtMs > 0 && dtMs <= MAX_COUNTER_DELTA_GAP_MS) {
                const dtSec = dtMs / 1000;
                const currRx = typeof snap.net_rx_bytes === 'number'
                    ? snap.net_rx_bytes
                    : typeof snap.net_rx_mb === 'number'
                        ? snap.net_rx_mb * 1048576
                        : null;
                const prevRx = typeof prevSnap.net_rx_bytes === 'number'
                    ? prevSnap.net_rx_bytes
                    : typeof prevSnap.net_rx_mb === 'number'
                        ? prevSnap.net_rx_mb * 1048576
                        : null;
                if (currRx !== null && prevRx !== null && currRx >= prevRx) {
                    netDown = roundTwo((currRx - prevRx) / dtSec);
                }

                const currTx = typeof snap.net_tx_bytes === 'number'
                    ? snap.net_tx_bytes
                    : typeof snap.net_tx_mb === 'number'
                        ? snap.net_tx_mb * 1048576
                        : null;
                const prevTx = typeof prevSnap.net_tx_bytes === 'number'
                    ? prevSnap.net_tx_bytes
                    : typeof prevSnap.net_tx_mb === 'number'
                        ? prevSnap.net_tx_mb * 1048576
                        : null;
                if (currTx !== null && prevTx !== null && currTx >= prevTx) {
                    netUp = roundTwo((currTx - prevTx) / dtSec);
                }
            }
        }

        points.push({
            timestamp,
            cpu,
            memory,
            netDown,
            netUp,
            diskRead,
            diskWrite,
        });
        prevSnap = snap;
        prevTs = timestamp;
    }

    return points;
}

let lastPushedMetrics: SystemMetrics | null = null;
let lastSyncedServices: Record<string, unknown> | null = null;
let hydrationGeneration = 0;

export interface HistoryStoreState {
    timeWindow: TimeWindow;
    setTimeWindow: (timeWindow: TimeWindow) => void;
    history: MetricsHistory;
    visibleHistory: MetricsHistory;
    lastPushAt: number;
    isHydrated: boolean;
    gapCount: number;
    pushMetrics: (metrics: SystemMetrics, timestampMs?: number) => void;
    hydrateHistory: (snapshots: PersistedMetricsSnapshot[]) => void;
    hydrateFromBackend: (days?: number, requestedWindow?: TimeWindow) => Promise<void>;
    syncServices: (services: Record<string, unknown> | null | undefined) => void;
    resetHistory: () => void;
}

export const useHistoryStore = create<HistoryStoreState>((set, get) => ({
    timeWindow: '5m',
    setTimeWindow: (timeWindow: TimeWindow) => {
        set((state) => ({
            timeWindow,
            visibleHistory: sliceHistory(state.history, timeWindow),
        }));
        if (timeWindow === '6h' || timeWindow === '24h') {
            void get().hydrateFromBackend(1, timeWindow);
        }
    },
    history: emptyHistory,
    visibleHistory: emptyHistory,
    lastPushAt: 0,
    isHydrated: false,
    gapCount: 0,
    pushMetrics: (metrics: SystemMetrics, timestampMs?: number) => {
        if (!metrics) return;
        const currentState = get();
        if (lastPushedMetrics === metrics && currentState.history.timestamps.length > 0 && timestampMs === undefined) {
            return;
        }
        const now = typeof timestampMs === 'number' && timestampMs > 0 ? timestampMs : Date.now();
        if (
            timestampMs === undefined &&
            currentState.lastPushAt > 0 &&
            now - currentState.lastPushAt < 100
        ) {
            lastPushedMetrics = metrics;
            return;
        }
        lastPushedMetrics = metrics;

        set((state) => {
            const memoryPercent = metrics.memory && metrics.memory.total > 0
                ? roundTwo((metrics.memory.used / metrics.memory.total) * 100)
                : 0;
            const livePoint: InternalMetricPoint = {
                timestamp: now,
                cpu: roundTwo(metrics.cpu_usage),
                memory: memoryPercent,
                netDown: parseSpeed(metrics.network?.down as string),
                netUp: parseSpeed(metrics.network?.up as string),
                diskRead: roundTwo(metrics.disk_io?.read_bytes_sec || 0),
                diskWrite: roundTwo(metrics.disk_io?.write_bytes_sec || 0),
            };
            const existingPoints = extractCanonicalPoints(state.history);
            const { points, gapCount } = mergeAndDeduplicatePoints(existingPoints, [livePoint]);
            const nextHistory = pointsToHistory(points);
            return {
                lastPushAt: now,
                gapCount,
                history: nextHistory,
                visibleHistory: sliceHistory(nextHistory, state.timeWindow),
            };
        });
    },
    hydrateHistory: (snapshots: PersistedMetricsSnapshot[]) => {
        const persistedPoints = normalizePersistedSnapshots(snapshots);
        if (persistedPoints.length === 0) {
            set({ isHydrated: true });
            return;
        }
        set((state) => {
            const existingPoints = extractCanonicalPoints(state.history);
            const { points, gapCount } = mergeAndDeduplicatePoints(persistedPoints, existingPoints);
            const nextHistory = pointsToHistory(points);
            return {
                isHydrated: true,
                gapCount,
                history: nextHistory,
                visibleHistory: sliceHistory(nextHistory, state.timeWindow),
            };
        });
    },
    hydrateFromBackend: async (days = 1, requestedWindow?: TimeWindow) => {
        const currentGen = hydrationGeneration;
        const clampedDays = Math.max(1, Math.min(30, Math.round(days)));
        const activeWindow = requestedWindow ?? '24h';
        try {
            let res = await apiFetch(
                `/api/v1/auth/system/metrics/history?days=${clampedDays}&window=${encodeURIComponent(activeWindow)}&limit=${MAX_HISTORY_SIZE}&downsample=1&target_points=${MAX_HISTORY_SIZE}`
            );
            if (!res.ok) {
                res = await apiFetch(`/api/v1/admin/ai/predictions/history?days=${clampedDays}`);
            }
            if (!res.ok || currentGen !== hydrationGeneration) return;
            const payload = await res.json();
            if (currentGen !== hydrationGeneration) return;
            const rows: PersistedMetricsSnapshot[] | null = Array.isArray(payload)
                ? payload
                : (payload && typeof payload === 'object' && Array.isArray((payload as { history?: unknown }).history))
                    ? (payload as { history: PersistedMetricsSnapshot[] }).history
                    : null;
            if (!rows || rows.length === 0) return;
            get().hydrateHistory(rows);
        } catch {
            // Silently ignore transient hydration fetch errors
        }
    },
    syncServices: (services: Record<string, unknown> | null | undefined) => {
        if (!services || lastSyncedServices === services) return;
        lastSyncedServices = services;
        globalMutate('/api/v1/auth/services', services, false);
    },
    resetHistory: () => {
        hydrationGeneration += 1;
        lastPushedMetrics = null;
        lastSyncedServices = null;
        set({
            timeWindow: '5m',
            history: emptyHistory,
            visibleHistory: emptyHistory,
            lastPushAt: 0,
            isHydrated: false,
            gapCount: 0,
        });
    },
}));
