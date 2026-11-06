'use client';

import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
    Activity,
    BarChart3,
    Calendar,
    Clock,
    Film,
    Filter,
    FolderOpen,
    Globe,
    Info,
    Loader2,
    Monitor,
    RefreshCw,
    Server,
    ShieldAlert,
    Tag,
    Users,
    AlertTriangle,
    AlertCircle,
    ArrowUpRight,
} from 'lucide-react';
import { apiFetch } from '@/lib/fetcher';
import { StreamingHistoryQuery, streamingHistorySearchParams } from '@/lib/streaming-history';
import {
    formatHistoryBytes,
    formatHistoryDuration,
} from '@/components/streaming/StreamingHistoryExplorer';

export interface StreamingInsightsProps {
    query: StreamingHistoryQuery;
    snapshot: string;
    onDrilldown: (filters: Partial<StreamingHistoryQuery>) => void;
}

export interface HourlyActivity {
    hour: number;
    playCount: number;
    watchTimeSecs: number;
    estimatedBytes: number;
    percentageOfPlays: number;
}

export interface WeekdayActivity {
    weekday: number;
    weekdayName: string;
    playCount: number;
    watchTimeSecs: number;
    estimatedBytes: number;
    percentageOfPlays: number;
}

export interface ActivityTimeseriesBucket {
    bucketStart: string;
    bucketEnd: string;
    playCount: number;
    watchTimeSecs: number;
    estimatedBytes: number;
}

export interface ActivityReport {
    timezone: string;
    window: string;
    from: string | null;
    until: string | null;
    totalConfirmedPlays: number;
    totalWatchTimeSecs: number;
    totalEstimatedBytes: number;
    undatedRecords: number;
    hourlyBreakdown: HourlyActivity[];
    weekdayBreakdown: WeekdayActivity[];
    timeseries: ActivityTimeseriesBucket[];
    dstTransitionsObserved: string[];
}

export type ConcurrencyBucketStatus =
    | 'available'
    | 'no_activity'
    | 'gap'
    | 'retention_expired'
    | 'unknown';

export interface ConcurrencyBucket {
    bucketStart: string;
    bucketEnd: string;
    peakConcurrency: number | null;
    avgConcurrency: number | null;
    peakBitrateBps: number | null;
    sampleCount: number;
    status: ConcurrencyBucketStatus;
}

export interface ConcurrencyReport {
    window: string;
    from: string | null;
    until: string | null;
    timezone: string;
    retentionDays: number;
    retentionCutoff: string | null;
    retentionLimited: boolean;
    sampleIntervalSecs?: number;
    peakConcurrency: number | null;
    peakConcurrencyAt: string | null;
    avgConcurrency: number | null;
    peakBitrateBps: number | null;
    totalSamplesAnalyzed: number;
    buckets: ConcurrencyBucket[];
    limitations: string[];
}

export interface PatternsSummaryReport {
    activity: ActivityReport;
    concurrency: ConcurrencyReport;
}

export interface ProviderServerDrilldownItem {
    provider: string;
    serverId?: string | null;
    serverName?: string | null;
    playCount: number;
    watchTimeSecs: number;
    estimatedBytes: number;
    distinctUsers?: number;
    distinctItems?: number;
    percentageOfPlays: number;
}

export interface UserDrilldownItem {
    provider: string;
    serverId: string | null;
    userId: string;
    userName: string;
    playCount: number;
    watchTimeSecs: number;
    estimatedBytes: number;
    distinctItems: number;
    lastPlayedAt: string | null;
    directPlayCount: number;
    directStreamCount: number;
    transcodeCount: number;
    unknownMethodCount: number;
    percentageOfPlays: number;
}

export interface ClientDrilldownItem {
    provider?: string | null;
    serverId?: string | null;
    clientName: string | null;
    deviceName: string | null;
    playCount: number;
    watchTimeSecs: number;
    estimatedBytes: number;
    distinctUsers: number;
    directPlayCount: number;
    directStreamCount: number;
    transcodeCount: number;
    unknownMethodCount: number;
    percentageOfPlays: number;
}

export interface ItemDrilldownItem {
    provider: string;
    serverId?: string | null;
    itemId: string;
    itemName: string;
    itemType: string | null;
    seriesName: string | null;
    playCount: number;
    watchTimeSecs: number;
    estimatedBytes: number;
    distinctViewers: number;
    lastPlayedAt: string | null;
    percentageOfPlays: number;
}

export interface LibraryDrilldownItem {
    provider?: string | null;
    serverId?: string | null;
    libraryId: string;
    libraryName: string;
    playCount: number;
    watchTimeSecs: number;
    estimatedBytes: number;
    distinctViewers: number;
    distinctItems: number;
    percentageOfPlays: number;
}

export interface GenreDrilldownItem {
    provider?: string | null;
    serverId?: string | null;
    genre: string;
    playCount: number;
    watchTimeSecs: number;
    estimatedBytes: number;
    distinctViewers: number;
    distinctItems: number;
    percentageOfPlays: number;
}

export interface LabelMetrics {
    cohortDistinctPlays: number;
    sumOfLabelPlays: number;
    isOverlapping: boolean;
    unlabeledPlays: number;
    totalDistinctLabels?: number;
    truncated?: boolean;
}

export interface DrilldownReport {
    cohortDistinctPlays: number;
    cohortTotalWatchTimeSecs: number;
    cohortTotalEstimatedBytes: number;
    cohortDistinctUsers: number;
    cohortDistinctItems: number;
    cohortDistinctClients?: number;
    cohortDistinctServers?: number;
    providers?: ProviderServerDrilldownItem[];
    servers?: ProviderServerDrilldownItem[];
    users: UserDrilldownItem[];
    clients: ClientDrilldownItem[];
    items: ItemDrilldownItem[];
    libraries: LibraryDrilldownItem[];
    libraryMetrics: LabelMetrics;
    genres: GenreDrilldownItem[];
    genreMetrics: LabelMetrics;
}

type ActivityChartMode = 'hourly' | 'weekday' | 'daily';
type DrilldownTab = 'users' | 'clients' | 'items' | 'libraries' | 'genres' | 'servers';

function isAbortError(error: unknown): boolean {
    if (!error || typeof error !== 'object') return false;
    const candidate = error as { name?: unknown; code?: unknown };
    return candidate.name === 'AbortError' || candidate.code === 'ABORT_ERR';
}

async function extractResponseErrorMessage(res: Response, fallback: string): Promise<string> {
    try {
        const text = await res.text();
        if (!text.trim()) return `${fallback} (HTTP ${res.status})`;
        try {
            const parsed = JSON.parse(text) as { message?: string; error?: string };
            if (typeof parsed.message === 'string' && parsed.message.trim()) {
                return parsed.message.trim();
            }
            if (typeof parsed.error === 'string' && parsed.error.trim()) {
                return parsed.error.trim();
            }
        } catch {
            return text.trim().slice(0, 240);
        }
    } catch {
        // ignore read error
    }
    return `${fallback} (HTTP ${res.status})`;
}

export function buildInsightsRequestQuery(
    query: StreamingHistoryQuery,
    snapshot: string
): StreamingHistoryQuery {
    const next: StreamingHistoryQuery = { ...query };
    delete next.cursor;
    const trimmedSnapshot = snapshot.trim();
    if (trimmedSnapshot !== '') {
        next.snapshot = trimmedSnapshot;
    } else {
        delete next.snapshot;
    }
    return next;
}

export function formatBitrateBps(bps: number | null | undefined): string {
    if (bps === null || bps === undefined || !Number.isFinite(bps)) {
        return 'Unknown';
    }
    if (bps <= 0) return '0 bps';
    if (bps >= 1_000_000_000) {
        return `${(bps / 1_000_000_000).toFixed(2)} Gbps`;
    }
    if (bps >= 1_000_000) {
        return `${(bps / 1_000_000).toFixed(1)} Mbps`;
    }
    if (bps >= 1_000) {
        return `${(bps / 1_000).toFixed(0)} Kbps`;
    }
    return `${Math.round(bps)} bps`;
}

function formatHourLabel(hour: number): string {
    const normalized = Math.max(0, Math.min(23, Math.floor(hour)));
    return `${String(normalized).padStart(2, '0')}:00`;
}

function formatBucketDateLabel(iso: string, timezone: string): string {
    if (!iso) return 'Unknown';
    const parsed = new Date(iso);
    if (Number.isNaN(parsed.getTime())) return iso.slice(0, 16);
    try {
        return new Intl.DateTimeFormat('en-US', {
            timeZone: timezone || 'UTC',
            month: 'short',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            hour12: false,
        }).format(parsed);
    } catch {
        return iso.slice(0, 16).replace('T', ' ');
    }
}

function getConcurrencyStatusMeta(status: ConcurrencyBucketStatus): {
    label: string;
    badgeClass: string;
    barClass: string;
    isNullConcurrency: boolean;
} {
    switch (status) {
        case 'available':
            return {
                label: 'Sampled Active',
                badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
                barClass: 'bg-emerald-400',
                isNullConcurrency: false,
            };
        case 'no_activity':
            return {
                label: '0 Active (Observed)',
                badgeClass: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
                barClass: 'bg-sky-400/50',
                isNullConcurrency: false,
            };
        case 'retention_expired':
            return {
                label: 'Unknown (>90d Retention)',
                badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
                barClass: 'bg-amber-500/30',
                isNullConcurrency: true,
            };
        case 'gap':
        case 'unknown':
        default:
            return {
                label: 'Unknown (Sampling Gap)',
                badgeClass: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
                barClass: 'bg-slate-500/30',
                isNullConcurrency: true,
            };
    }
}

function buildScopeFilterPatch(
    basePatch: Partial<StreamingHistoryQuery>,
    provider?: string | null,
    serverId?: string | null
): Partial<StreamingHistoryQuery> {
    const patch: Partial<StreamingHistoryQuery> = { ...basePatch };
    if (typeof provider === 'string' && provider.trim() !== '' && provider.trim() !== 'all') {
        patch.provider = provider.trim();
    }
    patch.serverId = typeof serverId === 'string' ? serverId.trim() : '';
    return patch;
}

export function StreamingInsights({
    query,
    snapshot,
    onDrilldown,
}: StreamingInsightsProps) {
    const [activityMode, setActivityMode] = useState<ActivityChartMode>('hourly');
    const [activeTab, setActiveTab] = useState<DrilldownTab>('users');
    const [reloadTrigger, setReloadTrigger] = useState<number>(0);

    const [patternsData, setPatternsData] = useState<PatternsSummaryReport | null>(null);
    const [drilldownData, setDrilldownData] = useState<DrilldownReport | null>(null);
    const [isLoading, setIsLoading] = useState<boolean>(true);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [isConflict409, setIsConflict409] = useState<boolean>(false);

    const requestGenRef = useRef<number>(0);

    const requestQuery = useMemo(
        () => buildInsightsRequestQuery(query, snapshot),
        [query, snapshot]
    );

    const customRangeIncomplete =
        requestQuery.window === 'custom' && (!requestQuery.from || !requestQuery.until);

    const queryString = useMemo(() => {
        const params = streamingHistorySearchParams(requestQuery);
        return params.toString();
    }, [requestQuery]);

    // Fetch patterns and drilldown on query/snapshot changes without live polling
    useEffect(() => {
        if (customRangeIncomplete) {
            return;
        }

        const controller = new AbortController();
        const gen = ++requestGenRef.current;

        const patternsEndpoint = `/api/v1/auth/streaming/patterns${queryString ? `?${queryString}` : ''}`;
        const drilldownEndpoint = `/api/v1/auth/streaming/drilldown${queryString ? `?${queryString}` : ''}`;

        void (async () => {
            await Promise.resolve();
            if (controller.signal.aborted || gen !== requestGenRef.current) return;

            setIsLoading(true);
            setErrorMessage(null);
            setIsConflict409(false);

            try {
                const [patternsRes, drilldownRes] = await Promise.all([
                    apiFetch(patternsEndpoint, { signal: controller.signal }),
                    apiFetch(drilldownEndpoint, { signal: controller.signal }),
                ]);

                if (controller.signal.aborted || gen !== requestGenRef.current) return;

                if (patternsRes.status === 409 || drilldownRes.status === 409) {
                    const conflictRes = patternsRes.status === 409 ? patternsRes : drilldownRes;
                    const msg = await extractResponseErrorMessage(
                        conflictRes,
                        'Analytics snapshot expired or changed (HTTP 409). Refresh the explorer snapshot.'
                    );
                    if (controller.signal.aborted || gen !== requestGenRef.current) return;
                    setIsConflict409(true);
                    setErrorMessage(msg);
                    return;
                }

                if (!patternsRes.ok) {
                    const msg = await extractResponseErrorMessage(
                        patternsRes,
                        'Failed to load streaming activity and concurrency patterns'
                    );
                    if (controller.signal.aborted || gen !== requestGenRef.current) return;
                    setErrorMessage(msg);
                    return;
                }

                if (!drilldownRes.ok) {
                    const msg = await extractResponseErrorMessage(
                        drilldownRes,
                        'Failed to load streaming cohort drilldowns'
                    );
                    if (controller.signal.aborted || gen !== requestGenRef.current) return;
                    setErrorMessage(msg);
                    return;
                }

                const [patternsPayload, drilldownPayload] = (await Promise.all([
                    patternsRes.json(),
                    drilldownRes.json(),
                ])) as [PatternsSummaryReport, DrilldownReport];

                if (controller.signal.aborted || gen !== requestGenRef.current) return;

                setPatternsData(patternsPayload);
                setDrilldownData(drilldownPayload);
            } catch (err: unknown) {
                if (controller.signal.aborted || isAbortError(err) || gen !== requestGenRef.current) {
                    return;
                }
                setErrorMessage(
                    err instanceof Error
                        ? err.message
                        : 'Unable to reach streaming analytics endpoints.'
                );
            } finally {
                if (!controller.signal.aborted && gen === requestGenRef.current) {
                    setIsLoading(false);
                }
            }
        })();

        return () => {
            controller.abort();
        };
    }, [queryString, customRangeIncomplete, reloadTrigger]);

    const handleRetry = useCallback(() => {
        setReloadTrigger((n) => n + 1);
    }, []);

    const activity = patternsData?.activity ?? null;
    const concurrency = patternsData?.concurrency ?? null;
    const effectiveTimezone = activity?.timezone || concurrency?.timezone || requestQuery.timezone || 'UTC';
    const topLimit = requestQuery.pageSize && requestQuery.pageSize >= 1 ? requestQuery.pageSize : 50;

    // Derive provider/server summary groups from backend if provided, or from stable user/item drilldown identities
    const providerServerGroups = useMemo<ProviderServerDrilldownItem[]>(() => {
        if (!drilldownData) return [];
        if (Array.isArray(drilldownData.servers) && drilldownData.servers.length > 0) {
            return drilldownData.servers;
        }
        if (Array.isArray(drilldownData.providers) && drilldownData.providers.length > 0) {
            return drilldownData.providers;
        }
        const map = new Map<
            string,
            {
                provider: string;
                serverId: string | null;
                playCount: number;
                watchTimeSecs: number;
                estimatedBytes: number;
                distinctUsers: number;
            }
        >();
        for (const u of drilldownData.users ?? []) {
            const normServerId =
                typeof u.serverId === 'string' && u.serverId.trim() !== ''
                    ? u.serverId.trim()
                    : null;
            const key = `${u.provider}::${normServerId ?? ''}`;
            const existing = map.get(key);
            if (existing) {
                existing.playCount += u.playCount;
                existing.watchTimeSecs += u.watchTimeSecs;
                existing.estimatedBytes += u.estimatedBytes;
                existing.distinctUsers += 1;
            } else {
                map.set(key, {
                    provider: u.provider,
                    serverId: normServerId,
                    playCount: u.playCount,
                    watchTimeSecs: u.watchTimeSecs,
                    estimatedBytes: u.estimatedBytes,
                    distinctUsers: 1,
                });
            }
        }
        const denom = drilldownData.cohortDistinctPlays || 0;
        return Array.from(map.values())
            .sort((a, b) => b.playCount - a.playCount || b.watchTimeSecs - a.watchTimeSecs)
            .map((entry) => ({
                ...entry,
                percentageOfPlays: denom > 0 ? (entry.playCount / denom) * 100 : 0,
            }));
    }, [drilldownData]);

    const concurrencyCounts = useMemo(() => {
        const buckets = concurrency?.buckets ?? [];
        let availableCount = 0;
        let noActivityCount = 0;
        let gapCount = 0;
        let expiredCount = 0;
        for (const b of buckets) {
            if (b.status === 'available') availableCount += 1;
            else if (b.status === 'no_activity') noActivityCount += 1;
            else if (b.status === 'retention_expired') expiredCount += 1;
            else gapCount += 1;
        }
        return {
            total: buckets.length,
            availableCount,
            noActivityCount,
            gapCount,
            expiredCount,
            hasNullConcurrency:
                (concurrency?.totalSamplesAnalyzed ?? 0) === 0 ||
                concurrency?.peakConcurrency === null ||
                gapCount > 0 ||
                expiredCount > 0,
        };
    }, [concurrency]);

    const activityBars = useMemo(() => {
        if (!activity) return [];
        if (activityMode === 'hourly') {
            return (activity.hourlyBreakdown ?? []).map((item) => ({
                key: `hour-${item.hour}`,
                label: formatHourLabel(item.hour),
                subLabel: `Local Hour (${effectiveTimezone})`,
                playCount: item.playCount,
                watchTimeSecs: item.watchTimeSecs,
                estimatedBytes: item.estimatedBytes,
                percentage: item.percentageOfPlays,
            }));
        }
        if (activityMode === 'weekday') {
            return (activity.weekdayBreakdown ?? []).map((item) => ({
                key: `weekday-${item.weekday}`,
                label: item.weekdayName,
                subLabel: `Weekday #${item.weekday + 1} (${effectiveTimezone})`,
                playCount: item.playCount,
                watchTimeSecs: item.watchTimeSecs,
                estimatedBytes: item.estimatedBytes,
                percentage: item.percentageOfPlays,
            }));
        }
        const denom = activity.totalConfirmedPlays || 0;
        return (activity.timeseries ?? []).map((bucket, idx) => ({
            key: `ts-${bucket.bucketStart}-${idx}`,
            label: formatBucketDateLabel(bucket.bucketStart, effectiveTimezone),
            subLabel: `${formatBucketDateLabel(bucket.bucketStart, effectiveTimezone)} → ${formatBucketDateLabel(bucket.bucketEnd, effectiveTimezone)}`,
            playCount: bucket.playCount,
            watchTimeSecs: bucket.watchTimeSecs,
            estimatedBytes: bucket.estimatedBytes,
            percentage: denom > 0 ? (bucket.playCount / denom) * 100 : 0,
        }));
    }, [activity, activityMode, effectiveTimezone]);

    const maxActivityPlays = useMemo(() => {
        let max = 0;
        for (const bar of activityBars) {
            if (bar.playCount > max) max = bar.playCount;
        }
        return max;
    }, [activityBars]);

    const maxConcurrencyPeak = useMemo(() => {
        let max = 0;
        for (const b of concurrency?.buckets ?? []) {
            if (typeof b.peakConcurrency === 'number' && b.peakConcurrency > max) {
                max = b.peakConcurrency;
            }
        }
        return max;
    }, [concurrency]);

    const isPeakConcurrencyNull =
        !concurrency ||
        concurrency.peakConcurrency === null ||
        (concurrency.totalSamplesAnalyzed === 0 &&
            concurrencyCounts.availableCount === 0 &&
            concurrencyCounts.noActivityCount === 0);

    return (
        <section
            aria-label="Streaming Activity Patterns & Cohort Drilldowns"
            data-testid="streaming-insights"
            className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5 space-y-5 w-full min-w-0"
        >
            {/* ===================================================================== */}
            {/* 1. HEADER & SNAPSHOT / TIMEZONE / HONESTY DISCLOSURES                 */}
            {/* ===================================================================== */}
            <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-4 border-b border-white/[0.06]">
                <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2.5">
                        <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                            <BarChart3 size={18} className="text-indigo-400 shrink-0" />
                            <span>Streaming Activity Patterns &amp; Connected Cohort Drilldowns</span>
                        </h3>

                        <span
                            data-testid="insights-timezone-badge"
                            className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-indigo-500/15 border border-indigo-500/30 text-indigo-200 inline-flex items-center gap-1.5"
                        >
                            <Globe size={12} className="text-indigo-400" />
                            <span>TZ: {effectiveTimezone}</span>
                        </span>

                        {snapshot && (
                            <span
                                data-testid="insights-snapshot-badge"
                                className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-white/[0.06] border border-white/10 text-slate-300"
                            >
                                Snapshot Locked
                            </span>
                        )}
                    </div>

                    <p className="text-xs text-slate-400">
                        Confirmed-play activity and drilldowns (<code>observed_session</code> +{' '}
                        <code>imported_event</code>) evaluated at the active query and snapshot without 5-second live polling. Select any group row to filter the archive explorer by stable identity.
                    </p>
                </div>

                <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <button
                        type="button"
                        onClick={handleRetry}
                        disabled={isLoading || customRangeIncomplete}
                        aria-label="Reload streaming insights"
                        data-testid="refresh-insights-btn"
                        className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] hover:bg-white/[0.08] disabled:opacity-50 border border-white/10 text-slate-200 flex items-center gap-1.5 transition-all"
                    >
                        <RefreshCw size={13} className={isLoading ? 'animate-spin text-indigo-400' : ''} />
                        <span>Reload Insights</span>
                    </button>
                </div>
            </div>

            {/* ===================================================================== */}
            {/* 2. LOADING, CUSTOM RANGE VALIDATION, AND ERROR STATES                 */}
            {/* ===================================================================== */}
            {customRangeIncomplete && (
                <div
                    role="alert"
                    data-testid="insights-custom-range-incomplete"
                    className="p-3.5 rounded-xl border border-amber-500/30 bg-amber-950/30 text-xs text-amber-200 flex items-center gap-2.5"
                >
                    <AlertTriangle size={16} className="text-amber-400 shrink-0" />
                    <span>
                        Complete both <strong>Custom From</strong> and <strong>Custom Until</strong> RFC3339 timestamps to load patterns and drilldowns.
                    </span>
                </div>
            )}

            {errorMessage && (
                <div
                    role="alert"
                    data-testid={
                        isConflict409 ? 'insights-conflict-banner' : 'insights-error-banner'
                    }
                    className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs ${
                        isConflict409
                            ? 'border-amber-500/40 bg-amber-950/35 text-amber-100'
                            : 'border-rose-500/40 bg-rose-950/35 text-rose-100'
                    }`}
                >
                    <div className="flex items-start gap-2.5">
                        {isConflict409 ? (
                            <AlertTriangle size={16} className="text-amber-400 shrink-0 mt-0.5" />
                        ) : (
                            <AlertCircle size={16} className="text-rose-400 shrink-0 mt-0.5" />
                        )}
                        <div>
                            <p className="font-bold">
                                {isConflict409
                                    ? 'Analytics Snapshot Expired or Changed (HTTP 409)'
                                    : 'Insights Request Error'}
                            </p>
                            <p className="mt-0.5 text-slate-200">{errorMessage}</p>
                        </div>
                    </div>
                    <button
                        type="button"
                        onClick={handleRetry}
                        data-testid="retry-insights-btn"
                        className="px-3.5 py-1.5 rounded-xl bg-white/10 hover:bg-white/20 text-white font-bold shrink-0 transition-all"
                    >
                        Retry Insights
                    </button>
                </div>
            )}

            {isLoading && !patternsData && !drilldownData && !errorMessage && !customRangeIncomplete && (
                <div
                    role="status"
                    aria-live="polite"
                    data-testid="insights-loading-state"
                    className="py-10 px-4 rounded-xl border border-white/[0.06] bg-black/25 text-center text-xs text-slate-400"
                >
                    <Loader2 size={20} className="animate-spin text-indigo-400 mx-auto mb-2" />
                    <p>Computing timezone-aware activity, sampled concurrency, and cohort drilldowns...</p>
                </div>
            )}

            {/* ===================================================================== */}
            {/* 3. PATTERNS GRID: TIMEZONE ACTIVITY & SAMPLED CONCURRENCY             */}
            {/* ===================================================================== */}
            {patternsData && !errorMessage && (
                <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
                    {/* 3A. TIMEZONE-AWARE ACTIVITY PATTERNS */}
                    <div
                        data-testid="activity-patterns-card"
                        className="rounded-xl border border-white/[0.06] bg-black/25 p-4 space-y-4 min-w-0"
                    >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                            <div>
                                <h4 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                                    <Calendar size={15} className="text-indigo-400 shrink-0" />
                                    <span>Timezone-Aware Activity Breakdown</span>
                                </h4>
                                <p className="text-xs text-slate-400 mt-0.5">
                                    Confirmed plays grouped in <code>{effectiveTimezone}</code> ({activity?.totalConfirmedPlays.toLocaleString() ?? 0} plays,{' '}
                                    {formatHistoryDuration(activity?.totalWatchTimeSecs ?? 0)},{' '}
                                    {formatHistoryBytes(activity?.totalEstimatedBytes ?? 0, 2)} est.)
                                </p>
                            </div>

                            <div
                                role="tablist"
                                aria-label="Activity grouping mode"
                                className="inline-flex rounded-xl bg-slate-950/80 border border-white/10 p-1 shrink-0"
                            >
                                {(
                                    [
                                        { id: 'hourly', label: 'Hourly (00–23)' },
                                        { id: 'weekday', label: 'Weekday' },
                                        { id: 'daily', label: 'Timeseries' },
                                    ] as const
                                ).map((tab) => {
                                    const selected = activityMode === tab.id;
                                    return (
                                        <button
                                            key={tab.id}
                                            type="button"
                                            role="tab"
                                            aria-selected={selected}
                                            data-testid={`activity-mode-${tab.id}-btn`}
                                            onClick={() => setActivityMode(tab.id)}
                                            className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-all ${
                                                selected
                                                    ? 'bg-indigo-600 text-white shadow'
                                                    : 'text-slate-300 hover:text-white'
                                            }`}
                                        >
                                            {tab.label}
                                        </button>
                                    );
                                })}
                            </div>
                        </div>

                        {/* DST transition & Undated disclosures */}
                        {activity && activity.dstTransitionsObserved.length > 0 && (
                            <div
                                data-testid="activity-dst-notice"
                                className="px-3 py-2 rounded-xl border border-indigo-500/30 bg-indigo-950/25 text-xs text-indigo-200 flex items-start gap-2"
                            >
                                <Clock size={14} className="text-indigo-400 shrink-0 mt-0.5" />
                                <div className="space-y-0.5">
                                    {activity.dstTransitionsObserved.map((note, idx) => (
                                        <p key={idx}>{note}</p>
                                    ))}
                                </div>
                            </div>
                        )}

                        {activity && activity.undatedRecords > 0 && (
                            <div
                                data-testid="activity-undated-notice"
                                className="px-3 py-2 rounded-xl border border-amber-500/25 bg-amber-950/20 text-xs text-amber-200 flex items-center gap-2"
                            >
                                <Info size={14} className="text-amber-400 shrink-0" />
                                <span>
                                    <strong>{activity.undatedRecords.toLocaleString()}</strong> confirmed play(s) have unrecorded timestamps and are excluded from hourly/weekday/timeseries buckets rather than placed at a fake hour or date.
                                </span>
                            </div>
                        )}

                        {/* Accessible Activity Bar List (local scoped scroll) */}
                        {activity && activity.totalConfirmedPlays === 0 ? (
                            <div
                                data-testid="activity-empty-state"
                                className="py-8 px-4 rounded-xl border border-white/[0.05] bg-slate-950/40 text-center text-xs text-slate-400"
                            >
                                No dated confirmed plays recorded in this window and filter scope.
                            </div>
                        ) : (
                            <div
                                role="list"
                                aria-label={`Activity bars (${activityMode})`}
                                data-testid={`activity-bars-${activityMode}`}
                                className="max-h-72 overflow-y-auto pr-1 space-y-1.5"
                            >
                                {activityBars.map((bar) => {
                                    const widthPct =
                                        maxActivityPlays > 0
                                            ? Math.max(
                                                  bar.playCount > 0 ? 4 : 0,
                                                  Math.round((bar.playCount / maxActivityPlays) * 100)
                                              )
                                            : 0;
                                    return (
                                        <div
                                            key={bar.key}
                                            role="listitem"
                                            data-testid={`activity-bar-row-${bar.key}`}
                                            className="rounded-lg border border-white/[0.05] bg-slate-950/60 px-3 py-2 text-xs"
                                        >
                                            <div className="flex items-center justify-between gap-2 mb-1">
                                                <span className="font-mono font-semibold text-slate-200">
                                                    {bar.label}
                                                </span>
                                                <div className="flex items-center gap-2 font-mono text-slate-300">
                                                    <span>
                                                        <strong className="text-white">
                                                            {bar.playCount.toLocaleString()}
                                                        </strong>{' '}
                                                        plays ({bar.percentage.toFixed(1)}%)
                                                    </span>
                                                    <span className="text-slate-500">&middot;</span>
                                                    <span className="text-emerald-300">
                                                        {formatHistoryDuration(bar.watchTimeSecs)}
                                                    </span>
                                                    <span className="text-slate-500">&middot;</span>
                                                    <span className="text-teal-300">
                                                        {formatHistoryBytes(bar.estimatedBytes, 1)}
                                                    </span>
                                                </div>
                                            </div>
                                            <div className="w-full h-2 rounded-full bg-white/[0.06] overflow-hidden">
                                                <div
                                                    className="h-full rounded-full bg-indigo-500 transition-all"
                                                    style={{ width: `${widthPct}%` }}
                                                />
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>

                    {/* 3B. SAMPLED CONCURRENCY & EXPLICIT 15s / 90d / GAP / NULL LIMITS */}
                    <div
                        data-testid="concurrency-patterns-card"
                        className="rounded-xl border border-white/[0.06] bg-black/25 p-4 space-y-4 min-w-0"
                    >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                            <div>
                                <h4 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                                    <Activity size={15} className="text-emerald-400 shrink-0" />
                                    <span>Sampled Session Concurrency &amp; Retention Bounds</span>
                                </h4>
                                <p className="text-xs text-slate-400 mt-0.5">
                                    Derived strictly from 15s live collector samples (<code>streaming_session_samples</code>,{' '}
                                    <code>{concurrency?.retentionDays ?? 90}d</code> retention). Never synthesized from item summaries or legacy rows.
                                </p>
                            </div>
                            <span
                                data-testid="concurrency-retention-badge"
                                className={`text-xs font-mono px-2.5 py-0.5 rounded-full border shrink-0 ${
                                    concurrency?.retentionLimited
                                        ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                        : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                }`}
                            >
                                {concurrency?.retentionLimited
                                    ? `Retention Limited (${concurrency.retentionDays}d max)`
                                    : `${concurrency?.retentionDays ?? 90}d Sample Window`}
                            </span>
                        </div>

                        {/* Concurrency Summary KPIs */}
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                            <div className="rounded-xl border border-white/[0.06] bg-slate-950/60 p-3">
                                <span className="text-xs font-bold text-slate-400 block">
                                    Peak Concurrent Streams
                                </span>
                                <div
                                    data-testid="concurrency-peak-value"
                                    className="mt-1 text-base font-extrabold text-white font-mono"
                                >
                                    {isPeakConcurrencyNull
                                        ? 'Unknown (No Samples)'
                                        : `${concurrency.peakConcurrency?.toLocaleString()} streams`}
                                </div>
                                <p className="text-xs text-slate-400 mt-0.5">
                                    {concurrency?.peakConcurrencyAt
                                        ? `At ${formatBucketDateLabel(concurrency.peakConcurrencyAt, effectiveTimezone)}`
                                        : 'Null/unknown where unsampled'}
                                </p>
                            </div>

                            <div className="rounded-xl border border-white/[0.06] bg-slate-950/60 p-3">
                                <span className="text-xs font-bold text-slate-400 block">
                                    Avg Active Sampled
                                </span>
                                <div
                                    data-testid="concurrency-avg-value"
                                    className="mt-1 text-base font-extrabold text-emerald-200 font-mono"
                                >
                                    {isPeakConcurrencyNull || concurrency?.avgConcurrency === null
                                        ? 'Unknown'
                                        : `${concurrency.avgConcurrency.toFixed(2)} avg`}
                                </div>
                                <p className="text-xs text-slate-400 mt-0.5">
                                    Across {concurrency?.totalSamplesAnalyzed.toLocaleString() ?? 0} observation timestamps (partial per-provider coverage)
                                </p>
                            </div>

                            <div className="rounded-xl border border-white/[0.06] bg-slate-950/60 p-3">
                                <span className="text-xs font-bold text-slate-400 block">
                                    Peak Sampled Bitrate
                                </span>
                                <div
                                    data-testid="concurrency-peak-bitrate"
                                    className="mt-1 text-base font-extrabold text-teal-200 font-mono"
                                >
                                    {isPeakConcurrencyNull
                                        ? 'Unknown'
                                        : formatBitrateBps(concurrency?.peakBitrateBps)}
                                </div>
                                <p className="text-xs text-slate-400 mt-0.5">
                                    {concurrencyCounts.gapCount} gap(s) &middot; {concurrencyCounts.expiredCount} expired(&gt;{concurrency?.retentionDays ?? 90}d)
                                </p>
                            </div>
                        </div>

                        {/* Honest Sampling, Retention & Null-Concurrency Disclosures */}
                        <div
                            data-testid="concurrency-limitations-box"
                            className="rounded-xl border border-amber-500/25 bg-amber-950/20 p-3 text-xs text-amber-100 space-y-1.5"
                        >
                            <div className="font-bold flex items-center gap-1.5 text-amber-300">
                                <ShieldAlert size={14} className="shrink-0" />
                                <span>Explicit 15s Sampling, Gap &amp; {concurrency?.retentionDays ?? 90}-Day Retention Limits</span>
                            </div>
                            <p className="text-slate-200">
                                Concurrency is observed at ~15-second collector intervals and retained for{' '}
                                <strong>{concurrency?.retentionDays ?? 90} days</strong>
                                {concurrency?.retentionCutoff
                                    ? ` (cutoff: ${concurrency.retentionCutoff.slice(0, 10)})`
                                    : ''}
                                . Unsampled intervals (<code>gap</code>) and windows older than{' '}
                                {concurrency?.retentionDays ?? 90} days (<code>retention_expired</code>) are reported as{' '}
                                <strong>Unknown / null concurrency</strong>—never fabricated as zero streams.
                            </p>
                            {concurrency && concurrency.limitations.length > 0 && (
                                <ul className="list-disc list-inside text-slate-300 space-y-0.5">
                                    {concurrency.limitations.map((lim, idx) => (
                                        <li key={idx}>{lim}</li>
                                    ))}
                                </ul>
                            )}
                        </div>

                        {/* Concurrency Bucket List */}
                        <div
                            role="list"
                            aria-label="Sampled concurrency buckets"
                            data-testid="concurrency-buckets-list"
                            className="max-h-56 overflow-y-auto pr-1 space-y-1.5"
                        >
                            {(concurrency?.buckets ?? []).map((bucket, idx) => {
                                const meta = getConcurrencyStatusMeta(bucket.status);
                                const peakVal = meta.isNullConcurrency
                                    ? null
                                    : bucket.peakConcurrency ?? 0;
                                const widthPct =
                                    peakVal !== null && maxConcurrencyPeak > 0
                                        ? Math.max(
                                              peakVal > 0 ? 5 : 0,
                                              Math.round((peakVal / maxConcurrencyPeak) * 100)
                                          )
                                        : 0;
                                return (
                                    <div
                                        key={`${bucket.bucketStart}-${idx}`}
                                        role="listitem"
                                        data-testid={`concurrency-bucket-${idx}`}
                                        className="rounded-lg border border-white/[0.05] bg-slate-950/60 px-3 py-2 text-xs"
                                    >
                                        <div className="flex flex-wrap items-center justify-between gap-2">
                                            <span className="font-mono text-slate-200">
                                                {formatBucketDateLabel(
                                                    bucket.bucketStart,
                                                    effectiveTimezone
                                                )}
                                            </span>
                                            <div className="flex items-center gap-2">
                                                <span
                                                    className={`px-2 py-0.5 rounded-full border text-xs font-semibold ${meta.badgeClass}`}
                                                >
                                                    {meta.label}
                                                </span>
                                                <span className="font-mono text-slate-200">
                                                    {meta.isNullConcurrency || bucket.peakConcurrency === null
                                                        ? 'Unknown (null)'
                                                        : `Peak ${bucket.peakConcurrency} · Avg ${(bucket.avgConcurrency ?? 0).toFixed(1)} · ${bucket.sampleCount} samples`}
                                                </span>
                                            </div>
                                        </div>
                                        {!meta.isNullConcurrency && (
                                            <div className="w-full h-1.5 rounded-full bg-white/[0.06] overflow-hidden mt-1.5">
                                                <div
                                                    className={`h-full rounded-full ${meta.barClass}`}
                                                    style={{ width: `${widthPct}%` }}
                                                />
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                </div>
            )}

            {/* ===================================================================== */}
            {/* 4. CONNECTED COHORT DRILLDOWNS (STABLE IDENTITIES, OVERLAP HONESTY)   */}
            {/* ===================================================================== */}
            {drilldownData && !errorMessage && (
                <div
                    data-testid="cohort-drilldown-section"
                    className="rounded-xl border border-white/[0.06] bg-black/25 p-4 space-y-4 min-w-0"
                >
                    {/* Cohort Denominator Banner & Top-N Truncation Disclosure */}
                    <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-3 border-b border-white/[0.06]">
                        <div className="space-y-1">
                            <div className="flex flex-wrap items-center gap-2">
                                <h4 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                                    <Filter size={15} className="text-indigo-400 shrink-0" />
                                    <span>Interactive Cohort Drilldowns (Stable Identity Grouping)</span>
                                </h4>
                                <span
                                    data-testid="drilldown-cohort-denominator-badge"
                                    className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-200"
                                >
                                    Denominator: {drilldownData.cohortDistinctPlays.toLocaleString()} distinct confirmed plays
                                </span>
                                <span
                                    data-testid="drilldown-top-limit-badge"
                                    className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-white/[0.06] border border-white/10 text-slate-300"
                                >
                                    Top {topLimit} per facet
                                </span>
                            </div>
                            <p className="text-xs text-slate-400">
                                Grouped by stable provider/server/entity IDs (never collapsed by display name). Percentages use{' '}
                                <strong>{drilldownData.cohortDistinctPlays.toLocaleString()}</strong> distinct cohort plays as denominator ({drilldownData.cohortDistinctUsers.toLocaleString()} distinct users,{' '}
                                {drilldownData.cohortDistinctItems.toLocaleString()} distinct items).
                            </p>
                        </div>

                        {/* Facet Selector Tabs */}
                        <div
                            role="tablist"
                            aria-label="Drilldown facets"
                            className="flex flex-wrap gap-1.5 rounded-xl bg-slate-950/80 border border-white/10 p-1 shrink-0"
                        >
                            {(
                                [
                                    {
                                        id: 'users',
                                        label: `Users (${drilldownData.users.length})`,
                                        icon: Users,
                                    },
                                    {
                                        id: 'clients',
                                        label: `Clients & Devices (${drilldownData.clients.length})`,
                                        icon: Monitor,
                                    },
                                    {
                                        id: 'items',
                                        label: `Items (${drilldownData.items.length})`,
                                        icon: Film,
                                    },
                                    {
                                        id: 'libraries',
                                        label: `Libraries (${drilldownData.libraries.length})`,
                                        icon: FolderOpen,
                                    },
                                    {
                                        id: 'genres',
                                        label: `Genres (${drilldownData.genres.length})`,
                                        icon: Tag,
                                    },
                                    {
                                        id: 'servers',
                                        label: `Providers & Servers (${providerServerGroups.length})`,
                                        icon: Server,
                                    },
                                ] as const
                            ).map((tab) => {
                                const Icon = tab.icon;
                                const selected = activeTab === tab.id;
                                return (
                                    <button
                                        key={tab.id}
                                        type="button"
                                        role="tab"
                                        aria-selected={selected}
                                        data-testid={`drilldown-tab-${tab.id}`}
                                        onClick={() => setActiveTab(tab.id)}
                                        className={`px-2.5 py-1.5 rounded-lg text-xs font-semibold inline-flex items-center gap-1.5 transition-all ${
                                            selected
                                                ? 'bg-indigo-600 text-white shadow'
                                                : 'text-slate-300 hover:text-white hover:bg-white/[0.05]'
                                        }`}
                                    >
                                        <Icon size={13} />
                                        <span>{tab.label}</span>
                                    </button>
                                );
                            })}
                        </div>
                    </div>

                    {/* 4A. USERS DRILLDOWN */}
                    {activeTab === 'users' && (
                        <div data-testid="drilldown-panel-users" className="space-y-3">
                            {drilldownData.cohortDistinctUsers > drilldownData.users.length && (
                                <div
                                    data-testid="users-truncation-notice"
                                    className="px-3 py-2 rounded-xl border border-amber-500/30 bg-amber-950/25 text-xs text-amber-200 flex items-center gap-2"
                                >
                                    <Info size={14} className="text-amber-400 shrink-0" />
                                    <span>
                                        Showing top <strong>{drilldownData.users.length}</strong> of{' '}
                                        <strong>{drilldownData.cohortDistinctUsers.toLocaleString()}</strong> distinct users in cohort (truncated to pageSize={topLimit}).
                                    </span>
                                </div>
                            )}

                            {drilldownData.users.length === 0 ? (
                                <div className="py-6 text-center text-xs text-slate-400">
                                    No confirmed user plays in this cohort.
                                </div>
                            ) : (
                                <div className="max-h-80 overflow-y-auto pr-1 space-y-2">
                                    {drilldownData.users.map((u) => {
                                        const stableKey = `${u.provider}::${u.serverId ?? 'none'}::${u.userId}`;
                                        return (
                                            <button
                                                key={stableKey}
                                                type="button"
                                                data-testid={`drilldown-user-btn-${u.provider}-${u.serverId || 'none'}-${u.userId}`}
                                                onClick={() =>
                                                    onDrilldown(
                                                        buildScopeFilterPatch(
                                                            { userId: u.userId },
                                                            u.provider,
                                                            u.serverId
                                                        )
                                                    )
                                                }
                                                className="w-full text-left rounded-xl border border-white/[0.06] bg-slate-950/70 hover:bg-indigo-950/30 hover:border-indigo-500/40 focus:outline-none focus:ring-2 focus:ring-indigo-500 p-3 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                                            >
                                                <div className="space-y-0.5 min-w-0">
                                                    <div className="flex flex-wrap items-center gap-2">
                                                        <span className="text-xs font-bold text-slate-100">
                                                            {u.userName || 'Unknown'}
                                                        </span>
                                                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-white/[0.06] text-indigo-300 border border-white/10">
                                                            {u.provider}
                                                            {u.serverId ? ` · ${u.serverId}` : ''} · ID: {u.userId}
                                                        </span>
                                                    </div>
                                                    <p className="text-xs text-slate-400">
                                                        {u.distinctItems.toLocaleString()} distinct items &middot; DirectPlay:{' '}
                                                        {u.directPlayCount} &middot; DirectStream:{' '}
                                                        {u.directStreamCount} &middot; Transcode:{' '}
                                                        {u.transcodeCount}
                                                        {u.unknownMethodCount > 0
                                                            ? ` · Unknown Method: ${u.unknownMethodCount}`
                                                            : ''}
                                                    </p>
                                                </div>

                                                <div className="flex items-center gap-3 shrink-0 font-mono text-xs">
                                                    <span className="text-white font-bold">
                                                        {u.playCount.toLocaleString()} plays ({u.percentageOfPlays.toFixed(1)}%)
                                                    </span>
                                                    <span className="text-emerald-300">
                                                        {formatHistoryDuration(u.watchTimeSecs)}
                                                    </span>
                                                    <span className="text-teal-300">
                                                        {formatHistoryBytes(u.estimatedBytes, 1)}
                                                    </span>
                                                    <ArrowUpRight size={14} className="text-indigo-400" />
                                                </div>
                                            </button>
                                        );
                                    })}
                                </div>
                            )}
                        </div>
                    )}

                    {/* 4B. CLIENTS & DEVICES DRILLDOWN */}
                    {activeTab === 'clients' && (
                        <div data-testid="drilldown-panel-clients" className="space-y-3">
                            {drilldownData.clients.length >= topLimit && (
                                <div
                                    data-testid="clients-truncation-notice"
                                    className="px-3 py-2 rounded-xl border border-amber-500/30 bg-amber-950/25 text-xs text-amber-200 flex items-center gap-2"
                                >
                                    <Info size={14} className="text-amber-400 shrink-0" />
                                    <span>
                                        Showing top <strong>{drilldownData.clients.length}</strong> client/device pairs (truncated to top {topLimit} limit).
                                    </span>
                                </div>
                            )}

                            {drilldownData.clients.length === 0 ? (
                                <div className="py-6 text-center text-xs text-slate-400">
                                    No client/device records in this cohort.
                                </div>
                            ) : (
                                <div className="max-h-80 overflow-y-auto pr-1 space-y-2">
                                    {drilldownData.clients.map((c, idx) => {
                                        const clientLabel =
                                            c.clientName && c.clientName.trim() !== ''
                                                ? c.clientName
                                                : 'Unknown';
                                        const deviceLabel =
                                            c.deviceName && c.deviceName.trim() !== ''
                                                ? c.deviceName
                                                : 'Unknown';
                                        return (
                                            <button
                                                key={`${c.provider ?? ''}::${c.serverId ?? ''}::${clientLabel}::${deviceLabel}::${idx}`}
                                                type="button"
                                                data-testid={`drilldown-client-btn-${idx}`}
                                                onClick={() =>
                                                    onDrilldown(
                                                        buildScopeFilterPatch(
                                                            {
                                                                client: clientLabel,
                                                                device: deviceLabel,
                                                            },
                                                            c.provider,
                                                            c.serverId
                                                        )
                                                    )
                                                }
                                                className="w-full text-left rounded-xl border border-white/[0.06] bg-slate-950/70 hover:bg-indigo-950/30 hover:border-indigo-500/40 focus:outline-none focus:ring-2 focus:ring-indigo-500 p-3 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                                            >
                                                <div className="space-y-0.5 min-w-0">
                                                    <div className="flex flex-wrap items-center gap-2">
                                                        <span className="text-xs font-bold text-slate-100">
                                                            {clientLabel}
                                                        </span>
                                                        <span className="text-xs text-slate-400">
                                                            on <strong className="text-slate-200">{deviceLabel}</strong>
                                                        </span>
                                                        {(c.provider || c.serverId) && (
                                                            <span className="text-xs font-mono px-2 py-0.5 rounded bg-white/[0.06] text-indigo-300 border border-white/10">
                                                                {c.provider || 'all'}
                                                                {c.serverId ? ` · ${c.serverId}` : ''}
                                                            </span>
                                                        )}
                                                    </div>
                                                    <p className="text-xs text-slate-400">
                                                        {c.distinctUsers.toLocaleString()} distinct user(s) &middot; DirectPlay:{' '}
                                                        {c.directPlayCount} &middot; DirectStream:{' '}
                                                        {c.directStreamCount} &middot; Transcode:{' '}
                                                        {c.transcodeCount}
                                                    </p>
                                                </div>

                                                <div className="flex items-center gap-3 shrink-0 font-mono text-xs">
                                                    <span className="text-white font-bold">
                                                        {c.playCount.toLocaleString()} plays ({c.percentageOfPlays.toFixed(1)}%)
                                                    </span>
                                                    <span className="text-emerald-300">
                                                        {formatHistoryDuration(c.watchTimeSecs)}
                                                    </span>
                                                    <span className="text-teal-300">
                                                        {formatHistoryBytes(c.estimatedBytes, 1)}
                                                    </span>
                                                    <ArrowUpRight size={14} className="text-indigo-400" />
                                                </div>
                                            </button>
                                        );
                                    })}
                                </div>
                            )}
                        </div>
                    )}

                    {/* 4C. ITEMS DRILLDOWN */}
                    {activeTab === 'items' && (
                        <div data-testid="drilldown-panel-items" className="space-y-3">
                            {drilldownData.cohortDistinctItems > drilldownData.items.length && (
                                <div
                                    data-testid="items-truncation-notice"
                                    className="px-3 py-2 rounded-xl border border-amber-500/30 bg-amber-950/25 text-xs text-amber-200 flex items-center gap-2"
                                >
                                    <Info size={14} className="text-amber-400 shrink-0" />
                                    <span>
                                        Showing top <strong>{drilldownData.items.length}</strong> of{' '}
                                        <strong>{drilldownData.cohortDistinctItems.toLocaleString()}</strong> distinct media items in cohort (truncated to pageSize={topLimit}).
                                    </span>
                                </div>
                            )}

                            {drilldownData.items.length === 0 ? (
                                <div className="py-6 text-center text-xs text-slate-400">
                                    No confirmed media items in this cohort.
                                </div>
                            ) : (
                                <div className="max-h-80 overflow-y-auto pr-1 space-y-2">
                                    {drilldownData.items.map((item) => {
                                        const stableKey = `${item.provider}::${item.serverId ?? 'none'}::${item.itemId}`;
                                        return (
                                            <button
                                                key={stableKey}
                                                type="button"
                                                data-testid={`drilldown-item-btn-${item.provider}-${item.serverId || 'none'}-${item.itemId}`}
                                                onClick={() =>
                                                    onDrilldown(
                                                        buildScopeFilterPatch(
                                                            { itemId: item.itemId },
                                                            item.provider,
                                                            item.serverId
                                                        )
                                                    )
                                                }
                                                className="w-full text-left rounded-xl border border-white/[0.06] bg-slate-950/70 hover:bg-indigo-950/30 hover:border-indigo-500/40 focus:outline-none focus:ring-2 focus:ring-indigo-500 p-3 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                                            >
                                                <div className="space-y-0.5 min-w-0">
                                                    <div className="flex flex-wrap items-center gap-2">
                                                        <span className="text-xs font-bold text-slate-100">
                                                            {item.itemName || 'Unknown'}
                                                        </span>
                                                        {item.seriesName && (
                                                            <span className="text-xs text-slate-300">
                                                                ({item.seriesName})
                                                            </span>
                                                        )}
                                                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-white/[0.06] text-indigo-300 border border-white/10">
                                                            {item.provider}
                                                            {item.serverId ? ` · ${item.serverId}` : ''} · ID: {item.itemId}
                                                        </span>
                                                    </div>
                                                    <p className="text-xs text-slate-400">
                                                        Type: {item.itemType ?? 'Unknown'} &middot;{' '}
                                                        {item.distinctViewers.toLocaleString()} distinct viewer(s)
                                                    </p>
                                                </div>

                                                <div className="flex items-center gap-3 shrink-0 font-mono text-xs">
                                                    <span className="text-white font-bold">
                                                        {item.playCount.toLocaleString()} plays ({item.percentageOfPlays.toFixed(1)}%)
                                                    </span>
                                                    <span className="text-emerald-300">
                                                        {formatHistoryDuration(item.watchTimeSecs)}
                                                    </span>
                                                    <span className="text-teal-300">
                                                        {formatHistoryBytes(item.estimatedBytes, 1)}
                                                    </span>
                                                    <ArrowUpRight size={14} className="text-indigo-400" />
                                                </div>
                                            </button>
                                        );
                                    })}
                                </div>
                            )}
                        </div>
                    )}

                    {/* 4D. LIBRARIES DRILLDOWN (WITH OVERLAP & UNLABELED DISCLOSURE) */}
                    {activeTab === 'libraries' && (
                        <div data-testid="drilldown-panel-libraries" className="space-y-3">
                            <div
                                data-testid="library-label-metrics-banner"
                                className="px-3.5 py-2.5 rounded-xl border border-indigo-500/25 bg-indigo-950/20 text-xs text-indigo-100 flex flex-wrap items-center justify-between gap-2"
                            >
                                <div>
                                    <strong>Many-to-Many Library Labels:</strong> Cohort denominator is{' '}
                                    <strong className="font-mono">
                                        {drilldownData.libraryMetrics.cohortDistinctPlays.toLocaleString()}
                                    </strong>{' '}
                                    distinct plays; sum across library labels is{' '}
                                    <strong className="font-mono">
                                        {drilldownData.libraryMetrics.sumOfLabelPlays.toLocaleString()}
                                    </strong>{' '}
                                    label assignments
                                    {drilldownData.libraryMetrics.isOverlapping
                                        ? ' (overlapping multi-library items present; percentages can sum > 100%).'
                                        : '.'}
                                </div>
                                <span
                                    data-testid="library-unlabeled-count"
                                    className="font-mono px-2 py-0.5 rounded bg-white/[0.06] border border-white/10 text-slate-200"
                                >
                                    Unlabeled plays: {drilldownData.libraryMetrics.unlabeledPlays.toLocaleString()}
                                </span>
                            </div>

                            {drilldownData.libraries.length >= topLimit && (
                                <div
                                    data-testid="libraries-truncation-notice"
                                    className="px-3 py-2 rounded-xl border border-amber-500/30 bg-amber-950/25 text-xs text-amber-200 flex items-center gap-2"
                                >
                                    <Info size={14} className="text-amber-400 shrink-0" />
                                    <span>
                                        Showing top <strong>{drilldownData.libraries.length}</strong> libraries (truncated to top {topLimit} limit).
                                    </span>
                                </div>
                            )}

                            {drilldownData.libraries.length === 0 ? (
                                <div className="py-6 text-center text-xs text-slate-400">
                                    No labeled library plays in this cohort.
                                </div>
                            ) : (
                                <div className="max-h-80 overflow-y-auto pr-1 space-y-2">
                                    {drilldownData.libraries.map((lib) => {
                                        const stableKey = `${lib.provider ?? ''}::${lib.serverId ?? ''}::${lib.libraryId}`;
                                        return (
                                            <button
                                                key={stableKey}
                                                type="button"
                                                data-testid={`drilldown-library-btn-${lib.libraryId}`}
                                                onClick={() =>
                                                    onDrilldown(
                                                        buildScopeFilterPatch(
                                                            { libraryId: lib.libraryId },
                                                            lib.provider,
                                                            lib.serverId
                                                        )
                                                    )
                                                }
                                                className="w-full text-left rounded-xl border border-white/[0.06] bg-slate-950/70 hover:bg-indigo-950/30 hover:border-indigo-500/40 focus:outline-none focus:ring-2 focus:ring-indigo-500 p-3 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                                            >
                                                <div className="space-y-0.5 min-w-0">
                                                    <div className="flex flex-wrap items-center gap-2">
                                                        <span className="text-xs font-bold text-slate-100">
                                                            {lib.libraryName || lib.libraryId}
                                                        </span>
                                                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-white/[0.06] text-indigo-300 border border-white/10">
                                                            ID: {lib.libraryId}
                                                            {lib.provider ? ` · ${lib.provider}` : ''}
                                                            {lib.serverId ? ` · ${lib.serverId}` : ''}
                                                        </span>
                                                    </div>
                                                    <p className="text-xs text-slate-400">
                                                        {lib.distinctItems.toLocaleString()} distinct items &middot;{' '}
                                                        {lib.distinctViewers.toLocaleString()} distinct viewers
                                                    </p>
                                                </div>

                                                <div className="flex items-center gap-3 shrink-0 font-mono text-xs">
                                                    <span className="text-white font-bold">
                                                        {lib.playCount.toLocaleString()} plays ({lib.percentageOfPlays.toFixed(1)}%)
                                                    </span>
                                                    <span className="text-emerald-300">
                                                        {formatHistoryDuration(lib.watchTimeSecs)}
                                                    </span>
                                                    <span className="text-teal-300">
                                                        {formatHistoryBytes(lib.estimatedBytes, 1)}
                                                    </span>
                                                    <ArrowUpRight size={14} className="text-indigo-400" />
                                                </div>
                                            </button>
                                        );
                                    })}
                                </div>
                            )}
                        </div>
                    )}

                    {/* 4E. GENRES DRILLDOWN (WITH OVERLAP & UNLABELED DISCLOSURE) */}
                    {activeTab === 'genres' && (
                        <div data-testid="drilldown-panel-genres" className="space-y-3">
                            <div
                                data-testid="genre-label-metrics-banner"
                                className="px-3.5 py-2.5 rounded-xl border border-indigo-500/25 bg-indigo-950/20 text-xs text-indigo-100 flex flex-wrap items-center justify-between gap-2"
                            >
                                <div>
                                    <strong>Many-to-Many Genre Labels:</strong> Cohort denominator is{' '}
                                    <strong className="font-mono">
                                        {drilldownData.genreMetrics.cohortDistinctPlays.toLocaleString()}
                                    </strong>{' '}
                                    distinct plays; sum across genre labels is{' '}
                                    <strong className="font-mono">
                                        {drilldownData.genreMetrics.sumOfLabelPlays.toLocaleString()}
                                    </strong>{' '}
                                    label assignments
                                    {drilldownData.genreMetrics.isOverlapping
                                        ? ' (overlapping multi-genre items present; percentages can sum > 100%).'
                                        : '.'}
                                </div>
                                <span
                                    data-testid="genre-unlabeled-count"
                                    className="font-mono px-2 py-0.5 rounded bg-white/[0.06] border border-white/10 text-slate-200"
                                >
                                    Unlabeled plays: {drilldownData.genreMetrics.unlabeledPlays.toLocaleString()}
                                </span>
                            </div>

                            {drilldownData.genres.length >= topLimit && (
                                <div
                                    data-testid="genres-truncation-notice"
                                    className="px-3 py-2 rounded-xl border border-amber-500/30 bg-amber-950/25 text-xs text-amber-200 flex items-center gap-2"
                                >
                                    <Info size={14} className="text-amber-400 shrink-0" />
                                    <span>
                                        Showing top <strong>{drilldownData.genres.length}</strong> genres (truncated to top {topLimit} limit).
                                    </span>
                                </div>
                            )}

                            {drilldownData.genres.length === 0 ? (
                                <div className="py-6 text-center text-xs text-slate-400">
                                    No labeled genre plays in this cohort.
                                </div>
                            ) : (
                                <div className="max-h-80 overflow-y-auto pr-1 space-y-2">
                                    {drilldownData.genres.map((g) => {
                                        const stableKey = `${g.provider ?? ''}::${g.serverId ?? ''}::${g.genre}`;
                                        return (
                                            <button
                                                key={stableKey}
                                                type="button"
                                                data-testid={`drilldown-genre-btn-${g.genre}`}
                                                onClick={() =>
                                                    onDrilldown(
                                                        buildScopeFilterPatch(
                                                            { genre: g.genre },
                                                            g.provider,
                                                            g.serverId
                                                        )
                                                    )
                                                }
                                                className="w-full text-left rounded-xl border border-white/[0.06] bg-slate-950/70 hover:bg-indigo-950/30 hover:border-indigo-500/40 focus:outline-none focus:ring-2 focus:ring-indigo-500 p-3 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                                            >
                                                <div className="space-y-0.5 min-w-0">
                                                    <div className="flex flex-wrap items-center gap-2">
                                                        <span className="text-xs font-bold text-slate-100">
                                                            {g.genre}
                                                        </span>
                                                        {(g.provider || g.serverId) && (
                                                            <span className="text-xs font-mono px-2 py-0.5 rounded bg-white/[0.06] text-indigo-300 border border-white/10">
                                                                {g.provider || 'all'}
                                                                {g.serverId ? ` · ${g.serverId}` : ''}
                                                            </span>
                                                        )}
                                                    </div>
                                                    <p className="text-xs text-slate-400">
                                                        {g.distinctItems.toLocaleString()} distinct items &middot;{' '}
                                                        {g.distinctViewers.toLocaleString()} distinct viewers
                                                    </p>
                                                </div>

                                                <div className="flex items-center gap-3 shrink-0 font-mono text-xs">
                                                    <span className="text-white font-bold">
                                                        {g.playCount.toLocaleString()} plays ({g.percentageOfPlays.toFixed(1)}%)
                                                    </span>
                                                    <span className="text-emerald-300">
                                                        {formatHistoryDuration(g.watchTimeSecs)}
                                                    </span>
                                                    <span className="text-teal-300">
                                                        {formatHistoryBytes(g.estimatedBytes, 1)}
                                                    </span>
                                                    <ArrowUpRight size={14} className="text-indigo-400" />
                                                </div>
                                            </button>
                                        );
                                    })}
                                </div>
                            )}
                        </div>
                    )}

                    {/* 4F. PROVIDERS & SERVERS DRILLDOWN */}
                    {activeTab === 'servers' && (
                        <div data-testid="drilldown-panel-servers" className="space-y-3">
                            {providerServerGroups.length === 0 ? (
                                <div className="py-6 text-center text-xs text-slate-400">
                                    No provider/server groups in this cohort.
                                </div>
                            ) : (
                                <div className="max-h-80 overflow-y-auto pr-1 space-y-2">
                                    {providerServerGroups.map((srv) => {
                                        const stableKey = `${srv.provider}::${srv.serverId ?? 'none'}`;
                                        return (
                                            <button
                                                key={stableKey}
                                                type="button"
                                                data-testid={`drilldown-server-btn-${srv.provider}-${srv.serverId || 'none'}`}
                                                onClick={() =>
                                                    onDrilldown(
                                                        buildScopeFilterPatch(
                                                            {},
                                                            srv.provider,
                                                            srv.serverId
                                                        )
                                                    )
                                                }
                                                className="w-full text-left rounded-xl border border-white/[0.06] bg-slate-950/70 hover:bg-indigo-950/30 hover:border-indigo-500/40 focus:outline-none focus:ring-2 focus:ring-indigo-500 p-3 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                                            >
                                                <div className="space-y-0.5 min-w-0">
                                                    <div className="flex flex-wrap items-center gap-2">
                                                        <span className="text-xs font-bold text-slate-100 uppercase">
                                                            {srv.provider}
                                                        </span>
                                                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-white/[0.06] text-indigo-300 border border-white/10">
                                                            Server ID: {srv.serverId || 'Unrecorded / Default'}
                                                        </span>
                                                    </div>
                                                    <p className="text-xs text-slate-400">
                                                        Filter explorer by provider <code>{srv.provider}</code>
                                                        {srv.serverId ? ` and server ${srv.serverId}` : ''}
                                                    </p>
                                                </div>

                                                <div className="flex items-center gap-3 shrink-0 font-mono text-xs">
                                                    <span className="text-white font-bold">
                                                        {srv.playCount.toLocaleString()} plays ({srv.percentageOfPlays.toFixed(1)}%)
                                                    </span>
                                                    <span className="text-emerald-300">
                                                        {formatHistoryDuration(srv.watchTimeSecs)}
                                                    </span>
                                                    <span className="text-teal-300">
                                                        {formatHistoryBytes(srv.estimatedBytes, 1)}
                                                    </span>
                                                    <ArrowUpRight size={14} className="text-indigo-400" />
                                                </div>
                                            </button>
                                        );
                                    })}
                                </div>
                            )}
                        </div>
                    )}
                </div>
            )}
        </section>
    );
}

export default StreamingInsights;
