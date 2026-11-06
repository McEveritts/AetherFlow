'use client';

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
    Clock,
    Search,
    Download,
    RefreshCw,
    ChevronLeft,
    ChevronRight,
    AlertCircle,
    AlertTriangle,
    ShieldCheck,
    SlidersHorizontal,
    RotateCcw,
    Loader2,
    FileSpreadsheet,
    CheckCircle2,
    Info,
    ArrowUpDown,
    Globe,
} from 'lucide-react';
import { apiFetch } from '@/lib/fetcher';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/contexts/ToastContext';
import StreamingInsights from '@/components/streaming/StreamingInsights';
import StreamingPortability from '@/components/streaming/StreamingPortability';
import StreamingHistoryAdmin from '@/components/streaming/StreamingHistoryAdmin';
import {
    CanonicalStreamingHistoryItem,
    HistoryProvenance,
    StreamingHistoryCounts,
    StreamingHistoryPage,
    StreamingHistoryQuery,
    streamingHistorySearchParams,
} from '@/lib/streaming-history';

export interface StreamingHistoryExplorerProps {
    initialQuery?: Partial<StreamingHistoryQuery>;
    searchDebounceMs?: number;
}

const VALID_WINDOWS: ReadonlyArray<NonNullable<StreamingHistoryQuery['window']>> = [
    'all',
    '7d',
    '30d',
    '90d',
    '365d',
    'today',
    'month',
    'year',
    'custom',
];

const VALID_PROVENANCES: ReadonlyArray<NonNullable<StreamingHistoryQuery['provenance']>> = [
    'all',
    'observed_session',
    'imported_event',
    'item_summary',
    'legacy_unverified',
];

const VALID_SORTS: ReadonlyArray<NonNullable<StreamingHistoryQuery['sort']>> = [
    'startedDesc',
    'startedAsc',
];

const URL_PARAM_MAP: ReadonlyArray<{
    urlKey: string;
    queryKey: keyof StreamingHistoryQuery;
}> = [
    { urlKey: 'sh_window', queryKey: 'window' },
    { urlKey: 'sh_from', queryKey: 'from' },
    { urlKey: 'sh_until', queryKey: 'until' },
    { urlKey: 'sh_tz', queryKey: 'timezone' },
    { urlKey: 'sh_provider', queryKey: 'provider' },
    { urlKey: 'sh_server', queryKey: 'serverId' },
    { urlKey: 'sh_user', queryKey: 'userId' },
    { urlKey: 'sh_client', queryKey: 'client' },
    { urlKey: 'sh_device', queryKey: 'device' },
    { urlKey: 'sh_item', queryKey: 'itemId' },
    { urlKey: 'sh_library', queryKey: 'libraryId' },
    { urlKey: 'sh_genre', queryKey: 'genre' },
    { urlKey: 'sh_media', queryKey: 'mediaType' },
    { urlKey: 'sh_method', queryKey: 'playMethod' },
    { urlKey: 'sh_prov', queryKey: 'provenance' },
    { urlKey: 'sh_q', queryKey: 'search' },
    { urlKey: 'sh_sort', queryKey: 'sort' },
    { urlKey: 'sh_size', queryKey: 'pageSize' },
    { urlKey: 'sh_excl', queryKey: 'includeExcluded' },
    { urlKey: 'sh_cursor', queryKey: 'cursor' },
];

const COMMON_TIMEZONES = [
    'UTC',
    'America/New_York',
    'America/Chicago',
    'America/Denver',
    'America/Los_Angeles',
    'Europe/London',
    'Europe/Berlin',
    'Europe/Paris',
    'Asia/Tokyo',
    'Asia/Singapore',
    'Australia/Sydney',
];

function isAbortError(error: unknown): boolean {
    if (!error || typeof error !== 'object') return false;
    const candidate = error as { name?: unknown; code?: unknown };
    return candidate.name === 'AbortError' || candidate.code === 'ABORT_ERR';
}

export function formatHistoryBytes(bytes: number | null | undefined, decimals = 2): string {
    if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) {
        return 'Unrecorded';
    }
    if (bytes <= 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
}

export function formatHistoryDuration(secs: number | null | undefined): string {
    if (secs === null || secs === undefined || !Number.isFinite(secs)) {
        return 'Unrecorded';
    }
    if (secs <= 0) return '0s';
    if (secs < 60) return `${Math.floor(secs)}s`;
    const hours = Math.floor(secs / 3600);
    const mins = Math.floor((secs % 3600) / 60);
    const remSecs = Math.floor(secs % 60);
    if (hours === 0) {
        return remSecs > 0 ? `${mins}m ${remSecs}s` : `${mins}m`;
    }
    if (hours < 24) {
        return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
    }
    const days = Math.floor(hours / 24);
    const remHours = hours % 24;
    return remHours > 0 ? `${days}d ${remHours}h` : `${days}d`;
}

export function getProvenanceMeta(provenance: HistoryProvenance): {
    label: string;
    badgeClass: string;
    description: string;
} {
    switch (provenance) {
        case 'observed_session':
            return {
                label: 'Observed Session',
                badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
                description: 'Confirmed live session observed by collector.',
            };
        case 'imported_event':
            return {
                label: 'Imported Event',
                badgeClass: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
                description: 'Confirmed upstream playback event with stable source ID.',
            };
        case 'item_summary':
            return {
                label: 'Item Summary',
                badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
                description: 'Item-level played state summary; not a complete session log.',
            };
        case 'legacy_unverified':
        default:
            return {
                label: 'Legacy Unverified',
                badgeClass: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
                description: 'Retained pre-contract record without verified session provenance.',
            };
    }
}

export function getTimestampCertaintyLabel(
    certainty: CanonicalStreamingHistoryItem['timestampCertainty']
): string {
    switch (certainty) {
        case 'observed':
            return 'Observed start';
        case 'source_event':
            return 'Upstream event time';
        case 'last_played':
            return 'Last-played summary';
        case 'unrecorded':
            return 'Unrecorded timestamp';
        case 'legacy_unverified':
        default:
            return 'Legacy timestamp (unverified)';
    }
}

export function getByteAccuracyMeta(
    accuracy: CanonicalStreamingHistoryItem['byteAccuracy'],
    estimatedBytes: number | null
): {
    valueLabel: string;
    badgeLabel: string;
    badgeClass: string;
    tooltip: string;
} {
    if (estimatedBytes === null || estimatedBytes === undefined || accuracy === 'unrecorded') {
        return {
            valueLabel: 'Unrecorded',
            badgeLabel: 'Unrecorded',
            badgeClass: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
            tooltip: 'Transfer bytes were not recorded for this entry; missing values remain null.',
        };
    }
    if (accuracy === 'legacy_unverified') {
        return {
            valueLabel: formatHistoryBytes(estimatedBytes, 2),
            badgeLabel: 'Estimated (Legacy)',
            badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
            tooltip: 'Retained legacy byte figure; estimate only, not a network interface measurement.',
        };
    }
    return {
        valueLabel: formatHistoryBytes(estimatedBytes, 2),
        badgeLabel: 'Estimated',
        badgeClass: 'bg-teal-500/15 text-teal-300 border-teal-500/30',
        tooltip: 'Estimated transfer from bitrate and playing duration; not measured network traffic.',
    };
}

export function parseInitialQueryFromUrl(
    searchString: string,
    defaults?: Partial<StreamingHistoryQuery>
): StreamingHistoryQuery {
    const params = new URLSearchParams(searchString);
    const rawWindow = params.get('sh_window') || params.get('historyWindow') || defaults?.window || 'all';
    const windowVal: NonNullable<StreamingHistoryQuery['window']> = VALID_WINDOWS.includes(
        rawWindow as NonNullable<StreamingHistoryQuery['window']>
    )
        ? (rawWindow as NonNullable<StreamingHistoryQuery['window']>)
        : 'all';

    const rawProv = params.get('sh_prov') || params.get('historyProvenance') || defaults?.provenance || 'all';
    const provenanceVal: NonNullable<StreamingHistoryQuery['provenance']> = VALID_PROVENANCES.includes(
        rawProv as NonNullable<StreamingHistoryQuery['provenance']>
    )
        ? (rawProv as NonNullable<StreamingHistoryQuery['provenance']>)
        : 'all';

    const rawSort = params.get('sh_sort') || params.get('historySort') || defaults?.sort || 'startedDesc';
    const sortVal: NonNullable<StreamingHistoryQuery['sort']> = VALID_SORTS.includes(
        rawSort as NonNullable<StreamingHistoryQuery['sort']>
    )
        ? (rawSort as NonNullable<StreamingHistoryQuery['sort']>)
        : 'startedDesc';

    const rawSize = Number(params.get('sh_size') || params.get('historyPageSize') || defaults?.pageSize || 50);
    const pageSizeVal =
        Number.isFinite(rawSize) && rawSize >= 1 && rawSize <= 200 ? Math.floor(rawSize) : 50;

    const rawExcl = params.get('sh_excl');
    const includeExcludedVal =
        rawExcl === 'true' || rawExcl === '1'
            ? true
            : rawExcl === 'false' || rawExcl === '0'
              ? false
              : Boolean(defaults?.includeExcluded);

    return {
        window: windowVal,
        from: params.get('sh_from') ?? defaults?.from ?? '',
        until: params.get('sh_until') ?? defaults?.until ?? '',
        timezone: params.get('sh_tz') || defaults?.timezone || 'UTC',
        provider: params.get('sh_provider') ?? defaults?.provider ?? '',
        serverId: params.get('sh_server') ?? defaults?.serverId ?? '',
        userId: params.get('sh_user') ?? defaults?.userId ?? '',
        client: params.get('sh_client') ?? defaults?.client ?? '',
        device: params.get('sh_device') ?? defaults?.device ?? '',
        itemId: params.get('sh_item') ?? defaults?.itemId ?? '',
        libraryId: params.get('sh_library') ?? defaults?.libraryId ?? '',
        genre: params.get('sh_genre') ?? defaults?.genre ?? '',
        mediaType: params.get('sh_media') ?? defaults?.mediaType ?? '',
        playMethod: params.get('sh_method') ?? defaults?.playMethod ?? '',
        provenance: provenanceVal,
        search: params.get('sh_q') ?? defaults?.search ?? '',
        sort: sortVal,
        pageSize: pageSizeVal,
        includeExcluded: includeExcludedVal,
        cursor: defaults?.cursor || undefined,
    };
}

export function buildCanonicalHistoryRequestQuery(
    state: StreamingHistoryQuery,
    isAdmin: boolean
): StreamingHistoryQuery {
    const query: StreamingHistoryQuery = {
        window: state.window || 'all',
        timezone: (state.timezone || 'UTC').trim() || 'UTC',
        sort: state.sort || 'startedDesc',
        pageSize: state.pageSize || 50,
    };

    if (query.window === 'custom') {
        if (state.from && state.from.trim()) query.from = state.from.trim();
        if (state.until && state.until.trim()) query.until = state.until.trim();
    }

    const optionalTextFields: ReadonlyArray<
        | 'provider'
        | 'serverId'
        | 'userId'
        | 'client'
        | 'device'
        | 'itemId'
        | 'libraryId'
        | 'genre'
        | 'mediaType'
        | 'playMethod'
    > = [
        'provider',
        'serverId',
        'userId',
        'client',
        'device',
        'itemId',
        'libraryId',
        'genre',
        'mediaType',
        'playMethod',
    ];

    for (const field of optionalTextFields) {
        const val = state[field];
        if (typeof val === 'string' && val.trim() !== '' && val.trim() !== 'all') {
            query[field] = val.trim();
        }
    }

    if (state.provenance && state.provenance !== 'all') {
        query.provenance = state.provenance;
    }

    if (typeof state.search === 'string' && state.search.trim() !== '') {
        query.search = state.search.trim();
    }

    if (isAdmin && state.includeExcluded) {
        query.includeExcluded = true;
    }

    if (typeof state.cursor === 'string' && state.cursor.trim() !== '') {
        query.cursor = state.cursor.trim();
    }

    return query;
}

export function buildExportHistoryRequestQuery(
    requestQuery: StreamingHistoryQuery,
    snapshotToken?: string | null
): StreamingHistoryQuery {
    const exportQuery: StreamingHistoryQuery = { ...requestQuery };
    delete exportQuery.cursor;
    if (snapshotToken && snapshotToken.trim() !== '') {
        exportQuery.snapshot = snapshotToken.trim();
    }
    return exportQuery;
}

export function syncHistoryStateToWindowUrl(
    state: StreamingHistoryQuery,
    isAdmin: boolean
): void {
    if (typeof window === 'undefined' || !window.history?.replaceState) return;

    const params = new URLSearchParams(window.location.search);
    for (const { urlKey } of URL_PARAM_MAP) {
        params.delete(urlKey);
    }

    if (state.window && state.window !== 'all') {
        params.set('sh_window', state.window);
    }
    if (state.window === 'custom') {
        if (state.from?.trim()) params.set('sh_from', state.from.trim());
        if (state.until?.trim()) params.set('sh_until', state.until.trim());
    }
    if (state.timezone && state.timezone.trim() !== '' && state.timezone.trim() !== 'UTC') {
        params.set('sh_tz', state.timezone.trim());
    }
    if (state.provider?.trim() && state.provider.trim() !== 'all') {
        params.set('sh_provider', state.provider.trim());
    }
    if (state.serverId?.trim()) params.set('sh_server', state.serverId.trim());
    if (state.userId?.trim()) params.set('sh_user', state.userId.trim());
    if (state.client?.trim()) params.set('sh_client', state.client.trim());
    if (state.device?.trim()) params.set('sh_device', state.device.trim());
    if (state.itemId?.trim()) params.set('sh_item', state.itemId.trim());
    if (state.libraryId?.trim()) params.set('sh_library', state.libraryId.trim());
    if (state.genre?.trim()) params.set('sh_genre', state.genre.trim());
    if (state.mediaType?.trim() && state.mediaType.trim() !== 'all') {
        params.set('sh_media', state.mediaType.trim());
    }
    if (state.playMethod?.trim() && state.playMethod.trim() !== 'all') {
        params.set('sh_method', state.playMethod.trim());
    }
    if (state.provenance && state.provenance !== 'all') {
        params.set('sh_prov', state.provenance);
    }
    if (state.search?.trim()) {
        params.set('sh_q', state.search.trim());
    }
    if (state.sort && state.sort !== 'startedDesc') {
        params.set('sh_sort', state.sort);
    }
    if (state.pageSize && state.pageSize !== 50) {
        params.set('sh_size', String(state.pageSize));
    }
    if (isAdmin && state.includeExcluded) {
        params.set('sh_excl', 'true');
    }
    const nextQueryString = params.toString();
    const nextUrl = `${window.location.pathname}${nextQueryString ? `?${nextQueryString}` : ''}${window.location.hash || ''}`;
    const currentUrl = `${window.location.pathname}${window.location.search}${window.location.hash || ''}`;
    if (nextUrl !== currentUrl) {
        window.history.replaceState(window.history.state, '', nextUrl);
    }
}

async function extractResponseErrorMessage(res: Response, fallback: string): Promise<string> {
    try {
        const text = await res.text();
        if (!text.trim()) return `${fallback} (HTTP ${res.status})`;
        try {
            const parsed = JSON.parse(text) as { message?: string; error?: string; code?: string };
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
        // ignore body read errors
    }
    return `${fallback} (HTTP ${res.status})`;
}

function parseFilenameFromContentDisposition(header: string | null): string | null {
    if (!header) return null;
    const utf8Match = header.match(/filename\*=UTF-8''([^;]+)/i);
    if (utf8Match?.[1]) {
        try {
            return decodeURIComponent(utf8Match[1].trim().replace(/^"(.*)"$/, '$1'));
        } catch {
            // fallback to standard filename
        }
    }
    const basicMatch = header.match(/filename="?([^";]+)"?/i);
    if (basicMatch?.[1]) {
        return basicMatch[1].trim();
    }
    return null;
}

export function StreamingHistoryExplorer({
    initialQuery,
    searchDebounceMs = 300,
}: StreamingHistoryExplorerProps = {}) {
    const { user } = useAuth();
    const { addToast } = useToast();
    const isAdmin = user?.role === 'admin';

    const [queryState, setQueryState] = useState<StreamingHistoryQuery>(() =>
        parseInitialQueryFromUrl(
            typeof window !== 'undefined' ? window.location.search : '',
            initialQuery
        )
    );

    const [searchInput, setSearchInput] = useState<string>(() => queryState.search || '');
    const [cursorStack, setCursorStack] = useState<Array<string | undefined>>([]);
    const [showAdvancedFilters, setShowAdvancedFilters] = useState<boolean>(() =>
        Boolean(
            queryState.serverId ||
                queryState.userId ||
                queryState.client ||
                queryState.device ||
                queryState.itemId ||
                queryState.libraryId ||
                queryState.genre
        )
    );

    const [pageData, setPageData] = useState<StreamingHistoryPage | null>(null);
    const [isLoading, setIsLoading] = useState<boolean>(true);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [isConflict409, setIsConflict409] = useState<boolean>(false);
    const [isExporting, setIsExporting] = useState<boolean>(false);
    const [exportErrorMessage, setExportErrorMessage] = useState<string | null>(null);
    const [reloadTrigger, setReloadTrigger] = useState<number>(0);

    const requestGenRef = useRef<number>(0);
    const exportControllerRef = useRef<AbortController | null>(null);
    const drilldownOwnedRef = useRef<Partial<StreamingHistoryQuery>>({});

    useEffect(() => () => exportControllerRef.current?.abort(), []);

    // Debounce literal search input and reset cursor stack when search text changes
    useEffect(() => {
        if (searchInput === (queryState.search || '')) return;

        const timer = window.setTimeout(() => {
            setCursorStack([]);
            setQueryState((prev) => ({
                ...prev,
                search: searchInput,
                cursor: undefined,
            }));
        }, searchDebounceMs);

        return () => window.clearTimeout(timer);
    }, [searchInput, queryState.search, searchDebounceMs]);

    // Update filter helper: resets cursor and cursor stack on any filter/sort/window/pageSize change
    const updateFilter = useCallback(
        <K extends keyof StreamingHistoryQuery>(key: K, value: StreamingHistoryQuery[K]) => {
            delete drilldownOwnedRef.current[key];
            setCursorStack([]);
            setQueryState((prev) => ({
                ...prev,
                [key]: value,
                cursor: undefined,
            }));
        },
        []
    );

    const handleResetFilters = useCallback(() => {
        drilldownOwnedRef.current = {};
        setSearchInput('');
        setCursorStack([]);
        setIsConflict409(false);
        setErrorMessage(null);
        setExportErrorMessage(null);
        setQueryState({
            window: 'all',
            from: '',
            until: '',
            timezone: 'UTC',
            provider: '',
            serverId: '',
            userId: '',
            client: '',
            device: '',
            itemId: '',
            libraryId: '',
            genre: '',
            mediaType: '',
            playMethod: '',
            provenance: 'all',
            search: '',
            sort: 'startedDesc',
            pageSize: 50,
            includeExcluded: false,
            cursor: undefined,
        });
    }, []);

    // Synchronize explorer query state to URL without clobbering unrelated dashboard query/hash
    useEffect(() => {
        syncHistoryStateToWindowUrl(queryState, isAdmin);
    }, [queryState, isAdmin]);

    // Respond to browser back/forward navigation
    useEffect(() => {
        if (typeof window === 'undefined') return;
        const handlePopState = () => {
            const parsed = parseInitialQueryFromUrl(window.location.search, initialQuery);
            setSearchInput(parsed.search || '');
            setCursorStack([]);
            setQueryState(parsed);
        };
        window.addEventListener('popstate', handlePopState);
        return () => window.removeEventListener('popstate', handlePopState);
    }, [initialQuery]);

    const canonicalRequestQuery = useMemo(
        () => buildCanonicalHistoryRequestQuery(queryState, isAdmin),
        [queryState, isAdmin]
    );

    const customRangeIncomplete =
        canonicalRequestQuery.window === 'custom' &&
        (!canonicalRequestQuery.from || !canonicalRequestQuery.until);

    const customRangeValidationMessage = customRangeIncomplete
        ? 'Custom window requires both "From" and "Until" offset-bearing RFC3339 timestamps (e.g., 2026-10-01T00:00:00Z).'
        : null;

    useEffect(() => {
        if (customRangeIncomplete) {
            const generation = ++requestGenRef.current;
            void Promise.resolve().then(() => {
                if (generation !== requestGenRef.current) return;
                setIsLoading(false);
                setPageData(null);
                setIsConflict409(false);
                setErrorMessage(null);
            });
            return;
        }

        const controller = new AbortController();
        const gen = ++requestGenRef.current;

        const params = streamingHistorySearchParams(canonicalRequestQuery);
        const queryString = params.toString();
        const endpoint = `/api/v1/auth/streaming/history${queryString ? `?${queryString}` : ''}`;

        void (async () => {
            await Promise.resolve();
            if (controller.signal.aborted || gen !== requestGenRef.current) return;

            setIsLoading(true);
            setErrorMessage(null);
            setIsConflict409(false);

            try {
                const res = await apiFetch(endpoint, { signal: controller.signal });
                if (controller.signal.aborted || gen !== requestGenRef.current) return;

                if (res.status === 409) {
                    const msg = await extractResponseErrorMessage(
                        res,
                        'History snapshot was invalidated by new evidence, policy, or identity updates. Restart query from page 1.'
                    );
                    if (controller.signal.aborted || gen !== requestGenRef.current) return;
                    setIsConflict409(true);
                    setPageData(null);
                    setErrorMessage(msg);
                    return;
                }

                if (!res.ok) {
                    const msg = await extractResponseErrorMessage(
                        res,
                        'Failed to load streaming history'
                    );
                    if (controller.signal.aborted || gen !== requestGenRef.current) return;
                    setErrorMessage(msg);
                    return;
                }

                const payload = (await res.json()) as StreamingHistoryPage;
                if (controller.signal.aborted || gen !== requestGenRef.current) return;
                setPageData(payload);
            } catch (err: unknown) {
                if (controller.signal.aborted || isAbortError(err) || gen !== requestGenRef.current) {
                    return;
                }
                setErrorMessage(
                    err instanceof Error ? err.message : 'Unable to reach streaming history endpoint.'
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
    }, [canonicalRequestQuery, customRangeIncomplete, reloadTrigger]);

    const handleRestartQuery = useCallback(() => {
        exportControllerRef.current?.abort();
        setCursorStack([]);
        setIsConflict409(false);
        setErrorMessage(null);
        setExportErrorMessage(null);
        setQueryState((prev) => ({
            ...prev,
            cursor: undefined,
            snapshot: undefined,
        }));
        setReloadTrigger((n) => n + 1);
    }, []);

    const handleNextPage = useCallback(() => {
        const nextCursor = pageData?.nextCursor;
        if (!nextCursor || isLoading) return;
        setCursorStack((prev) => [...prev, queryState.cursor]);
        setQueryState((prev) => ({
            ...prev,
            cursor: nextCursor,
        }));
    }, [pageData, isLoading, queryState.cursor]);

    const handlePreviousPage = useCallback(() => {
        if (isLoading) return;
        if (cursorStack.length === 0) {
            if (queryState.cursor) {
                setQueryState((prev) => ({ ...prev, cursor: undefined }));
            }
            return;
        }
        const nextStack = [...cursorStack];
        const previousCursor = nextStack.pop();
        setCursorStack(nextStack);
        setQueryState((prev) => ({
            ...prev,
            cursor: previousCursor,
        }));
    }, [cursorStack, isLoading, queryState.cursor]);

    const handleExportFullQuery = useCallback(async () => {
        if (isExporting || customRangeIncomplete || isConflict409 || !pageData) return;
        const controller = new AbortController();
        exportControllerRef.current = controller;
        setIsExporting(true);
        setExportErrorMessage(null);

        try {
            const exportQuery = buildExportHistoryRequestQuery(
                canonicalRequestQuery,
                pageData?.scope?.snapshotToken
            );
            const params = streamingHistorySearchParams(exportQuery);
            const queryString = params.toString();
            const exportUrl = `/api/v1/auth/streaming/history/export${queryString ? `?${queryString}` : ''}`;

            const res = await apiFetch(exportUrl, {
                signal: controller.signal,
                headers: {
                    Accept: 'text/csv, application/vnd.aetherflow.v1+json;q=0.9, */*;q=0.8',
                },
            });

            if (res.status === 409) {
                const msg = await extractResponseErrorMessage(
                    res,
                    'Export snapshot expired or was invalidated (HTTP 409). Please restart the query and retry export.'
                );
                setIsConflict409(true);
                setExportErrorMessage(msg);
                addToast(msg, 'error');
                return;
            }

            if (!res.ok) {
                const msg = await extractResponseErrorMessage(
                    res,
                    'Failed to export streaming history CSV'
                );
                setExportErrorMessage(msg);
                addToast(msg, 'error');
                return;
            }

            // Stream or read the response body without pre-loading the archive into component state.
            // If mid-stream cancellation/timeout/mutation happens, reader.read() or res.blob() rejects
            // before any download link is triggered.
            const chunks: BlobPart[] = [];
            let byteCount = 0;
            if (res.body && typeof res.body.getReader === 'function') {
                const reader = res.body.getReader();
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    if (controller.signal.aborted) {
                        await reader.cancel();
                        return;
                    }
                    if (value) {
                        byteCount += value.byteLength;
                        if (byteCount > 128 * 1024 * 1024) {
                            await reader.cancel();
                            throw new Error('CSV exceeds the 128 MiB browser download limit. Narrow the query and retry.');
                        }
                        chunks.push(new Uint8Array(value));
                    }
                }
            } else {
                const fallbackBlob = await res.blob();
                if (fallbackBlob.size > 128 * 1024 * 1024) throw new Error('CSV exceeds the 128 MiB browser download limit.');
                chunks.push(fallbackBlob);
            }

            if (controller.signal.aborted) return;

            const blob = new Blob(chunks, { type: 'text/csv;charset=utf-8;' });
            const filename =
                parseFilenameFromContentDisposition(res.headers.get('Content-Disposition')) ||
                `aetherflow-streaming-history-${new Date().toISOString().slice(0, 10)}.csv`;

            if (typeof URL.createObjectURL === 'function') {
                const objectUrl = URL.createObjectURL(blob);
                try {
                    const anchor = document.createElement('a');
                    anchor.href = objectUrl;
                    anchor.download = filename;
                    anchor.style.display = 'none';
                    document.body.appendChild(anchor);
                    anchor.click();
                    document.body.removeChild(anchor);
                } finally {
                    if (typeof URL.revokeObjectURL === 'function') {
                        URL.revokeObjectURL(objectUrl);
                    }
                }
            }

            const matchingTotal = pageData?.counts?.matchingRecords;
            addToast(
                matchingTotal !== undefined
                    ? `Exported full matching cohort (${matchingTotal.toLocaleString()} records) to ${filename}.`
                    : `Exported streaming history CSV (${filename}).`,
                'success'
            );
        } catch (err: unknown) {
            if (controller.signal.aborted || isAbortError(err)) return;
            const msg =
                err instanceof Error
                    ? `CSV export interrupted: ${err.message}`
                    : 'CSV export failed before completion.';
            setExportErrorMessage(msg);
            addToast(msg, 'error');
        } finally {
            if (exportControllerRef.current === controller) exportControllerRef.current = null;
            setIsExporting(false);
        }
    }, [isExporting, isConflict409, customRangeIncomplete, canonicalRequestQuery, pageData, addToast]);

    const counts: StreamingHistoryCounts | null = pageData?.counts ?? null;
    const scope = pageData?.scope ?? null;
    const items: CanonicalStreamingHistoryItem[] = pageData?.items ?? [];

    const showAdminDeviceAndIpColumns =
        isAdmin && (scope?.permissionScope === 'administrative' || scope === null);

    const currentPageNumber = cursorStack.length + (queryState.cursor && cursorStack.length === 0 ? 2 : 1);
    const hasPreviousPage = cursorStack.length > 0 || Boolean(queryState.cursor);
    const hasNextPage = Boolean(pageData?.nextCursor);

    const isDatedWindow = Boolean(queryState.window && queryState.window !== 'all');

    return (
        <section
            aria-label="Streaming History Explorer"
            data-testid="streaming-history-explorer"
            className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5 space-y-5 w-full min-w-0"
        >
            {/* ===================================================================== */}
            {/* 1. HEADER, SCOPE DISCLOSURE & FULL-QUERY EXPORT                       */}
            {/* ===================================================================== */}
            <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-4 border-b border-white/[0.06]">
                <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2.5">
                        <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                            <Clock size={18} className="text-indigo-400 shrink-0" />
                            <span>Canonical Streaming History Explorer</span>
                        </h3>

                        <span
                            data-testid="history-counts-badge"
                            className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-white/[0.06] border border-white/10 text-slate-200"
                        >
                            {counts
                                ? `${counts.matchingRecords.toLocaleString()} matching of ${counts.availableRecords.toLocaleString()} available records`
                                : 'Loading archive counts...'}
                        </span>

                        {scope && (
                            <span
                                data-testid="history-permission-scope-badge"
                                className={`text-xs font-semibold px-2.5 py-0.5 rounded-full border inline-flex items-center gap-1.5 ${
                                    scope.permissionScope === 'administrative'
                                        ? 'bg-purple-500/15 text-purple-300 border-purple-500/30'
                                        : 'bg-sky-500/15 text-sky-300 border-sky-500/30'
                                }`}
                            >
                                <ShieldCheck size={12} />
                                <span>
                                    {scope.permissionScope === 'administrative'
                                        ? 'Administrative Scope'
                                        : 'Linked-User Scope'}
                                </span>
                            </span>
                        )}
                    </div>

                    <p className="text-xs text-slate-400">
                        Cursor-paginated archive explorer independent of the 5-second live stream poll. Only confirmed observed sessions and imported events count as confirmed plays, watch time, and estimated transfer.
                    </p>
                </div>

                <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <button
                        type="button"
                        onClick={() => setShowAdvancedFilters((prev) => !prev)}
                        aria-expanded={showAdvancedFilters}
                        data-testid="toggle-advanced-filters-btn"
                        className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-slate-200 flex items-center gap-1.5 transition-all"
                    >
                        <SlidersHorizontal size={13} className="text-indigo-400" />
                        <span>{showAdvancedFilters ? 'Hide Facet Filters' : 'More Facet Filters'}</span>
                    </button>

                    <button
                        type="button"
                        onClick={handleResetFilters}
                        data-testid="reset-history-filters-btn"
                        className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-slate-300 flex items-center gap-1.5 transition-all"
                    >
                        <RotateCcw size={13} />
                        <span>Reset Filters</span>
                    </button>

                    <button
                        type="button"
                        onClick={handleRestartQuery}
                        disabled={isLoading}
                        aria-label="Refresh history snapshot"
                        data-testid="refresh-history-snapshot-btn"
                        className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] hover:bg-white/[0.08] disabled:opacity-50 border border-white/10 text-slate-200 flex items-center gap-1.5 transition-all"
                    >
                        <RefreshCw size={13} className={isLoading ? 'animate-spin text-indigo-400' : ''} />
                        <span>Refresh Snapshot</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => void handleExportFullQuery()}
                        disabled={
                            isExporting ||
                            isConflict409 ||
                            isLoading ||
                            pageData === null ||
                            customRangeIncomplete ||
                            (counts !== null && counts.matchingRecords === 0)
                        }
                        data-testid="export-full-history-btn"
                        aria-label="Export full matching query to CSV"
                        title="Streams the complete filtered cohort from GET /api/v1/auth/streaming/history/export at the active snapshot token (not just the current page)"
                        className="px-3.5 py-1.5 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white shadow-md shadow-indigo-500/20 flex items-center gap-1.5 transition-all"
                    >
                        {isExporting ? (
                            <Loader2 size={13} className="animate-spin" />
                        ) : (
                            <Download size={13} />
                        )}
                        <span>
                            {isExporting
                                ? 'Exporting CSV...'
                                : counts
                                  ? `Export Full Query CSV (${counts.matchingRecords.toLocaleString()})`
                                  : 'Export Full Query CSV'}
                        </span>
                    </button>
                </div>
            </div>

            {/* ===================================================================== */}
            {/* 2. NON-ADMIN LINKED USER & PROVENANCE / UNDATED HONEST DISCLOSURES    */}
            {/* ===================================================================== */}
            {(!isAdmin || scope?.permissionScope === 'linked_user') && (
                <div
                    data-testid="linked-user-scope-notice"
                    className="px-3.5 py-2.5 rounded-xl border border-sky-500/25 bg-sky-950/25 text-xs text-sky-200 flex items-start gap-2.5"
                >
                    <Info size={15} className="text-sky-400 shrink-0 mt-0.5" />
                    <div>
                        <strong className="font-bold">Linked Provider Account Scope:</strong> Non-admin history contains only media provider accounts explicitly linked to your AetherFlow user in{' '}
                        <code className="font-mono text-sky-100">streaming_user_links</code> (never guessed from display names). If no provider user is linked, 0 available records are returned. IP addresses, device IDs, and policy-excluded raw records are omitted.
                    </div>
                </div>
            )}

            {/* ===================================================================== */}
            {/* 3. COHORT METRICS STRIP (CONFIRMED VS SUMMARIES VS LEGACY VS UNDATED) */}
            {/* ===================================================================== */}
            {counts && (
                <div
                    data-testid="history-cohort-summary-grid"
                    className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3"
                >
                    {/* Matching vs Available */}
                    <div className="rounded-xl border border-white/[0.06] bg-black/30 p-3">
                        <span className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
                            Filtered Cohort
                        </span>
                        <div className="mt-1 flex items-baseline gap-1.5">
                            <span
                                data-testid="summary-matching-records"
                                className="text-lg font-extrabold text-white tabular-nums"
                            >
                                {counts.matchingRecords.toLocaleString()}
                            </span>
                            <span className="text-xs text-slate-400">
                                of{' '}
                                <strong
                                    data-testid="summary-available-records"
                                    className="text-slate-200 tabular-nums"
                                >
                                    {counts.availableRecords.toLocaleString()}
                                </strong>{' '}
                                available
                            </span>
                        </div>
                        <p className="text-xs text-slate-500 mt-1">
                            Complete matching query across archive (loaded {items.length} on this page)
                        </p>
                    </div>

                    {/* Confirmed Plays & Watch Time */}
                    <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/15 p-3">
                        <div className="flex items-center justify-between">
                            <span className="text-xs font-bold uppercase tracking-wider text-emerald-300">
                                Confirmed Plays
                            </span>
                            <CheckCircle2 size={13} className="text-emerald-400" />
                        </div>
                        <div className="mt-1 flex items-baseline gap-2">
                            <span
                                data-testid="summary-confirmed-plays"
                                className="text-lg font-extrabold text-emerald-200 tabular-nums"
                            >
                                {counts.confirmedPlays.toLocaleString()}
                            </span>
                            <span
                                data-testid="summary-watch-time"
                                className="text-xs font-mono text-emerald-300/90"
                            >
                                {formatHistoryDuration(counts.watchTimeSecs)}
                            </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">
                            Included <code className="font-mono">observed_session</code> +{' '}
                            <code className="font-mono">imported_event</code> only. Watch time sums recorded durations; missing durations are not measured zeroes.
                        </p>
                    </div>

                    {/* Estimated Transfer */}
                    <div className="rounded-xl border border-teal-500/20 bg-teal-950/15 p-3">
                        <div className="flex items-center justify-between">
                            <span className="text-xs font-bold uppercase tracking-wider text-teal-300">
                                Estimated Transfer
                            </span>
                            <span className="text-xs font-semibold px-1.5 py-0.2 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">
                                Estimated
                            </span>
                        </div>
                        <div className="mt-1 flex items-baseline gap-2">
                            <span
                                data-testid="summary-estimated-bytes"
                                className="text-lg font-extrabold text-teal-200 tabular-nums"
                            >
                                {formatHistoryBytes(counts.estimatedBytes, 2)}
                            </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">
                            Bitrate &times; duration estimate, not measured network interface traffic
                        </p>
                    </div>

                    {/* Item Summaries & Legacy Unverified */}
                    <div className="rounded-xl border border-amber-500/20 bg-amber-950/15 p-3">
                        <span className="text-xs font-bold uppercase tracking-wider text-amber-300 block">
                            Summaries &amp; Legacy
                        </span>
                        <div className="mt-1 flex items-baseline gap-3 text-xs">
                            <div>
                                <span
                                    data-testid="summary-item-summaries"
                                    className="text-base font-extrabold text-amber-200 tabular-nums"
                                >
                                    {counts.itemSummaries.toLocaleString()}
                                </span>{' '}
                                <span className="text-slate-300">summaries</span>
                            </div>
                            <div>
                                <span
                                    data-testid="summary-legacy-records"
                                    className="text-base font-extrabold text-slate-200 tabular-nums"
                                >
                                    {counts.legacyRecords.toLocaleString()}
                                </span>{' '}
                                <span className="text-slate-400">legacy</span>
                            </div>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">
                            Separately inspectable; excluded from confirmed play totals
                        </p>
                    </div>

                    {/* Undated Records */}
                    <div className="rounded-xl border border-white/[0.06] bg-black/30 p-3">
                        <span className="text-xs font-bold uppercase tracking-wider text-slate-300 block">
                            Undated Records
                        </span>
                        <div className="mt-1 flex items-baseline gap-2">
                            <span
                                data-testid="summary-undated-records"
                                className="text-lg font-extrabold text-slate-200 tabular-nums"
                            >
                                {counts.undatedRecords.toLocaleString()}
                            </span>
                            <span className="text-xs text-slate-400">
                                {isDatedWindow ? 'excluded in dated window' : 'retained in All Time'}
                            </span>
                        </div>
                        <p className="text-xs text-slate-500 mt-1">
                            {isDatedWindow
                                ? 'Switch window to "All Time" to inspect undated rows (ordered last).'
                                : 'Undated rows sort after dated rows in both ascending and descending order.'}
                        </p>
                    </div>
                </div>
            )}

            {/* ===================================================================== */}
            {/* 4. PRIMARY FILTER BAR (WINDOW, TIMEZONE, PROVENANCE, SEARCH, SORT)    */}
            {/* ===================================================================== */}
            <div className="rounded-xl border border-white/[0.06] bg-black/30 p-3.5 space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3">
                    {/* Window */}
                    <div>
                        <label
                            htmlFor="sh-window-select"
                            className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1"
                        >
                            Time Window
                        </label>
                        <select
                            id="sh-window-select"
                            value={queryState.window || 'all'}
                            onChange={(e) =>
                                updateFilter(
                                    'window',
                                    e.target.value as NonNullable<StreamingHistoryQuery['window']>
                                )
                            }
                            className="w-full px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                        >
                            <option value="all">All Time (includes undated)</option>
                            <option value="7d">Last 7 Days (rolling)</option>
                            <option value="30d">Last 30 Days (rolling)</option>
                            <option value="90d">Last 90 Days (rolling)</option>
                            <option value="365d">Last 365 Days (rolling)</option>
                            <option value="today">Today (calendar)</option>
                            <option value="month">This Month (calendar)</option>
                            <option value="year">This Year (calendar)</option>
                            <option value="custom">Custom Range [from, until)</option>
                        </select>
                    </div>

                    {/* IANA Timezone */}
                    <div>
                        <label
                            htmlFor="sh-timezone-input"
                            className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1 flex items-center gap-1"
                        >
                            <Globe size={11} className="text-indigo-400" />
                            <span>IANA Timezone</span>
                        </label>
                        <input
                            id="sh-timezone-input"
                            type="text"
                            list="sh-timezone-datalist"
                            value={queryState.timezone ?? 'UTC'}
                            onChange={(e) => updateFilter('timezone', e.target.value)}
                            placeholder="UTC or America/New_York"
                            className="w-full px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 font-mono focus:outline-none focus:border-indigo-500"
                        />
                        <datalist id="sh-timezone-datalist">
                            {COMMON_TIMEZONES.map((tz) => (
                                <option key={tz} value={tz} />
                            ))}
                        </datalist>
                    </div>

                    {/* Provenance */}
                    <div>
                        <label
                            htmlFor="sh-provenance-select"
                            className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1"
                        >
                            Record Provenance
                        </label>
                        <select
                            id="sh-provenance-select"
                            value={queryState.provenance || 'all'}
                            onChange={(e) =>
                                updateFilter(
                                    'provenance',
                                    e.target.value as NonNullable<StreamingHistoryQuery['provenance']>
                                )
                            }
                            className="w-full px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                        >
                            <option value="all">All Provenances</option>
                            <option value="observed_session">Observed Session (Confirmed)</option>
                            <option value="imported_event">Imported Event (Confirmed)</option>
                            <option value="item_summary">Item Summary (Last-Played)</option>
                            <option value="legacy_unverified">Legacy Unverified</option>
                        </select>
                    </div>

                    {/* Play Method */}
                    <div>
                        <label
                            htmlFor="sh-play-method-select"
                            className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1"
                        >
                            Play Method
                        </label>
                        <select
                            id="sh-play-method-select"
                            value={queryState.playMethod || ''}
                            onChange={(e) => updateFilter('playMethod', e.target.value)}
                            className="w-full px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                        >
                            <option value="">All Play Methods</option>
                            <option value="DirectPlay">Direct Play</option>
                            <option value="DirectStream">Direct Stream</option>
                            <option value="Transcode">Transcode</option>
                            <option value="Unknown">Unknown / Unrecorded</option>
                        </select>
                    </div>

                    {/* Media Type */}
                    <div>
                        <label
                            htmlFor="sh-media-type-select"
                            className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1"
                        >
                            Media Type
                        </label>
                        <select
                            id="sh-media-type-select"
                            value={queryState.mediaType || ''}
                            onChange={(e) => updateFilter('mediaType', e.target.value)}
                            className="w-full px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                        >
                            <option value="">All Media Types</option>
                            <option value="Movie">Movie</option>
                            <option value="Episode">Episode</option>
                            <option value="Audio">Audio</option>
                        </select>
                    </div>

                    {/* Provider */}
                    <div>
                        <label
                            htmlFor="sh-provider-select"
                            className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1"
                        >
                            Provider
                        </label>
                        <select
                            id="sh-provider-select"
                            value={queryState.provider || ''}
                            onChange={(e) => updateFilter('provider', e.target.value)}
                            className="w-full px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                        >
                            <option value="">All Providers</option>
                            <option value="jellyfin">Jellyfin</option>
                            <option value="plex">Plex</option>
                            <option value="emby">Emby</option>
                        </select>
                    </div>
                </div>

                {/* Custom Date Bounds [from, until) */}
                {queryState.window === 'custom' && (
                    <div
                        data-testid="custom-date-bounds-panel"
                        className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-white/[0.06]"
                    >
                        <div>
                            <label
                                htmlFor="sh-custom-from-input"
                                className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-1"
                            >
                                Custom From (RFC3339 inclusive start)
                            </label>
                            <input
                                id="sh-custom-from-input"
                                type="text"
                                value={queryState.from || ''}
                                onChange={(e) => updateFilter('from', e.target.value)}
                                placeholder="2026-10-01T00:00:00Z"
                                className="w-full px-3 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 font-mono focus:outline-none focus:border-indigo-500"
                            />
                        </div>
                        <div>
                            <label
                                htmlFor="sh-custom-until-input"
                                className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-1"
                            >
                                Custom Until (RFC3339 exclusive end)
                            </label>
                            <input
                                id="sh-custom-until-input"
                                type="text"
                                value={queryState.until || ''}
                                onChange={(e) => updateFilter('until', e.target.value)}
                                placeholder="2026-11-01T00:00:00Z"
                                className="w-full px-3 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 font-mono focus:outline-none focus:border-indigo-500"
                            />
                        </div>
                    </div>
                )}

                {/* Search, Sort, Page Size & Admin Include Excluded */}
                <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-3 pt-2 border-t border-white/[0.06]">
                    {/* Literal Debounced Search */}
                    <div className="flex-1 min-w-0">
                        <label
                            htmlFor="sh-search-input"
                            className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1"
                        >
                            Literal Archive Search (Title, Series, User, Client, Device)
                        </label>
                        <div className="relative">
                            <Search
                                size={14}
                                className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none"
                            />
                            <input
                                id="sh-search-input"
                                type="text"
                                value={searchInput}
                                onChange={(e) => setSearchInput(e.target.value)}
                                placeholder="Literal search (wildcards % and _ matched literally; IPs/device IDs/session keys not searchable)..."
                                className="w-full pl-9 pr-3 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
                            />
                        </div>
                    </div>

                    <div className="flex flex-wrap items-end gap-3 shrink-0">
                        {/* Sort Order */}
                        <div>
                            <label
                                htmlFor="sh-sort-select"
                                className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1 flex items-center gap-1"
                            >
                                <ArrowUpDown size={11} className="text-indigo-400" />
                                <span>Sort Order</span>
                            </label>
                            <select
                                id="sh-sort-select"
                                value={queryState.sort || 'startedDesc'}
                                onChange={(e) =>
                                    updateFilter(
                                        'sort',
                                        e.target.value as NonNullable<StreamingHistoryQuery['sort']>
                                    )
                                }
                                className="px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                            >
                                <option value="startedDesc">Newest Started First (undated last)</option>
                                <option value="startedAsc">Oldest Started First (undated last)</option>
                            </select>
                        </div>

                        {/* Page Size */}
                        <div>
                            <label
                                htmlFor="sh-page-size-select"
                                className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1"
                            >
                                Page Size
                            </label>
                            <select
                                id="sh-page-size-select"
                                value={queryState.pageSize || 50}
                                onChange={(e) =>
                                    updateFilter('pageSize', Number(e.target.value) || 50)
                                }
                                className="px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                            >
                                <option value={25}>25 / page</option>
                                <option value={50}>50 / page (default)</option>
                                <option value={100}>100 / page</option>
                                <option value={200}>200 / page (max)</option>
                            </select>
                        </div>

                        {/* Admin-Only Include Policy-Excluded Records */}
                        {isAdmin && (
                            <label
                                htmlFor="sh-include-excluded-checkbox"
                                className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-purple-500/10 border border-purple-500/30 text-xs font-semibold text-purple-200 cursor-pointer select-none"
                            >
                                <input
                                    id="sh-include-excluded-checkbox"
                                    type="checkbox"
                                    checked={Boolean(queryState.includeExcluded)}
                                    onChange={(e) =>
                                        updateFilter('includeExcluded', e.target.checked)
                                    }
                                    className="rounded border-purple-400/50 bg-slate-950 text-indigo-500 focus:ring-indigo-500"
                                />
                                <span>Include Policy-Excluded Raw Records</span>
                            </label>
                        )}
                    </div>
                </div>

                {/* Expandable Facet Filters (Server, User, Client, Device, Item, Library, Genre) */}
                {showAdvancedFilters && (
                    <div
                        data-testid="advanced-facet-filters-panel"
                        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-2.5 pt-3 border-t border-white/[0.06]"
                    >
                        <div>
                            <label
                                htmlFor="sh-server-id-input"
                                className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1"
                            >
                                Server ID
                            </label>
                            <input
                                id="sh-server-id-input"
                                type="text"
                                value={queryState.serverId || ''}
                                onChange={(e) => updateFilter('serverId', e.target.value)}
                                placeholder="e.g. jf-srv-01"
                                className="w-full px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 font-mono"
                            />
                        </div>
                        <div>
                            <label
                                htmlFor="sh-user-id-input"
                                className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1"
                            >
                                Provider User ID
                            </label>
                            <input
                                id="sh-user-id-input"
                                type="text"
                                value={queryState.userId || ''}
                                onChange={(e) => updateFilter('userId', e.target.value)}
                                placeholder="e.g. u-1"
                                className="w-full px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 font-mono"
                            />
                        </div>
                        <div>
                            <label
                                htmlFor="sh-client-input"
                                className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1"
                            >
                                Client Name
                            </label>
                            <input
                                id="sh-client-input"
                                type="text"
                                value={queryState.client || ''}
                                onChange={(e) => updateFilter('client', e.target.value)}
                                placeholder="e.g. Swiftfin iOS"
                                className="w-full px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100"
                            />
                        </div>
                        <div>
                            <label
                                htmlFor="sh-device-input"
                                className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1"
                            >
                                Device Name
                            </label>
                            <input
                                id="sh-device-input"
                                type="text"
                                value={queryState.device || ''}
                                onChange={(e) => updateFilter('device', e.target.value)}
                                placeholder="e.g. Apple TV"
                                className="w-full px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100"
                            />
                        </div>
                        <div>
                            <label
                                htmlFor="sh-item-id-input"
                                className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1"
                            >
                                Item ID
                            </label>
                            <input
                                id="sh-item-id-input"
                                type="text"
                                value={queryState.itemId || ''}
                                onChange={(e) => updateFilter('itemId', e.target.value)}
                                placeholder="e.g. item-42"
                                className="w-full px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 font-mono"
                            />
                        </div>
                        <div>
                            <label
                                htmlFor="sh-library-id-input"
                                className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1"
                            >
                                Library ID
                            </label>
                            <input
                                id="sh-library-id-input"
                                type="text"
                                value={queryState.libraryId || ''}
                                onChange={(e) => updateFilter('libraryId', e.target.value)}
                                placeholder="e.g. lib-movies"
                                className="w-full px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100 font-mono"
                            />
                        </div>
                        <div>
                            <label
                                htmlFor="sh-genre-input"
                                className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1"
                            >
                                Genre
                            </label>
                            <input
                                id="sh-genre-input"
                                type="text"
                                value={queryState.genre || ''}
                                onChange={(e) => updateFilter('genre', e.target.value)}
                                placeholder="e.g. Sci-Fi"
                                className="w-full px-2.5 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-slate-100"
                            />
                        </div>
                    </div>
                )}
            </div>

            {/* ===================================================================== */}
            {/* 5. SNAPSHOT INVALIDATION (409), FETCH ERROR & EXPORT ERROR BANNERS    */}
            {/* ===================================================================== */}
            {isConflict409 && (
                <div
                    role="alert"
                    data-testid="history-snapshot-conflict-banner"
                    className="rounded-xl border border-amber-500/40 bg-amber-950/35 p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3"
                >
                    <div className="flex items-start gap-3">
                        <AlertTriangle size={18} className="text-amber-400 shrink-0 mt-0.5" />
                        <div>
                            <h4 className="text-xs font-bold text-amber-200 uppercase tracking-wider">
                                Snapshot Invalidated or Expired (HTTP 409)
                            </h4>
                            <p className="text-xs text-amber-300/90 mt-0.5">
                                {errorMessage ||
                                    exportErrorMessage ||
                                    'Existing history evidence, policy status, or user links changed since this snapshot was opened. Restart the query from page 1 rather than appending stale pages.'}
                            </p>
                        </div>
                    </div>
                    <button
                        type="button"
                        onClick={handleRestartQuery}
                        data-testid="restart-query-409-btn"
                        className="px-3.5 py-1.5 rounded-xl text-xs font-bold bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-100 flex items-center gap-1.5 shrink-0 transition-all"
                    >
                        <RefreshCw size={13} />
                        <span>Restart Query from Page 1</span>
                    </button>
                </div>
            )}

            {(customRangeValidationMessage || (errorMessage && !isConflict409)) && (
                <div
                    role="alert"
                    data-testid="history-error-banner"
                    className="rounded-xl border border-rose-500/35 bg-rose-950/35 p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3"
                >
                    <div className="flex items-start gap-3">
                        <AlertCircle size={18} className="text-rose-400 shrink-0 mt-0.5" />
                        <div>
                            <h4 className="text-xs font-bold text-rose-200 uppercase tracking-wider">
                                {customRangeValidationMessage
                                    ? 'Custom Date Range Incomplete'
                                    : 'Streaming History Request Failed'}
                            </h4>
                            <p className="text-xs text-rose-300/90 mt-0.5">
                                {customRangeValidationMessage || errorMessage}
                            </p>
                        </div>
                    </div>
                    <button
                        type="button"
                        onClick={handleRestartQuery}
                        data-testid="retry-history-query-btn"
                        className="px-3.5 py-1.5 rounded-xl text-xs font-bold bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 flex items-center gap-1.5 shrink-0 transition-all"
                    >
                        <RefreshCw size={13} />
                        <span>Retry Query</span>
                    </button>
                </div>
            )}

            {exportErrorMessage && !isConflict409 && (
                <div
                    role="alert"
                    data-testid="history-export-error-banner"
                    className="rounded-xl border border-rose-500/35 bg-rose-950/30 p-3.5 flex items-center justify-between gap-3 text-xs text-rose-200"
                >
                    <div className="flex items-center gap-2">
                        <FileSpreadsheet size={15} className="text-rose-400 shrink-0" />
                        <span>{exportErrorMessage}</span>
                    </div>
                    <button
                        type="button"
                        onClick={() => setExportErrorMessage(null)}
                        className="px-2.5 py-1 rounded-lg bg-white/10 hover:bg-white/15 text-rose-100 font-semibold"
                    >
                        Dismiss
                    </button>
                </div>
            )}

            {/* ===================================================================== */}
            {/* 6. SCOPED OVERFLOW TABLE (KEYBOARD ACCESSIBLE)                        */}
            {/* ===================================================================== */}
            <div
                tabIndex={0}
                role="region"
                aria-label="Streaming history records table"
                className="overflow-x-auto rounded-xl border border-white/[0.06] bg-slate-950/40 focus:outline-none focus:ring-1 focus:ring-indigo-500/50"
            >
                <table className="w-full text-left border-collapse text-xs">
                    <thead>
                        <tr className="border-b border-white/[0.06] bg-white/[0.02] text-slate-400 uppercase tracking-wider text-xs">
                            <th scope="col" className="py-2.5 px-3 font-semibold">
                                Title &amp; Media
                            </th>
                            <th scope="col" className="py-2.5 px-3 font-semibold">
                                Provenance &amp; Policy
                            </th>
                            <th scope="col" className="py-2.5 px-3 font-semibold">
                                Timestamps &amp; Certainty
                            </th>
                            <th scope="col" className="py-2.5 px-3 font-semibold">
                                User &amp; Provider
                            </th>
                            <th scope="col" className="py-2.5 px-3 font-semibold">
                                Client &amp; Device
                            </th>
                            {showAdminDeviceAndIpColumns && (
                                <th
                                    scope="col"
                                    data-testid="admin-network-column-header"
                                    className="py-2.5 px-3 font-semibold"
                                >
                                    IP &amp; Device ID
                                </th>
                            )}
                            <th scope="col" className="py-2.5 px-3 font-semibold">
                                Play Method
                            </th>
                            <th scope="col" className="py-2.5 px-3 font-semibold">
                                Transfer &amp; Accuracy
                            </th>
                            <th scope="col" className="py-2.5 px-3 font-semibold">
                                Watched / Duration
                            </th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-white/[0.04]">
                        {isLoading && items.length === 0 ? (
                            <tr>
                                <td
                                    colSpan={showAdminDeviceAndIpColumns ? 9 : 8}
                                    data-testid="history-loading-state"
                                    className="py-12 text-center text-slate-400"
                                >
                                    <div className="inline-flex items-center gap-2">
                                        <Loader2 size={16} className="animate-spin text-indigo-400" />
                                        <span>Loading canonical streaming history...</span>
                                    </div>
                                </td>
                            </tr>
                        ) : items.length === 0 ? (
                            <tr>
                                <td
                                    colSpan={showAdminDeviceAndIpColumns ? 9 : 8}
                                    data-testid="history-empty-state"
                                    className="py-12 text-center text-slate-400 space-y-1"
                                >
                                    <p className="font-semibold text-slate-300">
                                        {counts && counts.availableRecords === 0
                                            ? !isAdmin || scope?.permissionScope === 'linked_user'
                                                ? 'No linked streaming history available for your account.'
                                                : 'No streaming history records exist in the archive yet.'
                                            : 'No streaming history records match the active filters.'}
                                    </p>
                                    {counts && counts.undatedRecords > 0 && isDatedWindow && (
                                        <p className="text-xs text-amber-300">
                                            {counts.undatedRecords.toLocaleString()} undated record(s) are excluded by the current dated window. Switch to &ldquo;All Time&rdquo; to inspect them.
                                        </p>
                                    )}
                                </td>
                            </tr>
                        ) : (
                            items.map((item) => {
                                const provMeta = getProvenanceMeta(item.provenance);
                                const certaintyLabel = getTimestampCertaintyLabel(
                                    item.timestampCertainty
                                );
                                const byteMeta = getByteAccuracyMeta(
                                    item.byteAccuracy,
                                    item.estimatedBytes
                                );

                                const primaryTimestamp =
                                    item.startedAt || item.endedAt || item.lastSeenAt || null;

                                return (
                                    <tr
                                        key={item.id}
                                        data-testid={`history-row-${item.id}`}
                                        className={`hover:bg-white/[0.02] transition-colors ${
                                            !item.included ? 'opacity-70 bg-rose-950/10' : ''
                                        }`}
                                    >
                                        {/* Title & Media */}
                                        <td className="py-3 px-3">
                                            <div className="flex items-start gap-2">
                                                {item.isActive && (
                                                    <span
                                                        className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse shrink-0 mt-1.5"
                                                        title="Active stream"
                                                    />
                                                )}
                                                <div>
                                                    <p className="font-bold text-slate-100">
                                                        {item.seriesName
                                                            ? `${item.seriesName} — ${item.itemName}`
                                                            : item.itemName}
                                                    </p>
                                                    <div className="flex flex-wrap items-center gap-1.5 mt-0.5 text-xs text-slate-400">
                                                        <span>
                                                            {item.itemType || 'Unknown media type'}
                                                        </span>
                                                        <span>&middot;</span>
                                                        <span className="font-mono text-slate-500">
                                                            ID #{item.id}
                                                        </span>
                                                        {item.genres && item.genres.length > 0 && (
                                                            <>
                                                                <span>&middot;</span>
                                                                <span>{item.genres.join(', ')}</span>
                                                            </>
                                                        )}
                                                    </div>
                                                </div>
                                            </div>
                                        </td>

                                        {/* Provenance & Policy */}
                                        <td className="py-3 px-3">
                                            <div className="flex flex-col items-start gap-1">
                                                <span
                                                    title={provMeta.description}
                                                    className={`text-xs font-bold px-2 py-0.5 rounded-full border ${provMeta.badgeClass}`}
                                                >
                                                    {provMeta.label}
                                                </span>
                                                <div className="flex items-center gap-1.5 text-xs">
                                                    {!item.included && (
                                                        <span className="px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold">
                                                            Excluded
                                                        </span>
                                                    )}
                                                    <span className="text-slate-400 font-mono">
                                                        {item.policyStatus || 'included'}
                                                    </span>
                                                </div>
                                            </div>
                                        </td>

                                        {/* Timestamps & Certainty */}
                                        <td className="py-3 px-3 whitespace-nowrap">
                                            {primaryTimestamp ? (
                                                <time
                                                    dateTime={primaryTimestamp}
                                                    className="font-mono text-slate-200 block"
                                                >
                                                    {primaryTimestamp}
                                                </time>
                                            ) : (
                                                <span className="italic text-amber-300 font-semibold block">
                                                    Undated (Unrecorded)
                                                </span>
                                            )}
                                            <span className="text-xs text-slate-400 block mt-0.5">
                                                {certaintyLabel}
                                            </span>
                                        </td>

                                        {/* User & Provider */}
                                        <td className="py-3 px-3">
                                            <p className="font-semibold text-slate-200">
                                                {item.userName || 'Unknown user'}
                                            </p>
                                            <p className="text-xs text-slate-400 font-mono">
                                                {item.provider} &middot; {item.serverId}
                                            </p>
                                        </td>

                                        {/* Client & Device */}
                                        <td className="py-3 px-3">
                                            <p className="text-slate-200">
                                                {item.clientName ?? 'Unknown client'}
                                            </p>
                                            <p className="text-xs text-slate-400">
                                                {item.deviceName ?? 'Unrecorded device'}
                                            </p>
                                        </td>

                                        {/* Admin-only IP & Device ID */}
                                        {showAdminDeviceAndIpColumns && (
                                            <td
                                                data-testid={`admin-network-cell-${item.id}`}
                                                className="py-3 px-3 font-mono text-xs"
                                            >
                                                <p className="text-slate-200">
                                                    {item.ipAddress ?? 'Unrecorded IP'}
                                                </p>
                                                <p className="text-slate-500">
                                                    {item.deviceId ?? 'Unrecorded device ID'}
                                                </p>
                                            </td>
                                        )}

                                        {/* Play Method */}
                                        <td className="py-3 px-3">
                                            <span className="px-2 py-0.5 rounded-full border border-white/10 bg-white/[0.04] text-slate-200 font-semibold">
                                                {item.playMethod ?? 'Unknown'}
                                            </span>
                                        </td>

                                        {/* Transfer & Byte Accuracy */}
                                        <td className="py-3 px-3">
                                            <div className="flex items-center gap-1.5 font-mono">
                                                <span className="text-teal-300 font-bold">
                                                    {byteMeta.valueLabel}
                                                </span>
                                                <span
                                                    title={byteMeta.tooltip}
                                                    className={`text-xs font-sans font-semibold px-1.5 py-0.2 rounded border ${byteMeta.badgeClass}`}
                                                >
                                                    {byteMeta.badgeLabel}
                                                </span>
                                            </div>
                                        </td>

                                        {/* Watched / Duration */}
                                        <td className="py-3 px-3 font-mono text-slate-200">
                                            <span>{formatHistoryDuration(item.watchedSecs)}</span>
                                            <span className="text-slate-500"> / </span>
                                            <span className="text-slate-400">
                                                {formatHistoryDuration(item.durationSecs)}
                                            </span>
                                        </td>
                                    </tr>
                                );
                            })
                        )}
                    </tbody>
                </table>
            </div>

            {/* ===================================================================== */}
            {/* 7. CURSOR PAGINATION FOOTER & SNAPSHOT METADATA                       */}
            {/* ===================================================================== */}
            <div className="pt-3 border-t border-white/[0.06] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs text-slate-400">
                <div className="space-y-0.5">
                    <div data-testid="pagination-status-text">
                        Page <strong className="text-slate-200">{currentPageNumber}</strong> &middot; Showing{' '}
                        <strong className="text-slate-200">{items.length}</strong> row(s) on this page
                        {counts
                            ? ` of ${counts.matchingRecords.toLocaleString()} matching (${counts.availableRecords.toLocaleString()} available in scope)`
                            : ''}
                    </div>
                    {scope && (
                        <div className="text-xs text-slate-500 font-mono">
                            Snapshot rev #{scope.revision} (watermark #{scope.watermark}) &middot; TZ:{' '}
                            {scope.timezone} &middot; {scope.dateSemantics}
                        </div>
                    )}
                </div>

                <div className="flex items-center gap-2 shrink-0">
                    <button
                        type="button"
                        onClick={handlePreviousPage}
                        disabled={!hasPreviousPage || isLoading}
                        data-testid="history-prev-page-btn"
                        aria-label="Previous history page"
                        className="px-3 py-1.5 rounded-xl bg-white/[0.05] hover:bg-white/[0.1] disabled:opacity-40 disabled:cursor-not-allowed border border-white/10 text-slate-200 font-semibold flex items-center gap-1 transition-all"
                    >
                        <ChevronLeft size={14} />
                        <span>Previous</span>
                    </button>
                    <button
                        type="button"
                        onClick={handleNextPage}
                        disabled={!hasNextPage || isLoading}
                        data-testid="history-next-page-btn"
                        aria-label="Next history page"
                        className="px-3 py-1.5 rounded-xl bg-white/[0.05] hover:bg-white/[0.1] disabled:opacity-40 disabled:cursor-not-allowed border border-white/10 text-slate-200 font-semibold flex items-center gap-1 transition-all"
                    >
                        <span>Next</span>
                        <ChevronRight size={14} />
                    </button>
                </div>
            </div>
            {scope && !isLoading && !isConflict409 && (
                <StreamingInsights
                    query={pageData?.query ?? canonicalRequestQuery}
                    snapshot={scope.snapshotToken}
                    onDrilldown={(filters) => {
                        setCursorStack([]);
                        setSearchInput('');
                        setShowAdvancedFilters(true);
                        const previousBase = drilldownOwnedRef.current;
                        const nextBase: Partial<StreamingHistoryQuery> = {};
                        for (const key of Object.keys(filters) as Array<keyof StreamingHistoryQuery>) {
                            Object.assign(nextBase, { [key]: key in previousBase ? previousBase[key] : queryState[key] });
                        }
                        drilldownOwnedRef.current = nextBase;
                        setQueryState((previous) => ({ ...previous, ...previousBase, search: '', ...filters, cursor: undefined, snapshot: undefined }));
                    }}
                />
            )}
            {isAdmin && <StreamingPortability onRestoreApplied={handleRestartQuery} />}
            {isAdmin && <StreamingHistoryAdmin onChanged={handleRestartQuery} />}
        </section>
    );
}

export default StreamingHistoryExplorer;
