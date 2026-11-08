'use client';

import React, { useState, useMemo, useRef, useSyncExternalStore } from 'react';
import useSWR from 'swr';
import StreamingHistoryExplorer from '@/components/streaming/StreamingHistoryExplorer';
import StreamingDialog from '@/components/streaming/StreamingDialog';
import StreamingImportedHistory, { StreamingHistoryEstimate } from '@/components/streaming/StreamingImportedHistory';
import {
    Tv,
    Play,
    Pause,
    Square,
    MessageSquare,
    RefreshCw,
    Settings2,
    Activity,
    HardDrive,
    Users,
    Film,
    Clock,
    Zap,
    Radio,
    CheckCircle2,
    AlertCircle,
    Sparkles,
    Search,
    Server,
    Trophy,
    Flame,
    Monitor,
    Wifi,
    Layers,
    X,
    Send,
    Loader2,
    ShieldCheck,
    Music,
    Database,
    Download,
    ChevronLeft,
    ChevronRight,
    ChevronDown
} from 'lucide-react';
import { computeDualLinearScales, formatStreamingAxisDateTick } from '@/components/streaming/streamingChartScales';
import {
    Area,
    Bar,
    ComposedChart,
    Line,
    XAxis,
    YAxis,
    Tooltip,
    ResponsiveContainer,
    CartesianGrid
} from 'recharts';
import { apiFetch, fetcher } from '@/lib/fetcher';
import { useToast } from '@/contexts/ToastContext';
import { useAuth } from '@/contexts/AuthContext';
import { triggerHaptic } from '@/lib/design';
import { useSystemStore } from '@/store/useSystemStore';
import {
    evaluateSessionCapabilities,
    recomputeLiveSummaryFromSessions,
    isHistoricalSyncEntry,
    normalizePlayMethodKind,
    downloadStreamingHistoryCsv,
    parseStreamingTimestamp,
} from '@/lib/streaming';

export interface StreamingLibraryCounts {
    movies: number;
    series: number;
    episodes: number;
    audio: number;
}

export interface StreamingServerStatus {
    provider: 'jellyfin' | 'plex' | 'emby';
    name: string;
    url: string;
    apiKeyMasked: string;
    configured: boolean;
    enabled: boolean;
    status: 'connected' | 'unreachable' | 'unavailable' | 'disabled' | 'unconfigured' | 'coming_soon' | 'demo';
    supportStage: 'active' | 'coming_soon';
    serverId: string;
    version: string;
    operatingSystem: string;
    lastConnectedAt: string;
    libraryCounts: StreamingLibraryCounts;
    errorMessage?: string;
}

export interface ActiveStreamSession {
    sessionId: string;
    provider: string;
    serverName: string;
    serverId?: string;
    userId: string;
    userName: string;
    clientName: string;
    deviceName: string;
    deviceId: string;
    appVersion: string;
    ipAddress: string;
    isLan: boolean;
    itemId: string;
    itemName: string;
    itemType: string;
    seriesName?: string;
    seriesId?: string;
    seasonNumber?: number;
    episodeNumber?: number;
    productionYear?: number;
    hasArtwork: boolean;
    artworkItemId?: string;
    state: 'playing' | 'paused';
    positionSecs: number;
    durationSecs: number;
    progressPct: number;
    playMethod: 'DirectPlay' | 'DirectStream' | 'Transcode';
    container: string;
    targetContainer?: string;
    videoCodec: string;
    targetVideoCodec?: string;
    videoResolution: string;
    videoRange: string;
    videoFramerate?: number;
    isVideoDirect: boolean;
    audioCodec: string;
    targetAudioCodec?: string;
    audioChannels: number;
    audioLayout: string;
    audioLanguage?: string;
    isAudioDirect: boolean;
    subtitleCodec?: string;
    subtitleLanguage?: string;
    hwAccel?: string;
    transcodeReasons: string[];
    transcodeProgressPct?: number;
    transcodeFps?: number;
    bitrateBps: number;
    bandwidthMbps: number;
    sessionDataBytes: number;
    startedAt: string;
    playSessionId?: string;
    mediaSourceId?: string;
    supportsMediaControl?: boolean;
    supportsRemoteControl?: boolean;
    canSendMessage?: boolean;
    supportedCommands?: string[];
}

export interface StreamingLiveSummary {
    activeStreams: number;
    directPlayCount: number;
    directStreamCount: number;
    transcodeCount: number;
    totalBitrateBps: number;
    totalBandwidthMbps: number;
    activeSessionBytes: number;
    lanStreams: number;
    wanStreams: number;
    isDemoMode: boolean;
}

export interface StreamTypeDistribution {
    directPlayCount: number;
    directPlayPct: number;
    directStreamCount: number;
    directStreamPct: number;
    transcodeCount: number;
    transcodePct: number;
}

export interface BreakdownEntry {
    label: string;
    count: number;
    pct: number;
    watchTimeSecs: number;
    dataUsedBytes: number;
}

export interface StreamingTimeSeriesPoint {
    date: string;
    plays: number;
    watchTimeSecs: number;
    dataUsedBytes: number;
    peakBandwidthMbps: number;
    directPlayCount: number;
    directStreamCount: number;
    transcodeCount: number;
}

export interface StreamingUserStat {
    userId: string;
    userName: string;
    provider: string;
    totalPlays: number;
    totalWatchSecs: number;
    totalDataBytes: number;
    uniqueItems: number;
    directPlayCount: number;
    transcodeCount: number;
    avgCompletionPct: number;
    lastDevice: string;
    lastSeenAt: string;
}

export interface StreamingTitleStat {
    itemId: string;
    itemName: string;
    itemType: string;
    seriesName?: string;
    productionYear?: number;
    provider: string;
    videoResolution: string;
    videoCodec: string;
    totalPlays: number;
    uniqueViewers: number;
    totalWatchSecs: number;
    totalDataBytes: number;
    avgCompletionPct: number;
    lastWatchedAt: string;
}

export interface StreamingHistoryItem {
    id: number;
    sessionKey: string;
    provider: string;
    serverName: string;
    userName: string;
    clientName: string;
    deviceName: string;
    ipAddress: string;
    itemId: string;
    itemName: string;
    itemType: string;
    seriesName?: string;
    seasonNumber?: number;
    episodeNumber?: number;
    productionYear?: number;
    playMethod: string;
    container: string;
    videoCodec: string;
    videoResolution: string;
    audioCodec: string;
    audioChannels: number;
    hwAccel?: string;
    bitrateBps: number;
    bandwidthMbps: number;
    durationSecs: number;
    watchedSecs: number;
    dataUsedBytes: number;
    completionPct: number;
    startedAt: string;
    lastSeenAt: string;
    isActive: boolean;
}

export interface StreamingAnalytics {
    windowDays: number;
    totalPlays: number;
    totalWatchTimeSecs: number;
    totalDataUsedBytes: number;
    uniqueUsers: number;
    uniqueTitles: number;
    avgCompletionPct: number;
    peakBandwidthMbps: number;
    streamTypes: StreamTypeDistribution;
    mediaTypeBreakdown: BreakdownEntry[];
    resolutionBreakdown: BreakdownEntry[];
    codecBreakdown: BreakdownEntry[];
    timeSeriesGranularity?: 'day' | 'month' | 'year';
    timeSeries: StreamingTimeSeriesPoint[];
    topUsers: StreamingUserStat[];
    topTitles: StreamingTitleStat[];
    recentHistory: StreamingHistoryItem[];
    historicalEstimates?: StreamingHistoryEstimate[];
}

export interface StreamingDashboardData {
    servers: StreamingServerStatus[];
    liveSummary: StreamingLiveSummary;
    activeSessions: ActiveStreamSession[];
    analytics: StreamingAnalytics;
    updatedAt: string;
}

function formatBytes(bytes: number, decimals = 2): string {
    if (!bytes || bytes <= 0) return '0 B';
    const kilo = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const unitIndex = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(kilo)));
    return `${parseFloat((bytes / Math.pow(kilo, unitIndex)).toFixed(decimals))} ${sizes[unitIndex]}`;
}

function formatBandwidthMbps(bandwidthMbps?: number, bitrateBps?: number): string {
    if (typeof bandwidthMbps === 'number' && Number.isFinite(bandwidthMbps)) {
        return bandwidthMbps.toFixed(1);
    }
    if (typeof bitrateBps === 'number' && Number.isFinite(bitrateBps) && bitrateBps > 0) {
        return (bitrateBps / 1_000_000).toFixed(1);
    }
    return '0.0';
}

function formatProviderDisplayName(rawProvider?: string | null): string {
    if (!rawProvider) return '';
    const normalizedProvider = rawProvider.trim().toLowerCase();
    if (normalizedProvider === 'plex') return 'Plex';
    if (normalizedProvider === 'jellyfin') return 'Jellyfin';
    if (normalizedProvider === 'emby') return 'Emby';
    return rawProvider;
}

function formatDurationClock(secs: number): string {
    if (!secs || secs <= 0) return '0:00';
    const hours = Math.floor(secs / 3600);
    const minutes = Math.floor((secs % 3600) / 60);
    const remainingSeconds = Math.floor(secs % 60);
    if (hours > 0) {
        return `${hours}:${String(minutes).padStart(2, '0')}:${String(remainingSeconds).padStart(2, '0')}`;
    }
    return `${minutes}:${String(remainingSeconds).padStart(2, '0')}`;
}

function formatWatchDuration(secs: number): string {
    if (!secs || secs <= 0) return '0m';
    if (secs < 60) return `${secs}s`;
    const hours = Math.floor(secs / 3600);
    const minutes = Math.floor((secs % 3600) / 60);
    if (hours === 0) return `${minutes}m`;
    if (hours < 24) return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`;
    const days = Math.floor(hours / 24);
    const remainingHours = hours % 24;
    return remainingHours > 0 ? `${days}d ${remainingHours}h` : `${days}d`;
}

function formatEpisodeBadge(season?: number, episode?: number): string | null {
    if (season == null && episode == null) return null;
    if (!season && !episode) return null;
    return `S${String(season ?? 1).padStart(2, '0')}E${String(episode ?? 1).padStart(2, '0')}`;
}

const renderHiddenUpperDateTick = () => null;

function formatTranscodeReason(reason: string): string {
    return reason
        .replace(/([A-Z])/g, ' $1')
        .replace(/^./, (match) => match.toUpperCase())
        .trim();
}

function getPlayMethodStyle(method?: string | null) {
    const kind = normalizePlayMethodKind(method);
    switch (kind) {
        case 'Transcode':
            return {
                label: 'Transcode',
                badge: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
                dot: 'bg-amber-400',
                bar: 'bg-gradient-to-r from-amber-500 to-orange-400',
            };
        case 'DirectStream':
            return {
                label: 'Direct Stream',
                badge: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
                dot: 'bg-sky-400',
                bar: 'bg-gradient-to-r from-sky-500 to-cyan-400',
            };
        case 'DirectPlay':
            return {
                label: 'Direct Play',
                badge: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
                dot: 'bg-emerald-400',
                bar: 'bg-gradient-to-r from-emerald-500 to-teal-400',
            };
        default:
            return {
                label: 'Unknown',
                badge: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
                dot: 'bg-slate-400',
                bar: 'bg-gradient-to-r from-slate-500 to-slate-400',
            };
    }
}

function subscribeToDesktopViewport(onStoreChange: () => void) {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
        return () => {};
    }
    const mediaQuery = window.matchMedia('(min-width: 640px)');
    if (typeof mediaQuery.addEventListener === 'function') {
        mediaQuery.addEventListener('change', onStoreChange);
        return () => mediaQuery.removeEventListener('change', onStoreChange);
    } else if (typeof mediaQuery.addListener === 'function') {
        mediaQuery.addListener(onStoreChange);
        return () => mediaQuery.removeListener(onStoreChange);
    }
    return () => {};
}

function getDesktopViewportSnapshot(): boolean {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
        return true;
    }
    return window.matchMedia('(min-width: 640px)').matches;
}

function getServerDesktopViewportSnapshot(): boolean {
    return true;
}

const HISTORICAL_PLAY_METHOD_OPTIONS: Array<{ id: string; label: string }> = [
    { id: 'all', label: 'All Methods' },
    { id: 'DirectPlay', label: 'Direct Play' },
    { id: 'DirectStream', label: 'Direct Stream' },
    { id: 'Transcode', label: 'Transcode' },
    { id: 'Unknown', label: 'Unknown' },
];

const HISTORICAL_MEDIA_TYPE_OPTIONS: Array<{ id: string; label: string }> = [
    { id: 'all', label: 'All Media' },
    { id: 'Movie', label: 'Movies' },
    { id: 'Episode', label: 'Episodes' },
    { id: 'Audio', label: 'Audio' },
];

export default function StreamingTab() {
    const { user } = useAuth();
    const { addToast } = useToast();
    const { hapticFeedback } = useSystemStore();
    const isAdmin = user?.role === 'admin';

    const [activeView, setActiveView] = useState<'dashboard' | 'streams' | 'analytics' | 'history'>('dashboard');
    const [windowDays, setWindowDays] = useState<number>(30);
    const [playMethodFilter, setPlayMethodFilter] = useState<string>('all');
    const [mediaTypeFilter, setMediaTypeFilter] = useState<string>('all');
    const selectedDeliverySummary = HISTORICAL_PLAY_METHOD_OPTIONS.find((option) => option.id === playMethodFilter)?.label || (playMethodFilter === 'all' ? 'All Methods' : playMethodFilter);
    const selectedMediaTypeSummary = HISTORICAL_MEDIA_TYPE_OPTIONS.find((option) => option.id === mediaTypeFilter)?.label || (mediaTypeFilter === 'all' ? 'All Media' : mediaTypeFilter);
    const [historySearch, setHistorySearch] = useState<string>('');
    const [historyPage, setHistoryPage] = useState<number>(1);
    const [historyPageSize, setHistoryPageSize] = useState<number>(20);

    const [showConfigModal, setShowConfigModal] = useState<boolean>(false);
    const [serverNameInput, setServerNameInput] = useState<string>('Jellyfin');
    const [serverUrlInput, setServerUrlInput] = useState<string>('http://127.0.0.1:8096');
    const [apiKeyInput, setApiKeyInput] = useState<string>('');
    const [configProvider, setConfigProvider] = useState<'jellyfin' | 'emby'>('jellyfin');
    const [serverEnabledInput, setServerEnabledInput] = useState(true);
    const configRevision = useRef(0);
    const providerDrafts = useRef<Partial<Record<'jellyfin' | 'emby', { name: string; url: string; key: string; enabled: boolean }>>>({});
    const [isTestingConn, setIsTestingConn] = useState<boolean>(false);
    const [isSavingConn, setIsSavingConn] = useState<boolean>(false);
    const [isSyncingHistory, setIsSyncingHistory] = useState<boolean>(false);
    const [isDemoLoading, setIsDemoLoading] = useState<boolean>(false);
    const [testResultMsg, setTestResultMsg] = useState<{ ok: boolean; text: string } | null>(null);
    const [pendingSessionActions, setPendingSessionActions] = useState<Set<string>>(new Set());

    const [messageSession, setMessageSession] = useState<ActiveStreamSession | null>(null);
    const [messageHeader, setMessageHeader] = useState<string>('AetherFlow Notice');
    const [messageBody, setMessageBody] = useState<string>('');
    const [isSendingMessage, setIsSendingMessage] = useState<boolean>(false);

    const isDesktopViewport = useSyncExternalStore(
        subscribeToDesktopViewport,
        getDesktopViewportSnapshot,
        getServerDesktopViewportSnapshot
    );
    const [isMobileActionsOpen, setIsMobileActionsOpen] = useState<boolean>(false);
    const [isMobileFiltersOpen, setIsMobileFiltersOpen] = useState<boolean>(false);

    const swrKey = `/api/v1/auth/streaming/dashboard?window=${windowDays}&playMethod=${encodeURIComponent(playMethodFilter)}&mediaType=${encodeURIComponent(mediaTypeFilter)}`;
    const { data, error, isLoading, isValidating, mutate } = useSWR<StreamingDashboardData>(swrKey, fetcher, {
        refreshInterval: 5000,
        revalidateOnFocus: true,
    });

    const jellyfinServer = useMemo(() => {
        return data?.servers?.find((server) => server.provider === 'jellyfin') || {
            provider: 'jellyfin' as const,
            name: 'Jellyfin',
            url: 'http://127.0.0.1:8096',
            apiKeyMasked: '',
            configured: false,
            enabled: true,
            status: 'unconfigured' as const,
            supportStage: 'active' as const,
            serverId: '',
            version: '',
            operatingSystem: '',
            lastConnectedAt: '',
            libraryCounts: { movies: 0, series: 0, episodes: 0, audio: 0 },
        };
    }, [data]);

    const connectedServer = data?.servers?.find((server) => server.enabled && server.status === 'connected');

    const selectConfigProvider = (provider: 'jellyfin' | 'emby', preserveCurrent = true) => {
        if (preserveCurrent) providerDrafts.current[configProvider] = {
            name: serverNameInput, url: serverUrlInput, key: apiKeyInput, enabled: serverEnabledInput,
        };
        const server = data?.servers.find(candidate => candidate.provider === provider);
        const draft = providerDrafts.current[provider];
        setConfigProvider(provider);
        setServerNameInput(draft?.name ?? server?.name ?? (provider === 'emby' ? 'Emby' : 'Jellyfin'));
        setServerUrlInput(draft?.url ?? server?.url ?? 'http://127.0.0.1:8096');
        setApiKeyInput(draft?.key ?? server?.apiKeyMasked ?? '');
        setServerEnabledInput(draft?.enabled ?? server?.enabled ?? true);
        configRevision.current += 1;
        setTestResultMsg(null);
    };

    const closeConfig = () => { if (!isSavingConn && !isTestingConn) setShowConfigModal(false); };
    const closeMessage = () => { if (!isSendingMessage) setMessageSession(null); };

    const openServerConfig = () => {
        triggerHaptic(8, hapticFeedback);
        selectConfigProvider(configProvider, false);
        setShowConfigModal(true);
    };

    const handleTestConnection = async () => {
        if (isTestingConn || isSavingConn) return;
        const revision = configRevision.current;
        setIsTestingConn(true);
        setTestResultMsg(null);
        try {
            const response = await apiFetch('/api/v1/admin/streaming/servers/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    provider: configProvider,
                    url: serverUrlInput,
                    apiKey: apiKeyInput,
                }),
            });
            const responseBody = await response.json().catch(() => ({}));
            if (response.ok && responseBody.ok) {
                const message = responseBody.message || `Connected to ${configProvider} successfully!`;
                if (revision === configRevision.current) setTestResultMsg({ ok: true, text: message });
                addToast(message, 'success');
            } else {
                const errorMessage = responseBody.message || responseBody.error || `Could not authenticate with ${configProvider} (HTTP ${response.status})`;
                if (revision === configRevision.current) setTestResultMsg({ ok: false, text: errorMessage });
                addToast(errorMessage, 'error');
            }
        } catch (thrownError: unknown) {
            const errorMessage = thrownError instanceof Error ? thrownError.message : 'Connection test failed';
            if (revision === configRevision.current) setTestResultMsg({ ok: false, text: errorMessage });
            addToast(errorMessage, 'error');
        } finally {
            setIsTestingConn(false);
        }
    };

    const handleSaveConfig = async (event: React.FormEvent) => {
        event.preventDefault();
        if (isSavingConn || isTestingConn) return;
        const revision = configRevision.current;
        const provider = configProvider;
        setIsSavingConn(true);
        try {
            const response = await apiFetch(`/api/v1/admin/streaming/servers/${provider}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: serverNameInput,
                    url: serverUrlInput,
                    apiKey: apiKeyInput,
                    enabled: serverEnabledInput,
                }),
            });
            const responseBody = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(responseBody.message || responseBody.error || 'Failed to save Jellyfin configuration');
            }
            await mutate();
            const serverStatus = responseBody.server?.status;
            if (serverStatus === 'unreachable' || serverStatus === 'unavailable') {
                const errorMessage =
                    responseBody.server?.errorMessage ||
                    responseBody.message ||
                    'Jellyfin configuration saved, but server is currently unreachable.';
                if (revision === configRevision.current) setTestResultMsg({ ok: false, text: errorMessage });
                addToast(errorMessage, 'error');
            } else {
                if (revision === configRevision.current) {
                    delete providerDrafts.current[provider];
                    setShowConfigModal(false);
                }
                addToast(responseBody.message || `${provider} connection settings saved.`, 'success');
            }
        } catch (thrownError: unknown) {
            const errorMessage = thrownError instanceof Error ? thrownError.message : 'Failed to save Jellyfin configuration';
            if (revision === configRevision.current) setTestResultMsg({ ok: false, text: errorMessage });
            addToast(errorMessage, 'error');
        } finally {
            setIsSavingConn(false);
        }
    };

    const handleSyncHistory = async () => {
        setIsSyncingHistory(true);
        try {
            const response = await apiFetch('/api/v1/admin/streaming/servers/jellyfin/sync', {
                method: 'POST',
            });
            const responseBody = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(responseBody.message || responseBody.error || 'History sync failed');
            }
            await mutate();
            addToast(`Synchronized Jellyfin item summaries (${responseBody.imported ?? 0} records updated; not playback events).`, 'success');
        } catch (thrownError: unknown) {
            addToast(thrownError instanceof Error ? thrownError.message : 'Failed to sync Jellyfin history', 'error');
        } finally {
            setIsSyncingHistory(false);
        }
    };

    const handleToggleDemo = async (action: 'seed' | 'clear') => {
        setIsDemoLoading(true);
        try {
            const response = await apiFetch('/api/v1/admin/streaming/demo', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action }),
            });
            const responseBody = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(responseBody.message || responseBody.error || 'Failed to toggle demo telemetry');
            }
            await mutate();
            addToast(
                action === 'seed'
                    ? 'Demo Jellyfin streams, codecs, and bandwidth telemetry loaded.'
                    : 'Demo telemetry cleared.',
                'info'
            );
        } catch (thrownError: unknown) {
            addToast(thrownError instanceof Error ? thrownError.message : 'Failed to update demo telemetry state', 'error');
        } finally {
            setIsDemoLoading(false);
        }
    };

    const handleSessionCommand = async (session: ActiveStreamSession, command: 'pause' | 'resume' | 'stop') => {
        const capabilities = evaluateSessionCapabilities(session);
        const capability = capabilities[command];
        if (!capability.supported) {
            addToast(capability.reason, 'error');
            return;
        }
        const sessionId = session.sessionId;
        triggerHaptic(8, hapticFeedback);
        const actionKey = `${session.provider}:${sessionId}:${command}`;
        if (pendingSessionActions.has(actionKey)) return;
        setPendingSessionActions(current => new Set(current).add(actionKey));
        try {
            const response = await apiFetch(`/api/v1/admin/streaming/sessions/${encodeURIComponent(sessionId)}/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command, provider: session.provider }),
            });
            if (!response.ok) {
                const responseBody = await response.json().catch(() => ({}));
                throw new Error(responseBody.message || responseBody.error || `Failed to ${command} session`);
            }
            await mutate(
                (current) => {
                    if (!current) return current;
                    const updatedSessions =
                        command === 'stop'
                            ? current.activeSessions.filter((activeSession) => activeSession.sessionId !== sessionId || activeSession.provider !== session.provider)
                            : current.activeSessions.map((activeSession) => {
                                  if (activeSession.sessionId !== sessionId || activeSession.provider !== session.provider) return activeSession;
                                  const nextState: 'playing' | 'paused' = command === 'pause' ? 'paused' : 'playing';
                                  const nextBandwidth =
                                      nextState === 'paused'
                                          ? 0
                                          : Math.round((activeSession.bitrateBps / 1_000_000) * 100) / 100;
                                  return { ...activeSession, state: nextState, bandwidthMbps: nextBandwidth };
                              });
                    return {
                        ...current,
                        activeSessions: updatedSessions,
                        liveSummary: recomputeLiveSummaryFromSessions(current.liveSummary, updatedSessions),
                    };
                },
                { revalidate: true }
            );
            addToast(`Sent ${command} command to stream session.`, 'success');
        } catch (thrownError: unknown) {
            addToast(thrownError instanceof Error ? thrownError.message : `Command ${command} failed`, 'error');
        } finally {
            setPendingSessionActions(current => { const next = new Set(current); next.delete(actionKey); return next; });
        }
    };

    const handleSendSessionMessage = async (event: React.FormEvent) => {
        event.preventDefault();
        if (!messageSession || !messageBody.trim() || isSendingMessage) return;
        const capabilities = evaluateSessionCapabilities(messageSession);
        if (!capabilities.message.supported) {
            addToast(capabilities.message.reason, 'error');
            return;
        }
        setIsSendingMessage(true);
        try {
            const response = await apiFetch(`/api/v1/admin/streaming/sessions/${encodeURIComponent(messageSession.sessionId)}/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    command: 'message',
                    provider: messageSession.provider,
                    header: messageHeader,
                    message: messageBody,
                }),
            });
            if (!response.ok) {
                const responseBody = await response.json().catch(() => ({}));
                throw new Error(responseBody.message || responseBody.error || 'Failed to send message to client');
            }
            addToast(`Message delivered to ${messageSession.userName} (${messageSession.deviceName})`, 'success');
            setMessageSession(null);
            setMessageBody('');
        } catch (thrownError: unknown) {
            addToast(thrownError instanceof Error ? thrownError.message : 'Failed to deliver message', 'error');
        } finally {
            setIsSendingMessage(false);
        }
    };

    const liveSummary = data?.liveSummary || {
        activeStreams: 0,
        directPlayCount: 0,
        directStreamCount: 0,
        transcodeCount: 0,
        totalBitrateBps: 0,
        totalBandwidthMbps: 0,
        activeSessionBytes: 0,
        lanStreams: 0,
        wanStreams: 0,
        isDemoMode: false,
    };

    const activeSessions = data?.activeSessions || [];
    const isAnalyticsPayloadUnavailable = !data;

    const isPlexObserved = useMemo(() => {
        const hasPlexSession = (data?.activeSessions || []).some(
            (session) => (session.provider || '').toLowerCase() === 'plex'
        );
        const hasPlexActiveServer = (data?.servers || []).some(
            (server) => (server.provider || '').toLowerCase() === 'plex' && server.status !== 'coming_soon' && server.status !== 'unconfigured'
        );
        return hasPlexSession || hasPlexActiveServer;
    }, [data?.activeSessions, data?.servers]);

    const sessionGridClass = activeSessions.length === 1
        ? 'grid grid-cols-1 gap-4 items-start'
        : activeSessions.length === 2
        ? 'grid grid-cols-1 lg:grid-cols-2 gap-4 items-start'
        : 'grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4 items-start';
    const analytics = data?.analytics || {
        windowDays: 30,
        totalPlays: 0,
        totalWatchTimeSecs: 0,
        totalDataUsedBytes: 0,
        uniqueUsers: 0,
        uniqueTitles: 0,
        avgCompletionPct: 0,
        peakBandwidthMbps: 0,
        streamTypes: {
            directPlayCount: 0,
            directPlayPct: 0,
            directStreamCount: 0,
            directStreamPct: 0,
            transcodeCount: 0,
            transcodePct: 0,
        },
        mediaTypeBreakdown: [],
        resolutionBreakdown: [],
        codecBreakdown: [],
        timeSeries: [],
        topUsers: [],
        topTitles: [],
        recentHistory: [],
    };

    const loadedHistory = useMemo(() => analytics.recentHistory || [], [analytics.recentHistory]);
    const filteredHistory = useMemo(() => {
        const query = historySearch.trim().toLowerCase();
        const playFilter = playMethodFilter.trim().toLowerCase();
        const mediaFilter = mediaTypeFilter.trim().toLowerCase();
        return loadedHistory.filter((historyItem) => {
            if (playFilter !== '' && playFilter !== 'all') {
                const itemMethod = normalizePlayMethodKind(historyItem.playMethod).toLowerCase();
                if (itemMethod !== playFilter) return false;
            }
            if (mediaFilter !== '' && mediaFilter !== 'all') {
                if ((historyItem.itemType || '').trim().toLowerCase() !== mediaFilter) return false;
            }
            if (!query) return true;
            return (
                (historyItem.itemName || '').toLowerCase().includes(query) ||
                Boolean(historyItem.seriesName && historyItem.seriesName.toLowerCase().includes(query)) ||
                (historyItem.userName || '').toLowerCase().includes(query) ||
                (historyItem.clientName || '').toLowerCase().includes(query) ||
                (historyItem.deviceName || '').toLowerCase().includes(query) ||
                (historyItem.videoCodec || '').toLowerCase().includes(query) ||
                (historyItem.playMethod || '').toLowerCase().includes(query) ||
                (historyItem.serverName || '').toLowerCase().includes(query)
            );
        });
    }, [loadedHistory, historySearch, playMethodFilter, mediaTypeFilter]);

    const totalHistoryPages = Math.max(1, Math.ceil(filteredHistory.length / historyPageSize));
    const safeHistoryPage = Math.min(historyPage, totalHistoryPages);

    const paginatedHistory = useMemo(() => {
        const startIndex = (safeHistoryPage - 1) * historyPageSize;
        return filteredHistory.slice(startIndex, startIndex + historyPageSize);
    }, [filteredHistory, safeHistoryPage, historyPageSize]);

    const hasHistoricalSyncImports = useMemo(() => {
        return loadedHistory.some((historyItem) => isHistoricalSyncEntry(historyItem));
    }, [loadedHistory]);

    const isHistoryBounded = analytics.totalPlays > loadedHistory.length;

    const unknownPlaysCount = useMemo(() => {
        const knownCount =
            (analytics.streamTypes.directPlayCount || 0) +
            (analytics.streamTypes.directStreamCount || 0) +
            (analytics.streamTypes.transcodeCount || 0);
        return Math.max(0, (analytics.totalPlays || 0) - knownCount);
    }, [analytics.streamTypes, analytics.totalPlays]);

    const unknownPlaysPct = useMemo(() => {
        if (!analytics.totalPlays || analytics.totalPlays <= 0 || unknownPlaysCount <= 0) return 0;
        return Math.round((unknownPlaysCount / analytics.totalPlays) * 1000) / 10;
    }, [analytics.totalPlays, unknownPlaysCount]);

    const handleExportHistoryCsv = () => {
        if (filteredHistory.length === 0) {
            addToast('No matching playback history rows to export.', 'error');
            return;
        }
        try {
            downloadStreamingHistoryCsv(filteredHistory);
            const scopeNote = isHistoryBounded
                ? `Exported ${filteredHistory.length} loaded rows (bounded from ${analytics.totalPlays} total records).`
                : `Exported ${filteredHistory.length} playback history rows to CSV.`;
            addToast(scopeNote, 'success');
        } catch (thrownError: unknown) {
            addToast(thrownError instanceof Error ? thrownError.message : 'Failed to export playback history CSV', 'error');
        }
    };

    const chartData = useMemo(() => {
        return (analytics.timeSeries || []).map((point) => ({
            ...point,
            watchHours: Math.round((point.watchTimeSecs / 3600) * 100) / 100,
            dataGB: Math.round((point.dataUsedBytes / (1024 * 1024 * 1024)) * 100) / 100,
            unknownPlayCount: Math.max(0, point.plays - point.directPlayCount - point.directStreamCount - point.transcodeCount),
        }));
    }, [analytics.timeSeries]);

    const chartedPeakMbps = useMemo(() => {
        let maxPeak = 0;
        for (const point of chartData) {
            if (typeof point.peakBandwidthMbps === 'number' && Number.isFinite(point.peakBandwidthMbps) && point.peakBandwidthMbps > maxPeak) {
                maxPeak = point.peakBandwidthMbps;
            }
        }
        return maxPeak;
    }, [chartData]);

    const chart1Scales = useMemo(() => {
        let maxDataGB = 0;
        let maxBandwidthMbps = 0;
        for (const point of chartData) {
            if (Number.isFinite(point.dataGB) && point.dataGB > maxDataGB) {
                maxDataGB = point.dataGB;
            }
            if (Number.isFinite(point.peakBandwidthMbps) && point.peakBandwidthMbps > maxBandwidthMbps) {
                maxBandwidthMbps = point.peakBandwidthMbps;
            }
        }
        return computeDualLinearScales(maxDataGB, maxBandwidthMbps, {
            leftMinCeiling: 4,
            rightMinCeiling: 10,
            intervalCount: 4,
        });
    }, [chartData]);

    const chart2Scales = useMemo(() => {
        let maxPlays = 0;
        let maxHours = 0;
        for (const point of chartData) {
            const pointPlays = (point.directPlayCount || 0) +
                (point.directStreamCount || 0) +
                (point.transcodeCount || 0) +
                (point.unknownPlayCount || 0);
            if (pointPlays > maxPlays) {
                maxPlays = pointPlays;
            }
            if (Number.isFinite(point.watchHours) && point.watchHours > maxHours) {
                maxHours = point.watchHours;
            }
        }
        return computeDualLinearScales(maxPlays, maxHours, {
            leftIntegerOnly: true,
            leftMinCeiling: 4,
            rightMinCeiling: 1,
            intervalCount: 4,
        });
    }, [chartData]);

    const sortedResolutionBreakdown = useMemo(() => {
        return [...analytics.resolutionBreakdown].sort((firstEntry, secondEntry) => {
            const countDifference = secondEntry.count - firstEntry.count;
            if (countDifference !== 0) {
                return countDifference;
            }
            const pctDifference = secondEntry.pct - firstEntry.pct;
            if (pctDifference !== 0) {
                return pctDifference;
            }
            return 0;
        });
    }, [analytics.resolutionBreakdown]);

    const bucketLabel = analytics.timeSeriesGranularity === 'month'
        ? 'Monthly'
        : analytics.timeSeriesGranularity === 'year' ? 'Yearly' : 'Daily';

    const lastContactFormatted = useMemo(() => {
        let candidateTimestamp = jellyfinServer.lastConnectedAt;
        if (!candidateTimestamp && data?.servers) {
            for (const serverItem of data.servers) {
                if (serverItem.lastConnectedAt) {
                    candidateTimestamp = serverItem.lastConnectedAt;
                    break;
                }
            }
        }
        if (!candidateTimestamp) return null;
        const parsedDate = parseStreamingTimestamp(candidateTimestamp);
        if (!parsedDate) return null;
        return `${parsedDate.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
    }, [data, jellyfinServer.lastConnectedAt]);

    if (!isAdmin) return (
        <section className="min-w-0 max-w-full space-y-4" aria-label="Your streaming history">
            <h2 className="text-lg font-bold text-slate-100">Your Streaming Archive</h2>
            <p role="note" className="text-sm text-slate-400">Server-wide live telemetry is withheld for privacy, not zero or unconfigured. Your explicitly linked playback records are available below; ask an administrator to link your provider identity if none appear.</p>
            <StreamingHistoryExplorer />
        </section>
    );

    const isConfigureServerPrimary = jellyfinServer.status !== 'connected';

    return (
        <div className="space-y-3 sm:space-y-6 animate-fade-in relative z-10 w-full min-w-0">
            <div className="flex flex-col gap-2.5 sm:gap-4 pb-2.5 sm:pb-4 border-b border-white/[0.08] relative z-30">
                <div className="flex flex-wrap sm:flex-nowrap items-center justify-between gap-2 sm:gap-3.5 w-full min-w-0">
                    <div className="flex items-center gap-2.5 sm:gap-3.5 min-w-0">
                        <div className="h-9 w-9 sm:h-10 sm:w-10 rounded-xl flex items-center justify-center border bg-indigo-500/10 border-indigo-500/20 text-indigo-400 shrink-0 mt-0.5 sm:mt-0">
                            <Tv size={18} className="sm:hidden" />
                            <Tv size={20} className="hidden sm:block" />
                        </div>
                        <div className="min-w-0">
                            <h2 className="text-base sm:text-xl font-bold text-slate-100 tracking-tight">
                                Streaming Dashboard
                            </h2>
                            <p className="hidden sm:block text-xs text-slate-400 mt-0.5 sm:mt-1">
                                Real-time stream telemetry, transcode pipelines, and playback analytics
                            </p>
                        </div>
                    </div>

                    <details
                        open={isDesktopViewport || isMobileActionsOpen}
                        onToggle={(event) => {
                            if (!isDesktopViewport) {
                                setIsMobileActionsOpen(event.currentTarget.open);
                            }
                        }}
                        className={`group shrink-0 sm:order-last sm:self-center open:w-full open:mt-2 open:rounded-xl open:border open:border-white/[0.08] open:bg-slate-950/90 open:p-2.5 sm:open:w-auto sm:open:mt-0 sm:open:border-0 sm:open:bg-transparent sm:open:p-0 transition-all ${
                            isMobileActionsOpen
                                ? 'w-full mt-2 rounded-xl border border-white/[0.08] bg-slate-950/90 p-2.5 sm:w-auto sm:mt-0 sm:border-0 sm:bg-transparent sm:p-0'
                                : 'w-auto sm:w-auto sm:border-0 sm:bg-transparent sm:p-0'
                        }`}
                    >
                        <summary
                            className="sm:hidden cursor-pointer font-medium text-xs text-slate-300 hover:text-white flex items-center justify-between gap-1.5 select-none min-h-[44px] px-2.5 py-1.5 rounded-xl border border-white/[0.08] bg-slate-950/80 shrink-0 obs-touch-target-standard"
                            aria-label="Server & Provider Actions"
                        >
                            <span className="flex items-center gap-1.5">
                                <Settings2 size={13} className="text-indigo-400 shrink-0" />
                                <span className="sr-only">Server & Provider Actions</span>
                                <span aria-hidden="true">Server actions</span>
                            </span>
                            <ChevronDown size={14} className="text-slate-400 group-open:rotate-180 transition-transform shrink-0" />
                        </summary>
                        <div className="mt-2 sm:mt-0 pt-2 sm:pt-0 border-t border-white/[0.06] sm:border-t-0 flex flex-wrap sm:flex-nowrap items-center gap-2">
                            {isAdmin && (
                                <>
                                    {(jellyfinServer.status === 'connected' || jellyfinServer.configured) && (
                                        <button
                                            type="button"
                                            onClick={handleSyncHistory}
                                            disabled={isSyncingHistory}
                                            className="obs-touch-target-standard min-h-[44px] flex-1 sm:flex-initial flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-slate-800/80 hover:bg-slate-700/80 border border-white/10 text-slate-200 transition-all disabled:opacity-50"
                                            title="Import played media items and watch history from Jellyfin"
                                        >
                                            <Database size={14} className={isSyncingHistory ? 'animate-pulse text-indigo-400 shrink-0' : 'text-indigo-400 shrink-0'} />
                                            <span>{isSyncingHistory ? 'Syncing...' : 'Sync Jellyfin'}</span>
                                        </button>
                                    )}

                                    <button
                                        type="button"
                                        onClick={openServerConfig}
                                        className={`obs-touch-target-standard min-h-[44px] flex-1 sm:flex-initial flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl text-xs transition-all ${
                                            isConfigureServerPrimary
                                                ? 'bg-indigo-600 hover:bg-indigo-500 text-white font-semibold shadow-sm'
                                                : 'bg-slate-800/80 hover:bg-slate-700/80 border border-white/10 text-slate-200 font-medium'
                                        }`}
                                    >
                                        <Settings2 size={14} className={isConfigureServerPrimary ? 'text-white shrink-0' : 'text-indigo-400 shrink-0'} />
                                        <span>Configure Server</span>
                                    </button>
                                </>
                            )}

                            <button
                                type="button"
                                onClick={() => void mutate()}
                                aria-label="Refresh Streaming Telemetry"
                                className="obs-touch-target-standard min-h-[44px] flex-1 sm:flex-initial flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-slate-800/80 hover:bg-slate-700/80 border border-white/10 text-slate-200 transition-all"
                                title="Refresh Streaming Telemetry"
                            >
                                <RefreshCw size={14} className={isValidating ? 'animate-spin text-indigo-400 shrink-0' : 'text-slate-400 shrink-0'} />
                                <span>Refresh</span>
                            </button>
                        </div>
                    </details>

                    <div className="w-full sm:w-auto flex flex-wrap items-center gap-1.5 sm:gap-2.5 order-3 sm:order-none">
                        <button
                            type="button"
                            onClick={isAdmin ? openServerConfig : undefined}
                            className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-0.5 rounded-full border transition-all ${
                                !data
                                    ? 'bg-slate-500/15 text-slate-300 border-slate-500/30 hover:bg-slate-500/25'
                                    : jellyfinServer.status === 'connected'
                                    ? 'bg-purple-500/15 text-purple-300 border-purple-500/30 hover:bg-purple-500/25'
                                    : jellyfinServer.status === 'demo'
                                    ? 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30 hover:bg-indigo-500/25'
                                    : 'bg-amber-500/15 text-amber-300 border-amber-500/30 hover:bg-amber-500/25'
                            }`}
                            title="Click to configure Jellyfin connection"
                        >
                            <span
                                className={`h-1.5 w-1.5 rounded-full ${
                                    !data
                                        ? 'bg-slate-400'
                                        : jellyfinServer.status === 'connected'
                                        ? 'bg-emerald-400 shadow-[0_0_6px_#34d399]'
                                        : jellyfinServer.status === 'demo'
                                        ? 'bg-indigo-400 shadow-[0_0_6px_#818cf8]'
                                        : 'bg-amber-400'
                                }`}
                            />
                            <span>
                                Jellyfin
                                {!data ? (error ? ' (Status unavailable)' : ' (Loading status)') : ''}
                                {jellyfinServer.version ? ` v${jellyfinServer.version}` : ''}
                                {jellyfinServer.status === 'demo' ? ' (Demo Preview)' : ''}
                            </span>
                        </button>

                        {isPlexObserved && (
                            <span
                                className="inline-flex items-center gap-1.5 text-xs font-medium px-2 py-0.5 rounded-full border border-white/10 bg-white/[0.04] text-slate-300"
                                title="Observed stream telemetry from Plex session (monitoring only; control unsupported)"
                            >
                                <span className="h-1.5 w-1.5 rounded-full bg-slate-400" />
                                Plex &middot; Read-only telemetry
                            </span>
                        )}
                    </div>
                </div>

                <nav aria-label="Streaming views" className="w-full min-w-0 shrink-0">
                    <div className="sm:hidden w-full">
                        <label htmlFor="mobile-streaming-view-selector" className="sr-only">Select streaming view</label>
                        <div className="relative">
                            <select
                                id="mobile-streaming-view-selector"
                                aria-label="Select streaming view"
                                value={activeView}
                                onChange={(event) => {
                                    triggerHaptic(6, hapticFeedback);
                                    setActiveView(event.target.value as 'dashboard' | 'streams' | 'analytics' | 'history');
                                }}
                                className="w-full obs-touch-target-standard min-h-[44px] appearance-none rounded-xl bg-slate-900/90 border border-white/10 px-3.5 py-2.5 text-xs font-medium text-slate-200 focus:outline-none focus:border-indigo-500 pr-9 shadow-sm"
                            >
                                <option value="dashboard">Dashboard</option>
                                <option value="streams">Live ({liveSummary.activeStreams})</option>
                                <option value="analytics">Playback Analytics</option>
                                <option value="history">Watch History</option>
                            </select>
                            <ChevronDown size={14} className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-slate-400" />
                        </div>
                    </div>

                    <div className="hidden sm:flex sm:items-center gap-1 sm:gap-1.5 p-1 bg-slate-950/80 border border-white/[0.08] rounded-xl">
                        {([
                            { id: 'dashboard', label: 'Dashboard', icon: Tv },
                            { id: 'streams', label: `Live (${data ? liveSummary.activeStreams : '—'})`, icon: Radio },
                            { id: 'analytics', label: 'Playback Analytics', icon: Activity },
                            { id: 'history', label: 'Watch History', icon: Clock },
                        ] as const).map((tab) => {
                            const TabIcon = tab.icon;
                            const isActive = activeView === tab.id;
                            return (
                                <button
                                    key={tab.id}
                                    type="button"
                                    aria-pressed={isActive}
                                    onClick={() => {
                                        triggerHaptic(6, hapticFeedback);
                                        setActiveView(tab.id);
                                    }}
                                    className={`obs-touch-target-standard min-h-[44px] px-3 sm:px-3.5 py-1.5 sm:py-2 rounded-lg text-xs font-medium transition-all flex items-center justify-center sm:justify-start gap-1.5 shrink-0 min-w-0 ${
                                        isActive
                                            ? 'bg-indigo-600 text-white shadow-sm'
                                            : 'text-slate-300 hover:text-white hover:bg-white/[0.05]'
                                    }`}
                                >
                                    <TabIcon size={14} className="shrink-0" />
                                    <span className="whitespace-nowrap">{tab.label}</span>
                                </button>
                            );
                        })}
                    </div>
                </nav>
            </div>

            {error && (
                <div
                    role="alert"
                    className="rounded-xl border border-rose-500/35 bg-rose-950/35 p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3"
                >
                    <div className="flex items-start gap-3">
                        <AlertCircle size={18} className="text-rose-400 shrink-0 mt-0.5" />
                        <div>
                            <h3 className="text-xs font-bold text-rose-200 uppercase tracking-wider">
                                {data ? 'Streaming Telemetry Refresh Failed — Showing Cached Snapshot' : 'Streaming Telemetry Unavailable'}
                            </h3>
                            <p className="text-xs text-rose-300/90 mt-0.5">
                                {error instanceof Error ? error.message : 'Unable to reach the AetherFlow streaming telemetry endpoint.'}
                            </p>
                        </div>
                    </div>
                    <button
                        type="button"
                        onClick={() => void mutate()}
                        disabled={isValidating}
                        className="px-3.5 py-1.5 rounded-xl text-xs font-bold bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 flex items-center gap-1.5 shrink-0 transition-all disabled:opacity-50"
                    >
                        <RefreshCw size={13} className={isValidating ? 'animate-spin' : ''} />
                        <span>Retry Refresh</span>
                    </button>
                </div>
            )}

            {data && jellyfinServer.status !== 'connected' && (
                <div
                    className={`rounded-xl border p-4 sm:p-5 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 ${
                        jellyfinServer.status === 'unreachable'
                            ? 'border-rose-500/30 bg-rose-950/25'
                            : 'border-indigo-500/25 bg-slate-900/60'
                    }`}
                >
                    <div className="flex items-start gap-3.5">
                        <div
                            className={`w-10 h-10 rounded-xl border flex items-center justify-center shrink-0 mt-0.5 ${
                                jellyfinServer.status === 'unreachable'
                                    ? 'bg-rose-500/20 border-rose-500/30 text-rose-300'
                                    : 'bg-purple-500/20 border-purple-500/30 text-purple-300'
                            }`}
                        >
                            {jellyfinServer.status === 'unreachable' ? <AlertCircle size={20} /> : <Server size={20} />}
                        </div>
                        <div>
                            <div className="flex flex-wrap items-center gap-2">
                                <h3 className="text-sm font-bold text-white">
                                    {jellyfinServer.status === 'unreachable'
                                        ? `Jellyfin Server Unreachable (${jellyfinServer.name || jellyfinServer.url}) — Showing Stored History`
                                        : liveSummary.isDemoMode
                                          ? 'Demo Telemetry Active — Connect Your Jellyfin Server Anytime'
                                          : 'Connect Jellyfin to Track Live Streams, Bandwidth & Play Statistics'}
                                </h3>
                                <span className="text-xs font-mono uppercase px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30">
                                    Jellyfin First &middot; Plex & Emby Coming Later
                                </span>
                            </div>
                            <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                                {jellyfinServer.errorMessage
                                    ? jellyfinServer.errorMessage
                                    : 'Enter your Jellyfin URL (default http://127.0.0.1:8096) and an API Key from Jellyfin Dashboard → Advanced → API Keys to monitor active sessions, bitrates, codecs, and historical data usage.'}
                            </p>
                        </div>
                    </div>
                    {isAdmin && (
                        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
                            {jellyfinServer.status === 'unreachable' && (
                                <button
                                    type="button"
                                    onClick={() => void mutate()}
                                    disabled={isValidating}
                                    className="obs-touch-target-standard px-3.5 py-2 rounded-xl text-xs font-bold bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 flex items-center gap-1.5 transition-all disabled:opacity-50"
                                >
                                    <RefreshCw size={14} className={isValidating ? 'animate-spin' : ''} />
                                    <span>Retry Connection</span>
                                </button>
                            )}
                            <button
                                type="button"
                                onClick={openServerConfig}
                                className="obs-touch-target-standard px-4 py-2 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 text-white shadow-sm flex items-center gap-1.5 transition-all"
                            >
                                <Settings2 size={14} />
                                <span>Connect Jellyfin</span>
                            </button>
                            {liveSummary.isDemoMode ? (
                                <button
                                    type="button"
                                    onClick={() => handleToggleDemo('clear')}
                                    disabled={isDemoLoading}
                                    className="obs-touch-target-standard px-3.5 py-2 rounded-xl text-xs font-medium bg-slate-800/80 hover:bg-slate-700/80 border border-white/10 text-slate-200 flex items-center gap-1.5 transition-all"
                                >
                                    <X size={14} />
                                    <span>Clear Demo Data</span>
                                </button>
                            ) : (
                                <button
                                    type="button"
                                    onClick={() => handleToggleDemo('seed')}
                                    disabled={isDemoLoading}
                                    className="obs-touch-target-standard px-3.5 py-2 rounded-xl text-xs font-medium bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/30 text-purple-200 flex items-center gap-1.5 transition-all"
                                >
                                    <Sparkles size={14} />
                                    <span>{isDemoLoading ? 'Loading...' : 'Load Demo Telemetry'}</span>
                                </button>
                            )}
                        </div>
                    )}
                </div>
            )}

            {data ? <section aria-label="Live Stream Overview" className="space-y-2 sm:space-y-2.5">
                {activeSessions.length === 0 ? (
                    <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 p-3 sm:p-3.5 space-y-2">
                        <div className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
                            <div className="flex items-center gap-2">
                                <span className="relative flex h-2.5 w-2.5">
                                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-slate-600" />
                                </span>
                                <h3 className="text-sm font-semibold text-slate-100 tracking-tight">
                                    Live Stream Telemetry
                                </h3>
                            </div>
                            <div className="flex items-center gap-2.5 sm:gap-4 text-xs font-medium">
                                <div className="flex items-baseline gap-1">
                                    <span className="text-slate-400">Active streams:</span>
                                    <span className="text-sm sm:text-base font-bold text-white tabular-nums">{liveSummary.activeStreams}</span>
                                </div>
                                <span className="text-slate-600">&middot;</span>
                                <div className="flex items-baseline gap-1">
                                    <span className="text-slate-400">Bandwidth:</span>
                                    <span className="text-sm sm:text-base font-bold text-cyan-300 tabular-nums">
                                        {formatBandwidthMbps(liveSummary.totalBandwidthMbps, liveSummary.totalBitrateBps)}
                                    </span>
                                    <span className="text-cyan-400">Mbps</span>
                                </div>
                            </div>
                        </div>

                        {(activeView === 'dashboard' || activeView === 'streams') && (
                            <div
                                data-testid="compact-no-streams-state"
                                className="pt-2 border-t border-white/[0.06] flex flex-wrap items-center justify-between gap-x-2 gap-y-1 text-xs text-slate-300"
                            >
                                {isLoading && !data ? (
                                    <div className="flex items-center gap-2 text-slate-400">
                                        <Loader2 size={14} className="animate-spin text-indigo-400 shrink-0" />
                                        <span>Polling media server sessions...</span>
                                    </div>
                                ) : connectedServer ? (
                                    <>
                                        <div className="flex items-center gap-2 text-slate-300">
                                            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 shrink-0" />
                                            <span className="font-medium">
                                                {connectedServer.name} connected &middot; Idle{connectedServer.supportStage === 'coming_soon' ? ' (staged)' : ''}
                                            </span>
                                        </div>
                                        {lastContactFormatted && (
                                            <span className="text-xs text-slate-300 font-mono break-words">
                                                Last contact: {lastContactFormatted}
                                            </span>
                                        )}
                                    </>
                                ) : jellyfinServer.errorMessage || data?.servers.some((server) => server.enabled && ['unavailable', 'unreachable'].includes(server.status)) ? (
                                    <>
                                        <div className="flex items-center gap-2 text-amber-300">
                                            <AlertCircle size={14} className="text-amber-400 shrink-0" />
                                            <span className="font-medium">
                                                {jellyfinServer.errorMessage || 'Live telemetry unavailable \u2014 media server unreachable or offline'}
                                            </span>
                                        </div>
                                        {lastContactFormatted && (
                                            <span className="text-xs text-slate-300 font-mono break-words">
                                                Last contact: {lastContactFormatted}
                                            </span>
                                        )}
                                    </>
                                ) : jellyfinServer.status === 'demo' ? (
                                    <>
                                        <div className="flex items-center gap-2 text-indigo-300">
                                            <Sparkles size={14} className="text-indigo-400 shrink-0" />
                                            <span>Demo preview telemetry active &middot; Standing by for simulated playback</span>
                                        </div>
                                        {lastContactFormatted && (
                                            <span className="text-xs text-slate-300 font-mono break-words">
                                                Last contact: {lastContactFormatted}
                                            </span>
                                        )}
                                    </>
                                ) : jellyfinServer.status === 'unavailable' || jellyfinServer.status === 'unreachable' ? (
                                    <>
                                        <div className="flex items-center gap-2 text-amber-300">
                                            <AlertCircle size={14} className="text-amber-400 shrink-0" />
                                            <span>Live telemetry unavailable &middot; Media server unreachable</span>
                                        </div>
                                        {lastContactFormatted && (
                                            <span className="text-xs text-slate-300 font-mono break-words">
                                                Last contact: {lastContactFormatted}
                                            </span>
                                        )}
                                    </>
                                ) : (
                                    <div className="flex items-center gap-2 text-slate-400">
                                        <span>No media server configured &middot; Connect Jellyfin to track live playback</span>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                ) : (
                    <>
                        <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                                <span className="relative flex h-2.5 w-2.5">
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
                                </span>
                                <h3 className="text-sm font-semibold text-slate-100 tracking-tight">
                                    Live Stream Telemetry
                                </h3>
                            </div>
                            {lastContactFormatted && (
                                <span className="text-xs text-slate-300 font-mono break-words">
                                    Last contact: {lastContactFormatted}
                                </span>
                            )}
                        </div>

                        <div className="grid grid-cols-2 gap-3 sm:gap-3.5">
                            <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 p-3 sm:p-4 flex flex-col">
                                <div className="flex items-center justify-between">
                                    <span className="text-xs text-slate-400 font-medium uppercase tracking-wider leading-snug">Active Streams</span>
                                    <div className="hidden sm:flex h-8 w-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 items-center justify-center text-indigo-400 shrink-0">
                                        <Radio size={16} />
                                    </div>
                                </div>
                                <div className="mt-2 flex items-baseline gap-1.5">
                                    <span className="text-2xl font-bold text-white tabular-nums">{liveSummary.activeStreams}</span>
                                    <span className="text-xs font-semibold text-slate-400/90">
                                        {liveSummary.activeStreams === 1 ? 'stream' : 'streams'}
                                    </span>
                                </div>
                                <div className="mt-2 text-xs text-slate-300 leading-relaxed break-words flex-1 flex flex-col justify-start">
                                    <p>
                                        {liveSummary.lanStreams} LAN &middot; {liveSummary.wanStreams} WAN
                                    </p>
                                    <div className="flex flex-wrap items-center gap-1 sm:gap-1.5 mt-1.5 font-medium">
                                        <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/20 text-xs break-words">
                                            {liveSummary.directPlayCount} Direct Play
                                        </span>
                                        {liveSummary.directStreamCount > 0 && (
                                            <span className="px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/20 text-xs break-words">
                                                {liveSummary.directStreamCount} Direct Stream
                                            </span>
                                        )}
                                        <span className="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/20 text-xs break-words">
                                            {liveSummary.transcodeCount} Transcode
                                        </span>
                                    </div>
                                </div>
                            </div>

                            <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 p-3 sm:p-4 flex flex-col">
                                <div className="flex items-center justify-between">
                                    <span className="text-xs text-slate-400 font-medium uppercase tracking-wider leading-snug">Live Bandwidth</span>
                                    <div className="hidden sm:flex h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 items-center justify-center text-cyan-400 shrink-0">
                                        <Wifi size={16} />
                                    </div>
                                </div>
                                <div className="mt-2 flex items-baseline gap-1.5">
                                    <span className="text-2xl font-bold text-cyan-300 tabular-nums">
                                        {formatBandwidthMbps(liveSummary.totalBandwidthMbps, liveSummary.totalBitrateBps)}
                                    </span>
                                    <span className="text-xs font-semibold text-cyan-400/90">Mbps</span>
                                </div>
                                <div className="mt-2 text-xs text-slate-300 leading-relaxed break-words flex-1 flex flex-col justify-start">
                                    {liveSummary.activeSessionBytes > 0 ? (
                                        <div className="space-y-1">
                                            <p>
                                                Estimated active transfer: <span className="text-slate-100 font-mono font-semibold">{formatBytes(liveSummary.activeSessionBytes, 1)}</span>
                                            </p>
                                            <p className="text-[13px] text-slate-300 leading-normal">
                                                Accumulated from observed playing intervals (bitrate &times; poll duration &divide; 8) across active playback sessions
                                            </p>
                                        </div>
                                    ) : (
                                        <p>Idle &middot; No active throughput</p>
                                    )}
                                </div>
                            </div>
                        </div>
                    </>
                )}
            </section> : (
                <div role="status" className="rounded-xl border border-white/[0.08] bg-slate-900/60 p-4 text-sm text-slate-300">
                    {error ? 'Live stream telemetry is unavailable.' : 'Loading live stream telemetry…'}
                </div>
            )}

            {(activeView === 'dashboard' || activeView === 'streams') && activeSessions.length > 0 && (
                <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 p-4 sm:p-5">
                    <div className="flex flex-wrap items-center justify-between gap-2.5 mb-3 pb-2.5 border-b border-white/[0.06]">
                        <div className="flex items-center gap-2.5">
                            <div className="relative flex h-2.5 w-2.5">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
                            </div>
                            <h3 className="text-sm font-semibold text-slate-100 tracking-tight">
                                Active Media Sessions
                            </h3>
                        </div>
                        <div className="text-xs text-slate-400 flex items-center gap-3">
                            <span className="inline-flex items-center gap-1.5">
                                <span className="w-2 h-2 rounded-full bg-emerald-400" /> Direct Play
                            </span>
                            <span className="inline-flex items-center gap-1.5">
                                <span className="w-2 h-2 rounded-full bg-sky-400" /> Direct Stream
                            </span>
                            <span className="inline-flex items-center gap-1.5">
                                <span className="w-2 h-2 rounded-full bg-amber-400" /> Transcode
                            </span>
                        </div>
                    </div>

                    <div data-testid="active-sessions-grid" className={sessionGridClass}>
                            {activeSessions.map((session) => {
                                const methodStyle = getPlayMethodStyle(session.playMethod);
                                const episodeBadge = formatEpisodeBadge(session.seasonNumber, session.episodeNumber);
                                return (
                                    <article
                                        key={`${session.provider}:${session.sessionId}`}
                                        className="rounded-xl border border-white/[0.08] bg-slate-950/60 hover:border-indigo-500/30 transition-all overflow-hidden flex flex-col justify-start"
                                    >
                                        <div className="p-3 sm:p-4 space-y-3">
                                            <div className="flex items-start gap-3 sm:gap-3.5">
                                                <div className="w-16 h-24 rounded-xl bg-slate-900 border border-white/10 overflow-hidden shrink-0 flex items-center justify-center relative">
                                                    {session.hasArtwork && session.artworkItemId ? (
                                                        <>
                                                        <img
                                                            src={`/api/v1/auth/streaming/artwork/${encodeURIComponent(session.artworkItemId)}?provider=${encodeURIComponent(session.provider)}&serverId=${encodeURIComponent(session.serverId || data?.servers.find(server => server.provider === session.provider)?.serverId || '')}`}
                                                            onError={event => {
                                                                event.currentTarget.hidden = true;
                                                                const fallback = event.currentTarget.nextElementSibling;
                                                                if (fallback instanceof HTMLElement) fallback.hidden = false;
                                                            }}
                                                            alt={session.itemName}
                                                            className="w-full h-full object-cover relative"
                                                        />
                                                        <span hidden role="img" aria-label={`Artwork unavailable for ${session.itemName}`} className="text-indigo-400/60"><Film size={22} /></span>
                                                        </>
                                                    ) : (
                                                        <div className="flex flex-col items-center justify-center text-indigo-400/60">
                                                            {session.itemType === 'Audio' ? <Music size={22} /> : <Film size={22} />}
                                                        </div>
                                                    )}
                                                    <span
                                                        className={`absolute bottom-1 left-1 right-1 text-center text-xs font-bold uppercase py-0.5 rounded ${
                                                            session.state === 'playing'
                                                                ? 'bg-emerald-500/90 text-slate-950'
                                                                : 'bg-amber-500/90 text-slate-950'
                                                        }`}
                                                    >
                                                        {session.state === 'playing' ? 'Playing' : 'Paused'}
                                                    </span>
                                                </div>

                                                <div className="flex-1 min-w-0">
                                                    <div className="flex flex-wrap items-center justify-between gap-1.5">
                                                        <div className="flex flex-wrap items-center gap-1.5 min-w-0">
                                                            <span className="text-xs font-semibold tracking-wider px-1.5 py-0.5 rounded border border-white/10 bg-white/[0.06] text-slate-200 shrink-0">
                                                                {formatProviderDisplayName(session.provider)}
                                                            </span>
                                                            <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${methodStyle.badge} break-words whitespace-normal`}>
                                                                {methodStyle.label}
                                                                {session.hwAccel ? ` \u00b7 ${session.hwAccel}` : ''}
                                                            </span>
                                                        </div>
                                                        <span className="text-xs font-mono font-bold text-cyan-300 tabular-nums shrink-0">
                                                            {formatBandwidthMbps(session.bandwidthMbps, session.bitrateBps)} Mbps
                                                        </span>
                                                    </div>

                                                    <h4 className="text-sm sm:text-base font-bold text-white break-words mt-1.5" title={session.itemName}>
                                                        {session.seriesName ? session.seriesName : session.itemName}
                                                    </h4>
                                                    <p className="text-xs text-slate-300 break-words">
                                                        {session.seriesName ? (
                                                            <>
                                                                {episodeBadge && <span className="font-mono text-indigo-300 mr-1.5">{episodeBadge}</span>}
                                                                <span>{session.itemName}</span>
                                                            </>
                                                        ) : (
                                                            <span>
                                                                {session.itemType} {session.productionYear ? ` \u00b7 ${session.productionYear}` : ''}
                                                            </span>
                                                        )}
                                                    </p>

                                                    <div className="mt-2.5 pt-2 border-t border-white/[0.06] flex flex-col gap-1.5 text-xs">
                                                        <div className="flex flex-wrap items-center justify-between gap-1 text-slate-200">
                                                            <span className="font-semibold flex items-center gap-1.5 break-words min-w-0">
                                                                <Users size={12} className="text-indigo-400 shrink-0" />
                                                                <span>{session.userName}</span>
                                                            </span>
                                                            <span
                                                                className={`text-xs font-mono px-1.5 py-0.5 rounded border break-all ${
                                                                    session.isLan
                                                                        ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20'
                                                                        : 'bg-purple-500/10 text-purple-300 border-purple-500/20'
                                                                }`}
                                                            >
                                                                {session.isLan ? 'LAN' : 'WAN'}{session.ipAddress ? ` \u00b7 ${session.ipAddress}` : ''}
                                                            </span>
                                                        </div>
                                                        <div className="flex flex-wrap items-center justify-between gap-1 text-slate-300">
                                                            <span className="break-words flex items-center gap-1.5 min-w-0" title={`${session.clientName} \u00b7 ${session.deviceName}`}>
                                                                <Monitor size={12} className="text-slate-400 shrink-0" />
                                                                <span>{session.clientName} &middot; {session.deviceName}</span>
                                                            </span>
                                                            <span className="font-mono text-teal-300 font-semibold shrink-0">
                                                                {formatBytes(session.sessionDataBytes, 2)}
                                                            </span>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>

                                            {session.transcodeReasons && session.transcodeReasons.length > 0 && (
                                                <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 px-3 py-2 text-[13px] text-slate-300 leading-relaxed">
                                                    <span className="font-semibold text-amber-300">Transcode reason: </span>
                                                    <span>{session.transcodeReasons.map(formatTranscodeReason).join(', ')}</span>
                                                </div>
                                            )}

                                            <details className="group rounded-xl bg-slate-950/60 border border-white/[0.06] overflow-hidden text-[13px]">
                                                <summary className="px-3 py-2.5 cursor-pointer select-none font-medium text-slate-300 flex items-center justify-between hover:bg-white/[0.02] transition-colors focus:outline-none min-h-[44px] obs-touch-target-standard text-[13px]">
                                                    <span className="flex items-center gap-1.5">
                                                        <Layers size={13} className="text-slate-400 shrink-0" />
                                                        <span>Stream pipeline &amp; codec details</span>
                                                    </span>
                                                    <ChevronDown size={14} className="text-slate-400 group-open:rotate-180 transition-transform shrink-0" />
                                                </summary>
                                                <div className="p-3 pt-1 border-t border-white/[0.04] space-y-2 text-[13px]">
                                                    <div className="flex flex-wrap items-baseline justify-between border-b border-white/[0.04] pb-1 gap-x-2 gap-y-0.5">
                                                        <span className="text-[13px] text-slate-300 font-medium shrink-0">Container</span>
                                                        <span className="font-mono text-slate-100 font-semibold text-right break-words min-w-0 text-[13px]">
                                                            {session.container || 'MKV'}
                                                            {session.targetContainer && session.targetContainer !== session.container && (
                                                                <span className="text-amber-300 font-normal"> &rarr; {session.targetContainer}</span>
                                                            )}
                                                        </span>
                                                    </div>
                                                    <div className="flex flex-wrap items-baseline justify-between border-b border-white/[0.04] pb-1 gap-x-2 gap-y-0.5">
                                                        <span className="text-[13px] text-slate-300 font-medium shrink-0">Video Stream</span>
                                                        <div className="font-mono text-slate-100 font-semibold text-right break-words flex flex-wrap items-center justify-end gap-1.5 min-w-0 text-[13px]">
                                                            <span>
                                                                {session.videoResolution} &middot; {session.videoCodec}
                                                                {session.targetVideoCodec && !session.isVideoDirect && (
                                                                    <span className="text-amber-300 font-normal"> &rarr; {session.targetVideoCodec}</span>
                                                                )}
                                                            </span>
                                                            {session.videoRange && (
                                                                <span className="text-xs px-1.5 py-0.5 rounded bg-white/10 text-slate-200 font-medium shrink-0">
                                                                    {session.videoRange}
                                                                </span>
                                                            )}
                                                        </div>
                                                    </div>
                                                    <div className="flex flex-wrap items-baseline justify-between border-b border-white/[0.04] pb-1 gap-x-2 gap-y-0.5">
                                                        <span className="text-[13px] text-slate-300 font-medium shrink-0">Audio Stream</span>
                                                        <span className="font-mono text-slate-100 font-semibold text-right break-words min-w-0 text-[13px]">
                                                            {session.audioCodec} ({session.audioLayout})
                                                            {session.targetAudioCodec && !session.isAudioDirect && (
                                                                <span className="text-amber-300 font-normal"> &rarr; {session.targetAudioCodec}</span>
                                                            )}
                                                        </span>
                                                    </div>
                                                    <div className="flex flex-wrap items-baseline justify-between gap-x-2 gap-y-0.5">
                                                        <span className="text-[13px] text-slate-300 font-medium shrink-0">Stream Throughput</span>
                                                        <span className="font-mono text-teal-300 font-semibold text-right break-words min-w-0 text-[13px]">
                                                            {formatBandwidthMbps(session.bandwidthMbps, session.bitrateBps)} Mbps {session.transcodeFps ? `\u00b7 ${session.transcodeFps} fps` : ''}
                                                        </span>
                                                    </div>
                                                </div>
                                            </details>
                                        </div>

                                        <div className="px-3 sm:px-4 pb-3.5 pt-2 bg-white/[0.02] border-t border-white/[0.06] space-y-2.5">
                                            <div>
                                                {(() => {
                                                    const hasTranscodeBuffer =
                                                        typeof session.transcodeProgressPct === 'number' &&
                                                        Number.isFinite(session.transcodeProgressPct) &&
                                                        session.transcodeProgressPct > (Number.isFinite(session.progressPct) ? session.progressPct : 0);
                                                    return (
                                                        <div className="space-y-1.5">
                                                            <div>
                                                                <div className="flex flex-wrap items-center justify-between text-[13px] font-mono text-slate-300 mb-1 gap-x-2 gap-y-0.5">
                                                                    <span>{formatDurationClock(session.positionSecs)}</span>
                                                                    <div className="flex flex-wrap items-center gap-1.5 text-[13px]">
                                                                        <span className="text-slate-100 font-semibold">
                                                                            Playback {(Number.isFinite(session.progressPct) ? session.progressPct : 0).toFixed(1)}%
                                                                        </span>
                                                                    </div>
                                                                    <span>{formatDurationClock(session.durationSecs)}</span>
                                                                </div>
                                                                <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                                                                    <div
                                                                        className={`h-full rounded-full ${methodStyle.bar}`}
                                                                        style={{ width: `${Math.min(100, Math.max(0, session.progressPct || 0))}%` }}
                                                                    />
                                                                </div>
                                                            </div>
                                                            {hasTranscodeBuffer && (
                                                                <div className="pt-0.5 space-y-1">
                                                                    <div className="flex items-center justify-between text-[13px] text-amber-300">
                                                                        <span className="font-medium">
                                                                            Transcode buffer {session.transcodeProgressPct?.toFixed(1)}%
                                                                        </span>
                                                                        <span className="text-[13px] font-mono text-amber-400 font-semibold uppercase tracking-wider">
                                                                            Buffer track
                                                                        </span>
                                                                    </div>
                                                                    <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                                                                        <div
                                                                            className="h-full rounded-full bg-amber-400/80"
                                                                            style={{ width: `${Math.min(100, Math.max(0, session.transcodeProgressPct || 0))}%` }}
                                                                        />
                                                                    </div>
                                                                </div>
                                                            )}
                                                        </div>
                                                    );
                                                })()}
                                            </div>

                                            {isAdmin && (() => {
                                                const capabilities = evaluateSessionCapabilities(session);
                                                const isPermanentlyUnsupported =
                                                    !capabilities.pause.supported &&
                                                    !capabilities.resume.supported &&
                                                    !capabilities.stop.supported &&
                                                    !capabilities.message.supported &&
                                                    capabilities.pause.reason.toLowerCase().includes('not supported for provider');

                                                if (isPermanentlyUnsupported) {
                                                    return (
                                                        <div className="pt-1.5">
                                                            <div
                                                                className="flex items-center justify-between gap-2 text-[13px] text-slate-200 py-1.5 px-3 rounded-lg bg-slate-900/80 border border-white/[0.08]"
                                                                title={capabilities.pause.reason}
                                                            >
                                                                <span className="inline-flex items-center gap-1.5 text-[13px] text-slate-200 font-medium">
                                                                    <ShieldCheck size={14} className="text-slate-400 shrink-0" />
                                                                    <span>Read-only stream telemetry &middot; Remote control unsupported for {formatProviderDisplayName(session.provider)}</span>
                                                                </span>
                                                                <span className="text-[11px] font-mono uppercase tracking-wider px-2 py-0.5 rounded border border-white/10 bg-white/[0.06] text-slate-300 font-semibold shrink-0">
                                                                    Read-Only
                                                                </span>
                                                            </div>
                                                        </div>
                                                    );
                                                }

                                                const isPausePending = pendingSessionActions.has(`${session.provider}:${session.sessionId}:pause`);
                                                const isResumePending = pendingSessionActions.has(`${session.provider}:${session.sessionId}:resume`);
                                                const isStopPending = pendingSessionActions.has(`${session.provider}:${session.sessionId}:stop`);
                                                const unsupportedReasons: string[] = [];
                                                if (session.state === 'playing') {
                                                    if (!capabilities.pause.supported && capabilities.pause.reason) {
                                                        unsupportedReasons.push(capabilities.pause.reason);
                                                    }
                                                } else {
                                                    if (!capabilities.resume.supported && capabilities.resume.reason) {
                                                        unsupportedReasons.push(capabilities.resume.reason);
                                                    }
                                                }
                                                if (!capabilities.stop.supported && capabilities.stop.reason && !unsupportedReasons.includes(capabilities.stop.reason)) {
                                                    unsupportedReasons.push(capabilities.stop.reason);
                                                }
                                                if (!capabilities.message.supported && capabilities.message.reason && !unsupportedReasons.includes(capabilities.message.reason)) {
                                                    unsupportedReasons.push(capabilities.message.reason);
                                                }
                                                const visibleReason = unsupportedReasons.join(' · ');
                                                return (
                                                    <div className="space-y-1.5 pt-1">
                                                        <div className="flex flex-wrap items-center gap-2">
                                                            {session.state === 'playing' ? (
                                                                <button
                                                                    type="button"
                                                                    disabled={!capabilities.pause.supported || isPausePending}
                                                                    aria-disabled={!capabilities.pause.supported || isPausePending}
                                                                    onClick={() => handleSessionCommand(session, 'pause')}
                                                                    className="flex-1 min-w-max sm:flex-initial min-h-[44px] sm:min-h-[40px] px-2.5 sm:px-3 py-2 rounded-xl bg-white/[0.05] hover:bg-white/[0.1] border border-white/10 text-xs font-medium text-slate-200 flex items-center justify-center gap-1.5 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                                                                    title={capabilities.pause.reason}
                                                                >
                                                                    <Pause size={13} className="shrink-0" />
                                                                    <span>Pause</span>
                                                                </button>
                                                            ) : (
                                                                <button
                                                                    type="button"
                                                                    disabled={!capabilities.resume.supported || isResumePending}
                                                                    aria-disabled={!capabilities.resume.supported || isResumePending}
                                                                    onClick={() => handleSessionCommand(session, 'resume')}
                                                                    className="flex-1 min-w-max sm:flex-initial min-h-[44px] sm:min-h-[40px] px-2.5 sm:px-3 py-2 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-xs font-medium text-emerald-300 flex items-center justify-center gap-1.5 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                                                                    title={capabilities.resume.reason}
                                                                >
                                                                    <Play size={13} className="shrink-0" />
                                                                    <span>Resume</span>
                                                                </button>
                                                            )}

                                                            <button
                                                                type="button"
                                                                disabled={!capabilities.stop.supported || isStopPending}
                                                                aria-disabled={!capabilities.stop.supported || isStopPending}
                                                                onClick={() => handleSessionCommand(session, 'stop')}
                                                                className="flex-1 min-w-max sm:flex-initial min-h-[44px] sm:min-h-[40px] px-2.5 sm:px-3 py-2 rounded-xl bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-xs font-medium text-rose-300 flex items-center justify-center gap-1.5 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                                                                title={capabilities.stop.reason}
                                                            >
                                                                <Square size={13} className="shrink-0" />
                                                                <span>Stop</span>
                                                            </button>

                                                            <button
                                                                type="button"
                                                                disabled={!capabilities.message.supported}
                                                                aria-disabled={!capabilities.message.supported}
                                                                onClick={() => {
                                                                    if (!capabilities.message.supported) {
                                                                        addToast(capabilities.message.reason, 'error');
                                                                        return;
                                                                    }
                                                                    setMessageSession(session);
                                                                    setMessageBody('');
                                                                }}
                                                                className="flex-1 min-w-max sm:flex-initial min-h-[44px] sm:min-h-[40px] px-2.5 sm:px-3 py-2 rounded-xl bg-indigo-500/15 hover:bg-indigo-500/25 border border-indigo-500/30 text-xs font-medium text-indigo-300 flex items-center justify-center gap-1.5 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                                                                title={capabilities.message.reason}
                                                            >
                                                                <MessageSquare size={13} className="shrink-0" />
                                                                <span>Message</span>
                                                            </button>
                                                        </div>
                                                        {visibleReason ? (
                                                            <div className="text-xs text-amber-300/90 leading-snug flex items-start gap-1.5 pt-0.5">
                                                                <AlertCircle size={12} className="shrink-0 text-amber-400 mt-0.5" />
                                                                <span>{visibleReason}</span>
                                                            </div>
                                                        ) : null}
                                                    </div>
                                                );
                                            })()}
                                        </div>
                                    </article>
                                );
                            })}
                        </div>
                </div>
            )}

            {(activeView === 'dashboard' || activeView === 'analytics' || activeView === 'history') && (
                <div className="space-y-3">
                    <details
                        open={isDesktopViewport || isMobileFiltersOpen}
                        onToggle={(event) => {
                            if (!isDesktopViewport) {
                                setIsMobileFiltersOpen(event.currentTarget.open);
                            }
                        }}
                        className="group rounded-xl border border-white/[0.08] bg-slate-900/60 p-2.5 sm:p-3.5 space-y-3"
                    >
                        <summary
                            className="sm:hidden cursor-pointer select-none min-h-[44px] flex items-center justify-between gap-2.5 text-xs py-1"
                            aria-label="Historical Analytics Filters"
                        >
                            <div className="flex flex-col gap-0.5 min-w-0 flex-1">
                                <div className="flex items-center gap-1.5">
                                    <span className="font-semibold text-slate-200 text-xs">Historical Filters</span>
                                    <span className="text-[11px] text-slate-400 font-normal">&middot; Confirmed &amp; estimated</span>
                                </div>
                                <span className="text-xs text-slate-300 break-words leading-relaxed">
                                    Window: {windowDays === 0 ? 'All Time' : `${windowDays} Days`} &middot; {selectedDeliverySummary} &middot; {selectedMediaTypeSummary}
                                </span>
                            </div>
                            <span className="text-xs font-medium text-indigo-400 flex items-center gap-1 shrink-0 self-center">
                                <span>{isMobileFiltersOpen ? 'Hide' : 'Edit filters'}</span>
                                <ChevronDown size={14} className="group-open:rotate-180 transition-transform shrink-0" />
                            </span>
                        </summary>

                        <div className="flex flex-wrap items-center justify-between gap-2 pb-2.5 border-b border-white/[0.06]">
                            <div className="flex flex-wrap items-center gap-2.5 min-w-0">
                                <h3 className="text-sm sm:text-base font-bold text-slate-100 tracking-tight">
                                    Historical Analytics ({windowDays === 0 ? 'All Time' : `${windowDays} Days`})
                                </h3>
                                <span className="text-xs font-medium px-2 py-0.5 rounded-full border border-indigo-500/20 bg-indigo-500/10 text-indigo-300 shrink-0">
                                    All recorded providers
                                </span>
                            </div>
                            <details className="group text-xs text-slate-400 shrink-0">
                                <summary className="cursor-pointer font-medium text-slate-300 hover:text-white flex items-center gap-1.5 select-none min-h-[44px] px-2 py-1 rounded-lg hover:bg-white/[0.04] transition-colors obs-touch-target-standard">
                                    <span>How these metrics are measured</span>
                                    <ChevronDown size={14} className="text-slate-400 group-open:rotate-180 transition-transform shrink-0" />
                                </summary>
                                <div className="mt-2 p-3 rounded-xl border border-white/[0.06] bg-slate-900/60 space-y-1.5 text-slate-300 text-xs leading-relaxed max-w-xl">
                                    <h4 className="font-semibold text-slate-200">Measurement methodology, overlap &amp; nonadditivity details</h4>
                                    <p role="note">Confirmed statistics use included observed sessions and imported events across all recorded providers. Preserved imported and legacy watch-time estimates appear separately below; use All Time to see older records. Bandwidth peaks remain a legacy provider aggregate.</p>
                                    <p>Imported item summaries and preserved legacy watch-time estimates are unverified and not measured session durations.</p>
                                    <p>Imported items and legacy series may overlap: these series are kept separate, not added together or to confirmed watch time.</p>
                                    <p>Data transfer totals and peak bandwidth are estimates based on bitrate and observed playing time, not measured network interface traffic. Historical imports do not reconstruct missing transfer bytes.</p>
                                </div>
                            </details>
                        </div>

                        <div className="pt-1 sm:pt-0 flex flex-wrap items-center gap-x-6 gap-y-4 w-full min-w-0 max-w-full">
                            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-1.5 sm:gap-2 w-full max-w-full min-w-0 sm:w-auto sm:shrink-0">
                                <span className="text-xs font-semibold text-slate-400 shrink-0">Time Window:</span>
                                <div
                                    role="group"
                                    aria-label="Time Window Filter"
                                    className="flex flex-wrap sm:flex-nowrap items-center gap-1 bg-slate-950/60 p-1 rounded-xl border border-white/[0.08] w-full max-w-full min-w-0 sm:w-auto sm:shrink-0"
                                >
                                    {[
                                        { days: 7, label: '7 Days' },
                                        { days: 30, label: '30 Days' },
                                        { days: 90, label: '90 Days' },
                                        { days: 0, label: 'All Time' },
                                    ].map((windowOption) => (
                                        <button
                                            key={windowOption.days}
                                            type="button"
                                            aria-pressed={windowDays === windowOption.days}
                                            onClick={() => {
                                                setWindowDays(windowOption.days);
                                                setHistoryPage(1);
                                            }}
                                            className={`obs-touch-target-standard min-h-[44px] px-3.5 py-2 rounded-lg text-xs font-medium whitespace-nowrap shrink-0 transition-all ${
                                                windowDays === windowOption.days
                                                    ? 'bg-indigo-600/30 border border-indigo-500/50 text-indigo-200 shadow-sm'
                                                    : 'border border-transparent text-slate-300 hover:text-white hover:bg-white/[0.06]'
                                            }`}
                                        >
                                            {windowOption.label}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-1.5 sm:gap-2 w-full max-w-full min-w-0 sm:w-auto sm:shrink-0">
                                <span className="text-xs font-semibold text-slate-400 shrink-0">Delivery:</span>
                                <div
                                    role="group"
                                    aria-label="Play Method Filter"
                                    className="flex flex-wrap sm:flex-nowrap items-center gap-1 bg-slate-950/60 p-1 rounded-xl border border-white/[0.08] w-full max-w-full min-w-0 sm:w-auto sm:shrink-0"
                                >
                                    {HISTORICAL_PLAY_METHOD_OPTIONS.map((methodOption) => (
                                        <button
                                            key={methodOption.id}
                                            type="button"
                                            aria-pressed={playMethodFilter === methodOption.id}
                                            onClick={() => {
                                                setPlayMethodFilter(methodOption.id);
                                                setHistoryPage(1);
                                            }}
                                            className={`obs-touch-target-standard min-h-[44px] px-3 py-2 rounded-lg text-xs font-medium whitespace-nowrap shrink-0 transition-all ${
                                                playMethodFilter === methodOption.id
                                                    ? 'bg-indigo-600/30 border border-indigo-500/50 text-indigo-200 shadow-sm'
                                                    : 'border border-transparent text-slate-300 hover:text-white hover:bg-white/[0.06]'
                                            }`}
                                        >
                                            {methodOption.label}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-1.5 sm:gap-2 w-full max-w-full min-w-0 sm:w-auto sm:shrink-0">
                                <span className="text-xs font-semibold text-slate-400 shrink-0">Media:</span>
                                <div
                                    role="group"
                                    aria-label="Media Type Filter"
                                    className="flex flex-wrap sm:flex-nowrap items-center gap-1 bg-slate-950/60 p-1 rounded-xl border border-white/[0.08] w-full max-w-full min-w-0 sm:w-auto sm:shrink-0"
                                >
                                    {HISTORICAL_MEDIA_TYPE_OPTIONS.map((mediaTypeOption) => (
                                        <button
                                            key={mediaTypeOption.id}
                                            type="button"
                                            aria-pressed={mediaTypeFilter === mediaTypeOption.id}
                                            onClick={() => {
                                                setMediaTypeFilter(mediaTypeOption.id);
                                                setHistoryPage(1);
                                            }}
                                            className={`obs-touch-target-standard min-h-[44px] px-3 py-2 rounded-lg text-xs font-medium whitespace-nowrap shrink-0 transition-all ${
                                                mediaTypeFilter === mediaTypeOption.id
                                                    ? 'bg-indigo-600/30 border border-indigo-500/50 text-indigo-200 shadow-sm'
                                                    : 'border border-transparent text-slate-300 hover:text-white hover:bg-white/[0.06]'
                                            }`}
                                        >
                                            {mediaTypeOption.label}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </details>

                    {isAnalyticsPayloadUnavailable ? (
                        <div role="status" className="rounded-xl border border-indigo-500/25 bg-indigo-500/[0.06] px-4 py-6 text-center text-sm text-slate-300">
                            {error
                                ? 'Analytics for the selected filters are unavailable. Retry to load this cohort.'
                                : `Loading analytics for ${windowDays === 0 ? 'All Time' : `${windowDays} Days`}, ${selectedDeliverySummary}, ${selectedMediaTypeSummary}…`}
                        </div>
                    ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
                        <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 p-4 flex flex-col justify-between">
                            <div className="flex items-center justify-between">
                                <span className="text-[13px] text-slate-300 font-medium uppercase tracking-wider">
                                    Data Usage ({windowDays === 0 ? 'All' : `${windowDays}d`})
                                </span>
                                <div className="h-8 w-8 rounded-lg bg-teal-500/10 border border-teal-500/20 flex items-center justify-center text-teal-400 shrink-0">
                                    <HardDrive size={16} />
                                </div>
                            </div>
                            <div className="mt-3">
                                <div className="flex items-baseline gap-2">
                                    <span className="text-2xl font-bold text-teal-300 tabular-nums">
                                        {formatBytes(analytics.totalDataUsedBytes, 2)}
                                    </span>
                                    {analytics.totalDataUsedBytes > 0 ? (
                                        <span
                                            className="text-xs font-semibold px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 uppercase tracking-wide"
                                            title="Transfer totals are estimates based on bitrate and observed playing time, not measured network traffic. Historical imports do not reconstruct missing transfer bytes."
                                        >
                                            ESTIMATED
                                        </span>
                                    ) : null}
                                </div>
                                <div className="text-[13px] text-slate-300 mt-2 leading-relaxed">
                                    {analytics.peakBandwidthMbps > 0 ? (
                                        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                                            <span>
                                                Window peak (incl. live):{' '}
                                                <span className="text-slate-200 font-mono font-semibold">
                                                    {formatBandwidthMbps(analytics.peakBandwidthMbps)} Mbps
                                                </span>
                                            </span>
                                            {chartedPeakMbps > 0 && analytics.peakBandwidthMbps > chartedPeakMbps ? (
                                                <span className="text-[13px] text-slate-300">
                                                    &middot; Charted peak: {formatBandwidthMbps(chartedPeakMbps)} Mbps
                                                </span>
                                            ) : chartedPeakMbps === 0 && analytics.peakBandwidthMbps > 0 ? (
                                                <span className="text-[13px] text-slate-300">
                                                    &middot; Window summary and recorded buckets differ
                                                </span>
                                            ) : null}
                                        </div>
                                    ) : (
                                        <p>No recorded throughput peaks</p>
                                    )}
                                </div>
                            </div>
                        </div>

                        <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 p-4 flex flex-col justify-between">
                            <div className="flex items-center justify-between">
                                <span className="text-[13px] text-slate-300 font-medium uppercase tracking-wider">
                                    Confirmed Play Statistics ({windowDays === 0 ? 'All' : `${windowDays}d`})
                                </span>
                                <div className="h-8 w-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 shrink-0">
                                    <Activity size={16} />
                                </div>
                            </div>
                            <div className="mt-3">
                                <div className="flex items-baseline gap-2">
                                    <span className="text-2xl font-bold text-white tabular-nums">{analytics.totalPlays}</span>
                                    {analytics.totalPlays > 0 ? (
                                        <span className="text-[13px] text-slate-300">
                                            confirmed plays &middot; {formatWatchDuration(analytics.totalWatchTimeSecs)}
                                        </span>
                                    ) : (
                                        <span className="text-[13px] text-slate-300">No playback in window</span>
                                    )}
                                </div>
                                <p className="text-[13px] text-slate-300 mt-2 leading-relaxed">
                                    {analytics.totalPlays > 0 ? (
                                        <>{analytics.uniqueUsers} viewers &middot; <span className="text-emerald-400 font-medium">{analytics.avgCompletionPct}%</span> avg completion</>
                                    ) : (
                                        'Standing by for playback events'
                                    )}
                                </p>
                            </div>
                        </div>

                        <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 p-4 flex flex-col justify-between sm:col-span-2 lg:col-span-1">
                            <div className="flex items-center justify-between">
                                <span className="text-[13px] text-slate-300 font-medium uppercase tracking-wider">Jellyfin Library</span>
                                <div className="h-8 w-8 rounded-lg bg-fuchsia-500/10 border border-fuchsia-500/20 flex items-center justify-center text-fuchsia-400 shrink-0">
                                    <Film size={16} />
                                </div>
                            </div>
                            <div className="mt-3 grid grid-cols-2 gap-x-3 gap-y-1.5 text-[13px]">
                                <div className="flex items-center justify-between">
                                    <span className="text-slate-300">Movies</span>
                                    <span className="font-semibold text-slate-200 tabular-nums">{jellyfinServer.libraryCounts?.movies || 0}</span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-slate-300">Series</span>
                                    <span className="font-semibold text-slate-200 tabular-nums">{jellyfinServer.libraryCounts?.series || 0}</span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-slate-300">Episodes</span>
                                    <span className="font-semibold text-slate-200 tabular-nums">{jellyfinServer.libraryCounts?.episodes || 0}</span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-slate-300">Audio</span>
                                    <span className="font-semibold text-slate-200 tabular-nums">{jellyfinServer.libraryCounts?.audio || 0}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    )}
                </div>
            )}

            {(activeView === 'dashboard' || activeView === 'analytics') && data && (
                <>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 p-5 flex flex-col">
                            <div className="flex items-center justify-between mb-4">
                                <div>
                                    <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                                        <HardDrive size={16} className="text-teal-400" />
                                        Stream Data Usage & Bandwidth Over Time
                                    </h3>
                                    <p className="text-xs text-slate-400 mt-0.5">
                                        {bucketLabel} estimated transfer (GB) and recorded peak bitrate (Mbps) &middot; UTC
                                    </p>
                                </div>
                                <span className="text-xs font-mono font-medium text-teal-300 bg-teal-500/10 px-2.5 py-1 rounded-lg border border-teal-500/20 whitespace-nowrap shrink-0">
                                    Total: {formatBytes(analytics.totalDataUsedBytes, 2)}
                                </span>
                            </div>

                            <div className="flex flex-wrap items-center justify-between gap-2 pb-1.5 border-b border-white/[0.06] mb-2 text-[13px]">
                                <div className="flex items-center gap-1.5">
                                    <span className="inline-block w-3.5 h-3.5 rounded-sm bg-teal-400/30 border-2 border-teal-400" />
                                    <span className="text-teal-300 font-semibold">Transferred data (GB)</span>
                                    <span className="text-xs text-amber-300 bg-amber-500/15 px-1.5 py-0.5 rounded border border-amber-500/30 uppercase font-semibold">Estimated</span>
                                </div>
                            </div>

                            <div className="h-[160px] w-full">
                                {chartData.length === 0 ? (
                                    <div className="h-full flex flex-col items-center justify-center text-slate-400 text-xs">
                                        <Activity size={20} className="text-slate-500 mb-2" />
                                        <span>No time-series data recorded for this window</span>
                                    </div>
                                ) : (
                                    <ResponsiveContainer width="100%" height={160}>
                                        <ComposedChart
                                            syncId="stream-transfer-bandwidth"
                                            syncMethod="value"
                                            data={chartData}
                                            margin={{ top: 8, right: 18, left: 0, bottom: 0 }}
                                        >
                                            <defs>
                                                <linearGradient id="streamDataGrad" x1="0" y1="0" x2="0" y2="1">
                                                    <stop offset="5%" stopColor="#2dd4bf" stopOpacity={0.4} />
                                                    <stop offset="95%" stopColor="#2dd4bf" stopOpacity={0.02} />
                                                </linearGradient>
                                            </defs>
                                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" syncWithTicks={true} />
                                            <XAxis
                                                dataKey="date"
                                                stroke="rgba(255,255,255,0.15)"
                                                tick={renderHiddenUpperDateTick}
                                                tickLine={false}
                                                axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                                                height={8}
                                                minTickGap={24}
                                                tickFormatter={(dateTickValue) => formatStreamingAxisDateTick(dateTickValue, analytics.timeSeriesGranularity)}
                                            />
                                            <YAxis
                                                stroke="rgba(255,255,255,0.2)"
                                                tick={{ fill: '#e2e8f0', fontSize: 13 }}
                                                tickFormatter={(numericalValue) => `${numericalValue}`}
                                                domain={chart1Scales.leftAxis.domain}
                                                ticks={chart1Scales.leftAxis.ticks}
                                                interval={0}
                                                width={56}
                                            />
                                            <Tooltip
                                                contentStyle={{
                                                    backgroundColor: '#0f172a',
                                                    border: '1px solid rgba(255,255,255,0.12)',
                                                    borderRadius: '10px',
                                                }}
                                                labelFormatter={(label) => label ? `${label} UTC` : ''}
                                                labelStyle={{ color: '#cbd5e1', fontSize: '13px', marginBottom: '4px' }}
                                                formatter={(value, name) => {
                                                    if (name === 'Transferred data (GB)' || name === 'Data Used') return [`${value} GB`, 'Transferred data (GB) \u00b7 Estimated'];
                                                    return [String(value), String(name)];
                                                }}
                                            />
                                            <Area
                                                type="linear"
                                                name="Transferred data (GB)"
                                                dataKey="dataGB"
                                                stroke="#2dd4bf"
                                                strokeWidth={2}
                                                fillOpacity={1}
                                                fill="url(#streamDataGrad)"
                                            />
                                        </ComposedChart>
                                    </ResponsiveContainer>
                                )}
                            </div>

                            <div className="flex flex-wrap items-center justify-between gap-2 pb-1 border-b border-white/[0.06] mb-1.5 text-[13px] pt-2.5">
                                <div className="flex items-center gap-1.5">
                                    <span className="inline-block w-4 h-0.5 bg-violet-400" />
                                    <span className="text-violet-300 font-semibold">Recorded peak bitrate (Mbps)</span>
                                    <span className="text-[13px] text-slate-300">({bucketLabel} UTC buckets)</span>
                                </div>
                            </div>

                            <div className="h-[160px] w-full">
                                {chartData.length === 0 ? (
                                    <div className="h-full flex flex-col items-center justify-center text-slate-400 text-xs">
                                        <Activity size={20} className="text-slate-500 mb-2" />
                                        <span>No time-series data recorded for this window</span>
                                    </div>
                                ) : (
                                    <ResponsiveContainer width="100%" height={160}>
                                        <ComposedChart
                                            syncId="stream-transfer-bandwidth"
                                            syncMethod="value"
                                            data={chartData}
                                            margin={{ top: 8, right: 18, left: 0, bottom: 0 }}
                                        >
                                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" syncWithTicks={true} />
                                            <XAxis
                                                dataKey="date"
                                                stroke="rgba(255,255,255,0.2)"
                                                tick={{ fill: '#e2e8f0', fontSize: 13 }}
                                                tickFormatter={(dateTickValue) => formatStreamingAxisDateTick(dateTickValue, analytics.timeSeriesGranularity)}
                                                minTickGap={24}
                                            />
                                            <YAxis
                                                stroke="rgba(167,139,250,0.35)"
                                                tick={{ fill: '#ddd6fe', fontSize: 13 }}
                                                tickFormatter={(numericalValue) => `${numericalValue}`}
                                                domain={chart1Scales.rightAxis.domain}
                                                ticks={chart1Scales.rightAxis.ticks}
                                                interval={0}
                                                width={56}
                                            />
                                            <Tooltip
                                                contentStyle={{
                                                    backgroundColor: '#0f172a',
                                                    border: '1px solid rgba(255,255,255,0.12)',
                                                    borderRadius: '10px',
                                                }}
                                                labelFormatter={(label) => label ? `${label} UTC` : ''}
                                                labelStyle={{ color: '#cbd5e1', fontSize: '13px', marginBottom: '4px' }}
                                                formatter={(value, name) => {
                                                    if (name === 'Recorded peak bitrate (Mbps)' || name === 'Peak bitrate (Mbps)' || name === 'Peak Bandwidth') return [`${value} Mbps`, 'Recorded peak bitrate (Mbps)'];
                                                    return [String(value), String(name)];
                                                }}
                                            />
                                            <Line
                                                type="linear"
                                                name="Recorded peak bitrate (Mbps)"
                                                dataKey="peakBandwidthMbps"
                                                stroke="#a78bfa"
                                                strokeWidth={2.25}
                                                dot={false}
                                            />
                                        </ComposedChart>
                                    </ResponsiveContainer>
                                )}
                            </div>
                        </div>

                        <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 p-5 flex flex-col">
                            <div className="flex items-center justify-between mb-4">
                                <div>
                                    <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                                        <Activity size={16} className="text-indigo-400" />
                                        Play Sessions & Watch Time Activity
                                    </h3>
                                    <p className="text-xs text-slate-400 mt-0.5">
                                        {bucketLabel} sessions by delivery method (including Unknown) and Watch Hours &middot; UTC
                                    </p>
                                </div>
                                <span className="text-xs font-mono font-medium text-indigo-300 bg-indigo-500/10 px-2.5 py-1 rounded-lg border border-indigo-500/20 whitespace-nowrap shrink-0">
                                    Watch Time: {formatWatchDuration(analytics.totalWatchTimeSecs)}
                                </span>
                            </div>

                            <div className="flex flex-wrap items-center justify-between gap-2 pb-1.5 border-b border-white/[0.06] mb-2 text-[13px]">
                                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                                    <span className="text-slate-200 font-semibold mr-1">Play sessions</span>
                                    <div className="flex items-center gap-1.5">
                                        <span className="inline-block w-2.5 h-2.5 rounded-sm bg-emerald-500" />
                                        <span className="text-slate-200">Direct Play (sessions)</span>
                                    </div>
                                    <div className="flex items-center gap-1.5">
                                        <span className="inline-block w-2.5 h-2.5 rounded-sm bg-sky-400" />
                                        <span className="text-slate-200">Direct Stream (sessions)</span>
                                    </div>
                                    <div className="flex items-center gap-1.5">
                                        <span className="inline-block w-2.5 h-2.5 rounded-sm bg-amber-400" />
                                        <span className="text-slate-200">Transcode (sessions)</span>
                                    </div>
                                    <div className="flex items-center gap-1.5">
                                        <span className="inline-block w-2.5 h-2.5 rounded-sm bg-slate-400" />
                                        <span className="text-slate-200">Unknown (sessions)</span>
                                    </div>
                                </div>
                            </div>

                            <div className="h-[160px] w-full">
                                {chartData.length === 0 ? (
                                    <div className="h-full flex flex-col items-center justify-center text-slate-400 text-xs">
                                        <Activity size={20} className="text-slate-500 mb-2" />
                                        <span>No watch activity recorded for this window</span>
                                    </div>
                                ) : (
                                    <ResponsiveContainer width="100%" height={160}>
                                        <ComposedChart
                                            syncId="stream-sessions-watchtime"
                                            syncMethod="value"
                                            data={chartData}
                                            margin={{ top: 8, right: 18, left: 0, bottom: 0 }}
                                        >
                                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" syncWithTicks={true} />
                                            <XAxis
                                                dataKey="date"
                                                scale="band"
                                                stroke="rgba(255,255,255,0.15)"
                                                tick={renderHiddenUpperDateTick}
                                                tickLine={false}
                                                axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                                                height={8}
                                                minTickGap={24}
                                                tickFormatter={(dateTickValue) => formatStreamingAxisDateTick(dateTickValue, analytics.timeSeriesGranularity)}
                                            />
                                            <YAxis
                                                stroke="rgba(255,255,255,0.2)"
                                                tick={{ fill: '#e2e8f0', fontSize: 13 }}
                                                allowDecimals={false}
                                                tickFormatter={(numericalValue) => `${numericalValue}`}
                                                domain={chart2Scales.leftAxis.domain}
                                                ticks={chart2Scales.leftAxis.ticks}
                                                interval={0}
                                                width={48}
                                            />
                                            <Tooltip
                                                contentStyle={{
                                                    backgroundColor: '#0f172a',
                                                    border: '1px solid rgba(255,255,255,0.12)',
                                                    borderRadius: '10px',
                                                }}
                                                labelFormatter={(label) => label ? `${label} UTC` : ''}
                                                labelStyle={{ color: '#cbd5e1', fontSize: '13px', marginBottom: '4px' }}
                                                formatter={(value, name) => [`${value} sessions`, String(name)]}
                                            />
                                            <Bar dataKey="directPlayCount" name="Direct Play (sessions)" stackId="plays" fill="#10b981" radius={[0, 0, 0, 0]} />
                                            <Bar dataKey="directStreamCount" name="Direct Stream (sessions)" stackId="plays" fill="#38bdf8" radius={[0, 0, 0, 0]} />
                                            <Bar dataKey="transcodeCount" name="Transcode (sessions)" stackId="plays" fill="#f59e0b" radius={[4, 4, 0, 0]} />
                                            <Bar dataKey="unknownPlayCount" name="Unknown (sessions)" stackId="plays" fill="#94a3b8" />
                                        </ComposedChart>
                                    </ResponsiveContainer>
                                )}
                            </div>

                            <div className="flex flex-wrap items-center justify-between gap-2 pb-1 border-b border-white/[0.06] mb-1.5 text-[13px] pt-2.5">
                                <div className="flex items-center gap-1.5">
                                    <span className="inline-block w-4 h-0 border-t-2 border-dashed border-purple-400" />
                                    <span className="text-purple-300 font-semibold">Watch time (hours)</span>
                                </div>
                            </div>

                            <div className="h-[160px] w-full">
                                {chartData.length === 0 ? (
                                    <div className="h-full flex flex-col items-center justify-center text-slate-400 text-xs">
                                        <Activity size={20} className="text-slate-500 mb-2" />
                                        <span>No watch activity recorded for this window</span>
                                    </div>
                                ) : (
                                    <ResponsiveContainer width="100%" height={160}>
                                        <ComposedChart
                                            syncId="stream-sessions-watchtime"
                                            syncMethod="value"
                                            data={chartData}
                                            margin={{ top: 8, right: 18, left: 0, bottom: 0 }}
                                        >
                                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" syncWithTicks={true} />
                                            <XAxis
                                                dataKey="date"
                                                scale="band"
                                                stroke="rgba(255,255,255,0.2)"
                                                tick={{ fill: '#e2e8f0', fontSize: 13 }}
                                                tickFormatter={(dateTickValue) => formatStreamingAxisDateTick(dateTickValue, analytics.timeSeriesGranularity)}
                                                minTickGap={24}
                                            />
                                            <YAxis
                                                stroke="rgba(196,181,253,0.35)"
                                                tick={{ fill: '#ddd6fe', fontSize: 13 }}
                                                tickFormatter={(numericalValue) => `${numericalValue}`}
                                                domain={chart2Scales.rightAxis.domain}
                                                ticks={chart2Scales.rightAxis.ticks}
                                                interval={0}
                                                width={48}
                                            />
                                            <Tooltip
                                                contentStyle={{
                                                    backgroundColor: '#0f172a',
                                                    border: '1px solid rgba(255,255,255,0.12)',
                                                    borderRadius: '10px',
                                                }}
                                                labelFormatter={(label) => label ? `${label} UTC` : ''}
                                                labelStyle={{ color: '#cbd5e1', fontSize: '13px', marginBottom: '4px' }}
                                                formatter={(value) => [`${value} h`, 'Watch time (hours)']}
                                            />
                                            <Line
                                                type="linear"
                                                dataKey="watchHours"
                                                name="Watch time (hours)"
                                                stroke="#a855f7"
                                                strokeWidth={2}
                                                strokeDasharray="4 4"
                                                dot={false}
                                            />
                                        </ComposedChart>
                                    </ResponsiveContainer>
                                )}
                            </div>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 p-4 space-y-3">
                            <div className="flex items-center justify-between">
                                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                                    <Zap size={14} className="text-emerald-400" />
                                    Play Method Breakdown
                                </h4>
                                <span className="text-xs font-mono text-slate-400">{analytics.totalPlays} total</span>
                            </div>
                            <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-slate-800">
                                {analytics.streamTypes.directPlayPct > 0 && (
                                    <div
                                        className="bg-emerald-500 transition-all"
                                        style={{ width: `${analytics.streamTypes.directPlayPct}%` }}
                                    />
                                )}
                                {analytics.streamTypes.directStreamPct > 0 && (
                                    <div
                                        className="bg-sky-400 transition-all"
                                        style={{ width: `${analytics.streamTypes.directStreamPct}%` }}
                                    />
                                )}
                                {analytics.streamTypes.transcodePct > 0 && (
                                    <div
                                        className="bg-amber-500 transition-all"
                                        style={{ width: `${analytics.streamTypes.transcodePct}%` }}
                                    />
                                )}
                                {unknownPlaysPct > 0 && (
                                    <div
                                        className="bg-slate-500 transition-all"
                                        style={{ width: `${unknownPlaysPct}%` }}
                                        title={`Unknown: ${unknownPlaysCount} (${unknownPlaysPct}%)`}
                                    />
                                )}
                            </div>
                            <div className={`grid ${unknownPlaysCount > 0 ? 'grid-cols-2 sm:grid-cols-4' : 'grid-cols-3'} gap-2.5 sm:gap-3 pt-2 text-xs`}>
                                <div className="bg-slate-950/60 rounded-xl p-3 border border-white/[0.06]">
                                    <span className="text-xs text-emerald-400 font-semibold block">Direct Play</span>
                                    <span className="text-sm font-bold text-white tabular-nums">
                                        {analytics.streamTypes.directPlayCount}{' '}
                                        <span className="text-xs text-slate-400 font-normal">({analytics.streamTypes.directPlayPct}%)</span>
                                    </span>
                                </div>
                                <div className="bg-slate-950/60 rounded-xl p-3 border border-white/[0.06]">
                                    <span className="text-xs text-sky-400 font-semibold block">Direct Stream</span>
                                    <span className="text-sm font-bold text-white tabular-nums">
                                        {analytics.streamTypes.directStreamCount}{' '}
                                        <span className="text-xs text-slate-400 font-normal">({analytics.streamTypes.directStreamPct}%)</span>
                                    </span>
                                </div>
                                <div className="bg-slate-950/60 rounded-xl p-3 border border-white/[0.06]">
                                    <span className="text-xs text-amber-400 font-semibold block">Transcode</span>
                                    <span className="text-sm font-bold text-white tabular-nums">
                                        {analytics.streamTypes.transcodeCount}{' '}
                                        <span className="text-xs text-slate-400 font-normal">({analytics.streamTypes.transcodePct}%)</span>
                                    </span>
                                </div>
                                {unknownPlaysCount > 0 && (
                                    <div className="bg-slate-950/60 rounded-xl p-3 border border-white/[0.06]" title="Imported from Jellyfin played-items sync where live play method was not recorded">
                                        <span className="text-xs text-slate-300 font-semibold block">Unknown</span>
                                        <span className="text-sm font-bold text-white tabular-nums">
                                            {unknownPlaysCount}{' '}
                                            <span className="text-xs text-slate-400 font-normal">({unknownPlaysPct}%)</span>
                                        </span>
                                    </div>
                                )}
                            </div>
                        </div>

                        <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 p-4 space-y-2.5">
                            <div className="flex flex-col gap-0.5">
                                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                                    <Monitor size={14} className="text-indigo-400" />
                                    Resolution Mix &middot; Share of Plays
                                </h4>
                                <span className="text-xs text-slate-400">
                                    Bar reflects share of plays; estimated transfer shown separately
                                </span>
                            </div>
                            <div className="space-y-2">
                                {sortedResolutionBreakdown.length === 0 ? (
                                    <p className="text-xs text-slate-500 py-4 text-center">No resolution metrics recorded yet</p>
                                ) : (
                                    sortedResolutionBreakdown.slice(0, 4).map((resolutionEntry) => (
                                        <div key={resolutionEntry.label} className="space-y-1.5">
                                            <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                                                <span className="text-[13px] font-medium text-slate-200 shrink-0">{resolutionEntry.label}</span>
                                                <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5 font-mono text-[13px]">
                                                    <span className="font-semibold text-slate-100 tabular-nums">
                                                        {resolutionEntry.count} plays
                                                    </span>
                                                    <span className="text-slate-400 tabular-nums">
                                                        ({resolutionEntry.pct}%)
                                                    </span>
                                                    <span className="text-slate-500">&middot;</span>
                                                    <span className="text-[13px] text-slate-300 font-medium tabular-nums">
                                                        est. {formatBytes(resolutionEntry.dataUsedBytes, 1)}
                                                    </span>
                                                </div>
                                            </div>
                                            <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                                                <div
                                                    className="h-full rounded-full bg-gradient-to-r from-indigo-500 to-cyan-400"
                                                    style={{ width: `${Math.min(100, Math.max(0, resolutionEntry.pct))}%` }}
                                                />
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>

                        <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 p-4 space-y-2.5">
                            <div className="flex flex-col gap-0.5">
                                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                                    <Layers size={14} className="text-fuchsia-400" />
                                    Source Codec Telemetry &middot; Share of Plays
                                </h4>
                                <span className="text-xs text-slate-400">
                                    Bar reflects share of plays; estimated transfer shown separately
                                </span>
                            </div>
                            <div className="space-y-2">
                                {analytics.codecBreakdown.length === 0 ? (
                                    <p className="text-xs text-slate-500 py-4 text-center">No codec metrics recorded yet</p>
                                ) : (
                                    analytics.codecBreakdown.slice(0, 4).map((codecEntry) => (
                                        <div key={codecEntry.label} className="space-y-1.5">
                                            <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                                                <span className="text-[13px] font-mono font-medium text-slate-200 shrink-0">{codecEntry.label}</span>
                                                <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5 font-mono text-[13px]">
                                                    <span className="font-semibold text-slate-100 tabular-nums">
                                                        {codecEntry.count} plays
                                                    </span>
                                                    <span className="text-slate-400 tabular-nums">
                                                        ({codecEntry.pct}%)
                                                    </span>
                                                    <span className="text-slate-500">&middot;</span>
                                                    <span className="text-[13px] text-slate-300 font-medium tabular-nums">
                                                        est. {formatBytes(codecEntry.dataUsedBytes, 1)}
                                                    </span>
                                                </div>
                                            </div>
                                            <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                                                <div
                                                    className="h-full rounded-full bg-gradient-to-r from-fuchsia-500 to-purple-400"
                                                    style={{ width: `${Math.min(100, Math.max(0, codecEntry.pct))}%` }}
                                                />
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 overflow-hidden">
                            <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
                                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                                    <Trophy size={16} className="text-amber-400" />
                                    Top Watchers & Data Usage by User
                                </h3>
                                <span className="text-xs text-slate-400">{analytics.topUsers.length} users</span>
                            </div>
                            <div className="divide-y divide-white/[0.04]">
                                {analytics.topUsers.length === 0 ? (
                                    <div className="py-12 text-center text-xs text-slate-400">
                                        No user playback statistics recorded for this period.
                                    </div>
                                ) : (
                                    analytics.topUsers.map((userStat, index) => (
                                        <div
                                            key={userStat.userName}
                                            className="px-5 py-3.5 flex items-center justify-between gap-3 hover:bg-white/[0.02] transition-colors"
                                        >
                                            <div className="flex items-center gap-3 min-w-0">
                                                <span className="w-6 h-6 rounded-lg bg-white/[0.05] border border-white/10 flex items-center justify-center text-xs font-bold text-slate-300 shrink-0">
                                                    {index + 1}
                                                </span>
                                                <div className="w-9 h-9 rounded-full bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-xs font-bold text-indigo-300 shrink-0 uppercase">
                                                    {userStat.userName.slice(0, 2)}
                                                </div>
                                                <div className="min-w-0">
                                                    <p className="text-sm font-bold text-slate-100 truncate">{userStat.userName}</p>
                                                    <p className="text-[13px] text-slate-300 truncate">
                                                        {userStat.uniqueItems} unique titles &middot; {userStat.lastDevice || 'Jellyfin Client'}
                                                    </p>
                                                </div>
                                            </div>
                                            <div className="text-right shrink-0">
                                                <div className="flex items-center justify-end gap-2">
                                                    <span className="text-xs font-mono font-bold text-teal-300 bg-teal-500/10 px-2 py-0.5 rounded border border-teal-500/20">
                                                        {formatBytes(userStat.totalDataBytes, 1)}
                                                    </span>
                                                    <span className="text-sm font-bold text-white tabular-nums">
                                                        {userStat.totalPlays} plays
                                                    </span>
                                                </div>
                                                <p className="text-[13px] text-slate-300 mt-0.5 tabular-nums">
                                                    {formatWatchDuration(userStat.totalWatchSecs)} watched &middot; {userStat.directPlayCount} direct / {userStat.transcodeCount} transcode
                                                </p>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>

                        <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 overflow-hidden">
                            <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
                                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                                    <Flame size={16} className="text-orange-400" />
                                    Most Watched Media Titles
                                </h3>
                                <span className="text-xs text-slate-400">{analytics.topTitles.length} titles</span>
                            </div>
                            <div className="divide-y divide-white/[0.04]">
                                {analytics.topTitles.length === 0 ? (
                                    <div className="py-12 text-center text-xs text-slate-500">
                                        No media titles played in this window yet.
                                    </div>
                                ) : (
                                    analytics.topTitles.map((titleStat, index) => (
                                        <div
                                            key={`${titleStat.itemName}-${index}`}
                                            className="px-5 py-3.5 flex items-center justify-between gap-3 hover:bg-white/[0.02] transition-colors"
                                        >
                                            <div className="flex items-center gap-3 min-w-0">
                                                <span className="w-6 h-6 rounded-lg bg-white/[0.05] border border-white/10 flex items-center justify-center text-xs font-bold text-slate-300 shrink-0">
                                                    {index + 1}
                                                </span>
                                                <div className="min-w-0">
                                                    <div className="flex items-center gap-2">
                                                        <p className="text-sm font-bold text-slate-100 truncate">{titleStat.itemName}</p>
                                                        {titleStat.productionYear ? (
                                                            <span className="text-[13px] font-mono text-slate-300">({titleStat.productionYear})</span>
                                                        ) : null}
                                                    </div>
                                                    <div className="flex flex-wrap items-center gap-1.5 mt-0.5 text-[13px]">
                                                        <span className="px-1.5 py-0.2 rounded bg-purple-500/15 text-purple-300 border border-purple-500/20">
                                                            {titleStat.itemType}
                                                        </span>
                                                        {titleStat.videoResolution && (
                                                            <span className="px-1.5 py-0.2 rounded bg-white/10 text-slate-300 font-mono">
                                                                {titleStat.videoResolution}
                                                            </span>
                                                        )}
                                                        {titleStat.videoCodec && (
                                                            <span className="px-1.5 py-0.2 rounded bg-indigo-500/15 text-indigo-300 font-mono">
                                                                {titleStat.videoCodec}
                                                            </span>
                                                        )}
                                                    </div>
                                                </div>
                                            </div>
                                            <div className="text-right shrink-0">
                                                <div className="flex items-center justify-end gap-2">
                                                    <span className="text-xs font-mono text-teal-300">
                                                        {formatBytes(titleStat.totalDataBytes, 1)}
                                                    </span>
                                                    <span className="text-sm font-bold text-white tabular-nums">
                                                        {titleStat.totalPlays} plays
                                                    </span>
                                                </div>
                                                <p className="text-[13px] text-slate-300 mt-0.5 tabular-nums">
                                                    {titleStat.uniqueViewers} viewer{titleStat.uniqueViewers === 1 ? '' : 's'} &middot; {formatWatchDuration(titleStat.totalWatchSecs)}
                                                </p>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>
                    </div>

                    <StreamingImportedHistory estimates={analytics.historicalEstimates ?? []} windowDays={windowDays} />
                </>
            )}

            {(activeView === 'dashboard' || activeView === 'history') && data && (
                <div className="rounded-xl border border-white/[0.08] bg-slate-900/60 p-5">
                    <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 mb-4 pb-3 border-b border-white/[0.06]">
                        <div>
                            <div className="flex flex-wrap items-center gap-2">
                                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                                    <Clock size={16} className="text-indigo-400" />
                                    Playback & Stream Data Usage Log — Recent Loaded Preview
                                </h3>
                                <span
                                    data-testid="history-result-count"
                                    className="text-xs font-mono px-2.5 py-1 rounded-full bg-indigo-500/15 border border-indigo-500/30 text-indigo-200 font-semibold"
                                >
                                    {filteredHistory.length === 0
                                        ? `0 matching of ${loadedHistory.length} loaded`
                                        : `Showing ${(safeHistoryPage - 1) * historyPageSize + 1}–${Math.min(
                                              safeHistoryPage * historyPageSize,
                                              filteredHistory.length
                                          )} of ${filteredHistory.length} matching`}
                                    {isHistoryBounded
                                        ? ` (${loadedHistory.length} loaded of ${analytics.totalPlays} total)`
                                        : ''}
                                </span>
                            </div>
                            <p className="text-xs text-slate-300 mt-0.5">
                                Detailed per-session audit of play method, codecs, bitrate, data consumed, and completion
                            </p>
                        </div>

                        <div className="flex flex-wrap items-center gap-2">
                            <label htmlFor="history-play-method-select" className="sr-only">
                                Filter history by play method
                            </label>
                            <select
                                id="history-play-method-select"
                                aria-label="Filter history by play method"
                                value={playMethodFilter}
                                onChange={(event) => {
                                    setPlayMethodFilter(event.target.value);
                                    setHistoryPage(1);
                                }}
                                className="min-h-[40px] px-3 py-2 rounded-xl bg-slate-950/60 border border-white/10 text-xs text-slate-200 focus:outline-none focus:border-indigo-500/50"
                            >
                                <option value="all">All Play Methods</option>
                                <option value="DirectPlay">Direct Play</option>
                                <option value="DirectStream">Direct Stream</option>
                                <option value="Transcode">Transcode</option>
                                <option value="Unknown">Unknown (Imported)</option>
                            </select>

                            <label htmlFor="history-page-size-select" className="sr-only">
                                History rows per page
                            </label>
                            <select
                                id="history-page-size-select"
                                aria-label="History rows per page"
                                value={historyPageSize}
                                onChange={(event) => {
                                    setHistoryPageSize(Number(event.target.value) || 10);
                                    setHistoryPage(1);
                                }}
                                className="min-h-[40px] px-3 py-2 rounded-xl bg-slate-950/60 border border-white/10 text-xs text-slate-200 focus:outline-none focus:border-indigo-500/50"
                            >
                                <option value={10}>10 / page</option>
                                <option value={20}>20 / page</option>
                                <option value={25}>25 / page</option>
                                <option value={50}>50 / page</option>
                            </select>

                            <div className="relative w-full sm:w-64">
                                <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                                <input
                                    type="text"
                                    aria-label="Search playback history"
                                    value={historySearch}
                                    onChange={(event) => {
                                        setHistorySearch(event.target.value);
                                        setHistoryPage(1);
                                    }}
                                    placeholder="Search title, user, client, device..."
                                    className="min-h-[40px] w-full pl-9 pr-3 py-2 rounded-xl bg-slate-950/60 border border-white/10 text-xs text-slate-200 placeholder:text-slate-400 focus:outline-none focus:border-indigo-500/50"
                                />
                            </div>

                            <button
                                type="button"
                                onClick={handleExportHistoryCsv}
                                disabled={filteredHistory.length === 0}
                                aria-label={
                                    isHistoryBounded
                                        ? `Export ${filteredHistory.length} loaded rows to CSV`
                                        : `Export ${filteredHistory.length} rows to CSV`
                                }
                                title={
                                    isHistoryBounded
                                        ? `Exports the ${filteredHistory.length} loaded matching rows (${analytics.totalPlays} total records exist in backend window)`
                                        : `Export ${filteredHistory.length} matching rows to CSV`
                                }
                                className="min-h-[40px] px-3.5 py-2 rounded-xl text-xs font-medium bg-slate-850 hover:bg-slate-750 disabled:opacity-40 disabled:cursor-not-allowed border border-white/10 text-slate-200 flex items-center gap-1.5 transition-all"
                            >
                                <Download size={13} />
                                <span>
                                    {isHistoryBounded
                                        ? `Export Loaded CSV (${filteredHistory.length})`
                                        : `Export CSV (${filteredHistory.length})`}
                                </span>
                            </button>
                        </div>
                    </div>

                    {(isHistoryBounded || hasHistoricalSyncImports) && (
                        <div className="mb-4 flex flex-col gap-2">
                            {isHistoryBounded && (
                                <div
                                    data-testid="bounded-history-notice"
                                    className="px-3.5 py-2 rounded-xl border border-amber-500/35 bg-amber-500/15 text-xs text-amber-200 flex items-center justify-between gap-2"
                                >
                                    <span>
                                        Showing the most recent <strong>{loadedHistory.length}</strong> loaded history rows out of{' '}
                                        <strong>{analytics.totalPlays}</strong> total plays in the selected window. Search and CSV export operate on loaded rows.
                                    </span>
                                </div>
                            )}
                            {hasHistoricalSyncImports && (
                                <div
                                    data-testid="historical-estimate-notice"
                                    className="px-3.5 py-2 rounded-xl border border-slate-400/35 bg-slate-800/70 text-xs text-slate-200 flex items-center justify-between gap-2"
                                >
                                    <span>
                                        <strong className="text-white font-semibold">Historical Import Limitation:</strong> Jellyfin played-item imports are last-played summaries, not complete session logs. Client, delivery method and transfer bytes are unrecorded. Retained legacy byte values and live-poll transfer totals are estimates, not measured network traffic.
                                    </span>
                                </div>
                            )}
                        </div>
                    )}

                    <div className="overflow-x-auto min-w-0 max-w-full">
                        <table className="w-full text-left border-collapse text-xs">
                            <thead>
                                <tr className="border-b border-white/[0.06] text-slate-400 uppercase tracking-wider text-xs">
                                    <th className="py-2.5 px-3 font-semibold">Title</th>
                                    <th className="py-2.5 px-3 font-semibold">Playback Time (UTC)</th>
                                    <th className="py-2.5 px-3 font-semibold">User</th>
                                    <th className="py-2.5 px-3 font-semibold">Client & Device</th>
                                    <th className="py-2.5 px-3 font-semibold">Stream Pipeline</th>
                                    <th className="py-2.5 px-3 font-semibold">Data & Bitrate</th>
                                    <th className="py-2.5 px-3 font-semibold">Watched</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-white/[0.04]">
                                {error && loadedHistory.length === 0 ? (
                                    <tr>
                                        <td colSpan={7} className="py-10 text-center text-red-400">
                                            Failed to load playback history
                                        </td>
                                    </tr>
                                ) : filteredHistory.length === 0 ? (
                                    <tr>
                                        <td colSpan={7} className="py-10 text-center text-slate-400">
                                            No playback history entries match the current filter.
                                        </td>
                                    </tr>
                                ) : (
                                    paginatedHistory.map((historyItem) => {
                                        const methodStyle = getPlayMethodStyle(historyItem.playMethod);
                                        const episodeBadge = formatEpisodeBadge(historyItem.seasonNumber, historyItem.episodeNumber);
                                        const isSyncedEstimate = isHistoricalSyncEntry(historyItem);
                                        const playbackTime = parseStreamingTimestamp(historyItem.startedAt || historyItem.lastSeenAt);
                                        return (
                                            <tr key={historyItem.id} className="hover:bg-white/[0.02] transition-colors">
                                                <td className="py-3 px-3">
                                                    <div className="flex items-center gap-2">
                                                        {historyItem.isActive && (
                                                            <span
                                                                className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse shrink-0"
                                                                title="Currently Playing"
                                                            />
                                                        )}
                                                        <div>
                                                            <p className="font-bold text-slate-100">
                                                                {historyItem.seriesName ? `${historyItem.seriesName} · ` : ''}
                                                                {episodeBadge ? `${episodeBadge} — ` : ''}
                                                                {historyItem.itemName}
                                                            </p>
                                                            <p className="text-xs text-slate-400 mt-0.5">
                                                                {historyItem.itemType} {historyItem.productionYear ? `(${historyItem.productionYear})` : ''} &middot; {historyItem.serverName}
                                                            </p>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td className="py-3 px-3 whitespace-nowrap text-slate-300">
                                                    <time dateTime={playbackTime?.toISOString()}>
                                                        {playbackTime ? `${playbackTime.toISOString().slice(0, 19).replace('T', ' ')} UTC` : 'Unknown date'}
                                                    </time>
                                                </td>
                                                <td className="py-3 px-3 font-semibold text-slate-200">{historyItem.userName}</td>
                                                <td className="py-3 px-3">
                                                    <p className="text-slate-200">{historyItem.clientName || (isSyncedEstimate ? 'Historical Import' : 'Unknown Client')}</p>
                                                    <p className="text-xs text-slate-400">
                                                        {historyItem.deviceName || (isSyncedEstimate ? 'Unrecorded device' : 'Unknown device')} {historyItem.ipAddress ? `· ${historyItem.ipAddress}` : ''}
                                                    </p>
                                                </td>
                                                <td className="py-3 px-3">
                                                    <div className="flex flex-wrap items-center gap-1">
                                                        <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${methodStyle.badge}`}>
                                                            {methodStyle.label}
                                                            {historyItem.hwAccel ? ` (${historyItem.hwAccel})` : ''}
                                                        </span>
                                                        <span className="text-xs font-mono bg-white/[0.06] text-slate-300 px-1.5 py-0.5 rounded">
                                                            {[historyItem.videoResolution, [historyItem.videoCodec, historyItem.audioCodec].filter(Boolean).join(' / ')].filter(Boolean).join(' · ') || 'Unrecorded pipeline'}
                                                        </span>
                                                    </div>
                                                </td>
                                                <td className="py-3 px-3 font-mono">
                                                    <div className="flex items-center gap-1.5">
                                                        <p className="text-teal-300 font-bold">
                                                            {isSyncedEstimate && (!historyItem.dataUsedBytes || historyItem.dataUsedBytes <= 0)
                                                                ? 'Unrecorded'
                                                                : formatBytes(historyItem.dataUsedBytes, 2)}
                                                        </p>
                                                        {isSyncedEstimate && (
                                                            <span
                                                                className="text-xs font-sans font-semibold px-1.5 py-0.2 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30"
                                                                title="Imported from Jellyfin played-item history; live session bytes and delivery method were not measured"
                                                            >
                                                                {historyItem.dataUsedBytes && historyItem.dataUsedBytes > 0 ? 'Est.' : 'Sync'}
                                                            </span>
                                                        )}
                                                    </div>
                                                    <p className="text-xs text-slate-400">{formatBandwidthMbps(historyItem.bandwidthMbps, historyItem.bitrateBps)} Mbps</p>
                                                </td>
                                                <td className="py-3 px-3">
                                                    <div className="flex items-center gap-2">
                                                        <div className="w-20 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                                                            <div
                                                                className="h-full bg-indigo-500 rounded-full"
                                                                style={{ width: `${Math.min(100, Number.isFinite(historyItem.completionPct) ? historyItem.completionPct : 0)}%` }}
                                                            />
                                                        </div>
                                                        <span className="text-xs font-mono text-slate-300">
                                                            {Math.round(Number.isFinite(historyItem.completionPct) ? historyItem.completionPct : 0)}%
                                                        </span>
                                                    </div>
                                                    <p className="text-xs text-slate-400 mt-0.5">
                                                        {formatWatchDuration(historyItem.watchedSecs)} / {formatWatchDuration(historyItem.durationSecs)}
                                                    </p>
                                                </td>
                                            </tr>
                                        );
                                    })
                                )}
                            </tbody>
                        </table>
                    </div>

                    {filteredHistory.length > 0 && (
                        <div className="mt-4 pt-3 border-t border-white/[0.06] flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
                            <span>
                                Page <strong className="text-slate-200">{safeHistoryPage}</strong> of{' '}
                                <strong className="text-slate-200">{totalHistoryPages}</strong> ({filteredHistory.length} matching row
                                {filteredHistory.length === 1 ? '' : 's'})
                            </span>
                            <div className="flex items-center gap-2">
                                <button
                                    type="button"
                                    aria-label="Previous loaded history page"
                                    disabled={safeHistoryPage <= 1}
                                    onClick={() => setHistoryPage((page) => Math.max(1, page - 1))}
                                    className="px-2.5 py-1 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] disabled:opacity-40 disabled:cursor-not-allowed border border-white/10 text-slate-200 flex items-center gap-1"
                                >
                                    <ChevronLeft size={13} />
                                    <span>Previous</span>
                                </button>
                                <button
                                    type="button"
                                    aria-label="Next loaded history page"
                                    disabled={safeHistoryPage >= totalHistoryPages}
                                    onClick={() => setHistoryPage((page) => Math.min(totalHistoryPages, page + 1))}
                                    className="px-2.5 py-1 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] disabled:opacity-40 disabled:cursor-not-allowed border border-white/10 text-slate-200 flex items-center gap-1"
                                >
                                    <span>Next</span>
                                    <ChevronRight size={13} />
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            )}

            {(activeView === 'dashboard' || activeView === 'history' || activeView === 'analytics') && <StreamingHistoryExplorer />}

            {showConfigModal && (
                <StreamingDialog name="Media Server Providers" onClose={closeConfig}>
                    <div
                        className="w-full max-w-xl rounded-2xl border border-indigo-500/30 bg-slate-950/95 p-4 sm:p-6 shadow-2xl space-y-4 sm:space-y-5"
                        onClick={(event) => event.stopPropagation()}
                    >
                        <div className="flex items-center justify-between pb-3 border-b border-white/10 gap-2">
                            <div className="flex items-center gap-2.5 sm:gap-3 min-w-0">
                                <div className="h-9 w-9 sm:h-10 sm:w-10 rounded-xl bg-purple-500/20 border border-purple-500/30 flex items-center justify-center text-purple-300 shrink-0">
                                    <Server size={18} className="sm:hidden" />
                                    <Server size={20} className="hidden sm:block" />
                                </div>
                                <div className="min-w-0">
                                    <h3 className="text-sm sm:text-base font-bold text-white break-words">Media Server Providers</h3>
                                    <p className="text-xs text-slate-400 leading-snug">
                                        Jellyfin telemetry and staged Emby configuration. Real-provider acceptance remains pending.
                                    </p>
                                </div>
                            </div>
                            <button
                                type="button"
                                onClick={closeConfig}
                                className="obs-touch-target-standard min-h-[44px] min-w-[44px] sm:min-h-[40px] sm:min-w-[40px] p-2 rounded-xl text-slate-400 hover:text-white hover:bg-white/10 shrink-0 flex items-center justify-center transition-colors"
                                aria-label="Close modal"
                            >
                                <X size={18} />
                            </button>
                        </div>

                        <div className="grid grid-cols-1 min-[360px]:grid-cols-3 gap-2 sm:gap-2.5">
                            <div className="rounded-xl border border-purple-500/40 bg-purple-500/10 p-2.5 sm:p-3 min-w-0">
                                <div className="flex flex-wrap items-center justify-between gap-1">
                                    <span className="text-xs font-bold text-white shrink-0">Jellyfin</span>
                                    <span className="text-xs font-bold uppercase px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 shrink-0">
                                        Active
                                    </span>
                                </div>
                                <p className="text-xs text-slate-300 mt-1">Full stream, codec & bandwidth telemetry</p>
                            </div>
                            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-2.5 sm:p-3 opacity-70 min-w-0">
                                <div className="flex flex-wrap items-center justify-between gap-1">
                                    <span className="text-xs font-bold text-slate-300 shrink-0">Plex</span>
                                    <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-white/10 text-slate-400 shrink-0">
                                        {isPlexObserved ? 'Observed' : 'Planned'}
                                    </span>
                                </div>
                                <p className="text-xs text-slate-400 mt-1">
                                    {isPlexObserved
                                        ? 'Observed stream telemetry from Plex session'
                                        : 'Planned integration · X-Plex-Token session adapter'}
                                </p>
                            </div>
                            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-2.5 sm:p-3 opacity-70 min-w-0">
                                <div className="flex flex-wrap items-center justify-between gap-1">
                                    <span className="text-xs font-bold text-slate-300 shrink-0">Emby</span>
                                    <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-white/10 text-slate-400 shrink-0">
                                        Planned
                                    </span>
                                </div>
                                <p className="text-xs text-slate-400 mt-1">Planned integration · Staged telemetry</p>
                            </div>
                        </div>

                        <form onSubmit={handleSaveConfig} className="space-y-4">
                            <label className="block text-sm">Provider
                                <select aria-label="Provider" value={configProvider} disabled={isSavingConn || isTestingConn}
                                    onChange={event => selectConfigProvider(event.target.value as 'jellyfin' | 'emby')}
                                    className="block w-full bg-slate-900 rounded-lg p-2">
                                    <option value="jellyfin">Jellyfin</option><option value="emby">Emby (staged)</option>
                                </select>
                            </label>
                            <label className="flex items-center gap-2 text-sm">
                                <input type="checkbox" checked={serverEnabledInput} onChange={event => {
                                    configRevision.current += 1; setServerEnabledInput(event.target.checked);
                                }} />Enable provider collection
                            </label>
                            <p className="text-xs text-slate-400">Disabling preserves credentials and historical evidence. Credential removal is not supported here. Unchanged masked keys preserve the saved secret. Emby commands and item-summary synchronization are unsupported.</p>
                            <div>
                                <label
                                    htmlFor="jellyfin-server-name-input"
                                    className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-1.5"
                                >
                                    Server Display Name
                                </label>
                                <input
                                    id="jellyfin-server-name-input"
                                    type="text"
                                    value={serverNameInput}
                                    onChange={(event) => { configRevision.current += 1; setServerNameInput(event.target.value); }}
                                    placeholder="AetherFlow Jellyfin"
                                    className="w-full px-3.5 py-2.5 rounded-xl bg-black/50 border border-white/10 text-sm text-white focus:outline-none focus:border-indigo-500"
                                />
                            </div>

                            <div>
                                <label
                                    htmlFor="jellyfin-server-url-input"
                                    className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-1.5"
                                >
                                    {configProvider === 'emby' ? 'Emby' : 'Jellyfin'} Server URL
                                </label>
                                <input
                                    id="jellyfin-server-url-input"
                                    type="text"
                                    value={serverUrlInput}
                                    onChange={(event) => { configRevision.current += 1; setServerUrlInput(event.target.value); }}
                                    placeholder="http://127.0.0.1:8096"
                                    required
                                    className="w-full px-3.5 py-2.5 rounded-xl bg-black/50 border border-white/10 text-sm text-white font-mono focus:outline-none focus:border-indigo-500"
                                />
                            </div>

                            <div>
                                <label
                                    htmlFor="jellyfin-api-key-input"
                                    className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-1.5"
                                >
                                    {configProvider === 'emby' ? 'Emby' : 'Jellyfin'} API Key
                                </label>
                                <input
                                    id="jellyfin-api-key-input"
                                    type="password"
                                    value={apiKeyInput}
                                    onChange={(event) => { configRevision.current += 1; setApiKeyInput(event.target.value); }}
                                    placeholder="Paste API key from Jellyfin Dashboard → Advanced → API Keys"
                                    className="w-full px-3.5 py-2.5 rounded-xl bg-black/50 border border-white/10 text-sm text-white font-mono focus:outline-none focus:border-indigo-500"
                                />
                                <p className="text-xs text-slate-400 mt-1 flex items-center gap-1">
                                    <ShieldCheck size={12} className="text-emerald-400" />
                                    Encrypted at rest with AES-256-GCM in SQLite WAL.
                                </p>
                            </div>

                            {testResultMsg && (
                                <div
                                    className={`p-3 rounded-xl border text-xs flex items-center gap-2 ${
                                        testResultMsg.ok
                                            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                                            : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                                    }`}
                                >
                                    {testResultMsg.ok ? <CheckCircle2 size={15} /> : <AlertCircle size={15} />}
                                    <span>{testResultMsg.text}</span>
                                </div>
                            )}

                            <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-white/10">
                                <button
                                    type="button"
                                    onClick={handleTestConnection}
                                    disabled={isTestingConn}
                                    className="obs-touch-target-standard min-h-[44px] sm:min-h-[40px] px-4 py-2.5 rounded-xl text-xs font-bold bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-slate-200 flex items-center justify-center gap-1.5 transition-all"
                                >
                                    {isTestingConn ? <Loader2 size={14} className="animate-spin" /> : <Wifi size={14} />}
                                    <span>Test Connection</span>
                                </button>

                                <div className="flex flex-wrap items-center gap-2">
                                    <button
                                        type="button"
                                        onClick={closeConfig}
                                        className="obs-touch-target-standard min-h-[44px] sm:min-h-[40px] px-4 py-2.5 rounded-xl text-xs font-semibold text-slate-400 hover:text-white flex items-center justify-center transition-colors"
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        type="submit"
                                        disabled={isSavingConn || isTestingConn}
                                        className="obs-touch-target-standard min-h-[44px] sm:min-h-[40px] px-5 py-2.5 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-500/25 flex items-center justify-center gap-1.5 transition-all"
                                    >
                                        {isSavingConn ? <Loader2 size={14} className="animate-spin" /> : <CheckCircle2 size={14} />}
                                        <span>Save Connection</span>
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </StreamingDialog>
            )}

            {!isAdmin && (
                <p role="note" className="text-sm text-slate-400">
                    Shared legacy dashboard statistics are withheld for privacy. Your explicitly linked playback records are available in the canonical archive.
                </p>
            )}

            {messageSession && (
                <StreamingDialog name={`Message ${messageSession.userName}`} onClose={closeMessage}>
                    <form
                        onSubmit={handleSendSessionMessage}
                        className="w-full max-w-md rounded-2xl border border-indigo-500/30 bg-slate-950/95 p-6 shadow-2xl space-y-4"
                        onClick={(event) => event.stopPropagation()}
                    >
                        <div className="flex items-center justify-between pb-2 border-b border-white/10">
                            <h3 className="text-sm font-bold text-white flex items-center gap-2">
                                <MessageSquare size={16} className="text-indigo-400" />
                                Message {messageSession.userName} ({messageSession.deviceName})
                            </h3>
                            <button
                                type="button"
                                aria-label="Close message modal"
                                onClick={closeMessage}
                                className="p-1 text-slate-400 hover:text-white"
                            >
                                <X size={16} />
                            </button>
                        </div>

                        <div>
                            <label htmlFor="session-message-header" className="block text-xs font-semibold text-slate-400 mb-1">
                                Header
                            </label>
                            <input
                                id="session-message-header"
                                type="text"
                                value={messageHeader}
                                onChange={(event) => setMessageHeader(event.target.value)}
                                className="w-full px-3 py-2 rounded-xl bg-black/50 border border-white/10 text-xs text-white"
                            />
                        </div>

                        <div>
                            <label htmlFor="session-message-body" className="block text-xs font-semibold text-slate-400 mb-1">
                                Message
                            </label>
                            <textarea
                                id="session-message-body"
                                rows={3}
                                value={messageBody}
                                onChange={(event) => setMessageBody(event.target.value)}
                                placeholder="Enter message to display on viewer's screen..."
                                required
                                className="w-full px-3 py-2 rounded-xl bg-black/50 border border-white/10 text-xs text-white"
                            />
                        </div>

                        <div className="flex justify-end gap-2 pt-2">
                            <button
                                type="button"
                                onClick={closeMessage}
                                className="px-3 py-1.5 rounded-xl text-xs text-slate-400 hover:text-white"
                            >
                                Cancel
                            </button>
                            <button
                                type="submit"
                                disabled={isSendingMessage}
                                className="px-4 py-1.5 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 text-white flex items-center gap-1.5"
                            >
                                {isSendingMessage ? <Loader2 size={13} className="animate-spin" /> : <Send size={13} />}
                                <span>Send Message</span>
                            </button>
                        </div>
                    </form>
                </StreamingDialog>
            )}
        </div>
    );
}
