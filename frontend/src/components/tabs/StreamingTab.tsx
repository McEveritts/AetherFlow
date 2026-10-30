'use client';

import React, { useState, useMemo } from 'react';
import useSWR from 'swr';
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
    ArrowRight,
    X,
    Send,
    Loader2,
    ShieldCheck,
    Music,
    Database
} from 'lucide-react';
import {
    AreaChart,
    Area,
    BarChart,
    Bar,
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
    status: 'connected' | 'unreachable' | 'unconfigured' | 'coming_soon' | 'demo';
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
    timeSeries: StreamingTimeSeriesPoint[];
    topUsers: StreamingUserStat[];
    topTitles: StreamingTitleStat[];
    recentHistory: StreamingHistoryItem[];
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
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
}

function formatDurationClock(secs: number): string {
    if (!secs || secs <= 0) return '0:00';
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = Math.floor(secs % 60);
    if (h > 0) {
        return `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
    }
    return `${m}:${String(s).padStart(2, '0')}`;
}

function formatWatchDuration(secs: number): string {
    if (!secs || secs <= 0) return '0m';
    if (secs < 60) return `${secs}s`;
    const hours = Math.floor(secs / 3600);
    const mins = Math.floor((secs % 3600) / 60);
    if (hours === 0) return `${mins}m`;
    if (hours < 24) return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
    const days = Math.floor(hours / 24);
    const remHours = hours % 24;
    return remHours > 0 ? `${days}d ${remHours}h` : `${days}d`;
}

function formatEpisodeBadge(season?: number, episode?: number): string | null {
    if (season == null && episode == null) return null;
    if (!season && !episode) return null;
    return `S${String(season ?? 1).padStart(2, '0')}E${String(episode ?? 1).padStart(2, '0')}`;
}

function formatTranscodeReason(reason: string): string {
    return reason
        .replace(/([A-Z])/g, ' $1')
        .replace(/^./, (s) => s.toUpperCase())
        .trim();
}

function getPlayMethodStyle(method: string) {
    switch (method) {
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
        default:
            return {
                label: 'Direct Play',
                badge: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
                dot: 'bg-emerald-400',
                bar: 'bg-gradient-to-r from-emerald-500 to-teal-400',
            };
    }
}

export default function StreamingTab() {
    const { user } = useAuth();
    const { addToast } = useToast();
    const { hapticFeedback } = useSystemStore();
    const isAdmin = user?.role === 'admin';

    // View & filter state
    const [activeView, setActiveView] = useState<'dashboard' | 'streams' | 'analytics' | 'history'>('dashboard');
    const [windowDays, setWindowDays] = useState<number>(30);
    const [playMethodFilter, setPlayMethodFilter] = useState<string>('all');
    const [mediaTypeFilter, setMediaTypeFilter] = useState<string>('all');
    const [historySearch, setHistorySearch] = useState<string>('');

    // Server Configuration Drawer state
    const [showConfigModal, setShowConfigModal] = useState<boolean>(false);
    const [serverNameInput, setServerNameInput] = useState<string>('Jellyfin');
    const [serverUrlInput, setServerUrlInput] = useState<string>('http://127.0.0.1:8096');
    const [apiKeyInput, setApiKeyInput] = useState<string>('');
    const [isTestingConn, setIsTestingConn] = useState<boolean>(false);
    const [isSavingConn, setIsSavingConn] = useState<boolean>(false);
    const [isSyncingHistory, setIsSyncingHistory] = useState<boolean>(false);
    const [isDemoLoading, setIsDemoLoading] = useState<boolean>(false);
    const [testResultMsg, setTestResultMsg] = useState<{ ok: boolean; text: string } | null>(null);

    // Message modal state for active stream
    const [messageSession, setMessageSession] = useState<ActiveStreamSession | null>(null);
    const [messageHeader, setMessageHeader] = useState<string>('AetherFlow Notice');
    const [messageBody, setMessageBody] = useState<string>('');
    const [isSendingMessage, setIsSendingMessage] = useState<boolean>(false);

    const swrKey = `/api/v1/auth/streaming/dashboard?window=${windowDays}&playMethod=${playMethodFilter}&mediaType=${mediaTypeFilter}`;
    const { data, error, isLoading, isValidating, mutate } = useSWR<StreamingDashboardData>(swrKey, fetcher, {
        refreshInterval: 5000,
        revalidateOnFocus: true,
    });

    const jellyfinServer = useMemo(() => {
        return data?.servers?.find((s) => s.provider === 'jellyfin') || {
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

    const openServerConfig = () => {
        triggerHaptic(8, hapticFeedback);
        setServerNameInput(jellyfinServer.name || 'Jellyfin');
        setServerUrlInput(jellyfinServer.url || 'http://127.0.0.1:8096');
        setApiKeyInput(jellyfinServer.apiKeyMasked || '');
        setTestResultMsg(null);
        setShowConfigModal(true);
    };

    const handleTestConnection = async () => {
        setIsTestingConn(true);
        setTestResultMsg(null);
        try {
            const res = await apiFetch('/api/v1/admin/streaming/servers/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    provider: 'jellyfin',
                    url: serverUrlInput,
                    apiKey: apiKeyInput,
                }),
            });
            const body = await res.json();
            if (body.ok) {
                setTestResultMsg({ ok: true, text: body.message || 'Connected to Jellyfin successfully!' });
                addToast(body.message || 'Jellyfin connection verified', 'success');
            } else {
                setTestResultMsg({ ok: false, text: body.message || 'Could not authenticate with Jellyfin' });
            }
        } catch (err: unknown) {
            setTestResultMsg({ ok: false, text: err instanceof Error ? err.message : 'Connection test failed' });
        } finally {
            setIsTestingConn(false);
        }
    };

    const handleSaveConfig = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSavingConn(true);
        try {
            const res = await apiFetch('/api/v1/admin/streaming/servers/jellyfin', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: serverNameInput,
                    url: serverUrlInput,
                    apiKey: apiKeyInput,
                    enabled: true,
                }),
            });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.message || 'Failed to save Jellyfin configuration');
            }
            await mutate();
            setShowConfigModal(false);
            addToast('Jellyfin server saved and telemetry linked.', 'success');
        } catch (err: unknown) {
            addToast(err instanceof Error ? err.message : 'Failed to save Jellyfin configuration', 'error');
        } finally {
            setIsSavingConn(false);
        }
    };

    const handleSyncHistory = async () => {
        setIsSyncingHistory(true);
        try {
            const res = await apiFetch('/api/v1/admin/streaming/servers/jellyfin/sync', {
                method: 'POST',
            });
            const body = await res.json();
            if (!res.ok) {
                throw new Error(body.message || 'History sync failed');
            }
            await mutate();
            addToast(`Synchronized Jellyfin watch history (${body.imported ?? 0} new records imported).`, 'success');
        } catch (err: unknown) {
            addToast(err instanceof Error ? err.message : 'Failed to sync Jellyfin history', 'error');
        } finally {
            setIsSyncingHistory(false);
        }
    };

    const handleToggleDemo = async (action: 'seed' | 'clear') => {
        setIsDemoLoading(true);
        try {
            const res = await apiFetch('/api/v1/admin/streaming/demo', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action }),
            });
            if (!res.ok) {
                throw new Error('Failed to toggle demo telemetry');
            }
            await mutate();
            addToast(
                action === 'seed'
                    ? 'Demo Jellyfin streams, codecs, and bandwidth telemetry loaded.'
                    : 'Demo telemetry cleared.',
                'info'
            );
        } catch {
            addToast('Failed to update demo telemetry state', 'error');
        } finally {
            setIsDemoLoading(false);
        }
    };

    const handleSessionCommand = async (sessionId: string, command: 'pause' | 'resume' | 'stop') => {
        triggerHaptic(8, hapticFeedback);
        try {
            const res = await apiFetch(`/api/v1/admin/streaming/sessions/${encodeURIComponent(sessionId)}/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command }),
            });
            if (!res.ok) {
                const body = await res.json().catch(() => ({}));
                throw new Error(body.message || `Failed to ${command} session`);
            }
            await mutate();
            addToast(`Sent ${command} command to stream session.`, 'success');
        } catch (err: unknown) {
            addToast(err instanceof Error ? err.message : `Command ${command} failed`, 'error');
        }
    };

    const handleSendSessionMessage = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!messageSession || !messageBody.trim()) return;
        setIsSendingMessage(true);
        try {
            const res = await apiFetch(`/api/v1/admin/streaming/sessions/${encodeURIComponent(messageSession.sessionId)}/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    command: 'message',
                    header: messageHeader,
                    message: messageBody,
                }),
            });
            if (!res.ok) {
                throw new Error('Failed to send message to client');
            }
            addToast(`Message delivered to ${messageSession.userName} (${messageSession.deviceName})`, 'success');
            setMessageSession(null);
            setMessageBody('');
        } catch (err: unknown) {
            addToast(err instanceof Error ? err.message : 'Failed to deliver message', 'error');
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

    const filteredHistory = useMemo(() => {
        const list = analytics.recentHistory || [];
        const q = historySearch.trim().toLowerCase();
        if (!q) return list;
        return list.filter(
            (item) =>
                item.itemName.toLowerCase().includes(q) ||
                (item.seriesName && item.seriesName.toLowerCase().includes(q)) ||
                item.userName.toLowerCase().includes(q) ||
                item.clientName.toLowerCase().includes(q) ||
                item.deviceName.toLowerCase().includes(q) ||
                item.videoCodec.toLowerCase().includes(q) ||
                item.playMethod.toLowerCase().includes(q)
        );
    }, [analytics.recentHistory, historySearch]);

    const chartData = useMemo(() => {
        return (analytics.timeSeries || []).map((pt) => ({
            ...pt,
            watchHours: Math.round((pt.watchTimeSecs / 3600) * 100) / 100,
            dataGB: Math.round((pt.dataUsedBytes / (1024 * 1024 * 1024)) * 100) / 100,
        }));
    }, [analytics.timeSeries]);

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-w-0">
            {/* ========================================================================= */}
            {/* 1. TOP COMMAND HEADER & MULTI-SERVER PROVIDER BAR                         */}
            {/* ========================================================================= */}
            <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-4 border-b border-white/[0.06] relative z-30">
                <div className="flex items-start sm:items-center gap-3.5">
                    <div className="h-11 w-11 rounded-2xl flex items-center justify-center border bg-indigo-500/20 border-indigo-500/30 shadow-[0_0_24px_rgba(99,102,241,0.2)] text-indigo-400 shrink-0">
                        <Tv size={22} />
                    </div>
                    <div>
                        <div className="flex flex-wrap items-center gap-2.5">
                            <h2 className="text-lg md:text-xl font-extrabold text-slate-100 tracking-tight">
                                Streaming Dashboard
                            </h2>
                            {/* Jellyfin Active Provider Pill */}
                            <button
                                type="button"
                                onClick={isAdmin ? openServerConfig : undefined}
                                className={`inline-flex items-center gap-1.5 text-xs font-bold px-2.5 py-0.5 rounded-full border transition-all ${
                                    jellyfinServer.status === 'connected'
                                        ? 'bg-purple-500/15 text-purple-300 border-purple-500/30 hover:bg-purple-500/25'
                                        : jellyfinServer.status === 'demo'
                                        ? 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30 hover:bg-indigo-500/25'
                                        : 'bg-amber-500/15 text-amber-300 border-amber-500/30 hover:bg-amber-500/25'
                                }`}
                                title="Click to configure Jellyfin connection"
                            >
                                <span
                                    className={`h-1.5 w-1.5 rounded-full ${
                                        jellyfinServer.status === 'connected'
                                            ? 'bg-emerald-400 shadow-[0_0_6px_#34d399]'
                                            : jellyfinServer.status === 'demo'
                                            ? 'bg-indigo-400 shadow-[0_0_6px_#818cf8]'
                                            : 'bg-amber-400'
                                    }`}
                                />
                                <span>
                                    Jellyfin
                                    {jellyfinServer.version ? ` v${jellyfinServer.version}` : ''}
                                    {jellyfinServer.status === 'demo' ? ' (Demo Preview)' : ''}
                                </span>
                            </button>

                            {/* Upcoming Providers: Plex & Emby */}
                            <span
                                className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full border bg-white/[0.03] text-slate-400 border-white/10"
                                title="Plex integration is planned for a future update"
                            >
                                <span className="h-1.5 w-1.5 rounded-full bg-amber-400/50" />
                                Plex · Later
                            </span>
                            <span
                                className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full border bg-white/[0.03] text-slate-400 border-white/10"
                                title="Emby integration is planned for a future update"
                            >
                                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400/50" />
                                Emby · Later
                            </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">
                            Real-time stream inspector, codec & transcode pipeline monitor, data usage telemetry, and historical watch analytics
                        </p>
                    </div>
                </div>

                {/* View Switcher & Action Controls */}
                <div className="flex flex-wrap items-center gap-2">
                    <div className="flex items-center gap-1 p-1 bg-white/[0.04] border border-white/10 rounded-xl">
                        {([
                            { id: 'dashboard', label: 'Dashboard', icon: Tv },
                            { id: 'streams', label: `Live (${liveSummary.activeStreams})`, icon: Radio },
                            { id: 'analytics', label: 'Play & Data Stats', icon: Activity },
                            { id: 'history', label: 'Watch History', icon: Clock },
                        ] as const).map((tab) => {
                            const Icon = tab.icon;
                            const isActive = activeView === tab.id;
                            return (
                                <button
                                    key={tab.id}
                                    type="button"
                                    onClick={() => {
                                        triggerHaptic(6, hapticFeedback);
                                        setActiveView(tab.id);
                                    }}
                                    className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                                        isActive
                                            ? 'bg-indigo-500/20 border border-indigo-500/30 text-indigo-300 shadow-md shadow-indigo-500/10'
                                            : 'text-slate-400 hover:text-white'
                                    }`}
                                >
                                    <Icon size={13} />
                                    <span>{tab.label}</span>
                                </button>
                            );
                        })}
                    </div>

                    {isAdmin && (
                        <>
                            {jellyfinServer.status === 'connected' && (
                                <button
                                    type="button"
                                    onClick={handleSyncHistory}
                                    disabled={isSyncingHistory}
                                    className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-purple-500/15 border border-purple-500/30 text-purple-300 hover:bg-purple-500/25 transition-all disabled:opacity-50"
                                    title="Import played media items and watch history from Jellyfin"
                                >
                                    <Database size={13} className={isSyncingHistory ? 'animate-pulse' : ''} />
                                    <span>{isSyncingHistory ? 'Syncing...' : 'Sync Jellyfin'}</span>
                                </button>
                            )}

                            <button
                                type="button"
                                onClick={openServerConfig}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-200 hover:bg-white/[0.08] transition-all"
                            >
                                <Settings2 size={14} className="text-indigo-400" />
                                <span>Configure Server</span>
                            </button>
                        </>
                    )}

                    <button
                        type="button"
                        onClick={() => mutate()}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all"
                        title="Refresh Streaming Telemetry"
                    >
                        <RefreshCw size={14} className={isValidating ? 'animate-spin text-indigo-400' : 'text-slate-400'} />
                        <span className="hidden sm:inline">Refresh</span>
                    </button>
                </div>
            </div>

            {/* ========================================================================= */}
            {/* 2. CONNECTION ONBOARDING / DEMO BANNER (WHEN UNCONFIGURED)                */}
            {/* ========================================================================= */}
            {jellyfinServer.status !== 'connected' && (
                <div className="rounded-2xl border border-indigo-500/30 bg-gradient-to-r from-indigo-950/40 via-slate-900/60 to-purple-950/30 backdrop-blur-xl p-4 sm:p-5 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
                    <div className="flex items-start gap-3.5">
                        <div className="w-10 h-10 rounded-xl bg-purple-500/20 border border-purple-500/30 flex items-center justify-center text-purple-300 shrink-0 mt-0.5">
                            <Server size={20} />
                        </div>
                        <div>
                            <div className="flex flex-wrap items-center gap-2">
                                <h3 className="text-sm font-bold text-white">
                                    {liveSummary.isDemoMode
                                        ? 'Demo Telemetry Active — Connect Your Jellyfin Server Anytime'
                                        : 'Connect Jellyfin to Track Live Streams, Bandwidth & Play Statistics'}
                                </h3>
                                <span className="text-xs font-mono uppercase px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30">
                                    Jellyfin First · Plex & Emby Coming Later
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
                            <button
                                type="button"
                                onClick={openServerConfig}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive px-4 py-2 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-500/25 flex items-center gap-1.5 transition-all"
                            >
                                <Settings2 size={14} />
                                <span>Connect Jellyfin</span>
                            </button>
                            {liveSummary.isDemoMode ? (
                                <button
                                    type="button"
                                    onClick={() => handleToggleDemo('clear')}
                                    disabled={isDemoLoading}
                                    className="obs-touch-target-standard obs-gpu-120hz-interactive px-3.5 py-2 rounded-xl text-xs font-semibold bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-slate-200 flex items-center gap-1.5 transition-all"
                                >
                                    <X size={14} />
                                    <span>Clear Demo Data</span>
                                </button>
                            ) : (
                                <button
                                    type="button"
                                    onClick={() => handleToggleDemo('seed')}
                                    disabled={isDemoLoading}
                                    className="obs-touch-target-standard obs-gpu-120hz-interactive px-3.5 py-2 rounded-xl text-xs font-semibold bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/30 text-purple-200 flex items-center gap-1.5 transition-all"
                                >
                                    <Sparkles size={14} />
                                    <span>{isDemoLoading ? 'Loading...' : 'Load Demo Telemetry'}</span>
                                </button>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* ========================================================================= */}
            {/* 3. REAL-TIME TELEMETRY & DATA USAGE KPI STRIP                             */}
            {/* ========================================================================= */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
                {/* KPI 1: Active Streams */}
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex flex-col justify-between">
                    <div className="flex items-center justify-between">
                        <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Active Streams</span>
                        <div className="h-9 w-9 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                            <Radio size={18} />
                        </div>
                    </div>
                    <div className="mt-2">
                        <div className="flex items-baseline gap-2">
                            <span className="text-2xl font-extrabold text-white tabular-nums">{liveSummary.activeStreams}</span>
                            <span className="text-xs text-slate-400">
                                {liveSummary.lanStreams} LAN · {liveSummary.wanStreams} WAN
                            </span>
                        </div>
                        <div className="flex flex-wrap items-center gap-1.5 mt-2 text-xs font-semibold">
                            <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/20">
                                {liveSummary.directPlayCount} Direct Play
                            </span>
                            {liveSummary.directStreamCount > 0 && (
                                <span className="px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/20">
                                    {liveSummary.directStreamCount} Direct Stream
                                </span>
                            )}
                            <span className="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/20">
                                {liveSummary.transcodeCount} Transcode
                            </span>
                        </div>
                    </div>
                </div>

                {/* KPI 2: Live Stream Bandwidth */}
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex flex-col justify-between">
                    <div className="flex items-center justify-between">
                        <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Live Bandwidth</span>
                        <div className="h-9 w-9 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                            <Wifi size={18} />
                        </div>
                    </div>
                    <div className="mt-2">
                        <div className="flex items-baseline gap-1.5">
                            <span className="text-2xl font-extrabold text-cyan-300 tabular-nums">
                                {liveSummary.totalBandwidthMbps.toFixed(1)}
                            </span>
                            <span className="text-xs font-bold text-cyan-400/80">Mbps</span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1.5">
                            Active session transfer: <span className="text-slate-200 font-mono">{formatBytes(liveSummary.activeSessionBytes, 1)}</span>
                        </p>
                    </div>
                </div>

                {/* KPI 3: Cumulative Data Usage */}
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex flex-col justify-between">
                    <div className="flex items-center justify-between">
                        <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">
                            Data Usage ({windowDays === 0 ? 'All' : `${windowDays}d`})
                        </span>
                        <div className="h-9 w-9 rounded-xl bg-teal-500/10 border border-teal-500/20 flex items-center justify-center text-teal-400">
                            <HardDrive size={18} />
                        </div>
                    </div>
                    <div className="mt-2">
                        <div className="flex items-baseline gap-2">
                            <span className="text-2xl font-extrabold text-teal-300 tabular-nums">
                                {formatBytes(analytics.totalDataUsedBytes, 2)}
                            </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1.5">
                            Peak throughput: <span className="text-slate-200 font-mono">{analytics.peakBandwidthMbps.toFixed(1)} Mbps</span>
                        </p>
                    </div>
                </div>

                {/* KPI 4: Play Statistics & Watch Time */}
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex flex-col justify-between">
                    <div className="flex items-center justify-between">
                        <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">
                            Play Statistics ({windowDays === 0 ? 'All' : `${windowDays}d`})
                        </span>
                        <div className="h-9 w-9 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                            <Activity size={18} />
                        </div>
                    </div>
                    <div className="mt-2">
                        <div className="flex items-baseline gap-2">
                            <span className="text-2xl font-extrabold text-white tabular-nums">{analytics.totalPlays}</span>
                            <span className="text-xs text-slate-400">plays · {formatWatchDuration(analytics.totalWatchTimeSecs)}</span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1.5">
                            {analytics.uniqueUsers} viewers · <span className="text-emerald-400 font-semibold">{analytics.avgCompletionPct}%</span> avg completion
                        </p>
                    </div>
                </div>

                {/* KPI 5: Library Inventory */}
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex flex-col justify-between">
                    <div className="flex items-center justify-between">
                        <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Jellyfin Library</span>
                        <div className="h-9 w-9 rounded-xl bg-fuchsia-500/10 border border-fuchsia-500/20 flex items-center justify-center text-fuchsia-400">
                            <Film size={18} />
                        </div>
                    </div>
                    <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
                        <div className="flex items-center justify-between">
                            <span className="text-slate-400">Movies</span>
                            <span className="font-bold text-slate-100 tabular-nums">{jellyfinServer.libraryCounts?.movies || 0}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <span className="text-slate-400">Series</span>
                            <span className="font-bold text-slate-100 tabular-nums">{jellyfinServer.libraryCounts?.series || 0}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <span className="text-slate-400">Episodes</span>
                            <span className="font-bold text-slate-100 tabular-nums">{jellyfinServer.libraryCounts?.episodes || 0}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <span className="text-slate-400">Audio</span>
                            <span className="font-bold text-slate-100 tabular-nums">{jellyfinServer.libraryCounts?.audio || 0}</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* ========================================================================= */}
            {/* 4. LIVE ACTIVE STREAMS SECTION (STREAM INFO, CODECS & CONTROLS)           */}
            {/* ========================================================================= */}
            {(activeView === 'dashboard' || activeView === 'streams') && (
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5">
                    <div className="flex flex-wrap items-center justify-between gap-3 mb-4 pb-3 border-b border-white/[0.06]">
                        <div className="flex items-center gap-2.5">
                            <div className="relative flex h-2.5 w-2.5">
                                {liveSummary.activeStreams > 0 && (
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                                )}
                                <span
                                    className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                                        liveSummary.activeStreams > 0 ? 'bg-emerald-500' : 'bg-slate-600'
                                    }`}
                                />
                            </div>
                            <h3 className="text-sm font-bold text-slate-100 tracking-tight">
                                Active Jellyfin Sessions
                            </h3>
                            <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-white/[0.05] text-slate-300 border border-white/10">
                                {liveSummary.activeStreams} active · {liveSummary.totalBandwidthMbps.toFixed(1)} Mbps total
                            </span>
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

                    {isLoading && !data ? (
                        <div className="py-12 flex items-center justify-center gap-2 text-slate-400 text-sm">
                            <Loader2 size={18} className="animate-spin text-indigo-400" />
                            <span>Polling Jellyfin sessions...</span>
                        </div>
                    ) : activeSessions.length === 0 ? (
                        <div className="py-12 flex flex-col items-center justify-center text-center">
                            <div className="w-12 h-12 rounded-2xl bg-white/[0.03] border border-white/[0.06] flex items-center justify-center text-slate-500 mb-3">
                                <Tv size={24} />
                            </div>
                            <p className="text-sm font-semibold text-slate-300">No Active Streams Right Now</p>
                            <p className="text-xs text-slate-500 mt-1 max-w-md">
                                Active Jellyfin sessions will appear here in real time with codec pipelines, resolution, client device, and live bandwidth consumption.
                            </p>
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
                            {activeSessions.map((sess) => {
                                const methodStyle = getPlayMethodStyle(sess.playMethod);
                                const epBadge = formatEpisodeBadge(sess.seasonNumber, sess.episodeNumber);
                                return (
                                    <article
                                        key={sess.sessionId}
                                        className="rounded-2xl border border-white/[0.08] bg-slate-950/60 hover:border-indigo-500/30 transition-all overflow-hidden flex flex-col justify-between shadow-lg"
                                    >
                                        {/* Top Media & User Header */}
                                        <div className="p-4 space-y-3">
                                            <div className="flex items-start gap-3.5">
                                                {/* Poster / Cover Art Thumbnail */}
                                                <div className="w-16 h-24 rounded-xl bg-slate-900 border border-white/10 overflow-hidden shrink-0 flex items-center justify-center relative">
                                                    {sess.hasArtwork && sess.artworkItemId ? (
                                                        <img
                                                            src={`/api/v1/auth/streaming/artwork/${encodeURIComponent(sess.artworkItemId)}`}
                                                            alt={sess.itemName}
                                                            className="w-full h-full object-cover"
                                                        />
                                                    ) : (
                                                        <div className="flex flex-col items-center justify-center text-indigo-400/60">
                                                            {sess.itemType === 'Audio' ? <Music size={22} /> : <Film size={22} />}
                                                        </div>
                                                    )}
                                                    <span
                                                        className={`absolute bottom-1 left-1 right-1 text-center text-xs font-bold uppercase py-0.5 rounded ${
                                                            sess.state === 'playing'
                                                                ? 'bg-emerald-500/90 text-slate-950'
                                                                : 'bg-amber-500/90 text-slate-950'
                                                        }`}
                                                    >
                                                        {sess.state === 'playing' ? 'Playing' : 'Paused'}
                                                    </span>
                                                </div>

                                                {/* Title, Series, User & Device */}
                                                <div className="flex-1 min-w-0">
                                                    <div className="flex items-center justify-between gap-2">
                                                        <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${methodStyle.badge}`}>
                                                            {methodStyle.label}
                                                            {sess.hwAccel ? ` · ${sess.hwAccel}` : ''}
                                                        </span>
                                                        <span className="text-xs font-mono font-bold text-cyan-300 tabular-nums">
                                                            {sess.bandwidthMbps.toFixed(1)} Mbps
                                                        </span>
                                                    </div>

                                                    <h4 className="text-sm font-bold text-white truncate mt-1.5" title={sess.itemName}>
                                                        {sess.seriesName ? sess.seriesName : sess.itemName}
                                                    </h4>
                                                    <p className="text-xs text-slate-400 truncate">
                                                        {sess.seriesName ? (
                                                            <>
                                                                {epBadge && <span className="font-mono text-indigo-300 mr-1.5">{epBadge}</span>}
                                                                <span>{sess.itemName}</span>
                                                            </>
                                                        ) : (
                                                            <span>
                                                                {sess.itemType} {sess.productionYear ? `· ${sess.productionYear}` : ''}
                                                            </span>
                                                        )}
                                                    </p>

                                                    {/* User & Client Device */}
                                                    <div className="mt-2.5 pt-2 border-t border-white/[0.06] flex flex-col gap-1 text-xs">
                                                        <div className="flex items-center justify-between text-slate-200">
                                                            <span className="font-semibold flex items-center gap-1.5 truncate">
                                                                <Users size={12} className="text-indigo-400 shrink-0" />
                                                                {sess.userName}
                                                            </span>
                                                            <span
                                                                className={`text-xs font-mono px-1.5 py-0.2 rounded border ${
                                                                    sess.isLan
                                                                        ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20'
                                                                        : 'bg-purple-500/10 text-purple-300 border-purple-500/20'
                                                                }`}
                                                            >
                                                                {sess.isLan ? 'LAN' : 'WAN'} · {sess.ipAddress || 'local'}
                                                            </span>
                                                        </div>
                                                        <div className="flex items-center justify-between text-slate-400">
                                                            <span className="truncate flex items-center gap-1.5" title={`${sess.clientName} · ${sess.deviceName}`}>
                                                                <Monitor size={12} className="text-slate-500 shrink-0" />
                                                                {sess.clientName} · {sess.deviceName}
                                                            </span>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>

                                            {/* Stream Information & Codec Pipeline Matrix */}
                                            <div className="rounded-xl bg-black/40 border border-white/[0.05] p-3 space-y-1.5 text-xs">
                                                <div className="flex items-center justify-between">
                                                    <span className="text-slate-400">Container</span>
                                                    <span className="font-mono text-slate-200 font-semibold">
                                                        {sess.container || 'MKV'}
                                                        {sess.targetContainer && sess.targetContainer !== sess.container && (
                                                            <span className="text-amber-300"> &rarr; {sess.targetContainer}</span>
                                                        )}
                                                    </span>
                                                </div>
                                                <div className="flex items-center justify-between">
                                                    <span className="text-slate-400">Video Stream</span>
                                                    <span className="font-mono text-slate-200 font-semibold">
                                                        {sess.videoResolution} · {sess.videoCodec}
                                                        {sess.targetVideoCodec && !sess.isVideoDirect && (
                                                            <span className="text-amber-300"> &rarr; {sess.targetVideoCodec}</span>
                                                        )}
                                                        <span className="ml-1.5 text-xs px-1.5 py-0.2 rounded bg-white/10 text-slate-300">
                                                            {sess.videoRange}
                                                        </span>
                                                    </span>
                                                </div>
                                                <div className="flex items-center justify-between">
                                                    <span className="text-slate-400">Audio Stream</span>
                                                    <span className="font-mono text-slate-200 font-semibold">
                                                        {sess.audioCodec} ({sess.audioLayout})
                                                        {sess.targetAudioCodec && !sess.isAudioDirect && (
                                                            <span className="text-amber-300"> &rarr; {sess.targetAudioCodec}</span>
                                                        )}
                                                    </span>
                                                </div>
                                                <div className="flex items-center justify-between">
                                                    <span className="text-slate-400">Data Transferred</span>
                                                    <span className="font-mono text-teal-300 font-semibold">
                                                        {formatBytes(sess.sessionDataBytes, 2)}
                                                        {sess.transcodeFps ? ` · ${sess.transcodeFps} fps` : ''}
                                                    </span>
                                                </div>

                                                {sess.transcodeReasons && sess.transcodeReasons.length > 0 && (
                                                    <div className="pt-1.5 border-t border-white/[0.05] flex flex-wrap items-center gap-1">
                                                        <span className="text-xs text-amber-400/90 font-semibold mr-1">Reason:</span>
                                                        {sess.transcodeReasons.map((r) => (
                                                            <span
                                                                key={r}
                                                                className="text-xs px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20"
                                                            >
                                                                {formatTranscodeReason(r)}
                                                            </span>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>
                                        </div>

                                        {/* Playback Timeline & Admin Controls Footer */}
                                        <div className="px-4 pb-3.5 pt-2 bg-white/[0.02] border-t border-white/[0.05] space-y-2.5">
                                            <div>
                                                <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1">
                                                    <span>{formatDurationClock(sess.positionSecs)}</span>
                                                    <span className="text-slate-200 font-bold">{sess.progressPct.toFixed(1)}%</span>
                                                    <span>{formatDurationClock(sess.durationSecs)}</span>
                                                </div>
                                                <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden relative">
                                                    {sess.transcodeProgressPct && sess.transcodeProgressPct > sess.progressPct && (
                                                        <div
                                                            className="absolute inset-y-0 left-0 bg-amber-500/25 rounded-full"
                                                            style={{ width: `${Math.min(100, sess.transcodeProgressPct)}%` }}
                                                            title={`Transcode buffer: ${sess.transcodeProgressPct}%`}
                                                        />
                                                    )}
                                                    <div
                                                        className={`h-full rounded-full relative z-10 ${methodStyle.bar}`}
                                                        style={{ width: `${Math.min(100, sess.progressPct)}%` }}
                                                    />
                                                </div>
                                            </div>

                                            {isAdmin && (
                                                <div className="flex items-center justify-between gap-2 pt-1">
                                                    <div className="flex items-center gap-1.5">
                                                        {sess.state === 'playing' ? (
                                                            <button
                                                                type="button"
                                                                onClick={() => handleSessionCommand(sess.sessionId, 'pause')}
                                                                className="px-2.5 py-1 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] border border-white/10 text-xs font-semibold text-slate-200 flex items-center gap-1 transition-all"
                                                                title="Pause Playback"
                                                            >
                                                                <Pause size={12} />
                                                                <span>Pause</span>
                                                            </button>
                                                        ) : (
                                                            <button
                                                                type="button"
                                                                onClick={() => handleSessionCommand(sess.sessionId, 'resume')}
                                                                className="px-2.5 py-1 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-xs font-semibold text-emerald-300 flex items-center gap-1 transition-all"
                                                                title="Resume Playback"
                                                            >
                                                                <Play size={12} />
                                                                <span>Resume</span>
                                                            </button>
                                                        )}

                                                        <button
                                                            type="button"
                                                            onClick={() => handleSessionCommand(sess.sessionId, 'stop')}
                                                            className="px-2.5 py-1 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-xs font-semibold text-rose-300 flex items-center gap-1 transition-all"
                                                            title="Stop / Terminate Session"
                                                        >
                                                            <Square size={12} />
                                                            <span>Stop</span>
                                                        </button>
                                                    </div>

                                                    <button
                                                        type="button"
                                                        onClick={() => {
                                                            setMessageSession(sess);
                                                            setMessageBody('');
                                                        }}
                                                        className="px-2.5 py-1 rounded-lg bg-indigo-500/15 hover:bg-indigo-500/25 border border-indigo-500/30 text-xs font-semibold text-indigo-300 flex items-center gap-1 transition-all"
                                                        title="Send On-Screen Message to Viewer"
                                                    >
                                                        <MessageSquare size={12} />
                                                        <span>Message</span>
                                                    </button>
                                                </div>
                                            )}
                                        </div>
                                    </article>
                                );
                            })}
                        </div>
                    )}
                </div>
            )}

            {/* ========================================================================= */}
            {/* 5. ANALYTICS FILTER TOOLBAR & CHARTS (PLAY STATS & DATA USAGE)            */}
            {/* ========================================================================= */}
            {(activeView === 'dashboard' || activeView === 'analytics' || activeView === 'history') && (
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-3.5 flex flex-wrap items-center justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs font-bold text-slate-400 uppercase tracking-wider px-2">
                            Analytics Filters:
                        </span>
                        {/* Play Method Filter */}
                        <div className="flex items-center gap-1 bg-black/40 p-1 rounded-xl border border-white/10">
                            {[
                                { id: 'all', label: 'All Methods' },
                                { id: 'DirectPlay', label: 'Direct Play' },
                                { id: 'DirectStream', label: 'Direct Stream' },
                                { id: 'Transcode', label: 'Transcode' },
                            ].map((m) => (
                                <button
                                    key={m.id}
                                    type="button"
                                    onClick={() => setPlayMethodFilter(m.id)}
                                    className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-all ${
                                        playMethodFilter === m.id
                                            ? 'bg-indigo-500/25 text-indigo-300 border border-indigo-500/30'
                                            : 'text-slate-400 hover:text-slate-200'
                                    }`}
                                >
                                    {m.label}
                                </button>
                            ))}
                        </div>

                        {/* Media Type Filter */}
                        <div className="flex items-center gap-1 bg-black/40 p-1 rounded-xl border border-white/10">
                            {[
                                { id: 'all', label: 'All Media' },
                                { id: 'Movie', label: 'Movies' },
                                { id: 'Episode', label: 'Episodes' },
                                { id: 'Audio', label: 'Audio' },
                            ].map((mt) => (
                                <button
                                    key={mt.id}
                                    type="button"
                                    onClick={() => setMediaTypeFilter(mt.id)}
                                    className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-all ${
                                        mediaTypeFilter === mt.id
                                            ? 'bg-purple-500/25 text-purple-300 border border-purple-500/30'
                                            : 'text-slate-400 hover:text-slate-200'
                                    }`}
                                >
                                    {mt.label}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Time Window Selector */}
                    <div className="flex items-center gap-1 bg-black/40 p-1 rounded-xl border border-white/10">
                        {[
                            { days: 7, label: '7 Days' },
                            { days: 30, label: '30 Days' },
                            { days: 90, label: '90 Days' },
                            { days: 0, label: 'All Time' },
                        ].map((w) => (
                            <button
                                key={w.days}
                                type="button"
                                onClick={() => setWindowDays(w.days)}
                                className={`px-3 py-1 rounded-lg text-xs font-bold transition-all ${
                                    windowDays === w.days
                                        ? 'bg-indigo-600 text-white shadow'
                                        : 'text-slate-400 hover:text-slate-200'
                                }`}
                            >
                                {w.label}
                            </button>
                        ))}
                    </div>
                </div>
            )}

            {(activeView === 'dashboard' || activeView === 'analytics') && (
                <>

                    {/* Time-Series Charts Row: Bandwidth/Data Usage & Play Statistics */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        {/* Chart 1: Data Usage & Bandwidth Telemetry */}
                        <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5 flex flex-col">
                            <div className="flex items-center justify-between mb-4">
                                <div>
                                    <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                                        <HardDrive size={16} className="text-teal-400" />
                                        Stream Data Usage & Bandwidth Over Time
                                    </h3>
                                    <p className="text-xs text-slate-400 mt-0.5">
                                        Daily data transferred (GB) and peak stream bandwidth (Mbps)
                                    </p>
                                </div>
                                <span className="text-xs font-mono font-bold text-teal-300 bg-teal-500/10 px-2.5 py-1 rounded-lg border border-teal-500/20">
                                    Total: {formatBytes(analytics.totalDataUsedBytes, 2)}
                                </span>
                            </div>

                            <div className="h-[220px] w-full">
                                <ResponsiveContainer width="100%" height={220}>
                                    <AreaChart data={chartData} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
                                        <defs>
                                            <linearGradient id="streamDataGrad" x1="0" y1="0" x2="0" y2="1">
                                                <stop offset="5%" stopColor="#2dd4bf" stopOpacity={0.4} />
                                                <stop offset="95%" stopColor="#2dd4bf" stopOpacity={0.02} />
                                            </linearGradient>
                                            <linearGradient id="streamBwGrad" x1="0" y1="0" x2="0" y2="1">
                                                <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.35} />
                                                <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.02} />
                                            </linearGradient>
                                        </defs>
                                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                                        <XAxis
                                            dataKey="date"
                                            stroke="rgba(255,255,255,0.2)"
                                            tick={{ fill: 'rgba(255,255,255,0.45)', fontSize: 10 }}
                                            tickFormatter={(v) => {
                                                const p = String(v).split('-');
                                                return p.length === 3 ? `${p[1]}/${p[2]}` : String(v);
                                            }}
                                            minTickGap={20}
                                        />
                                        <YAxis
                                            stroke="rgba(255,255,255,0.2)"
                                            tick={{ fill: 'rgba(255,255,255,0.45)', fontSize: 10 }}
                                            tickFormatter={(v) => `${v} GB`}
                                            width={52}
                                        />
                                        <Tooltip
                                            contentStyle={{
                                                backgroundColor: 'rgba(15, 23, 42, 0.94)',
                                                border: '1px solid rgba(255,255,255,0.12)',
                                                borderRadius: '12px',
                                            }}
                                            labelStyle={{ color: '#94a3b8', fontSize: '11px', marginBottom: '4px' }}
                                            formatter={(value, name) => {
                                                if (name === 'Data Used') return [`${value} GB`, 'Data Used'];
                                                return [`${value} Mbps`, String(name)];
                                            }}
                                        />
                                        <Area
                                            type="monotone"
                                            name="Data Used"
                                            dataKey="dataGB"
                                            stroke="#2dd4bf"
                                            strokeWidth={2}
                                            fillOpacity={1}
                                            fill="url(#streamDataGrad)"
                                        />
                                    </AreaChart>
                                </ResponsiveContainer>
                            </div>
                        </div>

                        {/* Chart 2: Watch Time & Play Method Trends */}
                        <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5 flex flex-col">
                            <div className="flex items-center justify-between mb-4">
                                <div>
                                    <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                                        <Activity size={16} className="text-indigo-400" />
                                        Play Sessions & Watch Time Activity
                                    </h3>
                                    <p className="text-xs text-slate-400 mt-0.5">
                                        Daily Direct Play, Direct Stream, and Transcode sessions
                                    </p>
                                </div>
                                <span className="text-xs font-mono font-bold text-indigo-300 bg-indigo-500/10 px-2.5 py-1 rounded-lg border border-indigo-500/20">
                                    Watch Time: {formatWatchDuration(analytics.totalWatchTimeSecs)}
                                </span>
                            </div>

                            <div className="h-[220px] w-full">
                                <ResponsiveContainer width="100%" height={220}>
                                    <BarChart data={chartData} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
                                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                                        <XAxis
                                            dataKey="date"
                                            stroke="rgba(255,255,255,0.2)"
                                            tick={{ fill: 'rgba(255,255,255,0.45)', fontSize: 10 }}
                                            tickFormatter={(v) => {
                                                const p = String(v).split('-');
                                                return p.length === 3 ? `${p[1]}/${p[2]}` : String(v);
                                            }}
                                            minTickGap={20}
                                        />
                                        <YAxis
                                            stroke="rgba(255,255,255,0.2)"
                                            tick={{ fill: 'rgba(255,255,255,0.45)', fontSize: 10 }}
                                            allowDecimals={false}
                                            width={36}
                                        />
                                        <Tooltip
                                            contentStyle={{
                                                backgroundColor: 'rgba(15, 23, 42, 0.94)',
                                                border: '1px solid rgba(255,255,255,0.12)',
                                                borderRadius: '12px',
                                            }}
                                            labelStyle={{ color: '#94a3b8', fontSize: '11px', marginBottom: '4px' }}
                                        />
                                        <Bar dataKey="directPlayCount" name="Direct Play" stackId="plays" fill="#10b981" radius={[0, 0, 0, 0]} />
                                        <Bar dataKey="directStreamCount" name="Direct Stream" stackId="plays" fill="#38bdf8" radius={[0, 0, 0, 0]} />
                                        <Bar dataKey="transcodeCount" name="Transcode" stackId="plays" fill="#f59e0b" radius={[4, 4, 0, 0]} />
                                    </BarChart>
                                </ResponsiveContainer>
                            </div>
                        </div>
                    </div>

                    {/* Stream Type, Resolution & Codec Distribution Strip */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        {/* Stream Type Distribution */}
                        <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 space-y-3">
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
                            </div>
                            <div className="grid grid-cols-3 gap-2 pt-1 text-xs">
                                <div className="bg-black/30 rounded-xl p-2 border border-white/5">
                                    <span className="text-xs text-emerald-400 font-semibold block">Direct Play</span>
                                    <span className="text-sm font-bold text-white tabular-nums">
                                        {analytics.streamTypes.directPlayCount}{' '}
                                        <span className="text-xs text-slate-400 font-normal">({analytics.streamTypes.directPlayPct}%)</span>
                                    </span>
                                </div>
                                <div className="bg-black/30 rounded-xl p-2 border border-white/5">
                                    <span className="text-xs text-sky-400 font-semibold block">Direct Stream</span>
                                    <span className="text-sm font-bold text-white tabular-nums">
                                        {analytics.streamTypes.directStreamCount}{' '}
                                        <span className="text-xs text-slate-400 font-normal">({analytics.streamTypes.directStreamPct}%)</span>
                                    </span>
                                </div>
                                <div className="bg-black/30 rounded-xl p-2 border border-white/5">
                                    <span className="text-xs text-amber-400 font-semibold block">Transcode</span>
                                    <span className="text-sm font-bold text-white tabular-nums">
                                        {analytics.streamTypes.transcodeCount}{' '}
                                        <span className="text-xs text-slate-400 font-normal">({analytics.streamTypes.transcodePct}%)</span>
                                    </span>
                                </div>
                            </div>
                        </div>

                        {/* Resolution Breakdown */}
                        <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 space-y-2.5">
                            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                                <Monitor size={14} className="text-indigo-400" />
                                Resolution & Bandwidth Share
                            </h4>
                            <div className="space-y-2">
                                {analytics.resolutionBreakdown.length === 0 ? (
                                    <p className="text-xs text-slate-500 py-4 text-center">No resolution metrics recorded yet</p>
                                ) : (
                                    analytics.resolutionBreakdown.slice(0, 4).map((item) => (
                                        <div key={item.label} className="space-y-1">
                                            <div className="flex items-center justify-between text-xs">
                                                <span className="font-semibold text-slate-200">{item.label}</span>
                                                <span className="text-slate-400 font-mono text-xs">
                                                    {item.count} plays ({item.pct}%) · {formatBytes(item.dataUsedBytes, 1)}
                                                </span>
                                            </div>
                                            <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                                                <div
                                                    className="h-full rounded-full bg-gradient-to-r from-indigo-500 to-cyan-400"
                                                    style={{ width: `${Math.max(4, item.pct)}%` }}
                                                />
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>

                        {/* Video Codec Breakdown */}
                        <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 space-y-2.5">
                            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                                <Layers size={14} className="text-fuchsia-400" />
                                Source Codec Telemetry
                            </h4>
                            <div className="space-y-2">
                                {analytics.codecBreakdown.length === 0 ? (
                                    <p className="text-xs text-slate-500 py-4 text-center">No codec metrics recorded yet</p>
                                ) : (
                                    analytics.codecBreakdown.slice(0, 4).map((item) => (
                                        <div key={item.label} className="space-y-1">
                                            <div className="flex items-center justify-between text-xs">
                                                <span className="font-mono font-bold text-slate-200">{item.label}</span>
                                                <span className="text-slate-400 font-mono text-xs">
                                                    {item.count} plays ({item.pct}%) · {formatBytes(item.dataUsedBytes, 1)}
                                                </span>
                                            </div>
                                            <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                                                <div
                                                    className="h-full rounded-full bg-gradient-to-r from-fuchsia-500 to-purple-400"
                                                    style={{ width: `${Math.max(4, item.pct)}%` }}
                                                />
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Top Watchers Leaderboard & Top Watched Titles */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        {/* Top Watchers & Data Consumers */}
                        <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl overflow-hidden">
                            <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
                                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                                    <Trophy size={16} className="text-amber-400" />
                                    Top Watchers & Data Usage by User
                                </h3>
                                <span className="text-xs text-slate-400">{analytics.topUsers.length} users</span>
                            </div>
                            <div className="divide-y divide-white/[0.04]">
                                {analytics.topUsers.length === 0 ? (
                                    <div className="py-12 text-center text-xs text-slate-500">
                                        No user playback statistics recorded for this period.
                                    </div>
                                ) : (
                                    analytics.topUsers.map((u, idx) => {
                                        const rankMedal = idx === 0 ? '🥇' : idx === 1 ? '🥈' : idx === 2 ? '🥉' : `#${idx + 1}`;
                                        return (
                                            <div
                                                key={u.userName}
                                                className="px-5 py-3.5 flex items-center justify-between gap-3 hover:bg-white/[0.02] transition-colors"
                                            >
                                                <div className="flex items-center gap-3 min-w-0">
                                                    <span className="w-6 text-center text-sm font-bold text-slate-400 shrink-0">
                                                        {rankMedal}
                                                    </span>
                                                    <div className="w-9 h-9 rounded-full bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-xs font-bold text-indigo-300 shrink-0 uppercase">
                                                        {u.userName.slice(0, 2)}
                                                    </div>
                                                    <div className="min-w-0">
                                                        <p className="text-sm font-bold text-slate-100 truncate">{u.userName}</p>
                                                        <p className="text-xs text-slate-400 truncate">
                                                            {u.uniqueItems} unique titles · {u.lastDevice || 'Jellyfin Client'}
                                                        </p>
                                                    </div>
                                                </div>
                                                <div className="text-right shrink-0">
                                                    <div className="flex items-center justify-end gap-2">
                                                        <span className="text-xs font-mono font-bold text-teal-300 bg-teal-500/10 px-2 py-0.5 rounded border border-teal-500/20">
                                                            {formatBytes(u.totalDataBytes, 1)}
                                                        </span>
                                                        <span className="text-sm font-bold text-white tabular-nums">
                                                            {u.totalPlays} plays
                                                        </span>
                                                    </div>
                                                    <p className="text-xs text-slate-400 mt-0.5 tabular-nums">
                                                        {formatWatchDuration(u.totalWatchSecs)} watched · {u.directPlayCount} direct / {u.transcodeCount} transcode
                                                    </p>
                                                </div>
                                            </div>
                                        );
                                    })
                                )}
                            </div>
                        </div>

                        {/* Top Watched Titles */}
                        <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl overflow-hidden">
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
                                    analytics.topTitles.map((t, idx) => (
                                        <div
                                            key={`${t.itemName}-${idx}`}
                                            className="px-5 py-3.5 flex items-center justify-between gap-3 hover:bg-white/[0.02] transition-colors"
                                        >
                                            <div className="flex items-center gap-3 min-w-0">
                                                <span className="w-6 h-6 rounded-lg bg-white/[0.05] border border-white/10 flex items-center justify-center text-xs font-bold text-slate-300 shrink-0">
                                                    {idx + 1}
                                                </span>
                                                <div className="min-w-0">
                                                    <div className="flex items-center gap-2">
                                                        <p className="text-sm font-bold text-slate-100 truncate">{t.itemName}</p>
                                                        {t.productionYear ? (
                                                            <span className="text-xs font-mono text-slate-400">({t.productionYear})</span>
                                                        ) : null}
                                                    </div>
                                                    <div className="flex flex-wrap items-center gap-1.5 mt-0.5 text-xs">
                                                        <span className="px-1.5 py-0.2 rounded bg-purple-500/15 text-purple-300 border border-purple-500/20">
                                                            {t.itemType}
                                                        </span>
                                                        {t.videoResolution && (
                                                            <span className="px-1.5 py-0.2 rounded bg-white/10 text-slate-300 font-mono">
                                                                {t.videoResolution}
                                                            </span>
                                                        )}
                                                        {t.videoCodec && (
                                                            <span className="px-1.5 py-0.2 rounded bg-indigo-500/15 text-indigo-300 font-mono">
                                                                {t.videoCodec}
                                                            </span>
                                                        )}
                                                    </div>
                                                </div>
                                            </div>
                                            <div className="text-right shrink-0">
                                                <div className="flex items-center justify-end gap-2">
                                                    <span className="text-xs font-mono text-teal-300">
                                                        {formatBytes(t.totalDataBytes, 1)}
                                                    </span>
                                                    <span className="text-sm font-bold text-white tabular-nums">
                                                        {t.totalPlays} plays
                                                    </span>
                                                </div>
                                                <p className="text-xs text-slate-400 mt-0.5 tabular-nums">
                                                    {t.uniqueViewers} viewer{t.uniqueViewers === 1 ? '' : 's'} · {formatWatchDuration(t.totalWatchSecs)}
                                                </p>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>
                    </div>
                </>
            )}

            {/* ========================================================================= */}
            {/* 6. PLAYBACK & DATA USAGE HISTORY LOG TABLE                                */}
            {/* ========================================================================= */}
            {(activeView === 'dashboard' || activeView === 'history') && (
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-white/[0.06]">
                        <div>
                            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                                <Clock size={16} className="text-indigo-400" />
                                Playback & Stream Data Usage Log
                            </h3>
                            <p className="text-xs text-slate-400 mt-0.5">
                                Detailed per-session audit of play method, codecs, bitrate, data consumed, and completion
                            </p>
                        </div>
                        <div className="relative w-full sm:w-72">
                            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                            <input
                                type="text"
                                value={historySearch}
                                onChange={(e) => setHistorySearch(e.target.value)}
                                placeholder="Search title, user, device, codec..."
                                className="w-full pl-9 pr-3 py-1.5 rounded-xl bg-black/40 border border-white/10 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500/50"
                            />
                        </div>
                    </div>

                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs">
                            <thead>
                                <tr className="border-b border-white/[0.06] text-slate-400 uppercase tracking-wider text-xs">
                                    <th className="py-2.5 px-3 font-semibold">Title</th>
                                    <th className="py-2.5 px-3 font-semibold">User</th>
                                    <th className="py-2.5 px-3 font-semibold">Client & Device</th>
                                    <th className="py-2.5 px-3 font-semibold">Stream Pipeline</th>
                                    <th className="py-2.5 px-3 font-semibold">Data & Bitrate</th>
                                    <th className="py-2.5 px-3 font-semibold">Watched</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-white/[0.04]">
                                {error ? (
                                    <tr>
                                        <td colSpan={6} className="py-10 text-center text-red-400">
                                            Failed to load playback history
                                        </td>
                                    </tr>
                                ) : filteredHistory.length === 0 ? (
                                    <tr>
                                        <td colSpan={6} className="py-10 text-center text-slate-500">
                                            No playback history entries match the current filter.
                                        </td>
                                    </tr>
                                ) : (
                                    filteredHistory.map((h) => {
                                        const mStyle = getPlayMethodStyle(h.playMethod);
                                        const epBadge = formatEpisodeBadge(h.seasonNumber, h.episodeNumber);
                                        return (
                                            <tr key={h.id} className="hover:bg-white/[0.02] transition-colors">
                                                <td className="py-3 px-3">
                                                    <div className="flex items-center gap-2">
                                                        {h.isActive && (
                                                            <span
                                                                className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse shrink-0"
                                                                title="Currently Playing"
                                                            />
                                                        )}
                                                        <div>
                                                            <p className="font-bold text-slate-100">
                                                                {h.seriesName ? `${h.seriesName} · ` : ''}
                                                                {epBadge ? `${epBadge} — ` : ''}
                                                                {h.itemName}
                                                            </p>
                                                            <p className="text-xs text-slate-500 mt-0.5">
                                                                {h.itemType} {h.productionYear ? `(${h.productionYear})` : ''} · {h.serverName}
                                                            </p>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td className="py-3 px-3 font-semibold text-slate-200">{h.userName}</td>
                                                <td className="py-3 px-3">
                                                    <p className="text-slate-200">{h.clientName}</p>
                                                    <p className="text-xs text-slate-500">
                                                        {h.deviceName} {h.ipAddress ? `· ${h.ipAddress}` : ''}
                                                    </p>
                                                </td>
                                                <td className="py-3 px-3">
                                                    <div className="flex flex-wrap items-center gap-1">
                                                        <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${mStyle.badge}`}>
                                                            {mStyle.label}
                                                            {h.hwAccel ? ` (${h.hwAccel})` : ''}
                                                        </span>
                                                        <span className="text-xs font-mono bg-white/[0.06] text-slate-300 px-1.5 py-0.5 rounded">
                                                            {h.videoResolution} · {h.videoCodec} / {h.audioCodec}
                                                        </span>
                                                    </div>
                                                </td>
                                                <td className="py-3 px-3 font-mono">
                                                    <p className="text-teal-300 font-bold">{formatBytes(h.dataUsedBytes, 2)}</p>
                                                    <p className="text-xs text-slate-400">{h.bandwidthMbps.toFixed(1)} Mbps</p>
                                                </td>
                                                <td className="py-3 px-3">
                                                    <div className="flex items-center gap-2">
                                                        <div className="w-20 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                                                            <div
                                                                className="h-full bg-indigo-500 rounded-full"
                                                                style={{ width: `${Math.min(100, h.completionPct)}%` }}
                                                            />
                                                        </div>
                                                        <span className="text-xs font-mono text-slate-300">
                                                            {Math.round(h.completionPct)}%
                                                        </span>
                                                    </div>
                                                    <p className="text-xs text-slate-500 mt-0.5">
                                                        {formatWatchDuration(h.watchedSecs)} / {formatWatchDuration(h.durationSecs)}
                                                    </p>
                                                </td>
                                            </tr>
                                        );
                                    })
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* ========================================================================= */}
            {/* 7. SERVER CONFIGURATION MODAL (JELLYFIN FIRST, PLEX & EMBY LATER)         */}
            {/* ========================================================================= */}
            {showConfigModal && (
                <div
                    className="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4"
                    onClick={() => setShowConfigModal(false)}
                >
                    <div
                        className="w-full max-w-xl rounded-2xl border border-indigo-500/30 bg-slate-950/95 p-6 shadow-2xl space-y-5"
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="flex items-center justify-between pb-3 border-b border-white/10">
                            <div className="flex items-center gap-3">
                                <div className="h-10 w-10 rounded-xl bg-purple-500/20 border border-purple-500/30 flex items-center justify-center text-purple-300">
                                    <Server size={20} />
                                </div>
                                <div>
                                    <h3 className="text-base font-bold text-white">Media Server Providers</h3>
                                    <p className="text-xs text-slate-400">
                                        Connect Jellyfin now; Plex and Emby provider adapters are queued for upcoming releases
                                    </p>
                                </div>
                            </div>
                            <button
                                type="button"
                                onClick={() => setShowConfigModal(false)}
                                className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-white/10"
                                aria-label="Close modal"
                            >
                                <X size={18} />
                            </button>
                        </div>

                        {/* Provider Roadmap Cards */}
                        <div className="grid grid-cols-3 gap-2.5">
                            <div className="rounded-xl border border-purple-500/40 bg-purple-500/10 p-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-xs font-bold text-white">Jellyfin</span>
                                    <span className="text-xs font-bold uppercase px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                                        Active
                                    </span>
                                </div>
                                <p className="text-xs text-slate-300 mt-1">Full stream, codec & bandwidth telemetry</p>
                            </div>
                            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3 opacity-70">
                                <div className="flex items-center justify-between">
                                    <span className="text-xs font-bold text-slate-300">Plex</span>
                                    <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-white/10 text-slate-400">
                                        Later
                                    </span>
                                </div>
                                <p className="text-xs text-slate-500 mt-1">X-Plex-Token session adapter</p>
                            </div>
                            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3 opacity-70">
                                <div className="flex items-center justify-between">
                                    <span className="text-xs font-bold text-slate-300">Emby</span>
                                    <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-white/10 text-slate-400">
                                        Later
                                    </span>
                                </div>
                                <p className="text-xs text-slate-500 mt-1">Emby Connect API adapter</p>
                            </div>
                        </div>

                        <form onSubmit={handleSaveConfig} className="space-y-4">
                            <div>
                                <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-1.5">
                                    Server Display Name
                                </label>
                                <input
                                    type="text"
                                    value={serverNameInput}
                                    onChange={(e) => setServerNameInput(e.target.value)}
                                    placeholder="AetherFlow Jellyfin"
                                    className="w-full px-3.5 py-2.5 rounded-xl bg-black/50 border border-white/10 text-sm text-white focus:outline-none focus:border-indigo-500"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-1.5">
                                    Jellyfin Server URL
                                </label>
                                <input
                                    type="text"
                                    value={serverUrlInput}
                                    onChange={(e) => setServerUrlInput(e.target.value)}
                                    placeholder="http://127.0.0.1:8096"
                                    required
                                    className="w-full px-3.5 py-2.5 rounded-xl bg-black/50 border border-white/10 text-sm text-white font-mono focus:outline-none focus:border-indigo-500"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-1.5">
                                    Jellyfin API Key
                                </label>
                                <input
                                    type="password"
                                    value={apiKeyInput}
                                    onChange={(e) => setApiKeyInput(e.target.value)}
                                    placeholder="Paste API key from Jellyfin Dashboard → Advanced → API Keys"
                                    className="w-full px-3.5 py-2.5 rounded-xl bg-black/50 border border-white/10 text-sm text-white font-mono focus:outline-none focus:border-indigo-500"
                                />
                                <p className="text-xs text-slate-500 mt-1 flex items-center gap-1">
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
                                    className="px-4 py-2 rounded-xl text-xs font-bold bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-slate-200 flex items-center gap-1.5 transition-all"
                                >
                                    {isTestingConn ? <Loader2 size={14} className="animate-spin" /> : <Wifi size={14} />}
                                    <span>Test Connection</span>
                                </button>

                                <div className="flex items-center gap-2">
                                    <button
                                        type="button"
                                        onClick={() => setShowConfigModal(false)}
                                        className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white"
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        type="submit"
                                        disabled={isSavingConn}
                                        className="px-5 py-2 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-500/25 flex items-center gap-1.5 transition-all"
                                    >
                                        {isSavingConn ? <Loader2 size={14} className="animate-spin" /> : <CheckCircle2 size={14} />}
                                        <span>Save & Connect</span>
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* ========================================================================= */}
            {/* 8. SEND MESSAGE TO JELLYFIN VIEWER MODAL                                  */}
            {/* ========================================================================= */}
            {messageSession && (
                <div
                    className="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4"
                    onClick={() => setMessageSession(null)}
                >
                    <form
                        onSubmit={handleSendSessionMessage}
                        className="w-full max-w-md rounded-2xl border border-indigo-500/30 bg-slate-950/95 p-6 shadow-2xl space-y-4"
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="flex items-center justify-between pb-2 border-b border-white/10">
                            <h3 className="text-sm font-bold text-white flex items-center gap-2">
                                <MessageSquare size={16} className="text-indigo-400" />
                                Message {messageSession.userName} ({messageSession.deviceName})
                            </h3>
                            <button
                                type="button"
                                onClick={() => setMessageSession(null)}
                                className="p-1 text-slate-400 hover:text-white"
                            >
                                <X size={16} />
                            </button>
                        </div>

                        <div>
                            <label className="block text-xs font-semibold text-slate-400 mb-1">Header</label>
                            <input
                                type="text"
                                value={messageHeader}
                                onChange={(e) => setMessageHeader(e.target.value)}
                                className="w-full px-3 py-2 rounded-xl bg-black/50 border border-white/10 text-xs text-white"
                            />
                        </div>

                        <div>
                            <label className="block text-xs font-semibold text-slate-400 mb-1">Message</label>
                            <textarea
                                rows={3}
                                value={messageBody}
                                onChange={(e) => setMessageBody(e.target.value)}
                                placeholder="Enter message to display on viewer's screen..."
                                required
                                className="w-full px-3 py-2 rounded-xl bg-black/50 border border-white/10 text-xs text-white"
                            />
                        </div>

                        <div className="flex justify-end gap-2 pt-2">
                            <button
                                type="button"
                                onClick={() => setMessageSession(null)}
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
                </div>
            )}
        </div>
    );
}
