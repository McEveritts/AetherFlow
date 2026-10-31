'use client';

import { RefreshCw, Box, Settings, Globe, RotateCcw, Square, Play, Server, Cpu, X, Network, ArrowUpCircle, ExternalLink, Key, Eye, EyeOff, Copy, Check } from 'lucide-react';
import { useState, useEffect, useRef } from 'react';
import useSWR, { useSWRConfig } from 'swr';
import { useToast } from '@/contexts/ToastContext';
import { useAuth } from '@/contexts/AuthContext';
import { ServicesSkeleton } from '@/components/layout/SkeletonBox';
import { apiFetch } from '@/lib/fetcher';
import RequireClaim from '@/components/auth/RequireClaim';
import ServiceLogsModal from '@/components/tabs/ServiceLogsModal';
import { Terminal } from 'lucide-react';
import { useSystemStore } from '@/store/useSystemStore';
import { ExternalAccessCard } from '@/components/ingress/ExternalAccessCard';
import { DeploymentStatus } from '@/components/deploy/DeploymentStatus';
import { ProgressRing } from '@/components/ui/ProgressRing';

// Fallback map when default_port is not provided by backend
const SERVICE_WEB_PORTS: Record<string, number | string> = {
    'plexmediaserver': 32400,
    'jellyfin': 8096,
    'emby-server': 8097,
    'sonarr': 8989,
    'radarr': 7878,
    'lidarr': 8686,
    'readarr': 8787,
    'prowlarr': 9696,
    'bazarr': 6767,
    'jellyseerr': 5055,
    'overseerr': 5056,
    'ombi': 5000,
    'tautulli': 8181,
    'jackett': 9117,
    'flaresolverr': 8191,
    'navidrome': 4533,
    'threadfin': 34400,
    'qbittorrent': 8180,
    'deluged': 8112,
    'transmission-daemon': 9091,
    'sabnzbd': 8085,
    'nzbget': 6789,
    'flood': 3001,
    'autobrr': 7474,
    'qui': 7476,
    'nextcloud': 8088,
    'syncthing': 8384,
    'filebrowser': 8095,
    'pihole-FTL': 8089,
    'vaultwarden': 8343,
    'grafana-server': 3000,
    'prometheus': 9090,
    'netdata': 19999,
    'uptime-kuma': 3004,
    'home-assistant@homeassistant': 8123,
    'adguardhome': 3080,
    'rutorrent': 8087,
    'rclone': 5572,
    'autoscan': 3030,
    'audiobookshelf': 13378,
    'kavita': 5002,
    'calibreweb': 8083,
    'librespeed': 8988,
    'thelounge': 9000,
    'znc': 6501,
    'scrutiny': 8098,
    'paperless-ngx': 8010,
    'paperless-webserver': 8010,
    'n8n': 5678,
    'gitea': 3002,
    'organizr': 8086,
    'dispatcharr': 9191,
    'duplicati': 8200,
    'filebot': 5452,
    'listenarr': 4546,
    'notifiarr': 5454,
    'novnc': 6080,
    'pyload': 8000,
    'requestrr': 4545,
    'seedcross': 8019,
    'unmanic': 8888,
    'apache2': 443,
    'aetherflow-frontend': '/',
    'aetherflow-api': '/api/v1/admin/services',
};

interface ServiceInfo {
    status: string;
    version: string;
    installed_version?: string;
    latest_version?: string;
    update_available?: boolean;
    update_checked_at?: string;
    update_url?: string;
    update_error?: string;
    job_status?: string;
    progress?: number;
    log_line?: string;
    started_at?: string;
    uptime: string;
    managed_by?: string;
    process?: string;
    id?: string;
    default_port?: number;
    active_port?: number;
    api_key?: string;
    internal_domain?: string;
    public_domain?: string;
    external_access_enabled?: boolean;
    tls_enabled?: boolean;
    web_path?: string;
    units?: string[];
}


export default function ServicesTab() {
    const { addToast } = useToast();
    const { user } = useAuth();
    const { mutate: globalMutate } = useSWRConfig();
    const [loadingService, setLoadingService] = useState<string | null>(null);
    const [updatingServices, setUpdatingServices] = useState<Set<string>>(new Set());
    const [checkingUpdates, setCheckingUpdates] = useState(false);
    const [checkingSingleService, setCheckingSingleService] = useState<string | null>(null);
    const [logsModalService, setLogsModalService] = useState<string | null>(null);
    const [ingressModalApp, setIngressModalApp] = useState<string | null>(null);
    const [revealedKeys, setRevealedKeys] = useState<Set<string>>(new Set());
    const [copiedKeyService, setCopiedKeyService] = useState<string | null>(null);
    const canControlServices = user?.role === 'admin';
    const { setActiveTab } = useSystemStore();

    const prevServicesRef = useRef<Record<string, ServiceInfo> | undefined>(undefined);
    const notifiedUpdateRef = useRef<Set<string>>(new Set());

    const { data: services, mutate, isLoading } = useSWR<Record<string, ServiceInfo>>(
        '/api/v1/auth/services',
        {
            refreshInterval: (currentData) => {
                if (updatingServices.size > 0) return 1500;
                if (!currentData) return 15000;
                const hasActiveJob = Object.values(currentData).some(
                    (s) => s.status === 'updating' || s.job_status === 'updating' || s.job_status === 'installing' || s.job_status === 'uninstalling'
                );
                return hasActiveJob ? 1500 : 15000;
            }
        }
    );

    useEffect(() => {
        if (!services) return;
        const prev = prevServicesRef.current;

        Object.entries(services).forEach(([name, info]) => {
            const appId = info.id || name;
            const prevInfo = prev?.[name];
            const wasUpdating =
                prevInfo?.status === 'updating' ||
                prevInfo?.job_status === 'updating' ||
                updatingServices.has(appId);
            const isNowUpdating = info.status === 'updating' || info.job_status === 'updating';

            if (wasUpdating && !isNowUpdating) {
                if (updatingServices.has(appId)) {
                    setUpdatingServices((curr) => {
                        const next = new Set(curr);
                        next.delete(appId);
                        return next;
                    });
                }

                if (!notifiedUpdateRef.current.has(appId)) {
                    notifiedUpdateRef.current.add(appId);
                    if (info.job_status === 'failed' || info.status === 'error') {
                        addToast(`Update failed for ${name}. Check system logs for details.`, 'error');
                    } else {
                        const ver = info.installed_version || info.version;
                        const verSuffix = ver ? ` to v${ver.replace(/^v/i, '')}` : '';
                        addToast(`${name} updated${verSuffix} and restarted.`, 'success');
                    }
                    globalMutate('/api/v1/public/marketplace');
                    setTimeout(() => notifiedUpdateRef.current.delete(appId), 5000);
                }
            }
        });

        prevServicesRef.current = services;
    }, [services, updatingServices, addToast, globalMutate]);

    const handleCheckAllUpdates = async () => {
        setCheckingUpdates(true);
        try {
            if (canControlServices) {
                const res = await apiFetch('/api/v1/admin/packages/updates/check', { method: 'POST' });
                if (res.ok) {
                    const payload = await res.json().catch(() => null);
                    await mutate();
                    globalMutate('/api/v1/public/marketplace');
                    if (payload && typeof payload.updates_available === 'number') {
                        if (payload.updates_available > 0) {
                            addToast(`${payload.updates_available} application update${payload.updates_available === 1 ? '' : 's'} available.`, 'info');
                        } else {
                            addToast('All installed applications are up to date.', 'success');
                        }
                    } else {
                        addToast('Synchronized service states and update metadata.', 'success');
                    }
                    return;
                }
            }
            await mutate();
            addToast('Synchronized service states.', 'info');
        } catch {
            await mutate();
            addToast('Failed to check remote updates; refreshed local service status.', 'error');
        } finally {
            setCheckingUpdates(false);
        }
    };

    const handleCheckSingleUpdate = async (name: string, data: ServiceInfo) => {
        if (!canControlServices || !data.id) return;
        setCheckingSingleService(name);
        try {
            const res = await apiFetch(`/api/v1/admin/packages/${encodeURIComponent(data.id)}/check-update`, {
                method: 'POST',
            });
            if (!res.ok) {
                const d = await res.json().catch(() => ({}));
                throw new Error(d.message || d.error || 'Update check failed.');
            }
            const result = await res.json().catch(() => ({}));
            await mutate();
            globalMutate('/api/v1/public/marketplace');
            if (result.update_available) {
                addToast(`Update available for ${name}: v${(result.latest_version || '').replace(/^v/i, '')}`, 'info');
            } else {
                addToast(`${name} is up to date${result.installed_version ? ` (v${result.installed_version.replace(/^v/i, '')})` : ''}.`, 'success');
            }
        } catch (err: unknown) {
            addToast(err instanceof Error ? err.message : 'Unable to check for updates.', 'error');
        } finally {
            setCheckingSingleService(null);
        }
    };

    const handleUpdateService = async (name: string, data: ServiceInfo) => {
        if (!canControlServices) {
            addToast('Authorization constraint: Admin privileges required to update applications.', 'error');
            return;
        }
        const appId = data.id;
        if (!appId) {
            addToast(`Cannot resolve package identifier for ${name}.`, 'error');
            return;
        }

        try {
            const res = await apiFetch(`/api/v1/admin/packages/${encodeURIComponent(appId)}/update`, {
                method: 'POST',
            });
            if (!res.ok) {
                const d = await res.json().catch(() => ({}));
                throw new Error(d.message || d.error || 'Package update request rejected.');
            }
            setUpdatingServices((curr) => new Set(curr).add(appId));
            if (services) {
                mutate(
                    {
                        ...services,
                        [name]: {
                            ...data,
                            status: 'updating',
                            job_status: 'updating',
                            progress: 5,
                            log_line: `Preparing update for ${name}...`,
                            started_at: new Date().toISOString(),
                        },
                    },
                    false
                );
            }
            const targetVer = data.latest_version ? ` to v${data.latest_version.replace(/^v/i, '')}` : '';
            addToast(`Updating ${name}${targetVer}...`, 'info');
            mutate();
            globalMutate('/api/v1/public/marketplace');
        } catch (err: unknown) {
            setUpdatingServices((curr) => {
                const next = new Set(curr);
                next.delete(appId);
                return next;
            });
            mutate();
            addToast(err instanceof Error ? err.message : 'Update failed to start.', 'error');
        }
    };

    const handleServiceControl = async (name: string, data: ServiceInfo, action: 'start' | 'stop' | 'restart') => {
        if (!canControlServices) {
            addToast('Authorization constraint: Admin privileges required for daemon control.', 'error');
            return;
        }

        setLoadingService(name);

        // Optimistic update — instantly reflect the pending state in the UI
        const optimisticStatus = action === 'stop' ? 'stopping' : action === 'start' ? 'starting' : 'restarting';
        const prevData = services;
        if (services) {
            mutate(
                { ...services, [name]: { ...data, status: optimisticStatus } },
                false // don't revalidate yet
            );
        }

        try {
            const res = await apiFetch(`/api/v1/admin/services/${encodeURIComponent(name)}/control`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action,
                    managed_by: data.managed_by || 'systemd',
                    process: data.process || name,
                })
            });
            if (!res.ok) {
                const d = await res.json().catch(() => ({}));
                throw new Error(d.message || d.error || 'Daemon control operation rejected.');
            }
            addToast(`Successfully executed '${action}' on ${name}.`, 'success');
            setTimeout(() => mutate(), 1500);
        } catch (err: unknown) {
            mutate(prevData, false);
            addToast(err instanceof Error ? err.message : 'Undefined system exception encountered.', 'error');
        } finally {
            setLoadingService(null);
        }
    };

    const allEntries = Object.entries(services || {});

    const corePlatformProcesses = ['aetherflow-api', 'aetherflow-frontend', 'apache2', 'nginx'];
    const isCorePlatformService = (info: ServiceInfo) =>
        corePlatformProcesses.includes(info.id || info.process || '');

    const hasWebUI = (info: ServiceInfo) => {
        if (typeof info.default_port === 'number') {
            return info.default_port > 0;
        }
        return (
            (info.id ? SERVICE_WEB_PORTS[info.id] != null : false) ||
            (info.process ? SERVICE_WEB_PORTS[info.process] != null : false)
        );
    };

    const coreServices = allEntries.filter(([, d]) => isCorePlatformService(d as ServiceInfo));
    const appServices = allEntries.filter(([, d]) => !isCorePlatformService(d as ServiceInfo));

    const runningCount = allEntries.filter(([, d]) => (d as ServiceInfo).status === 'running').length;
    const updatesAvailableCount = appServices.filter(([, d]) => Boolean((d as ServiceInfo).update_available)).length;

    const formatVersion = (ver?: string) => {
        if (!ver || ver === '-') return '-';
        return ver.startsWith('v') || ver.startsWith('V') ? ver : `v${ver}`;
    };

    const resolveServicePort = (name: string, data: ServiceInfo): { port: number | null; defaultPort: number | null; reassigned: boolean } => {
        const activePort = typeof data.active_port === 'number' && data.active_port > 0 ? data.active_port : null;
        const defaultPort = typeof data.default_port === 'number' && data.default_port > 0 ? data.default_port : null;
        if (activePort != null) {
            return {
                port: activePort,
                defaultPort,
                reassigned: defaultPort != null && activePort !== defaultPort,
            };
        }
        if (defaultPort != null) {
            return { port: defaultPort, defaultPort, reassigned: false };
        }
        const process = data.process || name;
        const fallback = (data.id ? SERVICE_WEB_PORTS[data.id] : undefined) ?? SERVICE_WEB_PORTS[process];
        if (typeof fallback === 'number' && fallback > 0) {
            return { port: fallback, defaultPort: fallback, reassigned: false };
        }
        return { port: null, defaultPort: null, reassigned: false };
    };

    const toggleRevealKey = (serviceKey: string) => {
        setRevealedKeys((prev) => {
            const next = new Set(prev);
            if (next.has(serviceKey)) {
                next.delete(serviceKey);
            } else {
                next.add(serviceKey);
            }
            return next;
        });
    };

    const handleCopyApiKey = async (name: string, apiKey: string) => {
        try {
            await navigator.clipboard.writeText(apiKey);
            setCopiedKeyService(name);
            addToast(`Copied ${name} API key to clipboard.`, 'success');
            setTimeout(() => {
                setCopiedKeyService((curr) => (curr === name ? null : curr));
            }, 2000);
        } catch {
            addToast('Unable to copy API key to clipboard.', 'error');
        }
    };

    const formatMaskedApiKey = (apiKey: string) => {
        const trimmed = apiKey.trim();
        if (trimmed.length <= 6) {
            return '••••••••';
        }
        return `${'•'.repeat(12)}${trimmed.slice(-4)}`;
    };

    const handleOpenWebUI = (name: string, data: ServiceInfo) => {
        const pathSuffix = data.web_path ? (data.web_path.startsWith('/') ? data.web_path : `/${data.web_path}`) : '';
        if (data.external_access_enabled && data.public_domain) {
            const proto = data.tls_enabled === false ? 'http:' : 'https:';
            window.open(`${proto}//${data.public_domain}${pathSuffix}`, '_blank');
            return;
        }
        const host = window.location.hostname;
        const effectivePort = data.active_port || data.default_port;
        if (effectivePort && effectivePort > 0) {
            window.open(`${window.location.protocol}//${host}:${effectivePort}${pathSuffix}`, '_blank');
            return;
        }
        const process = data.process || name;
        const portOrPath = (data.id ? SERVICE_WEB_PORTS[data.id] : undefined) ?? SERVICE_WEB_PORTS[process];
        if (portOrPath != null) {
            const url = typeof portOrPath === 'string'
                ? portOrPath.startsWith('/') ? `${window.location.protocol}//${host}${portOrPath}` : portOrPath
                : `${window.location.protocol}//${host}:${portOrPath}`;
            window.open(url, '_blank');
        } else {
            addToast('No web UI configured for this service.', 'info');
        }
    };

    const handleOpenSettings = (name: string, data: ServiceInfo) => {
        if (isCorePlatformService(data)) {
            setActiveTab('settings');
        } else {
            handleOpenWebUI(name, data);
        }
    };

    const renderServiceCard = (name: string, rawData: unknown) => {
        const data = rawData as ServiceInfo;
        const isCore = isCorePlatformService(data);
        const appId = data.id || '';
        const isUpdating =
            data.status === 'updating' ||
            data.job_status === 'updating' ||
            (appId ? updatingServices.has(appId) : false);
        const isRunning = data.status === 'running' && !isUpdating;
        const isError = data.status === 'error';
        const isBusy = loadingService === name || isUpdating;
        const controlDisabled = isBusy || !canControlServices;
        const webAvailable = hasWebUI(data);
        const hasUpdate = Boolean(!isCore && data.update_available);
        const installedVer = data.installed_version || data.version || '-';
        const latestVer = data.latest_version;
        const isCheckingThis = checkingSingleService === name;

        return (
            <div key={name} className={`glass-card relative bg-slate-950/80 border rounded-2xl p-6 transition-all group cursor-default overflow-hidden ${hasUpdate ? 'border-amber-500/30 hover:border-amber-400/60' : 'border-white/10 hover:border-indigo-500/50'}`}>
                <div className={`absolute top-0 left-0 w-1 h-full ${isUpdating ? 'bg-amber-400 animate-pulse' : (hasUpdate ? 'bg-amber-500/70' : (isRunning ? 'bg-emerald-500/50' : (isError ? 'bg-red-500/50' : 'bg-slate-500/50')))} transition-colors z-20`}></div>

                {isUpdating && (
                    <div className="absolute inset-0 bg-slate-950/90 backdrop-blur-md rounded-2xl z-30 flex items-center justify-center p-6 text-center">
                        <ProgressRing
                            progress={data.progress || 10}
                            status="updating"
                            logLine={data.log_line || `Updating ${name}...`}
                            startedAt={data.started_at}
                        />
                    </div>
                )}

                <div className="flex justify-between items-start mb-6 relative z-10">
                    <div className="flex items-center gap-4">
                        <div className="h-12 w-12 bg-white/5 rounded-xl border border-white/10 flex items-center justify-center shadow-inner overflow-hidden group-hover:scale-105 transition-transform">
                            {isCore ? (
                                <Cpu size={24} className={isRunning ? 'text-emerald-400' : (isError ? 'text-red-400' : 'text-slate-500')} />
                            ) : data.id ? (
                                <div className="relative w-8 h-8 flex items-center justify-center">
                                    <img 
                                        src={`/img/${data.id.toLowerCase()}.png`} 
                                        alt={name}
                                        className="w-full h-full object-contain"
                                        onError={(e) => {
                                            e.currentTarget.style.display = 'none';
                                            e.currentTarget.parentElement?.querySelector('.fallback')?.classList.remove('hidden');
                                        }}
                                    />
                                    <Box size={24} className={`fallback hidden ${isRunning ? 'text-emerald-400' : (isError ? 'text-red-400' : 'text-slate-500')} absolute`} />
                                </div>
                            ) : (
                                <Box size={24} className={isRunning ? 'text-emerald-400' : (isError ? 'text-red-400' : 'text-slate-500')} />
                            )}
                        </div>
                        <div>
                            <div className="flex items-center gap-2 flex-wrap">
                                <h3 className="text-base font-bold text-slate-200 group-hover:text-white transition-colors">{name}</h3>
                                {hasUpdate && (
                                    <span className="inline-flex items-center gap-1 text-xs font-bold px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/30">
                                        <ArrowUpCircle size={12} className="text-amber-400" />
                                        {latestVer ? `Update ${formatVersion(latestVer)}` : 'Update Available'}
                                    </span>
                                )}
                            </div>
                            <div className="flex items-center gap-2 mt-1 flex-wrap">
                                <span className="relative flex h-2 w-2">
                                    {isRunning && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
                                    <span className={`relative inline-flex rounded-full h-2 w-2 ${isUpdating ? 'bg-amber-400' : (isRunning ? 'bg-emerald-500' : (isError ? 'bg-red-500' : 'bg-slate-500'))}`}></span>
                                </span>
                                <span className="text-xs font-medium text-slate-400 capitalize">{isUpdating ? 'updating' : data.status}</span>
                                {data.managed_by && (
                                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-slate-500 border border-white/5 uppercase tracking-wider">
                                        {data.managed_by}
                                    </span>
                                )}
                                {data.public_domain && (
                                    <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-mono truncate max-w-[160px]" title={data.public_domain}>
                                        {data.public_domain}
                                    </span>
                                )}
                            </div>
                        </div>
                    </div>
                    <div className="flex items-center gap-1">
                        {!isCore && webAvailable && (
                            <button 
                                onClick={() => setIngressModalApp(data.id || data.process || name)}
                                disabled={isBusy}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 text-slate-500 hover:text-indigo-400 hover:bg-white/5 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center"
                                title="Ingress & Deployment"
                            >
                                <Network size={18} />
                            </button>
                        )}
                        {(isCore || webAvailable) && (
                            <button 
                                onClick={() => handleOpenSettings(name, data)}
                                disabled={isBusy}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 text-slate-500 hover:text-slate-300 hover:bg-white/5 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center"
                                title="Settings"
                            >
                                <Settings size={18} />
                            </button>
                        )}
                    </div>
                </div>

                {(() => {
                    const { port: effectivePort, defaultPort, reassigned } = resolveServicePort(name, data);
                    const apiKey = data.api_key?.trim() || '';
                    const isKeyRevealed = revealedKeys.has(name);
                    const isKeyCopied = copiedKeyService === name;

                    return (
                        <div className="mb-6 space-y-3">
                            <div className="grid grid-cols-3 gap-3">
                                <div className={`bg-slate-900/50 rounded-xl p-3 border ${hasUpdate ? 'border-amber-500/20 bg-amber-500/[0.03]' : 'border-white/[0.02]'}`}>
                                    <div className="flex items-center justify-between">
                                        <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Version</span>
                                        {!isCore && data.id && canControlServices && (
                                            <button
                                                onClick={() => handleCheckSingleUpdate(name, data)}
                                                disabled={isBusy || isCheckingThis}
                                                title="Check for updates"
                                                className="text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40"
                                            >
                                                <RefreshCw size={11} className={isCheckingThis ? 'animate-spin text-indigo-400' : ''} />
                                            </button>
                                        )}
                                    </div>
                                    <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
                                        <span className="text-sm font-medium text-slate-300 truncate">{formatVersion(installedVer)}</span>
                                        {hasUpdate && latestVer && (
                                            data.update_url && /^https?:\/\//i.test(data.update_url) ? (
                                                <a
                                                    href={data.update_url}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="inline-flex items-center gap-0.5 text-xs font-bold text-amber-400 hover:text-amber-300 transition-colors"
                                                    title="View release notes"
                                                >
                                                    → {formatVersion(latestVer)}
                                                    <ExternalLink size={10} />
                                                </a>
                                            ) : (
                                                <span className="text-xs font-bold text-amber-400">
                                                    → {formatVersion(latestVer)}
                                                </span>
                                            )
                                        )}
                                    </div>
                                </div>
                                <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.02]">
                                    <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Port</span>
                                    <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
                                        {effectivePort != null ? (
                                            <>
                                                <span className="text-sm font-mono font-medium text-slate-200">:{effectivePort}</span>
                                                {reassigned && defaultPort && (
                                                    <span
                                                        className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-mono"
                                                        title={`Dynamically reassigned from default port ${defaultPort}`}
                                                    >
                                                        def :{defaultPort}
                                                    </span>
                                                )}
                                            </>
                                        ) : (
                                            <span className="text-xs font-medium text-slate-500">Headless</span>
                                        )}
                                    </div>
                                </div>
                                <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.02]">
                                    <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Uptime</span>
                                    <p className="text-sm font-medium text-slate-300 mt-0.5 truncate" title={data.uptime || '-'}>{data.uptime || '-'}</p>
                                </div>
                            </div>

                            {apiKey && (
                                <div className="bg-slate-900/50 rounded-xl px-3 py-2.5 border border-white/[0.04] flex items-center justify-between gap-2">
                                    <div className="flex items-center gap-2 min-w-0 flex-1">
                                        <Key size={13} className="text-indigo-400 shrink-0" />
                                        <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider shrink-0">API Key</span>
                                        <code
                                            className="text-xs font-mono text-slate-300 truncate select-all bg-slate-950/60 px-2 py-0.5 rounded border border-white/5"
                                            title={isKeyRevealed ? apiKey : 'Click eye icon to reveal API key'}
                                        >
                                            {isKeyRevealed ? apiKey : formatMaskedApiKey(apiKey)}
                                        </code>
                                    </div>
                                    <div className="flex items-center gap-1 shrink-0">
                                        <button
                                            type="button"
                                            onClick={() => toggleRevealKey(name)}
                                            title={isKeyRevealed ? 'Hide API key' : 'Reveal API key'}
                                            aria-label={isKeyRevealed ? `Hide ${name} API key` : `Reveal ${name} API key`}
                                            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-white/5 rounded-md transition-colors"
                                        >
                                            {isKeyRevealed ? <EyeOff size={13} /> : <Eye size={13} />}
                                        </button>
                                        <button
                                            type="button"
                                            onClick={() => handleCopyApiKey(name, apiKey)}
                                            title="Copy API key"
                                            aria-label={`Copy ${name} API key`}
                                            className="p-1.5 text-slate-400 hover:text-indigo-400 hover:bg-white/5 rounded-md transition-colors"
                                        >
                                            {isKeyCopied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>
                    );
                })()}

                {hasUpdate && data.id && (
                    <RequireClaim>
                        <button
                            onClick={() => handleUpdateService(name, data)}
                            disabled={controlDisabled}
                            title={canControlServices ? `Update ${name}${latestVer ? ` to ${formatVersion(latestVer)}` : ''}` : 'Admin access required'}
                            className="obs-touch-target-standard obs-gpu-120hz-interactive w-full mb-2.5 py-2.5 bg-amber-500/15 hover:bg-amber-500 text-amber-300 hover:text-slate-950 text-xs font-bold rounded-lg transition-all flex items-center justify-center gap-2 border border-amber-500/30 shadow-lg shadow-amber-950/20 disabled:opacity-50"
                        >
                            <ArrowUpCircle size={15} />
                            {isUpdating ? 'Updating...' : `Update ${name}${latestVer ? ` to ${formatVersion(latestVer)}` : ''}`}
                        </button>
                    </RequireClaim>
                )}

                <div className="flex gap-2">
                    {isRunning ? (
                        <>
                            {webAvailable && (
                                <button
                                    onClick={() => handleOpenWebUI(name, data)}
                                    className="obs-touch-target-standard obs-gpu-120hz-interactive flex-1 py-2.5 bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
                                    disabled={isBusy}
                                >
                                    <Globe size={14} /> Web UI
                                </button>
                            )}
                            <RequireClaim>
                                <button
                                    onClick={() => setLogsModalService(data.process || name)}
                                    disabled={controlDisabled}
                                    title={canControlServices ? 'View live logs' : 'Admin access required'}
                                    className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 bg-slate-800/80 hover:bg-indigo-500/20 hover:text-indigo-400 text-slate-400 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center"
                                >
                                    <Terminal size={16} />
                                </button>
                                <button
                                    onClick={() => handleServiceControl(name, data, 'restart')}
                                    disabled={controlDisabled}
                                    title={canControlServices ? 'Restart service' : 'Admin access required'}
                                    className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 bg-slate-800/80 hover:bg-amber-500/20 hover:text-amber-400 text-slate-400 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center"
                                >
                                    <RotateCcw size={16} className={isBusy ? 'animate-spin' : ''} />
                                </button>
                                <button
                                    onClick={() => handleServiceControl(name, data, 'stop')}
                                    disabled={controlDisabled}
                                    title={canControlServices ? 'Stop service' : 'Admin access required'}
                                    className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 bg-slate-800/80 hover:bg-red-500/20 hover:text-red-400 text-slate-400 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center"
                                >
                                    <Square size={16} className="fill-current" />
                                </button>
                            </RequireClaim>
                        </>
                    ) : (
                        <RequireClaim>
                            <button
                                onClick={() => handleServiceControl(name, data, 'start')}
                                disabled={controlDisabled}
                                title={canControlServices ? 'Start service' : 'Admin access required'}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive w-full py-2.5 bg-indigo-500/20 hover:bg-indigo-500 text-indigo-300 hover:text-white text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-2 border border-indigo-500/30 disabled:opacity-50"
                            >
                                <Play size={14} className="fill-current" /> {isBusy ? 'Starting...' : 'Start Service'}
                            </button>
                        </RequireClaim>
                    )}
                </div>
            </div>
        );
    };

    if (isLoading) {
        return <ServicesSkeleton />;
    }

    return (
        <div className="space-y-8 animate-fade-in relative z-10 w-full min-h-screen">
            <div className="absolute inset-0 bg-blue-500/5 rounded-full blur-[120px] pointer-events-none -translate-y-1/2 -translate-x-1/2"></div>
            {/* Header */}
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-end gap-4">
                <div>
                    <h2 className="text-2xl font-bold text-slate-100 flex flex-wrap items-center gap-3">
                        App Ecosystem
                        <span className="text-xs font-semibold px-2.5 py-1 bg-white/10 rounded-full text-slate-300 border border-white/5">{allEntries.length} Total</span>
                        <span className="text-xs font-semibold px-2.5 py-1 bg-emerald-500/10 rounded-full text-emerald-400 border border-emerald-500/20">{runningCount} Running</span>
                        {updatesAvailableCount > 0 && (
                            <span className="text-xs font-semibold px-2.5 py-1 bg-amber-500/15 rounded-full text-amber-300 border border-amber-500/30 flex items-center gap-1.5">
                                <ArrowUpCircle size={13} className="text-amber-400" />
                                {updatesAvailableCount} {updatesAvailableCount === 1 ? 'Update' : 'Updates'} Available
                            </span>
                        )}
                    </h2>
                    <p className="text-slate-400 text-sm mt-2">Manage, monitor, and update services within the nexus.</p>
                </div>
                <div className="flex gap-3">
                    <button
                        onClick={handleCheckAllUpdates}
                        disabled={checkingUpdates}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive px-4 py-2 bg-white/[0.03] hover:bg-white/[0.08] border border-white/10 rounded-lg text-sm font-medium text-slate-300 transition-all flex items-center gap-2 disabled:opacity-50"
                    >
                        <RefreshCw size={14} className={checkingUpdates ? 'animate-spin text-indigo-400' : ''} />
                        {checkingUpdates ? 'Checking Updates...' : 'Check Updates & Sync'}
                    </button>
                </div>
            </div>

            {/* Core Platform */}
            {coreServices.length > 0 && (
                <div>
                    <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                        <Server size={14} className="text-indigo-400" /> Core Platform
                    </h3>
                    <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-5">
                        {coreServices.map(([name, data]) => renderServiceCard(name, data))}
                    </div>
                </div>
            )}

            {/* Installed Apps */}
            {appServices.length > 0 && (
                <div>
                    <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                        <Box size={14} className="text-emerald-400" /> Installed Applications
                    </h3>
                    <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-5">
                        {appServices.map(([name, data]) => renderServiceCard(name, data))}
                    </div>
                </div>
            )}

            {allEntries.length === 0 && (
                <div className="text-center py-20">
                    <Box size={48} className="mx-auto text-slate-600 mb-4" />
                    <h3 className="text-lg font-semibold text-slate-300 mb-2">No Services Detected</h3>
                    <p className="text-slate-500 text-sm">Install applications from the Marketplace to see them here.</p>
                </div>
            )}

            <ServiceLogsModal 
                serviceName={logsModalService} 
                onClose={() => setLogsModalService(null)} 
            />

            {ingressModalApp && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
                    <div className="glass-panel w-full max-w-xl max-h-[85vh] overflow-y-auto rounded-3xl p-6 border border-white/10 relative shadow-2xl">
                        <div className="flex items-center justify-between pb-4 border-b border-white/10">
                            <div className="flex items-center gap-2">
                                <Network className="text-indigo-400" size={20} />
                                <h3 className="text-lg font-bold text-white capitalize">{ingressModalApp} Ingress & Deploy</h3>
                            </div>
                            <button
                                onClick={() => setIngressModalApp(null)}
                                className="obs-touch-target-standard p-2 text-slate-400 hover:text-white rounded-lg hover:bg-white/5 transition-colors flex items-center justify-center"
                            >
                                <X size={18} />
                            </button>
                        </div>
                        <div className="space-y-4">
                            <ExternalAccessCard appName={ingressModalApp} />
                            <DeploymentStatus appName={ingressModalApp} isTriggered={true} />
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
