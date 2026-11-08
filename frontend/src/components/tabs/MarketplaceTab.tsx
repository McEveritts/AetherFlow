import React, { useState, useMemo, useEffect, useRef, useCallback } from 'react';
import { useMarketplace, useGithubDownloads, App, PendingAction, isLifecycleStatus, lifecycleIdentity, matchingJobOutcome } from '@/hooks/useMarketplace';
import { Search, Package, Download, RefreshCw, XCircle, AlertCircle, Filter, Globe, Puzzle, ShieldCheck, Play, Square, ExternalLink } from 'lucide-react';
import { useToast } from '@/contexts/ToastContext';
import { ProgressRing } from '@/components/ui/ProgressRing';
import { apiFetch } from '@/lib/fetcher';
import { getSVGLCatalog, matchSVGLLogo } from '@/lib/svgl';
import { ExternalAccessCard } from '@/components/ingress/ExternalAccessCard';
import { DeploymentStatus } from '@/components/deploy/DeploymentStatus';

export interface PluginScopeRule {
    method: string;
    route: string;
}

export interface PluginRuntimeView {
    id: string;
    name: string;
    version: string;
    sdk: string;
    contract_version: string;
    runtime_status: string;
    description: string;
    author: string;
    permissions: string[];
    granted_scopes: PluginScopeRule[];
    enabled: boolean;
    status: string;
    healthy: boolean;
    allocated_port: number;
    health_path: string;
    ui_url: string;
    proxy_base_url: string;
    slot: string;
    capabilities: string[];
    last_health_at?: string | null;
    last_error?: string;
}

const AppIcon = ({ app }: { app: App }) => {
    const [failedAppId, setFailedAppId] = useState<string | null>(null);
    const [svglState, setSvglState] = useState<{ appId: string; url: string | null; error: boolean } | null>(null);
    const localFailed = failedAppId === app.id;
    const svglUrl = svglState?.appId === app.id ? svglState.url : null;
    const iconError = svglState?.appId === app.id ? svglState.error : false;
    const localIconPath = `/img/${app.id.toLowerCase()}.png`;
    const primaryIconPath = localFailed ? svglUrl : localIconPath;

    useEffect(() => {
        if (!localFailed) return;
        let cancelled = false;
        getSVGLCatalog().then(catalog => {
            if (cancelled) return;
            const match = matchSVGLLogo(catalog, app.id, app.name);
            if (match) {
                setSvglState({ appId: app.id, url: match, error: false });
            } else {
                setSvglState({ appId: app.id, url: null, error: true });
            }
        });
        return () => {
            cancelled = true;
        };
    }, [localFailed, app.id, app.name]);

    if (iconError || (localFailed && !svglUrl)) {
        return (
            <div className="flex flex-col items-center justify-center h-full w-full bg-slate-900/20 text-slate-500">
                <Package size={24} />
                <span className="text-[8px] mt-1 font-bold uppercase opacity-50">{app.id.substring(0, 3)}</span>
            </div>
        );
    }

    return (
        <div className="relative w-full h-full flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
             <img
                src={primaryIconPath || localIconPath}
                onError={() => {
                    if (!localFailed) {
                        setFailedAppId(app.id);
                    } else {
                        setSvglState({ appId: app.id, url: null, error: true });
                    }
                }}
                className="w-full h-full object-contain p-2 drop-shadow-lg"
                alt={app.name}
                loading="lazy"
            />
        </div>
    );
};

export default function MarketplaceTab() {
    const { apps, isLoading, isError, mutate, pendingJobs, unconfirmedJobs, markPending, clearPending, registerJob } = useMarketplace();
    const totalGithubDownloads = useGithubDownloads();
    const { addToast } = useToast();
    const [searchQuery, setSearchQuery] = useState('');
    const [categoryFilter, setCategoryFilter] = useState('All');
    const [operatingApp, setOperatingApp] = useState<string | null>(null);
    const [ingressModalApp, setIngressModalApp] = useState<string | null>(null);

    // Installed Plugins & Sandboxed Capability Bridge State
    const [plugins, setPlugins] = useState<PluginRuntimeView[]>([]);
    const [rejectedPlugins, setRejectedPlugins] = useState<Array<{ id: string; error: string }>>([]);
    const [operatingPlugin, setOperatingPlugin] = useState<string | null>(null);
    const [mountedPlugin, setMountedPlugin] = useState<PluginRuntimeView | null>(null);
    const pluginIframeRef = useRef<HTMLIFrameElement | null>(null);

    const fetchPlugins = useCallback(async () => {
        try {
            const res = await apiFetch('/api/v1/auth/plugins');
            if (!res.ok) return;
            const data = await res.json();
            if (Array.isArray(data?.plugins)) {
                setPlugins(data.plugins);
            }
            if (Array.isArray(data?.rejected)) {
                setRejectedPlugins(data.rejected);
            }
        } catch {
            // Silently ignore when unauthenticated or offline
        }
    }, []);

    useEffect(() => {
        unconfirmedJobs?.forEach((identity, appId) => {
            if (unconfirmedNotifiedRef.current.has(identity)) return;
            unconfirmedNotifiedRef.current.add(identity);
            addToast(`${apps?.find(app => app.id === appId)?.name || appId}: operation outcome could not be confirmed. Its receipt may have been superseded. Check application state and logs before retrying.`, 'error');
        });
    }, [unconfirmedJobs, apps, addToast]);

    useEffect(() => {
        let active = true;
        apiFetch('/api/v1/auth/plugins')
            .then(async (response) => (response.ok ? response.json() : null))
            .then((payload) => {
                if (!active || !payload) return;
                if (Array.isArray(payload.plugins)) {
                    setPlugins(payload.plugins);
                }
                if (Array.isArray(payload.rejected)) {
                    setRejectedPlugins(payload.rejected);
                }
            })
            .catch(() => {});
        return () => {
            active = false;
        };
    }, []);

    // Sandboxed iframe postMessage capability bridge
    useEffect(() => {
        if (!mountedPlugin) return;

        const handlePluginMessage = async (event: MessageEvent) => {
            const iframeWin = pluginIframeRef.current?.contentWindow;
            if (!iframeWin || event.source !== iframeWin) return;
            const msg = event.data;
            if (!msg || typeof msg !== 'object') return;

            if (msg.type === 'AF_PLUGIN_READY' && msg.pluginId === mountedPlugin.id) {
                iframeWin.postMessage(
                    {
                        type: 'AF_PLUGIN_INIT',
                        pluginId: mountedPlugin.id,
                        capabilities: mountedPlugin.capabilities,
                        scopes: mountedPlugin.granted_scopes,
                    },
                    '*'
                );
                return;
            }

            if (msg.type === 'AF_PLUGIN_PROXY_REQUEST' && msg.pluginId === mountedPlugin.id) {
                const rawPath = String(msg.path || '').replace(/^\/+/, '');
                if (rawPath.includes('..') || rawPath.includes('\\')) {
                    iframeWin.postMessage(
                        {
                            type: 'AF_PLUGIN_PROXY_RESPONSE',
                            pluginId: mountedPlugin.id,
                            error: 'Path traversal is forbidden',
                        },
                        '*'
                    );
                    return;
                }
                const method = String(msg.method || 'GET').toUpperCase();
                if (!['GET', 'POST', 'PUT', 'DELETE'].includes(method)) {
                    iframeWin.postMessage(
                        {
                            type: 'AF_PLUGIN_PROXY_RESPONSE',
                            pluginId: mountedPlugin.id,
                            error: 'Unsupported HTTP method',
                        },
                        '*'
                    );
                    return;
                }
                const proxyUrl = rawPath
                    ? `${mountedPlugin.proxy_base_url}/${rawPath}`
                    : mountedPlugin.proxy_base_url;
                try {
                    const resp = await apiFetch(proxyUrl, { method });
                    const payload = await resp.json().catch(() => ({ status: resp.status }));
                    iframeWin.postMessage(
                        {
                            type: 'AF_PLUGIN_PROXY_RESPONSE',
                            pluginId: mountedPlugin.id,
                            status: resp.status,
                            payload,
                        },
                        '*'
                    );
                } catch (err: unknown) {
                    iframeWin.postMessage(
                        {
                            type: 'AF_PLUGIN_PROXY_RESPONSE',
                            pluginId: mountedPlugin.id,
                            error: err instanceof Error ? err.message : 'Proxy request failed',
                        },
                        '*'
                    );
                }
            }
        };

        window.addEventListener('message', handlePluginMessage);
        return () => window.removeEventListener('message', handlePluginMessage);
    }, [mountedPlugin]);

    const handlePluginControl = async (plugin: PluginRuntimeView, action: 'start' | 'stop' | 'restart' | 'revoke_tokens') => {
        setOperatingPlugin(plugin.id);
        try {
            const res = await apiFetch(`/api/v1/admin/plugins/${encodeURIComponent(plugin.id)}/control`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                throw new Error(data.message || `Plugin ${action} failed`);
            }
            addToast(data.message || `Plugin ${plugin.name} (${action}) completed`, 'success');
            if (data.plugin) {
                setPlugins((prev) => prev.map((p) => (p.id === plugin.id ? data.plugin : p)));
                if (mountedPlugin?.id === plugin.id && (action === 'stop' || !data.plugin.enabled)) {
                    setMountedPlugin(null);
                }
            } else {
                await fetchPlugins();
            }
        } catch (err: unknown) {
            addToast(err instanceof Error ? err.message : 'Plugin control error', 'error');
        } finally {
            setOperatingPlugin(null);
        }
    };

    // Job Completion Monitoring
    const observedJobsRef = useRef<Map<string, { action: PendingAction; identity: string }>>(new Map());
    const notifiedRef = useRef<Set<string>>(new Set());
    const unconfirmedNotifiedRef = useRef<Set<string>>(new Set());
    // Keep accepted identity/action after an observation timeout: a later receipt
    // can still confirm the real result, independently of the unknown notice.
    const acceptedJobsRef = useRef<Map<string, { action: PendingAction; identity: string }>>(new Map());
    const rememberJob = async (appId: string, res: Response, action: PendingAction) => {
        const body = await res.json() as { job_id?: string; started_at?: string };
        acceptedJobsRef.current.set(appId, { action, identity: registerJob(appId, body) });
    };

    useEffect(() => {
        if (!apps) return;
        apps.forEach(app => {
            if (isLifecycleStatus(app.status)) {
                const identity = lifecycleIdentity(app);
                if (identity && (!pendingJobs.has(app.id) || identity === acceptedJobsRef.current.get(app.id)?.identity)) observedJobsRef.current.set(app.id, { action: app.status, identity });
            }
            const observed = observedJobsRef.current.get(app.id);
            const localAction = pendingJobs.get(app.id);
            const accepted = acceptedJobsRef.current.get(app.id);
            const action = localAction || accepted?.action || observed?.action;
            const expected = localAction ? accepted?.identity : accepted?.identity || observed?.identity;
            if (!action) return;
            const outcome = matchingJobOutcome(app, action, expected);
            const identity = lifecycleIdentity(outcome);
            if (!outcome || !identity || notifiedRef.current.has(identity)) return;
            notifiedRef.current.add(identity);
            acceptedJobsRef.current.delete(app.id);
            observedJobsRef.current.delete(app.id);
            if (outcome.status === 'completed') {
                const verb = outcome.action === 'remove' ? 'removed' : outcome.action === 'update' ? 'updated' : outcome.action === 'reinstall' ? 'reinstalled' : 'installed';
                addToast(`${app.name} has been successfully ${verb}.`, 'success');
            } else {
                addToast(`${app.name}: ${outcome.action} ${outcome.status === 'failed' ? 'failed' : 'could not be confirmed'}. Check application state and system logs.`, 'error');
            }
        });
    }, [apps, addToast, pendingJobs]);

    const categories = useMemo(() => {
        if (!apps) return ['All'];
        const cats = Array.from(new Set(apps.map((app) => app.category)));
        return ['All', ...cats];
    }, [apps]);

    const filteredApps = useMemo(() => {
        if (!apps) return [];
        return apps.filter((app) => {
            const matchesSearch = app.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                                app.desc.toLowerCase().includes(searchQuery.toLowerCase());
            const matchesCategory = categoryFilter === 'All' || app.category === categoryFilter;
            return matchesSearch && matchesCategory;
        }).sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }));
    }, [apps, searchQuery, categoryFilter]);

    const isAppBusy = (app: App): boolean => {
        return isLifecycleStatus(app.status) || operatingApp === app.id || pendingJobs.has(app.id);
    };

    const getEffectiveStatus = (app: App): string => {
        if (isLifecycleStatus(app.status)) return app.status === 'reinstalling' ? 'installing' : app.status;
        if (pendingJobs.has(app.id)) {
            const pending = pendingJobs.get(app.id) as string;
            return pending === 'reinstalling' ? 'installing' : pending;
        }
        if (operatingApp === app.id) return 'installing';
        return app.status;
    };

    const [removeAppId, setRemoveAppId] = useState<string | null>(null);
    const [purgeData, setPurgeData] = useState(false);
    const [purgeConfirmation, setPurgeConfirmation] = useState('');
    const [reinstallAppId, setReinstallAppId] = useState<string | null>(null);
    const selectedRemoveApp = apps?.find(app => app.id === removeAppId);
    const selectedReinstallApp = apps?.find(app => app.id === reinstallAppId);

    const handleInstall = async (app: App, isReinstall = false) => {
        const pendingAction = isReinstall ? 'reinstalling' : 'installing';
        acceptedJobsRef.current.delete(app.id);
        setOperatingApp(app.id);
        markPending(app.id, pendingAction);
        try {
            const res = await apiFetch(`/api/v1/admin/packages/${encodeURIComponent(app.id)}/install`, { method: 'POST' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                clearPending(app.id);
                throw new Error(data.message || 'Installation request failed');
            }
            await rememberJob(app.id, res, pendingAction);
            addToast(`${isReinstall ? 'Reinstall' : 'Installation'} started for ${app.name}`, 'info');
            setOperatingApp(null);
            mutate();
        } catch (error: unknown) {
            addToast(error instanceof Error ? error.message : 'Network error.', 'error');
            clearPending(app.id);
            setOperatingApp(null);
        }
    };

    const handleUpdate = async (app: App) => {
        acceptedJobsRef.current.delete(app.id);
        setOperatingApp(app.id);
        markPending(app.id, 'updating');
        try {
            const res = await apiFetch(`/api/v1/admin/packages/${encodeURIComponent(app.id)}/update`, { method: 'POST' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                clearPending(app.id);
                throw new Error(data.message || 'Update request failed');
            }
            await rememberJob(app.id, res, 'updating');
            addToast(`Updating ${app.name}${app.latest_version ? ` to v${app.latest_version.replace(/^v/i, '')}` : ''}...`, 'info');
            setOperatingApp(null);
            mutate();
        } catch (error: unknown) {
            addToast(error instanceof Error ? error.message : 'Network error.', 'error');
            clearPending(app.id);
            setOperatingApp(null);
        }
    };

    const handleUninstall = async (app: App, purge = false) => {
        acceptedJobsRef.current.delete(app.id);
        setOperatingApp(app.id);
        markPending(app.id, 'uninstalling');
        try {
            const res = await apiFetch(`/api/v1/admin/packages/${encodeURIComponent(app.id)}/uninstall${purge ? "?purge=true" : ""}`, { method: 'POST' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                clearPending(app.id);
                throw new Error(data.message || 'Uninstallation request failed');
            }
            await rememberJob(app.id, res, 'uninstalling');
            addToast(`Uninstalling ${app.name}...`, 'info');
            setOperatingApp(null);
            mutate();
        } catch (error: unknown) {
            addToast(error instanceof Error ? error.message : 'Network error.', 'error');
            clearPending(app.id);
            setOperatingApp(null);
        }
    };

    return (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
            <div className="flex flex-col lg:flex-row gap-6 justify-between items-start lg:items-center">
                <div className="space-y-1">
                    <h2 className="text-3xl font-black text-white tracking-tight flex items-center gap-3">
                        AetherMarketplace
                        <span className="text-xs font-medium px-2 py-0.5 bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 rounded-full uppercase tracking-widest">Beta</span>
                    </h2>
                    <p className="text-slate-400 text-sm font-medium">Extend your system with high-performance native modules.</p>
                </div>

                <div className="flex flex-col sm:flex-row gap-3 w-full lg:w-auto">
                    <div className="relative group min-w-0 sm:min-w-[300px] w-full">
                        <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-indigo-400 transition-colors" size={18} />
                        <input
                            type="text"
                            placeholder="Find apps and services..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="w-full bg-slate-900/50 border border-white/10 rounded-xl py-3 pl-12 pr-4 text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/40 focus:border-indigo-500/50 transition-all backdrop-blur-md"
                        />
                    </div>
                </div>
            </div>

            <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-none obs-touch-pills">
                <Filter size={16} className="text-slate-500 shrink-0" />
                {categories.map((cat) => (
                    <button
                        key={cat}
                        onClick={() => setCategoryFilter(cat)}
                        className={`obs-touch-target-standard obs-gpu-120hz-interactive px-4 py-2 rounded-full text-xs font-bold transition-all whitespace-nowrap shadow-sm flex items-center ${categoryFilter === cat ? 'bg-indigo-500 text-white border-indigo-400 shadow-indigo-500/20' : 'bg-slate-900/50 text-slate-400 border border-white/5 hover:border-white/10 hover:text-slate-300'}`}
                    >
                        {cat}
                    </button>
                ))}
            </div>

            {isLoading && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {[1, 2, 3, 4, 5, 6].map((i) => (
                        <div key={i} className="bg-slate-950/40 border border-white/5 h-64 rounded-2xl animate-pulse" />
                    ))}
                </div>
            )}

            {isError && (
                <div className="flex flex-col items-center justify-center py-20 bg-red-500/5 border border-red-500/10 rounded-2xl space-y-4">
                    <AlertCircle className="text-red-400" size={48} />
                    <div className="text-center">
                        <h3 className="text-xl font-bold text-white">Marketplace Unreachable</h3>
                        <p className="text-red-400/70 text-sm mt-1">Check your API connection or server status.</p>
                    </div>
                    <button
                        onClick={() => mutate()}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive px-6 py-2 bg-red-500/15 text-red-400 hover:bg-red-500/25 border border-red-500/20 rounded-lg transition-all text-sm font-bold"
                    >
                        Retry Connection
                    </button>
                </div>
            )}

            {!isLoading && !isError && apps && filteredApps.length === 0 && (
                <div className="text-center text-slate-400 py-12 bg-slate-900/50 rounded-2xl border border-white/5">
                    No applications found matching your criteria.
                </div>
            )}

            {!isLoading && !isError && apps && filteredApps.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 relative z-10">
                    {filteredApps.map((app) => {
                        const effectiveStatus = getEffectiveStatus(app);
                        const busy = isAppBusy(app);

                        return (
                        <div key={app.id} className={`glass-card relative bg-slate-950/40 border rounded-3xl p-6 transition-all group flex flex-col justify-between h-full hover:shadow-2xl hover:shadow-indigo-500/10 ${busy ? 'border-indigo-500/30' : 'border-white/5 hover:border-white/10'}`}>
                            {busy && (
                                <div className="absolute inset-0 bg-slate-950/90 backdrop-blur-md rounded-3xl z-20 flex items-center justify-center p-8 text-center">
                                    <ProgressRing
                                        progress={app.progress || 0}
                                        status={effectiveStatus}
                                        logLine={app.log_line}
                                        startedAt={app.started_at}
                                    />
                                </div>
                            )}

                            <div className="space-y-6">
                                <div className="flex items-start justify-between">
                                    <div className="h-20 w-20 bg-gradient-to-br from-white/10 to-transparent rounded-2xl border border-white/10 flex items-center justify-center shadow-2xl overflow-hidden relative group-hover:border-indigo-500/30 transition-colors">
                                        <AppIcon app={app} />
                                    </div>
                                    <span className="text-[10px] font-black uppercase tracking-widest text-indigo-400/80 bg-indigo-500/5 px-3 py-1 rounded-full border border-indigo-500/10 shadow-sm">
                                        {app.category}
                                    </span>
                                </div>

                                <div className="space-y-2">
                                    <h3 className="text-xl font-black text-slate-100 group-hover:text-white transition-colors tracking-tight">
                                        {app.name}
                                    </h3>
                                    <p className="text-sm text-slate-400 line-clamp-2 leading-relaxed font-medium">{app.desc}</p>
                                </div>

                                <div className="flex flex-wrap gap-2">
                                    {app.status === 'installed' && !pendingJobs.has(app.id) && (
                                        <span className="inline-flex items-center gap-1.5 text-[10px] bg-emerald-500/10 text-emerald-400 px-3 py-1 rounded-full border border-emerald-500/20 font-black uppercase tracking-tighter">
                                            <div className="w-1 h-1 rounded-full bg-emerald-400 animate-pulse" />
                                            Active
                                        </span>
                                    )}
                                    {app.status === 'installed' && app.public_domain && (
                                        <a
                                            href={`${app.tls_enabled === false ? 'http:' : 'https:'}//${app.public_domain}${app.web_path ? (app.web_path.startsWith('/') ? app.web_path : `/${app.web_path}`) : ''}`}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="inline-flex items-center gap-1.5 text-[10px] bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 px-3 py-1 rounded-full border border-indigo-500/20 font-mono transition-colors"
                                            title={`Open ${app.tls_enabled === false ? 'http' : 'https'}://${app.public_domain}`}
                                        >
                                            <Globe size={10} className="text-indigo-400" />
                                            {app.public_domain}
                                        </a>
                                    )}
                                    {app.update_available && !app.update_error && (
                                        <span className="inline-flex items-center gap-1.5 text-[10px] bg-amber-500/10 text-amber-400 px-3 py-1 rounded-full border border-amber-500/20 font-black uppercase tracking-tighter">
                                            <RefreshCw size={10} className="animate-spin-slow" />
                                            v{app.latest_version || 'Update'}
                                        </span>
                                    )}
                                    {app.update_error && (
                                        <span
                                            className="inline-flex items-center gap-1.5 text-[10px] bg-red-500/10 text-red-400 px-3 py-1 rounded-full border border-red-500/20 font-black uppercase tracking-tighter"
                                            title={`Update check failed: ${app.update_error}`}
                                        >
                                            <AlertCircle size={10} />
                                            Check failed
                                        </span>
                                    )}
                                </div>
                            </div>

                            {(() => {
                                const deterministicMultiplier = (app.name.charCodeAt(0) + app.name.length) % 100 / 100;
                                const estimatedInstalls = totalGithubDownloads
                                    ? Math.floor(totalGithubDownloads * (0.05 + deterministicMultiplier * 0.4))
                                    : 0;
                                const displayInstalls = estimatedInstalls > 1000
                                    ? (estimatedInstalls / 1000).toFixed(1) + 'k'
                                    : estimatedInstalls.toString();

                                return (
                                    <div className="mt-10 pt-6 border-t border-white/5 flex items-center justify-between">
                                        <div className="flex items-center gap-2 text-slate-500 text-xs font-bold uppercase tracking-widest opacity-60">
                                            <Download size={14} className="text-indigo-400/60" />
                                            {displayInstalls} <span className="text-[10px] font-medium opacity-50 lowercase tracking-normal">units</span>
                                        </div>
                                        <div className="flex items-center justify-end flex-wrap gap-2 min-w-0">
                                            {app.status === 'installed' && (
                                                <button
                                                    onClick={() => setIngressModalApp(app.id)}
                                                    className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 text-slate-400 hover:text-indigo-400 rounded-xl hover:bg-white/5 transition-colors border border-white/5 flex items-center justify-center"
                                                    title="Ingress & Deployment"
                                                >
                                                    <Globe size={14} />
                                                </button>
                                            )}
                                            {effectiveStatus === 'installed' && app.update_available && !app.update_error && (
                                                <button
                                                    onClick={() => busy ? null : handleUpdate(app)}
                                                    disabled={busy}
                                                    className={`obs-touch-target-standard obs-gpu-120hz-interactive px-4 py-2.5 rounded-xl text-xs font-black transition-all flex items-center gap-1.5 ${busy ? 'bg-slate-900 text-slate-600 cursor-not-allowed shadow-none' : 'bg-amber-500/15 text-amber-300 hover:bg-amber-500 hover:text-slate-950 border border-amber-500/30 shadow-lg shadow-amber-900/10'}`}
                                                    title={app.latest_version ? `Update to v${app.latest_version.replace(/^v/i, '')}` : 'Update available'}
                                                >
                                                    <RefreshCw size={12} />
                                                    Update
                                                </button>
                                            )}
                                            {app.last_job && app.last_job.status !== 'completed' && !busy && <span role="status" className="text-xs text-red-300">Last {app.last_job.action}: {app.last_job.status}. Check logs.</span>}
                                            {effectiveStatus === 'installed' && (
                                                <button disabled={busy} onClick={() => setReinstallAppId(app.id)} className="px-3 py-2 text-xs text-slate-300 rounded-lg border border-white/10 disabled:opacity-50">Reinstall</button>
                                            )}
                                            <button
                                                onClick={() => busy ? null : (effectiveStatus === 'installed' ? setRemoveAppId(app.id) : handleInstall(app))}
                                                disabled={busy}
                                                className={`obs-touch-target-standard obs-gpu-120hz-interactive px-6 py-2.5 rounded-xl text-xs font-black transition-all ${busy ? 'bg-slate-900 text-slate-600 cursor-not-allowed shadow-none' : (effectiveStatus === 'installed' ? 'bg-white/5 text-slate-300 hover:bg-red-500/10 hover:text-red-400 hover:border-red-500/20 border border-transparent shadow-lg' : 'bg-indigo-600 text-white hover:bg-indigo-500 hover:shadow-indigo-500/30 border border-indigo-400/30 shadow-xl shadow-indigo-900/10')}`}
                                            >
                                                {effectiveStatus === 'installed' ? 'Uninstall' : (effectiveStatus === 'installing' ? 'Deploying...' : (effectiveStatus === 'updating' ? 'Updating...' : (effectiveStatus === 'uninstalling' ? 'Removing...' : 'Provision')))}
                                            </button>
                                        </div>
                                    </div>
                                );
                            })()}
                        </div>
                        );
                    })}
                </div>
            )}

            {selectedRemoveApp && (
                <div role="dialog" aria-modal="true" aria-label={`Uninstall ${selectedRemoveApp.name}`} className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
                    <div className="min-w-0 w-full max-w-lg max-h-[90vh] overflow-y-auto bg-slate-900 border border-white/10 rounded-xl p-6 space-y-4">
                        <h3 className="text-lg font-bold">Uninstall {selectedRemoveApp.name}</h3>
                        <p className="text-sm text-slate-300">Ordinary uninstall retains application data, configuration, secrets, and the allocated port for a later reinstall.</p>
                        <label className="flex gap-2 text-sm"><input type="checkbox" checked={purgeData} onChange={event => setPurgeData(event.target.checked)} /> Permanently delete application data and configuration</label>
                        {purgeData && <><p className="text-sm text-red-300">Purge asks the remover to delete {selectedRemoveApp.name}&apos;s managed databases, configuration, credentials, and data. Existing backups may remain. This cannot be undone.</p><label className="block text-sm">Type {selectedRemoveApp.id} to confirm<input aria-label="Purge confirmation" value={purgeConfirmation} onChange={event => setPurgeConfirmation(event.target.value)} className="block w-full mt-2 bg-slate-950 rounded p-2" /></label></>}
                        <div className="flex justify-end gap-3"><button onClick={() => { setRemoveAppId(null); setPurgeData(false); setPurgeConfirmation(''); }}>Cancel</button><button disabled={isAppBusy(selectedRemoveApp) || (purgeData && purgeConfirmation !== selectedRemoveApp.id)} onClick={() => { void handleUninstall(selectedRemoveApp, purgeData); setRemoveAppId(null); setPurgeData(false); setPurgeConfirmation(''); }} className="bg-red-600 disabled:opacity-40 rounded px-4 py-2">{purgeData ? 'Permanently purge' : 'Uninstall and keep data'}</button></div>
                    </div>
                </div>
            )}
            {selectedReinstallApp && (
                <div role="dialog" aria-modal="true" aria-label={`Reinstall ${selectedReinstallApp.name}`} className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
                    <div className="min-w-0 w-full max-w-lg bg-slate-900 border border-white/10 rounded-xl p-6 space-y-4">
                        <h3 className="text-lg font-bold">Reinstall {selectedReinstallApp.name}</h3>
                        <p className="text-sm text-slate-300">Reapply the installer in place using the existing configuration, data, secrets, and allocated port. The application may restart.</p>
                        <div className="flex justify-end gap-3"><button onClick={() => setReinstallAppId(null)}>Cancel</button><button disabled={isAppBusy(selectedReinstallApp)} onClick={() => { void handleInstall(selectedReinstallApp, true); setReinstallAppId(null); }} className="bg-indigo-600 rounded px-4 py-2 disabled:opacity-40">Reinstall and keep data</button></div>
                    </div>
                </div>
            )}

            {/* Installed Plugins & Runtime Extensions Section */}
            <div className="pt-8 border-t border-white/10 space-y-6" data-testid="installed-plugins-section">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="space-y-1">
                        <h3 className="text-xl font-black text-white tracking-tight flex items-center gap-2.5">
                            <Puzzle size={20} className="text-indigo-400" />
                            Installed Plugins &amp; Runtime Extensions
                            <span className="text-[10px] font-bold px-2.5 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full uppercase tracking-widest">
                                Scoped Sandbox v1
                            </span>
                        </h3>
                        <p className="text-slate-400 text-xs font-medium">
                            Isolated loopback companion plugins with manifest-bound short-lived tokens and opaque sandboxed UI origins.
                        </p>
                    </div>
                    <button
                        onClick={() => fetchPlugins()}
                        className="obs-touch-target-standard px-3.5 py-2 rounded-xl bg-slate-900/60 hover:bg-slate-800/80 border border-white/10 text-xs font-bold text-slate-300 flex items-center gap-2 transition-colors self-start sm:self-auto"
                    >
                        <RefreshCw size={13} />
                        Refresh Plugins
                    </button>
                </div>

                {rejectedPlugins.length > 0 && (
                    <div className="rounded-2xl border border-amber-500/20 bg-amber-500/5 p-4 space-y-1" data-testid="rejected-plugins-banner">
                        <p className="text-xs font-bold text-amber-300 uppercase tracking-wider">Rejected Plugin Manifests</p>
                        {rejectedPlugins.map((item) => (
                            <p key={item.id} className="text-xs text-amber-200/80 font-mono">
                                {item.id}: {item.error}
                            </p>
                        ))}
                    </div>
                )}

                {plugins.length === 0 ? (
                    <div className="rounded-2xl border border-white/5 bg-slate-900/30 p-6 text-center text-slate-400 text-xs">
                        No validated plugins discovered in <code className="text-indigo-300">plugins/</code>. Scaffold one with <code className="text-indigo-300">bash scripts/create-plugin-sdk.sh my-plugin &quot;My Plugin&quot; plugins/my-plugin rust</code>.
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {plugins.map((plugin) => {
                            const isBusy = operatingPlugin === plugin.id;
                            return (
                                <div
                                    key={plugin.id}
                                    data-testid={`plugin-card-${plugin.id}`}
                                    className="glass-card bg-slate-950/50 border border-white/10 rounded-3xl p-6 flex flex-col justify-between gap-5"
                                >
                                    <div className="space-y-4">
                                        <div className="flex items-start justify-between gap-3">
                                            <div>
                                                <div className="flex items-center gap-2">
                                                    <h4 className="text-lg font-black text-white">{plugin.name}</h4>
                                                    <span className="text-[10px] font-mono text-slate-400 bg-white/5 px-2 py-0.5 rounded-md">
                                                        v{plugin.version}
                                                    </span>
                                                </div>
                                                <p className="text-[11px] font-mono text-indigo-400 mt-0.5">
                                                    id: {plugin.id} · sdk: {plugin.sdk}
                                                </p>
                                            </div>
                                            <span
                                                className={`text-[10px] font-black uppercase tracking-wider px-2.5 py-1 rounded-full border ${
                                                    plugin.enabled
                                                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                                                        : 'bg-slate-800/80 text-slate-400 border-white/10'
                                                }`}
                                            >
                                                {plugin.enabled ? (plugin.healthy ? 'Healthy' : 'Enabled') : 'Stopped'}
                                            </span>
                                        </div>

                                        <p className="text-xs text-slate-400 leading-relaxed">
                                            {plugin.description || 'Sandboxed AetherFlow runtime extension.'}
                                        </p>

                                        <div className="space-y-1.5">
                                            <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-400">
                                                <ShieldCheck size={12} className="text-indigo-400" />
                                                Granted Scopes
                                            </div>
                                            <div className="flex flex-wrap gap-1.5">
                                                {plugin.granted_scopes.length === 0 ? (
                                                    <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-2 py-0.5 rounded">
                                                        default-deny (no host API scopes)
                                                    </span>
                                                ) : (
                                                    plugin.granted_scopes.map((s, idx) => (
                                                        <span
                                                            key={`${s.method}-${s.route}-${idx}`}
                                                            className="text-[10px] font-mono text-indigo-300 bg-indigo-500/10 border border-indigo-500/20 px-2 py-0.5 rounded"
                                                        >
                                                            {s.method} {s.route}
                                                        </span>
                                                    ))
                                                )}
                                            </div>
                                        </div>
                                    </div>

                                    <div className="pt-4 border-t border-white/5 flex items-center justify-between gap-2">
                                        <span className="text-[10px] font-mono text-slate-500">
                                            {plugin.allocated_port > 0 ? `127.0.0.1:${plugin.allocated_port}` : 'Loopback dynamic'}
                                        </span>
                                        <div className="flex items-center gap-2">
                                            {plugin.enabled && (
                                                <button
                                                    type="button"
                                                    onClick={() => setMountedPlugin(plugin)}
                                                    data-testid={`open-plugin-ui-${plugin.id}`}
                                                    className="px-3 py-2 rounded-xl text-xs font-bold bg-indigo-500/15 text-indigo-300 hover:bg-indigo-500/25 border border-indigo-500/30 flex items-center gap-1.5 transition-all"
                                                >
                                                    <ExternalLink size={12} />
                                                    Open Sandboxed UI
                                                </button>
                                            )}
                                            <button
                                                type="button"
                                                disabled={isBusy}
                                                onClick={() => handlePluginControl(plugin, plugin.enabled ? 'stop' : 'start')}
                                                data-testid={`toggle-plugin-${plugin.id}`}
                                                className={`px-3.5 py-2 rounded-xl text-xs font-black flex items-center gap-1.5 transition-all ${
                                                    plugin.enabled
                                                        ? 'bg-white/5 text-slate-300 hover:bg-red-500/15 hover:text-red-300 border border-white/10'
                                                        : 'bg-indigo-600 text-white hover:bg-indigo-500 border border-indigo-400/30'
                                                }`}
                                            >
                                                {plugin.enabled ? <Square size={11} /> : <Play size={11} />}
                                                {plugin.enabled ? 'Disable' : 'Enable'}
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>

            {mountedPlugin && (
                <div
                    className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in"
                    data-testid="plugin-sandbox-modal"
                >
                    <div className="glass-panel w-full max-w-3xl rounded-3xl p-6 border border-white/10 relative shadow-2xl space-y-4 bg-slate-950">
                        <div className="flex items-center justify-between pb-3 border-b border-white/10">
                            <div className="flex items-center gap-2.5">
                                <ShieldCheck className="text-emerald-400" size={20} />
                                <div>
                                    <h3 className="text-base font-bold text-white">
                                        {mountedPlugin.name} <span className="text-xs font-mono text-slate-400">({mountedPlugin.id})</span>
                                    </h3>
                                    <p className="text-[11px] text-slate-400">
                                        Isolated Opaque Origin Sandbox (<code className="text-emerald-300">sandbox=&quot;allow-scripts&quot;</code>) · Loopback Proxy <code className="text-indigo-300">127.0.0.1:{mountedPlugin.allocated_port}</code>
                                    </p>
                                </div>
                            </div>
                            <button
                                type="button"
                                onClick={() => setMountedPlugin(null)}
                                data-testid="close-plugin-sandbox"
                                className="obs-touch-target-standard p-2 text-slate-400 hover:text-white rounded-lg hover:bg-white/5 transition-colors flex items-center justify-center"
                            >
                                <XCircle size={18} />
                            </button>
                        </div>
                        <div className="rounded-2xl overflow-hidden border border-white/10 bg-slate-950 h-[360px]">
                            <iframe
                                ref={pluginIframeRef}
                                title={`Plugin Sandbox: ${mountedPlugin.name}`}
                                src={mountedPlugin.ui_url}
                                sandbox="allow-scripts"
                                referrerPolicy="no-referrer"
                                data-testid="plugin-sandbox-iframe"
                                className="w-full h-full border-0"
                            />
                        </div>
                    </div>
                </div>
            )}

            {ingressModalApp && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
                    <div className="glass-panel w-full max-w-xl max-h-[85vh] overflow-y-auto rounded-3xl p-6 border border-white/10 relative shadow-2xl">
                        <div className="flex items-center justify-between pb-4 border-b border-white/10">
                            <div className="flex items-center gap-2">
                                <Globe className="text-indigo-400" size={20} />
                                <h3 className="text-lg font-bold text-white capitalize">{ingressModalApp} Ingress & Deploy</h3>
                            </div>
                            <button
                                onClick={() => setIngressModalApp(null)}
                                className="obs-touch-target-standard p-2 text-slate-400 hover:text-white rounded-lg hover:bg-white/5 transition-colors flex items-center justify-center"
                            >
                                <XCircle size={18} />
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
