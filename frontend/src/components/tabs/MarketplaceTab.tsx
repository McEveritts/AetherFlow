import React, { useState, useMemo, useEffect, useRef } from 'react';
import { useMarketplace, useGithubDownloads, App } from '@/hooks/useMarketplace';
import { Search, Package, Download, RefreshCw, XCircle, AlertCircle, Filter, Globe } from 'lucide-react';
import { useToast } from '@/contexts/ToastContext';
import { ProgressRing } from '@/components/ui/ProgressRing';
import { apiFetch } from '@/lib/fetcher';
import { getSVGLCatalog, matchSVGLLogo } from '@/lib/svgl';
import { ExternalAccessCard } from '@/components/ingress/ExternalAccessCard';
import { DeploymentStatus } from '@/components/deploy/DeploymentStatus';

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
    const { apps, isLoading, isError, mutate, pendingJobs, markPending, clearPending } = useMarketplace();
    const totalGithubDownloads = useGithubDownloads();
    const { addToast } = useToast();
    const [searchQuery, setSearchQuery] = useState('');
    const [categoryFilter, setCategoryFilter] = useState('All');
    const [operatingApp, setOperatingApp] = useState<string | null>(null);
    const [ingressModalApp, setIngressModalApp] = useState<string | null>(null);

    // Job Completion Monitoring
    const prevAppsRef = useRef<App[] | undefined>(undefined);
    const notifiedRef = useRef<Set<string>>(new Set());

    useEffect(() => {
        if (!apps) return;

        apps.forEach(app => {
            const prevApp = prevAppsRef.current?.find(a => a.id === app.id);

            if (prevApp) {
                if (prevApp.status === 'installing' && app.status === 'installed') {
                    if (!notifiedRef.current.has(app.id)) {
                        notifiedRef.current.add(app.id);
                        const domainSuffix = app.public_domain ? ` (${app.public_domain})` : '';
                        addToast(`${app.name} has been successfully installed${domainSuffix}.`, 'success');
                        setTimeout(() => notifiedRef.current.delete(app.id), 5000);
                    }
                }
                if (prevApp.status === 'updating' && app.status === 'installed') {
                    if (!notifiedRef.current.has(app.id)) {
                        notifiedRef.current.add(app.id);
                        const verSuffix = app.installed_version ? ` to v${app.installed_version.replace(/^v/i, '')}` : '';
                        addToast(`${app.name} has been updated${verSuffix}.`, 'success');
                        setTimeout(() => notifiedRef.current.delete(app.id), 5000);
                    }
                }
                if (prevApp.status === 'uninstalling' && app.status !== 'uninstalling' && app.status !== 'installed') {
                    if (!notifiedRef.current.has(app.id)) {
                        notifiedRef.current.add(app.id);
                        addToast(`${app.name} has been successfully removed.`, 'success');
                        setTimeout(() => notifiedRef.current.delete(app.id), 5000);
                    }
                }
                if ((prevApp.status === 'installing' || prevApp.status === 'uninstalling' || prevApp.status === 'updating') && app.status === 'failed') {
                    if (!notifiedRef.current.has(app.id)) {
                        notifiedRef.current.add(app.id);
                        addToast(`Operation failed for ${app.name}. Check system logs.`, 'error');
                        setTimeout(() => notifiedRef.current.delete(app.id), 5000);
                    }
                }
            }

            // Fast-finish: pending action completed before first poll saw the transient state
            if (pendingJobs.has(app.id) && !notifiedRef.current.has(app.id)) {
                const action = pendingJobs.get(app.id);
                if (action === 'installing' && app.status === 'installed') {
                    notifiedRef.current.add(app.id);
                    const domainSuffix = app.public_domain ? ` (${app.public_domain})` : '';
                    addToast(`${app.name} has been successfully installed${domainSuffix}.`, 'success');
                    setTimeout(() => notifiedRef.current.delete(app.id), 5000);
                } else if (action === 'updating' && app.status === 'installed') {
                    notifiedRef.current.add(app.id);
                    const verSuffix = app.installed_version ? ` to v${app.installed_version.replace(/^v/i, '')}` : '';
                    addToast(`${app.name} has been updated${verSuffix}.`, 'success');
                    setTimeout(() => notifiedRef.current.delete(app.id), 5000);
                } else if (action === 'uninstalling' && app.status === 'uninstalled') {
                    notifiedRef.current.add(app.id);
                    addToast(`${app.name} has been successfully removed.`, 'success');
                    setTimeout(() => notifiedRef.current.delete(app.id), 5000);
                } else if (app.status === 'failed') {
                    notifiedRef.current.add(app.id);
                    addToast(`Operation failed for ${app.name}. Check system logs.`, 'error');
                    setTimeout(() => notifiedRef.current.delete(app.id), 5000);
                }
            }
        });

        prevAppsRef.current = apps;
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
        });
    }, [apps, searchQuery, categoryFilter]);

    const isAppBusy = (app: App): boolean => {
        return app.status === 'installing' || app.status === 'uninstalling' || app.status === 'updating' || operatingApp === app.id || pendingJobs.has(app.id);
    };

    const getEffectiveStatus = (app: App): string => {
        if (app.status === 'installing' || app.status === 'uninstalling' || app.status === 'updating') return app.status;
        if (pendingJobs.has(app.id)) return pendingJobs.get(app.id) as string;
        if (operatingApp === app.id) return 'installing';
        return app.status;
    };

    const handleInstall = async (app: App) => {
        setOperatingApp(app.id);
        markPending(app.id, 'installing');
        try {
            const res = await apiFetch(`/api/v1/admin/packages/${app.id}/install`, { method: 'POST' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                clearPending(app.id);
                throw new Error(data.message || 'Installation request failed');
            }
            addToast(`Installation started for ${app.name}`, 'info');
            setOperatingApp(null);
            mutate();
        } catch (error: unknown) {
            addToast(error instanceof Error ? error.message : 'Network error.', 'error');
            clearPending(app.id);
            setOperatingApp(null);
        }
    };

    const handleUpdate = async (app: App) => {
        setOperatingApp(app.id);
        markPending(app.id, 'updating');
        try {
            const res = await apiFetch(`/api/v1/admin/packages/${encodeURIComponent(app.id)}/update`, { method: 'POST' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                clearPending(app.id);
                throw new Error(data.message || 'Update request failed');
            }
            addToast(`Updating ${app.name}${app.latest_version ? ` to v${app.latest_version.replace(/^v/i, '')}` : ''}...`, 'info');
            setOperatingApp(null);
            mutate();
        } catch (error: unknown) {
            addToast(error instanceof Error ? error.message : 'Network error.', 'error');
            clearPending(app.id);
            setOperatingApp(null);
        }
    };

    const handleUninstall = async (app: App) => {
        setOperatingApp(app.id);
        markPending(app.id, 'uninstalling');
        try {
            const res = await apiFetch(`/api/v1/admin/packages/${app.id}/uninstall`, { method: 'POST' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                clearPending(app.id);
                throw new Error(data.message || 'Uninstallation request failed');
            }
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
                                            href={`https://${app.public_domain}${app.web_path ? (app.web_path.startsWith('/') ? app.web_path : `/${app.web_path}`) : ''}`}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="inline-flex items-center gap-1.5 text-[10px] bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 px-3 py-1 rounded-full border border-indigo-500/20 font-mono transition-colors"
                                            title={`Open https://${app.public_domain}`}
                                        >
                                            <Globe size={10} className="text-indigo-400" />
                                            {app.public_domain}
                                        </a>
                                    )}
                                    {app.update_available && (
                                        <span className="inline-flex items-center gap-1.5 text-[10px] bg-amber-500/10 text-amber-400 px-3 py-1 rounded-full border border-amber-500/20 font-black uppercase tracking-tighter">
                                            <RefreshCw size={10} className="animate-spin-slow" />
                                            v{app.latest_version || 'Update'}
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
                                        <div className="flex items-center gap-2">
                                            {app.status === 'installed' && (
                                                <button
                                                    onClick={() => setIngressModalApp(app.id)}
                                                    className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 text-slate-400 hover:text-indigo-400 rounded-xl hover:bg-white/5 transition-colors border border-white/5 flex items-center justify-center"
                                                    title="Ingress & Deployment"
                                                >
                                                    <Globe size={14} />
                                                </button>
                                            )}
                                            {effectiveStatus === 'installed' && app.update_available && (
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
                                            <button
                                                onClick={() => busy ? null : (effectiveStatus === 'installed' ? handleUninstall(app) : handleInstall(app))}
                                                disabled={busy}
                                                className={`obs-touch-target-standard obs-gpu-120hz-interactive px-6 py-2.5 rounded-xl text-xs font-black transition-all ${busy ? 'bg-slate-900 text-slate-600 cursor-not-allowed shadow-none' : (effectiveStatus === 'installed' ? 'bg-white/5 text-slate-300 hover:bg-red-500/10 hover:text-red-400 hover:border-red-500/20 border border-transparent shadow-lg' : 'bg-indigo-600 text-white hover:bg-indigo-500 hover:shadow-indigo-500/30 border border-indigo-400/30 shadow-xl shadow-indigo-900/10')}`}
                                            >
                                                {effectiveStatus === 'installed' ? 'Teardown' : (effectiveStatus === 'installing' ? 'Deploying...' : (effectiveStatus === 'updating' ? 'Updating...' : (effectiveStatus === 'uninstalling' ? 'Removing...' : 'Provision')))}
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
