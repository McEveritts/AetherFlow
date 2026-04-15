import React, { useState, useMemo, useEffect, useRef } from 'react';
import { useMarketplace, useGithubDownloads, App, PendingAction } from '@/hooks/useMarketplace';
import { Search, Package, Download, RefreshCw, XCircle, CheckCircle2, AlertCircle, Info, Filter } from 'lucide-react';
import { useToast } from '@/contexts/ToastContext';
import { ProgressRing } from '@/components/ui/ProgressRing';
import { apiFetch } from '@/lib/fetcher';

const AppIcon = ({ app }: { app: App }) => {
    const [iconError, setIconError] = useState(false);
    const iconPath = `/img/${app.id.toLowerCase()}.png`;

    if (iconError) {
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
                src={iconPath}
                onError={() => setIconError(true)}
                className="w-full h-full object-contain p-2"
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
                        addToast(`${app.name} has been successfully installed.`, 'success');
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
                if ((prevApp.status === 'installing' || prevApp.status === 'uninstalling') && app.status === 'failed') {
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
                    addToast(`${app.name} has been successfully installed.`, 'success');
                    setTimeout(() => notifiedRef.current.delete(app.id), 5000);
                }
                if (action === 'uninstalling' && app.status === 'uninstalled') {
                    notifiedRef.current.add(app.id);
                    addToast(`${app.name} has been successfully removed.`, 'success');
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
        return app.status === 'installing' || app.status === 'uninstalling' || operatingApp === app.id || pendingJobs.has(app.id);
    };

    /** Resolve the effective display status for the progress overlay.
     *  If the server hasn't caught up yet, use the locally-known pending action. */
    const getEffectiveStatus = (app: App): string => {
        if (app.status === 'installing' || app.status === 'uninstalling') return app.status;
        if (pendingJobs.has(app.id)) return pendingJobs.get(app.id) as string;
        if (operatingApp === app.id) return 'installing'; // fallback
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
                    <div className="relative group min-w-[300px]">
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

            <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-none">
                <Filter size={16} className="text-slate-500 shrink-0" />
                {categories.map((cat) => (
                    <button
                        key={cat}
                        onClick={() => setCategoryFilter(cat)}
                        className={`px-4 py-1.5 rounded-full text-xs font-bold transition-all whitespace-nowrap shadow-sm ${categoryFilter === cat ? 'bg-indigo-500 text-white border-indigo-400 shadow-indigo-500/20' : 'bg-slate-900/50 text-slate-400 border border-white/5 hover:border-white/10 hover:text-slate-300'}`}
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
                        className="px-6 py-2 bg-red-500/15 text-red-400 hover:bg-red-500/25 border border-red-500/20 rounded-lg transition-all text-sm font-bold"
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
                        <div key={app.id} className={`relative bg-slate-950/40 border rounded-3xl p-6 backdrop-blur-xl transition-all group flex flex-col justify-between h-full hover:shadow-2xl hover:shadow-indigo-500/10 ${busy ? 'border-indigo-500/30' : 'border-white/5 hover:border-white/10'}`}>
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
                                        <button
                                            onClick={() => busy ? null : (app.status === 'installed' ? handleUninstall(app) : handleInstall(app))}
                                            disabled={busy}
                                            className={`px-6 py-2.5 rounded-xl text-xs font-black transition-all transform active:scale-95 ${busy ? 'bg-slate-900 text-slate-600 cursor-not-allowed shadow-none' : (app.status === 'installed' ? 'bg-white/5 text-slate-300 hover:bg-red-500/10 hover:text-red-400 hover:border-red-500/20 border border-transparent shadow-lg' : 'bg-indigo-600 text-white hover:bg-indigo-500 hover:shadow-indigo-500/30 border border-indigo-400/30 shadow-xl shadow-indigo-900/10')}`}
                                        >
                                            {app.status === 'installed' ? 'Teardown' : (app.status === 'installing' ? 'Deploying...' : 'Provision')}
                                        </button>
                                    </div>
                                );
                            })()}
                        </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}