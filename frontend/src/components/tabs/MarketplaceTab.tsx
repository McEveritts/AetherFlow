import { useState, useMemo, useEffect } from 'react';
import { Store, Search, Filter, Box, Download, AlertCircle, ChevronDown, RefreshCw } from 'lucide-react';
import { useMarketplace, App } from '@/hooks/useMarketplace';
import { useToast } from '@/contexts/ToastContext';
import Image from 'next/image';
import { apiFetch } from '@/lib/fetcher';
import { ProgressRing } from '@/components/ui/ProgressRing';
import { Modal } from '@/components/ui/Modal';
import { ShieldAlert, CheckCircle, XCircle } from 'lucide-react';

const AppIcon = ({ appId }: { appId: string }) => {
    const [error, setError] = useState(false);

    if (error) {
        return <Box size={28} className="text-slate-300 group-hover:text-indigo-400 transition-colors" />;
    }

    return (
        <Image
            src={`/img/brands/${appId.toLowerCase()}.png`}
            alt={appId}
            width={40}
            height={40}
            className="object-contain group-hover:scale-110 transition-transform duration-300"
            onError={() => setError(true)}
        />
    );
};



export default function MarketplaceTab() {
    const { apps, isLoading, isError, error, mutate } = useMarketplace();
    const { addToast } = useToast();
    const [searchQuery, setSearchQuery] = useState('');
    const [activeCategory, setActiveCategory] = useState('All');
    const [isFilterOpen, setIsFilterOpen] = useState(false);
    const [operatingApp, setOperatingApp] = useState<string | null>(null);

    const [pendingInstall, setPendingInstall] = useState<App | null>(null);
    const [pendingUninstall, setPendingUninstall] = useState<App | null>(null);

    const handleInstall = async (app: App) => {
        setPendingInstall(null);
        setOperatingApp(app.id);
        try {
            const res = await apiFetch(`/api/v1/admin/packages/${app.id}/install`, { method: 'POST' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                throw new Error(data.error || 'Installation request failed');
            }
            addToast(`Provisioning sequence initiated for ${app.id}`, 'info');
            mutate();
        } catch (error: unknown) {
            addToast(error instanceof Error ? error.message : 'Network error.', 'error');
        } finally {
            setOperatingApp(null);
        }
    };

    const handleUninstall = async (app: App) => {
        setPendingUninstall(null);
        setOperatingApp(app.id);
        try {
            const res = await apiFetch(`/api/v1/admin/packages/${app.id}/uninstall`, { method: 'POST' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                throw new Error(data.error || 'Uninstallation request failed');
            }
            addToast(`Tear-down sequence initiated for ${app.id}`, 'info');
            mutate();
        } catch (error: unknown) {
            addToast(error instanceof Error ? error.message : 'Network error.', 'error');
        } finally {
            setOperatingApp(null);
        }
    };

    const categories = useMemo(() => {
        if (!apps) return ['All'];
        const unique = new Set(apps.map(a => a.category));
        return ['All', ...Array.from(unique)].sort();
    }, [apps]);

    const filteredApps = useMemo(() => {
        if (!apps) return [];
        return apps.filter(app => {
            const matchesSearch = app.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                app.desc.toLowerCase().includes(searchQuery.toLowerCase());
            const matchesCategory = activeCategory === 'All' || app.category === activeCategory;
            return matchesSearch && matchesCategory;
        });
    }, [apps, searchQuery, activeCategory]);

    const isAppBusy = (app: App): boolean => {
        return app.status === 'installing' || app.status === 'uninstalling' || operatingApp === app.id;
    };

    const isCatalogMissing = isError && typeof error === 'object' && error !== null && 'status' in error
        && (error as { status?: number }).status === 500;

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-h-screen">
            <div className="absolute inset-0 bg-blue-500/5 rounded-full blur-[120px] pointer-events-none -translate-y-1/2 -translate-x-1/2"></div>

            <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-6 mb-8 relative z-10">
                <div>
                    <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
                        <Store size={28} className="text-indigo-400" />
                        AetherMarketplace
                    </h2>
                    <p className="text-slate-400 text-sm mt-2">Discover and deploy containerized applications with a single click.</p>
                </div>
                <div className="flex gap-3 w-full md:w-auto">
                    <div className="relative flex-1 md:w-64">
                        <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                        <input
                            type="text"
                            placeholder="Search applications..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="w-full bg-slate-900/80 border border-white/10 rounded-lg py-2 pl-9 pr-4 text-sm text-slate-200 focus:outline-none focus:border-indigo-500/50 transition-colors"
                        />
                    </div>
                    <div className="relative">
                        <button
                            onClick={() => setIsFilterOpen(!isFilterOpen)}
                            className="px-3 py-2 bg-slate-900/80 border border-white/10 rounded-lg text-slate-300 hover:text-white transition-colors flex items-center justify-center gap-2"
                        >
                            <Filter size={16} />
                            <span className="text-sm">{activeCategory}</span>
                            <ChevronDown size={14} className={`transition-transform ${isFilterOpen ? 'rotate-180' : ''}`} />
                        </button>

                        {isFilterOpen && (
                            <div className="absolute right-0 mt-2 w-48 bg-slate-900 border border-white/10 rounded-xl shadow-xl overflow-hidden z-50">
                                <div className="max-h-64 overflow-y-auto">
                                    {categories.map(cat => (
                                        <button
                                            key={cat}
                                            onClick={() => {
                                                setActiveCategory(cat);
                                                setIsFilterOpen(false);
                                            }}
                                            className={`w-full text-left px-4 py-2 text-sm hover:bg-white/5 transition-colors ${activeCategory === cat ? 'text-indigo-400 font-medium bg-indigo-500/10' : 'text-slate-300'}`}
                                        >
                                            {cat}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {isLoading && (
                <div className="flex justify-center items-center h-64">
                    <div className="w-8 h-8 border-4 border-indigo-500/20 border-t-indigo-500 rounded-full animate-spin"></div>
                </div>
            )}

            {isCatalogMissing && (
                <div className="bg-amber-500/10 border border-amber-500/20 p-6 rounded-2xl flex flex-col items-center gap-3 text-center">
                    <AlertCircle size={32} className="text-amber-400" />
                    <h3 className="text-lg font-bold text-slate-200">Marketplace Configuration Missing</h3>
                    <p className="text-sm text-slate-400">The package catalog could not be loaded from `packages.json`. Restore the marketplace configuration and retry.</p>
                    <button onClick={() => mutate()} className="mt-2 px-4 py-2 bg-white/5 hover:bg-white/10 text-white text-sm rounded-lg transition-colors">Retry</button>
                </div>
            )}

            {isError && !isCatalogMissing && (
                <div className="bg-red-500/10 border border-red-500/20 p-6 rounded-2xl flex flex-col items-center gap-3 text-center">
                    <AlertCircle size={32} className="text-red-400" />
                    <h3 className="text-lg font-bold text-slate-200">Failed to load catalog</h3>
                    <p className="text-sm text-slate-400">Could not sync with the AetherMarketplace registry. Please try again later.</p>
                    <button onClick={() => mutate()} className="mt-2 px-4 py-2 bg-white/5 hover:bg-white/10 text-white text-sm rounded-lg transition-colors">Retry</button>
                </div>
            )}

            {!isLoading && !isError && apps && filteredApps.length === 0 && (
                <div className="text-center text-slate-400 py-12 bg-slate-900/50 rounded-2xl border border-white/5">
                    No applications found matching your criteria.
                </div>
            )}

            {!isLoading && !isError && apps && filteredApps.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 relative z-10">
                    {filteredApps.map((app) => (
                        <div key={app.id} className={`relative bg-slate-950/80 border rounded-2xl p-6 backdrop-blur-xl transition-all group flex flex-col justify-between h-full ${isAppBusy(app) ? 'border-indigo-500/30' : 'border-white/10 hover:border-indigo-500/50'}`}>

                            {/* Progress overlay when installing/uninstalling */}
                            {isAppBusy(app) && (
                                <div className="absolute inset-0 bg-slate-950/80 backdrop-blur-sm rounded-2xl z-20 flex items-center justify-center">
                                    <ProgressRing
                                        progress={app.progress || 0}
                                        status={app.status}
                                        logLine={app.log_line}
                                        startedAt={app.started_at}
                                    />
                                </div>
                            )}

                            <div>
                                <div className="flex items-start justify-between mb-4">
                                    <div className="h-14 w-14 bg-white/5 rounded-xl border border-white/10 flex items-center justify-center shadow-inner overflow-hidden">
                                        <AppIcon appId={app.id} />
                                    </div>
                                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 bg-white/5 px-2 py-1 rounded-md border border-white/5">
                                        {app.category}
                                    </span>
                                </div>
                                <h3 className="text-lg font-bold text-slate-200 group-hover:text-white transition-colors">
                                    {app.name}
                                </h3>
                                <p className="text-sm text-slate-400 mt-2 line-clamp-2 leading-relaxed">{app.desc}</p>
                                <div className="mt-3 flex flex-wrap gap-2">
                                    {app.status === 'installed' && (
                                        <span className="text-[10px] bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded-full border border-emerald-500/30 uppercase tracking-widest">
                                            Installed
                                        </span>
                                    )}
                                    {app.update_available && (
                                        app.update_url ? (
                                            <a
                                                href={app.update_url}
                                                target="_blank"
                                                rel="noreferrer"
                                                className="inline-flex items-center gap-1 text-[10px] bg-amber-500/15 text-amber-300 px-2 py-0.5 rounded-full border border-amber-400/20 uppercase tracking-widest"
                                            >
                                                <RefreshCw size={10} />
                                                Update {app.latest_version || 'available'}
                                            </a>
                                        ) : (
                                            <span className="inline-flex items-center gap-1 text-[10px] bg-amber-500/15 text-amber-300 px-2 py-0.5 rounded-full border border-amber-400/20 uppercase tracking-widest">
                                                <RefreshCw size={10} />
                                                Update {app.latest_version || 'available'}
                                            </span>
                                        )
                                    )}
                                </div>
                                {(app.installed_version || app.latest_version) && (
                                    <p className="text-[11px] text-slate-500 mt-3">
                                        {app.installed_version ? `Installed ${app.installed_version}` : 'Installed version unavailable'}
                                        {app.latest_version ? ` • Latest ${app.latest_version}` : ''}
                                    </p>
                                )}
                            </div>

                            <div className="mt-8 pt-4 border-t border-white/5 flex items-center justify-between">
                                <div className="flex items-center gap-1.5 text-slate-500 text-xs font-medium">
                                    <Download size={14} />
                                    {(app.hits / 1000).toFixed(1)}k Installs
                                </div>
                                <div className="flex gap-2">
                                    {app.status === 'installed' ? (
                                        <>
                                            <button
                                                className="px-4 py-1.5 bg-slate-800 text-slate-300 hover:text-white text-xs font-semibold rounded-lg transition-colors border border-white/10"
                                            >
                                                Manage
                                            </button>
                                            <button
                                                onClick={() => setPendingUninstall(app)}
                                                disabled={isAppBusy(app)}
                                                className="px-4 py-1.5 bg-red-500/10 text-red-500 hover:bg-red-500 hover:text-white disabled:opacity-50 text-xs font-semibold rounded-lg transition-colors border border-red-500/20"
                                            >
                                                Uninstall
                                            </button>
                                        </>
                                    ) : (
                                        <button
                                            onClick={() => setPendingInstall(app)}
                                            disabled={isAppBusy(app)}
                                            className="px-4 py-1.5 bg-indigo-500 hover:bg-indigo-400 disabled:bg-slate-800 disabled:text-slate-500 text-white text-xs font-semibold rounded-lg shadow-sm transition-all group-hover:shadow-[0_0_15px_rgba(99,102,241,0.4)] disabled:group-hover:shadow-none"
                                        >
                                            Install
                                        </button>
                                    )}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Install Boundary */}
            <Modal isOpen={!!pendingInstall} onClose={() => setPendingInstall(null)}>
                <div className="flex flex-col items-center text-center">
                    <div className="h-16 w-16 bg-indigo-500/20 rounded-2xl border border-indigo-500/30 flex items-center justify-center mb-6 shadow-inner">
                        <Box size={32} className="text-indigo-400" />
                    </div>
                    <h3 className="text-xl font-bold text-slate-100 mb-2">Authorize Provisioning</h3>
                    <p className="text-sm text-slate-400 mb-6">
                        You are about to deploy the <span className="text-indigo-300 font-bold">{pendingInstall?.name}</span> container stack to the bare-metal nexus. This will map required volumes and generic routes.
                    </p>
                    
                    <div className="w-full flex gap-3">
                        <button 
                            onClick={() => pendingInstall && handleInstall(pendingInstall)}
                            className="flex-1 glass-button-primary flex items-center justify-center gap-2 py-3 border-emerald-500/50 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"
                        >
                            <CheckCircle size={18} />
                            <span className="font-bold tracking-wide">AUTHORIZE</span>
                        </button>
                        <button 
                            onClick={() => setPendingInstall(null)}
                            className="flex-1 glass-button flex items-center justify-center gap-2 py-3 text-slate-400 hover:text-slate-200"
                        >
                            <XCircle size={18} />
                            <span className="font-bold tracking-wide">CANCEL</span>
                        </button>
                    </div>
                </div>
            </Modal>

            {/* Uninstall Boundary */}
            <Modal isOpen={!!pendingUninstall} onClose={() => setPendingUninstall(null)}>
                <div className="flex flex-col items-center text-center">
                    <div className="h-16 w-16 bg-red-500/20 rounded-2xl border border-red-500/30 flex items-center justify-center mb-6 shadow-inner">
                        <ShieldAlert size={32} className="text-red-400" />
                    </div>
                    <h3 className="text-xl font-bold text-slate-100 mb-2">Destructive Action Required</h3>
                    <p className="text-sm text-slate-400 mb-6">
                        You are about to fully dismantle the <span className="text-red-300 font-bold">{pendingUninstall?.name}</span> infrastructure. This will tear down the container state. Persistent volume data will <span className="font-bold text-slate-200 underline">not</span> be deleted automatically.
                    </p>
                    
                    <div className="w-full flex gap-3">
                        <button 
                            onClick={() => pendingUninstall && handleUninstall(pendingUninstall)}
                            className="flex-1 glass-button-primary flex items-center justify-center gap-2 py-3 border-red-500/50 bg-red-500/10 text-red-400 hover:bg-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.2)] hover:shadow-[0_0_20px_rgba(239,68,68,0.4)]"
                        >
                            <CheckCircle size={18} />
                            <span className="font-bold tracking-wide">CONFIRM TEAR-DOWN</span>
                        </button>
                        <button 
                            onClick={() => setPendingUninstall(null)}
                            className="flex-1 glass-button flex items-center justify-center gap-2 py-3 text-slate-400 hover:text-slate-200"
                        >
                            <XCircle size={18} />
                            <span className="font-bold tracking-wide">CANCEL</span>
                        </button>
                    </div>
                </div>
            </Modal>
        </div>
    );
}
