import { useState, useMemo } from 'react';
import { Store, Search, Filter, Box, Download, AlertCircle, ChevronDown } from 'lucide-react';
import { useMarketplace } from '@/hooks/useMarketplace';
import { useToast } from '@/contexts/ToastContext';

const AppIcon = ({ appId }: { appId: string }) => {
    const [error, setError] = useState(false);

    if (error) {
        return <Box size={28} className="text-slate-300 group-hover:text-indigo-400 transition-colors" />;
    }

    return (
        <img
            src={`/img/brands/${appId.toLowerCase()}.png`}
            alt={appId}
            className="w-10 h-10 object-contain group-hover:scale-110 transition-transform duration-300"
            onError={() => setError(true)}
        />
    );
};

export default function MarketplaceTab() {
    const { apps, isLoading, isError, mutate } = useMarketplace();
    const { addToast } = useToast();
    const [searchQuery, setSearchQuery] = useState('');
    const [activeCategory, setActiveCategory] = useState('All');
    const [isFilterOpen, setIsFilterOpen] = useState(false);
    const [operatingApp, setOperatingApp] = useState<string | null>(null);

    const handleInstall = async (id: string) => {
        setOperatingApp(id);
        try {
            const res = await fetch(`http://localhost:8080/api/packages/${id}/install`, { method: 'POST' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                throw new Error(data.error || 'Installation request failed');
            }
            addToast(`Installation started for ${id}`, 'success');
            mutate();
        } catch (error: any) {
            addToast(error.message || 'Network error.', 'error');
        } finally {
            setOperatingApp(null);
        }
    };

    const handleUninstall = async (id: string) => {
        setOperatingApp(id);
        try {
            const res = await fetch(`http://localhost:8080/api/packages/${id}/uninstall`, { method: 'POST' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                throw new Error(data.error || 'Uninstallation request failed');
            }
            addToast(`Uninstallation started for ${id}`, 'success');
            mutate();
        } catch (error: any) {
            addToast(error.message || 'Network error.', 'error');
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

            {isError && (
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
                        <div key={app.id} className="bg-slate-950/80 border border-white/10 rounded-2xl p-6 backdrop-blur-xl hover:border-indigo-500/50 transition-all group flex flex-col justify-between h-full">
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
                                    {app.status === 'installed' && <span className="ml-2 text-[10px] bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded-full border border-emerald-500/30 uppercase tracking-widest align-middle">Installed</span>}
                                </h3>
                                <p className="text-sm text-slate-400 mt-2 line-clamp-2 leading-relaxed">{app.desc}</p>
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
                                                onClick={() => handleUninstall(app.id)}
                                                disabled={operatingApp === app.id}
                                                className="px-4 py-1.5 bg-red-500/10 text-red-500 hover:bg-red-500 hover:text-white disabled:opacity-50 text-xs font-semibold rounded-lg transition-colors border border-red-500/20"
                                            >
                                                {operatingApp === app.id ? 'Working...' : 'Uninstall'}
                                            </button>
                                        </>
                                    ) : (
                                        <button
                                            onClick={() => handleInstall(app.id)}
                                            disabled={app.status === 'installing' || operatingApp === app.id}
                                            className="px-4 py-1.5 bg-indigo-500 hover:bg-indigo-400 disabled:bg-slate-800 disabled:text-slate-500 text-white text-xs font-semibold rounded-lg shadow-sm transition-all group-hover:shadow-[0_0_15px_rgba(99,102,241,0.4)] disabled:group-hover:shadow-none"
                                        >
                                            {app.status === 'installing' || operatingApp === app.id ? 'Installing...' : 'Install'}
                                        </button>
                                    )}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
