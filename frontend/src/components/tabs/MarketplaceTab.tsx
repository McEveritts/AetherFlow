import { Store, Search, Filter, Box, Download } from 'lucide-react';

const MOCK_APPS = [
    { name: 'Jellyfin', desc: 'The Free Software Media System.', hits: 15400, category: 'Media' },
    { name: 'Nextcloud', desc: 'A safe home for all your data.', hits: 32000, category: 'Storage' },
    { name: 'Home Assistant', desc: 'Open source home automation.', hits: 25000, category: 'Smart Home' },
    { name: 'Pi-hole', desc: 'Network-wide Ad Blocking.', hits: 18500, category: 'Network' },
    { name: 'qBittorrent', desc: 'A Qt5 bittorrent client.', hits: 11200, category: 'Downloaders' },
    { name: 'Vaultwarden', desc: 'Unofficial Bitwarden compatible server.', hits: 9000, category: 'Security' },
];

export default function MarketplaceTab() {
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
                            className="w-full bg-slate-900/80 border border-white/10 rounded-lg py-2 pl-9 pr-4 text-sm text-slate-200 focus:outline-none focus:border-indigo-500/50 transition-colors"
                        />
                    </div>
                    <button className="px-3 py-2 bg-slate-900/80 border border-white/10 rounded-lg text-slate-300 hover:text-white transition-colors flex items-center justify-center">
                        <Filter size={16} />
                    </button>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 relative z-10">
                {MOCK_APPS.map((app, idx) => (
                    <div key={idx} className="bg-slate-950/80 border border-white/10 rounded-2xl p-6 backdrop-blur-xl hover:border-indigo-500/50 transition-all group flex flex-col justify-between h-full">
                        <div>
                            <div className="flex items-start justify-between mb-4">
                                <div className="h-14 w-14 bg-white/5 rounded-xl border border-white/10 flex items-center justify-center shadow-inner overflow-hidden">
                                    <Box size={28} className="text-slate-300 group-hover:text-indigo-400 transition-colors" />
                                </div>
                                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 bg-white/5 px-2 py-1 rounded-md border border-white/5">
                                    {app.category}
                                </span>
                            </div>
                            <h3 className="text-lg font-bold text-slate-200 group-hover:text-white transition-colors">{app.name}</h3>
                            <p className="text-sm text-slate-400 mt-2 line-clamp-2 leading-relaxed">{app.desc}</p>
                        </div>

                        <div className="mt-8 pt-4 border-t border-white/5 flex items-center justify-between">
                            <div className="flex items-center gap-1.5 text-slate-500 text-xs font-medium">
                                <Download size={14} />
                                {(app.hits / 1000).toFixed(1)}k Installs
                            </div>
                            <button className="px-4 py-1.5 bg-indigo-500 hover:bg-indigo-400 text-white text-xs font-semibold rounded-lg shadow-sm transition-all group-hover:shadow-[0_0_15px_rgba(99,102,241,0.4)]">
                                Install
                            </button>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}
