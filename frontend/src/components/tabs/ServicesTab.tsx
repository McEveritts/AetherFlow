import { RefreshCw, Box, Settings, Globe, RotateCcw, Square, Play } from 'lucide-react';
import { SystemMetrics } from '@/types/dashboard';

interface ServicesTabProps {
    metrics: SystemMetrics;
    onDeployApp?: () => void;
}

export default function ServicesTab({ metrics, onDeployApp }: ServicesTabProps) {
    const servicesEntries = Object.entries(metrics.services);

    return (
        <div className="space-y-6 animate-fade-in">
            <div className="flex justify-between items-end mb-8">
                <div>
                    <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
                        App Ecosystem
                        <span className="text-xs font-semibold px-2.5 py-1 bg-white/10 rounded-full text-slate-300 border border-white/5">{servicesEntries.length} Total</span>
                    </h2>
                    <p className="text-slate-400 text-sm mt-2">Manage and monitor containerized services within the nexus.</p>
                </div>
                <div className="flex gap-3">
                    <button className="px-4 py-2 bg-white/[0.03] hover:bg-white/[0.08] border border-white/10 rounded-lg text-sm font-medium text-slate-300 transition-all flex items-center gap-2">
                        <RefreshCw size={14} /> Sync All
                    </button>
                    <button
                        onClick={onDeployApp}
                        className="px-4 py-2 bg-indigo-500 hover:bg-indigo-400 rounded-lg text-sm font-semibold text-white transition-all shadow-lg shadow-indigo-500/20"
                    >
                        Deploy App
                    </button>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-5">
                {servicesEntries.map(([name, data]) => {
                    const isRunning = data.status === 'running';
                    const isError = data.status === 'error';

                    return (
                        <div key={name} className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-6 hover:bg-white/[0.04] transition-all hover:border-white/10 group cursor-default relative overflow-hidden">

                            {/* Status Glow Banner */}
                            <div className={`absolute top-0 left-0 w-1 h-full ${isRunning ? 'bg-emerald-500/50' : (isError ? 'bg-red-500/50' : 'bg-slate-500/50')} transition-colors`}></div>

                            <div className="flex justify-between items-start mb-6">
                                <div className="flex items-center gap-4">
                                    <div className="h-12 w-12 rounded-2xl bg-slate-900 border border-white/10 flex items-center justify-center shadow-inner group-hover:scale-105 transition-transform">
                                        <Box size={24} className={isRunning ? 'text-emerald-400' : (isError ? 'text-red-400' : 'text-slate-500')} />
                                    </div>
                                    <div>
                                        <h3 className="text-base font-bold text-slate-200 group-hover:text-white transition-colors">{name}</h3>
                                        <div className="flex items-center gap-2 mt-1">
                                            <span className="relative flex h-2 w-2">
                                                {isRunning && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
                                                <span className={`relative inline-flex rounded-full h-2 w-2 ${isRunning ? 'bg-emerald-500' : (isError ? 'bg-red-500' : 'bg-slate-500')}`}></span>
                                            </span>
                                            <span className="text-xs font-medium text-slate-400 capitalize">{data.status}</span>
                                        </div>
                                    </div>
                                </div>
                                <button className="p-2 text-slate-500 hover:text-slate-300 hover:bg-white/5 rounded-lg transition-colors">
                                    <Settings size={18} />
                                </button>
                            </div>

                            <div className="grid grid-cols-2 gap-4 mb-6">
                                <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.02]">
                                    <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Version</span>
                                    <p className="text-sm font-medium text-slate-300 mt-0.5">{data.version}</p>
                                </div>
                                <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.02]">
                                    <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Uptime</span>
                                    <p className="text-sm font-medium text-slate-300 mt-0.5">{data.uptime}</p>
                                </div>
                            </div>

                            <div className="flex gap-2">
                                {isRunning ? (
                                    <>
                                        <button className="flex-1 py-2 bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-2">
                                            <Globe size={14} /> Web UI
                                        </button>
                                        <button className="p-2 bg-slate-800/80 hover:bg-amber-500/20 hover:text-amber-400 text-slate-400 rounded-lg transition-colors">
                                            <RotateCcw size={16} />
                                        </button>
                                        <button className="p-2 bg-slate-800/80 hover:bg-red-500/20 hover:text-red-400 text-slate-400 rounded-lg transition-colors">
                                            <Square size={16} className="fill-current" />
                                        </button>
                                    </>
                                ) : (
                                    <button className="w-full py-2 bg-indigo-500/20 hover:bg-indigo-500 text-indigo-300 hover:text-white text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-2 border border-indigo-500/30">
                                        <Play size={14} className="fill-current" /> Start Service
                                    </button>
                                )}
                            </div>
                        </div>
                    )
                })}
            </div>
        </div>
    );
}
