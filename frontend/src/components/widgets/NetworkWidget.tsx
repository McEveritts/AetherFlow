import { Network, ChevronRight } from 'lucide-react';
import { SystemMetrics, HardwareReport } from '@/types/dashboard';

interface NetworkWidgetProps {
    metrics: SystemMetrics;
    hardware: HardwareReport | null;
}

export default function NetworkWidget({ metrics, hardware }: NetworkWidgetProps) {
    return (
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-6 relative overflow-hidden group hover:bg-white/[0.04] transition-colors backdrop-blur-xl border-t-emerald-500/20 shadow-[0_-4px_24px_-12px_rgba(16,185,129,0.1)]">
            <div className="flex items-center justify-between mb-6">
                <h2 className="text-base font-semibold text-slate-200 flex items-center gap-2" title={hardware?.network?.[0]?.product || 'Network Adapter'}>
                    <Network size={18} className="text-emerald-400" /> <span className="max-w-[150px] truncate">{hardware?.network?.[0]?.product || 'Network Traffic'}</span>
                </h2>
                <span className="flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-2 w-2 rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                </span>
            </div>

            <div className="space-y-6 relative z-10 mt-2">
                <div className="bg-slate-900/50 p-4 rounded-2xl border border-white/5 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-emerald-500/20 rounded-lg"><ChevronRight size={16} className="text-emerald-400 rotate-90" /></div>
                        <span className="text-sm font-medium text-slate-300">Download</span>
                    </div>
                    <span className="text-xl font-bold tracking-tight text-white">{metrics.network.down}</span>
                </div>
                <div className="bg-slate-900/50 p-4 rounded-2xl border border-white/5 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-blue-500/20 rounded-lg"><ChevronRight size={16} className="text-blue-400 -rotate-90" /></div>
                        <span className="text-sm font-medium text-slate-300">Upload</span>
                    </div>
                    <span className="text-xl font-bold tracking-tight text-white">{metrics.network.up}</span>
                </div>
            </div>
        </div>
    );
}
