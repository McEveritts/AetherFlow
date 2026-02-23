import { MemoryStick } from 'lucide-react';
import { SystemMetrics, HardwareReport } from '@/types/dashboard';

interface MemoryWidgetProps {
    metrics: SystemMetrics;
    hardware: HardwareReport | null;
}

export default function MemoryWidget({ metrics, hardware }: MemoryWidgetProps) {
    return (
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-6 relative overflow-hidden group hover:bg-white/[0.04] transition-colors backdrop-blur-xl">
            <div className="flex items-center justify-between mb-6">
                <h2 className="text-base font-semibold text-slate-200 flex items-center gap-2">
                    <MemoryStick size={18} className="text-purple-400" /> Memory Usage
                </h2>
                <span className="text-xs font-medium px-2.5 py-1 bg-white/5 rounded-full text-slate-400">{hardware?.memory?.type || 'System RAM'}</span>
            </div>
            <div className="flex items-end space-x-2 mt-4">
                <span className="text-5xl font-bold tracking-tighter text-purple-400 relative z-10 w-24">
                    {metrics.memory.used.toFixed(1)}
                </span>
                <span className="text-slate-400 mb-2 relative z-10 font-medium">/ {metrics.memory.total.toFixed(0)} GB</span>
            </div>

            <div className="mt-8 space-y-2 relative z-10">
                <div className="flex justify-between text-xs text-slate-400 font-medium">
                    <span>Used ({(metrics.memory.used / metrics.memory.total * 100).toFixed(0)}%)</span>
                    <span>Free</span>
                </div>
                <div className="h-3 w-full bg-slate-800/80 rounded-full overflow-hidden shadow-inner flex">
                    <div
                        className="h-full bg-gradient-to-r from-purple-600 to-purple-400 transition-all duration-500 ease-out"
                        style={{ width: `${(metrics.memory.used / metrics.memory.total) * 100}%` }}
                    />
                </div>
            </div>
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full h-full bg-purple-500/5 rounded-full blur-3xl pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity"></div>
        </div>
    );
}
