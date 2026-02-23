import { MemoryStick } from 'lucide-react';
import { SystemMetrics, HardwareReport, MetricsHistory } from '@/types/dashboard';
import Sparkline from '@/components/charts/Sparkline';

interface MemoryWidgetProps {
    metrics: SystemMetrics;
    hardware: HardwareReport | null;
    history: MetricsHistory;
}

export default function MemoryWidget({ metrics, hardware, history }: MemoryWidgetProps) {
    const memPct = metrics.memory.total > 0 ? (metrics.memory.used / metrics.memory.total) * 100 : 0;
    const swapPct = metrics.swap?.total > 0 ? (metrics.swap.used / metrics.swap.total) * 100 : 0;
    const hasSwap = metrics.swap?.total > 0;

    return (
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 relative overflow-hidden group hover:bg-white/[0.04] transition-colors backdrop-blur-xl">
            {/* Header */}
            <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                    <MemoryStick size={16} className="text-purple-400" /> Memory
                </h2>
                <div className="flex items-baseline gap-1">
                    <span className="text-2xl font-bold tracking-tighter text-white">{metrics.memory.used.toFixed(1)}</span>
                    <span className="text-sm text-slate-400">/ {metrics.memory.total.toFixed(0)} GB</span>
                </div>
            </div>

            {/* Sparkline */}
            <div className="rounded-xl overflow-hidden bg-slate-900/50 border border-white/[0.03] mb-4">
                <Sparkline
                    data={history.memory.length > 1 ? history.memory : [0, 0]}
                    color="#a855f7"
                    gradientFrom="#a855f7"
                    height={90}
                    showArea={true}
                    currentValue={`${memPct.toFixed(1)}%`}
                />
            </div>

            {/* RAM Bar */}
            <div className="space-y-3">
                <div>
                    <div className="flex justify-between text-[10px] text-slate-400 font-semibold uppercase tracking-wider mb-1.5">
                        <span>RAM Used ({memPct.toFixed(0)}%)</span>
                        <span>{(metrics.memory.total - metrics.memory.used).toFixed(1)} GB free</span>
                    </div>
                    <div className="h-2.5 w-full bg-slate-800/80 rounded-full overflow-hidden flex">
                        <div
                            className="h-full bg-gradient-to-r from-purple-600 to-purple-400 transition-all duration-500 rounded-full"
                            style={{ width: `${memPct}%` }}
                        />
                    </div>
                </div>

                {/* Swap Bar */}
                {hasSwap && (
                    <div>
                        <div className="flex justify-between text-[10px] text-slate-400 font-semibold uppercase tracking-wider mb-1.5">
                            <span>Swap ({swapPct.toFixed(0)}%)</span>
                            <span>{metrics.swap.used.toFixed(2)} / {metrics.swap.total.toFixed(1)} GB</span>
                        </div>
                        <div className="h-2 w-full bg-slate-800/80 rounded-full overflow-hidden flex">
                            <div
                                className="h-full bg-gradient-to-r from-fuchsia-600 to-fuchsia-400 transition-all duration-500 rounded-full"
                                style={{ width: `${swapPct}%` }}
                            />
                        </div>
                    </div>
                )}
            </div>

            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full h-full bg-purple-500/5 rounded-full blur-3xl pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />
        </div>
    );
}
