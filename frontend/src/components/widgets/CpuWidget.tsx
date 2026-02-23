import { Cpu } from 'lucide-react';
import { SystemMetrics, HardwareReport, MetricsHistory } from '@/types/dashboard';
import Sparkline from '@/components/charts/Sparkline';

interface CpuWidgetProps {
    metrics: SystemMetrics;
    hardware: HardwareReport | null;
    history: MetricsHistory;
}

function getCoreColor(pct: number): string {
    if (pct >= 90) return 'bg-red-500';
    if (pct >= 70) return 'bg-orange-500';
    if (pct >= 50) return 'bg-amber-400';
    if (pct >= 25) return 'bg-blue-400';
    if (pct >= 10) return 'bg-blue-500/60';
    return 'bg-slate-700';
}

export default function CpuWidget({ metrics, hardware, history }: CpuWidgetProps) {
    const cores = metrics.per_core_cpu || [];

    return (
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 relative overflow-hidden group hover:bg-white/[0.04] transition-colors backdrop-blur-xl">
            {/* Header */}
            <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                    <Cpu size={16} className="text-blue-400" /> CPU Usage
                </h2>
                <div className="flex items-center gap-2">
                    <span className="text-2xl font-bold tracking-tighter text-white">{metrics.cpu_usage.toFixed(1)}%</span>
                </div>
            </div>

            {/* Sparkline Chart */}
            <div className="rounded-xl overflow-hidden bg-slate-900/50 border border-white/[0.03] mb-4">
                <Sparkline
                    data={history.cpu.length > 1 ? history.cpu : [0, 0]}
                    color="#6366f1"
                    gradientFrom="#6366f1"
                    height={90}
                    showArea={true}
                    currentValue={`${metrics.cpu_usage.toFixed(1)}%`}
                />
            </div>

            {/* Per-Core Heatmap */}
            <div>
                <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Per-Core Utilization</span>
                    <span className="text-[10px] text-slate-500">{hardware?.cpu?.model || ''}</span>
                </div>
                <div className="grid gap-1" style={{ gridTemplateColumns: `repeat(${Math.min(cores.length, 16)}, minmax(0, 1fr))` }}>
                    {cores.map((pct, i) => (
                        <div key={i} className="group/core relative">
                            <div
                                className={`h-5 rounded-sm ${getCoreColor(pct)} transition-colors duration-300`}
                                title={`Core ${i}: ${pct.toFixed(1)}%`}
                            />
                            <div className="absolute -top-7 left-1/2 -translate-x-1/2 bg-slate-800 text-white text-[9px] font-bold px-1.5 py-0.5 rounded opacity-0 group-hover/core:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-10 border border-white/10">
                                C{i}: {pct.toFixed(0)}%
                            </div>
                        </div>
                    ))}
                </div>
                {cores.length > 0 && (
                    <div className="flex items-center gap-2 mt-2 text-[9px] text-slate-500">
                        <span>{cores.length} cores</span>
                        <span>•</span>
                        <span>{hardware?.cpu?.threads || cores.length} threads</span>
                        {metrics.cpu_freq_mhz > 0 && (
                            <>
                                <span>•</span>
                                <span>{(metrics.cpu_freq_mhz / 1000).toFixed(2)} GHz</span>
                            </>
                        )}
                    </div>
                )}
            </div>

            <div className="absolute -bottom-16 -right-16 w-48 h-48 bg-blue-500/5 rounded-full blur-3xl pointer-events-none" />
        </div>
    );
}
