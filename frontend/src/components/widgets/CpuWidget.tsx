import { useState } from 'react';
import { Cpu } from 'lucide-react';
import { SystemMetrics, HardwareReport, MetricsHistory } from '@/types/dashboard';
import Sparkline from '@/components/charts/Sparkline';

interface CpuWidgetProps {
    cpuData: { usage: number; freq: number; cores: number[] };
    hardware: HardwareReport | null;
    history: MetricsHistory;
    density?: 'compact' | 'immersive';
}

function getCoreColor(pct: number): string {
    if (pct >= 90) return 'bg-red-500';
    if (pct >= 70) return 'bg-orange-500';
    if (pct >= 50) return 'bg-amber-400';
    if (pct >= 25) return 'bg-blue-400';
    if (pct >= 10) return 'bg-blue-500/60';
    return 'bg-slate-700';
}

export default function CpuWidget({ cpuData, hardware, history, density = 'compact' }: CpuWidgetProps) {
    const cores = cpuData.cores || [];
    const isImmersive = density === 'immersive';
    const [selectedCore, setSelectedCore] = useState<number | null>(null);

    return (
        <div className={`glass-card relative overflow-hidden group transition-all duration-300 hover:bg-white/[0.04] ${isImmersive ? 'p-6 space-y-4' : 'p-5'}`}>
            {/* Header */}
            <div className="flex items-center justify-between mb-3">
                <h2 className={`${isImmersive ? 'text-lg' : 'text-sm'} font-semibold text-slate-200 flex items-center gap-2`}>
                    <Cpu size={isImmersive ? 18 : 16} className="text-blue-400" /> CPU Usage
                </h2>
                <div className="flex items-center gap-2">
                    <span className={`${isImmersive ? 'text-3xl' : 'text-2xl'} font-bold tracking-tighter text-white`}>{cpuData.usage.toFixed(1)}%</span>
                </div>
            </div>

            {/* Sparkline Chart */}
            <div className={`rounded-xl overflow-hidden bg-slate-900/50 border border-white/[0.03] transition-all duration-300 ${isImmersive ? 'mb-6 shadow-2xl' : 'mb-4'}`}>
                <Sparkline
                    data={history.cpu.length > 1 ? history.cpu : [0, 0]}
                    color="#6366f1"
                    gradientFrom="#6366f1"
                    height={isImmersive ? 140 : 90}
                    showArea={true}
                    currentValue={`${cpuData.usage.toFixed(1)}%`}
                />
            </div>


            {/* Per-Core Heatmap */}
            <div>
                <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Per-Core Utilization</span>
                    <div className="flex items-center gap-2">
                        {selectedCore !== null && cores[selectedCore] !== undefined && (
                            <span className="text-xs font-mono font-bold text-blue-400 bg-blue-500/10 border border-blue-500/20 px-1.5 py-0.5 rounded">
                                C{selectedCore}: {cores[selectedCore].toFixed(1)}%
                            </span>
                        )}
                        <span className="text-xs text-slate-500 truncate max-w-[160px]">{hardware?.cpu?.model || ''}</span>
                    </div>
                </div>
                <div className="grid gap-1" style={{ gridTemplateColumns: `repeat(${Math.min(cores.length || 1, 16)}, minmax(0, 1fr))` }}>
                    {cores.map((pct, i) => {
                        const isSelected = selectedCore === i;
                        return (
                            <button
                                key={i}
                                type="button"
                                onClick={() => setSelectedCore(isSelected ? null : i)}
                                className="group/core relative py-1 -my-1 focus:outline-none cursor-pointer"
                                aria-label={`Core ${i}: ${pct.toFixed(1)}%`}
                            >
                                <div
                                    className={`h-6 rounded-sm ${getCoreColor(pct)} transition-all duration-200 ${isSelected ? 'ring-1 ring-white scale-y-110' : ''}`}
                                    title={`Core ${i}: ${pct.toFixed(1)}%`}
                                />
                                <div className={`absolute -top-7 left-1/2 -translate-x-1/2 bg-slate-800 text-white text-xs font-bold px-1.5 py-0.5 rounded transition-opacity pointer-events-none whitespace-nowrap z-10 border border-white/10 ${isSelected ? 'opacity-100' : 'opacity-0 group-hover/core:opacity-100'}`}>
                                    C{i}: {pct.toFixed(0)}%
                                </div>
                            </button>
                        );
                    })}
                </div>
                {cores.length > 0 && (
                    <div className="flex items-center gap-2 mt-2 text-xs text-slate-500">
                        <span>{cores.length} cores</span>
                        <span>•</span>
                        <span>{hardware?.cpu?.threads || cores.length} threads</span>
                        {cpuData.freq > 0 && (
                            <>
                                <span>•</span>
                                <span>{(cpuData.freq / 1000).toFixed(2)} GHz</span>
                            </>
                        )}
                    </div>
                )}
            </div>

            <div className="absolute -bottom-16 -right-16 w-48 h-48 bg-blue-500/5 rounded-full blur-3xl pointer-events-none" />
        </div>
    );
}
