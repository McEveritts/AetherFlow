import { useState } from 'react';
import { Cpu } from 'lucide-react';
import { HardwareReport, MetricsHistory } from '@/types/dashboard';
import Sparkline from '@/components/charts/Sparkline';

interface CpuWidgetProps {
    cpuData: { usage: number; freq: number; cores: number[] };
    hardware: HardwareReport | null;
    history: MetricsHistory;
    density?: 'compact' | 'immersive';
}

function getCoreColor(pct: number): string {
    if (pct >= 90) return 'bg-rose-500';
    if (pct >= 70) return 'bg-amber-500';
    if (pct >= 50) return 'bg-amber-400';
    if (pct >= 25) return 'bg-indigo-400';
    if (pct >= 10) return 'bg-indigo-500/60';
    return 'bg-slate-800';
}

export default function CpuWidget({ cpuData, hardware, history, density = 'compact' }: CpuWidgetProps) {
    const cores = cpuData.cores || [];
    const isImmersive = density === 'immersive';
    const [selectedCore, setSelectedCore] = useState<number | null>(null);

    return (
        <div className={`rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl relative overflow-hidden flex flex-col justify-between h-full ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                {/* Header */}
                <div className="flex items-center justify-between pb-3 mb-3.5 border-b border-white/[0.06]">
                    <div className="flex items-center gap-2.5 min-w-0">
                        <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shrink-0">
                            <Cpu size={16} />
                        </div>
                        <div className="min-w-0">
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">CPU Utilization</h2>
                            <p className="text-[11px] text-slate-500 truncate mt-1">
                                {hardware?.cpu?.model || `${cores.length || 1} logical cores`}
                            </p>
                        </div>
                    </div>
                    <div className="text-right shrink-0 ml-2">
                        <span className="text-xl font-extrabold tracking-tight text-white tabular-nums">
                            {cpuData.usage.toFixed(1)}%
                        </span>
                    </div>
                </div>

                {/* Sparkline Chart */}
                <div className="rounded-xl overflow-hidden bg-black/30 border border-white/[0.04] mb-3.5">
                    <Sparkline
                        data={history.cpu.length > 0 ? history.cpu : [cpuData.usage, cpuData.usage]}
                        color="#6366f1"
                        gradientFrom="#6366f1"
                        height={isImmersive ? 120 : 88}
                        showArea={true}
                        currentValue={`${cpuData.usage.toFixed(1)}%`}
                    />
                </div>
            </div>

            {/* Per-Core Heatmap Footer */}
            <div className="pt-1">
                <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Per-Core Load</span>
                    <div className="flex items-center gap-2">
                        {selectedCore !== null && cores[selectedCore] !== undefined ? (
                            <span className="text-[10px] font-mono font-bold text-blue-400 bg-blue-500/10 border border-blue-500/20 px-1.5 py-0.5 rounded">
                                C{selectedCore}: {cores[selectedCore].toFixed(1)}%
                            </span>
                        ) : (
                            <span className="text-[10px] font-mono text-slate-500">
                                {cores.length}C / {hardware?.cpu?.threads || cores.length}T
                                {cpuData.freq > 0 ? ` · ${(cpuData.freq / 1000).toFixed(2)} GHz` : ''}
                            </span>
                        )}
                    </div>
                </div>
                <div
                    className="grid gap-1 bg-black/30 p-2 rounded-xl border border-white/[0.04]"
                    style={{ gridTemplateColumns: `repeat(${Math.min(cores.length || 1, 16)}, minmax(0, 1fr))` }}
                >
                    {(cores.length > 0 ? cores : [cpuData.usage]).map((pct, i) => {
                        const isSelected = selectedCore === i;
                        return (
                            <button
                                key={i}
                                type="button"
                                onClick={() => setSelectedCore(isSelected ? null : i)}
                                className="group/core relative focus:outline-none cursor-pointer"
                                aria-label={`Core ${i}: ${pct.toFixed(1)}%`}
                            >
                                <div
                                    className={`h-5 rounded-[3px] ${getCoreColor(pct)} transition-all duration-200 ${isSelected ? 'ring-1 ring-white scale-y-110' : ''}`}
                                    title={`Core ${i}: ${pct.toFixed(1)}%`}
                                />
                                <div className={`absolute -top-7 left-1/2 -translate-x-1/2 bg-slate-900 text-white text-[10px] font-mono font-bold px-1.5 py-0.5 rounded transition-opacity pointer-events-none whitespace-nowrap z-10 border border-white/10 ${isSelected ? 'opacity-100' : 'opacity-0 group-hover/core:opacity-100'}`}>
                                    C{i}: {pct.toFixed(0)}%
                                </div>
                            </button>
                        );
                    })}
                </div>
            </div>
        </div>
    );
}
