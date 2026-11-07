import { useState } from 'react';
import { Cpu, ChevronDown } from 'lucide-react';
import { HardwareReport, MetricsHistory } from '@/types/dashboard';
import Sparkline from '@/components/charts/Sparkline';

interface CpuWidgetProps {
    cpuData: { usage: number; freq: number; cores: number[] };
    hardware: HardwareReport | null;
    history: MetricsHistory;
    density?: 'compact' | 'immersive';
    selectedWindow?: string;
    hasSharedSummary?: boolean;
}

function getCoreColor(loadPercentage: number): string {
    if (loadPercentage >= 90) return 'bg-rose-500';
    if (loadPercentage >= 70) return 'bg-amber-500';
    if (loadPercentage >= 50) return 'bg-amber-400';
    if (loadPercentage >= 25) return 'bg-indigo-400';
    if (loadPercentage >= 10) return 'bg-indigo-500/60';
    return 'bg-slate-800';
}

export default function CpuWidget({ cpuData, hardware, history, density = 'compact', selectedWindow, hasSharedSummary }: CpuWidgetProps) {
    const coresList = cpuData.cores || [];
    const isImmersive = density === 'immersive';
    const [selectedCoreIndex, setSelectedCoreIndex] = useState<number | null>(null);

    const physicalCores = hardware?.cpu?.cores;
    const logicalThreads = hardware?.cpu?.threads || coresList.length;
    const processorSummary = physicalCores
        ? `${physicalCores} Physical Cores · ${logicalThreads} Logical Processors`
        : `${logicalThreads} Logical Processors`;

    return (
        <div className={`rounded-2xl border border-slate-800/80 bg-slate-900/85 backdrop-blur-xl relative overflow-hidden flex flex-col ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div className="flex flex-col space-y-3.5">
                <div>
                    <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800/80">
                        <div className="flex items-center gap-2.5 min-w-0">
                            <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shrink-0">
                                <Cpu size={16} />
                            </div>
                            <div className="min-w-0">
                                <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">CPU Utilization</h2>
                                <p className="text-[13px] text-slate-300 break-words sm:truncate mt-1">
                                    {hardware?.cpu?.model || processorSummary}
                                </p>
                            </div>
                        </div>
                        <div className="text-right shrink-0 ml-2">
                            <span className="text-xl font-extrabold tracking-tight text-white tabular-nums">
                                {cpuData.usage.toFixed(1)}%
                            </span>
                        </div>
                    </div>

                    <div
                        role="meter"
                        aria-valuenow={Number(cpuData.usage.toFixed(1))}
                        aria-valuemin={0}
                        aria-valuemax={100}
                        aria-label="Current CPU utilization"
                        aria-valuetext={`${cpuData.usage.toFixed(1)}%`}
                        className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden mb-3"
                    >
                        <div
                            className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-all duration-300 rounded-full"
                            style={{ width: `${Math.min(100, Math.max(cpuData.usage > 0 ? 1 : 0, cpuData.usage))}%` }}
                        />
                    </div>

                    <div className="rounded-xl overflow-hidden bg-slate-950/60 border border-slate-800/60">
                        <Sparkline
                            data={history.cpu.length > 0 ? history.cpu : (cpuData.usage !== undefined ? [cpuData.usage] : [])}
                            color="#6366f1"
                            gradientFrom="#6366f1"
                            height={isImmersive ? 136 : 104}
                            showArea={true}
                            isPercentage={true}
                            yDomain={[0, 100]}
                            showMagnitudeReferences={true}
                            timestamps={history.timestamps}
                            selectedWindow={selectedWindow}
                            currentValue={`${cpuData.usage.toFixed(1)}%`}
                            hasSharedSummary={hasSharedSummary}
                        />
                    </div>
                </div>

                <div className="pt-1">
                    <details className="group/disclosure bg-slate-950/60 rounded-xl border border-slate-800/60 overflow-hidden text-xs">
                        <summary
                            data-testid="cpu-processors-summary"
                            className="min-h-[44px] cursor-pointer list-none flex items-center justify-between px-3 py-2.5 text-[13px] text-slate-300 font-semibold hover:text-white select-none transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
                        >
                            <div className="flex items-center gap-2">
                                <span>Logical Processors ({logicalThreads})</span>
                                {cpuData.freq > 0 && (
                                    <span className="text-[13px] text-slate-300 font-mono font-normal">
                                        · {(cpuData.freq / 1000).toFixed(2)} GHz
                                    </span>
                                )}
                            </div>
                            <ChevronDown size={14} className="text-indigo-400 group-open/disclosure:rotate-180 transition-transform" />
                        </summary>

                        <div className="p-3 pt-1 border-t border-slate-800/60 space-y-2.5">
                            <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] text-slate-400">
                                <span>Load Legend:</span>
                                <div className="flex items-center gap-2 font-mono">
                                    <span className="inline-flex items-center gap-1">
                                        <span className="w-2.5 h-2.5 rounded-sm bg-slate-800 border border-slate-700" /> &lt;10%
                                    </span>
                                    <span className="inline-flex items-center gap-1">
                                        <span className="w-2.5 h-2.5 rounded-sm bg-indigo-500/60" /> 10-24%
                                    </span>
                                    <span className="inline-flex items-center gap-1">
                                        <span className="w-2.5 h-2.5 rounded-sm bg-indigo-400" /> 25-49%
                                    </span>
                                    <span className="inline-flex items-center gap-1">
                                        <span className="w-2.5 h-2.5 rounded-sm bg-amber-400" /> 50-69%
                                    </span>
                                    <span className="inline-flex items-center gap-1">
                                        <span className="w-2.5 h-2.5 rounded-sm bg-amber-500" /> 70-89%
                                    </span>
                                    <span className="inline-flex items-center gap-1">
                                        <span className="w-2.5 h-2.5 rounded-sm bg-rose-500" /> &ge;90%
                                    </span>
                                </div>
                            </div>

                            {selectedCoreIndex !== null && coresList[selectedCoreIndex] !== undefined && (
                                <div className="text-xs font-mono font-bold text-blue-400 bg-blue-500/10 border border-blue-500/20 px-2.5 py-1 rounded-lg">
                                    Processor {selectedCoreIndex}: {coresList[selectedCoreIndex].toFixed(1)}% utilization
                                </div>
                            )}

                            <div
                                className="grid gap-1 bg-slate-950/80 p-2.5 rounded-xl border border-slate-800/60 max-h-[160px] overflow-y-auto"
                                style={{ gridTemplateColumns: `repeat(${Math.min(coresList.length || 1, 16)}, minmax(0, 1fr))` }}
                            >
                                {(coresList.length > 0 ? coresList : [cpuData.usage]).map((corePercentage, coreIndex) => {
                                    const isCoreSelected = selectedCoreIndex === coreIndex;
                                    return (
                                        <button
                                            key={coreIndex}
                                            type="button"
                                            onClick={() => setSelectedCoreIndex(isCoreSelected ? null : coreIndex)}
                                            className="group/core relative focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 rounded cursor-pointer min-h-[28px] flex items-center justify-center"
                                            aria-label={`Processor ${coreIndex}: ${corePercentage.toFixed(1)}%`}
                                        >
                                            <div
                                                className={`w-full h-5 rounded-[2px] ${getCoreColor(corePercentage)} transition-all duration-200 ${isCoreSelected ? 'ring-2 ring-white scale-y-110' : ''}`}
                                                title={`Processor ${coreIndex}: ${corePercentage.toFixed(1)}%`}
                                            />
                                            <div className={`absolute -top-7 left-1/2 -translate-x-1/2 bg-slate-900 text-white text-[10px] font-mono font-bold px-2 py-0.5 rounded transition-opacity pointer-events-none whitespace-nowrap z-20 border border-slate-700 ${isCoreSelected ? 'opacity-100' : 'opacity-0 group-hover/core:opacity-100'}`}>
                                                P{coreIndex}: {corePercentage.toFixed(0)}%
                                            </div>
                                        </button>
                                    );
                                })}
                            </div>
                        </div>
                    </details>
                </div>
            </div>
        </div>
    );
}
