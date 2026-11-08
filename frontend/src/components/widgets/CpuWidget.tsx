import { useId, useState } from 'react';
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
    const coreDetailsId = useId();
    const [showCores, setShowCores] = useState(false);
    const [selectedCoreIndex, setSelectedCoreIndex] = useState<number | null>(null);
    const [showAllProcessors, setShowAllProcessors] = useState(false);
    const processorLoads = coresList.length > 0 ? coresList : [cpuData.usage];
    const visibleProcessors = showAllProcessors ? processorLoads : processorLoads.slice(0, 16);

    const physicalCores = hardware?.cpu?.cores;
    const logicalThreads = hardware?.cpu?.threads || coresList.length;
    const processorSummary = physicalCores
        ? `${physicalCores} Physical Cores · ${logicalThreads} Logical Processors`
        : `${logicalThreads} Logical Processors`;

    return (
        <div data-cores-expanded={showCores} className={`obs-telemetry-surface obs-vital-card relative overflow-hidden flex flex-col ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                <div className="obs-vital-header">
                    <div className="flex items-center gap-2.5 min-w-0">
                        <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shrink-0">
                            <Cpu size={16} />
                        </div>
                        <div className="min-w-0">
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">CPU Utilization</h2>
                            <p className="text-xs text-slate-400 truncate mt-1" title={hardware?.cpu?.model || processorSummary}>
                                {hardware?.cpu?.model || processorSummary}
                            </p>
                        </div>
                    </div>
                    <div className="flex items-baseline justify-between gap-2">
                        <span className="text-xl font-extrabold tracking-tight text-white tabular-nums">
                            {cpuData.usage.toFixed(1)}%
                        </span>
                        {cpuData.freq > 0 && (
                            <span className="text-xs text-slate-400 font-mono tabular-nums">
                                {(cpuData.freq / 1000).toFixed(2)} GHz
                            </span>
                        )}
                    </div>
                </div>

                <div className="obs-vital-plot">
                    <Sparkline
                        data={history.cpu.length > 0 ? history.cpu : (cpuData.usage !== undefined ? [cpuData.usage] : [])}
                        color="#6366f1"
                        gradientFrom="#6366f1"
                        height={isImmersive ? 120 : 88}
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

            <div className="obs-vital-footer justify-between">
                <div className="min-w-0 flex-1">
                    <span className="text-xs font-medium text-slate-300" title={processorSummary}>
                        {physicalCores ? `Physical Cores (${physicalCores})` : `Logical Processors (${logicalThreads})`}
                    </span>
                    <div
                        role="meter"
                        aria-valuenow={Number(cpuData.usage.toFixed(1))}
                        aria-valuemin={0}
                        aria-valuemax={100}
                        aria-label="Current CPU utilization"
                        aria-valuetext={`${cpuData.usage.toFixed(1)}%`}
                        className="h-1 max-w-20 mt-1 bg-white/[0.06] rounded-full overflow-hidden"
                    >
                        <div
                            className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-all duration-300 rounded-full"
                            style={{ width: `${Math.min(100, Math.max(cpuData.usage > 0 ? 1 : 0, cpuData.usage))}%` }}
                        />
                    </div>
                </div>
                <button
                    type="button"
                    aria-label={showCores ? 'Hide cores' : 'Inspect cores'}
                    aria-expanded={showCores}
                    aria-controls={coreDetailsId}
                    onClick={() => {
                        setShowCores(!showCores);
                        setSelectedCoreIndex(null);
                        setShowAllProcessors(false);
                    }}
                    className="inline-flex min-h-[44px] min-w-[44px] shrink-0 items-center justify-center gap-1 rounded-lg px-1.5 text-xs font-medium text-indigo-300 hover:bg-white/[0.04] hover:text-indigo-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400"
                >
                    Cores
                    <ChevronDown size={14} aria-hidden="true" className={showCores ? 'rotate-180' : ''} />
                </button>
            </div>

            <div id={coreDetailsId} hidden={!showCores}>
                {showCores && <div role="region" aria-label="Per-core utilization" className="border-t border-white/[0.06] mt-3 pt-3 space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                            <span className="font-semibold text-slate-300">Logical Processors ({logicalThreads})</span>
                        </div>
                    </div>

                    <div className="grid grid-cols-4 sm:grid-cols-8 gap-1">
                        {visibleProcessors.map((corePercentage, coreIndex) => {
                            const isCoreSelected = selectedCoreIndex === coreIndex;
                            return (
                                <button
                                    key={coreIndex}
                                    type="button"
                                    onClick={() => setSelectedCoreIndex(isCoreSelected ? null : coreIndex)}
                                    className="group/core relative min-h-[40px] min-w-0 flex items-center justify-center rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400"
                                    aria-label={`Processor ${coreIndex}: ${corePercentage.toFixed(1)}%`}
                                    aria-pressed={isCoreSelected}
                                >
                                    <span
                                        className={`w-full h-5 rounded ${getCoreColor(corePercentage)} transition-colors ${isCoreSelected ? 'ring-2 ring-indigo-200' : ''}`}
                                        title={`Processor ${coreIndex}: ${corePercentage.toFixed(1)}%`}
                                    />
                                </button>
                            );
                        })}
                    </div>

                    {selectedCoreIndex !== null && processorLoads[selectedCoreIndex] !== undefined && (
                        <p role="status" className="text-xs font-mono text-indigo-300">
                            Processor {selectedCoreIndex}: {processorLoads[selectedCoreIndex].toFixed(1)}% utilization
                        </p>
                    )}

                    <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                        <p className="text-xs text-slate-400 leading-relaxed">
                            Load Legend: &lt;10% · <span className="text-indigo-300">10–49%</span> · <span className="text-amber-300">50–89%</span> · <span className="text-rose-400">≥90%</span>
                        </p>
                        {processorLoads.length > 16 && (
                            <button
                                type="button"
                                aria-expanded={showAllProcessors}
                                onClick={() => {
                                    setShowAllProcessors(!showAllProcessors);
                                    if (showAllProcessors && selectedCoreIndex !== null && selectedCoreIndex >= 16) setSelectedCoreIndex(null);
                                }}
                                className="inline-flex min-h-[44px] items-center gap-1.5 rounded-lg text-xs font-medium text-indigo-300 hover:text-indigo-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400"
                            >
                                {showAllProcessors ? 'Show first 16 processors' : `Show all ${processorLoads.length} processors`}
                                <ChevronDown size={13} className={showAllProcessors ? 'rotate-180' : ''} />
                            </button>
                        )}
                    </div>
                </div>}
            </div>
        </div>
    );
}
