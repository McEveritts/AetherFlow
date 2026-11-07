import { MemoryStick, ChevronDown } from 'lucide-react';
import { SystemMetrics, HardwareReport, MetricsHistory } from '@/types/dashboard';
import Sparkline from '@/components/charts/Sparkline';

interface MemoryWidgetProps {
    memoryData: { memory: SystemMetrics['memory']; swap: SystemMetrics['swap'] };
    hardware: HardwareReport | null;
    history: MetricsHistory;
    density?: 'compact' | 'immersive';
    selectedWindow?: string;
    hasSharedSummary?: boolean;
}

export default function MemoryWidget({ memoryData, history, density = 'compact', selectedWindow, hasSharedSummary }: MemoryWidgetProps) {
    const memoryPercentage = memoryData.memory.total > 0 ? (memoryData.memory.used / memoryData.memory.total) * 100 : 0;
    const swapPercentage = memoryData.swap?.total > 0 ? (memoryData.swap.used / memoryData.swap.total) * 100 : 0;
    const hasSwapMemory = memoryData.swap?.total > 0;
    const isImmersive = density === 'immersive';
    const availableGigabytes = Math.max(0, memoryData.memory.total - memoryData.memory.used);
    const hasHighPhysicalMemoryPressure = memoryPercentage >= 90;

    return (
        <div className={`rounded-2xl border border-slate-800/80 bg-slate-900/85 backdrop-blur-xl relative overflow-hidden flex flex-col ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                <div className="flex items-center justify-between pb-3 mb-3.5 border-b border-slate-800/80">
                    <div className="flex items-center gap-2.5">
                        <div className="h-8 w-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 shrink-0">
                            <MemoryStick size={16} />
                        </div>
                        <div>
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">System Memory</h2>
                            <p className="text-[13px] text-slate-300 mt-1">
                                Kernel &amp; workload memory
                            </p>
                        </div>
                    </div>
                    <div className="flex items-baseline gap-1 shrink-0">
                        <span className="text-xl font-extrabold tracking-tight text-white tabular-nums">
                            {memoryData.memory.used.toFixed(1)}
                        </span>
                        <span className="text-xs text-slate-400 font-semibold tabular-nums">
                            / {memoryData.memory.total.toFixed(0)} GB
                        </span>
                    </div>
                </div>

                <div className="rounded-xl overflow-hidden bg-slate-950/60 border border-slate-800/60 mb-3.5">
                    <Sparkline
                        data={history.memory.length > 0 ? history.memory : [memoryPercentage]}
                        color="#a855f7"
                        gradientFrom="#a855f7"
                        height={isImmersive ? 120 : 88}
                        showArea={true}
                        isPercentage={true}
                        yDomain={[0, 100]}
                        showMagnitudeReferences={true}
                        timestamps={history.timestamps}
                        selectedWindow={selectedWindow}
                        currentValue={`${memoryPercentage.toFixed(1)}%`}
                        hasSharedSummary={hasSharedSummary}
                    />
                </div>
            </div>

            <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800/60 space-y-3">
                <div>
                    <div className="flex justify-between items-center text-[13px] text-slate-300 font-semibold mb-1">
                        <span>RAM used · {memoryPercentage.toFixed(0)}%</span>
                        <span className="font-mono text-purple-300">{availableGigabytes.toFixed(1)} GB available</span>
                    </div>
                    <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                        <div
                            className={`h-full transition-all duration-500 rounded-full ${
                                hasHighPhysicalMemoryPressure
                                    ? 'bg-gradient-to-r from-amber-600 to-rose-500'
                                    : 'bg-gradient-to-r from-purple-600 to-purple-400'
                            }`}
                            style={{ width: `${Math.min(100, memoryPercentage)}%` }}
                        />
                    </div>
                    {hasHighPhysicalMemoryPressure && (
                        <p className="text-xs text-amber-400 mt-1">Elevated physical memory allocation pressure</p>
                    )}
                </div>

                {hasSwapMemory && (
                    <div>
                        <div className="flex justify-between text-[13px] text-slate-300 font-semibold mb-1">
                            <span>Swap Occupancy ({swapPercentage.toFixed(0)}%)</span>
                            <span className="font-mono text-slate-300">
                                {memoryData.swap.used.toFixed(2)} / {memoryData.swap.total.toFixed(1)} GB
                            </span>
                        </div>
                        <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-gradient-to-r from-indigo-600 to-indigo-400 transition-all duration-500 rounded-full"
                                style={{ width: `${Math.min(100, swapPercentage)}%` }}
                            />
                        </div>
                        <details className="mt-1.5 group/swap text-xs text-slate-300">
                            <summary
                                data-testid="memory-paging-reserve-summary"
                                className="min-h-[44px] cursor-pointer list-none font-semibold hover:text-slate-100 select-none flex items-center justify-between py-2 rounded-lg text-[13px] text-slate-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-purple-500/50"
                            >
                                <span>Paging reserve details</span>
                                <ChevronDown size={14} className="text-slate-400 group-open/swap:rotate-180 transition-transform" />
                            </summary>
                            <p className="mt-1 text-xs text-slate-300 pl-2 border-l border-slate-700/60 leading-relaxed font-medium">
                                Paging reserve · Kernel pages idle blocks to swap; occupancy does not imply critical exhaustion.
                            </p>
                        </details>
                    </div>
                )}
            </div>
        </div>
    );
}
