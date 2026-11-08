import { useId } from 'react';
import { MemoryStick } from 'lucide-react';
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
    const swapDescriptionId = useId();

    return (
        <div className={`obs-telemetry-surface obs-vital-card relative overflow-hidden flex flex-col ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                <div className="obs-vital-header">
                    <div className="flex items-center gap-2.5 min-w-0">
                        <div className="h-8 w-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 shrink-0">
                            <MemoryStick size={16} />
                        </div>
                        <div className="min-w-0">
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">System Memory</h2>
                            <p className="text-xs text-slate-400 mt-1">
                                Kernel &amp; workload memory
                            </p>
                        </div>
                    </div>
                    <div>
                        {hasHighPhysicalMemoryPressure && (
                            <p className="text-xs text-amber-400 mb-1">Elevated physical memory allocation pressure</p>
                        )}
                        <div className="flex flex-wrap justify-between gap-x-3 gap-y-1 text-xs text-slate-400 mb-1">
                            <span>RAM used · {memoryPercentage.toFixed(0)}%</span>
                            <span className="font-mono text-purple-300">{availableGigabytes.toFixed(1)} GB available</span>
                        </div>
                        <div className="flex items-baseline gap-1">
                            <span className="text-xl font-extrabold tracking-tight text-white tabular-nums">
                                {memoryData.memory.used.toFixed(1)}
                            </span>
                            <span className="text-xs text-slate-400 font-semibold tabular-nums">
                                / {memoryData.memory.total.toFixed(0)} GB
                            </span>
                        </div>
                    </div>
                </div>

                <div className="obs-vital-plot">
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

            {hasSwapMemory ? (
                <div className="obs-vital-footer justify-between" title="Kernel pages idle blocks to swap; occupancy does not imply critical exhaustion.">
                    <div className="min-w-0 flex-1">
                        <span className="text-xs font-medium text-slate-400">Swap · {swapPercentage.toFixed(0)}%</span>
                        <div
                            role="meter"
                            aria-label="Swap occupancy"
                            aria-valuenow={Number(swapPercentage.toFixed(1))}
                            aria-valuemin={0}
                            aria-valuemax={100}
                            aria-valuetext={`${memoryData.swap.used.toFixed(2)} of ${memoryData.swap.total.toFixed(1)} GB`}
                            aria-describedby={swapDescriptionId}
                            className="h-1 max-w-20 mt-1 bg-white/[0.06] rounded-full overflow-hidden"
                        >
                            <div
                                className="h-full bg-gradient-to-r from-indigo-600 to-indigo-400 transition-all duration-500 rounded-full"
                                style={{ width: `${Math.min(100, swapPercentage)}%` }}
                            />
                        </div>
                    </div>
                    <span className="text-xs font-mono text-slate-300 tabular-nums">
                        {memoryData.swap.used.toFixed(2)} / {memoryData.swap.total.toFixed(1)} GB
                    </span>
                    <p id={swapDescriptionId} className="sr-only">
                        Paging reserve · Kernel pages idle blocks to swap; occupancy does not imply critical exhaustion.
                    </p>
                </div>
            ) : (
                <p className="obs-vital-footer text-xs text-slate-400">No swap configured · Physical memory only</p>
            )}
        </div>
    );
}
