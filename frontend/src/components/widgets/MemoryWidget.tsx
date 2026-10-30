import { MemoryStick } from 'lucide-react';
import { SystemMetrics, HardwareReport, MetricsHistory } from '@/types/dashboard';
import Sparkline from '@/components/charts/Sparkline';

interface MemoryWidgetProps {
    memoryData: { memory: SystemMetrics['memory']; swap: SystemMetrics['swap'] };
    hardware: HardwareReport | null;
    history: MetricsHistory;
    density?: 'compact' | 'immersive';
}

export default function MemoryWidget({ memoryData, history, density = 'compact' }: MemoryWidgetProps) {
    const memPct = memoryData.memory.total > 0 ? (memoryData.memory.used / memoryData.memory.total) * 100 : 0;
    const swapPct = memoryData.swap?.total > 0 ? (memoryData.swap.used / memoryData.swap.total) * 100 : 0;
    const hasSwap = memoryData.swap?.total > 0;
    const isImmersive = density === 'immersive';
    const freeGB = Math.max(0, memoryData.memory.total - memoryData.memory.used);

    return (
        <div className={`rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl relative overflow-hidden flex flex-col justify-between h-full ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                {/* Header */}
                <div className="flex items-center justify-between pb-3 mb-3.5 border-b border-white/[0.06]">
                    <div className="flex items-center gap-2.5">
                        <div className="h-8 w-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 shrink-0">
                            <MemoryStick size={16} />
                        </div>
                        <div>
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">System Memory</h2>
                            <p className="text-[11px] text-slate-500 mt-1">
                                {freeGB.toFixed(1)} GB available · {memPct.toFixed(0)}% allocated
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

                {/* Sparkline */}
                <div className="rounded-xl overflow-hidden bg-black/30 border border-white/[0.04] mb-3.5">
                    <Sparkline
                        data={history.memory.length > 0 ? history.memory : [memPct, memPct]}
                        color="#a855f7"
                        gradientFrom="#a855f7"
                        height={isImmersive ? 120 : 88}
                        showArea={true}
                        currentValue={`${memPct.toFixed(1)}%`}
                    />
                </div>
            </div>

            {/* RAM & Swap Allocation Footer */}
            <div className="bg-black/30 rounded-xl p-2.5 border border-white/[0.04] space-y-2">
                <div>
                    <div className="flex justify-between text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-1">
                        <span>Physical RAM ({memPct.toFixed(0)}%)</span>
                        <span className="font-mono text-purple-300">{freeGB.toFixed(1)} GB Free</span>
                    </div>
                    <div className="h-1.5 w-full bg-slate-800/90 rounded-full overflow-hidden">
                        <div
                            className="h-full bg-gradient-to-r from-purple-600 to-purple-400 transition-all duration-500 rounded-full"
                            style={{ width: `${Math.min(100, memPct)}%` }}
                        />
                    </div>
                </div>

                {hasSwap && (
                    <div>
                        <div className="flex justify-between text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-1">
                            <span>Swap Space ({swapPct.toFixed(0)}%)</span>
                            <span className="font-mono text-slate-400">
                                {memoryData.swap.used.toFixed(2)} / {memoryData.swap.total.toFixed(1)} GB
                            </span>
                        </div>
                        <div className="h-1.5 w-full bg-slate-800/90 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-gradient-to-r from-fuchsia-600 to-fuchsia-400 transition-all duration-500 rounded-full"
                                style={{ width: `${Math.min(100, swapPct)}%` }}
                            />
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
