import { Network } from 'lucide-react';
import { SystemMetrics, HardwareReport, MetricsHistory } from '@/types/dashboard';
import Sparkline from '@/components/charts/Sparkline';

interface NetworkWidgetProps {
    networkData: { network: SystemMetrics['network']; total: SystemMetrics['total_net_bytes'] };
    hardware: HardwareReport | null;
    history: MetricsHistory;
    density?: 'compact' | 'immersive';
}

function formatTotalBytes(bytes: number): string {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let unitIndex = 0;
    let value = bytes;
    while (value >= 1024 && unitIndex < units.length - 1) {
        value /= 1024;
        unitIndex++;
    }
    return `${value.toFixed(unitIndex > 1 ? 1 : 0)} ${units[unitIndex]}`;
}

export default function NetworkWidget({ networkData, history, density = 'compact' }: NetworkWidgetProps) {
    const isImmersive = density === 'immersive';

    return (
        <div className={`rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl relative overflow-hidden flex flex-col justify-between h-full ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                {/* Header */}
                <div className="flex items-center justify-between pb-3 mb-3.5 border-b border-white/[0.06]">
                    <div className="flex items-center gap-2.5">
                        <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0">
                            <Network size={16} />
                        </div>
                        <div>
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none flex items-center gap-2">
                                Network Traffic
                                <span className="relative flex h-1.5 w-1.5">
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                                    <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
                                </span>
                            </h2>
                            <p className="text-[11px] text-slate-500 mt-1">
                                Real-time interface throughput
                            </p>
                        </div>
                    </div>
                    <span className="text-[11px] font-mono font-semibold text-slate-400 bg-white/[0.04] border border-white/[0.06] px-2 py-0.5 rounded-lg">
                        {networkData.network.active_connections} conns
                    </span>
                </div>

                {/* Dual-line Sparkline */}
                <div className="rounded-xl overflow-hidden bg-black/30 border border-white/[0.04] mb-3.5">
                    <Sparkline
                        data={history.netDown.length > 0 ? history.netDown : [0, 0]}
                        data2={history.netUp.length > 0 ? history.netUp : [0, 0]}
                        color="#10b981"
                        color2="#6366f1"
                        gradientFrom="#10b981"
                        gradientFrom2="#6366f1"
                        height={isImmersive ? 120 : 88}
                        showArea={true}
                        label="Download"
                        label2="Upload"
                        currentValue={networkData.network.down as string}
                        currentValue2={networkData.network.up as string}
                    />
                </div>
            </div>

            {/* Cumulative totals */}
            <div className="grid grid-cols-2 gap-2.5">
                <div className="bg-black/30 rounded-xl px-3 py-2 border border-white/[0.04] flex items-center justify-between">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Total RX</span>
                    <span className="text-xs font-mono font-bold text-emerald-400 tabular-nums">
                        {formatTotalBytes(networkData.total?.rx || 0)}
                    </span>
                </div>
                <div className="bg-black/30 rounded-xl px-3 py-2 border border-white/[0.04] flex items-center justify-between">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Total TX</span>
                    <span className="text-xs font-mono font-bold text-indigo-400 tabular-nums">
                        {formatTotalBytes(networkData.total?.tx || 0)}
                    </span>
                </div>
            </div>
        </div>
    );
}
