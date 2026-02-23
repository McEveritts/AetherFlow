import { Network } from 'lucide-react';
import { SystemMetrics, HardwareReport, MetricsHistory } from '@/types/dashboard';
import Sparkline from '@/components/charts/Sparkline';

interface NetworkWidgetProps {
    metrics: SystemMetrics;
    hardware: HardwareReport | null;
    history: MetricsHistory;
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

export default function NetworkWidget({ metrics, hardware, history }: NetworkWidgetProps) {
    return (
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 relative overflow-hidden group hover:bg-white/[0.04] transition-colors backdrop-blur-xl">
            {/* Header */}
            <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                    <Network size={16} className="text-emerald-400" />
                    Network
                    <span className="relative flex h-2 w-2 ml-1">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                    </span>
                </h2>
                <span className="text-[10px] text-slate-500 font-medium">{metrics.network.active_connections} connections</span>
            </div>

            {/* Dual-line Sparkline */}
            <div className="rounded-xl overflow-hidden bg-slate-900/50 border border-white/[0.03] mb-4">
                <Sparkline
                    data={history.netDown.length > 1 ? history.netDown : [0, 0]}
                    data2={history.netUp.length > 1 ? history.netUp : [0, 0]}
                    color="#10b981"
                    color2="#6366f1"
                    gradientFrom="#10b981"
                    gradientFrom2="#6366f1"
                    height={90}
                    showArea={true}
                    label="Download"
                    label2="Upload"
                    currentValue={metrics.network.down as string}
                    currentValue2={metrics.network.up as string}
                />
            </div>

            {/* Cumulative totals */}
            <div className="grid grid-cols-2 gap-3">
                <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.03]">
                    <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block">Total RX</span>
                    <span className="text-sm font-bold text-emerald-400">{formatTotalBytes(metrics.total_net_bytes?.rx || 0)}</span>
                </div>
                <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.03]">
                    <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block">Total TX</span>
                    <span className="text-sm font-bold text-indigo-400">{formatTotalBytes(metrics.total_net_bytes?.tx || 0)}</span>
                </div>
            </div>
        </div>
    );
}
