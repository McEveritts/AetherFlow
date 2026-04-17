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

export default function NetworkWidget({ networkData, hardware, history, density = 'compact' }: NetworkWidgetProps) {
    const isImmersive = density === 'immersive';

    return (
        <div className={`bg-white/[0.02] border border-white/[0.05] rounded-2xl relative overflow-hidden group transition-all duration-300 hover:bg-white/[0.04] backdrop-blur-xl ${isImmersive ? 'p-6 space-y-4' : 'p-5'}`}>

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
                <span className="text-[10px] text-slate-500 font-medium">{networkData.network.active_connections} connections</span>
            </div>

            {/* Dual-line Sparkline */}
            <div className={`rounded-xl overflow-hidden bg-slate-900/50 border border-white/[0.03] transition-all duration-300 ${isImmersive ? 'mb-6 shadow-2xl' : 'mb-4'}`}>
                <Sparkline
                    data={history.netDown.length > 1 ? history.netDown : [0, 0]}
                    data2={history.netUp.length > 1 ? history.netUp : [0, 0]}
                    color="#10b981"
                    color2="#6366f1"
                    gradientFrom="#10b981"
                    gradientFrom2="#6366f1"
                    height={isImmersive ? 140 : 90}
                    showArea={true}
                    label="Download"
                    label2="Upload"
                    currentValue={networkData.network.down as string}
                    currentValue2={networkData.network.up as string}
                />
            </div>


            {/* Cumulative totals */}
            <div className="grid grid-cols-2 gap-3">
                <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.03]">
                    <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block">Total Downloaded</span>
                    <span className="text-sm font-bold text-emerald-400">{formatTotalBytes(networkData.total?.rx || 0)}</span>
                </div>
                <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.03]">
                    <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block">Total Uploaded</span>
                    <span className="text-sm font-bold text-indigo-400">{formatTotalBytes(networkData.total?.tx || 0)}</span>
                </div>
            </div>
        </div>
    );
}
