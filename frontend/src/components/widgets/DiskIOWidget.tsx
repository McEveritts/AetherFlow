import { HardDrive } from 'lucide-react';
import { SystemMetrics, MetricsHistory } from '@/types/dashboard';
import Sparkline from '@/components/charts/Sparkline';

interface DiskIOWidgetProps {
    metrics: SystemMetrics;
    history: MetricsHistory;
}

function formatBytesPerSec(bytes: number): string {
    if (bytes < 1024) return `${bytes.toFixed(0)} B/s`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB/s`;
    if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB/s`;
    return `${(bytes / 1073741824).toFixed(2)} GB/s`;
}

export default function DiskIOWidget({ metrics, history }: DiskIOWidgetProps) {
    const read = metrics.disk_io?.read_bytes_sec || 0;
    const write = metrics.disk_io?.write_bytes_sec || 0;

    return (
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 relative overflow-hidden group hover:bg-white/[0.04] transition-colors backdrop-blur-xl">
            {/* Header */}
            <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                    <HardDrive size={16} className="text-amber-400" /> Disk I/O
                </h2>
            </div>

            {/* Dual-line Sparkline */}
            <div className="rounded-xl overflow-hidden bg-slate-900/50 border border-white/[0.03] mb-4">
                <Sparkline
                    data={history.diskRead.length > 1 ? history.diskRead : [0, 0]}
                    data2={history.diskWrite.length > 1 ? history.diskWrite : [0, 0]}
                    color="#f59e0b"
                    color2="#ef4444"
                    gradientFrom="#f59e0b"
                    gradientFrom2="#ef4444"
                    height={90}
                    showArea={true}
                    label="Read"
                    label2="Write"
                    currentValue={formatBytesPerSec(read)}
                    currentValue2={formatBytesPerSec(write)}
                />
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 gap-3">
                <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.03]">
                    <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block">Read</span>
                    <span className="text-sm font-bold text-amber-400">{formatBytesPerSec(read)}</span>
                </div>
                <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.03]">
                    <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block">Write</span>
                    <span className="text-sm font-bold text-red-400">{formatBytesPerSec(write)}</span>
                </div>
            </div>
        </div>
    );
}
