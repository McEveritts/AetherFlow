import { HardDrive } from 'lucide-react';
import { SystemMetrics, MetricsHistory } from '@/types/dashboard';
import Sparkline from '@/components/charts/Sparkline';

interface DiskIOWidgetProps {
    diskIoData: SystemMetrics['disk_io'];
    history: MetricsHistory;
    density?: 'compact' | 'immersive';
}

function formatBytesPerSec(bytes: number): string {
    if (bytes < 1024) return `${bytes.toFixed(0)} B/s`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB/s`;
    if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB/s`;
    return `${(bytes / 1073741824).toFixed(2)} GB/s`;
}

export default function DiskIOWidget({ diskIoData, history, density = 'compact' }: DiskIOWidgetProps) {
    const isImmersive = density === 'immersive';
    const read = diskIoData?.read_bytes_sec || 0;
    const write = diskIoData?.write_bytes_sec || 0;

    return (
        <div className={`rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl relative overflow-hidden flex flex-col justify-between h-full ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                {/* Header */}
                <div className="flex items-center justify-between pb-3 mb-3.5 border-b border-white/[0.06]">
                    <div className="flex items-center gap-2.5">
                        <div className="h-8 w-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 shrink-0">
                            <HardDrive size={16} />
                        </div>
                        <div>
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">Disk I/O</h2>
                            <p className="text-[11px] text-slate-500 mt-1">Block device read/write rate</p>
                        </div>
                    </div>
                    <span className="text-[11px] font-mono font-semibold text-amber-300/90 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded-lg tabular-nums">
                        {formatBytesPerSec(read + write)}
                    </span>
                </div>

                {/* Dual-line Sparkline */}
                <div className="rounded-xl overflow-hidden bg-black/30 border border-white/[0.04] mb-3.5">
                    <Sparkline
                        data={history.diskRead.length > 0 ? history.diskRead : [read, read]}
                        data2={history.diskWrite.length > 0 ? history.diskWrite : [write, write]}
                        color="#f59e0b"
                        color2="#ef4444"
                        gradientFrom="#f59e0b"
                        gradientFrom2="#ef4444"
                        height={isImmersive ? 120 : 88}
                        showArea={true}
                        label="Read"
                        label2="Write"
                        currentValue={formatBytesPerSec(read)}
                        currentValue2={formatBytesPerSec(write)}
                    />
                </div>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 gap-2.5">
                <div className="bg-black/30 rounded-xl px-3 py-2 border border-white/[0.04] flex items-center justify-between">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Read</span>
                    <span className="text-xs font-mono font-bold text-amber-400 tabular-nums">{formatBytesPerSec(read)}</span>
                </div>
                <div className="bg-black/30 rounded-xl px-3 py-2 border border-white/[0.04] flex items-center justify-between">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Write</span>
                    <span className="text-xs font-mono font-bold text-rose-400 tabular-nums">{formatBytesPerSec(write)}</span>
                </div>
            </div>
        </div>
    );
}
