import { HardDrive } from 'lucide-react';
import { SystemMetrics, MetricsHistory } from '@/types/dashboard';
import Sparkline from '@/components/charts/Sparkline';

interface DiskIOWidgetProps {
    diskIoData: SystemMetrics['disk_io'];
    history: MetricsHistory;
    density?: 'compact' | 'immersive';
    selectedWindow?: string;
    hasSharedSummary?: boolean;
}

function formatBytesPerSec(bytesPerSecond: number): string {
    if (!Number.isFinite(bytesPerSecond) || bytesPerSecond <= 0) return '0.0 B/s';
    if (bytesPerSecond < 1024) return `${bytesPerSecond.toFixed(1)} B/s`;
    if (bytesPerSecond < 1048576) return `${(bytesPerSecond / 1024).toFixed(1)} KB/s`;
    if (bytesPerSecond < 1073741824) return `${(bytesPerSecond / 1048576).toFixed(1)} MB/s`;
    return `${(bytesPerSecond / 1073741824).toFixed(1)} GB/s`;
}

export default function DiskIOWidget({ diskIoData, history, density = 'compact', selectedWindow, hasSharedSummary }: DiskIOWidgetProps) {
    const isImmersive = density === 'immersive';
    const readBytesPerSecond = diskIoData?.read_bytes_sec || 0;
    const writeBytesPerSecond = diskIoData?.write_bytes_sec || 0;
    const totalBytesPerSecond = readBytesPerSecond + writeBytesPerSecond;

    return (
        <div className={`rounded-2xl border border-slate-800/80 bg-slate-900/85 backdrop-blur-xl relative overflow-hidden flex flex-col ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                <div className="flex flex-wrap items-center justify-between gap-2 pb-3 mb-3.5 border-b border-slate-800/80">
                    <div className="flex items-center gap-2.5 min-w-0">
                        <div className="h-8 w-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 shrink-0">
                            <HardDrive size={16} />
                        </div>
                        <div className="min-w-0">
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">Disk I/O</h2>
                            <p className="text-[13px] text-slate-300 mt-1">
                                Total throughput <span className="font-semibold text-slate-200 tabular-nums">{formatBytesPerSec(totalBytesPerSecond)}</span>
                            </p>
                        </div>
                    </div>
                    <div className="flex flex-col items-end text-right shrink-0">
                        <div className="flex items-baseline gap-1.5">
                            <span className="text-[13px] font-semibold text-amber-400">Read</span>
                            <span className="text-lg sm:text-xl font-extrabold tracking-tight text-white tabular-nums">
                                {formatBytesPerSec(readBytesPerSecond)}
                            </span>
                        </div>
                        <div className="flex items-baseline gap-1.5 mt-0.5">
                            <span className="text-[13px] font-semibold text-sky-400">Write</span>
                            <span className="text-lg sm:text-xl font-extrabold tracking-tight text-white tabular-nums">
                                {formatBytesPerSec(writeBytesPerSecond)}
                            </span>
                        </div>
                    </div>
                </div>

                <div className="rounded-xl overflow-hidden bg-slate-950/60 border border-slate-800/60">
                    <Sparkline
                        data={history.diskRead.length > 0 ? history.diskRead : [readBytesPerSecond]}
                        data2={history.diskWrite.length > 0 ? history.diskWrite : [writeBytesPerSecond]}
                        color="#f59e0b"
                        color2="#38bdf8"
                        gradientFrom="#f59e0b"
                        gradientFrom2="#38bdf8"
                        height={isImmersive ? 120 : 88}
                        showArea={true}
                        showMagnitudeReferences={true}
                        unit="B/s"
                        timestamps={history.timestamps}
                        selectedWindow={selectedWindow}
                        label="Read"
                        label2="Write"
                        currentValue={formatBytesPerSec(readBytesPerSecond)}
                        currentValue2={formatBytesPerSec(writeBytesPerSecond)}
                        hasSharedSummary={hasSharedSummary}
                    />
                </div>
            </div>
        </div>
    );
}
