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
    const readShare = totalBytesPerSecond > 0 ? (readBytesPerSecond / totalBytesPerSecond) * 100 : null;
    const writeShare = readShare === null ? null : 100 - readShare;

    return (
        <div className={`obs-telemetry-surface obs-vital-card relative overflow-hidden flex flex-col ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                <div className="obs-vital-header">
                    <div className="flex items-center gap-2.5 min-w-0">
                        <div className="h-8 w-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 shrink-0">
                            <HardDrive size={16} />
                        </div>
                        <div className="min-w-0">
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">Disk I/O</h2>
                            <p className="text-xs text-slate-400 mt-1">
                                Total throughput <span className="font-semibold text-slate-200 tabular-nums">{formatBytesPerSec(totalBytesPerSecond)}</span>
                            </p>
                        </div>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                        <div className="min-w-0 flex flex-col gap-0.5">
                            <span className="text-xs font-medium text-amber-400">Read</span>
                            <span className="text-base font-bold tracking-tight text-amber-300 tabular-nums break-words">
                                {formatBytesPerSec(readBytesPerSecond)}
                            </span>
                        </div>
                        <div className="min-w-0 flex flex-col gap-0.5">
                            <span className="text-xs font-medium text-sky-400">Write</span>
                            <span className="text-base font-bold tracking-tight text-sky-300 tabular-nums break-words">
                                {formatBytesPerSec(writeBytesPerSecond)}
                            </span>
                        </div>
                    </div>
                </div>

                <div className="obs-vital-plot">
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
            <div className="obs-vital-footer">
                <div role="group" className="grid w-full grid-cols-2 divide-x divide-white/[0.06]" aria-label="Current disk throughput share">
                    <div className="min-w-0 flex flex-col gap-0.5 pr-3">
                        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Read share</span>
                        <span className="text-xs font-mono font-bold text-amber-300 tabular-nums">
                            {readShare === null ? 'Idle' : `${readShare.toFixed(0)}%`}
                        </span>
                    </div>
                    <div className="min-w-0 flex flex-col gap-0.5 pl-3">
                        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Write share</span>
                        <span className="text-xs font-mono font-bold text-sky-300 tabular-nums">
                            {writeShare === null ? 'Idle' : `${writeShare.toFixed(0)}%`}
                        </span>
                    </div>
                </div>
            </div>
        </div>
    );
}
