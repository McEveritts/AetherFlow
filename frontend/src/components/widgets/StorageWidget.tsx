import { HardDrive } from 'lucide-react';
import { SystemMetrics, HardwareReport, DiskPartition } from '@/types/dashboard';

interface StorageWidgetProps {
    storageData: DiskPartition[];
    hardware: HardwareReport | null;
    density?: 'compact' | 'immersive';
}

export default function StorageWidget({ storageData, hardware, density = 'compact' }: StorageWidgetProps) {
    const disks = storageData || [];
    const isImmersive = density === 'immersive';
    // Calculate total across all partitions
    const totalAllGB = disks.reduce((sum, d) => sum + d.total_gb, 0);
    const usedAllGB = disks.reduce((sum, d) => sum + d.used_gb, 0);
    const freeAllGB = totalAllGB - usedAllGB;
    const overallPct = totalAllGB > 0 ? (usedAllGB / totalAllGB) * 100 : 0;

    return (
        <div className={`bg-white/[0.02] border border-white/[0.05] rounded-2xl relative overflow-hidden backdrop-blur-xl transition-all duration-300 ${isImmersive ? 'p-6 space-y-4 shadow-xl' : 'p-5'}`}>
            <div className={`flex items-center justify-between ${isImmersive ? 'mb-6' : 'mb-4'}`}>
                <h2 className={`${isImmersive ? 'text-lg' : 'text-sm'} font-semibold text-slate-200 flex items-center gap-2`}>
                    <HardDrive size={isImmersive ? 18 : 16} className="text-amber-400" /> Storage
                </h2>
                <div className="flex items-baseline gap-1">
                    <span className={`${isImmersive ? 'text-3xl' : 'text-2xl'} font-bold tracking-tighter text-amber-400`}>{overallPct.toFixed(1)}%</span>
                </div>
            </div>


            {/* Overall summary */}
            <div className={isImmersive ? 'mb-8' : 'mb-4'}>
                <div className="flex justify-between text-[10px] text-slate-400 font-semibold uppercase tracking-wider mb-2">
                    <span>{usedAllGB.toFixed(1)} GB used</span>
                    <span>{freeAllGB.toFixed(1)} GB free</span>
                </div>
                <div className={`${isImmersive ? 'h-4' : 'h-3'} w-full bg-slate-800/80 rounded-full overflow-hidden flex transition-all duration-300`}>
                    <div
                        className="h-full bg-gradient-to-r from-amber-600 to-amber-400 transition-all duration-300 rounded-full shadow-[0_0_10px_rgba(245,158,11,0.3)]"
                        style={{ width: `${overallPct}%` }}
                    />
                </div>
                <div className="text-[10px] text-slate-500 mt-2 font-medium">{totalAllGB.toFixed(0)} GB total across {disks.length} partition{disks.length !== 1 ? 's' : ''}</div>
            </div>


            {/* Individual partitions */}
            {disks.length > 0 && (
                <div className="space-y-2">
                    <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Partitions</span>
                    <div className="space-y-2">
                        {disks.map((d, i) => (
                            <div key={i} className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.03]">
                                <div className="flex items-center justify-between mb-1.5">
                                    <div className="min-w-0 flex-1">
                                        <span className="text-xs font-medium text-slate-300 block truncate">{d.mount_point}</span>
                                        <span className="text-[10px] text-slate-500 truncate block">{d.device} · {d.fs_type}</span>
                                    </div>
                                    <span className="text-xs font-bold text-amber-400 whitespace-nowrap ml-2">
                                        {d.used_pct.toFixed(1)}%
                                    </span>
                                </div>
                                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                                    <div
                                        className="h-full rounded-full transition-all duration-300"
                                        style={{
                                            width: `${d.used_pct}%`,
                                            backgroundColor: d.used_pct > 90 ? '#ef4444' : d.used_pct > 75 ? '#f59e0b' : '#6366f1'
                                        }}
                                    />
                                </div>
                                <div className="flex justify-between text-[9px] text-slate-500 mt-1">
                                    <span>{d.used_gb.toFixed(1)} GB used</span>
                                    <span>{d.total_gb.toFixed(0)} GB total</span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
