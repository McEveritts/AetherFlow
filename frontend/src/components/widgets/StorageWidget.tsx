import { HardDrive } from 'lucide-react';
import { SystemMetrics, HardwareReport } from '@/types/dashboard';

interface StorageWidgetProps {
    metrics: SystemMetrics;
    hardware: HardwareReport | null;
}

export default function StorageWidget({ metrics, hardware }: StorageWidgetProps) {
    const disks = hardware?.storage || [];
    const usedPct = metrics.disk_space.total > 0 ? (metrics.disk_space.used / metrics.disk_space.total) * 100 : 0;

    return (
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 relative overflow-hidden backdrop-blur-xl">
            <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                    <HardDrive size={16} className="text-amber-400" /> Storage
                </h2>
                <span className="text-2xl font-bold tracking-tighter text-amber-400">{usedPct.toFixed(1)}%</span>
            </div>

            {/* Main disk usage */}
            <div className="mb-4">
                <div className="flex justify-between text-[10px] text-slate-400 font-semibold uppercase tracking-wider mb-1.5">
                    <span>{metrics.disk_space.used.toFixed(1)} GB used</span>
                    <span>{metrics.disk_space.free.toFixed(1)} GB free</span>
                </div>
                <div className="h-3 w-full bg-slate-800/80 rounded-full overflow-hidden flex">
                    <div
                        className="h-full bg-gradient-to-r from-amber-600 to-amber-400 transition-all duration-500 rounded-full"
                        style={{ width: `${usedPct}%` }}
                    />
                </div>
                <div className="text-[10px] text-slate-500 mt-1">{metrics.disk_space.total.toFixed(0)} GB total</div>
            </div>

            {/* Physical drives */}
            {disks.length > 0 && (
                <div className="space-y-2">
                    <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Physical Drives</span>
                    <div className="space-y-1.5">
                        {disks.map((disk, i) => (
                            <div key={i} className="flex items-center justify-between bg-slate-900/50 rounded-lg px-3 py-2 border border-white/[0.03]">
                                <div className="min-w-0">
                                    <span className="text-xs font-medium text-slate-300 block truncate">/dev/{disk.name}</span>
                                    <span className="text-[10px] text-slate-500 truncate block">{disk.model} · {disk.drive_type}</span>
                                </div>
                                <span className="text-xs font-bold text-slate-400 whitespace-nowrap ml-2">
                                    {(disk.size_bytes / (1024 * 1024 * 1024)).toFixed(0)} GB
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
