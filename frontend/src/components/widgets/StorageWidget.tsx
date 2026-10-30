import { useState } from 'react';
import { HardDrive } from 'lucide-react';
import { HardwareReport, DiskPartition } from '@/types/dashboard';

interface StorageWidgetProps {
    storageData: DiskPartition[];
    hardware: HardwareReport | null;
    density?: 'compact' | 'immersive';
}

export default function StorageWidget({ storageData, density = 'compact' }: StorageWidgetProps) {
    const disks = storageData || [];
    const isImmersive = density === 'immersive';

    const [selectedDrive, setSelectedDrive] = useState<string>('all');

    const filteredDisks = selectedDrive === 'all'
        ? disks
        : disks.filter(d => d.mount_point === selectedDrive);

    const totalAllGB = filteredDisks.reduce((sum, d) => sum + d.total_gb, 0);
    const usedAllGB = filteredDisks.reduce((sum, d) => sum + d.used_gb, 0);
    const freeAllGB = Math.max(0, totalAllGB - usedAllGB);
    const overallPct = totalAllGB > 0 ? (usedAllGB / totalAllGB) * 100 : 0;

    return (
        <div className={`rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl relative overflow-hidden flex flex-col justify-between h-full ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                {/* Header */}
                <div className="flex items-center justify-between gap-2 pb-3 mb-3.5 border-b border-white/[0.06]">
                    <div className="flex items-center gap-2.5 min-w-0">
                        <div className="h-8 w-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 shrink-0">
                            <HardDrive size={16} />
                        </div>
                        <div className="min-w-0">
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">Storage Pools</h2>
                            <p className="text-[11px] text-slate-500 truncate mt-1">
                                {totalAllGB.toFixed(0)} GB across {filteredDisks.length} mount{filteredDisks.length !== 1 ? 's' : ''}
                            </p>
                        </div>
                    </div>
                    <div className="flex items-center gap-2.5 shrink-0">
                        <select
                            value={selectedDrive}
                            onChange={(e) => setSelectedDrive(e.target.value)}
                            className="obs-touch-target-standard bg-black/40 border border-white/[0.08] text-xs text-slate-300 rounded-lg px-2.5 py-1 outline-none focus:border-amber-500/50 transition-colors cursor-pointer"
                        >
                            <option value="all" className="bg-slate-900">All Drives</option>
                            {disks.map((d, i) => (
                                <option key={i} value={d.mount_point} className="bg-slate-900">
                                    {d.mount_point}
                                </option>
                            ))}
                        </select>
                        <span className="text-lg font-extrabold tracking-tight text-amber-400 tabular-nums">
                            {overallPct.toFixed(1)}%
                        </span>
                    </div>
                </div>

                {/* Overall Pool Bar */}
                <div className="bg-black/30 rounded-xl p-3 border border-white/[0.04] mb-3.5">
                    <div className="flex justify-between text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-1.5">
                        <span>{usedAllGB.toFixed(1)} GB Used</span>
                        <span className="text-slate-300 font-mono">{freeAllGB.toFixed(1)} GB Free</span>
                    </div>
                    <div className="h-2 w-full bg-slate-800/90 rounded-full overflow-hidden flex">
                        <div
                            className="h-full bg-gradient-to-r from-amber-600 to-amber-400 transition-all duration-300 rounded-full"
                            style={{ width: `${Math.max(overallPct > 0 ? 1.5 : 0, Math.min(100, overallPct))}%` }}
                        />
                    </div>
                </div>

                {/* Individual Partitions */}
                {filteredDisks.length > 0 && (
                    <div className="space-y-2">
                        {filteredDisks.map((d, i) => (
                            <div key={i} className="bg-black/30 rounded-xl px-3.5 py-2.5 border border-white/[0.04]">
                                <div className="flex items-center justify-between mb-1.5">
                                    <div className="min-w-0 flex-1 flex items-baseline gap-2">
                                        <span className="text-xs font-bold text-slate-200 font-mono truncate">{d.mount_point}</span>
                                        <span className="text-[10px] text-slate-500 truncate">{d.device} · {d.fs_type}</span>
                                    </div>
                                    <span className="text-xs font-mono font-bold text-amber-400 whitespace-nowrap ml-2 tabular-nums">
                                        {d.used_pct.toFixed(1)}%
                                    </span>
                                </div>
                                <div className="h-1.5 w-full bg-slate-800/90 rounded-full overflow-hidden">
                                    <div
                                        className="h-full rounded-full transition-all duration-300"
                                        style={{
                                            width: `${Math.max(d.used_pct > 0 ? 1.5 : 0, Math.min(100, d.used_pct))}%`,
                                            backgroundColor: d.used_pct > 90 ? '#ef4444' : d.used_pct > 75 ? '#f59e0b' : '#6366f1'
                                        }}
                                    />
                                </div>
                                <div className="flex justify-between text-[10px] text-slate-500 mt-1 font-mono">
                                    <span>{d.used_gb.toFixed(1)} GB used</span>
                                    <span>{d.total_gb.toFixed(0)} GB total</span>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
