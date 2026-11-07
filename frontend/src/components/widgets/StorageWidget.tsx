import { useState } from 'react';
import { HardDrive } from 'lucide-react';
import { HardwareReport, DiskPartition } from '@/types/dashboard';

interface StorageWidgetProps {
    storageData: DiskPartition[];
    hardware: HardwareReport | null;
    density?: 'compact' | 'immersive';
}

function formatStorageGigabytes(gigabytesCount: number, decimalPlaces = 1): string {
    const unitsList = ['GB', 'TB', 'PB'];
    let scaledGigabytes = gigabytesCount;
    let unitIndex = 0;

    while (scaledGigabytes >= 1024 && unitIndex < unitsList.length - 1) {
        scaledGigabytes /= 1024;
        unitIndex++;
    }

    return `${scaledGigabytes.toFixed(unitIndex > 0 ? 1 : decimalPlaces)} ${unitsList[unitIndex]}`;
}

export default function StorageWidget({ storageData, density = 'compact' }: StorageWidgetProps) {
    const diskPartitions = storageData || [];
    const isImmersive = density === 'immersive';

    const [selectedDriveMountPoint, setSelectedDriveMountPoint] = useState<string>('all');

    const filteredDisks = selectedDriveMountPoint === 'all'
        ? diskPartitions
        : diskPartitions.filter(partition => partition.mount_point === selectedDriveMountPoint);

    const totalCapacityGigabytes = filteredDisks.reduce((accumulator, partition) => accumulator + partition.total_gb, 0);
    const usedCapacityGigabytes = filteredDisks.reduce((accumulator, partition) => accumulator + partition.used_gb, 0);
    const freeCapacityGigabytes = Math.max(0, totalCapacityGigabytes - usedCapacityGigabytes);
    const overallUsedPercentage = totalCapacityGigabytes > 0 ? (usedCapacityGigabytes / totalCapacityGigabytes) * 100 : 0;

    return (
        <div className={`rounded-2xl border border-slate-800/80 bg-slate-900/85 backdrop-blur-xl relative overflow-hidden flex flex-col ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                <div className="flex items-center justify-between gap-2 pb-3 mb-3.5 border-b border-slate-800/80">
                    <div className="flex items-center gap-2.5 min-w-0">
                        <div className="h-8 w-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 shrink-0">
                            <HardDrive size={16} />
                        </div>
                        <div className="min-w-0">
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">Storage Pools</h2>
                            <p className="text-[13px] text-slate-300 truncate mt-1">
                                {formatStorageGigabytes(totalCapacityGigabytes, 0)} across {filteredDisks.length} mount{filteredDisks.length !== 1 ? 's' : ''}
                            </p>
                        </div>
                    </div>
                    <div className="flex items-center gap-2.5 shrink-0">
                        <select
                            value={selectedDriveMountPoint}
                            onChange={(event) => setSelectedDriveMountPoint(event.target.value)}
                            aria-label="Filter storage partitions"
                            className="min-h-[40px] bg-slate-950/70 border border-slate-700 text-xs text-slate-200 rounded-lg px-3 py-1.5 outline-none focus-visible:ring-2 focus-visible:ring-amber-500/50 transition-colors cursor-pointer"
                        >
                            <option value="all" className="bg-slate-900">All Drives</option>
                            {diskPartitions.map((partition, partitionIndex) => (
                                <option key={partitionIndex} value={partition.mount_point} className="bg-slate-900">
                                    {partition.mount_point}
                                </option>
                            ))}
                        </select>
                        <span className="text-lg font-extrabold tracking-tight text-amber-400 tabular-nums">
                            {overallUsedPercentage.toFixed(1)}%
                        </span>
                    </div>
                </div>

                <div className="bg-slate-950/60 rounded-xl p-3.5 border border-slate-800/60 mb-3.5">
                    <div className="flex justify-between text-xs text-slate-300 font-semibold uppercase tracking-wider mb-1.5">
                        <span>{formatStorageGigabytes(usedCapacityGigabytes)} Used</span>
                        <span className="text-slate-300 font-mono">{formatStorageGigabytes(freeCapacityGigabytes)} Free</span>
                    </div>
                    <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden flex">
                        <div
                            className="h-full bg-gradient-to-r from-amber-600 to-amber-400 transition-all duration-300 rounded-full"
                            style={{ width: `${Math.max(overallUsedPercentage > 0 ? 1.5 : 0, Math.min(100, overallUsedPercentage))}%` }}
                        />
                    </div>
                </div>

                {filteredDisks.length > 0 && (
                    <div className="space-y-2">
                        {filteredDisks.map((partition, partitionIndex) => (
                            <div key={partitionIndex} className="bg-slate-950/60 rounded-xl px-3.5 py-2.5 border border-slate-800/60">
                                <div className="flex items-center justify-between mb-1.5">
                                    <div className="min-w-0 flex-1 flex items-baseline gap-2">
                                        <span className="text-xs font-bold text-slate-200 font-mono truncate">{partition.mount_point}</span>
                                        <span className="text-xs text-slate-300 font-mono truncate">{partition.device} · {partition.fs_type}</span>
                                    </div>
                                    <span className="text-xs font-mono font-bold text-amber-400 whitespace-nowrap ml-2 tabular-nums">
                                        {partition.used_pct.toFixed(1)}%
                                    </span>
                                </div>
                                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                                    <div
                                        className="h-full rounded-full transition-all duration-300"
                                        style={{
                                            width: `${Math.max(partition.used_pct > 0 ? 1.5 : 0, Math.min(100, partition.used_pct))}%`,
                                            backgroundColor: partition.used_pct > 90 ? '#ef4444' : partition.used_pct > 75 ? '#f59e0b' : '#6366f1'
                                        }}
                                    />
                                </div>
                                <div className="flex justify-between text-xs text-slate-300 mt-1 font-mono">
                                    <span>{formatStorageGigabytes(partition.used_gb)} used</span>
                                    <span>{formatStorageGigabytes(partition.total_gb, 0)} total</span>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
