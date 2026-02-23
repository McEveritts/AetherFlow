import { HardDrive } from 'lucide-react';
import { SystemMetrics } from '@/types/dashboard';

interface StorageWidgetProps {
    metrics: SystemMetrics;
}

export default function StorageWidget({ metrics }: StorageWidgetProps) {
    return (
        <div className="md:col-span-2 lg:col-span-3 bg-white/[0.02] border border-white/[0.05] rounded-3xl p-6 relative overflow-hidden group backdrop-blur-xl">
            <div className="flex items-center justify-between mb-8">
                <h2 className="text-base font-semibold text-slate-200 flex items-center gap-2">
                    <HardDrive size={18} className="text-amber-400" /> ZFS Storage Pools
                </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {/* Pool 1 */}
                <div>
                    <div className="flex justify-between items-end mb-3">
                        <div>
                            <h3 className="text-sm font-bold text-slate-200">/mnt/tank (Media)</h3>
                            <p className="text-xs text-slate-500 mt-0.5">RAID-Z2 • {metrics.disk_space.total.toFixed(0)} GB Total</p>
                        </div>
                        <span className="text-2xl font-bold tracking-tight text-amber-400">{((metrics.disk_space.used / metrics.disk_space.total) * 100).toFixed(1)}%</span>
                    </div>
                    <div className="h-4 w-full bg-slate-800/80 rounded-full overflow-hidden shadow-inner flex mb-2">
                        <div className="h-full bg-gradient-to-r from-amber-600 to-amber-400" style={{ width: `${(metrics.disk_space.used / metrics.disk_space.total) * 100}%` }} />
                    </div>
                    <div className="flex justify-between text-xs text-slate-400">
                        <span>{metrics.disk_space.used.toFixed(1)} GB Used</span>
                        <span>{metrics.disk_space.free.toFixed(1)} GB Free</span>
                    </div>
                </div>

                {/* Pool 2 (Mock Data) */}
                <div>
                    <div className="flex justify-between items-end mb-3">
                        <div>
                            <h3 className="text-sm font-bold text-slate-200">/ (Root)</h3>
                            <p className="text-xs text-slate-500 mt-0.5">NVMe SSD • 512 GB Total</p>
                        </div>
                        <span className="text-2xl font-bold tracking-tight text-slate-300">18.4%</span>
                    </div>
                    <div className="h-4 w-full bg-slate-800/80 rounded-full overflow-hidden shadow-inner flex mb-2">
                        <div className="h-full bg-slate-500" style={{ width: `18.4%` }} />
                    </div>
                    <div className="flex justify-between text-xs text-slate-400">
                        <span>94.2 GB Used</span>
                        <span>417.8 GB Free</span>
                    </div>
                </div>
            </div>
        </div>
    );
}
