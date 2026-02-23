import { Clock, Activity, Globe, Zap } from 'lucide-react';
import { SystemMetrics, HardwareReport } from '@/types/dashboard';
import CpuWidget from '@/components/widgets/CpuWidget';
import MemoryWidget from '@/components/widgets/MemoryWidget';
import NetworkWidget from '@/components/widgets/NetworkWidget';
import StorageWidget from '@/components/widgets/StorageWidget';

interface OverviewTabProps {
    metrics: SystemMetrics;
    hardware: HardwareReport | null;
}

export default function OverviewTab({ metrics, hardware }: OverviewTabProps) {
    return (
        <div className="space-y-6 animate-fade-in">
            {/* Quick Stats Row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 flex items-center gap-4 backdrop-blur-md">
                    <div className="p-3 bg-blue-500/10 rounded-xl"><Clock size={20} className="text-blue-400" /></div>
                    <div>
                        <p className="text-xs text-slate-400 uppercase font-semibold tracking-wider">System Uptime</p>
                        <p className="text-lg font-bold text-slate-100">{metrics.uptime}</p>
                    </div>
                </div>
                <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 flex items-center gap-4 backdrop-blur-md">
                    <div className="p-3 bg-emerald-500/10 rounded-xl"><Activity size={20} className="text-emerald-400" /></div>
                    <div>
                        <p className="text-xs text-slate-400 uppercase font-semibold tracking-wider">Load Average</p>
                        <p className="text-lg font-bold text-slate-100">{metrics.load_average.join(' / ')}</p>
                    </div>
                </div>
                <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 flex items-center gap-4 backdrop-blur-md">
                    <div className="p-3 bg-indigo-500/10 rounded-xl"><Globe size={20} className="text-indigo-400" /></div>
                    <div>
                        <p className="text-xs text-slate-400 uppercase font-semibold tracking-wider">Active Connections</p>
                        <p className="text-lg font-bold text-slate-100">{metrics.network.active_connections}</p>
                    </div>
                </div>
                <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 flex items-center gap-4 backdrop-blur-md">
                    <div className="p-3 bg-amber-500/10 rounded-xl"><Zap size={20} className="text-amber-400" /></div>
                    <div>
                        <p className="text-xs text-slate-400 uppercase font-semibold tracking-wider">Status</p>
                        <p className="text-lg font-bold text-emerald-400 tracking-tight">System Optimal</p>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <CpuWidget metrics={metrics} hardware={hardware} />
                <MemoryWidget metrics={metrics} hardware={hardware} />
                <NetworkWidget metrics={metrics} hardware={hardware} />
                <StorageWidget metrics={metrics} hardware={hardware} />
            </div>
        </div>
    );
}
