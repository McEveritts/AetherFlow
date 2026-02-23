import { Clock, Activity, Zap, Wifi, ArrowDown, ArrowUp, Server } from 'lucide-react';
import { SystemMetrics, HardwareReport, MetricsHistory } from '@/types/dashboard';
import CpuWidget from '@/components/widgets/CpuWidget';
import MemoryWidget from '@/components/widgets/MemoryWidget';
import NetworkWidget from '@/components/widgets/NetworkWidget';
import DiskIOWidget from '@/components/widgets/DiskIOWidget';
import ProcessWidget from '@/components/widgets/ProcessWidget';
import StorageWidget from '@/components/widgets/StorageWidget';

interface OverviewTabProps {
    metrics: SystemMetrics;
    hardware: HardwareReport | null;
    history: MetricsHistory;
}

function formatTotalBytes(bytes: number): string {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let unitIndex = 0;
    let value = bytes;
    while (value >= 1024 && unitIndex < units.length - 1) {
        value /= 1024;
        unitIndex++;
    }
    return `${value.toFixed(unitIndex > 1 ? 1 : 0)} ${units[unitIndex]}`;
}

export default function OverviewTab({ metrics, hardware, history }: OverviewTabProps) {
    return (
        <div className="space-y-5 animate-fade-in">
            {/* Hero Stats Row */}
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                <StatPill
                    icon={<Clock size={15} />}
                    iconColor="text-blue-400"
                    iconBg="bg-blue-500/10"
                    label="Uptime"
                    value={metrics.uptime}
                />
                <StatPill
                    icon={<Activity size={15} />}
                    iconColor="text-emerald-400"
                    iconBg="bg-emerald-500/10"
                    label="Load (1/5/15)"
                    value={metrics.load_average.map(l => l.toFixed(2)).join(' · ')}
                />
                <StatPill
                    icon={<Zap size={15} />}
                    iconColor="text-amber-400"
                    iconBg="bg-amber-500/10"
                    label="CPU Freq"
                    value={metrics.cpu_freq_mhz > 0 ? `${(metrics.cpu_freq_mhz / 1000).toFixed(2)} GHz` : 'N/A'}
                />
                <StatPill
                    icon={<Wifi size={15} />}
                    iconColor="text-indigo-400"
                    iconBg="bg-indigo-500/10"
                    label="Connections"
                    value={String(metrics.network.active_connections)}
                />
                <StatPill
                    icon={<ArrowDown size={15} />}
                    iconColor="text-emerald-400"
                    iconBg="bg-emerald-500/10"
                    label="Total RX"
                    value={formatTotalBytes(metrics.total_net_bytes?.rx || 0)}
                />
                <StatPill
                    icon={<ArrowUp size={15} />}
                    iconColor="text-indigo-400"
                    iconBg="bg-indigo-500/10"
                    label="Total TX"
                    value={formatTotalBytes(metrics.total_net_bytes?.tx || 0)}
                />
            </div>

            {/* System Identity */}
            {hardware && (hardware.system_vendor || hardware.system_product) && (
                <div className="flex items-center gap-2 px-1">
                    <Server size={12} className="text-slate-500" />
                    <span className="text-[11px] text-slate-500 font-medium">
                        {[hardware.system_vendor, hardware.system_product].filter(Boolean).join(' · ')}
                        {hardware.cpu?.model && ` · ${hardware.cpu.model}`}
                    </span>
                </div>
            )}

            {/* Main Metrics Grid — 2 columns */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                <CpuWidget metrics={metrics} hardware={hardware} history={history} />
                <MemoryWidget metrics={metrics} hardware={hardware} history={history} />
            </div>

            {/* IO Grid — 2 columns */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                <NetworkWidget metrics={metrics} hardware={hardware} history={history} />
                <DiskIOWidget metrics={metrics} history={history} />
            </div>

            {/* Processes + Storage */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                <ProcessWidget processes={metrics.processes} />
                <StorageWidget metrics={metrics} hardware={hardware} />
            </div>
        </div>
    );
}

function StatPill({ icon, iconColor, iconBg, label, value }: {
    icon: React.ReactNode;
    iconColor: string;
    iconBg: string;
    label: string;
    value: string;
}) {
    return (
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-xl px-4 py-3 flex items-center gap-3 backdrop-blur-md group hover:bg-white/[0.04] transition-colors">
            <div className={`p-2 ${iconBg} rounded-lg ${iconColor}`}>{icon}</div>
            <div className="min-w-0">
                <p className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">{label}</p>
                <p className="text-sm font-bold text-slate-100 truncate">{value}</p>
            </div>
        </div>
    );
}
