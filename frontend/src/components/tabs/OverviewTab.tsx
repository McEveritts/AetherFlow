import { Clock, Activity, Zap, Wifi, ArrowDown, ArrowUp, Server, Settings2, Maximize2, Minimize2, Sparkles } from 'lucide-react';
import { SystemMetrics, HardwareReport, MetricsHistory, ProcessInfo, DiskPartition, GpuMetric } from '@/types/dashboard';
import CpuWidget from '@/components/widgets/CpuWidget';
import MemoryWidget from '@/components/widgets/MemoryWidget';
import NetworkWidget from '@/components/widgets/NetworkWidget';
import DiskIOWidget from '@/components/widgets/DiskIOWidget';
import ProcessWidget from '@/components/widgets/ProcessWidget';
import StorageWidget from '@/components/widgets/StorageWidget';
import AppTopologyMap from '@/components/widgets/AppTopologyMap';
import GpuWidget from '@/components/widgets/GpuWidget';
import DataUsageHistoryWidget from '@/components/widgets/DataUsageHistoryWidget';
import BandwidthCard from '@/components/cards/BandwidthCard';
import PredictionsCard from '@/components/cards/PredictionsCard';
import React from 'react';
import { useConnectionStore } from '@/store/useConnectionStore';
import { useSystemStore } from '@/store/useSystemStore';
import { useShallow } from 'zustand/react/shallow';

// Memoize dashboard widgets with custom, primitive-level comparators to block render cascades
const MemoCpuWidget = React.memo(CpuWidget, (prev, next) => 
    prev.cpuData.usage === next.cpuData.usage && 
    prev.cpuData.freq === next.cpuData.freq &&
    prev.cpuData.cores === next.cpuData.cores &&
    (prev.cpuData.cores || []).join(',') === (next.cpuData.cores || []).join(',') &&
    prev.history === next.history &&
    prev.density === next.density &&
    prev.hardware === next.hardware
);
const MemoMemoryWidget = React.memo(MemoryWidget, (prev, next) => 
    prev.memoryData.memory.used === next.memoryData.memory.used && 
    prev.memoryData.swap.used === next.memoryData.swap.used &&
    prev.history === next.history &&
    prev.density === next.density &&
    prev.hardware === next.hardware
);
const MemoNetworkWidget = React.memo(NetworkWidget, (prev, next) => 
    `${prev.networkData.network.active_connections}-${prev.networkData.network.down}-${prev.networkData.network.up}-${prev.networkData.total?.rx}-${prev.networkData.total?.tx}` ===
    `${next.networkData.network.active_connections}-${next.networkData.network.down}-${next.networkData.network.up}-${next.networkData.total?.rx}-${next.networkData.total?.tx}` &&
    prev.history === next.history &&
    prev.density === next.density &&
    prev.hardware === next.hardware
);
const MemoDiskIOWidget = React.memo(DiskIOWidget, (prev, next) => 
    prev.diskIoData?.read_bytes_sec === next.diskIoData?.read_bytes_sec && 
    prev.diskIoData?.write_bytes_sec === next.diskIoData?.write_bytes_sec &&
    prev.history === next.history &&
    prev.density === next.density
);
const MemoProcessWidget = React.memo(ProcessWidget, (prev, next) => {
    const getProcHash = (p: ProcessInfo[]) => (p || []).slice(0, 5).map(proc => `${proc.pid}-${proc.cpu}`).join(':');
    return getProcHash(prev.processes) === getProcHash(next.processes) && prev.density === next.density;
});
const MemoStorageWidget = React.memo(StorageWidget, (prev, next) => {
    const getDiskHash = (d: DiskPartition[]) => (d || []).map(disk => `${disk.mount_point}-${disk.used_pct}`).join(':');
    return getDiskHash(prev.storageData) === getDiskHash(next.storageData) && prev.density === next.density && prev.hardware === next.hardware;
});
const MemoAppTopologyMap = React.memo(AppTopologyMap, (prev, next) => {
    const getStatusHash = (t: SystemMetrics['services']) => Object.values(t || {}).map(node => node.status).join(':');
    return getStatusHash(prev.topologyData) === getStatusHash(next.topologyData) && prev.density === next.density;
});
const MemoGpuWidget = React.memo(GpuWidget, (prev, next) => {
    const getGpuHash = (g: GpuMetric[]) => (g || []).map(gpu => `${gpu.index}-${gpu.usage_pct}-${gpu.temp}-${gpu.memory_used}-${gpu.memory_total}`).join(':');
    return getGpuHash(prev.gpus) === getGpuHash(next.gpus) && prev.density === next.density;
});

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
    const { connectionState, dashboardDensity, setDashboardDensity, showGpuWidget, showDataUsageWidget } = useConnectionStore(
        useShallow((state) => ({
            connectionState: state.connectionState,
            dashboardDensity: state.dashboardDensity,
            setDashboardDensity: state.setDashboardDensity,
            showGpuWidget: state.showGpuWidget,
            showDataUsageWidget: state.showDataUsageWidget
        }))
    );
    const { setActiveTab, setActiveSettingsTab } = useSystemStore(
        useShallow((state) => ({
            setActiveTab: state.setActiveTab,
            setActiveSettingsTab: state.setActiveSettingsTab
        }))
    );
    
    // Direct prop pass-through — the upstream Zustand store already throttles
    // at 250ms via pushMetrics. React.memo on child widgets prevents unnecessary
    // re-renders, so no additional render gating is needed.
    const tMetrics = metrics;
    const tHistory = history;

    return (
        <div className="space-y-6 animate-fade-in pb-10">
            {/* AetherNexus Live Status Control */}
            <div className="bg-gradient-to-r from-indigo-500/10 via-purple-500/10 to-blue-500/10 border border-white/[0.08] rounded-2xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 backdrop-blur-xl shadow-2xl">
                <div className="flex items-center gap-4">
                    <div className="relative">
                        <div className={`p-3 rounded-xl ${
                            connectionState === 'CONNECTED'
                                ? 'bg-emerald-500/20 text-emerald-400'
                                : 'bg-amber-500/20 text-amber-400'
                        } border border-white/10`}>
                            <Zap size={20} className="animate-pulse" />
                        </div>
                        <div className={`absolute -bottom-1 -right-1 w-3 h-3 rounded-full border-2 border-[#0B0E14] ${
                            connectionState === 'CONNECTED'
                                ? 'bg-emerald-500'
                                : 'bg-amber-500'
                        }`} />
                    </div>
                    <div>
                        <h2 className="text-xl font-black text-white tracking-tight flex items-center gap-2">
                            AetherNexus
                            <span className="text-[10px] bg-white/10 px-2 py-0.5 rounded-full font-bold uppercase tracking-widest text-slate-400 border border-white/5">
                                Live WS
                            </span>
                        </h2>
                        <p className="text-xs text-slate-400 font-medium">
                            {connectionState === 'CONNECTED'
                                ? 'Hyper-Link connection active (WS · 1.0s Live Stream)'
                                : 'Reconnecting to Hyper-Link WebSocket stream...'}
                        </p>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 w-full md:w-auto justify-end">
                    {/* Perspective / Immersion Toggle */}
                    <button 
                        onClick={() => setDashboardDensity(dashboardDensity === 'compact' ? 'immersive' : 'compact')}
                        className={`obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 rounded-xl border border-white/10 transition-all flex items-center justify-center ${dashboardDensity === 'immersive' ? 'bg-indigo-500/20 text-indigo-400 shadow-[0_0_15px_rgba(99,102,241,0.2)]' : 'bg-white/5 text-slate-400 hover:text-white dark:hover:bg-white/5'}`}
                        title={dashboardDensity === 'immersive' ? 'Exit Immersive Mode' : 'Enter Immersive Mode'}
                    >
                        {dashboardDensity === 'immersive' ? <Minimize2 size={18} /> : <Maximize2 size={18} />}
                    </button>

                    {/* Dashboard Settings Navigation */}
                    <button 
                        onClick={() => {
                            setActiveTab('settings');
                            setActiveSettingsTab('dashboard');
                        }}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 rounded-xl border border-white/10 transition-all bg-white/5 text-slate-400 hover:text-white hover:bg-white/10 flex items-center justify-center"
                        title="Manage Dashboard Settings"
                    >
                        <Settings2 size={18} />
                    </button>

                    <div className="flex items-center gap-2 bg-black/20 p-1.5 rounded-xl border border-white/5">
                        <div className="obs-touch-target-standard px-3.5 py-2 rounded-lg text-xs font-bold flex items-center gap-2 bg-indigo-500 text-white shadow-lg">
                            <Zap size={14} />
                            WebSocket
                        </div>
                    </div>
                </div>
            </div>

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
                    label="Downloaded"
                    value={formatTotalBytes(metrics.total_net_bytes?.rx || 0)}
                />
                <StatPill
                    icon={<ArrowUp size={15} />}
                    iconColor="text-indigo-400"
                    iconBg="bg-indigo-500/10"
                    label="Uploaded"
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
                        {hardware.gpus && hardware.gpus.length > 0 && ` · ${hardware.gpus.map(g => g.product).join(' + ')}`}
                    </span>
                </div>
            )}

            {/* Core Widgets Grid */}
            <div className={`grid gap-6 items-start ${dashboardDensity === 'immersive' ? 'grid-cols-1 xl:grid-cols-2' : 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3'}`}>
                
                {/* 1. Primary Metrics */}
                <div className="space-y-6">
                    <MemoCpuWidget cpuData={{ usage: tMetrics.cpu_usage, freq: tMetrics.cpu_freq_mhz, cores: tMetrics.per_core_cpu }} hardware={hardware} history={tHistory} density={dashboardDensity} />
                    <MemoMemoryWidget memoryData={{ memory: tMetrics.memory, swap: tMetrics.swap }} hardware={hardware} history={tHistory} density={dashboardDensity} />
                    
                    {/* GPU Widget - Auto Detectable & User Enabled */}
                    {(showGpuWidget && tMetrics.gpus && tMetrics.gpus.length > 0) && (
                        <MemoGpuWidget gpus={tMetrics.gpus} density={dashboardDensity} />
                    )}
                </div>

                {/* 2. Secondary Metrics */}
                <div className="space-y-6">
                    <MemoNetworkWidget networkData={{ network: tMetrics.network, total: tMetrics.total_net_bytes }} hardware={hardware} history={tHistory} density={dashboardDensity} />
                    <MemoDiskIOWidget diskIoData={tMetrics.disk_io} history={tHistory} density={dashboardDensity} />
                    
                    {/* Data Usage History Widget - User Enabled */}
                    {showDataUsageWidget && (
                        <DataUsageHistoryWidget density={dashboardDensity} />
                    )}
                </div>

                {/* 3. System Visualization & Processes */}
                <div className={`space-y-6 ${dashboardDensity === 'immersive' ? 'xl:col-span-2' : ''}`}>
                    <div className={`grid gap-6 items-start ${dashboardDensity === 'immersive' ? 'grid-cols-1 lg:grid-cols-3' : 'grid-cols-1'}`}>
                        <div className={dashboardDensity === 'immersive' ? 'lg:col-span-2' : ''}>
                            <MemoAppTopologyMap topologyData={tMetrics.services} density={dashboardDensity} />
                        </div>
                        <div className="space-y-6">
                            <MemoStorageWidget storageData={tMetrics.disks} hardware={hardware} density={dashboardDensity} />
                            <MemoProcessWidget processes={tMetrics.processes || []} density={dashboardDensity} />
                        </div>
                    </div>
                </div>
            </div>

            {/* 4. AI Telemetry & Capacity Section */}
            <div className="pt-2 space-y-4">
                <div className="flex items-center gap-2 px-1">
                    <Sparkles size={16} className="text-fuchsia-400" />
                    <h3 className="text-sm font-bold text-slate-200">AI Telemetry & Capacity Planning</h3>
                    <span className="text-xs text-slate-500 font-medium">Predictive resource forecasting & peering optimization</span>
                </div>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <PredictionsCard />
                    <BandwidthCard />
                </div>
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
        <div className="glass-card rounded-xl px-4 py-3 flex items-center gap-3 group hover:bg-white/[0.04] transition-colors">
            <div className={`p-2 ${iconBg} rounded-lg ${iconColor}`}>{icon}</div>
            <div className="min-w-0">
                <p className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">{label}</p>
                <p className="text-sm font-bold text-slate-100 truncate">{value}</p>
            </div>
        </div>
    );
}
