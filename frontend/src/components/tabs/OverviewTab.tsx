import { Clock, Activity, Zap, Wifi, ArrowDown, ArrowUp, Server, Settings2, Sparkles, Layers, Cpu } from 'lucide-react';
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

    const tMetrics = metrics;
    const tHistory = history;

    const hasGpuPanel = Boolean(showGpuWidget && tMetrics.gpus && tMetrics.gpus.length > 0);
    const serviceEntries = Object.values(tMetrics.services || {});
    const runningServicesCount = serviceEntries.filter((s) => s.status === 'running').length;

    const platformIdentity = hardware
        ? [hardware.system_vendor, hardware.system_product].filter(Boolean).join(' · ')
        : '';
    const computeIdentity = hardware
        ? [
            hardware.cpu?.model,
            hardware.gpus && hardware.gpus.length > 0 ? hardware.gpus.map((g) => g.product).join(' + ') : ''
        ].filter(Boolean).join(' · ')
        : '';

    return (
        <div className="space-y-5 animate-fade-in pb-10 relative z-10 w-full min-w-0">
            {/* ========================================================================= */}
            {/* 1. OPEN TOP COMMAND HEADER                                                */}
            {/* ========================================================================= */}
            <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-4 border-b border-white/[0.06] relative z-30 shrink-0">
                <div className="flex items-start sm:items-center gap-3.5">
                    <div className="h-11 w-11 rounded-2xl flex items-center justify-center border bg-indigo-500/20 border-indigo-500/30 shadow-[0_0_24px_rgba(99,102,241,0.2)] text-indigo-400 shrink-0">
                        <Zap size={22} />
                    </div>
                    <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2.5">
                            <h2 className="text-lg md:text-xl font-extrabold text-slate-100 tracking-tight">
                                AetherNexus
                            </h2>
                            <span
                                className={`inline-flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${
                                    connectionState === 'CONNECTED'
                                        ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                        : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                }`}
                            >
                                <span
                                    className={`h-1.5 w-1.5 rounded-full ${
                                        connectionState === 'CONNECTED'
                                            ? 'bg-emerald-400 shadow-[0_0_6px_#34d399] animate-pulse'
                                            : 'bg-amber-400 animate-pulse'
                                    }`}
                                />
                                {connectionState === 'CONNECTED' ? 'Live WS · 1.0s Stream' : 'Reconnecting Stream'}
                            </span>

                            {platformIdentity && (
                                <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold px-2.5 py-0.5 rounded-full border bg-white/[0.03] text-slate-300 border-white/10">
                                    <Server size={11} className="text-indigo-400" />
                                    {platformIdentity}
                                </span>
                            )}
                        </div>
                        <p className="text-xs text-slate-400 mt-1 truncate">
                            {computeIdentity
                                ? computeIdentity
                                : connectionState === 'CONNECTED'
                                    ? 'Real-time kernel telemetry, storage pool diagnostics, service mesh topology, and predictive AI capacity planning'
                                    : 'Synchronizing real-time telemetry stream with local Nexus daemon...'}
                        </p>
                    </div>
                </div>

                {/* Right Command Controls */}
                <div className="flex flex-wrap items-center gap-2 shrink-0">
                    {/* Density View Switcher */}
                    <div className="flex items-center gap-1 p-1 bg-white/[0.04] border border-white/10 rounded-xl">
                        <button
                            type="button"
                            onClick={() => setDashboardDensity('compact')}
                            className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                                dashboardDensity === 'compact'
                                    ? 'bg-indigo-500/20 border border-indigo-500/30 text-indigo-300 shadow-md shadow-indigo-500/10'
                                    : 'text-slate-400 hover:text-white'
                            }`}
                        >
                            <Layers size={13} />
                            <span>Standard</span>
                        </button>
                        <button
                            type="button"
                            onClick={() => setDashboardDensity('immersive')}
                            className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                                dashboardDensity === 'immersive'
                                    ? 'bg-indigo-500/20 border border-indigo-500/30 text-indigo-300 shadow-md shadow-indigo-500/10'
                                    : 'text-slate-400 hover:text-white'
                            }`}
                        >
                            <Activity size={13} />
                            <span>Expanded</span>
                        </button>
                    </div>

                    {serviceEntries.length > 0 && (
                        <button
                            type="button"
                            onClick={() => setActiveTab('services')}
                            className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all"
                            title="Inspect Managed Services"
                        >
                            <Cpu size={13} className="text-emerald-400" />
                            <span>{runningServicesCount}/{serviceEntries.length} Services</span>
                        </button>
                    )}

                    <button
                        type="button"
                        onClick={() => {
                            setActiveTab('settings');
                            setActiveSettingsTab('dashboard');
                        }}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all"
                        title="Configure Display & Telemetry Preferences"
                    >
                        <Settings2 size={14} className="text-indigo-400" />
                        <span>Configure</span>
                    </button>
                </div>
            </div>

            {/* ========================================================================= */}
            {/* 2. PERMANENT 6-CELL TELEMETRY RIBBON                                      */}
            {/* ========================================================================= */}
            <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 divide-y md:divide-y-0 md:divide-x divide-white/[0.06] overflow-hidden">
                <TelemetryCell
                    icon={<Clock size={16} />}
                    iconColor="text-blue-400"
                    iconBg="bg-blue-500/10 border-blue-500/20"
                    label="Uptime"
                    value={metrics.uptime}
                    sublabel="Continuous runtime"
                />
                <TelemetryCell
                    icon={<Activity size={16} />}
                    iconColor="text-emerald-400"
                    iconBg="bg-emerald-500/10 border-emerald-500/20"
                    label="Load (1/5/15)"
                    value={metrics.load_average.map((l) => l.toFixed(2)).join(' · ')}
                    sublabel="Kernel load avg"
                />
                <TelemetryCell
                    icon={<Zap size={16} />}
                    iconColor="text-amber-400"
                    iconBg="bg-amber-500/10 border-amber-500/20"
                    label="CPU Clock"
                    value={metrics.cpu_freq_mhz > 0 ? `${(metrics.cpu_freq_mhz / 1000).toFixed(2)} GHz` : 'N/A'}
                    sublabel={`${metrics.per_core_cpu?.length || hardware?.cpu?.threads || 1} logical threads`}
                />
                <TelemetryCell
                    icon={<Wifi size={16} />}
                    iconColor="text-indigo-400"
                    iconBg="bg-indigo-500/10 border-indigo-500/20"
                    label="Connections"
                    value={String(metrics.network.active_connections)}
                    sublabel="Active sockets"
                />
                <TelemetryCell
                    icon={<ArrowDown size={16} />}
                    iconColor="text-emerald-400"
                    iconBg="bg-emerald-500/10 border-emerald-500/20"
                    label="Downloaded"
                    value={formatTotalBytes(metrics.total_net_bytes?.rx || 0)}
                    sublabel={`Live: ${metrics.network.down}`}
                />
                <TelemetryCell
                    icon={<ArrowUp size={16} />}
                    iconColor="text-indigo-400"
                    iconBg="bg-indigo-500/10 border-indigo-500/20"
                    label="Uploaded"
                    value={formatTotalBytes(metrics.total_net_bytes?.tx || 0)}
                    sublabel={`Live: ${metrics.network.up}`}
                />
            </div>

            {/* ========================================================================= */}
            {/* 3. BAND 1: REAL-TIME COMPUTE, MEMORY & I/O VITALS                         */}
            {/* ========================================================================= */}
            <div className={`grid gap-4 items-stretch ${
                dashboardDensity === 'immersive'
                    ? 'grid-cols-1 lg:grid-cols-2'
                    : 'grid-cols-1 md:grid-cols-2 xl:grid-cols-4'
            }`}>
                <MemoCpuWidget
                    cpuData={{ usage: tMetrics.cpu_usage, freq: tMetrics.cpu_freq_mhz, cores: tMetrics.per_core_cpu }}
                    hardware={hardware}
                    history={tHistory}
                    density={dashboardDensity}
                />
                <MemoMemoryWidget
                    memoryData={{ memory: tMetrics.memory, swap: tMetrics.swap }}
                    hardware={hardware}
                    history={tHistory}
                    density={dashboardDensity}
                />
                <MemoNetworkWidget
                    networkData={{ network: tMetrics.network, total: tMetrics.total_net_bytes }}
                    hardware={hardware}
                    history={tHistory}
                    density={dashboardDensity}
                />
                <MemoDiskIOWidget
                    diskIoData={tMetrics.disk_io}
                    history={tHistory}
                    density={dashboardDensity}
                />
            </div>

            {/* ========================================================================= */}
            {/* 4. BAND 2: SERVICE TOPOLOGY MESH & HISTORICAL BANDWIDTH                   */}
            {/* ========================================================================= */}
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-stretch">
                <div className={showDataUsageWidget ? 'xl:col-span-6' : 'xl:col-span-12'}>
                    <MemoAppTopologyMap topologyData={tMetrics.services} density={dashboardDensity} />
                </div>
                {showDataUsageWidget && (
                    <div className="xl:col-span-6">
                        <DataUsageHistoryWidget density={dashboardDensity} />
                    </div>
                )}
            </div>

            {/* ========================================================================= */}
            {/* 5. BAND 3: STORAGE POOLS, COMPUTE ACCELERATORS & ACTIVE PROCESSES         */}
            {/* ========================================================================= */}
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-stretch">
                <div className={hasGpuPanel ? 'xl:col-span-4' : 'xl:col-span-5'}>
                    <MemoStorageWidget storageData={tMetrics.disks} hardware={hardware} density={dashboardDensity} />
                </div>
                {hasGpuPanel && (
                    <div className="xl:col-span-4">
                        <MemoGpuWidget gpus={tMetrics.gpus || []} density={dashboardDensity} />
                    </div>
                )}
                <div className={hasGpuPanel ? 'xl:col-span-4' : 'xl:col-span-7'}>
                    <MemoProcessWidget processes={tMetrics.processes || []} density={dashboardDensity} />
                </div>
            </div>

            {/* ========================================================================= */}
            {/* 6. BAND 4: AI TELEMETRY & CAPACITY PLANNING                               */}
            {/* ========================================================================= */}
            <div className="pt-2 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-white/[0.06]">
                    <div className="flex items-center gap-2.5">
                        <div className="h-7 w-7 rounded-lg bg-fuchsia-500/10 border border-fuchsia-500/20 flex items-center justify-center text-fuchsia-400">
                            <Sparkles size={14} />
                        </div>
                        <h3 className="text-sm font-bold text-slate-100 tracking-tight">AI Telemetry &amp; Capacity Planning</h3>
                        <span className="text-xs text-slate-500 font-medium hidden sm:inline">
                            · Predictive resource forecasting &amp; peering optimization
                        </span>
                    </div>
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-fuchsia-500/10 text-fuchsia-300 border border-fuchsia-500/20">
                        FlowAI Engine
                    </span>
                </div>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 items-stretch">
                    <PredictionsCard />
                    <BandwidthCard />
                </div>
            </div>
        </div>
    );
}

function TelemetryCell({
    icon,
    iconColor,
    iconBg,
    label,
    value,
    sublabel,
}: {
    icon: React.ReactNode;
    iconColor: string;
    iconBg: string;
    label: string;
    value: string;
    sublabel: string;
}) {
    return (
        <div className="p-4 flex items-center justify-between gap-3 hover:bg-white/[0.02] transition-colors min-w-0">
            <div className="min-w-0 flex-1">
                <p className="text-[10px] text-slate-400 uppercase font-bold tracking-wider truncate">{label}</p>
                <p className="text-base font-extrabold text-slate-100 truncate mt-0.5 tabular-nums">{value}</p>
                <p className="text-[10px] text-slate-500 truncate mt-0.5 font-medium">{sublabel}</p>
            </div>
            <div className={`h-9 w-9 rounded-xl border ${iconBg} ${iconColor} flex items-center justify-center shrink-0`}>
                {icon}
            </div>
        </div>
    );
}
