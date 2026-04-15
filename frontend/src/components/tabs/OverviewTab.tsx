import { Clock, Activity, Zap, Wifi, ArrowDown, ArrowUp, Server, Radio, ZapOff, Settings2, Gauge } from 'lucide-react';
import { SystemMetrics, HardwareReport, MetricsHistory } from '@/types/dashboard';
import CpuWidget from '@/components/widgets/CpuWidget';
import MemoryWidget from '@/components/widgets/MemoryWidget';
import NetworkWidget from '@/components/widgets/NetworkWidget';
import DiskIOWidget from '@/components/widgets/DiskIOWidget';
import ProcessWidget from '@/components/widgets/ProcessWidget';
import StorageWidget from '@/components/widgets/StorageWidget';
import AppTopologyMap from '@/components/widgets/AppTopologyMap';
import GpuWidget from '@/components/widgets/GpuWidget';
import React, { useState, useEffect, useRef } from 'react';
import { useConnectionStore, ConnectionMode } from '@/store/useConnectionStore';

// Memoize dashboard widgets to block parent render cascades
const MemoCpuWidget = React.memo(CpuWidget);
const MemoMemoryWidget = React.memo(MemoryWidget);
const MemoNetworkWidget = React.memo(NetworkWidget);
const MemoDiskIOWidget = React.memo(DiskIOWidget);
const MemoProcessWidget = React.memo(ProcessWidget);
const MemoStorageWidget = React.memo(StorageWidget);
const MemoAppTopologyMap = React.memo(AppTopologyMap);
const MemoGpuWidget = React.memo(GpuWidget);

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
    const { preferredMode, setPreferredMode, pollInterval, setPollInterval, connectionState, dashboardDensity, setDashboardDensity } = useConnectionStore();
    
    // Adaptive render cycle: Faster if we have high-frequency data
    const renderInterval = preferredMode === 'websocket' ? 500 : Math.min(pollInterval, 1000);

    const metricsRef = useRef(metrics);
    const historyRef = useRef(history);
    
    useEffect(() => {
        metricsRef.current = metrics;
        historyRef.current = history;
    }, [metrics, history]);

    const [tMetrics, setTMetrics] = useState(metrics);
    const [tHistory, setTHistory] = useState(history);

    useEffect(() => {
        const timer = setInterval(() => {
            setTMetrics(metricsRef.current);
            setTHistory(historyRef.current);
        }, renderInterval);
        return () => clearInterval(timer);
    }, [renderInterval]);

    return (
        <div className="space-y-6 animate-fade-in pb-10">
            {/* AetherNexus Live Status Control */}
            <div className="bg-gradient-to-r from-indigo-500/10 via-purple-500/10 to-blue-500/10 border border-white/[0.08] rounded-2xl p-4 flex flex-col md:flex-row items-center justify-between gap-4 backdrop-blur-xl shadow-2xl">
                <div className="flex items-center gap-4">
                    <div className="relative">
                        <div className={`p-3 rounded-xl ${connectionState === 'CONNECTED' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'} border border-white/10`}>
                            {preferredMode === 'websocket' ? <Zap size={20} className="animate-pulse" /> : <Radio size={20} className="animate-ping" />}
                        </div>
                        <div className={`absolute -bottom-1 -right-1 w-3 h-3 rounded-full border-2 border-[#0B0E14] ${connectionState === 'CONNECTED' ? 'bg-emerald-500' : 'bg-amber-500'}`} />
                    </div>
                    <div>
                        <h2 className="text-xl font-black text-white tracking-tight flex items-center gap-2">
                            AetherNexus
                            <span className="text-[10px] bg-white/10 px-2 py-0.5 rounded-full font-bold uppercase tracking-widest text-slate-400 border border-white/5">Live</span>
                        </h2>
                        <p className="text-xs text-slate-400 font-medium">
                            {preferredMode === 'websocket' ? 'Hyper-Link connection active (WS)' : `Polling Nexus active (${(pollInterval / 1000).toFixed(1)}s)`}
                        </p>
                    </div>
                </div>

                <div className="flex items-center gap-4">
                    {/* Settings Cog Wheel */}
                    <button 
                        onClick={() => setDashboardDensity(dashboardDensity === 'compact' ? 'immersive' : 'compact')}
                        className={`p-2 rounded-xl border border-white/10 transition-all ${dashboardDensity === 'immersive' ? 'bg-indigo-500/20 text-indigo-400 shadow-[0_0_15px_rgba(99,102,241,0.2)]' : 'bg-white/5 text-slate-400 hover:text-white'}`}
                        title="Toggle Immersion Mode"
                    >
                        <Settings2 size={18} className={dashboardDensity === 'immersive' ? 'rotate-90 transition-transform duration-500' : ''} />
                    </button>

                    <div className="flex items-center gap-3 bg-black/20 p-1.5 rounded-xl border border-white/5">
                    <button
                        onClick={() => setPreferredMode('websocket')}
                        className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${preferredMode === 'websocket' ? 'bg-indigo-500 text-white shadow-lg' : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'}`}
                    >
                        <Zap size={14} />
                        WebSocket
                    </button>
                    <button
                        onClick={() => setPreferredMode('poll')}
                        className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${preferredMode === 'poll' ? 'bg-purple-500 text-white shadow-lg' : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'}`}
                    >
                        <Radio size={14} />
                        Poll
                    </button>
                    
                    <div className="h-4 w-px bg-white/10 mx-1" />
                    
                    <select 
                        value={pollInterval}
                        onChange={(e) => setPollInterval(Number(e.target.value))}
                        disabled={preferredMode === 'websocket'}
                        className="bg-transparent text-slate-300 text-xs font-bold outline-none cursor-pointer hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
                    >
                        <option value={1000} className="bg-[#12141a]">1s</option>
                        <option value={2000} className="bg-[#12141a]">2s</option>
                        <option value={5000} className="bg-[#12141a]">5s</option>
                        <option value={10000} className="bg-[#12141a]">10s</option>
                    </select>
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

            {/* Core Widgets Grid */}
            <div className={`grid gap-6 ${dashboardDensity === 'immersive' ? 'grid-cols-1 xl:grid-cols-2' : 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3'}`}>
                
                {/* 1. Primary Metrics */}
                <div className="space-y-6">
                    <MemoCpuWidget metrics={tMetrics} history={tHistory} />
                    <MemoMemoryWidget metrics={tMetrics} history={tHistory} />
                    
                    {/* GPU Widget - Auto Detectable & User Enabled */}
                    {(showGpuWidget && tMetrics.gpus && tMetrics.gpus.length > 0) && (
                        <MemoGpuWidget gpus={tMetrics.gpus} density={dashboardDensity} />
                    )}
                </div>

                {/* 2. Secondary Metrics */}
                <div className="space-y-6">
                    <MemoNetworkWidget metrics={tMetrics} history={tHistory} />
                    <MemoDiskIOWidget metrics={tMetrics} history={tHistory} />
                </div>

                {/* 3. System Visualization & Processes */}
                <div className={`space-y-6 ${dashboardDensity === 'immersive' ? 'xl:col-span-2' : ''}`}>
                    <div className={`grid gap-6 ${dashboardDensity === 'immersive' ? 'grid-cols-1 lg:grid-cols-3' : 'grid-cols-1'}`}>
                        <div className={dashboardDensity === 'immersive' ? 'lg:col-span-2' : ''}>
                            <MemoAppTopologyMap metrics={tMetrics} hardware={hardware} />
                        </div>
                        <div className="space-y-6">
                            <MemoStorageWidget metrics={tMetrics} />
                            <MemoProcessWidget metrics={tMetrics} />
                        </div>
                    </div>
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
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-xl px-4 py-3 flex items-center gap-3 backdrop-blur-md group hover:bg-white/[0.04] transition-colors">
            <div className={`p-2 ${iconBg} rounded-lg ${iconColor}`}>{icon}</div>
            <div className="min-w-0">
                <p className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">{label}</p>
                <p className="text-sm font-bold text-slate-100 truncate">{value}</p>
            </div>
        </div>
    );
}
