import { Clock, Activity, Zap, Wifi, Server, Settings2, Sparkles, Layers, Cpu, AlertTriangle, ExternalLink, ChevronDown } from 'lucide-react';
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
import { isServiceException, getServiceExceptionDetail, formatServiceName } from '@/components/widgets/serviceHealthHelpers';
import React, { useMemo } from 'react';
import { useConnectionStore } from '@/store/useConnectionStore';
import { useSystemStore } from '@/store/useSystemStore';
import { useHistoryStore, TIME_WINDOW_OPTIONS } from '@/store/useHistoryStore';
import { useShallow } from 'zustand/react/shallow';
import { validateTimestampsAlignment, formatTimeEndpoint } from '@/components/charts/Sparkline';

export interface SharedSparseTelemetryInfo {
    sampleCount: number;
    spanSeconds: number;
    startTimestamp?: number;
    statusMessage: string;
    metadataMessage?: string;
}

export function getSharedSparseTelemetryInfo(
    history: MetricsHistory,
    selectedWindow?: string
): {
    sharedTelemetry: SharedSparseTelemetryInfo | null;
    isCpuShared: boolean;
    isMemoryShared: boolean;
    isNetworkShared: boolean;
    isDiskIoShared: boolean;
} {
    const { timestamps, cpu, memory, netDown, netUp, diskRead, diskWrite } = history;
    if (!timestamps || timestamps.length === 0) {
        return {
            sharedTelemetry: null,
            isCpuShared: false,
            isMemoryShared: false,
            isNetworkShared: false,
            isDiskIoShared: false,
        };
    }

    const sampleCount = timestamps.length;
    const alignment = validateTimestampsAlignment(sampleCount, timestamps);
    const isDegenerate = Boolean(
        alignment.isValid &&
        alignment.startTimestamp !== undefined &&
        alignment.endTimestamp !== undefined &&
        alignment.startTimestamp === alignment.endTimestamp
    );
    const isSparse = sampleCount < 2 || isDegenerate;
    if (!isSparse) {
        return {
            sharedTelemetry: null,
            isCpuShared: false,
            isMemoryShared: false,
            isNetworkShared: false,
            isDiskIoShared: false,
        };
    }

    const isCpuMatching = (cpu?.length || 0) === sampleCount;
    const isMemoryMatching = (memory?.length || 0) === sampleCount;
    const isNetworkMatching = (netDown?.length || 0) === sampleCount && (netUp?.length || 0) === sampleCount;
    const isDiskIoMatching = (diskRead?.length || 0) === sampleCount && (diskWrite?.length || 0) === sampleCount;

    const matchingCount = [isCpuMatching, isMemoryMatching, isNetworkMatching, isDiskIoMatching].filter(Boolean).length;
    if (matchingCount < 2) {
        return {
            sharedTelemetry: null,
            isCpuShared: false,
            isMemoryShared: false,
            isNetworkShared: false,
            isDiskIoShared: false,
        };
    }

    let statusMessage = '';
    if (sampleCount === 0) {
        statusMessage = 'Collecting · 0 samples';
    } else if (sampleCount === 1) {
        statusMessage = 'Collecting · 1 sample';
    } else {
        statusMessage = `Collecting · ${sampleCount} samples · 0s span`;
    }

    let metadataMessage: string | undefined = undefined;
    if (alignment.isValid && alignment.startTimestamp !== undefined) {
        const timeStr = formatTimeEndpoint(alignment.startTimestamp);
        if (selectedWindow) {
            metadataMessage = `Observed ${timeStr} · ${selectedWindow} max`;
        } else {
            metadataMessage = `Observed ${timeStr}`;
        }
    } else if (selectedWindow) {
        metadataMessage = `${selectedWindow} max`;
    }

    const sharedTelemetry: SharedSparseTelemetryInfo = {
        sampleCount,
        spanSeconds: alignment.spanSeconds ?? 0,
        startTimestamp: alignment.startTimestamp,
        statusMessage,
        metadataMessage,
    };

    return {
        sharedTelemetry,
        isCpuShared: isCpuMatching,
        isMemoryShared: isMemoryMatching,
        isNetworkShared: isNetworkMatching,
        isDiskIoShared: isDiskIoMatching,
    };
}

function areNumberArraysEqual(firstArray?: number[], secondArray?: number[]): boolean {
    if (firstArray === secondArray) return true;
    const leftArray = firstArray || [];
    const rightArray = secondArray || [];
    if (leftArray.length !== rightArray.length) return false;
    for (let itemIndex = 0; itemIndex < leftArray.length; itemIndex++) {
        if (leftArray[itemIndex] !== rightArray[itemIndex]) return false;
    }
    return true;
}

const MemoCpuWidget = React.memo(CpuWidget, (previousProps, nextProps) =>
    previousProps.cpuData.usage === nextProps.cpuData.usage &&
    previousProps.cpuData.freq === nextProps.cpuData.freq &&
    areNumberArraysEqual(previousProps.cpuData.cores, nextProps.cpuData.cores) &&
    previousProps.history.cpu === nextProps.history.cpu &&
    areNumberArraysEqual(previousProps.history.timestamps, nextProps.history.timestamps) &&
    previousProps.selectedWindow === nextProps.selectedWindow &&
    previousProps.density === nextProps.density &&
    previousProps.hardware === nextProps.hardware &&
    previousProps.hasSharedSummary === nextProps.hasSharedSummary
);

const MemoMemoryWidget = React.memo(MemoryWidget, (previousProps, nextProps) =>
    previousProps.memoryData.memory.used === nextProps.memoryData.memory.used &&
    previousProps.memoryData.swap.used === nextProps.memoryData.swap.used &&
    previousProps.history.memory === nextProps.history.memory &&
    areNumberArraysEqual(previousProps.history.timestamps, nextProps.history.timestamps) &&
    previousProps.selectedWindow === nextProps.selectedWindow &&
    previousProps.density === nextProps.density &&
    previousProps.hardware === nextProps.hardware &&
    previousProps.hasSharedSummary === nextProps.hasSharedSummary
);

const MemoNetworkWidget = React.memo(NetworkWidget, (previousProps, nextProps) =>
    `${previousProps.networkData.network.active_connections}-${previousProps.networkData.network.down}-${previousProps.networkData.network.up}-${previousProps.networkData.total?.rx}-${previousProps.networkData.total?.tx}` ===
    `${nextProps.networkData.network.active_connections}-${nextProps.networkData.network.down}-${nextProps.networkData.network.up}-${nextProps.networkData.total?.rx}-${nextProps.networkData.total?.tx}` &&
    previousProps.history.netDown === nextProps.history.netDown &&
    previousProps.history.netUp === nextProps.history.netUp &&
    areNumberArraysEqual(previousProps.history.timestamps, nextProps.history.timestamps) &&
    previousProps.selectedWindow === nextProps.selectedWindow &&
    previousProps.density === nextProps.density &&
    previousProps.hardware === nextProps.hardware &&
    previousProps.hasSharedSummary === nextProps.hasSharedSummary
);

const MemoDiskIOWidget = React.memo(DiskIOWidget, (previousProps, nextProps) =>
    previousProps.diskIoData?.read_bytes_sec === nextProps.diskIoData?.read_bytes_sec &&
    previousProps.diskIoData?.write_bytes_sec === nextProps.diskIoData?.write_bytes_sec &&
    previousProps.history.diskRead === nextProps.history.diskRead &&
    previousProps.history.diskWrite === nextProps.history.diskWrite &&
    areNumberArraysEqual(previousProps.history.timestamps, nextProps.history.timestamps) &&
    previousProps.selectedWindow === nextProps.selectedWindow &&
    previousProps.density === nextProps.density &&
    previousProps.hasSharedSummary === nextProps.hasSharedSummary
);

const MemoProcessWidget = React.memo(ProcessWidget, (previousProps, nextProps) => {
    const getProcessSignature = (processList: ProcessInfo[]) => (processList || []).map(processItem => `${processItem.pid}-${processItem.cpu}-${processItem.mem}`).join(':');
    return getProcessSignature(previousProps.processes) === getProcessSignature(nextProps.processes) && previousProps.density === nextProps.density;
});

const MemoStorageWidget = React.memo(StorageWidget, (previousProps, nextProps) => {
    const getDiskSignature = (diskList: DiskPartition[]) => (diskList || []).map(partition => `${partition.mount_point}-${partition.used_pct}`).join(':');
    return getDiskSignature(previousProps.storageData) === getDiskSignature(nextProps.storageData) && previousProps.density === nextProps.density && previousProps.hardware === nextProps.hardware;
});

const MemoAppTopologyMap = React.memo(AppTopologyMap, (previousProps, nextProps) => {
    const getTopologyStatusSignature = (topologyServices: SystemMetrics['services']) =>
        Object.entries(topologyServices || {}).map(([serviceName, nodeInfo]) => `${serviceName}-${nodeInfo.status}-${nodeInfo.job_status || ''}-${nodeInfo.health || ''}`).join(':');
    return getTopologyStatusSignature(previousProps.topologyData) === getTopologyStatusSignature(nextProps.topologyData) && previousProps.density === nextProps.density;
});

const MemoGpuWidget = React.memo(GpuWidget, (previousProps, nextProps) => {
    const getGpuSignature = (gpuList: GpuMetric[]) => (gpuList || []).map(gpuItem => `${gpuItem.index}-${gpuItem.usage_pct}-${gpuItem.temp}-${gpuItem.memory_used}-${gpuItem.memory_total}`).join(':');
    return getGpuSignature(previousProps.gpus) === getGpuSignature(nextProps.gpus) && previousProps.density === nextProps.density;
});

interface OverviewTabProps {
    metrics: SystemMetrics;
    hardware: HardwareReport | null;
    history: MetricsHistory;
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
    const { timeWindow, setTimeWindow } = useHistoryStore(
        useShallow((state) => ({
            timeWindow: state.timeWindow,
            setTimeWindow: state.setTimeWindow,
        }))
    );

    const hasGpuPanel = Boolean(showGpuWidget && metrics.gpus && metrics.gpus.length > 0);
    const serviceEntries = useMemo(() => Object.entries(metrics.services || {}), [metrics.services]);
    const runningServicesCount = useMemo(() => serviceEntries.filter(([, serviceInfo]) => serviceInfo.status === 'running').length, [serviceEntries]);
    const failedServices = useMemo(() => serviceEntries.filter(([, serviceInfo]) => isServiceException(serviceInfo)), [serviceEntries]);

    const sharedTelemetryInfo = useMemo(() => {
        return getSharedSparseTelemetryInfo(history, timeWindow);
    }, [history, timeWindow]);

    const platformIdentity = hardware
        ? [hardware.system_vendor, hardware.system_product].filter(Boolean).join(' · ')
        : '';
    const computeIdentity = hardware
        ? [
            hardware.cpu?.model,
            hardware.gpus && hardware.gpus.length > 0 ? hardware.gpus.map((gpuItem) => gpuItem.product).join(' + ') : ''
        ].filter(Boolean).join(' · ')
        : '';

    return (
        <div className="space-y-5 animate-fade-in pb-10 relative z-10 w-full min-w-0">
            <div className="flex flex-col 2xl:flex-row 2xl:items-center justify-between gap-3 sm:gap-4 pb-3 sm:pb-4 border-b border-slate-800/80 relative z-30 shrink-0">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 min-w-0 w-full 2xl:w-auto">
                    <div className="flex items-center gap-2.5 sm:gap-3.5 min-w-0">
                        <div className="h-9 w-9 sm:h-11 sm:w-11 rounded-xl sm:rounded-2xl flex items-center justify-center border bg-indigo-500/15 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.15)] text-indigo-400 shrink-0">
                            <Zap size={18} className="sm:hidden" />
                            <Zap size={22} className="hidden sm:block" />
                        </div>
                        <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2 sm:gap-2.5">
                                <h2 className="text-base sm:text-lg md:text-xl font-extrabold text-slate-100 tracking-tight">
                                    AetherNexus
                                </h2>
                                <span
                                    className={`inline-flex items-center gap-1.5 text-[11px] sm:text-xs font-semibold px-2 py-0.5 sm:px-2.5 sm:py-1 rounded-full border ${
                                        connectionState === 'CONNECTED'
                                            ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25'
                                            : 'bg-amber-500/10 text-amber-300 border-amber-500/25'
                                    }`}
                                >
                                    <span
                                        className={`h-1.5 w-1.5 sm:h-2 sm:w-2 rounded-full ${
                                            connectionState === 'CONNECTED'
                                                ? 'bg-emerald-400 shadow-[0_0_6px_#34d399] animate-pulse'
                                                : 'bg-amber-400 animate-pulse'
                                        }`}
                                    />
                                    {connectionState === 'CONNECTED' ? 'Live Telemetry' : 'Reconnecting'}
                                    <span className="hidden sm:inline"> · 1.0s Interval</span>
                                </span>

                                {platformIdentity && (
                                    <span className="hidden sm:inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full border bg-slate-800/80 text-slate-200 border-slate-700/60">
                                        <Server size={13} className="text-indigo-400" />
                                        {platformIdentity}
                                    </span>
                                )}
                            </div>
                            <p className="text-xs text-slate-400 mt-1 truncate hidden sm:block">
                                {computeIdentity
                                    ? computeIdentity
                                    : connectionState === 'CONNECTED'
                                        ? 'Real-time kernel telemetry, storage pool diagnostics, and service mesh topology'
                                        : 'Synchronizing real-time telemetry stream with local Nexus daemon...'}
                            </p>
                        </div>
                    </div>

                    <details className="sm:hidden w-full group text-xs">
                        <summary
                            data-testid="host-metadata-summary"
                            className="min-h-[44px] cursor-pointer list-none flex items-center justify-between px-3 py-2.5 rounded-xl bg-slate-950/70 border border-slate-800 text-slate-300 font-semibold hover:text-white transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
                        >
                            <span className="flex items-center gap-2">
                                <Settings2 size={13} className="text-indigo-400" />
                                <span>Host Metadata &amp; Controls</span>
                            </span>
                            <div className="flex items-center gap-2">
                                <span className="text-[11px] font-mono font-semibold text-indigo-300 bg-indigo-500/10 border border-indigo-500/20 px-1.5 py-0.5 rounded">
                                    {timeWindow.toUpperCase()} Window
                                </span>
                                <ChevronDown size={14} className="text-indigo-400 group-open:rotate-180 transition-transform" />
                            </div>
                        </summary>
                        <div className="pt-2.5 pb-1 space-y-2 border-t border-slate-800/60 mt-2">
                            {platformIdentity && (
                                <div className="flex items-center gap-2 text-slate-300 text-xs px-1">
                                    <Server size={13} className="text-indigo-400 shrink-0" />
                                    <span className="font-medium truncate">{platformIdentity}</span>
                                </div>
                            )}
                            {computeIdentity && (
                                <div className="text-[11px] text-slate-400 px-1 truncate">
                                    {computeIdentity}
                                </div>
                            )}
                            <div className="flex flex-wrap items-center gap-2 pt-1">
                                <div
                                    className="flex items-center gap-1 p-1 bg-slate-950/70 border border-slate-800 rounded-xl"
                                    role="group"
                                    aria-label="Telemetry History Window"
                                >
                                    <Clock size={13} className="text-indigo-400 ml-2 mr-1 shrink-0" />
                                    {TIME_WINDOW_OPTIONS.map((timeOption) => (
                                        <button
                                            key={timeOption.id}
                                            type="button"
                                            onClick={() => setTimeWindow(timeOption.id)}
                                            aria-label={`Select ${timeOption.label} history window`}
                                            className={`min-h-[36px] px-2.5 py-1 rounded-lg text-xs font-mono font-semibold transition-all focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none ${
                                                timeWindow === timeOption.id
                                                    ? 'bg-indigo-600/30 border border-indigo-500/50 text-indigo-200 shadow-sm'
                                                    : 'text-slate-400 hover:text-white'
                                            }`}
                                        >
                                            {timeOption.label}
                                        </button>
                                    ))}
                                </div>
                                <button
                                    type="button"
                                    onClick={() => {
                                        setActiveTab('settings');
                                        setActiveSettingsTab('dashboard');
                                    }}
                                    aria-label="Configure Display and Telemetry Preferences"
                                    className="min-h-[36px] flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold bg-slate-950/70 border border-slate-800 text-slate-300 hover:bg-slate-800 hover:text-white transition-all focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none"
                                >
                                    <Settings2 size={13} className="text-indigo-400" />
                                    <span>Configure</span>
                                </button>
                                {serviceEntries.length > 0 && (
                                    <button
                                        type="button"
                                        onClick={() => setActiveTab('services')}
                                        aria-label={`Inspect ${serviceEntries.length} managed ${serviceEntries.length === 1 ? 'service' : 'services'} (${runningServicesCount} running)`}
                                        className={`min-h-[36px] flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold border transition-all focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none ${
                                            failedServices.length > 0
                                                ? 'bg-rose-950/40 border-rose-800/80 text-rose-200 hover:bg-rose-900/50'
                                                : 'bg-slate-950/70 border-slate-800 text-slate-300 hover:bg-slate-800 hover:text-white'
                                        }`}
                                    >
                                        <Cpu size={13} className={failedServices.length > 0 ? 'text-rose-400' : 'text-emerald-400'} />
                                        <span>{runningServicesCount}/{serviceEntries.length} Running</span>
                                    </button>
                                )}
                            </div>
                        </div>
                    </details>
                </div>

                <div className="hidden sm:flex flex-wrap items-center gap-2.5 max-w-full shrink-0">
                    <div
                        className="flex items-center gap-1 p-1 bg-slate-950/70 border border-slate-800 rounded-xl"
                        role="group"
                        aria-label="Telemetry History Window"
                    >
                        <Clock size={13} className="text-indigo-400 ml-2 mr-1 shrink-0" />
                        {TIME_WINDOW_OPTIONS.map((timeOption) => (
                            <button
                                key={timeOption.id}
                                type="button"
                                data-testid={`history-window-${timeOption.id}`}
                                onClick={() => setTimeWindow(timeOption.id)}
                                aria-label={`Select ${timeOption.label} history window`}
                                className={`min-h-[40px] px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none ${
                                    timeWindow === timeOption.id
                                        ? 'bg-indigo-600/30 border border-indigo-500/50 text-indigo-200 shadow-sm'
                                        : 'text-slate-400 hover:text-white'
                                }`}
                            >
                                {timeOption.label}
                            </button>
                        ))}
                    </div>

                    <div className="flex items-center gap-1 p-1 bg-slate-950/70 border border-slate-800 rounded-xl" role="group" aria-label="Dashboard Density Mode">
                        <button
                            type="button"
                            onClick={() => setDashboardDensity('compact')}
                            aria-label="Set standard dashboard density"
                            className={`min-h-[40px] px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none ${
                                dashboardDensity === 'compact'
                                    ? 'bg-indigo-600/30 border border-indigo-500/50 text-indigo-200 shadow-sm'
                                    : 'text-slate-400 hover:text-white'
                            }`}
                        >
                            <Layers size={14} />
                            <span>Standard</span>
                        </button>
                        <button
                            type="button"
                            onClick={() => setDashboardDensity('immersive')}
                            aria-label="Set expanded dashboard density"
                            className={`min-h-[40px] px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none ${
                                dashboardDensity === 'immersive'
                                    ? 'bg-indigo-600/30 border border-indigo-500/50 text-indigo-200 shadow-sm'
                                    : 'text-slate-400 hover:text-white'
                            }`}
                        >
                            <Activity size={14} />
                            <span>Expanded</span>
                        </button>
                    </div>

                    {serviceEntries.length > 0 && (
                        <button
                            type="button"
                            onClick={() => setActiveTab('services')}
                            aria-label={`Inspect ${serviceEntries.length} managed ${serviceEntries.length === 1 ? 'service' : 'services'} (${runningServicesCount} running)`}
                            className={`min-h-[40px] flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-semibold border transition-all focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none ${
                                failedServices.length > 0
                                    ? 'bg-rose-950/40 border-rose-800/80 text-rose-200 hover:bg-rose-900/50'
                                    : 'bg-slate-950/70 border-slate-800 text-slate-300 hover:bg-slate-800 hover:text-white'
                            }`}
                            title={`Inspect ${serviceEntries.length} managed ${serviceEntries.length === 1 ? 'service' : 'services'} (${runningServicesCount} running)`}
                        >
                            <Cpu size={14} className={failedServices.length > 0 ? 'text-rose-400' : 'text-emerald-400'} />
                            <span>{runningServicesCount}/{serviceEntries.length} Running</span>
                        </button>
                    )}

                    <button
                        type="button"
                        onClick={() => {
                            setActiveTab('settings');
                            setActiveSettingsTab('dashboard');
                        }}
                        aria-label="Configure Display and Telemetry Preferences"
                        className="min-h-[40px] flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-slate-950/70 border border-slate-800 text-slate-300 hover:bg-slate-800 hover:text-white transition-all focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none"
                        title="Configure Display & Telemetry Preferences"
                    >
                        <Settings2 size={15} className="text-indigo-400" />
                        <span>Configure</span>
                    </button>
                </div>
            </div>

            {failedServices.length > 0 && (
                <div className="bg-rose-950/35 border border-rose-800/80 rounded-2xl p-3 sm:p-4 text-rose-200 space-y-2.5">
                    <div className="flex items-start gap-2.5 sm:gap-3 min-w-0">
                        <div className="h-8 w-8 rounded-xl bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400 shrink-0 mt-0.5">
                            <AlertTriangle size={16} />
                        </div>
                        <div className="min-w-0 flex-1">
                            <div className="text-xs sm:text-sm text-rose-100 flex flex-wrap items-baseline gap-x-1.5 gap-y-0.5">
                                <span className="font-bold text-rose-200">
                                    {failedServices.length === 1 ? 'Service Exception:' : `Service Exceptions (${failedServices.length}):`}
                                </span>
                                <span className="font-semibold text-rose-100">
                                    {failedServices.map(([serviceName, serviceInfo]) => {
                                        const formattedName = formatServiceName(serviceName);
                                        const exceptionDetail = getServiceExceptionDetail(serviceInfo);
                                        return exceptionDetail && exceptionDetail !== 'Exception reported'
                                            ? `${formattedName} (${exceptionDetail})`
                                            : formattedName;
                                    }).join(', ')}
                                </span>
                            </div>
                            <p className="text-xs text-rose-200/90 font-medium mt-1">
                                Clean stops are not failures.
                            </p>
                        </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 pt-0.5">
                        <button
                            type="button"
                            onClick={() => setActiveTab('services')}
                            aria-label="Open Services tab for exception triage"
                            className="min-h-[44px] px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-bold transition-colors flex items-center justify-center gap-1.5 shrink-0 focus-visible:ring-2 focus-visible:ring-rose-400 focus-visible:outline-none"
                        >
                            <span>Triage in Services</span>
                            <ExternalLink size={13} />
                        </button>
                        <details className="text-xs text-rose-200 group/policy">
                            <summary
                                data-testid="failure-criteria-summary"
                                className="min-h-[44px] cursor-pointer font-semibold hover:text-white select-none inline-flex items-center gap-1.5 px-3 py-2 rounded-xl border border-rose-800/60 bg-rose-900/30 hover:bg-rose-900/50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-400"
                            >
                                <span>Failure criteria</span>
                                <ChevronDown size={14} className="text-rose-300 group-open/policy:rotate-180 transition-transform" />
                            </summary>
                            <div className="pt-2 text-xs text-rose-200/90 font-medium pl-2.5 border-l-2 border-rose-500/40">
                                Clean stopped daemons remain on standby and are not treated as failures.
                            </div>
                        </details>
                    </div>
                </div>
            )}

            {sharedTelemetryInfo.sharedTelemetry && (
                <div
                    data-testid="shared-telemetry-summary"
                    className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 px-1 py-0.5 text-xs text-slate-300"
                >
                    <div className="flex items-center gap-2 font-medium">
                        <span className="h-1.5 w-1.5 rounded-full bg-indigo-400 shrink-0" />
                        <span>{sharedTelemetryInfo.sharedTelemetry.statusMessage}</span>
                    </div>
                    {sharedTelemetryInfo.sharedTelemetry.metadataMessage && (
                        <div className="text-slate-300 font-mono text-xs">
                            {sharedTelemetryInfo.sharedTelemetry.metadataMessage}
                        </div>
                    )}
                </div>
            )}

            <div className={`grid gap-4 items-start ${
                dashboardDensity === 'immersive'
                    ? 'grid-cols-1 2xl:grid-cols-2'
                    : 'grid-cols-1 md:grid-cols-2 2xl:grid-cols-4'
            }`}>
                <MemoCpuWidget
                    cpuData={{ usage: metrics.cpu_usage, freq: metrics.cpu_freq_mhz, cores: metrics.per_core_cpu }}
                    hardware={hardware}
                    history={history}
                    density={dashboardDensity}
                    selectedWindow={timeWindow}
                    hasSharedSummary={sharedTelemetryInfo.isCpuShared}
                />
                <MemoMemoryWidget
                    memoryData={{ memory: metrics.memory, swap: metrics.swap }}
                    hardware={hardware}
                    history={history}
                    density={dashboardDensity}
                    selectedWindow={timeWindow}
                    hasSharedSummary={sharedTelemetryInfo.isMemoryShared}
                />
                <MemoNetworkWidget
                    networkData={{ network: metrics.network, total: metrics.total_net_bytes }}
                    hardware={hardware}
                    history={history}
                    density={dashboardDensity}
                    selectedWindow={timeWindow}
                    hasSharedSummary={sharedTelemetryInfo.isNetworkShared}
                />
                <MemoDiskIOWidget
                    diskIoData={metrics.disk_io}
                    history={history}
                    density={dashboardDensity}
                    selectedWindow={timeWindow}
                    hasSharedSummary={sharedTelemetryInfo.isDiskIoShared}
                />
            </div>

            <div className="rounded-2xl border border-slate-800/80 bg-slate-800/50 backdrop-blur-xl grid grid-cols-2 md:grid-cols-4 gap-px overflow-hidden">
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
                    value={metrics.load_average.map((loadValue) => loadValue.toFixed(2)).join(' · ')}
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
            </div>

            <div className="grid grid-cols-1 2xl:grid-cols-12 gap-4 items-stretch">
                <div className={showDataUsageWidget ? '2xl:col-span-6' : '2xl:col-span-12'}>
                    <MemoAppTopologyMap topologyData={metrics.services} density={dashboardDensity} />
                </div>
                {showDataUsageWidget && (
                    <div className="2xl:col-span-6">
                        <DataUsageHistoryWidget density={dashboardDensity} />
                    </div>
                )}
            </div>

            <div className="grid grid-cols-1 2xl:grid-cols-12 gap-4 items-start">
                <div className={hasGpuPanel ? '2xl:col-span-4' : '2xl:col-span-5'}>
                    <MemoStorageWidget storageData={metrics.disks} hardware={hardware} density={dashboardDensity} />
                </div>
                {hasGpuPanel && (
                    <div className="2xl:col-span-4">
                        <MemoGpuWidget gpus={metrics.gpus || []} density={dashboardDensity} />
                    </div>
                )}
                <div className={hasGpuPanel ? '2xl:col-span-4' : '2xl:col-span-7'}>
                    <MemoProcessWidget processes={metrics.processes || []} density={dashboardDensity} />
                </div>
            </div>

            <div className="pt-2 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
                    <div className="flex items-center gap-2.5">
                        <div className="h-7 w-7 rounded-lg bg-fuchsia-500/10 border border-fuchsia-500/20 flex items-center justify-center text-fuchsia-400">
                            <Sparkles size={14} />
                        </div>
                        <h3 className="text-sm font-bold text-slate-100 tracking-tight">AI Telemetry &amp; Capacity Planning</h3>
                        <span className="text-xs text-slate-400 font-medium hidden sm:inline">
                            · Predictive resource forecasting &amp; peering optimization
                        </span>
                    </div>
                    <span className="text-xs font-mono font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-fuchsia-500/10 text-fuchsia-300 border border-fuchsia-500/20">
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
        <div className="p-3 sm:p-4 flex items-center justify-between gap-2 sm:gap-3 bg-slate-900/90 hover:bg-slate-800/30 transition-colors min-w-0">
            <div className="min-w-0 flex-1">
                <p className="text-[11px] sm:text-xs text-slate-400 uppercase font-semibold tracking-wider truncate">{label}</p>
                <p className="text-sm sm:text-base font-extrabold text-slate-100 truncate mt-0.5 tabular-nums">{value}</p>
                <p className="text-[13px] text-slate-300 truncate mt-0.5 font-medium">{sublabel}</p>
            </div>
            <div className={`hidden sm:flex h-9 w-9 rounded-xl border ${iconBg} ${iconColor} items-center justify-center shrink-0`}>
                {icon}
            </div>
        </div>
    );
}
