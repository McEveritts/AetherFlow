import { Network } from 'lucide-react';
import { SystemMetrics, HardwareReport, MetricsHistory } from '@/types/dashboard';
import Sparkline from '@/components/charts/Sparkline';

interface NetworkWidgetProps {
    networkData: { network: SystemMetrics['network']; total: SystemMetrics['total_net_bytes'] };
    hardware: HardwareReport | null;
    history: MetricsHistory;
    density?: 'compact' | 'immersive';
    selectedWindow?: string;
    hasSharedSummary?: boolean;
}

function formatTotalBytes(bytesCount: number): string {
    if (!bytesCount) return '0 B';
    const unitsList = ['B', 'KB', 'MB', 'GB', 'TB'];
    let unitIndex = 0;
    let scaledValue = bytesCount;
    while (scaledValue >= 1024 && unitIndex < unitsList.length - 1) {
        scaledValue /= 1024;
        unitIndex++;
    }
    return `${scaledValue.toFixed(unitIndex > 1 ? 1 : 0)} ${unitsList[unitIndex]}`;
}

function formatRateString(rateValue?: string): string {
    if (!rateValue) return '0.0 B/s';
    const trimmed = rateValue.trim();
    const match = trimmed.match(/^([\d.]+)\s*([A-Za-z/]+)$/);
    if (!match) return trimmed;
    const numericPart = parseFloat(match[1]);
    const unitPart = match[2];
    if (Number.isFinite(numericPart)) {
        return `${numericPart.toFixed(1)} ${unitPart}`;
    }
    return trimmed;
}

export default function NetworkWidget({ networkData, history, density = 'compact', selectedWindow, hasSharedSummary }: NetworkWidgetProps) {
    const isImmersive = density === 'immersive';
    const activeConnections = networkData.network.active_connections || 0;

    return (
        <div className={`obs-telemetry-surface obs-vital-card relative overflow-hidden flex flex-col ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                <div className="obs-vital-header">
                    <div className="flex items-center gap-2.5 min-w-0">
                        <div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 shrink-0">
                            <Network size={16} />
                        </div>
                        <div className="min-w-0">
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none flex items-center gap-2">
                                Network Traffic
                                <span className="relative flex h-1.5 w-1.5 shrink-0">
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                                    <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-cyan-500" />
                                </span>
                            </h2>
                            <p className="text-xs text-slate-400 mt-1">
                                {activeConnections} active connection{activeConnections === 1 ? '' : 's'}
                            </p>
                        </div>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                        <div className="min-w-0 flex flex-col gap-0.5">
                            <span className="text-xs font-medium text-cyan-400">Download</span>
                            <span className="text-base font-bold tracking-tight text-white tabular-nums break-words">
                                {formatRateString(networkData.network.down as string)}
                            </span>
                        </div>
                        <div className="min-w-0 flex flex-col gap-0.5">
                            <span className="text-xs font-medium text-indigo-400">Upload</span>
                            <span className="text-base font-bold tracking-tight text-white tabular-nums break-words">
                                {formatRateString(networkData.network.up as string)}
                            </span>
                        </div>
                    </div>
                </div>

                <div className="obs-vital-plot">
                    <Sparkline
                        data={history.netDown.length > 0 ? history.netDown : []}
                        data2={history.netUp.length > 0 ? history.netUp : []}
                        color="#06b6d4"
                        color2="#6366f1"
                        gradientFrom="#06b6d4"
                        gradientFrom2="#6366f1"
                        height={isImmersive ? 120 : 88}
                        showArea={true}
                        showMagnitudeReferences={true}
                        unit="B/s"
                        timestamps={history.timestamps}
                        selectedWindow={selectedWindow}
                        label="Download"
                        label2="Upload"
                        currentValue={formatRateString(networkData.network.down as string)}
                        currentValue2={formatRateString(networkData.network.up as string)}
                        hasSharedSummary={hasSharedSummary}
                    />
                </div>
            </div>

            <div className="obs-vital-footer">
                <div className="grid w-full grid-cols-2 divide-x divide-white/[0.06]">
                    <div className="min-w-0 flex flex-col gap-0.5 pr-3">
                        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total RX</span>
                        <span className="text-xs font-mono font-bold text-cyan-400 tabular-nums">
                            {formatTotalBytes(networkData.total?.rx || 0)}
                        </span>
                    </div>
                    <div className="min-w-0 flex flex-col gap-0.5 pl-3">
                        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total TX</span>
                        <span className="text-xs font-mono font-bold text-indigo-400 tabular-nums">
                            {formatTotalBytes(networkData.total?.tx || 0)}
                        </span>
                    </div>
                </div>
            </div>
        </div>
    );
}
