'use client';

import { useState, useEffect, useMemo } from 'react';
import { Activity, Download, Upload, ServerCrash, Calendar } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { fetcher } from '@/lib/fetcher';
import { computeNiceByteScale } from '@/components/widgets/bandwidthScaleHelpers';

interface DailyUsage {
    date: string;
    downloadedBytes: number;
    uploadedBytes: number;
}

interface MetricsSnapshot {
    timestamp: string;
    net_rx_bytes: number;
    net_tx_bytes: number;
}

function formatBytes(bytesCount: number, decimalPlaces = 1): string {
    if (!+bytesCount) return '0 B';
    const divisor = 1024;
    const precision = decimalPlaces < 0 ? 0 : decimalPlaces;
    const byteUnits = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const unitIndex = Math.floor(Math.log(bytesCount) / Math.log(divisor));
    return `${parseFloat((bytesCount / Math.pow(divisor, unitIndex)).toFixed(precision))} ${byteUnits[unitIndex]}`;
}

interface DataUsageHistoryWidgetProps {
    density?: 'compact' | 'immersive';
}

export default function DataUsageHistoryWidget({ density = 'compact' }: DataUsageHistoryWidgetProps) {
    const isImmersive = density === 'immersive';
    const [daysWindow, setDaysWindow] = useState<number>(30);
    const [isLoading, setIsLoading] = useState(true);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [usageData, setUsageData] = useState<DailyUsage[]>([]);

    useEffect(() => {
        let isMounted = true;
        const fetchUsageHistory = async () => {
            setIsLoading(true);
            setErrorMessage(null);
            try {
                const rawMetrics = await fetcher<MetricsSnapshot[]>(`/api/v1/admin/ai/predictions/history?days=${daysWindow}`);
                if (!isMounted) return;

                const dailySamplesMap = new Map<string, { timestampMs: number; rxBytes: number; txBytes: number }[]>();

                (Array.isArray(rawMetrics) ? rawMetrics : []).forEach(record => {
                    const dateKey = record.timestamp.split(/[ T]/)[0];
                    const timestampMs = new Date(record.timestamp).getTime() || 0;
                    const sample = { timestampMs, rxBytes: record.net_rx_bytes ?? 0, txBytes: record.net_tx_bytes ?? 0 };
                    const existingSamples = dailySamplesMap.get(dateKey);
                    if (!existingSamples) {
                        dailySamplesMap.set(dateKey, [sample]);
                    } else {
                        existingSamples.push(sample);
                    }
                });

                const parsedChartData: DailyUsage[] = Array.from(dailySamplesMap.entries()).map(([entryDate, samplesList]) => {
                    samplesList.sort((firstSample, secondSample) => firstSample.timestampMs - secondSample.timestampMs);
                    let downloadDelta = 0;
                    let uploadDelta = 0;
                    for (let sampleIndex = 1; sampleIndex < samplesList.length; sampleIndex++) {
                        const previousSample = samplesList[sampleIndex - 1];
                        const currentSample = samplesList[sampleIndex];
                        downloadDelta += currentSample.rxBytes >= previousSample.rxBytes
                            ? currentSample.rxBytes - previousSample.rxBytes
                            : currentSample.rxBytes;
                        uploadDelta += currentSample.txBytes >= previousSample.txBytes
                            ? currentSample.txBytes - previousSample.txBytes
                            : currentSample.txBytes;
                    }
                    return {
                        date: entryDate,
                        downloadedBytes: downloadDelta,
                        uploadedBytes: uploadDelta,
                    };
                }).sort((firstEntry, secondEntry) => firstEntry.date.localeCompare(secondEntry.date));

                if (parsedChartData.length === 1) {
                    const initialDate = new Date(`${parsedChartData[0].date}T00:00:00`);
                    if (!isNaN(initialDate.getTime())) {
                        initialDate.setDate(initialDate.getDate() - 1);
                        const yearString = initialDate.getFullYear();
                        const monthString = String(initialDate.getMonth() + 1).padStart(2, '0');
                        const dayString = String(initialDate.getDate()).padStart(2, '0');
                        parsedChartData.unshift({
                            date: `${yearString}-${monthString}-${dayString}`,
                            downloadedBytes: 0,
                            uploadedBytes: 0,
                        });
                    } else {
                        parsedChartData.unshift({
                            date: 'Prior',
                            downloadedBytes: 0,
                            uploadedBytes: 0,
                        });
                    }
                } else if (parsedChartData.length === 0) {
                    const todayDate = new Date();
                    const yesterdayDate = new Date(todayDate);
                    yesterdayDate.setDate(todayDate.getDate() - 1);
                    const formatDateString = (targetDate: Date) =>
                        `${targetDate.getFullYear()}-${String(targetDate.getMonth() + 1).padStart(2, '0')}-${String(targetDate.getDate()).padStart(2, '0')}`;
                    parsedChartData.push(
                        { date: formatDateString(yesterdayDate), downloadedBytes: 0, uploadedBytes: 0 },
                        { date: formatDateString(todayDate), downloadedBytes: 0, uploadedBytes: 0 }
                    );
                }

                setUsageData(parsedChartData);
            } catch (error: unknown) {
                if (isMounted) setErrorMessage(error instanceof Error ? error.message : 'Failed to load usage history');
            } finally {
                if (isMounted) setIsLoading(false);
            }
        };

        fetchUsageHistory();
        return () => { isMounted = false; };
    }, [daysWindow]);

    const { totalDownloadedBytes, totalUploadedBytes } = useMemo(() => {
        return usageData.reduce(
            (accumulator, currentItem) => {
                accumulator.totalDownloadedBytes += currentItem.downloadedBytes;
                accumulator.totalUploadedBytes += currentItem.uploadedBytes;
                return accumulator;
            },
            { totalDownloadedBytes: 0, totalUploadedBytes: 0 }
        );
    }, [usageData]);

    const peakDailyBytes = useMemo(() => {
        let maxFoundBytes = 0;
        for (const dataEntry of usageData) {
            if (dataEntry.downloadedBytes > maxFoundBytes) {
                maxFoundBytes = dataEntry.downloadedBytes;
            }
            if (dataEntry.uploadedBytes > maxFoundBytes) {
                maxFoundBytes = dataEntry.uploadedBytes;
            }
        }
        return maxFoundBytes;
    }, [usageData]);

    const yAxisScale = useMemo(() => {
        return computeNiceByteScale(peakDailyBytes);
    }, [peakDailyBytes]);

    const chartHeight = isImmersive ? 360 : 260;
    const recordedDayCount = usageData.length;
    const isPartialCoverage = recordedDayCount > 0 && recordedDayCount < daysWindow;

    return (
        <div className={`rounded-2xl border border-slate-800/80 bg-slate-900/85 backdrop-blur-xl relative overflow-hidden flex flex-col justify-between h-full ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                <div className="flex flex-wrap items-center justify-between gap-3 pb-3 mb-3.5 border-b border-slate-800/80">
                    <div className="flex items-center gap-2.5">
                        <div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 shrink-0">
                            <Activity size={16} />
                        </div>
                        <div>
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">Daily Bandwidth Transfer</h2>
                            <p className="text-xs text-slate-400 mt-1">
                                Truthful daily network ingress and egress volume
                            </p>
                        </div>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="flex bg-slate-950/70 p-1 rounded-xl border border-slate-800" role="group" aria-label="History Range Selection">
                            {[7, 30, 90].map((dayOption) => (
                                <button
                                    key={dayOption}
                                    type="button"
                                    onClick={() => setDaysWindow(dayOption)}
                                    aria-label={`View ${dayOption} days telemetry`}
                                    className={`min-h-[40px] px-3.5 py-2 text-xs font-semibold rounded-lg transition-all focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none ${
                                        daysWindow === dayOption
                                            ? 'bg-indigo-600/30 text-indigo-200 border border-indigo-500/50 shadow-sm'
                                            : 'text-slate-400 hover:text-slate-200'
                                    }`}
                                >
                                    {dayOption}d
                                </button>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 mb-3 px-1">
                    <div className="flex items-center gap-2 text-xs text-slate-300">
                        <Calendar size={13} className="text-indigo-400" />
                        <span className="font-mono text-slate-200">
                            Coverage: {recordedDayCount} of {daysWindow} days available
                        </span>
                        {isPartialCoverage && (
                            <span className="text-slate-300 hidden sm:inline">
                                · Sparse telemetry captured in window
                            </span>
                        )}
                    </div>
                    <div className="flex items-center gap-4 text-xs font-semibold">
                        <span className="inline-flex items-center gap-1.5 text-cyan-300">
                            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" /> Download
                        </span>
                        <span className="inline-flex items-center gap-1.5 text-indigo-300">
                            <span className="w-2.5 h-2.5 rounded-full bg-indigo-500" /> Upload
                        </span>
                    </div>
                </div>

                {errorMessage && !isLoading && (
                    <div
                        className="flex flex-col items-center justify-center bg-slate-950/60 rounded-xl border border-slate-800/80 text-center"
                        style={{ height: chartHeight }}
                    >
                        <ServerCrash className="text-rose-400/70 mb-2" size={28} />
                        <p className="text-xs font-semibold text-slate-300 mb-0.5">Failed to load history payload</p>
                        <p className="text-xs text-slate-400">{errorMessage}</p>
                    </div>
                )}

                {!errorMessage && (
                    <div
                        className="relative select-none w-full bg-slate-950/60 rounded-xl border border-slate-800/60 overflow-hidden pt-3 pr-2"
                        style={{ height: chartHeight, touchAction: 'pan-y' }}
                    >
                        {isLoading && usageData.length === 0 ? (
                            <div className="absolute inset-0 flex items-center justify-center">
                                <div className="w-5 h-5 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin" />
                            </div>
                        ) : (
                            <ResponsiveContainer width="100%" height={chartHeight - 16}>
                                <AreaChart data={usageData} margin={{ top: 6, right: 12, left: 0, bottom: 4 }}>
                                    <defs>
                                        <linearGradient id="colorDownloadLinear" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.35} />
                                            <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.02} />
                                        </linearGradient>
                                        <linearGradient id="colorUploadLinear" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#6366f1" stopOpacity={0.35} />
                                            <stop offset="95%" stopColor="#6366f1" stopOpacity={0.02} />
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                                    <XAxis
                                        dataKey="date"
                                        stroke="#475569"
                                        tick={{ fill: '#cbd5e1', fontSize: 12 }}
                                        tickFormatter={(entryDateString) => {
                                            const dateParts = String(entryDateString).split('-');
                                            return dateParts.length === 3 ? `${dateParts[1]}/${dateParts[2]}` : String(entryDateString);
                                        }}
                                        minTickGap={20}
                                    />
                                    <YAxis
                                        domain={yAxisScale.domain}
                                        ticks={yAxisScale.ticks}
                                        stroke="#475569"
                                        tick={{ fill: '#cbd5e1', fontSize: 12 }}
                                        tickFormatter={yAxisScale.formatTick}
                                        width={64}
                                    />
                                    <Tooltip
                                        contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.96)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '12px', backdropFilter: 'blur(16px)' }}
                                        itemStyle={{ fontSize: '12px', fontWeight: 'bold' }}
                                        labelStyle={{ color: '#cbd5e1', fontSize: '12px', marginBottom: '4px' }}
                                        formatter={(numericalValue, dataKeyName) => [
                                            formatBytes(Number(numericalValue || 0)),
                                            dataKeyName === 'downloadedBytes' ? 'Daily Download' : 'Daily Upload'
                                        ]}
                                        animationDuration={120}
                                    />
                                    <Area
                                        type="linear"
                                        name="downloadedBytes"
                                        dataKey="downloadedBytes"
                                        stroke="#06b6d4"
                                        strokeWidth={2}
                                        fillOpacity={1}
                                        fill="url(#colorDownloadLinear)"
                                        dot={{ r: 3, fill: '#06b6d4', fillOpacity: 0.9 }}
                                        activeDot={{ r: 5 }}
                                        animationDuration={180}
                                    />
                                    <Area
                                        type="linear"
                                        name="uploadedBytes"
                                        dataKey="uploadedBytes"
                                        stroke="#6366f1"
                                        strokeWidth={2}
                                        fillOpacity={1}
                                        fill="url(#colorUploadLinear)"
                                        dot={{ r: 3, fill: '#6366f1', fillOpacity: 0.9 }}
                                        activeDot={{ r: 5 }}
                                        animationDuration={180}
                                    />
                                </AreaChart>
                            </ResponsiveContainer>
                        )}
                    </div>
                )}
            </div>

            <div className="grid grid-cols-2 gap-2.5 mt-3.5">
                <div className="bg-slate-950/60 rounded-xl px-3.5 py-2.5 border border-slate-800/60 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <Download size={14} className="text-cyan-400 shrink-0" />
                        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Download ({daysWindow}d)</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-cyan-400 tabular-nums">
                        {isLoading && usageData.length === 0 ? '...' : formatBytes(totalDownloadedBytes)}
                    </span>
                </div>
                <div className="bg-slate-950/60 rounded-xl px-3.5 py-2.5 border border-slate-800/60 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <Upload size={14} className="text-indigo-400 shrink-0" />
                        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Upload ({daysWindow}d)</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-indigo-400 tabular-nums">
                        {isLoading && usageData.length === 0 ? '...' : formatBytes(totalUploadedBytes)}
                    </span>
                </div>
            </div>
        </div>
    );
}
