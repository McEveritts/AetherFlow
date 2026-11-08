'use client';

import { useState, useEffect, useMemo } from 'react';
import { Activity, Download, Upload, ServerCrash, Calendar } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { fetcher } from '@/lib/fetcher';
import { computeNiceByteScale } from '@/components/widgets/bandwidthScaleHelpers';

interface DailyUsage {
    date: string;
    downloadedBytes: number | null;
    uploadedBytes: number | null;
}

interface MetricsSnapshot {
    timestamp: string;
    net_rx_bytes: number;
    net_tx_bytes: number;
}

interface ParsedMetricsSnapshot {
    timestampMs: number;
    date: string;
    rxBytes: number;
    txBytes: number;
    sourceIndex: number;
}

interface InvalidMetricsTimestamp {
    timestampMs: number;
    sourceIndex: number;
    invalid: true;
}

interface DailyUsageResult {
    usageData: DailyUsage[];
    duplicateSamples: number;
    conflictingSamples: number;
    invalidSamples: number;
    counterResets: number;
}

export function deriveDailyUsage(rawMetrics: unknown): DailyUsageResult {
    const parsedSamples: (ParsedMetricsSnapshot | InvalidMetricsTimestamp)[] = [];
    let invalidSamples = 0;

    (Array.isArray(rawMetrics) ? rawMetrics : []).forEach((rawRecord, sourceIndex) => {
        if (!rawRecord || typeof rawRecord !== 'object') {
            invalidSamples += 1;
            return;
        }

        const record = rawRecord as Partial<MetricsSnapshot>;
        const timestampMs = typeof record.timestamp === 'string' ? Date.parse(record.timestamp) : Number.NaN;
        if (!Number.isFinite(timestampMs)) {
            invalidSamples += 1;
            return;
        }

        const rxBytes = record.net_rx_bytes;
        const txBytes = record.net_tx_bytes;
        if (typeof rxBytes !== 'number' || !Number.isFinite(rxBytes) || rxBytes < 0 ||
            typeof txBytes !== 'number' || !Number.isFinite(txBytes) || txBytes < 0) {
            invalidSamples += 1;
            parsedSamples.push({ timestampMs, sourceIndex, invalid: true });
            return;
        }

        parsedSamples.push({
            timestampMs,
            date: new Date(timestampMs).toISOString().slice(0, 10),
            rxBytes,
            txBytes,
            sourceIndex,
        });
    });

    parsedSamples.sort((firstSample, secondSample) =>
        firstSample.timestampMs - secondSample.timestampMs || firstSample.sourceIndex - secondSample.sourceIndex
    );

    const usageByDate = new Map<string, DailyUsage>();
    let previousSample: ParsedMetricsSnapshot | null = null;
    let duplicateSamples = 0;
    let conflictingSamples = 0;
    let counterResets = 0;

    for (let sampleIndex = 0; sampleIndex < parsedSamples.length;) {
        const timestampMs = parsedSamples[sampleIndex].timestampMs;
        const sameTimestampSamples: (ParsedMetricsSnapshot | InvalidMetricsTimestamp)[] = [];
        while (sampleIndex < parsedSamples.length && parsedSamples[sampleIndex].timestampMs === timestampMs) {
            sameTimestampSamples.push(parsedSamples[sampleIndex]);
            sampleIndex += 1;
        }

        if (sameTimestampSamples.some((sample) => 'invalid' in sample)) {
            previousSample = null;
            continue;
        }

        const validSamples = sameTimestampSamples as ParsedMetricsSnapshot[];
        const firstSample = validSamples[0];
        const hasConflictingCounters = validSamples.some((sample) =>
            sample.rxBytes !== firstSample.rxBytes || sample.txBytes !== firstSample.txBytes
        );
        if (hasConflictingCounters) {
            conflictingSamples += 1;
            previousSample = null;
            continue;
        }

        duplicateSamples += validSamples.length - 1;
        const currentSample = firstSample;
        const dayUsage = usageByDate.get(currentSample.date) || {
            date: currentSample.date,
            downloadedBytes: null,
            uploadedBytes: null,
        };
        usageByDate.set(currentSample.date, dayUsage);

        if (previousSample) {
            const rxReset = currentSample.rxBytes < previousSample.rxBytes;
            const txReset = currentSample.txBytes < previousSample.txBytes;
            if (rxReset) counterResets += 1;
            if (txReset) counterResets += 1;
            const downloadDelta = rxReset ? currentSample.rxBytes : currentSample.rxBytes - previousSample.rxBytes;
            const uploadDelta = txReset ? currentSample.txBytes : currentSample.txBytes - previousSample.txBytes;
            dayUsage.downloadedBytes = (dayUsage.downloadedBytes ?? 0) + downloadDelta;
            dayUsage.uploadedBytes = (dayUsage.uploadedBytes ?? 0) + uploadDelta;
        }

        previousSample = currentSample;
    }

    return {
        usageData: Array.from(usageByDate.values()).sort((firstEntry, secondEntry) => firstEntry.date.localeCompare(secondEntry.date)),
        duplicateSamples,
        conflictingSamples,
        invalidSamples,
        counterResets,
    };
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
    const [counterResetCount, setCounterResetCount] = useState(0);
    const [ignoredSampleCount, setIgnoredSampleCount] = useState(0);

    useEffect(() => {
        let isMounted = true;
        const fetchUsageHistory = async () => {
            setIsLoading(true);
            setErrorMessage(null);
            setUsageData([]);
            setCounterResetCount(0);
            setIgnoredSampleCount(0);
            try {
                const rawMetrics = await fetcher<MetricsSnapshot[]>(`/api/v1/admin/ai/predictions/history?days=${daysWindow}`);
                if (!isMounted) return;
                const usageResult = deriveDailyUsage(rawMetrics);
                setUsageData(usageResult.usageData);
                setCounterResetCount(usageResult.counterResets);
                setIgnoredSampleCount(usageResult.invalidSamples + usageResult.conflictingSamples);
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
                accumulator.totalDownloadedBytes += currentItem.downloadedBytes ?? 0;
                accumulator.totalUploadedBytes += currentItem.uploadedBytes ?? 0;
                return accumulator;
            },
            { totalDownloadedBytes: 0, totalUploadedBytes: 0 }
        );
    }, [usageData]);

    const peakDailyBytes = useMemo(() => {
        let maxFoundBytes = 0;
        for (const dataEntry of usageData) {
            if (dataEntry.downloadedBytes !== null && dataEntry.downloadedBytes > maxFoundBytes) {
                maxFoundBytes = dataEntry.downloadedBytes;
            }
            if (dataEntry.uploadedBytes !== null && dataEntry.uploadedBytes > maxFoundBytes) {
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
    const hasMeasuredInterval = usageData.some((entry) => entry.downloadedBytes !== null || entry.uploadedBytes !== null);
    const isPartialCoverage = recordedDayCount > 0 && recordedDayCount < daysWindow;

    return (
        <div className={`obs-telemetry-surface relative overflow-hidden flex flex-col justify-between h-full ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                <div className="flex flex-wrap items-center justify-between gap-3 pb-3 mb-3.5 border-b border-white/[0.06]">
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
                        <div className="flex bg-white/[0.03] p-1 rounded-xl border border-white/[0.08] backdrop-blur-md" role="group" aria-label="History Range Selection">
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

                <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                    <div className="flex items-center gap-2 text-xs text-slate-300">
                        <Calendar size={13} className="text-indigo-400" />
                        <span className="font-mono text-slate-200">
                            Coverage: {recordedDayCount} of {daysWindow} days observed
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

                <p role="note" className="mb-3 text-xs leading-relaxed text-slate-400">
                    Counter deltas are assigned to the UTC day of the ending sample; sparse intervals may span days, so daily allocation is estimated.
                    {counterResetCount > 0 ? ` ${counterResetCount} counter reset${counterResetCount === 1 ? '' : 's'} detected; only post-reset values are counted.` : ''}
                    {ignoredSampleCount > 0 ? ` ${ignoredSampleCount} invalid or conflicting sample${ignoredSampleCount === 1 ? '' : 's'} ignored.` : ''}
                </p>

                {errorMessage && !isLoading && (
                    <div
                        className="flex flex-col items-center justify-center text-center"
                        style={{ height: chartHeight }}
                    >
                        <ServerCrash className="text-rose-400/70 mb-2" size={28} />
                        <p className="text-xs font-semibold text-slate-300 mb-0.5">Failed to load history payload</p>
                        <p className="text-xs text-slate-400">{errorMessage}</p>
                    </div>
                )}

                {!errorMessage && (
                    <div
                        className="relative select-none w-full min-w-0 overflow-hidden pt-3 pr-2"
                        style={{ height: chartHeight, touchAction: 'pan-y' }}
                    >
                        {isLoading && usageData.length === 0 ? (
                            <div className="absolute inset-0 flex items-center justify-center">
                                <div className="w-5 h-5 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin" />
                            </div>
                        ) : usageData.length === 0 ? (
                            <div role="note" className="absolute inset-0 flex items-center justify-center px-4 text-center text-xs text-slate-400">
                                No bandwidth observations for this window; no zero-valued days are inferred.
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

            <div className="grid grid-cols-2 gap-0 mt-3.5 pt-3 border-t border-white/[0.06] divide-x divide-white/[0.06]">
                <div className="min-w-0 flex flex-wrap items-baseline justify-between gap-x-2 gap-y-1 pr-3 last:pr-0 last:pl-3">
                    <div className="flex items-center gap-2">
                        <Download size={14} className="text-cyan-400 shrink-0" />
                        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Download ({daysWindow}d)</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-cyan-400 tabular-nums">
                        {isLoading ? '...' : hasMeasuredInterval ? formatBytes(totalDownloadedBytes) : 'Unavailable'}
                    </span>
                </div>
                <div className="min-w-0 flex flex-wrap items-baseline justify-between gap-x-2 gap-y-1 pr-3 last:pr-0 last:pl-3">
                    <div className="flex items-center gap-2">
                        <Upload size={14} className="text-indigo-400 shrink-0" />
                        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Upload ({daysWindow}d)</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-indigo-400 tabular-nums">
                        {isLoading ? '...' : hasMeasuredInterval ? formatBytes(totalUploadedBytes) : 'Unavailable'}
                    </span>
                </div>
            </div>
        </div>
    );
}
