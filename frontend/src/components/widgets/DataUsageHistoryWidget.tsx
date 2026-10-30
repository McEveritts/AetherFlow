'use client';

import { useState, useEffect, useMemo } from 'react';
import { Activity, Download, Upload, ServerCrash } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { fetcher } from '@/lib/fetcher';

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

function formatBytes(bytes: number, decimals = 1): string {
    if (!+bytes) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

interface DataUsageHistoryWidgetProps {
    density?: 'compact' | 'immersive';
}

export default function DataUsageHistoryWidget({ density = 'compact' }: DataUsageHistoryWidgetProps) {
    const isImmersive = density === 'immersive';
    const [days, setDays] = useState<number>(30);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [data, setData] = useState<DailyUsage[]>([]);

    useEffect(() => {
        let isMounted = true;
        const fetchData = async () => {
            setLoading(true);
            setError(null);
            try {
                const rawData = await fetcher<MetricsSnapshot[]>(`/api/v1/admin/ai/predictions/history?days=${days}`);
                if (!isMounted) return;

                const dailySamples = new Map<string, { ts: number; rx: number; tx: number }[]>();

                (Array.isArray(rawData) ? rawData : []).forEach(record => {
                    const date = record.timestamp.split(/[ T]/)[0];
                    const ts = new Date(record.timestamp).getTime() || 0;
                    const sample = { ts, rx: record.net_rx_bytes ?? 0, tx: record.net_tx_bytes ?? 0 };
                    const existing = dailySamples.get(date);
                    if (!existing) {
                        dailySamples.set(date, [sample]);
                    } else {
                        existing.push(sample);
                    }
                });

                const chartData: DailyUsage[] = Array.from(dailySamples.entries()).map(([date, samples]) => {
                    samples.sort((a, b) => a.ts - b.ts);
                    let dlDelta = 0;
                    let ulDelta = 0;
                    for (let i = 1; i < samples.length; i++) {
                        const prev = samples[i - 1];
                        const curr = samples[i];
                        dlDelta += curr.rx >= prev.rx ? curr.rx - prev.rx : curr.rx;
                        ulDelta += curr.tx >= prev.tx ? curr.tx - prev.tx : curr.tx;
                    }
                    return {
                        date,
                        downloadedBytes: dlDelta,
                        uploadedBytes: ulDelta,
                    };
                }).sort((a, b) => a.date.localeCompare(b.date));

                if (chartData.length === 1) {
                    const firstDate = new Date(`${chartData[0].date}T00:00:00`);
                    if (!isNaN(firstDate.getTime())) {
                        firstDate.setDate(firstDate.getDate() - 1);
                        const yyyy = firstDate.getFullYear();
                        const mm = String(firstDate.getMonth() + 1).padStart(2, '0');
                        const dd = String(firstDate.getDate()).padStart(2, '0');
                        chartData.unshift({
                            date: `${yyyy}-${mm}-${dd}`,
                            downloadedBytes: 0,
                            uploadedBytes: 0,
                        });
                    } else {
                        chartData.unshift({
                            date: 'Prior',
                            downloadedBytes: 0,
                            uploadedBytes: 0,
                        });
                    }
                } else if (chartData.length === 0) {
                    const today = new Date();
                    const yesterday = new Date(today);
                    yesterday.setDate(today.getDate() - 1);
                    const fmt = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
                    chartData.push(
                        { date: fmt(yesterday), downloadedBytes: 0, uploadedBytes: 0 },
                        { date: fmt(today), downloadedBytes: 0, uploadedBytes: 0 }
                    );
                }

                setData(chartData);
            } catch (err: unknown) {
                if (isMounted) setError(err instanceof Error ? err.message : 'Failed to load usage history');
            } finally {
                if (isMounted) setLoading(false);
            }
        };

        fetchData();
        return () => { isMounted = false; };
    }, [days]);

    const { totalDL, totalUL } = useMemo(() => {
        return data.reduce(
            (acc, curr) => {
                acc.totalDL += curr.downloadedBytes;
                acc.totalUL += curr.uploadedBytes;
                return acc;
            },
            { totalDL: 0, totalUL: 0 }
        );
    }, [data]);

    const chartHeight = isImmersive ? 360 : 260;

    return (
        <div className={`rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl relative overflow-hidden flex flex-col justify-between h-full ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                {/* Header & Controls */}
                <div className="flex flex-wrap items-center justify-between gap-2 pb-3 mb-3.5 border-b border-white/[0.06]">
                    <div className="flex items-center gap-2.5">
                        <div className="h-8 w-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 shrink-0">
                            <Activity size={16} />
                        </div>
                        <div>
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">Historical Data Usage</h2>
                            <p className="text-[11px] text-slate-500 mt-1">
                                Cumulative ingress &amp; egress bandwidth ledger
                            </p>
                        </div>
                    </div>
                    <div className="flex bg-black/40 p-1 rounded-xl border border-white/[0.06]">
                        {[7, 30, 90].map((d) => (
                            <button
                                key={d}
                                type="button"
                                onClick={() => setDays(d)}
                                className={`obs-touch-target-standard obs-gpu-120hz-interactive px-2.5 py-1 text-[11px] font-semibold rounded-lg transition-all ${
                                    days === d
                                        ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 shadow-sm'
                                        : 'text-slate-400 hover:text-slate-200'
                                }`}
                            >
                                {d}d
                            </button>
                        ))}
                    </div>
                </div>

                {/* Error State */}
                {error && !loading && (
                    <div
                        className="flex flex-col items-center justify-center bg-black/30 rounded-xl border border-white/[0.04] text-center"
                        style={{ height: chartHeight }}
                    >
                        <ServerCrash className="text-rose-400/50 mb-2" size={28} />
                        <p className="text-xs font-semibold text-slate-300 mb-0.5">Failed to load payload</p>
                        <p className="text-[11px] text-slate-500">{error}</p>
                    </div>
                )}

                {/* Chart Surface */}
                {!error && (
                    <div
                        className="relative select-none w-full bg-black/30 rounded-xl border border-white/[0.04] overflow-hidden pt-3 pr-2"
                        style={{ height: chartHeight, touchAction: 'pan-y' }}
                    >
                        {loading && data.length === 0 ? (
                            <div className="absolute inset-0 flex items-center justify-center">
                                <div className="w-5 h-5 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin" />
                            </div>
                        ) : (
                            <ResponsiveContainer width="100%" height={chartHeight - 16}>
                                <AreaChart data={data} margin={{ top: 6, right: 8, left: 0, bottom: 0 }}>
                                    <defs>
                                        <linearGradient id="colorDl" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#818cf8" stopOpacity={0.35} />
                                            <stop offset="95%" stopColor="#818cf8" stopOpacity={0.02} />
                                        </linearGradient>
                                        <linearGradient id="colorUl" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#2dd4bf" stopOpacity={0.35} />
                                            <stop offset="95%" stopColor="#2dd4bf" stopOpacity={0.02} />
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                                    <XAxis
                                        dataKey="date"
                                        stroke="rgba(255,255,255,0.15)"
                                        tick={{ fill: 'rgba(255,255,255,0.45)', fontSize: 10 }}
                                        tickFormatter={(val) => {
                                            const parts = String(val).split('-');
                                            return parts.length === 3 ? `${parts[1]}/${parts[2]}` : String(val);
                                        }}
                                        minTickGap={20}
                                    />
                                    <YAxis
                                        stroke="rgba(255,255,255,0.15)"
                                        tick={{ fill: 'rgba(255,255,255,0.45)', fontSize: 10 }}
                                        tickFormatter={(val) => formatBytes(val, 0)}
                                        width={54}
                                    />
                                    <Tooltip
                                        contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.94)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', backdropFilter: 'blur(16px)' }}
                                        itemStyle={{ color: '#f8fafc', fontSize: '12px', fontWeight: 'bold' }}
                                        labelStyle={{ color: '#94a3b8', fontSize: '11px', marginBottom: '4px' }}
                                        formatter={(value) => [formatBytes(Number(value || 0)), '']}
                                        animationDuration={120}
                                    />
                                    <Area type="monotone" name="Downloaded" dataKey="downloadedBytes" stroke="#818cf8" strokeWidth={2} fillOpacity={1} fill="url(#colorDl)" dot={{ r: 3, fill: '#818cf8', fillOpacity: 0.9 }} activeDot={{ r: 5 }} animationDuration={180} />
                                    <Area type="monotone" name="Uploaded" dataKey="uploadedBytes" stroke="#2dd4bf" strokeWidth={2} fillOpacity={1} fill="url(#colorUl)" dot={{ r: 3, fill: '#2dd4bf', fillOpacity: 0.9 }} activeDot={{ r: 5 }} animationDuration={180} />
                                </AreaChart>
                            </ResponsiveContainer>
                        )}
                    </div>
                )}
            </div>

            {/* Summary Footer */}
            <div className="grid grid-cols-2 gap-2.5 mt-3.5">
                <div className="bg-black/30 rounded-xl px-3.5 py-2.5 border border-white/[0.04] flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <Download size={13} className="text-indigo-400 shrink-0" />
                        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">DL ({days}d)</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-indigo-300 tabular-nums">
                        {loading && data.length === 0 ? '...' : formatBytes(totalDL)}
                    </span>
                </div>
                <div className="bg-black/30 rounded-xl px-3.5 py-2.5 border border-white/[0.04] flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <Upload size={13} className="text-teal-400 shrink-0" />
                        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">UL ({days}d)</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-teal-300 tabular-nums">
                        {loading && data.length === 0 ? '...' : formatBytes(totalUL)}
                    </span>
                </div>
            </div>
        </div>
    );
}
