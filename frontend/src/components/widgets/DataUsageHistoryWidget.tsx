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

// Helper to format bytes cleanly (B, KB, MB, GB, TB)
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
    const [days, setDays] = useState<number>(30); // Default to 30 as user requested
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [data, setData] = useState<DailyUsage[]>([]);

    useEffect(() => {
        let isMounted = true;
        const fetchData = async () => {
            setLoading(true);
            setError(null);
            try {
                // Fetch the last X days of samples (sampled every 15m)
                const rawData = await fetcher<MetricsSnapshot[]>(`/api/v1/admin/ai/predictions/history?days=${days}`);
                if (!isMounted) return;
                
                // Group by Day (YYYY-MM-DD)
                const dailyGroups = new Map<string, { minRx: number; maxRx: number; minTx: number; maxTx: number }>();

                rawData.forEach(record => {
                    const date = record.timestamp.split(/[ T]/)[0];
                    if (!dailyGroups.has(date)) {
                        dailyGroups.set(date, { 
                            minRx: record.net_rx_bytes, maxRx: record.net_rx_bytes,
                            minTx: record.net_tx_bytes, maxTx: record.net_tx_bytes
                        });
                    } else {
                        const group = dailyGroups.get(date)!;
                        // Handle potential restarts (counters reset to 0) roughly. 
                        // If a recording is lower than max, we might have restarted, 
                        // but simple min/max usually captures the day's span well enough unless multi-restarts occur.
                        // To be perfectly accurate across restarts we'd need sequential diffs, but min/max is standard for net IO.
                        group.minRx = Math.min(group.minRx, record.net_rx_bytes);
                        group.maxRx = Math.max(group.maxRx, record.net_rx_bytes);
                        group.minTx = Math.min(group.minTx, record.net_tx_bytes);
                        group.maxTx = Math.max(group.maxTx, record.net_tx_bytes);
                    }
                });

                const chartData: DailyUsage[] = Array.from(dailyGroups.entries()).map(([date, group]) => ({
                    date,
                    downloadedBytes: group.maxRx - group.minRx,
                    uploadedBytes: group.maxTx - group.minTx,
                })).sort((a, b) => a.date.localeCompare(b.date)); // Sort chronologically

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

    // Calculate totals for the summary UI
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

    return (
        <div className={`bg-white/[0.02] border border-white/[0.05] rounded-2xl relative overflow-hidden group transition-all duration-300 hover:bg-white/[0.04] backdrop-blur-xl flex flex-col h-full ${isImmersive ? 'p-6 py-7' : 'p-5'}`}>
            {/* Header & Controls */}
            <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${isImmersive ? 'mb-8' : 'mb-6'}`}>
                <h2 className={`${isImmersive ? 'text-lg' : 'text-sm'} font-semibold text-slate-200 flex items-center gap-2`}>
                    <Activity size={isImmersive ? 18 : 16} className="text-indigo-400" /> Historical Data Usage
                </h2>
                <div className="flex bg-slate-900/50 p-1 rounded-lg border border-white/[0.05] self-start sm:self-auto">
                    {[7, 30, 90].map((d) => (
                        <button
                            key={d}
                            onClick={() => setDays(d)}
                            className={`px-3 py-1 text-xs font-medium rounded-md transition-all ${
                                days === d
                                    ? 'bg-indigo-500/20 text-indigo-300 shadow-sm'
                                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/[0.02]'
                            }`}
                        >
                            {d} Days
                        </button>
                    ))}
                </div>
            </div>

            {/* Error State */}
            {error && !loading && (
                <div className="flex flex-col items-center justify-center flex-1 py-10 text-center">
                    <ServerCrash className="text-red-400/50 mb-3" size={32} />
                    <p className="text-sm font-medium text-slate-300 mb-1">Failed to load payload</p>
                    <p className="text-xs text-slate-500">{error}</p>
                </div>
            )}

            {/* Loading / Data State */}
            {!error && (
                <div className={`flex-1 flex flex-col ${isImmersive ? 'min-h-[350px]' : 'min-h-[220px]'}`}>
                    {/* The Chart */}
                    <div className={`flex-1 relative -mx-2 ${isImmersive ? 'min-h-[280px]' : 'min-h-[160px]'}`}>
                        {loading && data.length === 0 ? (
                             <div className="absolute inset-0 flex items-center justify-center">
                                 <div className="w-5 h-5 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin" />
                             </div>
                        ) : (
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                                    <defs>
                                        <linearGradient id="colorDl" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#818cf8" stopOpacity={0.3} />
                                            <stop offset="95%" stopColor="#818cf8" stopOpacity={0} />
                                        </linearGradient>
                                        <linearGradient id="colorUl" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#2dd4bf" stopOpacity={0.3} />
                                            <stop offset="95%" stopColor="#2dd4bf" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                                    <XAxis 
                                        dataKey="date" 
                                        stroke="rgba(255,255,255,0.2)" 
                                        tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10 }}
                                        tickFormatter={(val) => {
                                            const parts = val.split('-');
                                            return `${parts[1]}/${parts[2]}`;
                                        }}
                                        minTickGap={20}
                                    />
                                    <YAxis 
                                        stroke="rgba(255,255,255,0.2)" 
                                        tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10 }}
                                        tickFormatter={(val) => formatBytes(val, 0)}
                                        width={55}
                                    />
                                    <Tooltip
                                        contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.9)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', backdropFilter: 'blur(16px)' }}
                                        itemStyle={{ color: '#f8fafc', fontSize: '12px', fontWeight: 'bold' }}
                                        labelStyle={{ color: '#94a3b8', fontSize: '11px', marginBottom: '4px' }}
                                    formatter={(value: number) => [formatBytes(Number(value)), '']}
                                    />
                                    <Area type="monotone" name="Downloaded" dataKey="downloadedBytes" stroke="#818cf8" strokeWidth={2} fillOpacity={1} fill="url(#colorDl)" />
                                    <Area type="monotone" name="Uploaded" dataKey="uploadedBytes" stroke="#2dd4bf" strokeWidth={2} fillOpacity={1} fill="url(#colorUl)" />
                                </AreaChart>
                            </ResponsiveContainer>
                        )}
                    </div>

                    {/* Summary Footer */}
                    <div className="grid grid-cols-2 gap-3 mt-4 pt-4 border-t border-white/[0.05]">
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-full bg-indigo-500/10 flex items-center justify-center">
                                <Download size={14} className="text-indigo-400" />
                            </div>
                            <div>
                                <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block">DL ({days}d)</span>
                                <span className="text-sm font-bold text-slate-200">
                                    {loading && data.length === 0 ? '...' : formatBytes(totalDL)}
                                </span>
                            </div>
                        </div>
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-full bg-teal-500/10 flex items-center justify-center">
                                <Upload size={14} className="text-teal-400" />
                            </div>
                            <div>
                                <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block">UL ({days}d)</span>
                                <span className="text-sm font-bold text-slate-200">
                                    {loading && data.length === 0 ? '...' : formatBytes(totalUL)}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
