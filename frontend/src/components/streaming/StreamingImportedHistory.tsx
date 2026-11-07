'use client';

import React from 'react';
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

export interface StreamingHistoryEstimate {
    provenance: 'item_summary' | 'legacy_unverified';
    records: number;
    reportedWatchTimeSecs: number;
    undatedRecords: number;
    timeSeries: { date: string; watchTimeSecs: number }[];
}

const sources = [
    { provenance: 'item_summary', label: 'Imported item estimates', color: '#38bdf8' },
    { provenance: 'legacy_unverified', label: 'Preserved legacy estimates', color: '#fbbf24' },
] as const;

export function importedWatchChartData(estimates: StreamingHistoryEstimate[]) {
    const byDate = new Map<string, Record<string, string | number>>();
    for (const estimate of estimates) {
        for (const point of estimate.timeSeries) {
            const record = byDate.get(point.date) ?? { date: point.date };
            record[estimate.provenance] = Math.round(point.watchTimeSecs / 36) / 100;
            byDate.set(point.date, record);
        }
    }
    return [...byDate.values()].sort((left, right) => String(left.date).localeCompare(String(right.date)));
}

export default function StreamingImportedHistory({ estimates, windowDays }: {
    estimates: StreamingHistoryEstimate[];
    windowDays: number;
}) {
    if (!estimates.length) return null;
    const chartData = importedWatchChartData(estimates);
    return (
        <section aria-label="Imported watch history" className="min-w-0 max-w-full rounded-2xl border border-white/[0.08] bg-slate-900/40 p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                    <div className="flex items-center gap-2">
                        <h3 className="text-sm font-semibold text-slate-100">
                            Imported Watch History ({windowDays === 0 ? 'All Time' : `${windowDays}d`})
                        </h3>
                        <span className="text-xs font-semibold px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 uppercase tracking-wide">
                            ESTIMATED
                        </span>
                    </div>
                    <p role="note" className="text-xs text-slate-400 mt-1 leading-relaxed">
                        Your imported history is preserved. These stored watch-time estimates are not measured sessions.
                        Item estimates use last-played dates and may reflect item runtimes, not elapsed viewing.
                        Legacy and item imports may overlap: these series are separate, not added together or to confirmed watch time.
                    </p>
                </div>
            </div>

            <details className="group rounded-xl border border-white/[0.06] bg-slate-950/40 px-3.5 py-2.5 text-xs text-slate-300">
                <summary className="cursor-pointer font-medium text-slate-300 hover:text-white flex items-center justify-between select-none">
                    <span>Import methodology, overlap & nonadditivity details</span>
                    <span className="text-xs text-slate-400 group-open:rotate-180 transition-transform">&#9662;</span>
                </summary>
                <div className="mt-2.5 pt-2.5 border-t border-white/[0.06] text-slate-400 text-xs space-y-1.5 leading-relaxed">
                    <p>Historical imports reconstruct media consumption from Jellyfin played-item dates and legacy database records. Stored watch-time estimates derive from item runtimes, not continuous session tracking.</p>
                    <p>Because multiple import runs and legacy tools may observe identical playback events, sources are maintained on independent timelines and are never summed together or added to live confirmed totals.</p>
                </div>
            </details>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {sources.map(source => {
                    const estimate = estimates.find(entry => entry.provenance === source.provenance);
                    if (!estimate) return null;
                    const totalMinutes = Math.floor(estimate.reportedWatchTimeSecs / 60);
                    return (
                        <div key={source.provenance} className="min-w-0 rounded-xl border border-white/[0.08] bg-slate-950/40 p-4">
                            <div className="flex items-center justify-between">
                                <h4 className="text-xs font-medium" style={{ color: source.color }}>{source.label}</h4>
                                <span className="text-xs font-semibold px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20 uppercase tracking-wide">
                                    ESTIMATED
                                </span>
                            </div>
                            <p className="text-lg font-bold text-slate-100 mt-1.5">{Math.floor(totalMinutes / 60).toLocaleString()}h {totalMinutes % 60}m</p>
                            <p className="text-xs text-slate-400 mt-0.5">{estimate.records.toLocaleString()} stored records &middot; unverified estimate</p>
                            {estimate.undatedRecords > 0 && (
                                <p className="text-xs text-amber-400/90 mt-1">{estimate.undatedRecords.toLocaleString()} undated records included in this total, not plotted.</p>
                            )}
                        </div>
                    );
                })}
            </div>

            <div role="img" aria-label="Imported and legacy estimated watch hours by stored date, shown separately in UTC" className="h-[220px] min-w-0 w-full">
                <ResponsiveContainer width="100%" height={220}>
                    <LineChart data={chartData} margin={{ top: 8, right: 12, bottom: 0, left: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                        <XAxis dataKey="date" tick={{ fill: 'rgba(255,255,255,0.7)', fontSize: 12 }} minTickGap={24} />
                        <YAxis tick={{ fill: 'rgba(255,255,255,0.7)', fontSize: 12 }} tickFormatter={value => `${value}h`} width={48} />
                        <Tooltip
                            contentStyle={{
                                backgroundColor: '#0f172a',
                                border: '1px solid rgba(255,255,255,0.12)',
                                borderRadius: '10px',
                            }}
                            formatter={(value, name) => [`${value} h (estimate)`, name]}
                        />
                        <Legend wrapperStyle={{ fontSize: 12, paddingTop: '4px' }} />
                        {sources.filter(source => estimates.some(entry => entry.provenance === source.provenance)).map(source =>
                            <Line key={source.provenance} dataKey={source.provenance} name={source.label} stroke={source.color} strokeWidth={2} dot={false} />
                        )}
                    </LineChart>
                </ResponsiveContainer>
            </div>
        </section>
    );
}
