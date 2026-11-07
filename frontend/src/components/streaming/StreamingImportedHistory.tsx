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
    return <section aria-label="Imported watch history" className="min-w-0 max-w-full rounded-2xl border border-white/10 bg-slate-900/40 p-5 space-y-4">
        <div>
            <h3 className="text-sm font-bold text-slate-100">Imported Watch History ({windowDays === 0 ? 'All Time' : `${windowDays}d`})</h3>
            <p role="note" className="text-sm text-slate-400 mt-1">
                Your imported history is preserved. These stored watch-time estimates are not measured sessions.
                Item estimates use last-played dates and may reflect item runtimes, not elapsed viewing.
                Legacy and item imports may overlap: these series are separate, not added together or to confirmed watch time.
            </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {sources.map(source => {
                const estimate = estimates.find(entry => entry.provenance === source.provenance);
                if (!estimate) return null;
                const totalMinutes = Math.floor(estimate.reportedWatchTimeSecs / 60);
                return <div key={source.provenance} className="min-w-0 rounded-xl border border-white/10 p-4">
                    <h4 className="text-sm font-semibold" style={{ color: source.color }}>{source.label}</h4>
                    <p className="text-xl font-bold text-slate-100 mt-1">{Math.floor(totalMinutes / 60).toLocaleString()}h {totalMinutes % 60}m</p>
                    <p className="text-sm text-slate-400">{estimate.records.toLocaleString()} stored records · unverified estimate</p>
                    {estimate.undatedRecords > 0 && <p className="text-sm text-slate-400">{estimate.undatedRecords.toLocaleString()} undated records included in this total, not plotted.</p>}
                </div>;
            })}
        </div>
        <div role="img" aria-label="Imported and legacy estimated watch hours by stored date, shown separately in UTC" className="h-[220px] min-w-0 w-full">
            <ResponsiveContainer width="100%" height={220}>
                <LineChart data={chartData} margin={{ top: 8, right: 12, bottom: 0, left: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                    <XAxis dataKey="date" tick={{ fontSize: 12 }} minTickGap={24} />
                    <YAxis tick={{ fontSize: 12 }} tickFormatter={value => `${value}h`} width={48} />
                    <Tooltip formatter={(value, name) => [`${value} h (estimate)`, name]} />
                    <Legend wrapperStyle={{ fontSize: 12 }} />
                    {sources.filter(source => estimates.some(entry => entry.provenance === source.provenance)).map(source =>
                        <Line key={source.provenance} dataKey={source.provenance} name={source.label} stroke={source.color} strokeWidth={2} dot={false} />
                    )}
                </LineChart>
            </ResponsiveContainer>
        </div>
    </section>;
}
