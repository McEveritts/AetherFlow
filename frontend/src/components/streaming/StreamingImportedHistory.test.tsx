import React from 'react';
import { render, screen } from '@testing-library/react';
import StreamingImportedHistory, { importedWatchChartData, StreamingHistoryEstimate } from './StreamingImportedHistory';

jest.mock('recharts', () => ({
    ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
    LineChart: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
    CartesianGrid: () => null,
    Legend: () => null,
    Line: () => null,
    Tooltip: () => null,
    XAxis: () => null,
    YAxis: () => null,
}));

const estimates: StreamingHistoryEstimate[] = [
    { provenance: 'item_summary', records: 844, reportedWatchTimeSecs: 1816293, undatedRecords: 1,
        timeSeries: [{ date: '2026-08-09', watchTimeSecs: 3600 }, { date: '2026-10-27', watchTimeSecs: 7200 }] },
    { provenance: 'legacy_unverified', records: 842, reportedWatchTimeSecs: 1811081, undatedRecords: 0,
        timeSeries: [{ date: '2026-08-09', watchTimeSecs: 3600 }] },
];

describe('StreamingImportedHistory', () => {
    it('restores pre-October-28 estimates visibly and warns that overlapping sources are not additive', () => {
        render(<StreamingImportedHistory estimates={estimates} windowDays={0} />);
        expect(screen.getByRole('region', { name: 'Imported watch history' })).toBeInTheDocument();
        expect(screen.getByText('Imported Watch History (All Time)')).toBeInTheDocument();
        expect(screen.getByText('504h 31m')).toBeInTheDocument();
        expect(screen.getByText('503h 4m')).toBeInTheDocument();
        expect(screen.getByText(/844 stored records/)).toBeInTheDocument();
        expect(screen.getByText(/842 stored records/)).toBeInTheDocument();
        expect(screen.getByRole('note')).toHaveTextContent(/not added together or to confirmed watch time/);
        expect(screen.getByRole('note')).toHaveTextContent(/item runtimes, not elapsed viewing/);
        expect(screen.getByText(/1 undated records included in this total, not plotted/)).toBeInTheDocument();
    });

    it('keeps the earlier chart dates and overlapping source values separate, without zeroing unknown values', () => {
        expect(importedWatchChartData(estimates)).toEqual([
            { date: '2026-08-09', item_summary: 1, legacy_unverified: 1 },
            { date: '2026-10-27', item_summary: 2 },
        ]);
    });

    it('does not claim lost or zero history for older API payloads without estimate fields', () => {
        const { container } = render(<StreamingImportedHistory estimates={[]} windowDays={30} />);
        expect(container).toBeEmptyDOMElement();
    });
});
