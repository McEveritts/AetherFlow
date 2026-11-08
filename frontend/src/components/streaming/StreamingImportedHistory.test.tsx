import React from 'react';
import { render, screen } from '@testing-library/react';
import StreamingImportedHistory, { importedWatchChartData, StreamingHistoryEstimate } from './StreamingImportedHistory';

jest.mock('recharts', () => ({
    ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
    LineChart: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
    CartesianGrid: () => null,
    Legend: () => null,
    Line: ({ dataKey, dot }: { dataKey: string; dot: false | { r: number; strokeWidth: number } }) => (
        <span data-testid={`estimate-line-${dataKey}`} data-dot={JSON.stringify(dot)} />
    ),
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

    it('renders methodology disclosure and explicit ESTIMATED badge labels', () => {
        render(<StreamingImportedHistory estimates={estimates} windowDays={30} />);
        expect(screen.getByText(/Import methodology, overlap & nonadditivity details/i)).toBeInTheDocument();
        expect(screen.getAllByText('ESTIMATED').length).toBeGreaterThan(0);
    });

    it('embeds source columns and charts in the page with a keyboard-accessible methodology disclosure', () => {
        render(<StreamingImportedHistory estimates={estimates} windowDays={30} />);
        const section = screen.getByRole('region', { name: 'Imported watch history' });
        expect(section).toHaveClass('border-b', 'border-white/[0.07]', 'py-6', 'min-w-0', 'max-w-full');
        expect(section).not.toHaveClass('obs-telemetry-surface', 'rounded-2xl', 'border', 'shadow-xl');
        const sources = screen.getByRole('heading', { name: 'Imported item estimates' }).parentElement?.parentElement?.parentElement;
        expect(sources).toHaveClass('sm:grid-cols-2', 'sm:divide-y-0', 'sm:divide-x', 'divide-white/[0.07]');
        expect(section.querySelector('.obs-telemetry-surface')).not.toBeInTheDocument();
        expect(screen.getAllByRole('note')).toHaveLength(1);
        expect(screen.getByRole('note')).toHaveTextContent('Your imported history is preserved.');
        const disclosure = screen.getByText('Import methodology, overlap & nonadditivity details').closest('details');
        expect(disclosure).not.toHaveAttribute('open');
        expect(disclosure?.querySelector('summary')).toHaveClass('min-h-[44px]', 'cursor-pointer');
    });

    it('keeps the earlier chart dates and overlapping source values separate, without zeroing unknown values', () => {
        expect(importedWatchChartData(estimates)).toEqual([
            { date: '2026-08-09', item_summary: 1, legacy_unverified: 1 },
            { date: '2026-10-27', item_summary: 2 },
        ]);
    });

    it('shows visible dots for sparse series independently of the other source timeline', () => {
        const denseItems: StreamingHistoryEstimate = {
            ...estimates[0],
            timeSeries: [1, 2, 3, 4].map(day => ({ date: `2026-10-0${day}`, watchTimeSecs: 3600 })),
        };
        const { rerender } = render(<StreamingImportedHistory estimates={[denseItems, estimates[1]]} windowDays={30} />);
        expect(screen.getByTestId('estimate-line-item_summary')).toHaveAttribute('data-dot', 'false');
        expect(screen.getByTestId('estimate-line-legacy_unverified')).toHaveAttribute('data-dot', '{"r":3,"strokeWidth":1.5}');

        rerender(<StreamingImportedHistory estimates={[{ ...denseItems, timeSeries: denseItems.timeSeries.slice(0, 3) }]} windowDays={30} />);
        expect(screen.getByTestId('estimate-line-item_summary')).toHaveAttribute('data-dot', '{"r":3,"strokeWidth":1.5}');
    });

    it('keeps undated-only estimates in totals without inventing dated chart values', () => {
        const undated: StreamingHistoryEstimate = { ...estimates[0], records: 2, undatedRecords: 2, timeSeries: [] };
        render(<StreamingImportedHistory estimates={[undated]} windowDays={0} />);
        expect(screen.getByText('504h 31m')).toBeInTheDocument();
        expect(screen.getByText(/2 undated records included in this total, not plotted/)).toBeInTheDocument();
        expect(importedWatchChartData([undated])).toEqual([]);
    });

    it('does not claim lost or zero history for older API payloads without estimate fields', () => {
        const { container } = render(<StreamingImportedHistory estimates={[]} windowDays={30} />);
        expect(container).toBeEmptyDOMElement();
    });
});
