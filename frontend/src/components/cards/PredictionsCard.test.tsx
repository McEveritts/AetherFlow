import React from 'react';
import { render, screen } from '@testing-library/react';
import PredictionsCard from '@/components/cards/PredictionsCard';
import { apiFetch } from '@/lib/fetcher';

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
}));

jest.mock('@/components/charts/Sparkline', () => function MockSparkline() {
    return <div data-testid="mock-sparkline" />;
});

const mockedApiFetch = apiFetch as jest.Mock;

const mockReport = {
    trend_summary: 'Capacity trajectory stable.',
    cpu_trend: 'increasing',
    memory_trend: 'stable',
    disk_io_trend: 'decreasing',
    network_trend: 'critical',
    warnings: ['Disk saturation approaching threshold'],
    recommendations: ['Expand pool volume'],
    predicted_bottleneck: 'disk',
    confidence_score: 0.88,
};

const sampleValues = [12, 18, 24];
const mockHistory = sampleValues.map((sampleValue, sampleIndex) => ({
    id: sampleIndex,
    timestamp: String(sampleIndex),
    cpu_avg: sampleValue,
    mem_used_gb: sampleValue,
    mem_total_gb: 64,
    disk_read_bps: sampleValue,
    disk_write_bps: sampleValue,
    net_rx_bytes: sampleValue,
    net_tx_bytes: sampleValue,
    load_avg_1: 1.5,
    active_conns: 10,
}));

describe('PredictionsCard geometry class contract', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockedApiFetch.mockImplementation(async (requestUrl: string) => ({
            ok: true,
            status: 200,
            json: async () => requestUrl.includes('history') ? mockHistory : mockReport,
        }));
    });

    it('enforces container query geometry and wrap contract without forced shrink or nowrap', async () => {
        render(<PredictionsCard />);
        await screen.findByText('Bottleneck');

        const surfaceContainer = screen.getByText('Resource Insights').closest('.obs-telemetry-surface');
        expect(surfaceContainer).toBeInTheDocument();
        expect(surfaceContainer).toHaveClass('@container');

        const cpuLabel = screen.getByText('CPU');
        const trendGrid = cpuLabel.closest('.grid');
        expect(trendGrid).toBeInTheDocument();
        expect(trendGrid).toHaveClass('@[640px]:grid-cols-2');
        expect(trendGrid).not.toHaveClass('sm:grid-cols-2');

        const increasingTrend = screen.getByText('increasing');
        const badgeElement = increasingTrend.closest('span');
        expect(badgeElement).toBeInTheDocument();
        expect(badgeElement).not.toHaveClass('shrink-0');
        expect(badgeElement).not.toHaveClass('whitespace-nowrap');
        expect(badgeElement).toHaveClass('break-words');

        const bottleneckLabel = screen.getByText('Bottleneck');
        const bottleneckGrid = bottleneckLabel.closest('.grid');
        expect(bottleneckGrid).toBeInTheDocument();
        expect(bottleneckGrid).toHaveClass('@[640px]:grid-cols-2');
    });
});
