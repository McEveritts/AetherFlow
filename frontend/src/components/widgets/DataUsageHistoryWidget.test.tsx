import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import DataUsageHistoryWidget from '@/components/widgets/DataUsageHistoryWidget';
import { fetcher } from '@/lib/fetcher';

jest.mock('@/lib/fetcher', () => ({
    fetcher: jest.fn(),
}));

jest.mock('recharts', () => {
    return {
        ResponsiveContainer: function MockResponsiveContainer({ children }: { children: React.ReactNode }) {
            return <div data-testid="responsive-container">{children}</div>;
        },
        AreaChart: function MockAreaChart({ children, data }: { children: React.ReactNode; data: unknown }) {
            return (
                <div data-testid="area-chart" data-chart-data={JSON.stringify(data)}>
                    {children}
                </div>
            );
        },
        Area: function MockArea({ dataKey, stroke, fill }: { dataKey: string; stroke: string; fill: string }) {
            return <div data-testid={`area-${dataKey}`} data-stroke={stroke} data-fill={fill} />;
        },
        XAxis: function MockXAxis() {
            return <div data-testid="x-axis" />;
        },
        YAxis: function MockYAxis({
            domain,
            ticks,
            tickFormatter,
        }: {
            domain?: [number, number];
            ticks?: number[];
            tickFormatter?: (value: number) => string;
        }) {
            const formattedTicks = ticks && tickFormatter ? ticks.map(tickFormatter) : [];
            return (
                <div
                    data-testid="y-axis"
                    data-domain={JSON.stringify(domain)}
                    data-ticks={JSON.stringify(ticks)}
                    data-formatted-ticks={JSON.stringify(formattedTicks)}
                />
            );
        },
        Tooltip: function MockTooltip() {
            return <div data-testid="tooltip" />;
        },
        CartesianGrid: function MockCartesianGrid() {
            return <div data-testid="cartesian-grid" />;
        },
    };
});

describe('DataUsageHistoryWidget', () => {
    const mockedFetcher = fetcher as jest.MockedFunction<typeof fetcher>;

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('renders truthful daily transfer title, explains sparse coverage, and uses consistent cyan and indigo colors', async () => {
        const sampleSnapshots = [
            { timestamp: '2026-11-01T00:00:00Z', net_rx_bytes: 1000000, net_tx_bytes: 500000 },
            { timestamp: '2026-11-01T23:59:59Z', net_rx_bytes: 3000000, net_tx_bytes: 1500000 },
            { timestamp: '2026-11-02T00:00:00Z', net_rx_bytes: 3000000, net_tx_bytes: 1500000 },
            { timestamp: '2026-11-02T23:59:59Z', net_rx_bytes: 6000000, net_tx_bytes: 2500000 },
            { timestamp: '2026-11-03T00:00:00Z', net_rx_bytes: 6000000, net_tx_bytes: 2500000 },
            { timestamp: '2026-11-03T23:59:59Z', net_rx_bytes: 9000000, net_tx_bytes: 4000000 },
        ];
        mockedFetcher.mockResolvedValueOnce(sampleSnapshots);

        render(<DataUsageHistoryWidget density="compact" />);

        expect(screen.getByText('Daily Bandwidth Transfer')).toBeInTheDocument();
        expect(screen.getByText('Truthful daily network ingress and egress volume')).toBeInTheDocument();

        await waitFor(() => {
            expect(screen.getByText(/Coverage: 3 of 30 days available/)).toBeInTheDocument();
        });

        const coverageTextElement = screen.getByText(/Coverage: 3 of 30 days available/);
        expect(coverageTextElement).toHaveClass('text-slate-200');

        expect(screen.getByText(/Sparse telemetry captured in window/)).toBeInTheDocument();

        expect(screen.getByText('Download')).toBeInTheDocument();
        expect(screen.getByText('Upload')).toBeInTheDocument();

        const downloadArea = screen.getByTestId('area-downloadedBytes');
        const uploadArea = screen.getByTestId('area-uploadedBytes');
        expect(downloadArea).toHaveAttribute('data-stroke', '#06b6d4');
        expect(uploadArea).toHaveAttribute('data-stroke', '#6366f1');

        expect(screen.getByText('Download (30d)')).toBeInTheDocument();
        expect(screen.getByText('Upload (30d)')).toBeInTheDocument();
    });

    it('re-fetches telemetry history with updated window when window option button is clicked', async () => {
        mockedFetcher.mockResolvedValue([]);

        render(<DataUsageHistoryWidget density="compact" />);

        await waitFor(() => {
            expect(mockedFetcher).toHaveBeenCalledWith('/api/v1/admin/ai/predictions/history?days=30');
        });

        const sevenDayButton = screen.getByRole('button', { name: /View 7 days telemetry/i });
        fireEvent.click(sevenDayButton);

        await waitFor(() => {
            expect(mockedFetcher).toHaveBeenCalledWith('/api/v1/admin/ai/predictions/history?days=7');
        });
    });

    it('configures truthful uniform linear Y-axis ticks and GB formatting for 15GB daily data', async () => {
        const gigabyteBytes = 1024 * 1024 * 1024;
        const fifteenGigabytes = 15 * gigabyteBytes;
        const sampleSnapshots = [
            { timestamp: '2026-11-01T00:00:00Z', net_rx_bytes: 0, net_tx_bytes: 0 },
            { timestamp: '2026-11-01T23:59:59Z', net_rx_bytes: fifteenGigabytes, net_tx_bytes: 2 * gigabyteBytes },
        ];
        mockedFetcher.mockResolvedValueOnce(sampleSnapshots);

        render(<DataUsageHistoryWidget density="compact" />);

        await waitFor(() => {
            expect(screen.getByTestId('y-axis')).toBeInTheDocument();
        });

        const yAxisElement = screen.getByTestId('y-axis');
        expect(yAxisElement).toHaveAttribute('data-domain', JSON.stringify([0, 16 * gigabyteBytes]));
        expect(yAxisElement).toHaveAttribute('data-ticks', JSON.stringify([
            0,
            4 * gigabyteBytes,
            8 * gigabyteBytes,
            12 * gigabyteBytes,
            16 * gigabyteBytes,
        ]));
        expect(yAxisElement).toHaveAttribute('data-formatted-ticks', JSON.stringify([
            '0 GB',
            '4 GB',
            '8 GB',
            '12 GB',
            '16 GB',
        ]));
    });

    it('configures linear Y-axis ticks uniformly for small transfer volumes', async () => {
        const smallSnapshots = [
            { timestamp: '2026-11-01T00:00:00Z', net_rx_bytes: 0, net_tx_bytes: 0 },
            { timestamp: '2026-11-01T23:59:59Z', net_rx_bytes: 500, net_tx_bytes: 100 },
        ];
        mockedFetcher.mockResolvedValueOnce(smallSnapshots);

        render(<DataUsageHistoryWidget density="compact" />);

        await waitFor(() => {
            expect(screen.getByTestId('y-axis')).toBeInTheDocument();
        });

        const yAxisElement = screen.getByTestId('y-axis');
        expect(yAxisElement).toHaveAttribute('data-domain', JSON.stringify([0, 800]));
        expect(yAxisElement).toHaveAttribute('data-ticks', JSON.stringify([0, 200, 400, 600, 800]));
        expect(yAxisElement).toHaveAttribute('data-formatted-ticks', JSON.stringify([
            '0 B',
            '200 B',
            '400 B',
            '600 B',
            '800 B',
        ]));
    });
});
