import React from 'react';
import { render, screen } from '@testing-library/react';
import NetworkWidget from '@/components/widgets/NetworkWidget';
import { MetricsHistory } from '@/types/dashboard';

jest.mock('@/components/charts/Sparkline', () => {
    return function MockSparkline({
        currentValue,
        currentValue2,
        hasSharedSummary,
    }: {
        currentValue?: string;
        currentValue2?: string;
        hasSharedSummary?: boolean;
    }) {
        return (
            <div
                data-testid="sparkline"
                data-current={currentValue}
                data-current2={currentValue2}
                data-has-shared-summary={String(Boolean(hasSharedSummary))}
            />
        );
    };
});

describe('NetworkWidget', () => {
    const mockHistory: MetricsHistory = {
        cpu: [0, 0],
        memory: [0, 0],
        netDown: [1000, 2000],
        netUp: [500, 1000],
        diskRead: [0, 0],
        diskWrite: [0, 0],
        timestamps: [1700000000000, 1700000010000],
    };

    it('formats rate strings with consistent decimal spacing and passes hasSharedSummary to sparkline', () => {
        const networkMetrics = {
            network: {
                down: '4 MB/s',
                up: '24.5 MB/s',
                active_connections: 12,
            },
            total: {
                rx: 104857600,
                tx: 52428800,
            },
        };

        render(
            <NetworkWidget
                networkData={networkMetrics}
                hardware={null}
                history={mockHistory}
                density="compact"
                hasSharedSummary={true}
            />
        );

        expect(screen.getByRole('heading', { name: /Network Traffic/i })).toBeInTheDocument();
        expect(screen.getByText('Download')).toBeInTheDocument();
        expect(screen.getByText('Upload')).toBeInTheDocument();
        expect(screen.getByText('4.0 MB/s')).toBeInTheDocument();
        expect(screen.getByText('24.5 MB/s')).toBeInTheDocument();
        expect(screen.getByText('12 active connections')).toBeInTheDocument();
        expect(screen.getByText('Total RX')).toBeInTheDocument();
        expect(screen.getByText('100.0 MB')).toBeInTheDocument();
        expect(screen.getByText('Total TX')).toBeInTheDocument();
        expect(screen.getByText('50.0 MB')).toBeInTheDocument();

        const sparklineElement = screen.getByTestId('sparkline');
        expect(sparklineElement.closest('.obs-telemetry-surface')).toBeInTheDocument();
        expect(sparklineElement.parentElement).toHaveClass('obs-vital-plot');
        expect(screen.getByText('Network Traffic').closest('.obs-vital-header')).toBeInTheDocument();
        expect(screen.getByText('Total RX').closest('.obs-vital-footer')).toBeInTheDocument();
        expect(sparklineElement.parentElement).not.toHaveClass('bg-slate-950/60', 'border');
        expect(sparklineElement).toHaveAttribute('data-current', '4.0 MB/s');
        expect(sparklineElement).toHaveAttribute('data-current2', '24.5 MB/s');
        expect(sparklineElement).toHaveAttribute('data-has-shared-summary', 'true');
    });

    it('formats singular active connection count correctly', () => {
        const networkMetrics = {
            network: {
                down: '1.2 KB/s',
                up: '3.4 KB/s',
                active_connections: 1,
            },
            total: {
                rx: 1024,
                tx: 2048,
            },
        };

        render(
            <NetworkWidget
                networkData={networkMetrics}
                hardware={null}
                history={mockHistory}
                density="compact"
                hasSharedSummary={false}
            />
        );

        expect(screen.getByText('1 active connection')).toBeInTheDocument();
        expect(screen.getByText('1.2 KB/s')).toBeInTheDocument();
        expect(screen.getByText('3.4 KB/s')).toBeInTheDocument();
    });
});
