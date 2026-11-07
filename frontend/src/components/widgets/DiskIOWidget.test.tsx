import React from 'react';
import { render, screen } from '@testing-library/react';
import DiskIOWidget from '@/components/widgets/DiskIOWidget';
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

describe('DiskIOWidget', () => {
    const mockHistory: MetricsHistory = {
        cpu: [0, 0],
        memory: [0, 0],
        netDown: [0, 0],
        netUp: [0, 0],
        diskRead: [1048576, 2097152],
        diskWrite: [4194304, 8388608],
        timestamps: [1700000000000, 1700000010000],
    };

    it('formats disk throughput rates consistently and forwards hasSharedSummary to sparkline', () => {
        const diskIoMetrics = {
            read_bytes_sec: 25600000,
            write_bytes_sec: 4000000,
        };

        render(
            <DiskIOWidget
                diskIoData={diskIoMetrics}
                history={mockHistory}
                density="compact"
                hasSharedSummary={true}
            />
        );

        expect(screen.getByText('Disk I/O')).toBeInTheDocument();
        expect(screen.getByText('Read')).toBeInTheDocument();
        expect(screen.getByText('Write')).toBeInTheDocument();
        expect(screen.getByText('24.4 MB/s')).toBeInTheDocument();
        expect(screen.getByText('3.8 MB/s')).toBeInTheDocument();
        expect(screen.getByText('28.2 MB/s')).toBeInTheDocument();

        const sparklineElement = screen.getByTestId('sparkline');
        expect(sparklineElement).toHaveAttribute('data-current', '24.4 MB/s');
        expect(sparklineElement).toHaveAttribute('data-current2', '3.8 MB/s');
        expect(sparklineElement).toHaveAttribute('data-has-shared-summary', 'true');
    });

    it('handles zero throughput rates truthfully', () => {
        const diskIoMetrics = {
            read_bytes_sec: 0,
            write_bytes_sec: 0,
        };

        render(
            <DiskIOWidget
                diskIoData={diskIoMetrics}
                history={mockHistory}
                density="compact"
                hasSharedSummary={false}
            />
        );

        const zeroValues = screen.getAllByText('0.0 B/s');
        expect(zeroValues.length).toBeGreaterThanOrEqual(2);
    });
});
