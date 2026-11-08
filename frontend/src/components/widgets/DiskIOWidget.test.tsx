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
        expect(sparklineElement.closest('.obs-telemetry-surface')).toBeInTheDocument();
        expect(sparklineElement.parentElement).toHaveClass('obs-vital-plot');
        expect(screen.getByText('Disk I/O').closest('.obs-vital-header')).toBeInTheDocument();
        expect(screen.getByText('Read share').closest('.obs-vital-footer')).toBeInTheDocument();
        expect(screen.getByText('86%')).toBeInTheDocument();
        expect(screen.getByText('14%')).toBeInTheDocument();
        expect(sparklineElement.parentElement).not.toHaveClass('bg-slate-950/60', 'border');
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
        expect(screen.getAllByText('Idle')).toHaveLength(2);
        expect(screen.queryByText('100%')).not.toBeInTheDocument();
    });

    it.each([
        { read: 1024, write: 3072, readShare: '25%', writeShare: '75%' },
        { read: 1024, write: 0, readShare: '100%', writeShare: '0%' },
        { read: 0, write: 1024, readShare: '0%', writeShare: '100%' },
    ])('uses current rates rather than historical peaks for $read / $write shares', ({ read, write, readShare, writeShare }) => {
        render(<DiskIOWidget diskIoData={{ read_bytes_sec: read, write_bytes_sec: write }} history={mockHistory} />);
        expect(screen.getByText('Read share').nextElementSibling).toHaveTextContent(readShare);
        expect(screen.getByText('Write share').nextElementSibling).toHaveTextContent(writeShare);
    });
});
