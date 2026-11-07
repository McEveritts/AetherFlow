import React from 'react';
import { render, screen } from '@testing-library/react';
import MemoryWidget from '@/components/widgets/MemoryWidget';
import { MetricsHistory } from '@/types/dashboard';

jest.mock('@/components/charts/Sparkline', () => {
    return function MockSparkline({ currentValue, hasSharedSummary }: { currentValue: string; hasSharedSummary?: boolean }) {
        return <div data-testid="sparkline" data-current={currentValue} data-has-shared-summary={String(Boolean(hasSharedSummary))} />;
    };
});

describe('MemoryWidget', () => {
    const dummyHistory: MetricsHistory = {
        cpu: [10, 10],
        memory: [50, 50],
        netDown: [0, 0],
        netUp: [0, 0],
        diskRead: [0, 0],
        diskWrite: [0, 0],
        timestamps: [1, 2],
    };

    it('distinguishes physical RAM from swap occupancy and places swap explanation in paging disclosure', () => {
        const nominalMemoryData = {
            memory: { used: 16, total: 32 },
            swap: { used: 6, total: 8 },
        };

        render(
            <MemoryWidget
                memoryData={nominalMemoryData}
                hardware={null}
                history={dummyHistory}
                density="compact"
                hasSharedSummary={true}
            />
        );

        expect(screen.getByText('System Memory')).toBeInTheDocument();
        expect(screen.getByText('Kernel & workload memory')).toBeInTheDocument();
        expect(screen.getByText(/16.0 GB available/)).toBeInTheDocument();
        expect(screen.getByText('RAM used · 50%')).toBeInTheDocument();
        expect(screen.getByText(/Swap Occupancy \(75%\)/)).toBeInTheDocument();
        const pagingSummaryElement = screen.getByTestId('memory-paging-reserve-summary');
        expect(pagingSummaryElement).toBeInTheDocument();
        expect(pagingSummaryElement).toHaveClass('min-h-[44px]');
        expect(screen.getByText('Paging reserve details')).toBeInTheDocument();
        expect(screen.getByText(/Kernel pages idle blocks to swap; occupancy does not imply critical exhaustion/)).toBeInTheDocument();
        expect(screen.queryByText(/Elevated physical memory allocation pressure/)).not.toBeInTheDocument();

        const sparklineElement = screen.getByTestId('sparkline');
        expect(sparklineElement).toHaveAttribute('data-has-shared-summary', 'true');
    });

    it('displays elevated pressure warning when physical RAM reaches threshold regardless of swap state', () => {
        const highMemoryPressureData = {
            memory: { used: 30, total: 32 },
            swap: { used: 1, total: 8 },
        };

        render(
            <MemoryWidget
                memoryData={highMemoryPressureData}
                hardware={null}
                history={dummyHistory}
                density="compact"
            />
        );

        expect(screen.getByText('Elevated physical memory allocation pressure')).toBeInTheDocument();
    });
});
