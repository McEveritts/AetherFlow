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

    it('distinguishes physical RAM from swap in a compact footer with an accessible paging explanation', () => {
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
        const ramSummary = screen.getByText('RAM used · 50%');
        expect(ramSummary.closest('.obs-vital-header')).toBeInTheDocument();
        expect(screen.getByTestId('sparkline').parentElement).toHaveClass('obs-vital-plot');
        expect(ramSummary.closest('.obs-telemetry-surface')?.querySelectorAll('[style*="width"]')).toHaveLength(1);
        expect(screen.getByText('Swap · 75%').closest('.obs-vital-footer')).toBeInTheDocument();
        expect(screen.getByRole('meter', { name: 'Swap occupancy' })).toHaveAttribute('aria-valuenow', '75');
        expect(screen.getByRole('meter', { name: 'Swap occupancy' })).toHaveAccessibleDescription(/occupancy does not imply critical exhaustion/);
        expect(screen.queryByText('Paging reserve details')).not.toBeInTheDocument();
        expect(screen.getByText(/Kernel pages idle blocks/).closest('details')).toBeNull();
        expect(screen.getByText(/Kernel pages idle blocks to swap; occupancy does not imply critical exhaustion/)).toBeInTheDocument();
        expect(screen.queryByText(/Elevated physical memory allocation pressure/)).not.toBeInTheDocument();

        const sparklineElement = screen.getByTestId('sparkline');
        expect(sparklineElement).toHaveAttribute('data-has-shared-summary', 'true');
    });

    it('preserves the footer band when swap is not configured', () => {
        render(<MemoryWidget memoryData={{ memory: { used: 4, total: 8 }, swap: { used: 0, total: 0 } }} hardware={null} history={dummyHistory} />);
        expect(screen.getByText('No swap configured · Physical memory only')).toHaveClass('obs-vital-footer');
        expect(screen.queryByRole('meter', { name: 'Swap occupancy' })).not.toBeInTheDocument();
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
