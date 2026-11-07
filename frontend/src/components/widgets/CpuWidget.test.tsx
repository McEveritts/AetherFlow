import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import CpuWidget from '@/components/widgets/CpuWidget';
import { HardwareReport, MetricsHistory } from '@/types/dashboard';

jest.mock('@/components/charts/Sparkline', () => {
    return function MockSparkline({
        timeContext,
        isPercentage,
        yDomain,
        timestamps,
        selectedWindow,
        hasSharedSummary,
    }: {
        timeContext?: string;
        isPercentage?: boolean;
        yDomain?: [number, number];
        timestamps?: number[];
        selectedWindow?: string;
        hasSharedSummary?: boolean;
    }) {
        return (
            <div
                data-testid="sparkline"
                data-time-context={timeContext}
                data-timestamps={JSON.stringify(timestamps)}
                data-selected-window={selectedWindow}
                data-is-percentage={String(isPercentage)}
                data-y-domain={JSON.stringify(yDomain)}
                data-has-shared-summary={String(Boolean(hasSharedSummary))}
            />
        );
    };
});

describe('CpuWidget hardware terminology and disclosure behavior', () => {
    const mockHistory: MetricsHistory = {
        cpu: [14.8, 14.8, 14.8],
        memory: [44.4, 44.4],
        netDown: [0, 0],
        netUp: [0, 0],
        diskRead: [0, 0],
        diskWrite: [0, 0],
        timestamps: [1700000000000, 1700000030000],
    };

    it('uses physical-core and logical-processor terminology when hardware data provides physical cores', () => {
        const hardwareWithKnownCores: HardwareReport = {
            system_vendor: 'AMD',
            system_product: 'EPYC Server',
            cpu: {
                model: 'AMD EPYC 7763 64-Core Processor',
                cores: 64,
                threads: 128,
            },
        };

        const cores128 = Array.from({ length: 128 }, (_, index) => (index % 2 === 0 ? 15 : 45));

        render(
            <CpuWidget
                cpuData={{ usage: 14.8, freq: 2450, cores: cores128 }}
                hardware={hardwareWithKnownCores}
                history={mockHistory}
            />
        );

        expect(screen.getByText('AMD EPYC 7763 64-Core Processor')).toBeInTheDocument();
        expect(screen.getByText('Logical Processors (128)')).toBeInTheDocument();
        expect(screen.getByText(/Load Legend:/)).toBeInTheDocument();

        const sparklineElement = screen.getByTestId('sparkline');
        expect(sparklineElement).toHaveAttribute('data-is-percentage', 'true');
        expect(sparklineElement).toHaveAttribute('data-y-domain', JSON.stringify([0, 100]));
        expect(sparklineElement).toHaveAttribute('data-timestamps', JSON.stringify(mockHistory.timestamps));
    });

    it('never infers physical cores when hardware cpu cores is missing, using logical processor terminology', () => {
        const hardwareWithoutCores: HardwareReport = {
            system_vendor: 'Unknown',
            system_product: 'Server',
            cpu: {
                model: '',
                threads: 128,
            },
        };

        const cores128 = Array.from({ length: 128 }, () => 14.8);

        render(
            <CpuWidget
                cpuData={{ usage: 14.8, freq: 2450, cores: cores128 }}
                hardware={hardwareWithoutCores}
                history={mockHistory}
            />
        );

        expect(screen.queryByText(/Physical Cores/)).not.toBeInTheDocument();
        expect(screen.getByText('128 Logical Processors')).toBeInTheDocument();
        expect(screen.getByText('Logical Processors (128)')).toBeInTheDocument();
    });

    it('provides expandable disclosure for processor grid and allows selecting individual processors', () => {
        const sampleCores = [12, 34, 56, 78];

        render(
            <CpuWidget
                cpuData={{ usage: 45, freq: 3200, cores: sampleCores }}
                hardware={null}
                history={mockHistory}
            />
        );

        expect(screen.getByText('4 Logical Processors')).toBeInTheDocument();

        const firstProcessorButton = screen.getByRole('button', { name: 'Processor 0: 12.0%' });
        expect(firstProcessorButton).toBeInTheDocument();

        fireEvent.click(firstProcessorButton);
        expect(screen.getByText('Processor 0: 12.0% utilization')).toBeInTheDocument();

        fireEvent.click(firstProcessorButton);
        expect(screen.queryByText('Processor 0: 12.0% utilization')).not.toBeInTheDocument();
    });

    it('forwards hasSharedSummary to Sparkline component', () => {
        render(
            <CpuWidget
                cpuData={{ usage: 20, freq: 3000, cores: [20] }}
                hardware={null}
                history={mockHistory}
                hasSharedSummary={true}
            />
        );

        const sparklineElement = screen.getByTestId('sparkline');
        expect(sparklineElement).toHaveAttribute('data-has-shared-summary', 'true');
    });

    it('ensures logical processors disclosure summary meets mobile min-h-[44px] touch target', () => {
        render(
            <CpuWidget
                cpuData={{ usage: 20, freq: 3000, cores: [20] }}
                hardware={null}
                history={mockHistory}
            />
        );

        const summaryElement = screen.getByTestId('cpu-processors-summary');
        expect(summaryElement).toHaveClass('min-h-[44px]');
    });

    it('renders a truthful proportional utilization meter with accessible values separate from history', () => {
        render(
            <CpuWidget
                cpuData={{ usage: 14.8, freq: 2450, cores: [14.8] }}
                hardware={null}
                history={mockHistory}
                hasSharedSummary={true}
            />
        );

        const meterElement = screen.getByRole('meter', { name: 'Current CPU utilization' });
        expect(meterElement).toBeInTheDocument();
        expect(meterElement).toHaveAttribute('aria-valuenow', '14.8');
        expect(meterElement).toHaveAttribute('aria-valuemin', '0');
        expect(meterElement).toHaveAttribute('aria-valuemax', '100');
        expect(meterElement).toHaveAttribute('aria-valuetext', '14.8%');
    });
});
