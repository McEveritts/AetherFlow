import React from 'react';
import { render, screen } from '@testing-library/react';
import GpuWidget from '@/components/widgets/GpuWidget';
import { GpuMetric } from '@/types/dashboard';

describe('GpuWidget content sizing and canonical source honesty', () => {
    const mockGpus: GpuMetric[] = [
        {
            index: 0,
            name: 'NVIDIA GeForce RTX 4090',
            usage_pct: 35.5,
            memory_total: 24576,
            memory_used: 8192,
            temp: 58,
        },
    ];

    it('renders real GPU metrics without artificial spreading or unsupported synthetic device nodes', () => {
        const { container } = render(<GpuWidget gpus={mockGpus} density="compact" />);

        expect(screen.getByText('Compute Accelerators')).toBeInTheDocument();
        expect(screen.getByText('NVIDIA GeForce RTX 4090')).toBeInTheDocument();
        expect(screen.getByText('GPU #0')).toBeInTheDocument();
        expect(screen.getByText('NVENC / CUDA')).toBeInTheDocument();
        expect(screen.getByText('35.5%')).toBeInTheDocument();
        expect(screen.getByText('58°C')).toBeInTheDocument();

        expect(screen.queryByText('/dev/dri/renderD128')).not.toBeInTheDocument();
        expect(screen.queryByText('Transcode API')).not.toBeInTheDocument();

        const rootElement = container.firstElementChild as HTMLElement;
        expect(rootElement).not.toHaveClass('justify-between');
        expect(rootElement).not.toHaveClass('h-full');
    });

    it('returns null when no GPUs are provided', () => {
        const { container } = render(<GpuWidget gpus={[]} density="compact" />);
        expect(container.firstChild).toBeNull();
    });
});
