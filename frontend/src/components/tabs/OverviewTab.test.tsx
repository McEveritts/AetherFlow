import React from 'react';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { act, render, screen, fireEvent } from '@testing-library/react';
import OverviewTab from '@/components/tabs/OverviewTab';
import Header from '@/components/layout/Header';
import { SystemMetrics, MetricsHistory, HardwareReport } from '@/types/dashboard';
import { useConnectionStore } from '@/store/useConnectionStore';

jest.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ user: null, logout: jest.fn() }) }));
jest.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ toasts: [], toggleDrawer: jest.fn() }) }));

jest.mock('@/components/widgets/CpuWidget', () => function MockCpuWidget(widgetProps: { hasSharedSummary?: boolean }) {
    return <div data-testid="cpu-widget" data-has-shared-summary={String(Boolean(widgetProps.hasSharedSummary))} />;
});
jest.mock('@/components/widgets/MemoryWidget', () => function MockMemoryWidget(widgetProps: { hasSharedSummary?: boolean }) {
    return <div data-testid="memory-widget" data-has-shared-summary={String(Boolean(widgetProps.hasSharedSummary))} />;
});
jest.mock('@/components/widgets/NetworkWidget', () => function MockNetworkWidget(widgetProps: { hasSharedSummary?: boolean }) {
    return <div data-testid="network-widget" data-has-shared-summary={String(Boolean(widgetProps.hasSharedSummary))} />;
});
jest.mock('@/components/widgets/DiskIOWidget', () => function MockDiskIOWidget(widgetProps: { hasSharedSummary?: boolean }) {
    return <div data-testid="disk-io-widget" data-has-shared-summary={String(Boolean(widgetProps.hasSharedSummary))} />;
});
jest.mock('@/components/widgets/ProcessWidget', () => function MockProcessWidget() {
    return <div data-testid="process-widget" />;
});
jest.mock('@/components/widgets/StorageWidget', () => function MockStorageWidget() {
    return <div data-testid="storage-widget" />;
});
jest.mock('@/components/widgets/AppTopologyMap', () => function MockAppTopologyMap({ topologyData }: { topologyData: SystemMetrics['services'] }) {
    return <div data-testid="topology-widget">{JSON.stringify(topologyData)}</div>;
});
jest.mock('@/components/widgets/GpuWidget', () => function MockGpuWidget() {
    return <div data-testid="gpu-widget" />;
});
jest.mock('@/components/widgets/DataUsageHistoryWidget', () => function MockDataUsageHistoryWidget() {
    return <div data-testid="data-usage-widget" />;
});
jest.mock('@/components/cards/BandwidthCard', () => function MockBandwidthCard() {
    return <div data-testid="bandwidth-card" />;
});
jest.mock('@/components/cards/PredictionsCard', () => function MockPredictionsCard() {
    return <div data-testid="predictions-card" />;
});

function createMockMetrics(serviceOverrides: SystemMetrics['services'] = {}): SystemMetrics {
    return {
        cpu_usage: 25,
        cpu_freq_mhz: 3600,
        per_core_cpu: [20, 30],
        memory: { used: 8, total: 32 },
        swap: { used: 1, total: 8 },
        disk_space: { used: 256, total: 1024, free: 768 },
        is_windows: false,
        disks: [],
        disk_io: { read_bytes_sec: 1024, write_bytes_sec: 2048 },
        network: { up: '1 MB/s', down: '2 MB/s', active_connections: 5 },
        total_net_bytes: { rx: 10485760, tx: 5242880 },
        load_average: [0.5, 0.4, 0.3],
        uptime: '2d 4h',
        processes: [],
        gpus: [],
        services: serviceOverrides,
    };
}

const mockHistory: MetricsHistory = {
    cpu: [20, 25],
    memory: [25, 25],
    netDown: [100, 200],
    netUp: [50, 100],
    diskRead: [10, 20],
    diskWrite: [15, 30],
    timestamps: [1, 2],
};

const mockHardware: HardwareReport = {
    system_vendor: 'Supermicro',
    system_product: 'SYS-E300',
    cpu: { vendor: 'Intel', model: 'Xeon E-2278G', cores: 8, threads: 16 },
};

describe('OverviewTab', () => {
    beforeEach(() => {
        useConnectionStore.setState({
            connectionState: 'CONNECTED',
            dashboardDensity: 'compact',
            showGpuWidget: true,
            showDataUsageWidget: true,
        });
    });

    it('updates topology when only terminal-job or degraded-component metadata changes', () => {
        const metrics = createMockMetrics({ sonarr: { status: 'running', health: 'healthy' } });
        const view = render(<OverviewTab metrics={metrics} hardware={mockHardware} history={mockHistory} />);
        expect(screen.getByTestId('topology-widget')).not.toHaveTextContent('storage missing');
        const changedMetrics = createMockMetrics({ sonarr: { status: 'running', health: 'healthy', last_job: { action: 'install', status: 'failed', error: 'storage missing' }, degraded_components: ['proxy'] } });
        view.rerender(<OverviewTab metrics={changedMetrics} hardware={mockHardware} history={mockHistory} />);
        expect(screen.getByTestId('topology-widget')).toHaveTextContent('storage missing');
        expect(screen.getByTestId('topology-widget')).toHaveTextContent('proxy');
    });

    it('labels a disconnected connection without claiming it is reconnecting', () => {
        useConnectionStore.setState({ connectionState: 'DISCONNECTED' });
        render(<OverviewTab metrics={createMockMetrics()} hardware={mockHardware} history={mockHistory} />);
        expect(screen.getByText('Disconnected')).toBeInTheDocument();
        expect(screen.queryByText('Reconnecting')).not.toBeInTheDocument();
    });

    it('surfaces actual service exceptions naming affected services without treating clean stopped as failures', () => {
        const metricsWithException = createMockMetrics({
            qbittorrent: { status: 'error', uptime: '0m', version: '4.6.0' },
            radarr: { status: 'stopped', uptime: '', version: '5.0.0' },
            sonarr: { status: 'running', uptime: '2d', version: '4.0.0' },
        });

        render(
            <OverviewTab
                metrics={metricsWithException}
                hardware={mockHardware}
                history={mockHistory}
            />
        );

        expect(screen.getByText(/Service Exception:/)).toBeInTheDocument();
        expect(screen.getByText(/qBittorrent/)).toBeInTheDocument();
        expect(screen.queryByText(/Clean stop/)).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Open Services tab for exception triage' })).toHaveClass('min-h-[44px]');

        expect(screen.getAllByText(/Supermicro/)[0]).toBeInTheDocument();
        expect(screen.getAllByText(/Xeon E-2278G/)[0]).toBeInTheDocument();
    });

    it('surfaces stopped daemons with failed installations as exceptions with specific detail', () => {
        const metricsWithInstallFailure = createMockMetrics({
            calibreweb: {
                status: 'stopped',
                uptime: '',
                version: '1.0.0',
                job_status: 'install_failed',
                last_job: { action: 'install', status: 'failed', error: 'Dependencies missing' },
            },
            jellyfin: { status: 'running', uptime: '1d', version: '10.8.0' },
            sonarr: { status: 'stopped', uptime: '', version: '4.0.0' },
        });

        render(
            <OverviewTab
                metrics={metricsWithInstallFailure}
                hardware={mockHardware}
                history={mockHistory}
            />
        );

        expect(screen.getByText(/Service Exception:/)).toBeInTheDocument();
        expect(screen.getByText(/Calibre-Web \(Install failed: Dependencies missing\)/)).toBeInTheDocument();
    });

    it('renders restrained live status and consistent telemetry ribbon metrics', () => {
        const normalMetrics = createMockMetrics({
            sonarr: { status: 'running', uptime: '2d', version: '4.0.0' },
        });

        render(
            <OverviewTab
                metrics={normalMetrics}
                hardware={mockHardware}
                history={mockHistory}
            />
        );

        expect(screen.queryByText(/Service Exception/)).not.toBeInTheDocument();
        expect(screen.getByText(/Live Telemetry/)).toBeInTheDocument();
        expect(screen.getByText(/1.0s Interval/)).toBeInTheDocument();

        expect(screen.getAllByText('1/1 Running')[0]).toBeInTheDocument();
        expect(screen.getAllByRole('button', { name: /^Inspect 1 managed service \(1 running\)$/i })[0]).toBeInTheDocument();

        expect(screen.getByText('Uptime')).toBeInTheDocument();
        expect(screen.getByText('2d 4h')).toBeInTheDocument();
        expect(screen.getByText('Continuous runtime')).toBeInTheDocument();
        expect(screen.getByText('Load (1/5/15)')).toBeInTheDocument();
        expect(screen.getByText('0.50 · 0.40 · 0.30')).toBeInTheDocument();
        expect(screen.getByText('Kernel load avg')).toBeInTheDocument();
        expect(screen.getByText('Services')).toBeInTheDocument();
        expect(screen.getByText('1 / 1')).toBeInTheDocument();
        expect(screen.getByText('Running / managed')).toBeInTheDocument();
        expect(screen.getByText('Processes / Threads')).toBeInTheDocument();
        expect(screen.getByText('0 / 2')).toBeInTheDocument();
        expect(screen.getByText('Observed tasks / logical threads')).toBeInTheDocument();
        expect(screen.queryByText('CPU Clock')).not.toBeInTheDocument();
        expect(screen.queryByText('Connections')).not.toBeInTheDocument();
        expect(screen.getByTestId('cpu-widget').parentElement).toHaveClass('xl:grid-cols-4');
        expect(screen.getByTestId('topology-widget').parentElement).toHaveClass('xl:col-span-6');

        expect(screen.queryByText('Downloaded')).not.toBeInTheDocument();
        expect(screen.queryByText('Uploaded')).not.toBeInTheDocument();
    });

    it('allows selecting different history time windows and density modes', () => {
        const normalMetrics = createMockMetrics();

        render(
            <OverviewTab
                metrics={normalMetrics}
                hardware={mockHardware}
                history={mockHistory}
            />
        );

        const fiveMinuteButton = screen.getByTestId('history-window-5m');
        fireEvent.click(fiveMinuteButton);

        const expandedButton = screen.getByRole('button', { name: /Set expanded dashboard density/i });
        fireEvent.click(expandedButton);

        const standardButton = screen.getByRole('button', { name: /Set standard dashboard density/i });
        fireEvent.click(standardButton);
    });

    it('renders shared telemetry summary when history is sparse and timestamps are coincident', () => {
        const normalMetrics = createMockMetrics();
        const coincidentHistory: MetricsHistory = {
            cpu: [12.5, 12.5],
            memory: [45.0, 45.0],
            netDown: [1000, 1000],
            netUp: [500, 500],
            diskRead: [2048, 2048],
            diskWrite: [4096, 4096],
            timestamps: [1700000000000, 1700000000000],
        };

        render(
            <OverviewTab
                metrics={normalMetrics}
                hardware={mockHardware}
                history={coincidentHistory}
            />
        );

        const summaryElement = screen.getByTestId('shared-telemetry-summary');
        expect(summaryElement).toBeInTheDocument();
        expect(summaryElement).toHaveTextContent(/Collecting · 2 samples · 0s span/);
        expect(screen.getByTestId('cpu-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('memory-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('network-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('disk-io-widget')).toHaveAttribute('data-has-shared-summary', 'true');
    });

    it('omits shared telemetry summary and marks widgets unshared when history is mature', () => {
        const normalMetrics = createMockMetrics();
        const matureHistory: MetricsHistory = {
            cpu: [12.5, 25.0],
            memory: [45.0, 50.0],
            netDown: [1000, 2000],
            netUp: [500, 1000],
            diskRead: [2048, 4096],
            diskWrite: [4096, 8192],
            timestamps: [1700000000000, 1700000060000],
        };

        render(
            <OverviewTab
                metrics={normalMetrics}
                hardware={mockHardware}
                history={matureHistory}
            />
        );

        expect(screen.queryByTestId('shared-telemetry-summary')).not.toBeInTheDocument();
        expect(screen.getByTestId('cpu-widget')).toHaveAttribute('data-has-shared-summary', 'false');
        expect(screen.getByTestId('memory-widget')).toHaveAttribute('data-has-shared-summary', 'false');
        expect(screen.getByTestId('network-widget')).toHaveAttribute('data-has-shared-summary', 'false');
        expect(screen.getByTestId('disk-io-widget')).toHaveAttribute('data-has-shared-summary', 'false');
    });

    it('preserves local exception status when one metric series does not match shared timestamps length', () => {
        const normalMetrics = createMockMetrics();
        const mismatchedCpuHistory: MetricsHistory = {
            cpu: [12.5],
            memory: [45.0, 45.0],
            netDown: [1000, 1000],
            netUp: [500, 500],
            diskRead: [2048, 2048],
            diskWrite: [4096, 4096],
            timestamps: [1700000000000, 1700000000000],
        };

        render(
            <OverviewTab
                metrics={normalMetrics}
                hardware={mockHardware}
                history={mismatchedCpuHistory}
            />
        );

        expect(screen.getByTestId('shared-telemetry-summary')).toBeInTheDocument();
        expect(screen.getByTestId('cpu-widget')).toHaveAttribute('data-has-shared-summary', 'false');
        expect(screen.getByTestId('memory-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('network-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('disk-io-widget')).toHaveAttribute('data-has-shared-summary', 'true');
    });

    it('preserves local exception status when secondary netUp series does not match shared timestamps length', () => {
        const normalMetrics = createMockMetrics();
        const mismatchedNetUpHistory: MetricsHistory = {
            cpu: [12.5, 12.5],
            memory: [45.0, 45.0],
            netDown: [1000, 1000],
            netUp: [500],
            diskRead: [2048, 2048],
            diskWrite: [4096, 4096],
            timestamps: [1700000000000, 1700000000000],
        };

        render(
            <OverviewTab
                metrics={normalMetrics}
                hardware={mockHardware}
                history={mismatchedNetUpHistory}
            />
        );

        expect(screen.getByTestId('shared-telemetry-summary')).toBeInTheDocument();
        expect(screen.getByTestId('cpu-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('memory-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('network-widget')).toHaveAttribute('data-has-shared-summary', 'false');
        expect(screen.getByTestId('disk-io-widget')).toHaveAttribute('data-has-shared-summary', 'true');
    });

    it('preserves local exception status when secondary diskWrite series does not match shared timestamps length', () => {
        const normalMetrics = createMockMetrics();
        const mismatchedDiskWriteHistory: MetricsHistory = {
            cpu: [12.5, 12.5],
            memory: [45.0, 45.0],
            netDown: [1000, 1000],
            netUp: [500, 500],
            diskRead: [2048, 2048],
            diskWrite: [4096],
            timestamps: [1700000000000, 1700000000000],
        };

        render(
            <OverviewTab
                metrics={normalMetrics}
                hardware={mockHardware}
                history={mismatchedDiskWriteHistory}
            />
        );

        expect(screen.getByTestId('shared-telemetry-summary')).toBeInTheDocument();
        expect(screen.getByTestId('cpu-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('memory-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('network-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('disk-io-widget')).toHaveAttribute('data-has-shared-summary', 'false');
    });

    it('renders shared summary once with explicit UTC and dedups all qualifying widgets', () => {
        const normalMetrics = createMockMetrics();
        const coincidentTimestamp = Date.UTC(2026, 10, 7, 23, 0, 0);
        const qualifyingSparseHistory: MetricsHistory = {
            cpu: [15.2, 15.2],
            memory: [55.0, 55.0],
            netDown: [1200, 1200],
            netUp: [600, 600],
            diskRead: [1024, 1024],
            diskWrite: [2048, 2048],
            timestamps: [coincidentTimestamp, coincidentTimestamp],
        };

        render(
            <OverviewTab
                metrics={normalMetrics}
                hardware={mockHardware}
                history={qualifyingSparseHistory}
            />
        );

        const summaryElement = screen.getByTestId('shared-telemetry-summary');
        expect(summaryElement).toBeInTheDocument();
        expect(summaryElement).toHaveTextContent('Collecting · 2 samples · 0s span');
        expect(summaryElement).toHaveTextContent('Observed 23:00:00 UTC · 5m max');
        const metadataMessageElement = screen.getByText('Observed 23:00:00 UTC · 5m max');
        expect(metadataMessageElement).toHaveClass('text-xs');
        expect(metadataMessageElement).toHaveClass('text-slate-300');

        expect(screen.getByTestId('cpu-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('memory-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('network-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('disk-io-widget')).toHaveAttribute('data-has-shared-summary', 'true');
    });

    it('preserves local exception status when multiple secondary series mismatch', () => {
        const normalMetrics = createMockMetrics();
        const dualMismatchedHistory: MetricsHistory = {
            cpu: [12.5, 12.5],
            memory: [45.0, 45.0],
            netDown: [1000, 1000],
            netUp: [500],
            diskRead: [2048, 2048],
            diskWrite: [],
            timestamps: [1700000000000, 1700000000000],
        };

        render(
            <OverviewTab
                metrics={normalMetrics}
                hardware={mockHardware}
                history={dualMismatchedHistory}
            />
        );

        expect(screen.getByTestId('shared-telemetry-summary')).toBeInTheDocument();
        expect(screen.getByTestId('cpu-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('memory-widget')).toHaveAttribute('data-has-shared-summary', 'true');
        expect(screen.getByTestId('network-widget')).toHaveAttribute('data-has-shared-summary', 'false');
        expect(screen.getByTestId('disk-io-widget')).toHaveAttribute('data-has-shared-summary', 'false');
    });

    it('keeps exception triage compact and retains accessible mobile metadata without repeated standby policy', () => {
        const metricsWithException = createMockMetrics({
            qbittorrent: { status: 'error', uptime: '0m', version: '4.6.0' },
        });

        render(
            <OverviewTab
                metrics={metricsWithException}
                hardware={mockHardware}
                history={mockHistory}
            />
        );

        const hostMetadataSummary = screen.getByTestId('host-metadata-summary');
        expect(hostMetadataSummary).toHaveClass('min-h-[44px]');

        expect(screen.queryByText(/Clean stop/)).not.toBeInTheDocument();
        expect(screen.queryByText('Failure criteria')).not.toBeInTheDocument();

        const triageButton = screen.getByRole('button', { name: /Open Services tab for exception triage/i });
        expect(triageButton).toHaveClass('min-h-[44px]');

        expect(triageButton.parentElement?.parentElement).toHaveClass('flex', 'flex-wrap', 'items-center');
    });

    it('embeds stretched vitals and the system ribbon without a containing card', () => {
        const normalMetrics = createMockMetrics();

        render(
            <OverviewTab
                metrics={normalMetrics}
                hardware={mockHardware}
                history={mockHistory}
            />
        );

        const cpuWidget = screen.getByTestId('cpu-widget');
        const gridContainer = cpuWidget.parentElement;
        expect(gridContainer).toHaveClass('obs-vitals-grid', 'items-stretch', 'border-b', 'border-white/[0.07]');
        const cockpit = screen.getByRole('region', { name: 'System telemetry cockpit' });
        expect(cockpit).not.toHaveClass('obs-telemetry-surface', 'rounded-2xl', 'shadow-lg');
        expect(gridContainer?.parentElement).toBe(cockpit);
        const ribbon = screen.getByText('Uptime').parentElement?.parentElement?.parentElement;
        expect(ribbon?.parentElement).toBe(cockpit);
        expect(ribbon).toHaveClass('border-b', 'bg-white/[0.01]', 'divide-y', 'sm:divide-y-0', 'sm:divide-x', 'divide-white/[0.07]');
    });

    it('embeds every lower panel in contiguous, responsive divided bands', () => {
        const { container } = render(<OverviewTab metrics={createMockMetrics()} hardware={mockHardware} history={mockHistory} />);
        const overview = container.firstElementChild;
        const topologyBand = screen.getByTestId('topology-widget').parentElement?.parentElement;
        const resourcesBand = screen.getByTestId('storage-widget').parentElement?.parentElement;
        const planningBand = screen.getByTestId('predictions-card').parentElement?.parentElement;

        expect(overview).not.toHaveClass('space-y-5');
        expect(overview?.firstElementChild).toHaveClass('border-b', 'border-white/[0.07]', 'pb-4');
        for (const band of [topologyBand, resourcesBand, planningBand]) {
            expect(band).toHaveClass('obs-telemetry-band', 'grid', 'grid-cols-1', 'border-b', 'border-white/[0.07]', 'divide-y', 'divide-white/[0.07]', 'items-stretch');
            expect(band).not.toHaveClass('gap-4', 'rounded-2xl', 'shadow-lg');
        }
        expect(topologyBand).toHaveClass('xl:grid-cols-12', 'xl:divide-y-0', 'xl:divide-x');
        expect(topologyBand).toContainElement(screen.getByTestId('data-usage-widget'));
        expect(resourcesBand).toHaveClass('xl:grid-cols-12', 'xl:divide-y-0', 'xl:divide-x');
        expect(resourcesBand).toContainElement(screen.getByTestId('process-widget'));
        expect(planningBand).toHaveClass('lg:grid-cols-2', 'lg:divide-y-0', 'lg:divide-x');
        expect(planningBand).toContainElement(screen.getByTestId('bandwidth-card'));
        expect(screen.getByRole('region', { name: 'AI Telemetry & Capacity Planning' })).toContainElement(planningBand ?? null);
    });

    it('keeps optional panels in the same flush grid without empty columns', () => {
        const metrics = createMockMetrics();
        metrics.gpus = [{ index: 0, name: 'GPU', usage_pct: 35, memory_total: 8192, memory_used: 2048, temp: 58 }];
        const view = render(<OverviewTab metrics={metrics} hardware={mockHardware} history={mockHistory} />);

        expect(screen.getByTestId('gpu-widget').parentElement).toHaveClass('min-w-0', 'xl:col-span-4');
        expect(screen.getByTestId('storage-widget').parentElement).toHaveClass('xl:col-span-4');
        expect(screen.getByTestId('process-widget').parentElement).toHaveClass('xl:col-span-4');

        act(() => {
            useConnectionStore.setState({ showGpuWidget: false, showDataUsageWidget: false });
        });
        view.rerender(<OverviewTab metrics={metrics} hardware={mockHardware} history={mockHistory} />);

        expect(screen.queryByTestId('gpu-widget')).not.toBeInTheDocument();
        expect(screen.queryByTestId('data-usage-widget')).not.toBeInTheDocument();
        expect(screen.getByTestId('topology-widget').parentElement).toHaveClass('min-w-0', 'xl:col-span-12');
        expect(screen.getByTestId('storage-widget').parentElement).toHaveClass('xl:col-span-5');
        expect(screen.getByTestId('process-widget').parentElement).toHaveClass('xl:col-span-7');
    });

    it('keeps shared telemetry surfaces transparent and lets the band own its outer separator', () => {
        const stylesheet = readFileSync(join(__dirname, '../../app/globals.css'), 'utf8');
        const surface = stylesheet.match(/\.obs-telemetry-surface\s*\{([^}]+)\}/)?.[1];
        const surfaceEdge = stylesheet.match(/\.obs-telemetry-surface::after\s*\{([^}]+)\}/)?.[1];
        const embeddedSurface = stylesheet.match(/\.obs-telemetry-band > div > \.obs-telemetry-surface\s*\{([^}]+)\}/)?.[1];

        expect(surface).toContain('background: transparent;');
        expect(surface).toContain('backdrop-filter: none;');
        expect(surface).toContain('border: 0;');
        expect(surface).toContain('border-bottom: 1px solid rgba(255, 255, 255, 0.07);');
        expect(surface).toContain('border-radius: 0;');
        expect(surface).toContain('box-shadow: none;');
        expect(surfaceEdge).toContain('content: none;');
        expect(surfaceEdge).not.toMatch(/mask|gradient/);
        expect(embeddedSurface).toContain('border-bottom: 0;');
    });
});

describe('Header command shortcut hints', () => {
    afterEach(() => jest.restoreAllMocks());

    it.each([
        ['Linux x86_64', 'Ctrl+K'],
        ['Win32', 'Ctrl+K'],
        ['MacIntel', '⌘K'],
        ['iPad', '⌘K'],
    ])('matches its title and keyboard badge on %s', (platform, shortcut) => {
        jest.spyOn(window.navigator, 'platform', 'get').mockReturnValue(platform);
        render(<Header />);
        const commandButton = screen.getByRole('button', { name: 'Open Command Palette' });
        expect(commandButton).toHaveAttribute('title', `Command Palette (${shortcut})`);
        expect(commandButton.querySelector('kbd')).toHaveTextContent(shortcut);
    });
});
