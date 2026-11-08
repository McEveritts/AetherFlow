import React from 'react';
import { render, screen, fireEvent, within, act } from '@testing-library/react';
import AppTopologyMap, { computeTopologyLayout, formatTopologyLabel } from '@/components/widgets/AppTopologyMap';
import { SystemMetrics } from '@/types/dashboard';
import { useSystemStore } from '@/store/useSystemStore';
import * as d3 from 'd3';

jest.mock('d3', () => {
    const mockSelection = {
        attr: jest.fn().mockReturnThis(),
        style: jest.fn().mockReturnThis(),
        call: jest.fn().mockReturnThis(),
        select: jest.fn().mockReturnThis(),
        selectAll: jest.fn().mockReturnThis(),
        data: jest.fn().mockReturnThis(),
        join: jest.fn().mockReturnThis(),
        append: jest.fn().mockReturnThis(),
        text: jest.fn().mockReturnThis(),
        on: jest.fn().mockReturnThis(),
        empty: jest.fn().mockReturnValue(false),
        transition: jest.fn().mockReturnThis(),
        duration: jest.fn().mockReturnThis(),
        html: jest.fn().mockReturnThis(),
    };
    const mockForceLink = {
        id: jest.fn().mockReturnThis(),
        distance: jest.fn().mockReturnThis(),
        strength: jest.fn().mockReturnThis(),
        links: jest.fn().mockReturnThis(),
    };
    const forcesMap: Record<string, unknown> = {
        link: mockForceLink,
    };
    const mockSimulation: {
        force: jest.Mock;
        nodes: jest.Mock;
        alpha: jest.Mock;
        alphaMin: jest.Mock;
        alphaTarget: jest.Mock;
        restart: jest.Mock;
        stop: jest.Mock;
        on: jest.Mock;
    } = {
        force: jest.fn((name: string, forceInstance?: unknown) => {
            if (forceInstance !== undefined) {
                forcesMap[name] = forceInstance;
                return mockSimulation;
            }
            return forcesMap[name];
        }),
        nodes: jest.fn().mockReturnThis(),
        alpha: jest.fn().mockReturnThis(),
        alphaMin: jest.fn().mockReturnValue(0.001),
        alphaTarget: jest.fn().mockReturnThis(),
        restart: jest.fn().mockReturnThis(),
        stop: jest.fn().mockReturnThis(),
        on: jest.fn().mockReturnThis(),
    };
    return {
        select: jest.fn(() => mockSelection),
        selectAll: jest.fn(() => mockSelection),
        zoom: jest.fn(() => ({
            scaleExtent: jest.fn().mockReturnThis(),
            on: jest.fn().mockReturnThis(),
            scaleBy: jest.fn(),
            transform: jest.fn(),
        })),
        zoomIdentity: {},
        forceSimulation: jest.fn(() => mockSimulation),
        forceLink: jest.fn(() => mockForceLink),
        forceManyBody: jest.fn(() => ({
            strength: jest.fn().mockReturnThis(),
        })),
        forceCenter: jest.fn(() => ({})),
        forceX: jest.fn(() => ({ strength: jest.fn().mockReturnThis() })),
        forceY: jest.fn(() => ({ strength: jest.fn().mockReturnThis() })),
        forceCollide: jest.fn(() => ({
            radius: jest.fn().mockReturnThis(),
        })),
        drag: jest.fn(() => ({
            on: jest.fn().mockReturnThis(),
        })),
    };
});

jest.mock('swr', () => ({
    __esModule: true,
    default: jest.fn(() => ({
        data: {
            nodes: [
                { id: 'AetherFlow API', group: 1, status: 'running' },
                { id: 'qbittorrent', group: 4, status: 'error' },
                { id: 'jellyfin', group: 4, status: 'running' },
                { id: 'sonarr', group: 4, status: 'stopped' },
            ],
            links: [
                { source: 'AetherFlow API', target: 'qbittorrent', value: 1 },
                { source: 'AetherFlow API', target: 'jellyfin', value: 1 },
            ],
        },
    })),
}));

describe('AppTopologyMap', () => {
    it('packs 28 node and centered-label footprints inside mobile bounds with no overlapping cells', () => {
        const layout = computeTopologyLayout(28, 316, 300);
        expect(layout.positions).toHaveLength(28);
        for (const position of layout.positions) {
            expect(position.x - 48).toBeGreaterThanOrEqual(0);
            expect(position.x + 48).toBeLessThanOrEqual(316);
            expect(position.y - 17).toBeGreaterThanOrEqual(0);
            expect(position.y + 32).toBeLessThanOrEqual(layout.height);
        }
        layout.positions.forEach((position, nodeIndex) => {
            layout.positions.slice(nodeIndex + 1).forEach(otherPosition => {
                expect(Math.hypot(position.x - otherPosition.x, position.y - otherPosition.y)).toBeGreaterThanOrEqual(104);
            });
        });
        expect(formatTopologyLabel('a-very-long-service-label')).toBe('a-very-long-ser…');
        expect(formatTopologyLabel('Jellyfin')).toBe('Jellyfin');
    });

    it('observes graph resizing, recenters the layout, and disconnects on view changes', () => {
        const originalResizeObserver = globalThis.ResizeObserver;
        let resizeCallback: ResizeObserverCallback = () => undefined;
        const observe = jest.fn();
        const disconnect = jest.fn();
        const MockResizeObserver = jest.fn((callback: ResizeObserverCallback) => {
            resizeCallback = callback;
            return { observe, disconnect, unobserve: jest.fn() };
        });
        globalThis.ResizeObserver = MockResizeObserver;
        try {
            render(<AppTopologyMap topologyData={{ jellyfin: { status: 'running' } }} />);
            fireEvent.click(screen.getByRole('button', { name: /Show interactive topology graph/i }));
            const observedContainer = observe.mock.calls[0][0] as HTMLElement;
            const selection = jest.mocked(d3.select).mock.results.at(-1)!.value;
            const simulation = jest.mocked(d3.forceSimulation).mock.results.at(-1)!.value;
            const restart = simulation.restart as jest.Mock;
            restart.mockClear();
            const entry: ResizeObserverEntry = {
                target: observedContainer,
                contentRect: new DOMRectReadOnly(0, 0, 316, 420),
                borderBoxSize: [],
                contentBoxSize: [],
                devicePixelContentBoxSize: [],
            };
            act(() => resizeCallback([entry], {} as ResizeObserver));
            expect(selection.attr).toHaveBeenCalledWith('viewBox', [0, 0, 316, 300]);
            expect(selection.attr).toHaveBeenCalledWith('text-anchor', 'middle');
            expect(selection.attr).toHaveBeenCalledWith('dx', 0);
            expect(jest.mocked(d3.forceCollide).mock.results.at(-1)!.value.radius).toHaveBeenCalledWith(52);
            expect(restart).toHaveBeenCalled();
            for (const name of ['Zoom in', 'Zoom out', 'Reset zoom']) {
                expect(screen.getByRole('button', { name })).toHaveClass('min-h-[40px]', 'obs-touch-target-standard');
            }
            fireEvent.click(screen.getByRole('button', { name: /Show scannable service health list/i }));
            expect(disconnect).toHaveBeenCalledTimes(1);
        } finally {
            globalThis.ResizeObserver = originalResizeObserver;
        }
    });

    const sampleTopologyData: SystemMetrics['services'] = {
        qbittorrent: { status: 'error', uptime: '0m', version: '4.6.0' },
        jellyfin: { status: 'running', uptime: '3d 4h', version: '10.8.13' },
        sonarr: { status: 'stopped', uptime: '', version: '4.0.0' },
    };

    it('defaults to scannable service health list with exceptions prioritized and non-failed stopped state', () => {
        render(<AppTopologyMap topologyData={sampleTopologyData} density="compact" />);

        expect(screen.getByText('Service Health')).toBeInTheDocument();
        const healthList = screen.getByRole('list', { name: 'Managed service health' });
        expect(healthList).toHaveClass('divide-y');
        expect(within(healthList).getAllByRole('listitem')).toHaveLength(3);
        expect(healthList.closest('.obs-telemetry-surface')).toBeInTheDocument();
        expect(screen.getByText('Showing 3 of 3 services')).toBeInTheDocument();

        expect(screen.getByText('qBittorrent')).toBeInTheDocument();
        expect(screen.getByText('Failed')).toBeInTheDocument();

        expect(screen.getByText('Jellyfin')).toBeInTheDocument();
        expect(screen.getByText('Running')).toBeInTheDocument();

        expect(screen.getByText('Sonarr')).toBeInTheDocument();
        expect(screen.getByText('Stopped')).toBeInTheDocument();
        expect(screen.getByText(/Standby/)).toBeInTheDocument();

        expect(screen.getByText('Registered Services')).toBeInTheDocument();
        expect(screen.getByText('3 Services')).toBeInTheDocument();
        expect(screen.getByText('Healthy Services')).toBeInTheDocument();
        expect(screen.getByText('1 / 3 Online')).toBeInTheDocument();
    });

    it('surfaces stopped daemons with failed installations under exceptions instead of ordinary standby', () => {
        const topologyWithFailedInstall: SystemMetrics['services'] = {
            calibreweb: {
                status: 'stopped',
                uptime: '',
                version: '1.0.0',
                job_status: 'install_failed',
                last_job: { action: 'install', status: 'failed', error: 'Storage volume unmounted' },
            },
            jellyfin: { status: 'running', uptime: '1d', version: '10.8.0' },
            sonarr: { status: 'stopped', uptime: '', version: '' },
        };

        render(<AppTopologyMap topologyData={topologyWithFailedInstall} density="compact" />);

        expect(screen.getByText('Calibre-Web')).toBeInTheDocument();
        expect(screen.getByText('Install Failed')).toBeInTheDocument();
        expect(screen.getByText('Install failed: Storage volume unmounted')).toBeInTheDocument();

        expect(screen.getByText('Sonarr')).toBeInTheDocument();
        expect(screen.getByText('Standby (non-critical)')).toBeInTheDocument();
    });

    it('switches between health list and topology graph when view toggle buttons are activated', () => {
        render(<AppTopologyMap topologyData={sampleTopologyData} density="compact" />);

        expect(screen.getByText('Service Health')).toBeInTheDocument();
        expect(screen.getByText('Registered Services')).toBeInTheDocument();
        expect(screen.getByText('3 Services')).toBeInTheDocument();
        expect(screen.getByText('Healthy Services')).toBeInTheDocument();

        const graphToggleButton = screen.getByRole('button', { name: /Show interactive topology graph/i });
        fireEvent.click(graphToggleButton);

        expect(screen.getByText('Service Topology Mesh')).toBeInTheDocument();
        expect(screen.getByText('Indexed Nodes')).toBeInTheDocument();
        expect(screen.getByText('4 Nodes')).toBeInTheDocument();
        expect(screen.getByText('Healthy Daemons')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Zoom in/i })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Zoom out/i })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Reset zoom/i })).toBeInTheDocument();

        const listToggleButton = screen.getByRole('button', { name: /Show scannable service health list/i });
        fireEvent.click(listToggleButton);

        expect(screen.getByText('Service Health')).toBeInTheDocument();
        expect(screen.getByText('Registered Services')).toBeInTheDocument();
        expect(screen.getByText('3 Services')).toBeInTheDocument();
    });

    it('stops the simulation on list view and reheats it when a fresh graph is mounted', () => {
        const view = render(<AppTopologyMap topologyData={sampleTopologyData} density="compact" />);
        fireEvent.click(screen.getByRole('button', { name: /Show interactive topology graph/i }));
        const simulation = jest.mocked(d3.forceSimulation).mock.results.at(-1)?.value;
        expect(simulation).toBeDefined();
        const restart = simulation!.restart as jest.Mock;
        const stop = simulation!.stop as jest.Mock;
        expect(restart).toHaveBeenCalled();
        restart.mockClear();
        stop.mockClear();
        fireEvent.click(screen.getByRole('button', { name: /Show scannable service health list/i }));
        expect(stop).toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: /Show interactive topology graph/i }));
        expect(simulation!.alpha).toHaveBeenCalledWith(0.3);
        expect(restart).toHaveBeenCalledTimes(1);
        restart.mockClear();
        view.rerender(<AppTopologyMap topologyData={{ ...sampleTopologyData }} density="compact" />);
        expect(restart).not.toHaveBeenCalled();
        view.unmount();
        expect(stop).toHaveBeenCalledTimes(2);
    });

    it('provides complete-row preview with Showing X of N services and expandable page flow', () => {
        const eightServices: SystemMetrics['services'] = {
            svc1: { status: 'running', uptime: '1h', version: '1.0' },
            svc2: { status: 'running', uptime: '1h', version: '1.0' },
            svc3: { status: 'running', uptime: '1h', version: '1.0' },
            svc4: { status: 'running', uptime: '1h', version: '1.0' },
            svc5: { status: 'running', uptime: '1h', version: '1.0' },
            svc6: { status: 'running', uptime: '1h', version: '1.0' },
            svc7: { status: 'running', uptime: '1h', version: '1.0' },
            svc8: { status: 'error', uptime: '0m', version: '1.0' },
        };

        render(<AppTopologyMap topologyData={eightServices} density="compact" />);

        expect(screen.getByText('Showing 6 of 8 services')).toBeInTheDocument();
        const expandButton = screen.getByRole('button', { name: /Expand service list to show all services/i });
        expect(expandButton).toHaveTextContent('Expand All (8)');
        expect(expandButton).toHaveClass('min-h-[44px]');

        fireEvent.click(expandButton);
        expect(screen.getByText('Showing all 8 services')).toBeInTheDocument();
        const collapseButton = screen.getByRole('button', { name: /Collapse service list to preview/i });
        expect(collapseButton).toHaveTextContent('Collapse');
        expect(collapseButton).toHaveClass('min-h-[44px]');

        const viewAllButton = screen.getByRole('button', { name: /View in Services/i });
        expect(viewAllButton).toHaveClass('min-h-[44px]');
        fireEvent.click(viewAllButton);
        expect(useSystemStore.getState().activeTab).toBe('services');
    });

    it('discovers canonical AetherFlow API once and maintains honest node and service counts', () => {
        const servicesWithApi: SystemMetrics['services'] = {
            'aetherflow-api': { status: 'running', uptime: '5d', version: '4.0.0-rc1' },
            qbittorrent: { status: 'running', uptime: '2d', version: '4.6.0' },
            jellyfin: { status: 'running', uptime: '1d', version: '10.8.13' },
            sonarr: { status: 'stopped', uptime: '', version: '4.0.0' },
        };

        render(<AppTopologyMap topologyData={servicesWithApi} density="compact" />);

        const apiElements = screen.getAllByText('AetherFlow API');
        expect(apiElements).toHaveLength(1);
        expect(screen.getByText('Core')).toBeInTheDocument();
        expect(screen.getByText('v4.0.0-rc1')).toBeInTheDocument();
        expect(screen.getAllByText('Running')).toHaveLength(3);

        expect(screen.getByText('Registered Services')).toBeInTheDocument();
        expect(screen.getByText('4 Services')).toBeInTheDocument();
        expect(screen.getByText('Healthy Services')).toBeInTheDocument();
        expect(screen.getByText('3 / 4 Online')).toBeInTheDocument();

        const graphToggleButton = screen.getByRole('button', { name: /Show interactive topology graph/i });
        fireEvent.click(graphToggleButton);

        expect(screen.getByText('Indexed Nodes')).toBeInTheDocument();
        expect(screen.getByText('4 Nodes')).toBeInTheDocument();
        expect(screen.getByText('Healthy Daemons')).toBeInTheDocument();
        expect(screen.getByText('3 / 4 Online')).toBeInTheDocument();
    });

    it('distinguishes list mode registered service counters from graph mode indexed node counters without counting host root as managed', () => {
        render(<AppTopologyMap topologyData={sampleTopologyData} density="compact" />);

        expect(screen.getByText('Registered Services')).toBeInTheDocument();
        expect(screen.getByText('3 Services')).toBeInTheDocument();
        expect(screen.queryByText('4 Services')).not.toBeInTheDocument();
        expect(screen.getByText('Healthy Services')).toBeInTheDocument();
        expect(screen.getByText('1 / 3 Online')).toBeInTheDocument();

        const graphToggleButton = screen.getByRole('button', { name: /Show interactive topology graph/i });
        fireEvent.click(graphToggleButton);

        expect(screen.getByText('Indexed Nodes')).toBeInTheDocument();
        expect(screen.getByText('4 Nodes')).toBeInTheDocument();
        expect(screen.getByText('Healthy Daemons')).toBeInTheDocument();
        expect(screen.getByText('1 / 3 Online')).toBeInTheDocument();
    });

    it('does not fabricate version 1.0 when version is omitted', () => {
        const servicesWithoutVersion: SystemMetrics['services'] = {
            'custom-worker': { status: 'running', uptime: '1h' },
        };

        render(<AppTopologyMap topologyData={servicesWithoutVersion} density="compact" />);

        expect(screen.queryByText('v1.0')).not.toBeInTheDocument();
        expect(screen.getByText('--')).toBeInTheDocument();
    });

    it('renders canonical Services friendly names and consistent Core badges for core services', () => {
        const coreServicesMap: SystemMetrics['services'] = {
            'aetherflow-frontend': { status: 'running', uptime: '3d', version: '4.0.0-rc1' },
            'apache2': { status: 'running', uptime: '10d', version: '2.4.52' },
            'radarr': { status: 'running', uptime: '1d', version: '5.2.0' },
        };

        render(<AppTopologyMap topologyData={coreServicesMap} density="compact" />);

        const frontendTitle = screen.getByText('AetherFlow Frontend');
        expect(frontendTitle).toBeInTheDocument();
        expect(frontendTitle).toHaveClass('text-sm');
        expect(frontendTitle).not.toHaveClass('truncate');
        expect(frontendTitle).toHaveClass('whitespace-normal');

        expect(screen.getByText('Apache Gateway')).toBeInTheDocument();
        expect(screen.getByText('Radarr')).toBeInTheDocument();

        const coreBadges = screen.getAllByText('Core');
        expect(coreBadges).toHaveLength(2);
        coreBadges.forEach(badge => {
            expect(badge).toHaveClass('text-xs');
        });

        const versionElement = screen.getByText('v4.0.0-rc1');
        const versionContainer = versionElement.closest('div');
        expect(versionContainer).toHaveClass('text-xs');
        expect(versionContainer).toHaveClass('text-slate-400');
    });
});
