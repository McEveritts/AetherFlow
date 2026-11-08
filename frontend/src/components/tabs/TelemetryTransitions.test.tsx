import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { mutate, SWRConfig } from 'swr';
import ServicesTab from './ServicesTab';
import StreamingTab, { type StreamingDashboardData } from './StreamingTab';
import { fetcher } from '@/lib/fetcher';
import { useHistoryStore } from '@/store/useHistoryStore';

const mockToast = jest.fn();

jest.mock('@/contexts/AuthContext', () => ({
    useAuth: () => ({ user: { id: 1, username: 'operator', role: 'admin' }, isAuthenticated: true }),
}));

jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({ addToast: mockToast }),
}));

jest.mock('@/lib/fetcher', () => ({ fetcher: jest.fn(), apiFetch: jest.fn() }));
jest.mock('@/components/streaming/StreamingHistoryExplorer', () => () => null);
jest.mock('@/components/ingress/ExternalAccessCard', () => ({ ExternalAccessCard: () => null }));
jest.mock('@/components/deploy/DeploymentStatus', () => ({ DeploymentStatus: () => null }));

function pendingRequest<Value>() {
    let resolveRequest!: (value: Value) => void;
    let rejectRequest!: (reason: Error) => void;
    const promise = new Promise<Value>((resolve, reject) => {
        resolveRequest = resolve;
        rejectRequest = reject;
    });
    return { promise, resolve: resolveRequest, reject: rejectRequest };
}

function streamingSnapshot(windowDays: number, totalDataUsedBytes: number): StreamingDashboardData {
    return {
        servers: [{
            provider: 'jellyfin', name: 'Jellyfin', url: '', apiKeyMasked: '', configured: true,
            enabled: true, status: 'connected', supportStage: 'active', serverId: 'server', version: '',
            operatingSystem: '', lastConnectedAt: '', libraryCounts: { movies: 0, series: 0, episodes: 0, audio: 0 },
        }],
        liveSummary: {
            activeStreams: 0, directPlayCount: 0, directStreamCount: 0, transcodeCount: 0,
            totalBitrateBps: 0, totalBandwidthMbps: 0, activeSessionBytes: 0, lanStreams: 0,
            wanStreams: 0, isDemoMode: false,
        },
        activeSessions: [],
        analytics: {
            windowDays, totalPlays: 0, totalWatchTimeSecs: 0, totalDataUsedBytes, uniqueUsers: 0,
            uniqueTitles: 0, avgCompletionPct: 0, peakBandwidthMbps: 0,
            streamTypes: { directPlayCount: 0, directPlayPct: 0, directStreamCount: 0, directStreamPct: 0, transcodeCount: 0, transcodePct: 0 },
            mediaTypeBreakdown: [], resolutionBreakdown: [], codecBreakdown: [], timeSeries: [],
            topUsers: [], topTitles: [], recentHistory: [],
        },
        updatedAt: '2026-11-08T00:00:00Z',
    };
}

describe('real SWR telemetry transitions', () => {
    afterEach(() => {
        jest.mocked(fetcher).mockReset();
        useHistoryStore.getState().resetHistory();
    });

    it('moves from initial inventory failure through retry and preserves newer WebSocket evidence after a refresh failure', async () => {
        const initial = pendingRequest<Record<string, unknown>>();
        const retry = pendingRequest<Record<string, unknown>>();
        const refresh = pendingRequest<Record<string, unknown>>();
        const recovery = pendingRequest<Record<string, unknown>>();
        const inventoryFetcher = jest.fn()
            .mockReturnValueOnce(initial.promise)
            .mockReturnValueOnce(retry.promise)
            .mockReturnValueOnce(refresh.promise)
            .mockReturnValueOnce(recovery.promise);
        const rendered = render(
            <SWRConfig value={{ fetcher: inventoryFetcher, dedupingInterval: 0, revalidateOnFocus: false }}>
                <ServicesTab />
            </SWRConfig>
        );

        expect(screen.getByRole('status', { name: 'Loading service inventory' })).toBeInTheDocument();
        await act(async () => { initial.reject(new Error('inventory offline')); });
        expect(await screen.findByRole('alert')).toHaveTextContent('Service inventory unavailable');
        expect(screen.queryByText('No Services Detected')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Retry service inventory' }));
        await waitFor(() => expect(inventoryFetcher).toHaveBeenCalledTimes(2));
        await act(async () => { retry.resolve({}); });
        expect(await screen.findByText('No Services Detected')).toBeInTheDocument();

        const original = { Sonarr: { id: 'sonarr', process: 'sonarr', status: 'running', version: '1.0.0', uptime: '1h', managed_by: 'systemd' } };
        await act(async () => { useHistoryStore.getState().syncServices(original); });
        expect(await screen.findByRole('article', { name: 'Sonarr service' })).toHaveTextContent('v1.0.0');

        let refreshResult: Promise<unknown> | undefined;
        act(() => { refreshResult = mutate('/api/v1/auth/services'); });
        await waitFor(() => expect(inventoryFetcher).toHaveBeenCalledTimes(3));
        await act(async () => { refresh.reject(new Error('refresh offline')); await refreshResult; });
        expect(await screen.findByText(/Service refresh failed/)).toBeInTheDocument();
        expect(screen.getByRole('article', { name: 'Sonarr service' })).toHaveTextContent('v1.0.0');

        const newer = { Sonarr: { ...original.Sonarr, version: '2.0.0' } };
        await act(async () => { useHistoryStore.getState().syncServices(newer); });
        await waitFor(() => expect(screen.getByRole('article', { name: 'Sonarr service' })).toHaveTextContent('v2.0.0'));
        expect(screen.getByText(/Service refresh failed/)).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
        await act(async () => { recovery.resolve(newer); });
        await waitFor(() => expect(screen.queryByText(/Service refresh failed/)).not.toBeInTheDocument());
        rendered.unmount();
        await mutate('/api/v1/auth/services', undefined, false);
    });

    it('never relabels an old cohort during window, method, or media changes and retains only same-key refresh data', async () => {
        const initial = pendingRequest<StreamingDashboardData>();
        const windowRequest = pendingRequest<StreamingDashboardData>();
        const retry = pendingRequest<StreamingDashboardData>();
        const methodRequest = pendingRequest<StreamingDashboardData>();
        const mediaRequest = pendingRequest<StreamingDashboardData>();
        const refresh = pendingRequest<StreamingDashboardData>();
        jest.mocked(fetcher)
            .mockReturnValueOnce(initial.promise)
            .mockReturnValueOnce(windowRequest.promise)
            .mockReturnValueOnce(retry.promise)
            .mockReturnValueOnce(methodRequest.promise)
            .mockReturnValueOnce(mediaRequest.promise)
            .mockReturnValueOnce(refresh.promise);
        render(
            <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, revalidateOnFocus: false }}>
                <StreamingTab />
            </SWRConfig>
        );

        expect(screen.getByText('Loading live stream telemetry…')).toBeInTheDocument();
        expect(screen.queryByText(/Connect Your Jellyfin Server/i)).not.toBeInTheDocument();
        expect(screen.queryByText('Active streams:')).not.toBeInTheDocument();
        await act(async () => { initial.resolve(streamingSnapshot(30, 1024 ** 3)); });
        expect((await screen.findAllByText('1 GB')).length).toBeGreaterThan(0);

        fireEvent.click(within(screen.getByRole('group', { name: 'Time Window Filter' })).getByRole('button', { name: '7 Days' }));
        expect(screen.getByText(/Loading analytics for 7 Days/)).toBeInTheDocument();
        expect(screen.queryByText('1 GB')).not.toBeInTheDocument();
        expect(screen.queryByText(/Connect Your Jellyfin Server/i)).not.toBeInTheDocument();
        await act(async () => { windowRequest.reject(new Error('cohort offline')); });
        expect(await screen.findByText(/Analytics for the selected filters are unavailable/)).toBeInTheDocument();
        expect(screen.queryByText('1 GB')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Retry Refresh' }));
        await act(async () => { retry.resolve(streamingSnapshot(7, 2 * 1024 ** 3)); });
        expect((await screen.findAllByText('2 GB')).length).toBeGreaterThan(0);

        fireEvent.click(within(screen.getByRole('group', { name: 'Play Method Filter' })).getByRole('button', { name: 'Direct Play' }));
        expect(screen.getByText(/Loading analytics for 7 Days, Direct Play/)).toBeInTheDocument();
        expect(screen.queryByText('2 GB')).not.toBeInTheDocument();
        await act(async () => { methodRequest.resolve(streamingSnapshot(7, 3 * 1024 ** 3)); });
        expect((await screen.findAllByText('3 GB')).length).toBeGreaterThan(0);

        fireEvent.click(within(screen.getByRole('group', { name: 'Media Type Filter' })).getByRole('button', { name: 'Episodes' }));
        expect(screen.getByText(/Loading analytics for 7 Days, Direct Play, Episodes/)).toBeInTheDocument();
        expect(screen.queryByText('3 GB')).not.toBeInTheDocument();
        await act(async () => { mediaRequest.resolve(streamingSnapshot(7, 4 * 1024 ** 3)); });
        expect((await screen.findAllByText('4 GB')).length).toBeGreaterThan(0);

        fireEvent.click(screen.getByRole('button', { name: 'Refresh Streaming Telemetry' }));
        expect(screen.getAllByText('4 GB').length).toBeGreaterThan(0);
        await act(async () => { refresh.reject(new Error('same cohort refresh offline')); });
        expect(await screen.findByText(/Showing Cached Snapshot/)).toBeInTheDocument();
        expect(screen.getAllByText('4 GB').length).toBeGreaterThan(0);
        expect(jest.mocked(fetcher).mock.calls.map(([key]) => key)).toEqual(expect.arrayContaining([
            expect.stringContaining('window=7&playMethod=DirectPlay&mediaType=Episode'),
        ]));
    });

    it('shows a WebSocket snapshot received during the initial inventory request without replacing it with the older response', async () => {
        const initial = pendingRequest<Record<string, unknown>>();
        const inventoryFetcher = jest.fn().mockReturnValueOnce(initial.promise);
        const rendered = render(
            <SWRConfig value={{ fetcher: inventoryFetcher, dedupingInterval: 0, revalidateOnFocus: false }}>
                <ServicesTab />
            </SWRConfig>
        );
        await waitFor(() => expect(inventoryFetcher).toHaveBeenCalledTimes(1));
        const newer = { Radarr: { id: 'radarr', process: 'radarr', status: 'running', version: '3.0.0', uptime: '1h', managed_by: 'systemd' } };
        await act(async () => { useHistoryStore.getState().syncServices(newer); });
        expect(await screen.findByRole('article', { name: 'Radarr service' })).toHaveTextContent('v3.0.0');
        await act(async () => { initial.resolve({ Radarr: { ...newer.Radarr, version: '2.0.0' } }); });
        expect(screen.getByRole('article', { name: 'Radarr service' })).toHaveTextContent('v3.0.0');
        rendered.unmount();
        await mutate('/api/v1/auth/services', undefined, false);
    });
});
