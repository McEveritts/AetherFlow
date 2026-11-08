import React from 'react';
import { render, screen, fireEvent, within, act } from '@testing-library/react';
import StreamingTab, { StreamingDashboardData } from '@/components/tabs/StreamingTab';

// Mock ToastContext
jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: jest.fn(),
    }),
}));

// Mock AuthContext
let mockRole = 'admin';
jest.mock('@/contexts/AuthContext', () => ({
    useAuth: () => ({
        user: { id: 1, username: 'admin', role: mockRole },
    }),
}));

// Mock Recharts ResponsiveContainer for jsdom
jest.mock('recharts', () => {
    const OriginalModule = jest.requireActual('recharts');
    return {
        ...OriginalModule,
        ResponsiveContainer: ({ children }: { children: React.ReactNode }) => {
            const chartElement = React.isValidElement(children) ? children : null;
            const chartProps = (chartElement?.props || {}) as {
                syncId?: string;
                syncMethod?: string;
                children?: React.ReactNode;
            };
            const childArray = React.Children.toArray(chartProps.children);
            const xAxisElement = childArray.find(
                (childNode) => React.isValidElement(childNode) && childNode.props && 'dataKey' in (childNode.props as Record<string, unknown>) && (childNode.props as Record<string, unknown>).dataKey === 'date'
            ) as React.ReactElement<{ scale?: string; tick?: unknown; tickFormatter?: unknown }> | undefined;
            const yAxisElement = childArray.find(
                (childNode) => React.isValidElement(childNode) && childNode.props && ('domain' in (childNode.props as Record<string, unknown>) || 'ticks' in (childNode.props as Record<string, unknown>) || 'width' in (childNode.props as Record<string, unknown>))
            ) as React.ReactElement<{ tickFormatter?: (valueNumber: number) => string; width?: number; interval?: number | string; ticks?: number[] }> | undefined;
            const gridElement = childArray.find(
                (childNode) => React.isValidElement(childNode) && childNode.props && ('syncWithTicks' in (childNode.props as Record<string, unknown>) || 'strokeDasharray' in (childNode.props as Record<string, unknown>))
            ) as React.ReactElement<{ syncWithTicks?: boolean; vertical?: boolean }> | undefined;
            return (
                <div
                    data-testid="recharts-responsive-container"
                    data-sync-id={chartProps.syncId}
                    data-sync-method={chartProps.syncMethod}
                    data-grid-vertical={gridElement?.props?.vertical !== false ? 'visible' : 'hidden'}
                    data-grid-sync-with-ticks={gridElement?.props?.syncWithTicks ? 'true' : 'false'}
                    data-xaxis-scale={xAxisElement?.props?.scale}
                    data-xaxis-tick={xAxisElement?.props?.tick === false || (typeof xAxisElement?.props?.tick === 'function' && xAxisElement.props.tick({} as never) === null) ? 'hidden' : 'visible'}
                    data-xaxis-null-renderer={typeof xAxisElement?.props?.tick === 'function' && xAxisElement.props.tick({} as never) === null ? 'true' : 'false'}
                    data-xaxis-has-formatter={typeof xAxisElement?.props?.tickFormatter === 'function' ? 'true' : 'false'}
                    data-yaxis-width={yAxisElement?.props?.width}
                    data-yaxis-interval={yAxisElement?.props?.interval !== undefined ? String(yAxisElement.props.interval) : undefined}
                    data-yaxis-ticks={Array.isArray(yAxisElement?.props?.ticks) ? JSON.stringify(yAxisElement.props.ticks) : undefined}
                    data-yaxis-sample-tick={yAxisElement?.props?.tickFormatter ? yAxisElement.props.tickFormatter(80) : undefined}
                    data-yaxis-max-tick={yAxisElement?.props?.tickFormatter ? yAxisElement.props.tickFormatter(1200) : undefined}
                    style={{ width: 800, height: 300 }}
                >
                    {children}
                </div>
            );
        },
    };
});

const mockDashboardData: StreamingDashboardData = {
    servers: [
        {
            provider: 'jellyfin',
            name: 'AetherFlow-Jellyfin',
            url: 'http://127.0.0.1:8096',
            apiKeyMasked: '****8f9a',
            configured: true,
            enabled: true,
            status: 'connected',
            supportStage: 'active',
            serverId: 'jf-srv-01',
            version: '10.9.11',
            operatingSystem: 'Linux',
            lastConnectedAt: new Date().toISOString(),
            libraryCounts: {
                movies: 412,
                series: 86,
                episodes: 3490,
                audio: 1840,
            },
        },
        {
            provider: 'plex',
            name: 'Plex Media Server',
            url: '',
            apiKeyMasked: '',
            configured: false,
            enabled: false,
            status: 'coming_soon',
            supportStage: 'coming_soon',
            serverId: '',
            version: '',
            operatingSystem: '',
            lastConnectedAt: '',
            libraryCounts: { movies: 0, series: 0, episodes: 0, audio: 0 },
        },
        {
            provider: 'emby',
            name: 'Emby Server',
            url: '',
            apiKeyMasked: '',
            configured: false,
            enabled: false,
            status: 'coming_soon',
            supportStage: 'coming_soon',
            serverId: '',
            version: '',
            operatingSystem: '',
            lastConnectedAt: '',
            libraryCounts: { movies: 0, series: 0, episodes: 0, audio: 0 },
        },
    ],
    liveSummary: {
        activeStreams: 2,
        directPlayCount: 1,
        directStreamCount: 0,
        transcodeCount: 1,
        totalBitrateBps: 43200000,
        totalBandwidthMbps: 43.2,
        activeSessionBytes: 1845000000,
        lanStreams: 1,
        wanStreams: 1,
        isDemoMode: false,
    },
    activeSessions: [
        {
            sessionId: 'jf-live-1',
            supportsMediaControl: true,
            canSendMessage: true,
            provider: 'jellyfin',
            serverName: 'AetherFlow-Jellyfin',
            userId: 'u-1',
            userName: 'alex_operator',
            clientName: 'Jellyfin Media Player',
            deviceName: 'MacBook Pro M3',
            deviceId: 'dev-1',
            appVersion: '1.11.1',
            ipAddress: '10.10.0.24',
            isLan: true,
            itemId: 'item-dune-2',
            itemName: 'Dune: Part Two',
            itemType: 'Movie',
            productionYear: 2024,
            hasArtwork: false,
            state: 'playing',
            positionSecs: 4520,
            durationSecs: 9960,
            progressPct: 45.4,
            playMethod: 'DirectPlay',
            container: 'MKV',
            videoCodec: 'HEVC',
            videoResolution: '4K UHD',
            videoRange: 'HDR10 / DoVi',
            videoFramerate: 23.976,
            isVideoDirect: true,
            audioCodec: 'TRUEHD',
            audioChannels: 8,
            audioLayout: '7.1',
            isAudioDirect: true,
            subtitleCodec: 'PGSSUB',
            transcodeReasons: [],
            bitrateBps: 28400000,
            bandwidthMbps: 28.4,
            sessionDataBytes: 1420000000,
            startedAt: new Date().toISOString(),
        },
        {
            sessionId: 'jf-live-2',
            provider: 'jellyfin',
            serverName: 'AetherFlow-Jellyfin',
            userId: 'u-2',
            userName: 'sarah_stream',
            clientName: 'Swiftfin iOS',
            deviceName: 'iPhone 16 Pro',
            deviceId: 'dev-2',
            appVersion: '1.3.0',
            ipAddress: '198.51.100.42',
            isLan: false,
            itemId: 'item-severance',
            itemName: 'Hello, Ms. Cobel',
            itemType: 'Episode',
            seriesName: 'Severance',
            seasonNumber: 2,
            episodeNumber: 1,
            productionYear: 2025,
            hasArtwork: false,
            state: 'playing',
            positionSecs: 1890,
            durationSecs: 3420,
            progressPct: 55.3,
            playMethod: 'Transcode',
            container: 'MKV',
            targetContainer: 'TS',
            videoCodec: 'HEVC',
            targetVideoCodec: 'H264',
            videoResolution: '1080p',
            videoRange: 'SDR',
            isVideoDirect: false,
            audioCodec: 'EAC3',
            targetAudioCodec: 'AAC',
            audioChannels: 6,
            audioLayout: '5.1',
            isAudioDirect: false,
            subtitleCodec: 'SRT',
            hwAccel: 'VAAPI',
            transcodeReasons: ['ContainerBitrateExceedsLimit'],
            transcodeProgressPct: 68.4,
            transcodeFps: 74.2,
            bitrateBps: 14800000,
            bandwidthMbps: 14.8,
            sessionDataBytes: 425000000,
            startedAt: new Date().toISOString(),
        },
    ],
    analytics: {
        windowDays: 30,
        totalPlays: 42,
        totalWatchTimeSecs: 142000,
        totalDataUsedBytes: 98500000000,
        uniqueUsers: 4,
        uniqueTitles: 18,
        avgCompletionPct: 82.5,
        peakBandwidthMbps: 62.4,
        streamTypes: {
            directPlayCount: 27,
            directPlayPct: 64.3,
            directStreamCount: 6,
            directStreamPct: 14.3,
            transcodeCount: 9,
            transcodePct: 21.4,
        },
        mediaTypeBreakdown: [
            { label: 'Movie', count: 24, pct: 57.1, watchTimeSecs: 92000, dataUsedBytes: 72000000000 },
            { label: 'Episode', count: 18, pct: 42.9, watchTimeSecs: 50000, dataUsedBytes: 26500000000 },
        ],
        resolutionBreakdown: [
            { label: '4K UHD', count: 18, pct: 42.9, watchTimeSecs: 68000, dataUsedBytes: 64000000000 },
            { label: '1080p', count: 24, pct: 57.1, watchTimeSecs: 74000, dataUsedBytes: 34500000000 },
        ],
        codecBreakdown: [
            { label: 'HEVC', count: 28, pct: 66.7, watchTimeSecs: 98000, dataUsedBytes: 76000000000 },
            { label: 'H264', count: 14, pct: 33.3, watchTimeSecs: 44000, dataUsedBytes: 22500000000 },
        ],
        timeSeries: [
            {
                date: '2026-10-28',
                plays: 6,
                watchTimeSecs: 33840,
                dataUsedBytes: 15240000000,
                peakBandwidthMbps: 48.5,
                directPlayCount: 4,
                directStreamCount: 1,
                transcodeCount: 1,
            },
        ],
        topUsers: [
            {
                userId: 'u-1',
                userName: 'alex_operator',
                provider: 'jellyfin',
                totalPlays: 19,
                totalWatchSecs: 68400,
                totalDataBytes: 52400000000,
                uniqueItems: 12,
                directPlayCount: 17,
                transcodeCount: 2,
                avgCompletionPct: 88.4,
                lastDevice: 'MacBook Pro M3',
                lastSeenAt: new Date().toISOString(),
            },
        ],
        topTitles: [
            {
                itemId: 'item-dune-2',
                itemName: 'Dune: Part Two',
                itemType: 'Movie',
                productionYear: 2024,
                provider: 'jellyfin',
                videoResolution: '4K UHD',
                videoCodec: 'HEVC',
                totalPlays: 8,
                uniqueViewers: 3,
                totalWatchSecs: 42000,
                totalDataBytes: 38400000000,
                avgCompletionPct: 91.2,
                lastWatchedAt: new Date().toISOString(),
            },
        ],
        recentHistory: [
            {
                id: 1,
                sessionKey: 'hist-1',
                provider: 'jellyfin',
                serverName: 'AetherFlow-Jellyfin',
                userName: 'alex_operator',
                clientName: 'Jellyfin Media Player',
                deviceName: 'MacBook Pro M3',
                ipAddress: '10.10.0.24',
                itemId: 'item-dune-2',
                itemName: 'Dune: Part Two',
                itemType: 'Movie',
                productionYear: 2024,
                playMethod: 'DirectPlay',
                container: 'MKV',
                videoCodec: 'HEVC',
                videoResolution: '4K UHD',
                audioCodec: 'TRUEHD',
                audioChannels: 8,
                bitrateBps: 28400000,
                bandwidthMbps: 28.4,
                durationSecs: 9960,
                watchedSecs: 9900,
                dataUsedBytes: 3420000000,
                completionPct: 99.4,
                startedAt: new Date().toISOString(),
                lastSeenAt: new Date().toISOString(),
                isActive: false,
            },
            {
                id: 2,
                sessionKey: 'hist-2-legacy',
                provider: 'jellyfin',
                serverName: 'AetherFlow-Jellyfin',
                userName: 'sarah_stream',
                clientName: 'Swiftfin iOS',
                deviceName: 'iPhone 16 Pro',
                ipAddress: '198.51.100.42',
                itemId: 'item-severance',
                itemName: 'Hello, Ms. Cobel',
                itemType: 'Episode',
                seriesName: 'Severance',
                seasonNumber: 2,
                episodeNumber: 1,
                productionYear: 2025,
                playMethod: 'Transcode',
                container: 'TS',
                videoCodec: 'H264',
                videoResolution: '1080p FHD',
                audioCodec: 'AAC',
                audioChannels: 2,
                hwAccel: 'NVENC',
                bitrateBps: 8400000,
                bandwidthMbps: undefined as unknown as number,
                durationSecs: 3300,
                watchedSecs: 1650,
                dataUsedBytes: 1732500000,
                completionPct: 50.0,
                startedAt: new Date().toISOString(),
                lastSeenAt: new Date().toISOString(),
                isActive: false,
            },
        ],
    },
    updatedAt: new Date().toISOString(),
};

// Mock SWR with Jellyfin streaming dashboard fixture
const mockMutate = jest.fn();
let currentSwrState: {
    data: StreamingDashboardData | null;
    error: Error | null;
    isLoading: boolean;
    isValidating?: boolean;
    mutate: jest.Mock;
} = {
    data: mockDashboardData,
    error: null,
    isLoading: false,
    isValidating: false,
    mutate: mockMutate,
};
let lastSwrKey = '';

jest.mock('swr', () => {
    return jest.fn((key: string) => {
        if (key && key.includes('/streaming/dashboard')) {
            lastSwrKey = key;
            return currentSwrState;
        }
        return { data: null, error: null, isLoading: false, mutate: mockMutate };
    });
});

import {
    buildStreamingHistoryCsv,
    escapeStreamingCsvCell,
    evaluateSessionCapabilities,
    recomputeLiveSummaryFromSessions,
    isHistoricalSyncEntry,
    parseStreamingTimestamp,
    formatStreamingBucket,
} from '@/lib/streaming';
import { waitFor } from '@testing-library/react';

describe('StreamingTab - Jellyfin Play Statistics, Data Usage & Stream Telemetry', () => {
    it('withholds server-wide KPIs and onboarding from ordinary viewers', () => {
        mockRole = 'user';
        render(<StreamingTab />);
        expect(screen.getByText(/Server-wide live telemetry is withheld/)).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /Configure Server/ })).not.toBeInTheDocument();
        expect(screen.queryByText('Streaming Dashboard')).not.toBeInTheDocument();
    });

    it('requires explicit media-control evidence even with remote and transcode fallback hints', () => {
        const session = { ...mockDashboardData.activeSessions[0], supportsMediaControl: undefined, supportsRemoteControl: true, playSessionId: 'active', playMethod: 'Transcode' as const };
        expect(evaluateSessionCapabilities(session).stop.supported).toBe(false);
        expect(evaluateSessionCapabilities(session).message.supported).toBe(false);
    });

    it('names, traps, Escape-dismisses and restores focus for both dialogs', () => {
        render(<StreamingTab />);
        const config = screen.getByRole('button', { name: /Configure Server/ });
        config.focus();
        fireEvent.click(config);
        const dialog = screen.getByRole('dialog', { name: 'Media Server Providers' });
        expect(dialog).toHaveAttribute('aria-modal', 'true');
        expect(dialog).toContainElement(document.activeElement as HTMLElement);
        const controls = within(dialog).getAllByRole('button');
        controls[controls.length - 1].focus();
        fireEvent.keyDown(document, { key: 'Tab' });
        expect(controls[0]).toHaveFocus();
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(config).toHaveFocus();
        const message = screen.getAllByRole('button', { name: /^Message$/ })[0];
        message.focus();
        fireEvent.click(message);
        expect(screen.getByRole('dialog', { name: /Message alex_operator/ })).toContainElement(document.activeElement as HTMLElement);
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(message).toHaveFocus();
    });

    it('routes staged Emby config and preserves later edits during a pending save', async () => {
        let resolveSave!: (value: Response) => void;
        const fetchSpy = jest.spyOn(global, 'fetch').mockImplementation(async (input) => {
            if (String(input).includes('/servers/emby')) return new Promise<Response>(resolve => { resolveSave = resolve; });
            if (String(input).includes('csrf-token')) return { ok: true, json: async () => ({ csrf_token: 'streaming-test-csrf' }) } as Response;
            return { ok: false, status: 401, json: async () => ({ error: 'test read unavailable' }) } as Response;
        });
        render(<StreamingTab />);
        fireEvent.click(screen.getByRole('button', { name: /Configure Server/ }));
        fireEvent.change(within(screen.getByRole('dialog')).getByLabelText('Provider'), { target: { value: 'emby' } });
        fireEvent.change(screen.getByLabelText('Server Display Name'), { target: { value: 'Emby draft' } });
        fireEvent.change(screen.getByLabelText('Emby Server URL'), { target: { value: 'http://127.0.0.1:8097' } });
        fireEvent.click(screen.getByRole('button', { name: /Save Connection/ }));
        await waitFor(() => expect(resolveSave).toBeDefined());
        const saveCall = fetchSpy.mock.calls.find(([input]) => String(input).includes('/servers/emby'));
        expect(JSON.parse(String(saveCall?.[1]?.body))).toMatchObject({ name: 'Emby draft', enabled: false, apiKey: '' });
        fireEvent.change(screen.getByLabelText('Server Display Name'), { target: { value: 'Newer Emby draft' } });
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(screen.getByRole('dialog')).toBeInTheDocument();
        await act(async () => resolveSave({ ok: true, json: async () => ({ server: { status: 'disabled' } }) } as Response));
        expect(screen.getByLabelText('Server Display Name')).toHaveValue('Newer Emby draft');
        fetchSpy.mockRestore();
    });

    beforeEach(() => {
        jest.clearAllMocks();
        mockRole = 'admin';
        currentSwrState = {
            data: JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData,
            error: null,
            isLoading: false,
            isValidating: false,
            mutate: mockMutate,
        };
        lastSwrKey = '';
        currentSwrState.data?.activeSessions.forEach(session => { session.supportsMediaControl = true; session.canSendMessage = true; });
    });

    it('renders Jellyfin online status alongside single neutral planned integration treatment in configuration modal', () => {
        render(<StreamingTab />);
        expect(screen.getByText(/Streaming Dashboard/i)).toBeInTheDocument();
        expect(screen.getByText(/Jellyfin v10\.9\.11/i)).toBeInTheDocument();
        expect(screen.queryByText(/Plex · Later/i)).not.toBeInTheDocument();
        expect(screen.queryByText(/Emby · Later/i)).not.toBeInTheDocument();
        expect(screen.queryByText('Planned integrations:')).not.toBeInTheDocument();
        expect(screen.queryByText(/Plex \(Planned\)/i)).not.toBeInTheDocument();
        expect(screen.queryByText(/Emby \(Planned\)/i)).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /Configure Server/i }));
        expect(screen.getByText(/Media Server Providers/i)).toBeInTheDocument();
        expect(screen.getByText(/Planned integration · X-Plex-Token session adapter/i)).toBeInTheDocument();
        expect(screen.getByText(/Planned integration · Staged telemetry/i)).toBeInTheDocument();
    });

    it.each(['Dashboard', 'Playback Analytics', 'Watch History'])('keeps the paginated archive below the primary sections in %s', (view) => {
        render(<StreamingTab />);
        fireEvent.click(screen.getByRole('button', { name: view }));

        const explorer = screen.getByText('Canonical Streaming History Explorer').closest('section')!;
        const filters = screen.getByRole('group', { name: 'Time Window Filter' });
        expect(filters.compareDocumentPosition(explorer) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

        const primarySections = view === 'Watch History'
            ? [/Playback & Stream Data Usage Log/i]
            : [
                /Stream Data Usage & Bandwidth Over Time/i,
                /Play Sessions & Watch Time Activity/i,
                /Play Method Breakdown/i,
                /Resolution (Mix|& Bandwidth Share)/i,
                /Source Codec Telemetry/i,
                /Top Watchers & Data Usage by User/i,
                /Most Watched Media Titles/i,
                ...(view === 'Dashboard' ? [/Playback & Stream Data Usage Log/i] : []),
            ];
        for (const title of primarySections) {
            expect(screen.getByText(title).compareDocumentPosition(explorer) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
        }
        expect(explorer.nextElementSibling).toBeNull();
        expect(screen.getByRole('button', { name: 'Previous history page' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Next history page' })).toBeInTheDocument();
    });

    it('renders real-time bandwidth, data usage, and play statistics KPI cards', () => {
        render(<StreamingTab />);
        expect(screen.getByText(/Active Streams/i)).toBeInTheDocument();
        expect(screen.getByText(/Live Bandwidth/i)).toBeInTheDocument();
        expect(screen.getByText(/Data Usage \(30d\)/i)).toBeInTheDocument();
        expect(screen.getByText(/Confirmed Play Statistics \(30d\)/i)).toBeInTheDocument();
        expect(screen.getByText(/Jellyfin Library/i)).toBeInTheDocument();
    });

    it('keeps imported estimates visible alongside confirmed statistics and preserves member privacy', () => {
        const customData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        customData.analytics.historicalEstimates = [{
            provenance: 'legacy_unverified', records: 842, reportedWatchTimeSecs: 1811081,
            undatedRecords: 0, timeSeries: [{ date: '2026-10-27', watchTimeSecs: 1811081 }],
        }];
        currentSwrState = { ...currentSwrState, data: customData };
        const { rerender } = render(<StreamingTab />);
        expect(screen.getByRole('region', { name: 'Imported watch history' })).toHaveTextContent('503h 4m');
        expect(screen.getByText(/Confirmed Play Statistics/)).toBeInTheDocument();
        mockRole = 'user';
        rerender(<StreamingTab />);
        expect(screen.queryByRole('region', { name: 'Imported watch history' })).not.toBeInTheDocument();
    });

    it('renders active stream cards with codec pipeline, Direct Play / Transcode badges, and session data usage', () => {
        render(<StreamingTab />);
        expect(screen.getAllByText(/Dune: Part Two/i).length).toBeGreaterThan(0);
        expect(screen.getAllByText(/Severance/i).length).toBeGreaterThan(0);
        expect(screen.getByText(/Transcode · VAAPI/i)).toBeInTheDocument();
        expect(screen.getByText(/Container Bitrate Exceeds Limit/i)).toBeInTheDocument();
    });

    it('renders watch history rows and safely falls back to bitrateBps when bandwidthMbps is omitted', () => {
        render(<StreamingTab />);
        expect(screen.getByText(/Playback & Stream Data Usage Log/i)).toBeInTheDocument();
        expect(screen.getAllByText('28.4 Mbps').length).toBeGreaterThan(0);
        expect(screen.getByText('8.4 Mbps')).toBeInTheDocument();
    });

    it('opens the Jellyfin connection configuration modal when Configure Server button is clicked', () => {
        render(<StreamingTab />);
        const configBtn = screen.getByRole('button', { name: /Configure Server/i });
        fireEvent.click(configBtn);
        expect(screen.getByText(/Media Server Providers/i)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Test Connection/i })).toBeInTheDocument();
        expect(screen.getByLabelText(/Server Display Name/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/Jellyfin Server URL/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/Jellyfin API Key/i)).toBeInTheDocument();
    });

    it('disables unsupported session control buttons when capabilities report false or non-Jellyfin provider', () => {
        const customData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        // Session 1: DirectPlay with supportsMediaControl=false, supportsRemoteControl=false, canSendMessage=false
        customData.activeSessions[0].supportsMediaControl = false;
        customData.activeSessions[0].supportsRemoteControl = false;
        customData.activeSessions[0].canSendMessage = false;
        customData.activeSessions[0].playSessionId = '';
        // Session 2: Transcode with supportsMediaControl=false -> Pause & Message disabled, but Stop enabled via Transcode fallback
        customData.activeSessions[1].supportsMediaControl = false;
        customData.activeSessions[1].supportsRemoteControl = false;
        customData.activeSessions[1].canSendMessage = false;

        currentSwrState = {
            ...currentSwrState,
            data: customData,
        };

        render(<StreamingTab />);

        const pauseBtns = screen.getAllByRole('button', { name: /^Pause$/i });
        const stopBtns = screen.getAllByRole('button', { name: /^Stop$/i });
        const messageBtns = screen.getAllByRole('button', { name: /^Message$/i });

        // Both sessions have supportsMediaControl=false, so Pause and Message must be disabled on both
        expect(pauseBtns[0]).toBeDisabled();
        expect(pauseBtns[1]).toBeDisabled();
        expect(messageBtns[0]).toBeDisabled();
        expect(messageBtns[1]).toBeDisabled();

        // Session 0 is DirectPlay without media/remote control or playSessionId -> Stop is disabled
        expect(stopBtns[0]).toBeDisabled();
        // Session 1 is Transcode -> Stop remains enabled via active transcode termination fallback
        expect(stopBtns[1]).toBeDisabled();

        // Verify non-Jellyfin provider disables all actions
        const plexCaps = evaluateSessionCapabilities({
            ...customData.activeSessions[1],
            provider: 'plex',
            supportsMediaControl: true,
        });
        expect(plexCaps.pause.supported).toBe(false);
        expect(plexCaps.stop.supported).toBe(false);
        expect(plexCaps.message.supported).toBe(false);
    });

    it('surfaces provider badge and concise read-only telemetry state for unsupported provider sessions', () => {
        const customData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        customData.activeSessions[0].provider = 'plex';
        currentSwrState = {
            ...currentSwrState,
            data: customData,
        };
        render(<StreamingTab />);
        const sessionCards = within(screen.getByTestId('active-sessions-grid')).getAllByRole('article');
        expect(within(sessionCards[0]).getByText('Plex')).toBeInTheDocument();
        expect(screen.getByText(/Read-only stream telemetry · Remote control unsupported for Plex/i)).toBeInTheDocument();
        expect(screen.getByText('Read-Only')).toBeInTheDocument();
        expect(screen.getByTitle('Session control is not supported for provider "plex"')).toBeInTheDocument();
        expect(within(sessionCards[0]).queryByRole('button', { name: /^Pause$/i })).not.toBeInTheDocument();
        expect(within(sessionCards[0]).queryByRole('button', { name: /^Resume$/i })).not.toBeInTheDocument();
        expect(within(sessionCards[0]).queryByRole('button', { name: /^Stop$/i })).not.toBeInTheDocument();
        expect(within(sessionCards[0]).queryByRole('button', { name: /^Message$/i })).not.toBeInTheDocument();
    });

    it('keeps server actions expanded on desktop, collapsed on mobile, and responsive to breakpoint changes', () => {
        type MatchMediaListener = (event: MediaQueryListEvent) => void;
        let registeredListener: MatchMediaListener | null = null;
        let currentMatches = false;

        const mockMatchMedia = jest.fn().mockImplementation((query: string) => ({
            matches: currentMatches,
            media: query,
            onchange: null,
            addListener: jest.fn((listener: MatchMediaListener) => { registeredListener = listener; }),
            removeListener: jest.fn(),
            addEventListener: jest.fn((eventType: string, listener: MatchMediaListener) => {
                if (eventType === 'change') registeredListener = listener;
            }),
            removeEventListener: jest.fn(),
            dispatchEvent: jest.fn(),
        }));

        const originalMatchMedia = window.matchMedia;
        window.matchMedia = mockMatchMedia;

        try {
            const { unmount } = render(<StreamingTab />);
            const summary = screen.getByText('Server & Provider Actions').closest('summary')!;
            const details = summary.closest('details')!;

            expect(details).not.toHaveAttribute('open');
            expect(summary).toHaveClass('min-h-[44px]');

            fireEvent.click(summary);
            expect(details).toHaveAttribute('open');

            if (registeredListener) {
                act(() => {
                    currentMatches = true;
                    registeredListener!({ matches: true } as MediaQueryListEvent);
                });
                expect(details).toHaveAttribute('open');
            }

            unmount();
        } finally {
            window.matchMedia = originalMatchMedia;
        }
    });

    it('optimistically recomputes liveSummary bandwidth and stream counts when stopping a session', async () => {
        const fetchSpy = jest.spyOn(global, 'fetch').mockImplementation(async (input: RequestInfo | URL) => {
            const url = String(input);
            if (url.includes('csrf-token')) {
                return {
                    ok: true,
                    json: async () => ({ token: 'test-csrf-token' }),
                } as Response;
            }
            return {
                ok: true,
                json: async () => ({ message: 'Session stopped' }),
            } as Response;
        });

        render(<StreamingTab />);
        const stopBtns = screen.getAllByRole('button', { name: /^Stop$/i });
        fireEvent.click(stopBtns[0]);

        await waitFor(() => {
            expect(fetchSpy).toHaveBeenCalledWith(
                '/api/v1/admin/streaming/sessions/jf-live-1/command',
                expect.objectContaining({ method: 'POST' })
            );
        });

        expect(mockMutate).toHaveBeenCalled();
        const updaterFn = mockMutate.mock.calls[0][0];
        if (typeof updaterFn === 'function') {
            const nextState = updaterFn(mockDashboardData) as StreamingDashboardData;
            expect(nextState.activeSessions).toHaveLength(1);
            expect(nextState.liveSummary.activeStreams).toBe(1);
            expect(nextState.liveSummary.directPlayCount).toBe(0);
            expect(nextState.liveSummary.transcodeCount).toBe(1);
            expect(nextState.liveSummary.totalBandwidthMbps).toBe(14.8);
        }

        fetchSpy.mockRestore();
    });

    it('surfaces stale/disconnected telemetry alert banner when SWR reports a fetch error without hiding loaded data', () => {
        currentSwrState = {
            ...currentSwrState,
            error: new Error('502 Bad Gateway from upstream proxy'),
        };

        render(<StreamingTab />);
        expect(screen.getByRole('alert')).toHaveTextContent(/Streaming telemetry refresh failed/i);
        expect(screen.getByRole('alert')).toHaveTextContent(/502 Bad Gateway/i);
        // Loaded history rows remain visible rather than being hidden behind an empty table error row
        expect(screen.getAllByText(/Dune: Part Two/i).length).toBeGreaterThan(0);
    });

    it('renders Unknown badge and historical sync limitation notice for imported history rows without claiming Direct Play', () => {
        const customData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        customData.analytics.recentHistory.unshift({
            id: 99,
            sessionKey: 'jellyfin:sync:u-1:item-interstellar',
            provider: 'jellyfin',
            serverName: 'AetherFlow-Jellyfin',
            userName: 'alex_operator',
            clientName: '',
            deviceName: '',
            ipAddress: '',
            itemId: 'item-interstellar',
            itemName: 'Interstellar',
            itemType: 'Movie',
            productionYear: 2014,
            playMethod: '',
            container: 'MKV',
            videoCodec: 'HEVC',
            videoResolution: '4K UHD',
            audioCodec: 'TRUEHD',
            audioChannels: 8,
            bitrateBps: 22000000,
            bandwidthMbps: 22.0,
            durationSecs: 10140,
            watchedSecs: 10140,
            dataUsedBytes: 0,
            completionPct: 100,
            startedAt: new Date().toISOString(),
            lastSeenAt: new Date().toISOString(),
            isActive: false,
        });

        currentSwrState = {
            ...currentSwrState,
            data: customData,
        };

        render(<StreamingTab />);

        // Shows historical estimate notice
        expect(screen.getByTestId('historical-estimate-notice')).toBeInTheDocument();
        // Displays Unknown play method badge instead of Direct Play
        expect(screen.getAllByText('Unknown').length).toBeGreaterThan(0);
        // Shows Unrecorded and Sync badge for 0-byte historical sync entry
        expect(screen.getByText('Unrecorded')).toBeInTheDocument();
        expect(screen.getByText('Sync')).toBeInTheDocument();
        expect(screen.getByText('Historical Import')).toBeInTheDocument();
    });

    it('filters watch history by search query and play method, paginates results, and discloses bounded history honestly', () => {
        const customData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        customData.analytics.totalPlays = 120; // More total plays in backend window than loaded rows (2)
        currentSwrState = {
            ...currentSwrState,
            data: customData,
        };

        render(<StreamingTab />);

        // Honest bounded history notice & result count
        expect(screen.getByTestId('bounded-history-notice')).toHaveTextContent(/Showing the most recent/i);
        expect(screen.getByTestId('history-result-count')).toHaveTextContent(
            /Showing 1–2 of 2 matching \(2 loaded of 120 total\)/i
        );
        // CSV button says Export Loaded CSV (2), never claiming Export All
        expect(screen.getByRole('button', { name: /Export 2 loaded rows to CSV/i })).toHaveTextContent(
            /Export Loaded CSV \(2\)/i
        );

        // Search by device/client
        const searchInput = screen.getByRole('textbox', { name: /Search playback history/i });
        fireEvent.change(searchInput, { target: { value: 'Swiftfin' } });

        expect(screen.getByTestId('history-result-count')).toHaveTextContent(
            /Showing 1–1 of 1 matching \(2 loaded of 120 total\)/i
        );
        expect(screen.getAllByText(/Hello, Ms\. Cobel/i).length).toBeGreaterThan(0);

        // Filter by play method via select
        fireEvent.change(searchInput, { target: { value: '' } });
        const pmSelect = screen.getByRole('combobox', { name: /Filter history by play method/i });
        fireEvent.change(pmSelect, { target: { value: 'DirectPlay' } });
        expect(lastSwrKey).toContain('playMethod=DirectPlay');
        expect(screen.getByTestId('history-result-count')).toHaveTextContent(/Showing 1–1 of 1 matching/i);
    });

    it('updates SWR query key and filters history when period filter changes in Analytics view', () => {
        render(<StreamingTab />);
        const analyticsTabBtn = screen.getByRole('button', { name: /Playback analytics/i });
        fireEvent.click(analyticsTabBtn);

        const sevenDaysBtn = screen.getByRole('button', { name: '7 Days' });
        fireEvent.click(sevenDaysBtn);
        expect(lastSwrKey).toContain('window=7');
        expect(sevenDaysBtn).toHaveAttribute('aria-pressed', 'true');
    });

    it('neutralizes CSV formula injection and properly quotes RFC 4180 special characters on export', () => {
        expect(escapeStreamingCsvCell('=cmd|\'/C calc\'!A0')).toBe("'=cmd|'/C calc'!A0");
        expect(escapeStreamingCsvCell('+SUM(A1:A2)')).toBe("'+SUM(A1:A2)");
        expect(escapeStreamingCsvCell('-2+3')).toBe("'-2+3");
        expect(escapeStreamingCsvCell('@IMPORTXML()')).toBe("'@IMPORTXML()");
        expect(escapeStreamingCsvCell('  =HYPERLINK("http://evil")')).toBe('"\'  =HYPERLINK(""http://evil"")"');
        expect(escapeStreamingCsvCell('Movie, "Director\'s Cut"')).toBe('"Movie, ""Director\'s Cut"""');

        const maliciousHistory = [
            {
                ...mockDashboardData.analytics.recentHistory[0],
                itemName: '=1+1,"evil"',
                userName: '@admin_user',
                sessionKey: 'jellyfin:sync:u-1:item-1',
                playMethod: '',
            },
        ];
        const csv = buildStreamingHistoryCsv(maliciousHistory);
        expect(csv).toContain('"\'=1+1,""evil"""');
        expect(csv).toContain("'@admin_user");
        expect(csv).toContain('Unknown');
        expect(csv).toContain('Estimated (Legacy Historical Sync)');

        // Verify recomputeLiveSummaryFromSessions helper
        const recomputed = recomputeLiveSummaryFromSessions(
            mockDashboardData.liveSummary,
            mockDashboardData.activeSessions.map((session) => ({ ...session, state: 'paused' as const }))
        );
        expect(recomputed.totalBandwidthMbps).toBe(0);
        expect(recomputed.activeStreams).toBe(2);
    });

    it('passes the Unknown cohort to the backend without replacing it with all', () => {
        render(<StreamingTab />);
        fireEvent.change(screen.getByRole('combobox', { name: /Filter history by play method/i }), {
            target: { value: 'Unknown' },
        });
        expect(lastSwrKey).toContain('playMethod=Unknown');
        expect(lastSwrKey).not.toContain('playMethod=all');
    });

    it('honors the backend window boundary and renders UTC timestamps with last-seen fallback', () => {
        const customData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        customData.updatedAt = '2026-11-01T12:00:00.950Z';
        customData.analytics.recentHistory[0].startedAt = '2026-10-02 12:00:00';
        customData.analytics.recentHistory[1].startedAt = '';
        customData.analytics.recentHistory[1].lastSeenAt = '2026-10-30 09:00:00';
        currentSwrState = { ...currentSwrState, data: customData };
        render(<StreamingTab />);
        expect(screen.getByText('2026-10-02 12:00:00 UTC')).toHaveAttribute('datetime', '2026-10-02T12:00:00.000Z');
        expect(screen.getByText('2026-10-30 09:00:00 UTC')).toHaveAttribute('datetime', '2026-10-30T09:00:00.000Z');
        expect(screen.getByRole('combobox', { name: /History rows per page/i })).toHaveValue('20');
    });

    it('labels coarse all-time chart buckets and preserves years in ticks', () => {
        expect(formatStreamingBucket('2024-05-01', 'month')).toBe('2024-05');
        expect(formatStreamingBucket('2024-01-01', 'year')).toBe('2024');
        expect(formatStreamingBucket('2024-05-31', 'day')).toBe('2024-05-31');
        const customData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        customData.analytics.timeSeriesGranularity = 'month';
        currentSwrState = { ...currentSwrState, data: customData };
        render(<StreamingTab />);
        fireEvent.click(screen.getByRole('button', { name: /Playback analytics/i }));
        expect(screen.getByText(/Monthly estimated transfer/i)).toBeInTheDocument();
        expect(screen.getByText(/Monthly sessions by delivery method/i)).toBeInTheDocument();
    });

    it('distinguishes unrecorded historical transfer from live estimates without inventing import provenance', () => {
        const original = mockDashboardData.analytics.recentHistory[0];
        const unrecorded = { ...original, sessionKey: 'jellyfin:sync:user:item', playMethod: '', dataUsedBytes: 0 };
        expect(buildStreamingHistoryCsv([unrecorded])).toContain('Unrecorded (Historical Sync)');
        const liveUnknown = { ...original, sessionKey: 'jellyfin:session:item', playMethod: 'Unknown' };
        expect(isHistoricalSyncEntry(liveUnknown)).toBe(false);
        const csv = buildStreamingHistoryCsv([liveUnknown]);
        expect(csv).toContain('Estimated (Live Poll)');
        expect(csv).not.toContain('Measured');
        expect(parseStreamingTimestamp('2026-11-01 12:00:00')?.toISOString()).toBe('2026-11-01T12:00:00.000Z');
        expect(parseStreamingTimestamp('2026-11-01T14:00:00+02:00')?.toISOString()).toBe('2026-11-01T12:00:00.000Z');
        expect(parseStreamingTimestamp('')).toBeNull();
        expect(parseStreamingTimestamp('invalid date')).toBeNull();
    });

    it('does not relabel a redacted WAN address as local', () => {
        const customData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        customData.activeSessions[1].ipAddress = '';
        customData.activeSessions[1].isLan = false;
        currentSwrState = { ...currentSwrState, data: customData };
        render(<StreamingTab />);
        expect(screen.getByText('WAN')).toBeInTheDocument();
        expect(screen.queryByText('WAN · local')).not.toBeInTheDocument();
    });

    it('paginates watch history across multiple pages and triggers Blob URL CSV download', () => {
        const customData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        customData.analytics.recentHistory = Array.from({ length: 12 }, (_, idx) => ({
            ...mockDashboardData.analytics.recentHistory[0],
            id: idx + 1,
            sessionKey: `hist-page-${idx + 1}`,
            itemName: `Test Title #${idx + 1}`,
        }));
        customData.analytics.totalPlays = 12;

        currentSwrState = {
            ...currentSwrState,
            data: customData,
        };

        const createObjectUrlMock = jest.fn(() => 'blob:http://localhost/mock-csv');
        const revokeObjectUrlMock = jest.fn();
        Object.defineProperty(URL, 'createObjectURL', {
            configurable: true,
            writable: true,
            value: createObjectUrlMock,
        });
        Object.defineProperty(URL, 'revokeObjectURL', {
            configurable: true,
            writable: true,
            value: revokeObjectUrlMock,
        });
        const anchorClickSpy = jest
            .spyOn(HTMLAnchorElement.prototype, 'click')
            .mockImplementation(() => undefined);

        render(<StreamingTab />);

        // Switch page size to 10 / page so 12 rows span 2 pages
        const pageSizeSelect = screen.getByRole('combobox', { name: /History rows per page/i });
        fireEvent.change(pageSizeSelect, { target: { value: '10' } });

        expect(screen.getByTestId('history-result-count')).toHaveTextContent(/Showing 1–10 of 12 matching/i);
        expect(screen.getByText('Test Title #1')).toBeInTheDocument();
        expect(screen.queryByText('Test Title #11')).not.toBeInTheDocument();

        // Navigate to Page 2
        const nextBtn = screen.getByRole('button', { name: /Next loaded history page/i });
        fireEvent.click(nextBtn);

        expect(screen.getByTestId('history-result-count')).toHaveTextContent(/Showing 11–12 of 12 matching/i);
        expect(screen.getByText('Test Title #11')).toBeInTheDocument();

        // Trigger CSV export
        const exportBtn = screen.getByRole('button', { name: /Export 12 rows to CSV/i });
        fireEvent.click(exportBtn);

        expect(createObjectUrlMock).toHaveBeenCalledTimes(1);
        expect(anchorClickSpy).toHaveBeenCalledTimes(1);
        expect(revokeObjectUrlMock).toHaveBeenCalledWith('blob:http://localhost/mock-csv');

        anchorClickSpy.mockRestore();
    });

    it('keeps config modal open and surfaces error when saving an unreachable Jellyfin server', async () => {
        const fetchSpy = jest.spyOn(global, 'fetch').mockImplementation(async (input: RequestInfo | URL) => {
            const url = String(input);
            if (url.includes('csrf-token')) {
                return {
                    ok: true,
                    json: async () => ({ token: 'test-csrf-token' }),
                } as Response;
            }
            return {
                ok: true,
                json: async () => ({
                    message: 'Saved Jellyfin server, but connection failed',
                    server: {
                        status: 'unreachable',
                        errorMessage: 'Connection refused on port 8096',
                    },
                }),
            } as Response;
        });

        render(<StreamingTab />);
        fireEvent.click(screen.getByRole('button', { name: /Configure Server/i }));

        const saveBtn = screen.getByRole('button', { name: /Save Connection/i });
        fireEvent.click(saveBtn);

        await waitFor(() => {
            expect(screen.getByText(/Connection refused on port 8096/i)).toBeInTheDocument();
        });
        // Modal remains open so the operator can fix the URL/key
        expect(screen.getByText(/Media Server Providers/i)).toBeInTheDocument();

        fetchSpy.mockRestore();
    });

    it('renders compact horizontal idle state when no active streams are running', () => {
        const customData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        customData.activeSessions = [];
        customData.liveSummary.activeStreams = 0;
        currentSwrState = { ...currentSwrState, data: customData };

        render(<StreamingTab />);
        const idleElement = screen.getByTestId('compact-no-streams-state');
        expect(idleElement).toBeInTheDocument();
        expect(within(idleElement).getByText(/connected · Idle/i)).toBeInTheDocument();
        expect(within(idleElement).queryByText('0 active')).not.toBeInTheDocument();
        expect(within(idleElement).getByText(/Last contact:/i)).toBeInTheDocument();
        expect(screen.queryByText(/No Active Streams Right Now/i)).not.toBeInTheDocument();
        expect(screen.queryByTestId('active-sessions-grid')).not.toBeInTheDocument();
    });

    it('provides accessible filter groups, >=44px touch targets, and methodology disclosure', () => {
        render(<StreamingTab />);
        const windowGroup = screen.getByRole('group', { name: 'Time Window Filter' });
        const playMethodGroup = screen.getByRole('group', { name: 'Play Method Filter' });
        const mediaTypeGroup = screen.getByRole('group', { name: 'Media Type Filter' });

        expect(windowGroup).toBeInTheDocument();
        expect(playMethodGroup).toBeInTheDocument();
        expect(mediaTypeGroup).toBeInTheDocument();

        const activeWindowButton = within(windowGroup).getByRole('button', { name: '30 Days' });
        expect(activeWindowButton).toHaveAttribute('aria-pressed', 'true');
        expect(activeWindowButton).toHaveClass('min-h-[44px]');

        const inactiveWindowButton = within(windowGroup).getByRole('button', { name: '7 Days' });
        expect(inactiveWindowButton).toHaveAttribute('aria-pressed', 'false');
        expect(inactiveWindowButton).toHaveClass('min-h-[44px]');

        expect(screen.getByText(/Measurement methodology, overlap & nonadditivity details/i)).toBeInTheDocument();
    });

    it('enforces import safety invariants and number-level ESTIMATED badges', () => {
        render(<StreamingTab />);
        const estimatedBadges = screen.getAllByText('ESTIMATED');
        expect(estimatedBadges.length).toBeGreaterThan(0);
        expect(screen.getByText(/Preserved imported and legacy watch-time estimates appear separately below/i)).toBeInTheDocument();
        expect(screen.getByText(/Bandwidth peaks remain a legacy provider aggregate/i)).toBeInTheDocument();
    });

    it('retains full readable navigation labels with responsive whitespace-nowrap styling and primary hierarchy', () => {
        render(<StreamingTab />);
        const navContainer = screen.getByRole('navigation', { name: 'Streaming views' });
        expect(navContainer).toBeInTheDocument();

        const dashboardButton = within(navContainer).getByRole('button', { name: 'Dashboard' });
        const liveButton = within(navContainer).getByRole('button', { name: /Live/ });
        const analyticsButton = within(navContainer).getByRole('button', { name: 'Playback Analytics' });
        const historyButton = within(navContainer).getByRole('button', { name: 'Watch History' });

        expect(within(dashboardButton).getByText('Dashboard')).toHaveClass('whitespace-nowrap');
        expect(within(liveButton).getByText(/Live/)).toHaveClass('whitespace-nowrap');
        expect(within(analyticsButton).getByText('Playback Analytics')).toHaveClass('whitespace-nowrap');
        expect(within(historyButton).getByText('Watch History')).toHaveClass('whitespace-nowrap');

        expect(screen.getByRole('button', { name: /Sync Jellyfin/i })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Configure Server/i })).toBeInTheDocument();
        expect(screen.getAllByRole('button', { name: /Refresh/i }).length).toBeGreaterThan(0);
    });

    it('renders responsive live KPI cards with hidden decoration on mobile and non-truncated headings', () => {
        const customData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        customData.liveSummary.activeSessionBytes = 0;
        currentSwrState = { ...currentSwrState, data: customData };

        render(<StreamingTab />);
        const activeStreamsHeading = screen.getByText('Active Streams');
        const liveBandwidthHeading = screen.getByText('Live Bandwidth');

        expect(activeStreamsHeading).toHaveClass('leading-snug');
        expect(activeStreamsHeading).not.toHaveClass('truncate');
        expect(liveBandwidthHeading).toHaveClass('leading-snug');
        expect(liveBandwidthHeading).not.toHaveClass('truncate');

        const idleThroughputSubtitle = screen.getByText('Idle · No active throughput');
        expect(idleThroughputSubtitle).toBeInTheDocument();
        expect(idleThroughputSubtitle.textContent).not.toContain('&middot;');
        expect(idleThroughputSubtitle.textContent).toContain('·');
    });

    it('renders explicit unit-bearing chart legends for history transfer and activity series', () => {
        render(<StreamingTab />);
        expect(screen.getAllByText('Transferred data (GB)').length).toBeGreaterThanOrEqual(1);
        expect(screen.getAllByText('Recorded peak bitrate (Mbps)').length).toBeGreaterThanOrEqual(1);
        expect(screen.getByText('Direct Play (sessions)')).toBeInTheDocument();
        expect(screen.getByText('Direct Stream (sessions)')).toBeInTheDocument();
        expect(screen.getByText('Transcode (sessions)')).toBeInTheDocument();
        expect(screen.getByText('Unknown (sessions)')).toBeInTheDocument();
        expect(screen.getByText('Watch time (hours)')).toBeInTheDocument();
    });

    it('renders truthful Plex telemetry-only badge when Plex session is observed and moves roadmap to secondary actions', () => {
        const plexCustomData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        plexCustomData.activeSessions = [
            {
                ...plexCustomData.activeSessions[0],
                sessionId: 'plex-stream-1',
                provider: 'Plex',
                serverName: 'Plex Server Alpha',
                supportsMediaControl: false,
                canSendMessage: false,
            },
        ];
        currentSwrState = { ...currentSwrState, data: plexCustomData };

        render(<StreamingTab />);
        expect(screen.getByText(/Plex · Read-only telemetry/i)).toBeInTheDocument();
        expect(screen.queryByText(/Plex · Later/i)).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Sync Jellyfin/i })).toBeInTheDocument();
        expect(screen.queryByText('Sync Providers')).not.toBeInTheDocument();
        expect(screen.queryByText('Planned integrations:')).not.toBeInTheDocument();
        expect(screen.queryByText(/Emby \(Planned\)/i)).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /Configure Server/i }));
        expect(screen.getByText(/Media Server Providers/i)).toBeInTheDocument();
        expect(screen.getByText(/Planned integration · Staged telemetry/i)).toBeInTheDocument();
    });

    it('renders dynamic grid classes based on active session count', () => {
        const singleSessionData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        singleSessionData.activeSessions = [singleSessionData.activeSessions[0]];
        currentSwrState = { ...currentSwrState, data: singleSessionData };

        const firstRender = render(<StreamingTab />);
        const singleContainer = screen.getByTestId('active-sessions-grid');
        expect(singleContainer).toHaveClass('grid-cols-1');
        expect(singleContainer).not.toHaveClass('lg:grid-cols-2');
        firstRender.unmount();

        const twoSessionData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        twoSessionData.activeSessions = [
            twoSessionData.activeSessions[0],
            { ...twoSessionData.activeSessions[0], sessionId: 'session-2', provider: 'jellyfin' },
        ];
        currentSwrState = { ...currentSwrState, data: twoSessionData };

        const secondRender = render(<StreamingTab />);
        const twoContainer = screen.getByTestId('active-sessions-grid');
        expect(twoContainer).toHaveClass('grid-cols-1');
        expect(twoContainer).toHaveClass('lg:grid-cols-2');
        expect(twoContainer).not.toHaveClass('xl:grid-cols-3');
        secondRender.unmount();

        const threeSessionData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        threeSessionData.activeSessions = [
            threeSessionData.activeSessions[0],
            { ...threeSessionData.activeSessions[0], sessionId: 'session-2' },
            { ...threeSessionData.activeSessions[0], sessionId: 'session-3' },
        ];
        currentSwrState = { ...currentSwrState, data: threeSessionData };

        render(<StreamingTab />);
        const threeContainer = screen.getByTestId('active-sessions-grid');
        expect(threeContainer).toHaveClass('xl:grid-cols-3');
    });

    it('verifies idle connection freshness and wrapping without truncate or duplicate 0 active badge', () => {
        const idleFreshData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        idleFreshData.activeSessions = [];
        idleFreshData.servers[0].lastConnectedAt = '2026-11-05T14:30:00.000Z';
        currentSwrState = { ...currentSwrState, data: idleFreshData };

        render(<StreamingTab />);
        const idleContainer = screen.getByTestId('compact-no-streams-state');
        expect(idleContainer).toBeInTheDocument();
        expect(within(idleContainer).queryByText('0 active')).not.toBeInTheDocument();
        const providerLine = within(idleContainer).getByText(/connected · Idle/i);
        expect(providerLine).not.toHaveClass('truncate');
        expect(within(idleContainer).getByText(/Last contact: 2026-11-05 14:30 UTC/i)).toBeInTheDocument();
    });

    it('eliminates redundant count and throughput badges in section headings and shows method legend only when active', () => {
        const activeData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        currentSwrState = { ...currentSwrState, data: activeData };

        const activeRender = render(<StreamingTab />);
        const liveSection = screen.getByRole('region', { name: 'Live Stream Overview' });
        expect(within(liveSection).queryByText(/Idle · Ready/i)).not.toBeInTheDocument();
        expect(within(liveSection).queryByText(/Mbps active bandwidth/i)).not.toBeInTheDocument();

        expect(screen.queryByText(/active · .* Mbps total/i)).not.toBeInTheDocument();
        const activeSessionsCard = screen.getByTestId('active-sessions-grid').parentElement!;
        expect(within(activeSessionsCard).getAllByText('Direct Play').length).toBeGreaterThanOrEqual(1);
        activeRender.unmount();

        const idleData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        idleData.activeSessions = [];
        idleData.liveSummary.activeStreams = 0;
        idleData.liveSummary.totalBandwidthMbps = 0;
        idleData.liveSummary.totalBitrateBps = 0;
        currentSwrState = { ...currentSwrState, data: idleData };

        render(<StreamingTab />);
        const idleSessionsCard = screen.getByTestId('compact-no-streams-state').parentElement!;
        expect(within(idleSessionsCard).queryByText('Direct Stream')).not.toBeInTheDocument();
    });

    it('consolidates future provider roadmap into single neutral planned integration treatment without live beacons', () => {
        const unobservedData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        currentSwrState = { ...currentSwrState, data: unobservedData };

        const initialRender = render(<StreamingTab />);
        expect(screen.queryByText(/Plex · Later/i)).not.toBeInTheDocument();
        expect(screen.queryByText(/Emby · Later/i)).not.toBeInTheDocument();
        expect(screen.queryByText('Planned integrations:')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /Configure Server/i }));
        const modalContainer = screen.getByText(/Media Server Providers/i).closest('.rounded-2xl') as HTMLElement;
        expect(modalContainer).toBeInTheDocument();

        const plexPlannedCard = within(modalContainer).getByText('Plex').closest('.rounded-xl') as HTMLElement;
        const embyPlannedCard = within(modalContainer).getByText('Emby').closest('.rounded-xl') as HTMLElement;
        expect(plexPlannedCard).toBeInTheDocument();
        expect(embyPlannedCard).toBeInTheDocument();

        expect(within(plexPlannedCard).getByText('Planned')).toBeInTheDocument();
        expect(within(embyPlannedCard).getByText('Planned')).toBeInTheDocument();
        expect(plexPlannedCard.querySelector('.bg-emerald-400')).toBeNull();
        expect(plexPlannedCard.querySelector('.bg-amber-400')).toBeNull();
        expect(embyPlannedCard.querySelector('.bg-emerald-400')).toBeNull();
        expect(embyPlannedCard.querySelector('.bg-amber-400')).toBeNull();
        initialRender.unmount();

        const observedData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        observedData.activeSessions = [
            {
                ...observedData.activeSessions[0],
                sessionId: 'plex-live-session',
                provider: 'Plex',
                supportsMediaControl: false,
                canSendMessage: false,
            },
        ];
        currentSwrState = { ...currentSwrState, data: observedData };

        render(<StreamingTab />);
        expect(screen.getByText(/Plex · Read-only telemetry/i)).toBeInTheDocument();
        expect(screen.queryByText(/Plex · Later/i)).not.toBeInTheDocument();
        expect(screen.queryByText('Planned integrations:')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /Configure Server/i }));
        const updatedModal = screen.getByText(/Media Server Providers/i).closest('.rounded-2xl') as HTMLElement;
        const updatedPlexCard = within(updatedModal).getByText('Plex').closest('.rounded-xl') as HTMLElement;
        expect(within(updatedPlexCard).getByText('Observed')).toBeInTheDocument();
        expect(within(updatedModal).getByText('Emby')).toBeInTheDocument();
    });

    it('contrasts unsupported-provider read-only telemetry state against supported and transient Jellyfin controls', () => {
        const contrastData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        contrastData.activeSessions = [
            {
                ...contrastData.activeSessions[0],
                sessionId: 'plex-unsupported-session',
                provider: 'Plex',
                state: 'playing',
                supportsMediaControl: false,
                canSendMessage: false,
            },
            {
                ...contrastData.activeSessions[0],
                sessionId: 'jellyfin-supported-session',
                provider: 'jellyfin',
                state: 'playing',
                supportsMediaControl: true,
                canSendMessage: true,
            },
            {
                ...contrastData.activeSessions[0],
                sessionId: 'jellyfin-transient-session',
                provider: 'jellyfin',
                state: 'playing',
                supportsMediaControl: false,
                canSendMessage: false,
            },
        ];
        currentSwrState = { ...currentSwrState, data: contrastData };

        render(<StreamingTab />);

        expect(screen.getByText(/Read-only stream telemetry · Remote control unsupported for Plex/i)).toBeInTheDocument();
        expect(screen.getByText('Read-Only')).toBeInTheDocument();
        expect(screen.getByTitle('Session control is not supported for provider "Plex"')).toBeInTheDocument();

        const pauseButtons = screen.getAllByRole('button', { name: /^Pause$/i });
        expect(pauseButtons).toHaveLength(2);
        expect(pauseButtons[0]).not.toBeDisabled();
        expect(pauseButtons[1]).toBeDisabled();

        expect(screen.getByText(/Client has no active remote-control WebSocket/i)).toBeInTheDocument();
        expect(screen.queryByText(/Session control is not supported for provider "jellyfin"/i)).not.toBeInTheDocument();
    });

    it('verifies Candidate G idle, active, and disconnected render paths distinctly', () => {
        const idleDashboardData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        idleDashboardData.activeSessions = [];
        idleDashboardData.liveSummary.activeStreams = 0;
        currentSwrState = { ...currentSwrState, data: idleDashboardData };

        const idleRender = render(<StreamingTab />);
        const idleStrip = screen.getByTestId('compact-no-streams-state');
        expect(idleStrip).toBeInTheDocument();
        expect(within(idleStrip).getByText(/connected · Idle/i)).toBeInTheDocument();
        expect(screen.queryByTestId('active-sessions-grid')).not.toBeInTheDocument();
        expect(screen.queryByText(/No Active Streams Right Now/i)).not.toBeInTheDocument();
        idleRender.unmount();

        const activeDashboardData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        currentSwrState = { ...currentSwrState, data: activeDashboardData };

        const activeRender = render(<StreamingTab />);
        expect(screen.getByTestId('active-sessions-grid')).toBeInTheDocument();
        expect(screen.queryByTestId('compact-no-streams-state')).not.toBeInTheDocument();
        activeRender.unmount();

        const disconnectedDashboardData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        disconnectedDashboardData.activeSessions = [];
        disconnectedDashboardData.servers[0].status = 'unreachable';
        disconnectedDashboardData.servers[0].errorMessage = 'Connection refused on port 8096';
        currentSwrState = { ...currentSwrState, data: disconnectedDashboardData };

        render(<StreamingTab />);
        expect(screen.getAllByText(/Connection refused on port 8096/i).length).toBeGreaterThanOrEqual(1);
        const disconnectedStrip = screen.getByTestId('compact-no-streams-state');
        expect(within(disconnectedStrip).getByText(/Connection refused on port 8096/i)).toBeInTheDocument();
        expect(within(disconnectedStrip).queryByText(/connected · Idle/i)).not.toBeInTheDocument();
        expect(within(disconnectedStrip).getByText(/Last contact:/i)).toBeInTheDocument();
        expect(screen.queryByTestId('active-sessions-grid')).not.toBeInTheDocument();
    });

    it('identifies a staged Emby-only connection as idle telemetry', () => {
        const idleData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        idleData.activeSessions = [];
        idleData.liveSummary.activeStreams = 0;
        idleData.servers[0].status = 'unconfigured';
        idleData.servers[0].configured = false;
        idleData.servers[2] = { ...idleData.servers[2], name: 'Lab Emby', enabled: true, configured: true, status: 'connected' };
        currentSwrState = { ...currentSwrState, data: idleData };
        render(<StreamingTab />);
        expect(within(screen.getByTestId('compact-no-streams-state')).getByText(/Lab Emby connected · Idle \(staged\)/)).toBeInTheDocument();
    });

    it('verifies Candidate G single secondary roadmap location in server config dialog and absence from operational toolbar', () => {
        render(<StreamingTab />);
        expect(screen.queryByText('Planned integrations:')).not.toBeInTheDocument();
        expect(screen.queryByText(/Plex \(Planned\)/i)).not.toBeInTheDocument();
        expect(screen.queryByText(/Emby \(Planned\)/i)).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /Configure Server/i }));
        const providerDialog = screen.getByRole('dialog', { name: 'Media Server Providers' });
        expect(providerDialog).toBeInTheDocument();

        const plexProviderCard = within(providerDialog).getByText('Plex').closest('.rounded-xl') as HTMLElement;
        const embyProviderCard = within(providerDialog).getByText('Emby').closest('.rounded-xl') as HTMLElement;
        expect(plexProviderCard).toBeInTheDocument();
        expect(embyProviderCard).toBeInTheDocument();

        expect(within(plexProviderCard).getByText('Planned')).toBeInTheDocument();
        expect(within(embyProviderCard).getByText('Planned')).toBeInTheDocument();
        expect(plexProviderCard.querySelector('.bg-emerald-400')).toBeNull();
        expect(plexProviderCard.querySelector('.bg-amber-400')).toBeNull();
        expect(embyProviderCard.querySelector('.bg-emerald-400')).toBeNull();
        expect(embyProviderCard.querySelector('.bg-amber-400')).toBeNull();

        const providerCardsGrid = plexProviderCard.parentElement as HTMLElement;
        expect(providerCardsGrid).toHaveClass('grid-cols-1');
        expect(providerCardsGrid).toHaveClass('min-[360px]:grid-cols-3');
    });

    it('verifies Candidate G bounded provider card grid and header layout responsive classes for narrow viewports', () => {
        render(<StreamingTab />);
        fireEvent.click(screen.getByRole('button', { name: /Configure Server/i }));
        const dialogElement = screen.getByRole('dialog', { name: 'Media Server Providers' });
        const modalBody = dialogElement.querySelector('.rounded-2xl') as HTMLElement;

        expect(modalBody).toHaveClass('p-4');
        expect(modalBody).toHaveClass('sm:p-6');

        const modalHeader = modalBody.querySelector('.border-b') as HTMLElement;
        expect(modalHeader).toHaveClass('flex');
        expect(modalHeader).toHaveClass('gap-2');
        expect(modalHeader.firstElementChild).toHaveClass('min-w-0');

        const cardsGrid = within(dialogElement).getByText('Active').closest('.grid') as HTMLElement;
        expect(cardsGrid).toHaveClass('grid-cols-1');
        expect(cardsGrid).toHaveClass('min-[360px]:grid-cols-3');

        const embyCard = within(cardsGrid).getByText('Emby').closest('.rounded-xl') as HTMLElement;
        const embyStatusHeader = within(embyCard).getByText('Emby').parentElement as HTMLElement;
        expect(embyStatusHeader).toHaveClass('flex-wrap');
        expect(within(embyCard).getByText('Planned')).toBeInTheDocument();
        expect(within(embyCard).getByText('Planned')).not.toHaveClass('truncate');
    });

    it('verifies Candidate G historical filter groups are left-aligned with consistent wrapping gap and standard touch targets', () => {
        render(<StreamingTab />);
        const historicalHeading = screen.getByRole('heading', { level: 3, name: /Historical Analytics/i });
        const filtersContainer = (historicalHeading.closest('.space-y-3') as HTMLElement).querySelector('.flex-wrap.items-center.gap-x-6.gap-y-4') as HTMLElement;

        expect(filtersContainer).toBeInTheDocument();
        expect(filtersContainer).toHaveClass('gap-x-6');
        expect(filtersContainer).toHaveClass('gap-y-4');
        expect(filtersContainer).not.toHaveClass('justify-between');

        const windowFilterGroup = screen.getByRole('group', { name: 'Time Window Filter' });
        const deliveryFilterGroup = screen.getByRole('group', { name: 'Play Method Filter' });
        const mediaFilterGroup = screen.getByRole('group', { name: 'Media Type Filter' });

        expect(windowFilterGroup).toBeInTheDocument();
        expect(deliveryFilterGroup).toBeInTheDocument();
        expect(mediaFilterGroup).toBeInTheDocument();

        const allFilterButtons = [
            ...within(windowFilterGroup).getAllByRole('button'),
            ...within(deliveryFilterGroup).getAllByRole('button'),
            ...within(mediaFilterGroup).getAllByRole('button'),
        ];

        for (const buttonElement of allFilterButtons) {
            expect(buttonElement).toHaveClass('min-h-[44px]');
            expect(buttonElement).toHaveClass('obs-touch-target-standard');
        }
    });

    it('verifies Candidate L decoupled single-quantity plots render explicit visible series-matched measure and unit headings without dual-axis bookkeeping', () => {
        render(<StreamingTab />);
        const transferChartHeading = screen.getByText('Stream Data Usage & Bandwidth Over Time');
        const transferChartContainer = transferChartHeading.closest('.rounded-xl') as HTMLElement;
        expect(within(transferChartContainer).queryByText('Left axis:')).not.toBeInTheDocument();
        expect(within(transferChartContainer).queryByText('Right axis:')).not.toBeInTheDocument();
        expect(within(transferChartContainer).getAllByText('Transferred data (GB)').length).toBeGreaterThanOrEqual(1);
        expect(within(transferChartContainer).getAllByText('Recorded peak bitrate (Mbps)').length).toBeGreaterThanOrEqual(1);

        const activityChartHeading = screen.getByText('Play Sessions & Watch Time Activity');
        const activityChartContainer = activityChartHeading.closest('.rounded-xl') as HTMLElement;
        expect(within(activityChartContainer).queryByText('Left axis:')).not.toBeInTheDocument();
        expect(within(activityChartContainer).queryByText('Right axis:')).not.toBeInTheDocument();
        expect(within(activityChartContainer).getByText('Play sessions')).toBeInTheDocument();
        expect(within(activityChartContainer).getByText('Watch time (hours)')).toBeInTheDocument();
    });

    it('verifies Candidate H Top Watchers uses native numeric rank badges without medal emojis', () => {
        render(<StreamingTab />);
        const topWatchersHeading = screen.getByText('Top Watchers & Data Usage by User');
        const topWatchersContainer = topWatchersHeading.closest('.rounded-xl') as HTMLElement;
        expect(topWatchersContainer).toBeInTheDocument();

        expect(within(topWatchersContainer).queryByText('🥇')).not.toBeInTheDocument();
        expect(within(topWatchersContainer).queryByText('🥈')).not.toBeInTheDocument();
        expect(within(topWatchersContainer).queryByText('🥉')).not.toBeInTheDocument();

        const numericBadge = within(topWatchersContainer).getByText('1');
        expect(numericBadge).toBeInTheDocument();
        expect(numericBadge).toHaveClass('w-6', 'h-6', 'rounded-lg');
    });

    it('verifies Candidate H active session hierarchy with deliberate pipeline disclosure and readable transcode summary', () => {
        render(<StreamingTab />);
        const sessionsGrid = screen.getByTestId('active-sessions-grid');
        const sessionArticles = within(sessionsGrid).getAllByRole('article');
        expect(sessionArticles.length).toBeGreaterThan(0);

        const transcodeArticle = sessionArticles.find((articleElement) => {
            return within(articleElement).queryAllByText(/Transcode/i).length > 0;
        }) as HTMLElement;
        expect(transcodeArticle).toBeInTheDocument();

        expect(within(transcodeArticle).getByText(/Transcode reason:/i)).toBeInTheDocument();
        expect(within(transcodeArticle).getByText(/Container Bitrate Exceeds Limit/i)).toBeInTheDocument();

        const pipelineSummary = within(transcodeArticle).getByText(/Stream pipeline & codec details/i);
        expect(pipelineSummary).toBeInTheDocument();
        const pipelineDetails = pipelineSummary.closest('details') as HTMLDetailsElement;
        expect(pipelineDetails).toBeInTheDocument();

        const pipelineSummaries = within(sessionsGrid).getAllByText(/Stream pipeline & codec details/i);
        expect(pipelineSummaries.length).toBeGreaterThanOrEqual(1);
        for (const summarySpan of pipelineSummaries) {
            const summaryElement = summarySpan.closest('summary') as HTMLElement;
            expect(summaryElement).toHaveClass('min-h-[44px]');
            expect(summaryElement).toHaveClass('obs-touch-target-standard');
        }

        const methodologySummary = screen.getByText('How these metrics are measured').closest('summary') as HTMLElement;
        expect(methodologySummary).toHaveClass('min-h-[44px]');
        expect(methodologySummary).toHaveClass('obs-touch-target-standard');
        expect(methodologySummary).not.toHaveClass('sm:min-h-0');
    });

    it('verifies Candidate H idle and live KPI alignment and structure symmetry', () => {
        const customData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        customData.activeSessions = [];
        customData.liveSummary.activeStreams = 0;
        customData.liveSummary.totalBandwidthMbps = 0;
        customData.liveSummary.totalBitrateBps = 0;
        customData.liveSummary.activeSessionBytes = 0;
        currentSwrState = { ...currentSwrState, data: customData };

        render(<StreamingTab />);
        const activeStreamsCard = screen.getByText(/Active streams:/i).closest('.rounded-xl') as HTMLElement;
        const liveBandwidthCard = screen.getByText(/Bandwidth:/i).closest('.rounded-xl') as HTMLElement;

        expect(within(activeStreamsCard).queryByText('0 concurrent sessions')).not.toBeInTheDocument();
        expect(within(activeStreamsCard).queryByText('Connected idle · Standing by')).not.toBeInTheDocument();
        expect(within(liveBandwidthCard).queryByText('Idle · No active throughput')).not.toBeInTheDocument();
        expect(within(activeStreamsCard).getByText(/connected · Idle/i)).toBeInTheDocument();

        const activeStreamsNumber = within(activeStreamsCard).getByText('0');
        const liveBandwidthNumber = within(liveBandwidthCard).getByText('0.0');
        expect(activeStreamsNumber).toHaveClass('font-bold');
        expect(liveBandwidthNumber).toHaveClass('font-bold');
    });

    it('verifies Candidate H historical provider scope indicator and responsive filter disclosure', () => {
        const mockMatchMedia = jest.fn().mockImplementation((queryText: string) => ({
            matches: false,
            media: queryText,
            onchange: null,
            addListener: jest.fn(),
            removeListener: jest.fn(),
            addEventListener: jest.fn(),
            removeEventListener: jest.fn(),
            dispatchEvent: jest.fn(),
        }));

        const originalMatchMedia = window.matchMedia;
        window.matchMedia = mockMatchMedia;

        try {
            const { unmount } = render(<StreamingTab />);
            expect(screen.getByText('All recorded providers')).toBeInTheDocument();

            const filterSummary = screen.getByLabelText('Historical Analytics Filters');
            expect(filterSummary).toBeInTheDocument();
            const filterDetails = filterSummary.closest('details') as HTMLDetailsElement;
            expect(filterDetails).not.toHaveAttribute('open');
            expect(within(filterSummary).getByText('Historical Filters')).toBeInTheDocument();

            fireEvent.click(filterSummary);
            expect(filterDetails).toHaveAttribute('open');

            unmount();
        } finally {
            window.matchMedia = originalMatchMedia;
        }
    });

    it('verifies Candidate H brightened Unknown sessions legend and user stats contrast', () => {
        render(<StreamingTab />);
        const unknownLegendText = screen.getByText('Unknown (sessions)');
        expect(unknownLegendText).toHaveClass('text-slate-200');

        const unknownColorIndicator = unknownLegendText.previousElementSibling as HTMLElement;
        expect(unknownColorIndicator).toHaveClass('bg-slate-400');
    });

    it('verifies Candidate H session controls at mobile width preserve enabled Jellyfin buttons and read-only Plex telemetry', () => {
        const dualProviderData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        dualProviderData.activeSessions = [
            {
                ...mockDashboardData.activeSessions[0],
                provider: 'jellyfin',
                supportsMediaControl: true,
                canSendMessage: true,
            },
            {
                ...mockDashboardData.activeSessions[1],
                provider: 'Plex',
                supportsMediaControl: false,
                canSendMessage: false,
            },
        ];
        currentSwrState = { ...currentSwrState, data: dualProviderData };

        render(<StreamingTab />);
        const sessionsGrid = screen.getByTestId('active-sessions-grid');
        const sessionArticles = within(sessionsGrid).getAllByRole('article');
        expect(sessionArticles).toHaveLength(2);

        const jellyfinArticle = sessionArticles[0];
        const plexArticle = sessionArticles[1];

        const jellyfinPause = within(jellyfinArticle).getByRole('button', { name: /^Pause$/i });
        const jellyfinStop = within(jellyfinArticle).getByRole('button', { name: /^Stop$/i });
        const jellyfinMessage = within(jellyfinArticle).getByRole('button', { name: /^Message$/i });
        expect(jellyfinPause).not.toBeDisabled();
        expect(jellyfinStop).not.toBeDisabled();
        expect(jellyfinMessage).not.toBeDisabled();
        expect(jellyfinPause).toHaveClass('min-h-[44px]', 'text-xs', 'min-w-max');
        expect(jellyfinStop).toHaveClass('min-h-[44px]', 'text-xs', 'min-w-max');
        expect(jellyfinMessage).toHaveClass('min-h-[44px]', 'text-xs', 'min-w-max');
        expect(jellyfinPause).not.toHaveClass('obs-touch-target-standard');
        expect(jellyfinStop).not.toHaveClass('obs-touch-target-standard');
        expect(jellyfinMessage).not.toHaveClass('obs-touch-target-standard');

        const pauseIcon = jellyfinPause.querySelector('svg');
        const stopIcon = jellyfinStop.querySelector('svg');
        const messageIcon = jellyfinMessage.querySelector('svg');
        expect(pauseIcon).toHaveClass('shrink-0');
        expect(stopIcon).toHaveClass('shrink-0');
        expect(messageIcon).toHaveClass('shrink-0');

        const controlsContainer = jellyfinPause.parentElement as HTMLElement;
        expect(controlsContainer).toHaveClass('flex', 'flex-wrap', 'items-center', 'gap-2');

        expect(within(plexArticle).queryByRole('button', { name: /^Pause$/i })).not.toBeInTheDocument();
        expect(within(plexArticle).queryByRole('button', { name: /^Resume$/i })).not.toBeInTheDocument();
        expect(within(plexArticle).queryByRole('button', { name: /^Stop$/i })).not.toBeInTheDocument();
        expect(within(plexArticle).queryByRole('button', { name: /^Message$/i })).not.toBeInTheDocument();
        expect(within(plexArticle).getByText('Read-Only')).toBeInTheDocument();
        expect(within(plexArticle).getByText(/Read-only stream telemetry \u00b7 Remote control unsupported for Plex/i)).toBeInTheDocument();
    });

    it('verifies Candidate H active session 320px inner containment and natural wrapping without truncation', () => {
        render(<StreamingTab />);
        const sessionsGrid = screen.getByTestId('active-sessions-grid');
        const sessionArticles = within(sessionsGrid).getAllByRole('article');

        for (const articleElement of sessionArticles) {
            const heading = within(articleElement).getByRole('heading', { level: 4 });
            expect(heading).toHaveClass('break-words');
            expect(heading).not.toHaveClass('truncate');

            const deliveryBadges = within(articleElement).getAllByText(/Direct Play|Transcode/i);
            for (const badgeElement of deliveryBadges) {
                if (badgeElement.tagName.toLowerCase() === 'span') {
                    expect(badgeElement).not.toHaveClass('truncate');
                }
            }
        }
    });

    it('verifies Candidate H historical filters summary uses >=12px font and natural wrapping without truncation at 320px', () => {
        render(<StreamingTab />);
        const filterSummary = screen.getByLabelText('Historical Analytics Filters');
        expect(filterSummary).toBeInTheDocument();
        const summaryText = within(filterSummary).getByText(/Window:/i);
        expect(summaryText).toHaveClass('text-xs', 'break-words');
        expect(summaryText).not.toHaveClass('truncate');
        expect(summaryText).not.toHaveClass('text-[11px]');
    });

    it('verifies Candidate H historical filters selected summary reuses human labels for DirectStream and Episode choices', () => {
        render(<StreamingTab />);
        const filterSummary = screen.getByLabelText('Historical Analytics Filters');
        expect(filterSummary).toBeInTheDocument();

        expect(within(filterSummary).getByText(/Window: 30 Days · All Methods · All Media/i)).toBeInTheDocument();

        const allTimeButton = screen.getByRole('button', { name: 'All Time' });
        const directStreamButton = screen.getByRole('button', { name: 'Direct Stream' });
        const episodesButton = screen.getByRole('button', { name: 'Episodes' });

        fireEvent.click(allTimeButton);
        fireEvent.click(directStreamButton);
        fireEvent.click(episodesButton);

        const updatedSummaryText = within(filterSummary).getByText(/Window: All Time · Direct Stream · Episodes/i);
        expect(updatedSummaryText).toBeInTheDocument();
        expect(updatedSummaryText).toHaveClass('text-xs', 'break-words');
        expect(updatedSummaryText).not.toHaveClass('truncate');
        expect(within(filterSummary).queryByText(/DirectStream/)).not.toBeInTheDocument();
        expect(within(filterSummary).queryByText(/· Episode$/)).not.toBeInTheDocument();
    });

    it('verifies Candidate H Live KPI stream delivery badges use >=12px text with honest wrapping', () => {
        render(<StreamingTab />);
        const activeStreamsCard = screen.getByText('Active Streams').closest('.rounded-xl') as HTMLElement;
        expect(activeStreamsCard).toBeInTheDocument();

        const directPlayBadge = within(activeStreamsCard).getByText(/Direct Play/i);
        expect(directPlayBadge).toHaveClass('text-xs', 'break-words');
        expect(directPlayBadge).not.toHaveClass('text-[11px]');

        const transcodeBadge = within(activeStreamsCard).getByText(/Transcode/i);
        expect(transcodeBadge).toHaveClass('text-xs', 'break-words');
        expect(transcodeBadge).not.toHaveClass('text-[11px]');
    });

    it('verifies Candidate H Configure Server dialog portal rendering, honest title wrapping, and >=44px touch targets', () => {
        const { unmount } = render(<StreamingTab />);
        const configureButton = screen.getByRole('button', { name: /Configure Server/i });
        fireEvent.click(configureButton);

        const dialogElement = screen.getByRole('dialog', { name: 'Media Server Providers' });
        expect(dialogElement).toBeInTheDocument();
        expect(document.body.contains(dialogElement)).toBe(true);

        const modalTitle = within(dialogElement).getByRole('heading', { level: 3 });
        expect(modalTitle).toHaveClass('break-words');
        expect(modalTitle).not.toHaveClass('truncate');

        const closeButton = within(dialogElement).getByRole('button', { name: 'Close modal' });
        expect(closeButton).toHaveClass('obs-touch-target-standard', 'min-h-[44px]', 'min-w-[44px]');

        const testConnectionButton = within(dialogElement).getByRole('button', { name: /Test Connection/i });
        expect(testConnectionButton).toHaveClass('obs-touch-target-standard', 'min-h-[44px]');

        const cancelButton = within(dialogElement).getByRole('button', { name: /^Cancel$/i });
        expect(cancelButton).toHaveClass('obs-touch-target-standard', 'min-h-[44px]');

        const saveConnectionButton = within(dialogElement).getByRole('button', { name: /Save Connection/i });
        expect(saveConnectionButton).toHaveClass('obs-touch-target-standard', 'min-h-[44px]');

        fireEvent.click(cancelButton);
        expect(screen.queryByRole('dialog', { name: 'Media Server Providers' })).not.toBeInTheDocument();
        unmount();
    });

    it('verifies Candidate I mobile view selector and desktop tabs reachability', () => {
        render(<StreamingTab />);
        const mobileSelector = screen.getByLabelText('Select streaming view') as HTMLSelectElement;
        expect(mobileSelector).toBeInTheDocument();
        expect(mobileSelector).toHaveClass('min-h-[44px]');
        expect(mobileSelector.id).toBe('mobile-streaming-view-selector');

        const options = Array.from(mobileSelector.options).map((optionItem) => optionItem.value);
        expect(options).toEqual(['dashboard', 'streams', 'analytics', 'history']);

        fireEvent.change(mobileSelector, { target: { value: 'analytics' } });
        expect(mobileSelector.value).toBe('analytics');

        const navElement = screen.getByRole('navigation', { name: 'Streaming views' });
        expect(navElement).toBeInTheDocument();

        const desktopContainer = navElement.querySelector('.hidden.sm\\:flex') as HTMLElement;
        expect(desktopContainer).toBeInTheDocument();
        expect(desktopContainer).toHaveClass('hidden', 'sm:flex');

        const desktopAnalyticsButton = within(desktopContainer).getByRole('button', { name: /Playback analytics/i });
        expect(desktopAnalyticsButton).toBeInTheDocument();
    });

    it('verifies Candidate I neutral Plex read-only telemetry badge and Jellyfin retention', () => {
        const plexObservedData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        plexObservedData.activeSessions[0].provider = 'Plex';
        currentSwrState = { ...currentSwrState, data: plexObservedData };

        render(<StreamingTab />);
        const plexBadge = screen.getByText(/Plex · Read-only telemetry/i);
        expect(plexBadge).toBeInTheDocument();
        expect(plexBadge).toHaveClass('text-slate-300', 'border-white/10');
        expect(screen.queryByText(/Plex · Telemetry$/i)).not.toBeInTheDocument();

        expect(screen.getByRole('button', { name: /^Jellyfin/i })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Sync Jellyfin/i })).toBeInTheDocument();
    });

    it('verifies Candidate I visible playback and transcode buffer semantics when buffer is ahead', () => {
        const customData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        customData.activeSessions[0].progressPct = 32.1;
        customData.activeSessions[0].transcodeProgressPct = 65.0;
        currentSwrState = { ...currentSwrState, data: customData };

        render(<StreamingTab />);
        expect(screen.getByText(/Playback 32\.1%/i)).toBeInTheDocument();
        expect(screen.getByText(/Transcode buffer 65\.0%/i)).toBeInTheDocument();
    });

    it('verifies Candidate I operational axis and helper font sizes are at least 12px with contrast', () => {
        render(<StreamingTab />);
        const helperElements = screen.getAllByText(/Bar reflects share of plays; estimated transfer shown separately/i);
        expect(helperElements.length).toBe(2);
        for (const helperItem of helperElements) {
            expect(helperItem).toHaveClass('text-xs');
            expect(helperItem).not.toHaveClass('text-[11px]');
        }

        const methodologySummary = screen.getByText(/How these metrics are measured/i).closest('summary');
        expect(methodologySummary).toHaveClass('min-h-[44px]');
    });

    it('verifies Candidate I unified compact idle area with integrated connection freshness footer and nonduplication', () => {
        const idleCustomData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        idleCustomData.activeSessions = [];
        idleCustomData.liveSummary.activeStreams = 0;
        idleCustomData.liveSummary.totalBandwidthMbps = 0;
        idleCustomData.liveSummary.totalBitrateBps = 0;
        idleCustomData.liveSummary.activeSessionBytes = 0;
        currentSwrState = { ...currentSwrState, data: idleCustomData };

        render(<StreamingTab />);
        const unifiedCard = screen.getByTestId('compact-no-streams-state').parentElement as HTMLElement;
        expect(within(unifiedCard).getByText(/Active streams:/i)).toBeInTheDocument();
        expect(within(unifiedCard).getByText(/Bandwidth:/i)).toBeInTheDocument();
        expect(within(unifiedCard).getByText('0')).toHaveClass('font-bold');
        expect(within(unifiedCard).getByText('0.0')).toHaveClass('font-bold');

        expect(within(unifiedCard).queryByText('0 concurrent sessions')).not.toBeInTheDocument();
        expect(within(unifiedCard).queryByText(/0 sessions/i)).not.toBeInTheDocument();
        expect(within(unifiedCard).queryByText('Connected idle · Standing by')).not.toBeInTheDocument();
        expect(within(unifiedCard).queryByText('Idle · No active throughput')).not.toBeInTheDocument();

        expect(within(unifiedCard).getByText(/connected · Idle/i)).toBeInTheDocument();
        expect(within(unifiedCard).getByText(/Last contact:/i)).toBeInTheDocument();
    });

    it('verifies Candidate I compact mobile historical header and consolidated filter summary', () => {
        render(<StreamingTab />);
        const historicalHeading = screen.getByRole('heading', { level: 3, name: /Historical Analytics/i });
        expect(historicalHeading).toBeInTheDocument();
        expect(historicalHeading).toHaveTextContent('Historical Analytics');
        expect(screen.getByText('All recorded providers')).toBeInTheDocument();

        const filterSummaryElement = screen.getByLabelText('Historical Analytics Filters');
        expect(within(filterSummaryElement).getByText(/Confirmed & estimated/i)).toBeInTheDocument();
        expect(within(filterSummaryElement).getByText(/Window: 30 Days/i)).toBeInTheDocument();
    });

    it('verifies Candidate J independent visible tracks for playback and transcode buffer without rail conflation', () => {
        const customData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        customData.activeSessions[0].progressPct = 32.1;
        customData.activeSessions[0].transcodeProgressPct = 85.0;
        currentSwrState = { ...currentSwrState, data: customData };

        render(<StreamingTab />);
        expect(screen.getByText(/Playback 32\.1%/i)).toBeInTheDocument();
        expect(screen.getByText(/Transcode buffer 85\.0%/i)).toBeInTheDocument();
        expect(screen.getAllByText('Buffer track').length).toBeGreaterThanOrEqual(1);
        expect(screen.getAllByText('Buffer track')[0]).toHaveClass('text-[13px]');

        const sessionGrid = screen.getByTestId('active-sessions-grid');
        const sessionArticle = within(sessionGrid).getAllByRole('article')[0];
        const progressBars = sessionArticle.querySelectorAll('.h-1\\.5.w-full.rounded-full');
        expect(progressBars.length).toBeGreaterThanOrEqual(2);
    });

    it('verifies Candidate J mobile title, actions, and full-width provider badges reflow', () => {
        const plexData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        plexData.activeSessions[0].provider = 'Plex';
        currentSwrState = { ...currentSwrState, data: plexData };

        render(<StreamingTab />);
        const dashboardTitle = screen.getByRole('heading', { level: 2, name: 'Streaming Dashboard' });
        expect(dashboardTitle).toBeInTheDocument();

        const serverActionsSummary = screen.getByLabelText('Server & Provider Actions');
        expect(serverActionsSummary).toBeInTheDocument();
        expect(serverActionsSummary).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');

        const jellyfinButton = screen.getByRole('button', { name: /^Jellyfin/i });
        expect(jellyfinButton).toBeInTheDocument();

        const plexBadge = screen.getByText(/Plex · Read-only telemetry/i);
        expect(plexBadge).toBeInTheDocument();

        const providerBadgesContainer = jellyfinButton.parentElement as HTMLElement;
        expect(providerBadgesContainer).toHaveClass('w-full', 'order-3', 'sm:order-none', 'sm:w-auto');
    });

    it('verifies Candidate K merged chart mapping strips, standardized playback progress, and top-aligned session cards', () => {
        render(<StreamingTab />);
        const sessionGridElement = screen.getByTestId('active-sessions-grid');
        expect(sessionGridElement).toHaveClass('items-start');

        expect(screen.getByText('Playback 45.4%')).toBeInTheDocument();

        const transferChartHeading = screen.getByText('Stream Data Usage & Bandwidth Over Time');
        const transferChartContainer = transferChartHeading.closest('.rounded-xl') as HTMLElement;
        expect(within(transferChartContainer).getAllByText('Estimated').length).toBe(1);

        const activityChartHeading = screen.getByText('Play Sessions & Watch Time Activity');
        const activityChartContainer = activityChartHeading.closest('.rounded-xl') as HTMLElement;
        const watchTimeLegendElement = within(activityChartContainer).getByText('Watch time (hours)');
        expect(watchTimeLegendElement.previousElementSibling).toHaveClass('border-dashed');

        const historicalHeadingElement = screen.getByRole('heading', { level: 3, name: /Historical Analytics/i });
        expect(historicalHeadingElement).toHaveTextContent('Historical Analytics (30 Days)');

        expect(screen.getByText('Resolution Mix · Share of Plays')).toBeInTheDocument();
        expect(screen.getByText('Source Codec Telemetry · Share of Plays')).toBeInTheDocument();
    });

    it('verifies Candidate L decoupled single-quantity plots, aligned time scope, operational annotations, and standardized chevrons', () => {
        const candidateLData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        candidateLData.activeSessions = [
            {
                ...mockDashboardData.activeSessions[0],
                sessionId: 'plex-unsupported-session',
                provider: 'Plex',
                state: 'playing',
                supportsMediaControl: false,
                canSendMessage: false,
            },
            {
                ...mockDashboardData.activeSessions[1],
                sessionId: 'jf-supported-session',
                provider: 'jellyfin',
                state: 'playing',
                supportsMediaControl: true,
                canSendMessage: true,
            },
        ];
        currentSwrState = { ...currentSwrState, data: candidateLData };

        render(<StreamingTab />);

        const transferHeading = screen.getByText('Stream Data Usage & Bandwidth Over Time');
        const transferCard = transferHeading.closest('.rounded-xl') as HTMLElement;
        expect(transferCard).toBeInTheDocument();

        expect(within(transferCard).queryByText('Left axis:')).not.toBeInTheDocument();
        expect(within(transferCard).queryByText('Right axis:')).not.toBeInTheDocument();

        const transferredDataTitle = within(transferCard).getByText('Transferred data (GB)');
        expect(transferredDataTitle).toBeInTheDocument();
        const peakBitrateTitle = within(transferCard).getByText('Recorded peak bitrate (Mbps)');
        expect(peakBitrateTitle).toBeInTheDocument();

        expect(transferredDataTitle.compareDocumentPosition(peakBitrateTitle) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

        const transferCardContainers = transferCard.querySelectorAll('[data-testid="recharts-responsive-container"]');
        expect(transferCardContainers.length).toBe(2);
        expect(transferCardContainers[0]).toHaveAttribute('data-sync-id', 'stream-transfer-bandwidth');
        expect(transferCardContainers[0]).toHaveAttribute('data-sync-method', 'value');
        expect(transferCardContainers[1]).toHaveAttribute('data-sync-id', 'stream-transfer-bandwidth');
        expect(transferCardContainers[1]).toHaveAttribute('data-sync-method', 'value');

        const activityHeading = screen.getByText('Play Sessions & Watch Time Activity');
        const activityCard = activityHeading.closest('.rounded-xl') as HTMLElement;
        expect(activityCard).toBeInTheDocument();

        expect(within(activityCard).queryByText('Left axis:')).not.toBeInTheDocument();
        expect(within(activityCard).queryByText('Right axis:')).not.toBeInTheDocument();

        const playSessionsTitle = within(activityCard).getByText('Play sessions');
        expect(playSessionsTitle).toBeInTheDocument();
        const watchHoursTitle = within(activityCard).getByText('Watch time (hours)');
        expect(watchHoursTitle).toBeInTheDocument();

        expect(playSessionsTitle.compareDocumentPosition(watchHoursTitle) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

        const activityCardContainers = activityCard.querySelectorAll('[data-testid="recharts-responsive-container"]');
        expect(activityCardContainers.length).toBe(2);
        expect(activityCardContainers[0]).toHaveAttribute('data-sync-id', 'stream-sessions-watchtime');
        expect(activityCardContainers[0]).toHaveAttribute('data-sync-method', 'value');
        expect(activityCardContainers[0]).toHaveAttribute('data-xaxis-scale', 'band');
        expect(activityCardContainers[1]).toHaveAttribute('data-sync-id', 'stream-sessions-watchtime');
        expect(activityCardContainers[1]).toHaveAttribute('data-sync-method', 'value');
        expect(activityCardContainers[1]).toHaveAttribute('data-xaxis-scale', 'band');

        expect(within(activityCard).getByText('Direct Play (sessions)')).toBeInTheDocument();
        expect(within(activityCard).getByText('Direct Stream (sessions)')).toBeInTheDocument();
        expect(within(activityCard).getByText('Transcode (sessions)')).toBeInTheDocument();
        expect(within(activityCard).getByText('Unknown (sessions)')).toBeInTheDocument();

        expect(watchHoursTitle.previousElementSibling).toHaveClass('border-dashed');

        const resolutionCard = screen.getByText('Resolution Mix · Share of Plays').closest('.rounded-xl') as HTMLElement;
        const resolutionAnnotations = within(resolutionCard).getAllByText(/est\./i);
        expect(resolutionAnnotations.length).toBeGreaterThan(0);
        for (const annotationElement of resolutionAnnotations) {
            expect(annotationElement).toHaveClass('text-[13px]', 'text-slate-300');
        }

        const codecCard = screen.getByText('Source Codec Telemetry · Share of Plays').closest('.rounded-xl') as HTMLElement;
        const codecAnnotations = within(codecCard).getAllByText(/est\./i);
        expect(codecAnnotations.length).toBeGreaterThan(0);
        for (const annotationElement of codecAnnotations) {
            expect(annotationElement).toHaveClass('text-[13px]', 'text-slate-300');
        }

        const plexCapabilityStatement = screen.getByText(/Read-only stream telemetry/i);
        expect(plexCapabilityStatement).toBeInTheDocument();
        expect(plexCapabilityStatement).toHaveTextContent(/Remote control unsupported for Plex/i);
        const plexCapabilityContainer = plexCapabilityStatement.closest('div.text-\\[13px\\]') as HTMLElement;
        expect(plexCapabilityContainer).toHaveClass('text-[13px]', 'text-slate-200');

        const plexCard = plexCapabilityStatement.closest('article') as HTMLElement;
        expect(within(plexCard).queryByRole('button', { name: /^pause$/i })).not.toBeInTheDocument();
        expect(within(plexCard).queryByRole('button', { name: /^resume$/i })).not.toBeInTheDocument();
        expect(within(plexCard).queryByRole('button', { name: /^stop$/i })).not.toBeInTheDocument();

        const allSummaryElements = document.querySelectorAll('summary');
        expect(allSummaryElements.length).toBeGreaterThanOrEqual(4);
        for (const summaryElement of allSummaryElements) {
            const chevronElement = summaryElement.querySelector('.lucide-chevron-down');
            expect(chevronElement).toBeInTheDocument();
        }
    });

    it('verifies Candidate M numeric-only Y ticks, explicit quantity units, and consistent pair widths', () => {
        mockRole = 'admin';
        currentSwrState = { ...currentSwrState, data: mockDashboardData };
        render(<StreamingTab />);

        const responsiveContainers = screen.getAllByTestId('recharts-responsive-container');
        expect(responsiveContainers.length).toBe(4);

        const transferContainer = responsiveContainers[0];
        const bitrateContainer = responsiveContainers[1];
        const sessionsContainer = responsiveContainers[2];
        const watchHoursContainer = responsiveContainers[3];

        expect(transferContainer).toHaveAttribute('data-yaxis-width', '56');
        expect(bitrateContainer).toHaveAttribute('data-yaxis-width', '56');
        expect(sessionsContainer).toHaveAttribute('data-yaxis-width', '48');
        expect(watchHoursContainer).toHaveAttribute('data-yaxis-width', '48');

        for (const singleContainer of responsiveContainers) {
            expect(singleContainer).toHaveAttribute('data-yaxis-sample-tick', '80');
            expect(singleContainer).toHaveAttribute('data-yaxis-max-tick', '1200');
        }

        expect(screen.getByText('Transferred data (GB)')).toBeInTheDocument();
        expect(screen.getByText('Recorded peak bitrate (Mbps)')).toBeInTheDocument();
        expect(screen.getByText('Direct Play (sessions)')).toBeInTheDocument();
        expect(screen.getByText('Watch time (hours)')).toBeInTheDocument();
    });

    it('verifies Candidate M historical filters whole-group flexwrap, non-shrinking segmented options, and desktop header rows', () => {
        mockRole = 'admin';
        currentSwrState = { ...currentSwrState, data: mockDashboardData };
        render(<StreamingTab />);

        const destinationNav = screen.getByRole('navigation', { name: 'Streaming views' });
        expect(destinationNav).toBeInTheDocument();
        expect(destinationNav).toHaveClass('w-full', 'min-w-0', 'shrink-0');

        const headerContainer = destinationNav.parentElement;
        expect(headerContainer?.className).not.toContain('min-[1800px]:flex-row');

        const allWindowButtons = screen.getAllByRole('button', { name: /^(7 days|30 days|90 days|180 days)$/i });
        for (const windowButton of allWindowButtons) {
            expect(windowButton).toHaveClass('whitespace-nowrap', 'shrink-0');
        }

        const transcodeReasonElement = screen.getByText('Transcode reason:').parentElement;
        expect(transcodeReasonElement).toHaveClass('text-[13px]', 'text-slate-300');

        const containerLabels = screen.getAllByText('Container');
        expect(containerLabels.length).toBeGreaterThan(0);
        for (const containerLabel of containerLabels) {
            expect(containerLabel).toHaveClass('text-[13px]', 'text-slate-300');
        }

        const resolutionCard = screen.getByText('Resolution Mix · Share of Plays').closest('.rounded-xl') as HTMLElement;
        const resolutionLabels = within(resolutionCard).getAllByText(/^(1080p|4K UHD)$/);
        expect(resolutionLabels.length).toBe(2);
        expect(resolutionLabels[0]).toHaveTextContent('1080p');
        expect(resolutionLabels[1]).toHaveTextContent('4K UHD');

        const resolution1080pRow = resolutionLabels[0].parentElement?.parentElement as HTMLElement;
        const resolution4kRow = resolutionLabels[1].parentElement?.parentElement as HTMLElement;
        const resolution1080pBar = resolution1080pRow.querySelector('.bg-gradient-to-r') as HTMLElement;
        const resolution4kBar = resolution4kRow.querySelector('.bg-gradient-to-r') as HTMLElement;

        expect(resolution1080pBar.style.width).toBe('57.1%');
        expect(resolution4kBar.style.width).toBe('42.9%');
    });

    it('verifies Candidate M responsive historical filters internal wrap on mobile and whole-group flow on desktop', () => {
        mockRole = 'admin';
        currentSwrState = { ...currentSwrState, data: mockDashboardData };
        render(<StreamingTab />);

        const timeWindowGroup = screen.getByRole('group', { name: 'Time Window Filter' });
        const playMethodGroup = screen.getByRole('group', { name: 'Play Method Filter' });
        const mediaTypeGroup = screen.getByRole('group', { name: 'Media Type Filter' });

        const filterGroups = [timeWindowGroup, playMethodGroup, mediaTypeGroup];
        for (const singleFilterGroup of filterGroups) {
            expect(singleFilterGroup).toHaveClass(
                'flex',
                'flex-wrap',
                'w-full',
                'max-w-full',
                'min-w-0',
                'sm:w-auto',
                'sm:flex-nowrap',
                'sm:shrink-0'
            );

            const groupWrapper = singleFilterGroup.parentElement as HTMLElement;
            expect(groupWrapper).toHaveClass(
                'flex',
                'flex-col',
                'sm:flex-row',
                'items-start',
                'sm:items-center',
                'w-full',
                'max-w-full',
                'min-w-0',
                'sm:w-auto',
                'sm:shrink-0'
            );
        }

        const unknownButton = screen.getByRole('button', { name: 'Unknown' });
        expect(unknownButton).toBeInTheDocument();
        expect(unknownButton).toHaveClass('whitespace-nowrap', 'shrink-0');
        expect(unknownButton.className).toContain('min-h-[44px]');

        const allTimeButton = screen.getByRole('button', { name: 'All Time' });
        expect(allTimeButton).toBeInTheDocument();
        expect(allTimeButton).toHaveClass('whitespace-nowrap', 'shrink-0');
        expect(allTimeButton.className).toContain('min-h-[44px]');

        const filterToolbar = timeWindowGroup.parentElement?.parentElement as HTMLElement;
        expect(filterToolbar).toHaveClass('flex', 'flex-wrap', 'w-full', 'min-w-0', 'max-w-full');
    });

    it('verifies Candidate N truthful peak scopes for unequal, equal, differ, and zero states', () => {
        mockRole = 'admin';
        currentSwrState = { ...currentSwrState, data: mockDashboardData };
        const { rerender } = render(<StreamingTab />);

        expect(screen.getByText(/Window peak \(incl\. live\):/)).toBeInTheDocument();
        expect(screen.getByText('62.4 Mbps')).toBeInTheDocument();
        expect(screen.getByText(/Charted peak: 48\.5 Mbps/)).toBeInTheDocument();

        const equalData: StreamingDashboardData = {
            ...mockDashboardData,
            analytics: {
                ...mockDashboardData.analytics,
                peakBandwidthMbps: 48.5,
            },
        };
        currentSwrState = { ...currentSwrState, data: equalData };
        rerender(<StreamingTab />);
        expect(screen.getByText(/Window peak \(incl\. live\):/)).toBeInTheDocument();
        expect(screen.getByText('48.5 Mbps')).toBeInTheDocument();
        expect(screen.queryByText(/Charted peak:/)).not.toBeInTheDocument();

        const differData: StreamingDashboardData = {
            ...mockDashboardData,
            analytics: {
                ...mockDashboardData.analytics,
                peakBandwidthMbps: 62.4,
                timeSeries: [],
            },
        };
        currentSwrState = { ...currentSwrState, data: differData };
        rerender(<StreamingTab />);
        expect(screen.getByText(/Window summary and recorded buckets differ/)).toBeInTheDocument();

        const zeroData: StreamingDashboardData = {
            ...mockDashboardData,
            analytics: {
                ...mockDashboardData.analytics,
                peakBandwidthMbps: 0,
            },
        };
        currentSwrState = { ...currentSwrState, data: zeroData };
        rerender(<StreamingTab />);
        expect(screen.getByText('No recorded throughput peaks')).toBeInTheDocument();
    });

    it('verifies Candidate N single shared bottom date labeling, normalized Plex casing, and reduced filter chrome', () => {
        const plexNormalizedData: StreamingDashboardData = {
            ...mockDashboardData,
            activeSessions: [
                {
                    ...mockDashboardData.activeSessions[0],
                    sessionId: 'plex-stream-1',
                    provider: 'plex',
                    serverName: 'Home-Plex',
                    supportsMediaControl: false,
                    canSendMessage: false,
                },
            ],
        };
        mockRole = 'admin';
        currentSwrState = { ...currentSwrState, data: plexNormalizedData };
        render(<StreamingTab />);

        const responsiveContainers = screen.getAllByTestId('recharts-responsive-container');
        expect(responsiveContainers.length).toBe(4);

        const transferPlot = responsiveContainers[0];
        const bitratePlot = responsiveContainers[1];
        const sessionsPlot = responsiveContainers[2];
        const watchHoursPlot = responsiveContainers[3];

        expect(transferPlot).toHaveAttribute('data-xaxis-tick', 'hidden');
        expect(bitratePlot).toHaveAttribute('data-xaxis-tick', 'visible');
        expect(sessionsPlot).toHaveAttribute('data-xaxis-tick', 'hidden');
        expect(watchHoursPlot).toHaveAttribute('data-xaxis-tick', 'visible');

        for (const singlePlot of [transferPlot, bitratePlot, sessionsPlot, watchHoursPlot]) {
            expect(singlePlot).toHaveAttribute('data-yaxis-interval', '0');
            const ticksAttribute = singlePlot.getAttribute('data-yaxis-ticks');
            expect(ticksAttribute).not.toBeNull();
            const parsedTicks = JSON.parse(ticksAttribute as string) as number[];
            expect(parsedTicks).toHaveLength(5);
            expect(parsedTicks[0]).toBe(0);
        }

        expect(screen.getByText('Recorded peak bitrate (Mbps)')).toBeInTheDocument();
        expect(screen.getByText('(Daily UTC buckets)')).toBeInTheDocument();

        const plexBadge = within(screen.getByTestId('active-sessions-grid')).getByText('Plex');
        expect(plexBadge).toBeInTheDocument();
        expect(plexBadge).toHaveClass('tracking-wider');

        const plexUnsupported = screen.getByText(/Remote control unsupported for Plex/);
        expect(plexUnsupported).toBeInTheDocument();

        const plexArticle = plexBadge.closest('article') as HTMLElement;
        expect(within(plexArticle).queryByRole('button', { name: /^pause$/i })).not.toBeInTheDocument();
        expect(within(plexArticle).queryByRole('button', { name: /^resume$/i })).not.toBeInTheDocument();
        expect(within(plexArticle).queryByRole('button', { name: /^stop$/i })).not.toBeInTheDocument();

        const methodologyButtons = screen.getAllByText('How these metrics are measured');
        expect(methodologyButtons.length).toBeGreaterThanOrEqual(1);
    });

    it('verifies Candidate O desktop simplified filter header, analytics annotations breathing room, and synchronized vertical date reference grid', () => {
        render(<StreamingTab />);

        const historicalHeading = screen.getByRole('heading', { level: 3, name: /Historical Analytics/i });
        expect(historicalHeading).toHaveTextContent('Historical Analytics (30 Days)');
        expect(screen.getByText('All recorded providers')).toBeInTheDocument();

        const desktopHeaderRow = historicalHeading.parentElement?.parentElement as HTMLElement;
        expect(desktopHeaderRow).toBeInTheDocument();
        expect(within(desktopHeaderRow).queryByText(/^Historical Filters$/i)).not.toBeInTheDocument();
        expect(within(desktopHeaderRow).queryByText(/Window:/i)).not.toBeInTheDocument();
        expect(within(desktopHeaderRow).getByText('How these metrics are measured')).toBeInTheDocument();

        const responsiveContainers = screen.getAllByTestId('recharts-responsive-container');
        expect(responsiveContainers).toHaveLength(4);

        for (const singlePlot of responsiveContainers) {
            expect(singlePlot).toHaveAttribute('data-grid-vertical', 'visible');
            expect(singlePlot).toHaveAttribute('data-grid-sync-with-ticks', 'true');
            expect(singlePlot).toHaveAttribute('data-yaxis-interval', '0');
        }

        const directPlayBox = screen.getAllByText('Direct Play').find((elementNode) => elementNode.classList.contains('text-emerald-400'))?.closest('div') as HTMLElement;
        expect(directPlayBox).toHaveClass('p-3');

        const resolutionCard = screen.getByText('Resolution Mix · Share of Plays').closest('.rounded-xl') as HTMLElement;
        const countElements = within(resolutionCard).getAllByText(/\d+\s+plays/);
        expect(countElements.length).toBeGreaterThan(0);
        for (const countElement of countElements) {
            expect(countElement).toHaveClass('tabular-nums');
        }

        expect(responsiveContainers[0]).toHaveAttribute('data-xaxis-null-renderer', 'true');
        expect(responsiveContainers[0]).toHaveAttribute('data-xaxis-has-formatter', 'true');
        expect(responsiveContainers[0]).toHaveAttribute('data-xaxis-tick', 'hidden');

        expect(responsiveContainers[1]).toHaveAttribute('data-xaxis-null-renderer', 'false');
        expect(responsiveContainers[1]).toHaveAttribute('data-xaxis-has-formatter', 'true');
        expect(responsiveContainers[1]).toHaveAttribute('data-xaxis-tick', 'visible');

        expect(responsiveContainers[2]).toHaveAttribute('data-xaxis-null-renderer', 'true');
        expect(responsiveContainers[2]).toHaveAttribute('data-xaxis-has-formatter', 'true');
        expect(responsiveContainers[2]).toHaveAttribute('data-xaxis-tick', 'hidden');

        expect(responsiveContainers[3]).toHaveAttribute('data-xaxis-null-renderer', 'false');
        expect(responsiveContainers[3]).toHaveAttribute('data-xaxis-has-formatter', 'true');
        expect(responsiveContainers[3]).toHaveAttribute('data-xaxis-tick', 'visible');
    });

    it('proves native Recharts getTicks and getCoordinatesOfGrid generate identical vertical date grid coordinates for upper null-tick renderer and lower axis', () => {
        const { getTicks } = jest.requireActual('recharts/lib/cartesian/getTicks');
        const { getCoordinatesOfGrid } = jest.requireActual('recharts/lib/util/ChartUtils');
        const { defaultCartesianAxisProps } = jest.requireActual('recharts/lib/cartesian/CartesianAxis');

        const mockDates = [];
        const baseDate = new Date('2026-10-09T00:00:00Z');
        for (let dayIndex = 0; dayIndex < 30; dayIndex += 1) {
            const dateEntry = new Date(baseDate.getTime() + dayIndex * 86400000);
            mockDates.push({
                value: dateEntry.toISOString(),
                coordinate: 48 + dayIndex * 31.724137931,
            });
        }

        const dateTickFormatter = (dateString: string) => {
            const parsedDate = new Date(dateString);
            return `${parsedDate.getUTCMonth() + 1}/${String(parsedDate.getUTCDate()).padStart(2, '0')}`;
        };

        const renderNullTick = () => null;

        const lowerAxisDefinition = {
            ...defaultCartesianAxisProps,
            dataKey: 'date',
            tick: { fill: '#e2e8f0', fontSize: 13 },
            tickFormatter: dateTickFormatter,
            minTickGap: 24,
            orientation: 'bottom',
            ticks: mockDates,
            viewBox: { x: 0, y: 0, width: 986, height: 160 },
        };

        const upperAxisDefinition = {
            ...defaultCartesianAxisProps,
            dataKey: 'date',
            tick: renderNullTick,
            tickLine: false,
            axisLine: { stroke: 'rgba(255,255,255,0.1)' },
            height: 8,
            minTickGap: 24,
            tickFormatter: dateTickFormatter,
            orientation: 'bottom',
            ticks: mockDates,
            viewBox: { x: 0, y: 0, width: 986, height: 160 },
        };

        const lowerTicks = getTicks(lowerAxisDefinition);
        const upperTicks = getTicks(upperAxisDefinition);
        expect(lowerTicks.length).toBeGreaterThan(0);
        expect(upperTicks.length).toBe(lowerTicks.length);

        const lowerGridCoordinates = getCoordinatesOfGrid(lowerTicks, 48, 968, true);
        const upperGridCoordinates = getCoordinatesOfGrid(upperTicks, 48, 968, true);

        expect(upperGridCoordinates.length).toBe(lowerGridCoordinates.length);
        expect(upperGridCoordinates).toEqual(lowerGridCoordinates);
        expect(renderNullTick()).toBeNull();
    });

    it('verifies Candidate P authentic last contact telemetry across active, idle, and disconnected states without fabricating timestamps', () => {
        const testTimestamp = '2026-11-05T14:30:00.000Z';
        const activeContactData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        activeContactData.servers[0].lastConnectedAt = testTimestamp;
        currentSwrState = { ...currentSwrState, data: activeContactData };

        const { unmount: unmountActive } = render(<StreamingTab />);
        expect(screen.getByText(/Last contact: 2026-11-05 14:30 UTC/i)).toBeInTheDocument();
        expect(screen.queryByText(/connected · Idle/i)).not.toBeInTheDocument();
        unmountActive();

        const idleContactData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        idleContactData.activeSessions = [];
        idleContactData.servers[0].lastConnectedAt = testTimestamp;
        currentSwrState = { ...currentSwrState, data: idleContactData };

        const { unmount: unmountIdle } = render(<StreamingTab />);
        const idleStrip = screen.getByTestId('compact-no-streams-state');
        expect(within(idleStrip).getByText(/connected · Idle/i)).toBeInTheDocument();
        expect(within(idleStrip).getByText(/Last contact: 2026-11-05 14:30 UTC/i)).toBeInTheDocument();
        unmountIdle();

        const disconnectedContactData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        disconnectedContactData.activeSessions = [];
        disconnectedContactData.servers[0].status = 'unreachable';
        disconnectedContactData.servers[0].errorMessage = 'Connection refused';
        disconnectedContactData.servers[0].lastConnectedAt = testTimestamp;
        currentSwrState = { ...currentSwrState, data: disconnectedContactData };

        const { unmount: unmountDisconnected } = render(<StreamingTab />);
        const disconnectedStrip = screen.getByTestId('compact-no-streams-state');
        expect(within(disconnectedStrip).getByText(/Connection refused/i)).toBeInTheDocument();
        expect(within(disconnectedStrip).getByText(/Last contact: 2026-11-05 14:30 UTC/i)).toBeInTheDocument();
        unmountDisconnected();

        const unobservedData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        unobservedData.servers[0].lastConnectedAt = '';
        currentSwrState = { ...currentSwrState, data: unobservedData };

        const { unmount: unmountUnobserved } = render(<StreamingTab />);
        expect(screen.queryByText(/Last contact:/i)).not.toBeInTheDocument();
        unmountUnobserved();
    });

    it('verifies Candidate P estimated active transfer accumulation formula and active streams population basis', () => {
        const transferData = JSON.parse(JSON.stringify(mockDashboardData)) as StreamingDashboardData;
        transferData.liveSummary.activeSessionBytes = 2469606195;
        currentSwrState = { ...currentSwrState, data: transferData };
        render(<StreamingTab />);

        expect(screen.getByText(/Estimated active transfer:/i)).toBeInTheDocument();
        expect(screen.getByText('2.3 GB')).toBeInTheDocument();

        const estimatedBadges = screen.getAllByText('ESTIMATED');
        expect(estimatedBadges.length).toBeGreaterThanOrEqual(1);

        const provenanceParagraph = screen.getByText(/Accumulated from observed playing intervals/i);
        expect(provenanceParagraph).toBeInTheDocument();
        expect(provenanceParagraph).toHaveClass('text-[13px]', 'text-slate-300');
        expect(provenanceParagraph).not.toHaveClass('text-[11px]');
        expect(provenanceParagraph).not.toHaveClass('text-slate-400');
        expect(screen.getByText(/bitrate × poll duration ÷ 8/i)).toBeInTheDocument();
        expect(screen.getByText(/across active playback sessions/i)).toBeInTheDocument();
    });

    it('verifies Candidate P analytical supporting typography, Charted peak, library categories, and watcher metrics ~13px slate300', () => {
        currentSwrState = { ...currentSwrState, data: mockDashboardData };
        render(<StreamingTab />);

        const chartedPeakElement = screen.getByText(/Charted peak: 48\.5 Mbps/i);
        expect(chartedPeakElement).toHaveClass('text-[13px]', 'text-slate-300');

        const confirmedPlaysSecondary = screen.getByText(/confirmed plays ·/i);
        expect(confirmedPlaysSecondary).toHaveClass('text-[13px]', 'text-slate-300');

        const libraryHeading = screen.getByText('Jellyfin Library');
        const libraryCard = libraryHeading.closest('.rounded-xl') as HTMLElement;
        const libraryGrid = libraryCard.querySelector('.grid') as HTMLElement;
        expect(libraryGrid).toHaveClass('text-[13px]', 'gap-y-1.5');

        const moviesLabel = within(libraryCard).getByText('Movies');
        expect(moviesLabel).toHaveClass('text-slate-300');

        const topWatchersHeading = screen.getByText('Top Watchers & Data Usage by User');
        const topWatchersCard = topWatchersHeading.closest('.rounded-xl') as HTMLElement;
        const userSubtitles = within(topWatchersCard).getAllByText(/unique titles ·/i);
        for (const userSubtitle of userSubtitles) {
            expect(userSubtitle).toHaveClass('text-[13px]', 'text-slate-300');
        }

        const mostWatchedHeading = screen.getByText('Most Watched Media Titles');
        const mostWatchedCard = mostWatchedHeading.closest('.rounded-xl') as HTMLElement;
        const mostWatchedSubtitles = within(mostWatchedCard).getAllByText(/viewer.*·/i);
        for (const mostWatchedSubtitle of mostWatchedSubtitles) {
            expect(mostWatchedSubtitle).toHaveClass('text-[13px]', 'text-slate-300');
        }
    });

    it('verifies Candidate P restrained historical filter pills styling, aria-pressed, touch targets, and mobile internal wrap', () => {
        currentSwrState = { ...currentSwrState, data: mockDashboardData };
        render(<StreamingTab />);

        const selectedPillLabels = ['30 Days', 'All Methods', 'All Media'];
        for (const pillLabel of selectedPillLabels) {
            const selectedButton = screen.getByRole('button', { name: pillLabel });
            expect(selectedButton).toHaveAttribute('aria-pressed', 'true');
            expect(selectedButton).toHaveClass('bg-indigo-600/30', 'border-indigo-500/50', 'text-indigo-200', 'shadow-sm');
            expect(selectedButton).not.toHaveClass('bg-indigo-600', 'text-white');
            expect(selectedButton.className).toContain('min-h-[44px]');
        }

        const unselectedButton = screen.getByRole('button', { name: '7 Days' });
        expect(unselectedButton).toHaveAttribute('aria-pressed', 'false');
        expect(unselectedButton).toHaveClass('border-transparent');
        expect(unselectedButton).not.toHaveClass('bg-indigo-600/30');

        const dashboardTab = screen.getByRole('button', { name: /^Dashboard$/ });
        expect(dashboardTab).toHaveClass('bg-indigo-600', 'text-white');
        expect(dashboardTab).not.toHaveClass('bg-indigo-600/30');
    });

    it('verifies Candidate P tightened pair plot vertical coupling while preserving verified Recharts date synchronization', () => {
        currentSwrState = { ...currentSwrState, data: mockDashboardData };
        render(<StreamingTab />);

        const bitrateHeader = screen.getByText('Recorded peak bitrate (Mbps)').parentElement?.parentElement as HTMLElement;
        expect(bitrateHeader).toHaveClass('pt-2.5', 'pb-1', 'mb-1.5');

        const watchTimeHeader = screen.getByText('Watch time (hours)').parentElement?.parentElement as HTMLElement;
        expect(watchTimeHeader).toHaveClass('pt-2.5', 'pb-1', 'mb-1.5');

        const responsiveContainers = screen.getAllByTestId('recharts-responsive-container');
        expect(responsiveContainers).toHaveLength(4);

        expect(responsiveContainers[0]).toHaveAttribute('data-sync-id', 'stream-transfer-bandwidth');
        expect(responsiveContainers[0]).toHaveAttribute('data-sync-method', 'value');
        expect(responsiveContainers[1]).toHaveAttribute('data-sync-id', 'stream-transfer-bandwidth');
        expect(responsiveContainers[1]).toHaveAttribute('data-sync-method', 'value');

        expect(responsiveContainers[2]).toHaveAttribute('data-sync-id', 'stream-sessions-watchtime');
        expect(responsiveContainers[2]).toHaveAttribute('data-sync-method', 'value');
        expect(responsiveContainers[3]).toHaveAttribute('data-sync-id', 'stream-sessions-watchtime');
        expect(responsiveContainers[3]).toHaveAttribute('data-sync-method', 'value');

        for (const singlePlot of responsiveContainers) {
            expect(singlePlot).toHaveAttribute('data-grid-sync-with-ticks', 'true');
            expect(singlePlot).toHaveAttribute('data-yaxis-interval', '0');
        }

        expect(responsiveContainers[0]).toHaveAttribute('data-xaxis-null-renderer', 'true');
        expect(responsiveContainers[0]).toHaveAttribute('data-xaxis-tick', 'hidden');
        expect(responsiveContainers[1]).toHaveAttribute('data-xaxis-null-renderer', 'false');
        expect(responsiveContainers[1]).toHaveAttribute('data-xaxis-tick', 'visible');
    });
});
