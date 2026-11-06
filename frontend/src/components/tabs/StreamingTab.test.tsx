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
        ResponsiveContainer: ({ children }: { children: React.ReactNode }) => (
            <div data-testid="recharts-responsive-container" style={{ width: 800, height: 300 }}>
                {children}
            </div>
        ),
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

    it('renders Jellyfin online status alongside Plex and Emby coming-soon indicators', () => {
        render(<StreamingTab />);
        expect(screen.getByText(/Streaming Dashboard/i)).toBeInTheDocument();
        expect(screen.getByText(/Jellyfin v10\.9\.11/i)).toBeInTheDocument();
        expect(screen.getByText(/Plex · Later/i)).toBeInTheDocument();
        expect(screen.getByText(/Emby · Later/i)).toBeInTheDocument();
    });

    it.each(['Dashboard', 'Play & Data Stats', 'Watch History'])('keeps the paginated archive below the primary sections in %s', (view) => {
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
                /Resolution & Bandwidth Share/i,
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
        expect(screen.getByText(/Legacy Record Statistics \(30d\)/i)).toBeInTheDocument();
        expect(screen.getByText(/Jellyfin Library/i)).toBeInTheDocument();
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
        const analyticsTabBtn = screen.getByRole('button', { name: /Play & Data Stats/i });
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
            mockDashboardData.activeSessions.map((s) => ({ ...s, state: 'paused' as const }))
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
        fireEvent.click(screen.getByRole('button', { name: /Play & Data Stats/i }));
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
});
