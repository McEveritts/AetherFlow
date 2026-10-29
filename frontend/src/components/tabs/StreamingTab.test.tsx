import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import StreamingTab, { StreamingDashboardData } from '@/components/tabs/StreamingTab';

// Mock ToastContext
jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: jest.fn(),
    }),
}));

// Mock AuthContext
jest.mock('@/contexts/AuthContext', () => ({
    useAuth: () => ({
        user: { id: 1, username: 'admin', role: 'admin' },
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
        ],
    },
    updatedAt: new Date().toISOString(),
};

// Mock SWR with Jellyfin streaming dashboard fixture
jest.mock('swr', () => {
    return jest.fn((key: string) => {
        if (key && key.includes('/streaming/dashboard')) {
            return {
                data: mockDashboardData,
                error: null,
                isLoading: false,
                mutate: jest.fn(),
            };
        }
        return { data: null, error: null, isLoading: false, mutate: jest.fn() };
    });
});

describe('StreamingTab - Jellyfin Play Statistics, Data Usage & Stream Telemetry', () => {
    it('renders Jellyfin online status alongside Plex and Emby coming-soon indicators', () => {
        render(<StreamingTab />);
        expect(screen.getByText(/Streaming Dashboard/i)).toBeInTheDocument();
        expect(screen.getByText(/Jellyfin v10\.9\.11/i)).toBeInTheDocument();
        expect(screen.getByText(/Plex · Later/i)).toBeInTheDocument();
        expect(screen.getByText(/Emby · Later/i)).toBeInTheDocument();
    });

    it('renders real-time bandwidth, data usage, and play statistics KPI cards', () => {
        render(<StreamingTab />);
        expect(screen.getByText(/Active Streams/i)).toBeInTheDocument();
        expect(screen.getByText(/Live Bandwidth/i)).toBeInTheDocument();
        expect(screen.getByText(/Data Usage \(30d\)/i)).toBeInTheDocument();
        expect(screen.getByText(/Play Statistics \(30d\)/i)).toBeInTheDocument();
        expect(screen.getByText(/Jellyfin Library/i)).toBeInTheDocument();
    });

    it('renders active stream cards with codec pipeline, Direct Play / Transcode badges, and session data usage', () => {
        render(<StreamingTab />);
        expect(screen.getAllByText(/Dune: Part Two/i).length).toBeGreaterThan(0);
        expect(screen.getAllByText(/Severance/i).length).toBeGreaterThan(0);
        expect(screen.getByText(/Transcode · VAAPI/i)).toBeInTheDocument();
        expect(screen.getByText(/Container Bitrate Exceeds Limit/i)).toBeInTheDocument();
    });

    it('opens the Jellyfin connection configuration modal when Configure Server button is clicked', () => {
        render(<StreamingTab />);
        const configBtn = screen.getByRole('button', { name: /Configure Server/i });
        fireEvent.click(configBtn);
        expect(screen.getByText(/Media Server Providers/i)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Test Connection/i })).toBeInTheDocument();
    });
});
