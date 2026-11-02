import { TextEncoder, TextDecoder } from 'util';
import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import StreamingInsights, {
    PatternsSummaryReport,
    DrilldownReport,
} from '@/components/streaming/StreamingInsights';
import { apiFetch } from '@/lib/fetcher';
import { StreamingHistoryQuery } from '@/lib/streaming-history';

Object.assign(globalThis, { TextEncoder, TextDecoder });

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
}));

const mockedApiFetch = apiFetch as jest.MockedFunction<typeof apiFetch>;

function createJsonResponse(body: unknown, status = 200): Response {
    return {
        ok: status >= 200 && status < 300,
        status,
        statusText: status === 200 ? 'OK' : 'Error',
        headers: new Headers({ 'Content-Type': 'application/json' }),
        json: async () => body,
        text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
    } as unknown as Response;
}

function makePatternsReport(
    overrides: Partial<PatternsSummaryReport> = {}
): PatternsSummaryReport {
    return {
        activity: {
            timezone: 'America/New_York',
            window: '30d',
            from: '2026-10-02T00:00:00Z',
            until: '2026-11-01T00:00:00Z',
            totalConfirmedPlays: 120,
            totalWatchTimeSecs: 216000,
            totalEstimatedBytes: 10737418240,
            undatedRecords: 3,
            hourlyBreakdown: Array.from({ length: 24 }, (_, hour) => ({
                hour,
                playCount: hour === 20 ? 42 : hour === 21 ? 30 : 2,
                watchTimeSecs: hour === 20 ? 75600 : 3600,
                estimatedBytes: hour === 20 ? 3221225472 : 104857600,
                percentageOfPlays: hour === 20 ? 35.0 : hour === 21 ? 25.0 : 1.67,
            })),
            weekdayBreakdown: [
                {
                    weekday: 0,
                    weekdayName: 'Monday',
                    playCount: 15,
                    watchTimeSecs: 27000,
                    estimatedBytes: 1073741824,
                    percentageOfPlays: 12.5,
                },
                {
                    weekday: 5,
                    weekdayName: 'Saturday',
                    playCount: 55,
                    watchTimeSecs: 99000,
                    estimatedBytes: 5368709120,
                    percentageOfPlays: 45.83,
                },
            ],
            timeseries: [
                {
                    bucketStart: '2026-10-30T00:00:00Z',
                    bucketEnd: '2026-10-31T00:00:00Z',
                    playCount: 28,
                    watchTimeSecs: 50400,
                    estimatedBytes: 2147483648,
                },
            ],
            dstTransitionsObserved: [
                'Observed DST transition in window: local UTC offset changed by -60 minutes (fall back (-offset))',
            ],
            ...(overrides.activity || {}),
        },
        concurrency: {
            window: '30d',
            from: '2026-10-02T00:00:00Z',
            until: '2026-11-01T00:00:00Z',
            timezone: 'America/New_York',
            retentionDays: 90,
            retentionCutoff: '2026-08-03T00:00:00Z',
            retentionLimited: true,
            peakConcurrency: 4,
            peakConcurrencyAt: '2026-10-30T21:15:00Z',
            avgConcurrency: 1.75,
            peakBitrateBps: 38500000,
            totalSamplesAnalyzed: 480,
            buckets: [
                {
                    bucketStart: '2026-07-20T00:00:00Z',
                    bucketEnd: '2026-07-21T00:00:00Z',
                    peakConcurrency: null,
                    avgConcurrency: null,
                    peakBitrateBps: null,
                    sampleCount: 0,
                    status: 'retention_expired',
                },
                {
                    bucketStart: '2026-10-29T00:00:00Z',
                    bucketEnd: '2026-10-30T00:00:00Z',
                    peakConcurrency: 0,
                    avgConcurrency: 0,
                    peakBitrateBps: 0,
                    sampleCount: 0,
                    status: 'gap',
                },
                {
                    bucketStart: '2026-10-30T00:00:00Z',
                    bucketEnd: '2026-10-31T00:00:00Z',
                    peakConcurrency: 4,
                    avgConcurrency: 2.1,
                    peakBitrateBps: 38500000,
                    sampleCount: 120,
                    status: 'available',
                },
            ],
            limitations: [
                'Concurrency is derived exclusively from active samples in streaming_session_samples (playing = 1).',
                'Detailed session samples are retained for at most 90 days; older periods are classified as retention_expired.',
            ],
            ...(overrides.concurrency || {}),
        },
    };
}

function makeDrilldownReport(
    overrides: Partial<DrilldownReport> = {}
): DrilldownReport {
    return {
        cohortDistinctPlays: 100,
        cohortTotalWatchTimeSecs: 180000,
        cohortTotalEstimatedBytes: 8589934592,
        cohortDistinctUsers: 5,
        cohortDistinctItems: 12,
        users: [
            {
                provider: 'jellyfin',
                serverId: 'srv-alpha',
                userId: 'user-101',
                userName: 'Alex Duplicate Name',
                playCount: 45,
                watchTimeSecs: 81000,
                estimatedBytes: 4294967296,
                distinctItems: 6,
                lastPlayedAt: '2026-10-31T21:00:00Z',
                directPlayCount: 40,
                directStreamCount: 3,
                transcodeCount: 2,
                unknownMethodCount: 0,
                percentageOfPlays: 45.0,
            },
            {
                provider: 'emby',
                serverId: 'srv-beta',
                userId: 'user-202',
                userName: 'Alex Duplicate Name',
                playCount: 30,
                watchTimeSecs: 54000,
                estimatedBytes: 2147483648,
                distinctItems: 4,
                lastPlayedAt: '2026-10-31T20:00:00Z',
                directPlayCount: 20,
                directStreamCount: 5,
                transcodeCount: 5,
                unknownMethodCount: 0,
                percentageOfPlays: 30.0,
            },
        ],
        clients: [
            {
                provider: 'jellyfin',
                serverId: 'srv-alpha',
                clientName: 'Swiftfin',
                deviceName: 'Apple TV 4K',
                playCount: 50,
                watchTimeSecs: 90000,
                estimatedBytes: 4294967296,
                distinctUsers: 2,
                directPlayCount: 48,
                directStreamCount: 2,
                transcodeCount: 0,
                unknownMethodCount: 0,
                percentageOfPlays: 50.0,
            },
            {
                provider: null,
                serverId: null,
                clientName: null,
                deviceName: null,
                playCount: 10,
                watchTimeSecs: 18000,
                estimatedBytes: 536870912,
                distinctUsers: 1,
                directPlayCount: 0,
                directStreamCount: 0,
                transcodeCount: 0,
                unknownMethodCount: 10,
                percentageOfPlays: 10.0,
            },
        ],
        items: [
            {
                provider: 'jellyfin',
                serverId: 'srv-alpha',
                itemId: 'item-dune-1984',
                itemName: 'Dune',
                itemType: 'Movie',
                seriesName: null,
                playCount: 25,
                watchTimeSecs: 45000,
                estimatedBytes: 2147483648,
                distinctViewers: 3,
                lastPlayedAt: '2026-10-30T20:00:00Z',
                percentageOfPlays: 25.0,
            },
            {
                provider: 'emby',
                serverId: 'srv-beta',
                itemId: 'item-dune-2021',
                itemName: 'Dune',
                itemType: 'Movie',
                seriesName: null,
                playCount: 20,
                watchTimeSecs: 36000,
                estimatedBytes: 2147483648,
                distinctViewers: 2,
                lastPlayedAt: '2026-10-31T20:00:00Z',
                percentageOfPlays: 20.0,
            },
        ],
        libraries: [
            {
                provider: 'jellyfin',
                serverId: 'srv-alpha',
                libraryId: 'lib-movies',
                libraryName: 'Movies',
                playCount: 80,
                watchTimeSecs: 144000,
                estimatedBytes: 6442450944,
                distinctViewers: 4,
                distinctItems: 10,
                percentageOfPlays: 80.0,
            },
            {
                provider: 'jellyfin',
                serverId: 'srv-alpha',
                libraryId: 'lib-4k',
                libraryName: '4K Vault',
                playCount: 45,
                watchTimeSecs: 81000,
                estimatedBytes: 4294967296,
                distinctViewers: 2,
                distinctItems: 5,
                percentageOfPlays: 45.0,
            },
        ],
        libraryMetrics: {
            cohortDistinctPlays: 100,
            sumOfLabelPlays: 125,
            isOverlapping: true,
            unlabeledPlays: 8,
        },
        genres: [
            {
                provider: 'jellyfin',
                serverId: 'srv-alpha',
                genre: 'Sci-Fi',
                playCount: 70,
                watchTimeSecs: 126000,
                estimatedBytes: 5368709120,
                distinctViewers: 4,
                distinctItems: 8,
                percentageOfPlays: 70.0,
            },
            {
                provider: null,
                serverId: null,
                genre: 'Adventure',
                playCount: 55,
                watchTimeSecs: 99000,
                estimatedBytes: 4294967296,
                distinctViewers: 3,
                distinctItems: 6,
                percentageOfPlays: 55.0,
            },
        ],
        genreMetrics: {
            cohortDistinctPlays: 100,
            sumOfLabelPlays: 125,
            isOverlapping: true,
            unlabeledPlays: 12,
        },
        ...overrides,
    };
}

describe('StreamingInsights', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('fetches /patterns and /drilldown with exact query minus cursor plus snapshot, and renders timezone-aware activity and explicit concurrency/gap/retention limits', async () => {
        const query: StreamingHistoryQuery = {
            window: '30d',
            timezone: 'America/New_York',
            provider: 'jellyfin',
            serverId: 'srv-alpha',
            provenance: 'observed_session',
            pageSize: 2,
            cursor: 'cursor-page-3-must-be-stripped',
        };

        mockedApiFetch
            .mockResolvedValueOnce(createJsonResponse(makePatternsReport()))
            .mockResolvedValueOnce(createJsonResponse(makeDrilldownReport()));

        const onDrilldown = jest.fn();

        render(
            <StreamingInsights
                query={query}
                snapshot="snap-token-rev-99"
                onDrilldown={onDrilldown}
            />
        );

        await waitFor(() => {
            expect(screen.getByTestId('activity-patterns-card')).toBeInTheDocument();
        });

        expect(mockedApiFetch).toHaveBeenCalledTimes(2);
        const patternsUrl = String(mockedApiFetch.mock.calls[0][0]);
        const drilldownUrl = String(mockedApiFetch.mock.calls[1][0]);

        expect(patternsUrl).toContain('/api/v1/auth/streaming/patterns?');
        expect(drilldownUrl).toContain('/api/v1/auth/streaming/drilldown?');

        for (const url of [patternsUrl, drilldownUrl]) {
            expect(url).toContain('window=30d');
            expect(url).toContain('timezone=America%2FNew_York');
            expect(url).toContain('provider=jellyfin');
            expect(url).toContain('serverId=srv-alpha');
            expect(url).toContain('provenance=observed_session');
            expect(url).toContain('pageSize=2');
            expect(url).toContain('snapshot=snap-token-rev-99');
            expect(url).not.toContain('cursor=');
        }

        // Verify timezone, DST notice, and undated records disclosure
        expect(screen.getByTestId('insights-timezone-badge')).toHaveTextContent(
            'TZ: America/New_York'
        );
        expect(screen.getByTestId('activity-dst-notice')).toHaveTextContent(
            'Observed DST transition in window'
        );
        expect(screen.getByTestId('activity-undated-notice')).toHaveTextContent(
            '3 confirmed play(s) have unrecorded timestamps'
        );

        // Switch between Hourly, Weekday, and Timeseries modes
        expect(screen.getByTestId('activity-bars-hourly')).toBeInTheDocument();
        fireEvent.click(screen.getByTestId('activity-mode-weekday-btn'));
        expect(screen.getByTestId('activity-bars-weekday')).toBeInTheDocument();
        expect(screen.getByText('Saturday')).toBeInTheDocument();

        fireEvent.click(screen.getByTestId('activity-mode-daily-btn'));
        expect(screen.getByTestId('activity-bars-daily')).toBeInTheDocument();

        // Concurrency: verify explicit 90-day retention, 15s sampling, and gap/expired Unknown(null) buckets
        expect(screen.getByTestId('concurrency-retention-badge')).toHaveTextContent(
            'Retention Limited (90d max)'
        );
        expect(screen.getByTestId('concurrency-peak-value')).toHaveTextContent('4 streams');
        expect(screen.getByTestId('concurrency-peak-bitrate')).toHaveTextContent('38.5 Mbps');
        expect(screen.getByTestId('concurrency-limitations-box')).toHaveTextContent(
            '90-Day Retention Limits'
        );

        const bucketExpired = screen.getByTestId('concurrency-bucket-0');
        expect(bucketExpired).toHaveTextContent('Unknown (>90d Retention)');
        expect(bucketExpired).toHaveTextContent('Unknown (null)');

        const bucketGap = screen.getByTestId('concurrency-bucket-1');
        expect(bucketGap).toHaveTextContent('Unknown (Sampling Gap)');
        expect(bucketGap).toHaveTextContent('Unknown (null)');

        const bucketAvailable = screen.getByTestId('concurrency-bucket-2');
        expect(bucketAvailable).toHaveTextContent('Sampled Active');
        expect(bucketAvailable).toHaveTextContent('Peak 4');
    });

    it('renders null concurrency honestly as Unknown when zero samples exist instead of fabricating zero streams', async () => {
        const unsampledPatterns = makePatternsReport({
            concurrency: {
                window: '365d',
                from: '2025-11-01T00:00:00Z',
                until: '2026-11-01T00:00:00Z',
                timezone: 'UTC',
                retentionDays: 90,
                retentionCutoff: '2026-08-03T00:00:00Z',
                retentionLimited: true,
                peakConcurrency: null,
                peakConcurrencyAt: null,
                avgConcurrency: null,
                peakBitrateBps: null,
                totalSamplesAnalyzed: 0,
                buckets: [
                    {
                        bucketStart: '2026-01-01T00:00:00Z',
                        bucketEnd: '2026-01-02T00:00:00Z',
                        peakConcurrency: 0,
                        avgConcurrency: 0,
                        peakBitrateBps: 0,
                        sampleCount: 0,
                        status: 'retention_expired',
                    },
                ],
                limitations: [],
            },
        });

        mockedApiFetch
            .mockResolvedValueOnce(createJsonResponse(unsampledPatterns))
            .mockResolvedValueOnce(createJsonResponse(makeDrilldownReport()));

        render(
            <StreamingInsights
                query={{ window: '365d', timezone: 'UTC' }}
                snapshot="snap-null-conc"
                onDrilldown={jest.fn()}
            />
        );

        await waitFor(() => {
            expect(screen.getByTestId('concurrency-patterns-card')).toBeInTheDocument();
        });

        expect(screen.getByTestId('concurrency-peak-value')).toHaveTextContent(
            'Unknown (No Samples)'
        );
        expect(screen.getByTestId('concurrency-avg-value')).toHaveTextContent('Unknown');
        expect(screen.getByTestId('concurrency-peak-bitrate')).toHaveTextContent('Unknown');
    });

    it('preserves duplicate display names via stable identities, discloses overlapping label denominators and top-list truncation, and passes provider+serverId to onDrilldown', async () => {
        const onDrilldown = jest.fn();

        mockedApiFetch
            .mockResolvedValueOnce(createJsonResponse(makePatternsReport()))
            .mockResolvedValueOnce(createJsonResponse(makeDrilldownReport()));

        render(
            <StreamingInsights
                query={{ window: '30d', timezone: 'UTC', pageSize: 2 }}
                snapshot="snap-drill-1"
                onDrilldown={onDrilldown}
            />
        );

        await waitFor(() => {
            expect(screen.getByTestId('cohort-drilldown-section')).toBeInTheDocument();
        });

        // Cohort denominator & truncation notice on Users tab (5 distinct users in cohort, top 2 shown)
        expect(screen.getByTestId('drilldown-cohort-denominator-badge')).toHaveTextContent(
            'Denominator: 100 distinct confirmed plays'
        );
        expect(screen.getByTestId('users-truncation-notice')).toHaveTextContent(
            'Showing top 2 of 5 distinct users in cohort'
        );

        // Both "Alex Duplicate Name" rows are rendered separately and keyed by stable identity
        const alexButtons = screen.getAllByText('Alex Duplicate Name');
        expect(alexButtons).toHaveLength(2);

        fireEvent.click(
            screen.getByTestId('drilldown-user-btn-jellyfin-srv-alpha-user-101')
        );
        expect(onDrilldown).toHaveBeenLastCalledWith({
            provider: 'jellyfin',
            serverId: 'srv-alpha',
            userId: 'user-101',
        });

        fireEvent.click(
            screen.getByTestId('drilldown-user-btn-emby-srv-beta-user-202')
        );
        expect(onDrilldown).toHaveBeenLastCalledWith({
            provider: 'emby',
            serverId: 'srv-beta',
            userId: 'user-202',
        });

        // Clients & Devices tab: includes explicit Unknown group and provider/server scope when present
        fireEvent.click(screen.getByTestId('drilldown-tab-clients'));
        expect(screen.getByTestId('clients-truncation-notice')).toBeInTheDocument();
        fireEvent.click(screen.getByTestId('drilldown-client-btn-0'));
        expect(onDrilldown).toHaveBeenLastCalledWith({
            provider: 'jellyfin',
            serverId: 'srv-alpha',
            client: 'Swiftfin',
            device: 'Apple TV 4K',
        });
        fireEvent.click(screen.getByTestId('drilldown-client-btn-1'));
        expect(onDrilldown).toHaveBeenLastCalledWith({
            client: 'Unknown',
            device: 'Unknown',
        });

        // Items tab: two "Dune" movies with different itemIds and providers
        fireEvent.click(screen.getByTestId('drilldown-tab-items'));
        expect(screen.getByTestId('items-truncation-notice')).toHaveTextContent(
            'Showing top 2 of 12 distinct media items'
        );
        expect(screen.getAllByText('Dune')).toHaveLength(2);
        fireEvent.click(
            screen.getByTestId('drilldown-item-btn-emby-srv-beta-item-dune-2021')
        );
        expect(onDrilldown).toHaveBeenLastCalledWith({
            provider: 'emby',
            serverId: 'srv-beta',
            itemId: 'item-dune-2021',
        });

        // Libraries tab: overlapping label disclosure (125 label assignments vs 100 distinct plays) + 8 unlabeled
        fireEvent.click(screen.getByTestId('drilldown-tab-libraries'));
        expect(screen.getByTestId('library-label-metrics-banner')).toHaveTextContent(
            '100 distinct plays'
        );
        expect(screen.getByTestId('library-label-metrics-banner')).toHaveTextContent(
            '125 label assignments'
        );
        expect(screen.getByTestId('library-unlabeled-count')).toHaveTextContent(
            'Unlabeled plays: 8'
        );
        fireEvent.click(screen.getByTestId('drilldown-library-btn-lib-4k'));
        expect(onDrilldown).toHaveBeenLastCalledWith({
            provider: 'jellyfin',
            serverId: 'srv-alpha',
            libraryId: 'lib-4k',
        });

        // Genres tab: overlapping label disclosure + unlabeled plays
        fireEvent.click(screen.getByTestId('drilldown-tab-genres'));
        expect(screen.getByTestId('genre-label-metrics-banner')).toHaveTextContent(
            'overlapping multi-genre items present'
        );
        expect(screen.getByTestId('genre-unlabeled-count')).toHaveTextContent(
            'Unlabeled plays: 12'
        );
        fireEvent.click(screen.getByTestId('drilldown-genre-btn-Sci-Fi'));
        expect(onDrilldown).toHaveBeenLastCalledWith({
            provider: 'jellyfin',
            serverId: 'srv-alpha',
            genre: 'Sci-Fi',
        });

        // Providers & Servers tab: drills down by provider + serverId
        fireEvent.click(screen.getByTestId('drilldown-tab-servers'));
        fireEvent.click(screen.getByTestId('drilldown-server-btn-jellyfin-srv-alpha'));
        expect(onDrilldown).toHaveBeenLastCalledWith({
            provider: 'jellyfin',
            serverId: 'srv-alpha',
        });
    });

    it('aborts in-flight requests and ignores stale out-of-order responses when query or snapshot changes', async () => {
        let resolveStalePatterns!: (value: Response) => void;
        const stalePatternsPromise = new Promise<Response>((resolve) => {
            resolveStalePatterns = resolve;
        });
        let resolveStaleDrilldown!: (value: Response) => void;
        const staleDrilldownPromise = new Promise<Response>((resolve) => {
            resolveStaleDrilldown = resolve;
        });

        let resolveFreshPatterns!: (value: Response) => void;
        const freshPatternsPromise = new Promise<Response>((resolve) => {
            resolveFreshPatterns = resolve;
        });
        let resolveFreshDrilldown!: (value: Response) => void;
        const freshDrilldownPromise = new Promise<Response>((resolve) => {
            resolveFreshDrilldown = resolve;
        });

        mockedApiFetch
            .mockImplementationOnce(() => stalePatternsPromise)
            .mockImplementationOnce(() => staleDrilldownPromise)
            .mockImplementationOnce(() => freshPatternsPromise)
            .mockImplementationOnce(() => freshDrilldownPromise);

        const { rerender } = render(
            <StreamingInsights
                query={{ window: '7d', timezone: 'UTC' }}
                snapshot="snap-old-1"
                onDrilldown={jest.fn()}
            />
        );

        await waitFor(() => {
            expect(mockedApiFetch).toHaveBeenCalledTimes(2);
        });

        const firstSignal = mockedApiFetch.mock.calls[0][1]?.signal as AbortSignal;
        expect(firstSignal).toBeDefined();
        expect(firstSignal.aborted).toBe(false);

        // Update query & snapshot before first pair resolves
        rerender(
            <StreamingInsights
                query={{ window: '90d', timezone: 'Europe/Berlin' }}
                snapshot="snap-fresh-2"
                onDrilldown={jest.fn()}
            />
        );

        expect(firstSignal.aborted).toBe(true);

        await waitFor(() => {
            expect(mockedApiFetch).toHaveBeenCalledTimes(4);
        });

        // Resolve fresh responses first
        await act(async () => {
            resolveFreshPatterns(
                createJsonResponse(
                    makePatternsReport({
                        activity: {
                            ...makePatternsReport().activity,
                            timezone: 'Europe/Berlin',
                            totalConfirmedPlays: 777,
                        },
                    })
                )
            );
            resolveFreshDrilldown(
                createJsonResponse(
                    makeDrilldownReport({
                        cohortDistinctPlays: 777,
                        users: [
                            {
                                provider: 'jellyfin',
                                serverId: 'srv-fresh',
                                userId: 'u-fresh',
                                userName: 'Fresh Winner User',
                                playCount: 777,
                                watchTimeSecs: 36000,
                                estimatedBytes: 1073741824,
                                distinctItems: 10,
                                lastPlayedAt: '2026-11-01T12:00:00Z',
                                directPlayCount: 777,
                                directStreamCount: 0,
                                transcodeCount: 0,
                                unknownMethodCount: 0,
                                percentageOfPlays: 100,
                            },
                        ],
                    })
                )
            );
        });

        await waitFor(() => {
            expect(screen.getByText('Fresh Winner User')).toBeInTheDocument();
        });

        // Now resolve stale first responses late -> must be ignored
        await act(async () => {
            resolveStalePatterns(
                createJsonResponse(
                    makePatternsReport({
                        activity: {
                            ...makePatternsReport().activity,
                            timezone: 'UTC',
                            totalConfirmedPlays: 11,
                        },
                    })
                )
            );
            resolveStaleDrilldown(
                createJsonResponse(
                    makeDrilldownReport({
                        cohortDistinctPlays: 11,
                        users: [
                            {
                                provider: 'jellyfin',
                                serverId: 'srv-stale',
                                userId: 'u-stale',
                                userName: 'Stale Loser User',
                                playCount: 11,
                                watchTimeSecs: 600,
                                estimatedBytes: 1024,
                                distinctItems: 1,
                                lastPlayedAt: '2026-10-01T12:00:00Z',
                                directPlayCount: 11,
                                directStreamCount: 0,
                                transcodeCount: 0,
                                unknownMethodCount: 0,
                                percentageOfPlays: 100,
                            },
                        ],
                    })
                )
            );
        });

        expect(screen.getByText('Fresh Winner User')).toBeInTheDocument();
        expect(screen.queryByText('Stale Loser User')).not.toBeInTheDocument();
        expect(screen.getByTestId('insights-timezone-badge')).toHaveTextContent(
            'TZ: Europe/Berlin'
        );
    });
});
