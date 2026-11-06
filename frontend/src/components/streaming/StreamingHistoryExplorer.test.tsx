import { TextEncoder, TextDecoder } from 'util';
import { readFileSync } from 'node:fs';
import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import StreamingHistoryExplorer, { parseInitialQueryFromUrl, syncHistoryStateToWindowUrl } from '@/components/streaming/StreamingHistoryExplorer';
import { apiFetch } from '@/lib/fetcher';
import { StreamingHistoryPage, CanonicalStreamingHistoryItem } from '@/lib/streaming-history';

Object.assign(globalThis, { TextEncoder, TextDecoder });

jest.mock('@/components/streaming/StreamingInsights', () => ({ __esModule: true, default: ({ onDrilldown }: { onDrilldown: (patch: { userId?: string; itemId?: string; serverId?: string }) => void }) => <div>
    <button onClick={() => onDrilldown({ userId: 'drilled-user', serverId: 'scoped-server' })}>Test user drilldown</button>
    <button onClick={() => onDrilldown({ itemId: 'drilled-item', serverId: '' })}>Test item drilldown</button>
</div> }));
jest.mock('@/components/streaming/StreamingPortability', () => ({ __esModule: true, default: () => null }));
jest.mock('@/components/streaming/StreamingHistoryAdmin', () => ({ __esModule: true, default: () => null }));

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
}));

const mockAddToast = jest.fn();
jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockAddToast,
    }),
}));

let mockAuthUser: { id: number; username: string; role: string } | null = {
    id: 1,
    username: 'admin_operator',
    role: 'admin',
};

jest.mock('@/contexts/AuthContext', () => ({
    useAuth: () => ({
        user: mockAuthUser,
        isAuthenticated: Boolean(mockAuthUser),
        isLoading: false,
    }),
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

function makeCanonicalItem(
    overrides: Partial<CanonicalStreamingHistoryItem> = {}
): CanonicalStreamingHistoryItem {
    return {
        id: 101,
        provider: 'jellyfin',
        serverId: 'jf-srv-01',
        sourceEventId: 'evt-101',
        provenance: 'observed_session',
        timestampCertainty: 'observed',
        byteAccuracy: 'estimated',
        userId: 'u-1',
        userName: 'alex_operator',
        clientName: 'Jellyfin Media Player',
        deviceName: 'MacBook Pro M3',
        deviceId: 'dev-mbp-01',
        ipAddress: '10.10.0.24',
        itemId: 'item-dune-2',
        itemName: 'Dune: Part Two',
        itemType: 'Movie',
        seriesName: null,
        playMethod: 'DirectPlay',
        watchedSecs: 7200,
        durationSecs: 9960,
        estimatedBytes: 2147483648,
        startedAt: '2026-10-30T20:00:00Z',
        lastSeenAt: '2026-10-30T22:00:00Z',
        endedAt: '2026-10-30T22:00:00Z',
        isActive: false,
        included: true,
        policyStatus: 'included',
        libraryIds: ['lib-movies'],
        genres: ['Sci-Fi', 'Adventure'],
        ...overrides,
    };
}

function makeHistoryPage(
    overrides: Partial<StreamingHistoryPage> = {}
): StreamingHistoryPage {
    return {
        schemaVersion: 1,
        query: {
            window: 'all',
            timezone: 'UTC',
            sort: 'startedDesc',
            pageSize: 50,
            ...(overrides.query || {}),
        },
        scope: {
            snapshotToken: 'snap-token-rev-12',
            watermark: 9400,
            revision: 12,
            asOf: '2026-11-01T23:00:00Z',
            expiresAt: '2026-11-01T23:15:00Z',
            timezone: 'UTC',
            permissionScope: mockAuthUser?.role === 'admin' ? 'administrative' : 'linked_user',
            sampleRetentionDays: 365,
            dateSemantics: 'UTC half-open [from, until)',
            ...(overrides.scope || {}),
        },
        counts: {
            availableRecords: 1850,
            matchingRecords: 642,
            undatedRecords: 14,
            confirmedPlays: 510,
            itemSummaries: 92,
            legacyRecords: 40,
            watchTimeSecs: 183600,
            estimatedBytes: 10737418240,
            ...(overrides.counts || {}),
        },
        items: overrides.items ?? [makeCanonicalItem()],
        nextCursor: overrides.nextCursor !== undefined ? overrides.nextCursor : 'cursor-page-2',
    };
}

describe('StreamingHistoryExplorer', () => {
    it('replaces prior drilldown facets and reveals effective all-instance filters', async () => {
        mockedApiFetch.mockResolvedValue(createJsonResponse(makeHistoryPage()));
        render(<StreamingHistoryExplorer />);
        await screen.findByText('Dune: Part Two');
        fireEvent.click(screen.getByRole('button', { name: 'Test user drilldown' }));
        expect(screen.getByLabelText('Provider User ID')).toHaveValue('drilled-user');
        fireEvent.click(screen.getByRole('button', { name: 'Test item drilldown' }));
        expect(screen.getByLabelText('Provider User ID')).toHaveValue('');
        await waitFor(() => {
            const url = String(mockedApiFetch.mock.calls[mockedApiFetch.mock.calls.length - 1][0]);
            expect(url).toContain('itemId=drilled-item');
            expect(url).not.toContain('userId=drilled-user');
            expect(url).not.toContain('serverId=scoped-server');
        });
    });

    beforeEach(() => {
        jest.clearAllMocks();
        mockAuthUser = { id: 1, username: 'admin_operator', role: 'admin' };
        window.history.replaceState({}, '', '/?tab=streaming&dashboardMode=live#watch-history');
    });

    it('keeps viewer-bound expiring cursors out of durable archive bookmarks', () => {
        const query = parseInitialQueryFromUrl('?sh_q=durable&sh_cursor=expired-viewer-token');
        expect(query.search).toBe('durable');
        expect(query.cursor).toBeUndefined();
        window.history.replaceState({}, '', '/?tab=streaming&sh_cursor=old#watch-history');
        syncHistoryStateToWindowUrl({ ...query, cursor: 'current-viewer-token' }, true);
        expect(window.location.search).toContain('tab=streaming');
        expect(window.location.search).toContain('sh_q=durable');
        expect(window.location.search).not.toContain('sh_cursor');
        expect(window.location.hash).toBe('#watch-history');
    });

    (process.env.AF_STREAMING_ARCHIVE_FIXTURE ? it : it.skip)('renders canonical mixed-provenance records serialized by Rust without inventing missing values', async () => {
        const fixtures: { administrative: StreamingHistoryPage; linked: StreamingHistoryPage } = JSON.parse(readFileSync(process.env.AF_STREAMING_ARCHIVE_FIXTURE!, 'utf8'));
        mockedApiFetch.mockResolvedValueOnce(createJsonResponse(fixtures.administrative));
        render(<StreamingHistoryExplorer />);
        await waitFor(() => expect(screen.getByText('Contract Observed Play')).toBeInTheDocument());
        expect(screen.getByText('Contract Imported Play')).toBeInTheDocument();
        const summary = fixtures.administrative.items.find(item => item.provenance === 'item_summary')!;
        expect(screen.getByTestId(`history-row-${summary.id}`)).toHaveTextContent('Unrecorded');
        expect(summary.startedAt).toBeNull();
        expect(summary.watchedSecs).toBeNull();
        expect(summary.estimatedBytes).toBeNull();
        expect(fixtures.administrative.counts.confirmedPlays).toBe(2);
        expect(fixtures.linked.scope.permissionScope).toBe('linked_user');
        for (const item of fixtures.linked.items) {
            expect(item.ipAddress).toBeUndefined();
            expect(item.deviceId).toBeUndefined();
        }
    });

    it('does not leave incomplete custom bookmarks loading or permit a stale export', async () => {
        window.history.replaceState({}, '', '/?tab=streaming&sh_window=custom');
        render(<StreamingHistoryExplorer />);
        await waitFor(() => expect(screen.queryByText('Loading canonical streaming history...')).not.toBeInTheDocument());
        expect(mockedApiFetch).not.toHaveBeenCalled();
        expect(screen.getByTestId('export-full-history-btn')).toBeDisabled();
        expect(screen.getByTestId('custom-date-bounds-panel')).toBeInTheDocument();
    });

    it('surfaces endpoint-provided records beyond the 500-row dashboard cap and displays matching vs available counts', async () => {
        const beyond500Record = makeCanonicalItem({
            id: 501,
            itemId: 'item-501-archive-deep',
            itemName: 'Archive Record #501: Deep Space Odyssey',
            userName: 'archive_researcher',
            startedAt: '2024-03-14T19:30:00Z',
        });

        mockedApiFetch.mockResolvedValueOnce(
            createJsonResponse(
                makeHistoryPage({
                    counts: {
                        availableRecords: 2400,
                        matchingRecords: 1205,
                        undatedRecords: 19,
                        confirmedPlays: 980,
                        itemSummaries: 150,
                        legacyRecords: 75,
                        watchTimeSecs: 720000,
                        estimatedBytes: 53687091200,
                    },
                    items: [beyond500Record],
                    nextCursor: 'cursor-after-501',
                })
            )
        );

        render(<StreamingHistoryExplorer />);

        await waitFor(() => {
            expect(
                screen.getByText('Archive Record #501: Deep Space Odyssey')
            ).toBeInTheDocument();
        });

        expect(mockedApiFetch).toHaveBeenCalledTimes(1);
        expect(mockedApiFetch.mock.calls[0][0]).toBe(
            '/api/v1/auth/streaming/history?window=all&timezone=UTC&sort=startedDesc&pageSize=50'
        );

        expect(screen.getByTestId('history-counts-badge')).toHaveTextContent(
            '1,205 matching of 2,400 available records'
        );
        expect(screen.getByTestId('summary-matching-records')).toHaveTextContent('1,205');
        expect(screen.getByTestId('summary-available-records')).toHaveTextContent('2,400');
        expect(screen.getByTestId('summary-confirmed-plays')).toHaveTextContent('980');
        expect(screen.getByTestId('summary-item-summaries')).toHaveTextContent('150');
        expect(screen.getByTestId('summary-legacy-records')).toHaveTextContent('75');
        expect(screen.getByTestId('summary-undated-records')).toHaveTextContent('19');
    });

    it('navigates forward and backward with cursor tokens and resets cursor stack when any filter changes', async () => {
        const page1 = makeHistoryPage({
            items: [makeCanonicalItem({ id: 1, itemName: 'Page One Title' })],
            nextCursor: 'cursor-token-p2',
        });
        const page2 = makeHistoryPage({
            items: [makeCanonicalItem({ id: 2, itemName: 'Page Two Title' })],
            nextCursor: 'cursor-token-p3',
        });
        const page1Reload = makeHistoryPage({
            items: [makeCanonicalItem({ id: 1, itemName: 'Page One Title' })],
            nextCursor: 'cursor-token-p2',
        });
        const filteredPage = makeHistoryPage({
            counts: {
                availableRecords: 1850,
                matchingRecords: 12,
                undatedRecords: 0,
                confirmedPlays: 12,
                itemSummaries: 0,
                legacyRecords: 0,
                watchTimeSecs: 36000,
                estimatedBytes: 1073741824,
            },
            items: [
                makeCanonicalItem({
                    id: 99,
                    itemName: 'Transcoded Episode',
                    playMethod: 'Transcode',
                }),
            ],
            nextCursor: null,
        });

        mockedApiFetch
            .mockResolvedValueOnce(createJsonResponse(page1))
            .mockResolvedValueOnce(createJsonResponse(page2))
            .mockResolvedValueOnce(createJsonResponse(page1Reload))
            .mockResolvedValueOnce(createJsonResponse(page2))
            .mockResolvedValueOnce(createJsonResponse(filteredPage));

        render(<StreamingHistoryExplorer />);

        await waitFor(() => {
            expect(screen.getByText('Page One Title')).toBeInTheDocument();
        });
        expect(screen.getByTestId('history-prev-page-btn')).toBeDisabled();
        expect(screen.getByTestId('history-next-page-btn')).not.toBeDisabled();

        // Click Next -> sends cursor=cursor-token-p2
        fireEvent.click(screen.getByTestId('history-next-page-btn'));

        await waitFor(() => {
            expect(screen.getByText('Page Two Title')).toBeInTheDocument();
        });
        expect(mockedApiFetch.mock.calls[1][0]).toContain('cursor=cursor-token-p2');
        expect(screen.getByTestId('pagination-status-text')).toHaveTextContent('Page 2');
        expect(screen.getByTestId('history-prev-page-btn')).not.toBeDisabled();

        // Click Previous -> pops cursor stack back to Page 1 (no cursor param)
        fireEvent.click(screen.getByTestId('history-prev-page-btn'));

        await waitFor(() => {
            expect(screen.getByText('Page One Title')).toBeInTheDocument();
        });
        expect(mockedApiFetch.mock.calls[2][0]).not.toContain('cursor=');
        expect(screen.getByTestId('pagination-status-text')).toHaveTextContent('Page 1');

        // Go to Page 2 again, then change Play Method filter -> must reset cursor and Page 1
        fireEvent.click(screen.getByTestId('history-next-page-btn'));
        await waitFor(() => {
            expect(screen.getByText('Page Two Title')).toBeInTheDocument();
        });

        fireEvent.change(screen.getByLabelText(/Play Method/i), {
            target: { value: 'Transcode' },
        });

        await waitFor(() => {
            expect(screen.getByText('Transcoded Episode')).toBeInTheDocument();
        });
        const filterCallUrl = String(mockedApiFetch.mock.calls[4][0]);
        expect(filterCallUrl).toContain('playMethod=Transcode');
        expect(filterCallUrl).not.toContain('cursor=');
        expect(screen.getByTestId('pagination-status-text')).toHaveTextContent('Page 1');
        expect(screen.getByTestId('history-prev-page-btn')).toBeDisabled();

        // Verify existing dashboard query & hash were preserved while syncing sh_method
        expect(window.location.search).toContain('tab=streaming');
        expect(window.location.search).toContain('dashboardMode=live');
        expect(window.location.search).toContain('sh_method=Transcode');
        expect(window.location.hash).toBe('#watch-history');
    });

    it('debounces literal search, preserves wildcards literally, and aborts stale out-of-order responses', async () => {
        jest.useFakeTimers();
        try {
            let resolveSlowSearch!: (value: Response) => void;
            const slowPromise = new Promise<Response>((resolve) => {
                resolveSlowSearch = resolve;
            });

            let resolveFastSearch!: (value: Response) => void;
            const fastPromise = new Promise<Response>((resolve) => {
                resolveFastSearch = resolve;
            });

            mockedApiFetch
                .mockResolvedValueOnce(
                    createJsonResponse(
                        makeHistoryPage({
                            items: [makeCanonicalItem({ id: 1, itemName: 'Initial Item' })],
                        })
                    )
                )
                .mockImplementationOnce(() => slowPromise)
                .mockImplementationOnce(() => fastPromise);

            render(<StreamingHistoryExplorer searchDebounceMs={250} />);

            await waitFor(() => {
                expect(screen.getByText('Initial Item')).toBeInTheDocument();
            });

            const searchInput = screen.getByLabelText(/Literal Archive Search/i);

            // Type first query with SQL wildcard characters that must be passed literally
            fireEvent.change(searchInput, { target: { value: '100%_literal_old' } });

            await act(async () => {
                jest.advanceTimersByTime(260);
            });

            expect(mockedApiFetch).toHaveBeenCalledTimes(2);
            const firstSearchCall = mockedApiFetch.mock.calls[1];
            expect(String(firstSearchCall[0])).toContain(
                `search=${encodeURIComponent('100%_literal_old')}`
            );
            const firstSignal = firstSearchCall[1]?.signal as AbortSignal;
            expect(firstSignal).toBeDefined();
            expect(firstSignal.aborted).toBe(false);

            // Type second query before first resolves
            fireEvent.change(searchInput, { target: { value: 'final_fresh_match' } });

            await act(async () => {
                jest.advanceTimersByTime(260);
            });

            expect(mockedApiFetch).toHaveBeenCalledTimes(3);
            expect(firstSignal.aborted).toBe(true);

            // Resolve newer request first
            await act(async () => {
                resolveFastSearch(
                    createJsonResponse(
                        makeHistoryPage({
                            items: [makeCanonicalItem({ id: 202, itemName: 'Fresh Winner Record' })],
                        })
                    )
                );
            });

            await waitFor(() => {
                expect(screen.getByText('Fresh Winner Record')).toBeInTheDocument();
            });

            // Now resolve stale first request late -> must be ignored
            await act(async () => {
                resolveSlowSearch(
                    createJsonResponse(
                        makeHistoryPage({
                            items: [makeCanonicalItem({ id: 999, itemName: 'Stale Loser Record' })],
                        })
                    )
                );
            });

            expect(screen.getByText('Fresh Winner Record')).toBeInTheDocument();
            expect(screen.queryByText('Stale Loser Record')).not.toBeInTheDocument();
        } finally {
            jest.useRealTimers();
        }
    });

    it('handles HTTP 409 snapshot invalidation by surfacing restart banner and restarting from page 1 without cursor', async () => {
        const page1 = makeHistoryPage({
            items: [makeCanonicalItem({ id: 10, itemName: 'Snapshot v1 Page 1' })],
            nextCursor: 'cursor-stale-v1',
        });
        const conflict409 = createJsonResponse(
            {
                code: 'SNAPSHOT_CONFLICT',
                message: 'Snapshot watermark invalidated by policy mutation.',
            },
            409
        );
        const restartedPage1 = makeHistoryPage({
            scope: {
                snapshotToken: 'snap-token-rev-13',
                watermark: 9450,
                revision: 13,
                asOf: '2026-11-01T23:05:00Z',
                expiresAt: '2026-11-01T23:20:00Z',
                timezone: 'UTC',
                permissionScope: 'administrative',
                sampleRetentionDays: 365,
                dateSemantics: 'UTC half-open [from, until)',
            },
            items: [makeCanonicalItem({ id: 11, itemName: 'Fresh Snapshot v2 Page 1' })],
            nextCursor: null,
        });

        mockedApiFetch
            .mockResolvedValueOnce(createJsonResponse(page1))
            .mockResolvedValueOnce(conflict409)
            .mockResolvedValueOnce(createJsonResponse(restartedPage1));

        render(<StreamingHistoryExplorer />);

        await waitFor(() => {
            expect(screen.getByText('Snapshot v1 Page 1')).toBeInTheDocument();
        });

        // Navigate to page 2 -> returns HTTP 409
        fireEvent.click(screen.getByTestId('history-next-page-btn'));

        await waitFor(() => {
            expect(
                screen.getByTestId('history-snapshot-conflict-banner')
            ).toBeInTheDocument();
        });
        expect(
            screen.getByText('Snapshot watermark invalidated by policy mutation.')
        ).toBeInTheDocument();
        expect(screen.queryByText('Snapshot v1 Page 1')).not.toBeInTheDocument();
        expect(screen.getByTestId('export-full-history-btn')).toBeDisabled();

        // Click Restart Query from Page 1 -> clears cursor and fetches fresh page 1
        fireEvent.click(screen.getByTestId('restart-query-409-btn'));

        await waitFor(() => {
            expect(screen.getByText('Fresh Snapshot v2 Page 1')).toBeInTheDocument();
        });

        const restartUrl = String(mockedApiFetch.mock.calls[2][0]);
        expect(restartUrl).not.toContain('cursor=');
        expect(
            screen.queryByTestId('history-snapshot-conflict-banner')
        ).not.toBeInTheDocument();
    });

    it('aborts a pending full-query export when unmounted', async () => {
        mockedApiFetch.mockResolvedValueOnce(createJsonResponse(makeHistoryPage()));
        const view = render(<StreamingHistoryExplorer />);
        await waitFor(() => expect(screen.getByTestId('export-full-history-btn')).toBeEnabled());
        mockedApiFetch.mockImplementationOnce(() => new Promise<Response>(() => undefined));
        fireEvent.click(screen.getByTestId('export-full-history-btn'));
        const signal = mockedApiFetch.mock.calls[1][1]?.signal;
        expect(signal?.aborted).toBe(false);
        view.unmount();
        expect(signal?.aborted).toBe(true);
    });

    it('cancels oversized CSV streams without downloading a partial file', async () => {
        mockedApiFetch.mockResolvedValueOnce(createJsonResponse(makeHistoryPage()));
        render(<StreamingHistoryExplorer />);
        await waitFor(() => expect(screen.getByTestId('export-full-history-btn')).toBeEnabled());
        const cancel = jest.fn(async () => undefined);
        const click = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
        mockedApiFetch.mockResolvedValueOnce({
            ok: true, status: 200, headers: new Headers(),
            body: { getReader: () => ({
                read: async () => ({ done: false, value: { byteLength: 128 * 1024 * 1024 + 1 } }),
                cancel,
            }) },
        } as unknown as Response);
        fireEvent.click(screen.getByTestId('export-full-history-btn'));
        await waitFor(() => expect(screen.getByTestId('history-export-error-banner')).toHaveTextContent('128 MiB'));
        expect(cancel).toHaveBeenCalledTimes(1);
        expect(click).not.toHaveBeenCalled();
        click.mockRestore();
    });

    it('exports full matching query with snapshotToken and without cursor, and fails cleanly on mid-stream error', async () => {
        const pageWithCursor = makeHistoryPage({
            scope: {
                snapshotToken: 'snap-export-token-777',
                watermark: 9400,
                revision: 12,
                asOf: '2026-11-01T23:00:00Z',
                expiresAt: '2026-11-01T23:15:00Z',
                timezone: 'America/New_York',
                permissionScope: 'administrative',
                sampleRetentionDays: 365,
                dateSemantics: 'America/New_York calendar bounds',
            },
            counts: {
                availableRecords: 3000,
                matchingRecords: 825,
                undatedRecords: 0,
                confirmedPlays: 825,
                itemSummaries: 0,
                legacyRecords: 0,
                watchTimeSecs: 400000,
                estimatedBytes: 21474836480,
            },
            items: [makeCanonicalItem({ id: 55, itemName: 'Page 2 Item' })],
            nextCursor: 'cursor-page-3',
        });

        const createObjectURLMock = jest.fn(() => 'blob:mock-export-csv');
        const revokeObjectURLMock = jest.fn();
        Object.defineProperty(URL, 'createObjectURL', {
            writable: true,
            value: createObjectURLMock,
        });
        Object.defineProperty(URL, 'revokeObjectURL', {
            writable: true,
            value: revokeObjectURLMock,
        });
        const anchorClickSpy = jest
            .spyOn(HTMLAnchorElement.prototype, 'click')
            .mockImplementation(() => {});

        try {
            // Start with cursor in initialQuery to verify cursor is stripped on export
            mockedApiFetch.mockResolvedValueOnce(createJsonResponse(pageWithCursor));

            render(
                <StreamingHistoryExplorer
                    initialQuery={{
                        window: '30d',
                        timezone: 'America/New_York',
                        provenance: 'observed_session',
                        cursor: 'cursor-page-2-active',
                    }}
                />
            );

            await waitFor(() => {
                expect(screen.getByText('Page 2 Item')).toBeInTheDocument();
            });

            // 1. Test successful streaming CSV export
            const csvBytes = new TextEncoder().encode('id,itemName\n55,Page 2 Item\n');
            let readStep = 0;
            const mockStreamResponse = {
                ok: true,
                status: 200,
                headers: new Headers({
                    'Content-Type': 'text/csv; charset=utf-8',
                    'Content-Disposition': 'attachment; filename="history-cohort-825.csv"',
                }),
                body: {
                    getReader: () => ({
                        read: async () => {
                            if (readStep === 0) {
                                readStep += 1;
                                return { done: false, value: csvBytes };
                            }
                            return { done: true, value: undefined };
                        },
                    }),
                },
            } as unknown as Response;

            mockedApiFetch.mockResolvedValueOnce(mockStreamResponse);

            fireEvent.click(screen.getByTestId('export-full-history-btn'));

            await waitFor(() => {
                expect(createObjectURLMock).toHaveBeenCalledTimes(1);
            });
            expect(anchorClickSpy).toHaveBeenCalledTimes(1);
            expect(revokeObjectURLMock).toHaveBeenCalledWith('blob:mock-export-csv');

            const exportCallUrl = String(mockedApiFetch.mock.calls[1][0]);
            expect(exportCallUrl).toContain('/api/v1/auth/streaming/history/export?');
            expect(exportCallUrl).toContain('window=30d');
            expect(exportCallUrl).toContain('timezone=America%2FNew_York');
            expect(exportCallUrl).toContain('provenance=observed_session');
            expect(exportCallUrl).toContain('snapshot=snap-export-token-777');
            expect(exportCallUrl).not.toContain('cursor=');

            // 2. Test mid-stream failure -> must NOT create download blob or claim success
            createObjectURLMock.mockClear();
            anchorClickSpy.mockClear();
            const interruptedStreamResponse = {
                ok: true,
                status: 200,
                headers: new Headers({ 'Content-Type': 'text/csv' }),
                body: {
                    getReader: () => ({
                        read: async () => {
                            throw new Error('Stream aborted: snapshot invalidated during batch read');
                        },
                    }),
                },
            } as unknown as Response;

            mockedApiFetch.mockResolvedValueOnce(interruptedStreamResponse);

            fireEvent.click(screen.getByTestId('export-full-history-btn'));

            await waitFor(() => {
                expect(screen.getByTestId('history-export-error-banner')).toBeInTheDocument();
            });
            expect(screen.getByTestId('history-export-error-banner')).toHaveTextContent(
                'CSV export interrupted: Stream aborted: snapshot invalidated during batch read'
            );
            expect(createObjectURLMock).not.toHaveBeenCalled();
            expect(anchorClickSpy).not.toHaveBeenCalled();
        } finally {
            anchorClickSpy.mockRestore();
        }
    });

    it('supports custom RFC3339 date windows, timezone, facet filters, admin includeExcluded, and non-409 error recovery', async () => {
        mockedApiFetch
            .mockResolvedValueOnce(
                createJsonResponse(
                    makeHistoryPage({
                        items: [makeCanonicalItem({ id: 700, itemName: 'Initial Admin Row' })],
                    })
                )
            )
            .mockResolvedValueOnce(
                createJsonResponse(
                    {
                        code: 'INVALID_TIMEZONE',
                        message: 'Invalid IANA timezone identifier.',
                    },
                    400
                )
            )
            .mockResolvedValueOnce(
                createJsonResponse(
                    makeHistoryPage({
                        items: [makeCanonicalItem({ id: 701, itemName: 'Custom Window Row' })],
                    })
                )
            );

        render(<StreamingHistoryExplorer />);

        await waitFor(() => {
            expect(screen.getByText('Initial Admin Row')).toBeInTheDocument();
        });

        // Trigger a 400 error via invalid timezone
        fireEvent.change(screen.getByLabelText(/IANA Timezone/i), {
            target: { value: 'Invalid/Zone' },
        });

        await waitFor(() => {
            expect(screen.getByTestId('history-error-banner')).toBeInTheDocument();
        });
        expect(screen.getByText('Invalid IANA timezone identifier.')).toBeInTheDocument();

        // Switch to custom window -> requires both from and until before firing request
        fireEvent.change(screen.getByLabelText(/Time Window/i), {
            target: { value: 'custom' },
        });
        expect(screen.getByTestId('custom-date-bounds-panel')).toBeInTheDocument();
        expect(screen.getByTestId('export-full-history-btn')).toBeDisabled();

        // Set valid timezone, custom from & until, and admin includeExcluded
        fireEvent.change(screen.getByLabelText(/IANA Timezone/i), {
            target: { value: 'Europe/Berlin' },
        });
        fireEvent.change(screen.getByLabelText(/Custom From/i), {
            target: { value: '2026-10-01T00:00:00+02:00' },
        });
        fireEvent.change(screen.getByLabelText(/Custom Until/i), {
            target: { value: '2026-10-31T23:59:59+01:00' },
        });

        await waitFor(() => {
            expect(screen.getByText('Custom Window Row')).toBeInTheDocument();
        });

        const customCallUrl = String(mockedApiFetch.mock.calls[2][0]);
        expect(customCallUrl).toContain('window=custom');
        expect(customCallUrl).toContain(
            `from=${encodeURIComponent('2026-10-01T00:00:00+02:00')}`
        );
        expect(customCallUrl).toContain(
            `until=${encodeURIComponent('2026-10-31T23:59:59+01:00')}`
        );
        expect(customCallUrl).toContain('timezone=Europe%2FBerlin');
    });

    it('renders missing/null metadata honestly as Unknown, Unrecorded, Undated, and Estimated without fake zeroes, and enforces non-admin scope visibility', async () => {
        mockAuthUser = { id: 42, username: 'viewer_user', role: 'user' };

        const sparseSummaryItem = makeCanonicalItem({
            id: 301,
            provenance: 'item_summary',
            timestampCertainty: 'unrecorded',
            byteAccuracy: 'unrecorded',
            clientName: null,
            deviceName: null,
            deviceId: undefined,
            ipAddress: undefined,
            itemName: 'Imported Played Summary Movie',
            itemType: null,
            playMethod: null,
            watchedSecs: null,
            durationSecs: null,
            estimatedBytes: null,
            startedAt: null,
            lastSeenAt: null,
            endedAt: null,
        });

        const zeroRecordedItem = makeCanonicalItem({
            id: 302,
            provenance: 'legacy_unverified',
            timestampCertainty: 'legacy_unverified',
            byteAccuracy: 'legacy_unverified',
            clientName: 'Jellyfin Web',
            deviceName: 'Firefox Linux',
            itemName: 'Legacy Zero Second Start',
            playMethod: 'DirectStream',
            watchedSecs: 0,
            durationSecs: 3600,
            estimatedBytes: 1048576,
            startedAt: '2025-01-02T03:04:05Z',
        });

        mockedApiFetch.mockResolvedValueOnce(
            createJsonResponse(
                makeHistoryPage({
                    scope: {
                        snapshotToken: 'snap-linked-user-1',
                        watermark: 500,
                        revision: 2,
                        asOf: '2026-11-01T23:00:00Z',
                        expiresAt: '2026-11-01T23:15:00Z',
                        timezone: 'UTC',
                        permissionScope: 'linked_user',
                        sampleRetentionDays: 365,
                        dateSemantics: 'UTC half-open [from, until)',
                    },
                    items: [sparseSummaryItem, zeroRecordedItem],
                    nextCursor: null,
                })
            )
        );

        render(<StreamingHistoryExplorer />);

        await waitFor(() => {
            expect(screen.getByText('Imported Played Summary Movie')).toBeInTheDocument();
        });

        // Non-admin scope disclosures & hidden admin controls
        expect(screen.getByTestId('linked-user-scope-notice')).toBeInTheDocument();
        expect(
            screen.queryByLabelText(/Include Policy-Excluded Raw Records/i)
        ).not.toBeInTheDocument();
        expect(
            screen.queryByTestId('admin-network-column-header')
        ).not.toBeInTheDocument();

        // Missing metadata labels on row 301
        const row301 = screen.getByTestId('history-row-301');
        expect(row301).toHaveTextContent('Item Summary');
        expect(row301).toHaveTextContent('Undated (Unrecorded)');
        expect(row301).toHaveTextContent('Unrecorded timestamp');
        expect(row301).toHaveTextContent('Unknown client');
        expect(row301).toHaveTextContent('Unrecorded device');
        expect(row301).toHaveTextContent('Unknown');
        expect(row301).toHaveTextContent('Unrecorded');

        // Actual recorded zero and legacy byte estimate on row 302
        const row302 = screen.getByTestId('history-row-302');
        expect(row302).toHaveTextContent('Legacy Unverified');
        expect(row302).toHaveTextContent('Estimated (Legacy)');
        expect(row302).toHaveTextContent('1 MB');
        expect(row302).toHaveTextContent('0s / 1h');
    });
});
