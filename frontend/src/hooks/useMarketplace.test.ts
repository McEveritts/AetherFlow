import { lastJobFailed } from './useMarketplace';

describe('lastJobFailed', () => {
    const failedUpdate = {
        last_job: {
            action: 'update',
            status: 'failed',
            started_at: '2026-11-05T21:00:00.000Z',
            finished_at: '2026-11-05T21:00:09.000Z',
        },
    };

    it('reports a failed update even though the package stays installed', () => {
        expect(lastJobFailed(failedUpdate, 'updating')).toBe(true);
    });

    it('ignores outcomes for a different action than the one being watched', () => {
        expect(lastJobFailed(failedUpdate, 'installing')).toBe(false);
        expect(lastJobFailed(failedUpdate, 'uninstalling')).toBe(false);
    });

    it('maps uninstall to the backend remove action and install/reinstall to backend install or reinstall actions', () => {
        expect(
            lastJobFailed({ last_job: { ...failedUpdate.last_job, action: 'remove' } }, 'uninstalling'),
        ).toBe(true);
        expect(
            lastJobFailed({ last_job: { ...failedUpdate.last_job, action: 'reinstall' } }, 'installing'),
        ).toBe(true);
        expect(
            lastJobFailed({ last_job: { ...failedUpdate.last_job, action: 'reinstall' } }, 'reinstalling'),
        ).toBe(true);
    });

    it('treats completed jobs, missing outcomes, and unknown actions as not failed', () => {
        expect(
            lastJobFailed({ last_job: { ...failedUpdate.last_job, status: 'completed' } }, 'updating'),
        ).toBe(false);
        expect(lastJobFailed({}, 'updating')).toBe(false);
        expect(lastJobFailed(failedUpdate, undefined)).toBe(false);
        expect(lastJobFailed(failedUpdate, 'restarting')).toBe(false);
    });
});

// Polls are deliberately allowed to arrive before the lifecycle POST resolves.
// A terminal package state alone must never settle a new request.
import React from 'react';
import { act, renderHook, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';
import {
    useMarketplace,
    App,
    lifecycleIdentity,
    matchingJobOutcome,
    LIFECYCLE_RECEIPT_TIMEOUT_MS,
    resolveInventoryAuthState,
    fetchMarketplaceData,
    latestTransportAuthByEndpoint,
    latestSettledPayloadByEndpoint,
    latestAuthoritativeAuthSeq,
    resetMarketplaceAuthTrackingForTests,
    scrubMarketplacePayloadInPlace,
    PUBLIC_ENVELOPE_ALLOWLIST,
    globalRevokedAuth,
    globalRequestSeq,
    isAuthFailureError,
} from './useMarketplace';
import { versionsMatchTarget, normalizeVersion, isDebianPlusRevision } from '@/components/tabs/MarketplaceTab';

const mockApiFetch = jest.fn();
jest.mock('@/lib/fetcher', () => ({
    ...jest.requireActual('@/lib/fetcher'),
    apiFetch: (...args: unknown[]) => mockApiFetch(...args),
}));

let useRealSwr = false;
let mockApps: App[] = [];
let mockError: Error | undefined;
let mockIsValidating = false;
let mockOptions: { refreshInterval: (apps?: App[]) => number; onSuccess: (apps: App[]) => void; onError?: (err: unknown) => void };
let lastSwrOptions: {
    onSuccess?: (data: unknown, key: string) => void;
    onError?: (error: unknown, key: string) => void;
} | undefined;
jest.mock('swr', () => {
    const actual = jest.requireActual<typeof import('swr')>('swr');
    return {
        ...actual,
        __esModule: true,
        default: (key: unknown, options: unknown) => {
            lastSwrOptions = options as typeof lastSwrOptions;
            if (useRealSwr) {
                return (actual.default as (...args: unknown[]) => unknown)(key, options);
            }
            mockOptions = options as typeof mockOptions;
            return { data: mockApps, error: mockError, isValidating: mockIsValidating, mutate: jest.fn(), isLoading: false };
        },
    };
});

const fixtureApp = (extra: Partial<App> = {}): App => ({
    id: 'fixture',
    name: 'Fixture',
    desc: '',
    hits: 0,
    category: 'Media',
    status: 'installed',
    progress: 0,
    update_available: false,
    inventory_known: true,
    inventory_authenticated: true,
    inventory_mode: 'authenticated',
    ...extra,
});

describe('useMarketplace identity matching', () => {
    beforeEach(() => { useRealSwr = false; latestTransportAuthByEndpoint.clear(); mockApps = [fixtureApp()]; mockError = undefined; mockIsValidating = false; });
    afterEach(() => { jest.useRealTimers(); });

    it.each(['completed', 'failed', 'deduplicated'])('keeps the exact active job pending across identical successful polls until %s', status => {
        jest.useFakeTimers();
        const { result, rerender, unmount } = renderHook(() => useMarketplace());
        act(() => result.current.markPending('fixture', 'updating'));
        act(() => { result.current.registerJob('fixture', { job_id: 'accepted-A' }); });
        mockApps = [fixtureApp({ status: 'updating', job_id: 'accepted-A' })];
        rerender();
        // SWR can preserve this same reference for equal successful responses.
        for (let poll = 0; poll < 6; poll++) {
            act(() => jest.advanceTimersByTime(60000));
            if (status === 'deduplicated') {
                mockIsValidating = true; rerender();
                mockIsValidating = false; rerender();
            } else {
                act(() => mockOptions.onSuccess(mockApps));
            }
            expect(result.current.pendingJobs.get('fixture')).toBe('updating');
            expect(result.current.unconfirmedJobs.size).toBe(0);
        }
        mockApps = [fixtureApp({ last_job: { job_id: 'accepted-A', action: 'update', status: status === 'deduplicated' ? 'completed' : status, started_at: 'now', finished_at: 'later' } })];
        rerender();
        expect(result.current.pendingJobs.size).toBe(0);
        expect(result.current.unconfirmedJobs.size).toBe(0);
        unmount();
        expect(jest.getTimerCount()).toBe(0);
    });

    it.each([' foreign-job', 'wrong-action', 'fetch-errors'].map(s => s.trim()))('does not refresh the deadline from %s', variant => {
        jest.useFakeTimers();
        const { result, rerender, unmount } = renderHook(() => useMarketplace());
        act(() => result.current.markPending('fixture', 'updating'));
        act(() => { result.current.registerJob('fixture', { job_id: 'accepted-A' }); });
        mockApps = [fixtureApp({ status: 'updating', job_id: 'accepted-A' })];
        rerender();
        for (let poll = 0; poll < 3; poll++) {
            act(() => jest.advanceTimersByTime(30000));
            if (variant === 'fetch-errors') {
                mockError = new Error('offline');
                rerender(); // stale cached A remains visible on every failure.
            } else {
                const observed = fixtureApp({ status: variant === 'wrong-action' ? 'installing' : 'updating', job_id: variant === 'foreign-job' ? 'client-B' : 'accepted-A' });
                act(() => mockOptions.onSuccess([observed]));
            }
        }
        act(() => jest.advanceTimersByTime(30000));
        expect(result.current.pendingJobs.size).toBe(0);
        expect(result.current.unconfirmedJobs.get('fixture')).toBe('accepted-A');
        unmount();
        expect(jest.getTimerCount()).toBe(0);
    });

    it.each(['superseded', 'missing', 'delayed'])('bounds an unobserved accepted outcome without inventing success (%s)', variant => {
        jest.useFakeTimers();
        const { result, rerender, unmount } = renderHook(() => useMarketplace());
        act(() => result.current.markPending('fixture', 'updating'));
        act(() => { result.current.registerJob('fixture', { job_id: 'accepted-A' }); });
        mockApps = variant === 'missing'
            ? Object.assign([], { inventory_known: true, inventory_authenticated: true, inventory_mode: 'authenticated' })
            : [fixtureApp({ last_job: { job_id: 'client-B', action: 'update', status: 'completed', started_at: 'later', finished_at: 'later' } })];
        rerender();
        expect(result.current.pendingJobs.has('fixture')).toBe(true);
        act(() => jest.advanceTimersByTime(LIFECYCLE_RECEIPT_TIMEOUT_MS));
        expect(result.current.pendingJobs.has('fixture')).toBe(false);
        expect(result.current.unconfirmedJobs.get('fixture')).toBe('accepted-A');
        expect(mockOptions.refreshInterval(mockApps)).toBe(15000);
        if (variant === 'delayed') expect(() => result.current.registerJob('fixture', { job_id: 'late-acceptance' })).toThrow('tracking expired');
        mockApps = [fixtureApp({ last_job: { job_id: 'accepted-A', action: 'update', status: 'completed', started_at: 'old', finished_at: 'old' } })];
        rerender();
        expect(result.current.unconfirmedJobs.get('fixture')).toBe('accepted-A');
        unmount();
        expect(jest.getTimerCount()).toBe(0);
        jest.useRealTimers();
    });

    it.each(['completed', 'failed', 'interrupted', 'unknown'])('settles only the accepted job (%s), including a finish before the POST response', async status => {
        const { result, rerender } = renderHook(() => useMarketplace());
        act(() => result.current.markPending('fixture', 'updating'));
        mockApps = [fixtureApp()];
        rerender();
        expect(result.current.pendingJobs.get('fixture')).toBe('updating');
        expect(mockOptions.refreshInterval(mockApps)).toBe(1000);
        mockApps = [fixtureApp({ last_job: { job_id: 'older', action: 'update', status: 'completed', started_at: 'old', finished_at: 'now' } })];
        rerender();
        act(() => { result.current.registerJob('fixture', { job_id: 'accepted' }); });
        expect(result.current.pendingJobs.has('fixture')).toBe(true);
        mockApps = [fixtureApp({ last_job: { job_id: 'accepted', action: 'update', status, started_at: 'now', finished_at: 'now' } })];
        rerender();
        expect(result.current.pendingJobs.has('fixture')).toBe(false);
        expect(mockOptions.refreshInterval(mockApps)).toBe(15000);
    });

    it.each([
        ['installing', 'reinstall'],
        ['reinstalling', 'reinstall'],
        ['reinstalling', 'install'],
    ] as const)('settles in-place reinstall receipts when pending action is %s and backend job action is %s without timing out', (pendingAction, backendAction) => {
        jest.useFakeTimers();
        const { result, rerender, unmount } = renderHook(() => useMarketplace());
        act(() => result.current.markPending('fixture', pendingAction));
        act(() => { result.current.registerJob('fixture', { job_id: 'reinstall-job-1' }); });
        mockApps = [fixtureApp({ status: pendingAction, job_id: 'reinstall-job-1' })];
        rerender();
        expect(result.current.pendingJobs.get('fixture')).toBe(pendingAction);

        mockApps = [
            fixtureApp({
                status: 'installed',
                last_job: {
                    job_id: 'reinstall-job-1',
                    action: backendAction,
                    status: 'completed',
                    started_at: '2026-11-08T00:00:00.000Z',
                    finished_at: '2026-11-08T00:00:05.000Z',
                },
            }),
        ];
        rerender();
        expect(matchingJobOutcome(mockApps[0], pendingAction, 'reinstall-job-1')).toEqual(mockApps[0].last_job);
        expect(result.current.pendingJobs.has('fixture')).toBe(false);
        act(() => jest.advanceTimersByTime(LIFECYCLE_RECEIPT_TIMEOUT_MS));
        expect(result.current.unconfirmedJobs.has('fixture')).toBe(false);
        unmount();
        expect(jest.getTimerCount()).toBe(0);
    });

    it('handles a result received before the acceptance response and rejects a different action', () => {
        const { result, rerender } = renderHook(() => useMarketplace());
        act(() => result.current.markPending('fixture', 'updating'));
        mockApps = [fixtureApp({ last_job: { job_id: 'accepted', action: 'remove', status: 'completed', started_at: 'same-time', finished_at: 'now' } })];
        rerender();
        act(() => { result.current.registerJob('fixture', { job_id: 'accepted' }); });
        expect(result.current.pendingJobs.has('fixture')).toBe(true);
        mockApps = [fixtureApp({ last_job: { ...mockApps[0].last_job!, action: 'update' } })];
        rerender();
        expect(result.current.pendingJobs.has('fixture')).toBe(false);
        expect(lifecycleIdentity({ job_id: 'uuid', started_at: 'time' })).toBe('uuid');
        expect(matchingJobOutcome(mockApps[0], 'updating', 'another-job')).toBeUndefined();
    });

    it('does not invent identity when the server omits it', () => {
        const { result } = renderHook(() => useMarketplace());
        act(() => result.current.markPending('fixture', 'updating'));
        expect(() => result.current.registerJob('fixture', {})).toThrow('job identity');
        expect(result.current.pendingJobs.has('fixture')).toBe(true);
    });
});

describe('useMarketplace inventory authentication and redaction', () => {
    beforeEach(() => {
        useRealSwr = false;
        latestTransportAuthByEndpoint.clear();
        mockApps = [fixtureApp()];
        mockError = undefined;
        mockIsValidating = false;
    });

    it('fails closed to public_redacted when inventory metadata is missing or empty', () => {
        // When fetcher returns an array of apps without affirmative inventory metadata
        mockApps = [{ id: 'fixture', name: 'Fixture', desc: '', hits: 0, category: 'Media', status: 'installed', progress: 0, update_available: false }];
        const { result } = renderHook(() => useMarketplace());
        expect(result.current.inventoryAuthenticated).toBe(false);
        expect(result.current.inventoryMode).toBe('public_redacted');

        // Missing / empty inputs all fail closed
        expect(resolveInventoryAuthState(null)).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
        expect(resolveInventoryAuthState(undefined)).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
        expect(resolveInventoryAuthState([])).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
        expect(resolveInventoryAuthState({})).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
        expect(resolveInventoryAuthState([{ id: 'test' }])).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
        expect(resolveInventoryAuthState({ apps: [{ id: 'test' }] })).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
    });

    it('fails closed to public_redacted when fetcher returns an array of apps with inventory_known: false without headers', () => {
        mockApps = [fixtureApp({ inventory_known: false })];
        const { result } = renderHook(() => useMarketplace());
        expect(result.current.inventoryAuthenticated).toBe(false);
        expect(result.current.inventoryMode).toBe('public_redacted');
    });

    it('resolves inventory auth state accurately for negative, affirmative, and header metadata', () => {
        // Negative checks
        expect(resolveInventoryAuthState([{ inventory_known: false }])).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
        expect(resolveInventoryAuthState([{ inventory_authenticated: false }])).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
        expect(resolveInventoryAuthState([{ inventory_mode: 'public_redacted' }])).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
        expect(resolveInventoryAuthState({ apps: [{ inventory_known: false }] })).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
        expect(resolveInventoryAuthState({ packages: [{ inventory_known: false }] })).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
        expect(resolveInventoryAuthState({ inventory_mode: 'public_redacted' })).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
        expect(resolveInventoryAuthState({ inventory_authenticated: false })).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
        expect(resolveInventoryAuthState([{ inventory_known: true }], { 'X-Aetherflow-Inventory-Mode': 'public_redacted' })).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
        expect(resolveInventoryAuthState([{ inventory_known: true }], { 'X-Aetherflow-Inventory-Auth': 'false' })).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        // Affirmative item checks
        expect(resolveInventoryAuthState([{ inventory_known: true }])).toEqual({
            authenticated: true,
            mode: 'authenticated',
        });
        expect(resolveInventoryAuthState([{ inventory_authenticated: true }])).toEqual({
            authenticated: true,
            mode: 'authenticated',
        });
        expect(resolveInventoryAuthState([{ inventory_mode: 'authenticated' }])).toEqual({
            authenticated: true,
            mode: 'authenticated',
        });
        expect(resolveInventoryAuthState({ apps: [{ inventory_known: true }] })).toEqual({
            authenticated: true,
            mode: 'authenticated',
        });
        expect(resolveInventoryAuthState({ packages: [{ inventory_authenticated: true }] })).toEqual({
            authenticated: true,
            mode: 'authenticated',
        });

        // Affirmative envelope checks
        expect(resolveInventoryAuthState({ inventory_mode: 'authenticated', apps: [] })).toEqual({
            authenticated: true,
            mode: 'authenticated',
        });
        expect(resolveInventoryAuthState({ inventory_authenticated: true, apps: [] })).toEqual({
            authenticated: true,
            mode: 'authenticated',
        });

        // Affirmative header checks
        expect(resolveInventoryAuthState([], { 'X-Aetherflow-Inventory-Mode': 'authenticated' })).toEqual({
            authenticated: true,
            mode: 'authenticated',
        });
        expect(resolveInventoryAuthState({ apps: [] }, { 'X-Aetherflow-Inventory-Auth': 'true' })).toEqual({
            authenticated: true,
            mode: 'authenticated',
        });
        expect(resolveInventoryAuthState({ 'X-Aetherflow-Inventory-Mode': 'authenticated', apps: [] })).toEqual({
            authenticated: true,
            mode: 'authenticated',
        });
    });

    it('never allows positive auth header to overwrite negative body or header evidence', () => {
        // Positive auth header combined with negative mode header
        expect(
            resolveInventoryAuthState(
                { apps: [{ inventory_known: true }] },
                'public_redacted',
                'true'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        // Positive auth header combined with negative mode header via object
        expect(
            resolveInventoryAuthState(
                { apps: [{ inventory_known: true }] },
                {
                    'X-Aetherflow-Inventory-Auth': 'true',
                    'X-Aetherflow-Inventory-Mode': 'public_redacted',
                }
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        // Positive auth header with negative envelope mode
        expect(
            resolveInventoryAuthState(
                { inventory_mode: 'public_redacted', apps: [{ inventory_known: true }] },
                undefined,
                'true'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        // Positive auth header with negative envelope inventory_authenticated
        expect(
            resolveInventoryAuthState(
                { inventory_authenticated: false, apps: [{ inventory_known: true }] },
                undefined,
                'true'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        // Positive auth header with negative envelope inventory_known
        expect(
            resolveInventoryAuthState(
                { inventory_known: false, apps: [{ inventory_known: true }] },
                undefined,
                'true'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        // Positive auth header and positive mode header, but items have negative flags
        expect(
            resolveInventoryAuthState(
                { apps: [{ id: 'app1', inventory_known: false }] },
                'authenticated',
                'true'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        expect(
            resolveInventoryAuthState(
                { apps: [{ id: 'app1', inventory_authenticated: false }] },
                'authenticated',
                'true'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        expect(
            resolveInventoryAuthState(
                { apps: [{ id: 'app1', inventory_mode: 'public_redacted' }] },
                'authenticated',
                'true'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        // Negative auth header ('false' or '0') overrides positive mode header
        expect(
            resolveInventoryAuthState(
                { apps: [{ inventory_known: true }] },
                'authenticated',
                'false'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        expect(
            resolveInventoryAuthState(
                { apps: [{ inventory_known: true }] },
                'authenticated',
                '0'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
    });

    it('resolves hook to authenticated when affirmative inventory metadata is present', () => {
        mockApps = [{ id: 'fixture', name: 'Fixture', desc: '', hits: 0, category: 'Media', status: 'installed', progress: 0, update_available: false, inventory_known: true }];
        const { result } = renderHook(() => useMarketplace());
        expect(result.current.inventoryAuthenticated).toBe(true);
        expect(result.current.inventoryMode).toBe('authenticated');
    });

    it('resolves conflicting header aliases on the same Headers, object, or nested sources strictly to public_redacted', () => {
        // Conflicting header aliases on the same plain object
        expect(
            resolveInventoryAuthState(
                { apps: [{ inventory_known: true }] },
                {
                    'X-Aetherflow-Inventory-Mode': 'authenticated',
                    'X-Inventory-Mode': 'public_redacted',
                }
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        // Conflicting header aliases on a Headers instance
        const headersWithConflict = new Headers();
        headersWithConflict.set('x-aetherflow-inventory-mode', 'authenticated');
        headersWithConflict.set('x-inventory-mode', 'public_redacted');
        expect(
            resolveInventoryAuthState(
                { apps: [{ inventory_known: true }] },
                headersWithConflict
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        // Transport header 'authenticated' + nested payload.headers['x-aetherflow-inventory-mode'] = 'public_redacted'
        expect(
            resolveInventoryAuthState(
                {
                    headers: { 'x-aetherflow-inventory-mode': 'public_redacted' },
                    apps: [{ inventory_known: true }],
                },
                'authenticated'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        // Transport header 'authenticated' + nested payload.headers['x-inventory-mode'] = 'public_redacted'
        expect(
            resolveInventoryAuthState(
                {
                    headers: { 'x-inventory-mode': 'public_redacted' },
                    apps: [{ inventory_known: true }],
                },
                'authenticated'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        // Transport header 'authenticated' + nested payload.meta.headers['inventory-mode'] = 'public_redacted'
        expect(
            resolveInventoryAuthState(
                {
                    meta: {
                        headers: { 'inventory-mode': 'public_redacted' },
                    },
                    apps: [{ inventory_known: true }],
                },
                'authenticated'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        // Transport header 'authenticated' + nested payload.meta.inventory_mode = 'public_redacted'
        expect(
            resolveInventoryAuthState(
                {
                    meta: {
                        inventory_mode: 'public_redacted',
                    },
                    apps: [{ inventory_known: true }],
                },
                'authenticated'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
    });

    it('preserves negative transport header public_redacted on array responses end-to-end', async () => {
        const rawPayload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                desc: 'Smart PVR for newsgroup and bittorrent users',
                hits: 10,
                category: 'Media',
                status: 'installed',
                progress: 100,
                update_available: false,
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        mockApiFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            headers: new Headers({
                'X-Aetherflow-Inventory-Mode': 'public_redacted',
            }),
            json: async () => JSON.parse(JSON.stringify(rawPayload)),
        });

        const fetchedData = await fetchMarketplaceData('/api/v1/public/marketplace');
        expect(Array.isArray(fetchedData)).toBe(true);
        expect((fetchedData as unknown as Record<string, unknown>).inventory_authenticated).toBe(false);
        expect((fetchedData as unknown as Record<string, unknown>).inventory_mode).toBe('public_redacted');

        mockApps = fetchedData as App[];
        const { result } = renderHook(() => useMarketplace());
        expect(result.current.inventoryAuthenticated).toBe(false);
        expect(result.current.inventoryMode).toBe('public_redacted');
    });

    it('resolves comma-joined duplicate headers to public_redacted when negative tokens are present', () => {
        expect(
            resolveInventoryAuthState(
                [{ id: 'sonarr', inventory_known: true }],
                'authenticated, public_redacted'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        expect(
            resolveInventoryAuthState(
                [{ id: 'sonarr', inventory_known: true }],
                { 'X-Aetherflow-Inventory-Mode': 'authenticated, public_redacted' }
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        expect(
            resolveInventoryAuthState(
                [{ id: 'sonarr', inventory_known: true }],
                undefined,
                'true, false'
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        expect(
            resolveInventoryAuthState(
                [{ id: 'sonarr', inventory_known: true }],
                undefined,
                { 'X-Aetherflow-Inventory-Auth': 'true, false' }
            )
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
    });

    it('resolves item-level item.meta negative flags strictly to public_redacted', () => {
        expect(
            resolveInventoryAuthState([
                {
                    id: 'app1',
                    inventory_known: true,
                    meta: { inventory_mode: 'public_redacted' },
                },
            ])
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        expect(
            resolveInventoryAuthState([
                {
                    id: 'app1',
                    inventory_known: true,
                    meta: { inventoryAuthenticated: false },
                },
            ])
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        expect(
            resolveInventoryAuthState([
                {
                    id: 'app1',
                    inventory_known: true,
                    meta: { inventory_authenticated: false },
                },
            ])
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });

        expect(
            resolveInventoryAuthState([
                {
                    id: 'app1',
                    inventory_known: true,
                    meta: { inventoryMode: 'public_redacted' },
                },
            ])
        ).toEqual({
            authenticated: false,
            mode: 'public_redacted',
        });
    });

    it('verifies versionsMatchTarget for stacked prefixes, Debian binNMUs, and debug build metadata', () => {
        expect(versionsMatchTarget('release-v1.2.3', '1.2.3')).toBe(true);
        expect(versionsMatchTarget('rel_v1.2.3', '1.2.3')).toBe(true);
        expect(versionsMatchTarget('rel-v2.0', '2.0')).toBe(true);
        expect(versionsMatchTarget('1.0.0+b1', '1.0.0+b2')).toBe(false);
        expect(versionsMatchTarget('1.0.0+b1', '1.0.0')).toBe(false);
        expect(versionsMatchTarget('1.0.0', '1.0.0+debug')).toBe(false);
        expect(versionsMatchTarget('1.0.0+debug', '1.0.0')).toBe(false);
        expect(versionsMatchTarget('1.0.0+debug', 'v1.0.0+debug')).toBe(true);
        expect(versionsMatchTarget('1.0.0+Debug', '1.0.0+debug')).toBe(false);
        expect(versionsMatchTarget('1.0.0+Debug', 'v1.0.0+Debug')).toBe(true);
        expect(versionsMatchTarget('frontend=1.0,backend=2.0,proxy=3.0', 'frontend:v1.0,backend:v2.0,proxy:v3.0')).toBe(true);

        expect(normalizeVersion('release-v1.2.3')).toBe('1.2.3');
        expect(normalizeVersion('rel_v1.2.3')).toBe('1.2.3');
        expect(normalizeVersion('1.0.0+b1')).toBe('1.0.0+b1');
        expect(normalizeVersion('1.0.0+b2')).toBe('1.0.0+b2');
        expect(normalizeVersion('1.0.0+debug')).toBe('1.0.0+debug');
        expect(normalizeVersion('v1.0.0+debug')).toBe('1.0.0+debug');
        expect(normalizeVersion('1.0.0+Debug')).toBe('1.0.0+Debug');
        expect(normalizeVersion('v1.0.0+Debug')).toBe('1.0.0+Debug');

        expect(isDebianPlusRevision('b1')).toBe(true);
        expect(isDebianPlusRevision('b2')).toBe(true);
        expect(isDebianPlusRevision('debug')).toBe(false);
    });

    it('suppresses lifecycle fields on packages and exposes pendingActions as {} when in public_redacted mode', async () => {
        const rawPayload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                desc: 'Smart PVR for newsgroup and bittorrent users',
                hits: 10,
                category: 'Media',
                status: 'updating',
                installed: true,
                installed_version: '3.0.0',
                update_available: true,
                update_error: 'Error checking',
                progress: 42,
                log_line: 'running secret migration',
                job_id: 'job-123',
                active_job: { action: 'update' },
                last_job: { action: 'update', status: 'running' },
                last_job_outcome: { action: 'update' },
                started_at: '2026-11-09T00:00:00Z',
                inventory_known: false,
                inventory_authenticated: false,
                inventory_mode: 'public_redacted',
            },
        ];

        mockApiFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            headers: new Headers({
                'X-Aetherflow-Inventory-Mode': 'public_redacted',
            }),
            json: async () => JSON.parse(JSON.stringify(rawPayload)),
        });

        const fetchedData = await fetchMarketplaceData('/api/v1/public/marketplace');
        const pkg = (fetchedData as Record<string, unknown>[])[0];
        expect(pkg.status).toBe('not_installed');
        expect(pkg.installed).toBe(false);
        expect(pkg.installed_version).toBeUndefined();
        expect(pkg.update_available).toBe(false);
        expect(pkg.update_error).toBeUndefined();
        expect(pkg.progress).toBeUndefined();
        expect(pkg.log_line).toBeUndefined();
        expect(pkg.job_id).toBeUndefined();
        expect(pkg.active_job).toBeUndefined();
        expect(pkg.last_job).toBeUndefined();
        expect(pkg.last_job_outcome).toBeUndefined();

        mockApps = fetchedData as App[];
        const { result } = renderHook(() => useMarketplace());
        expect(result.current.inventoryAuthenticated).toBe(false);
        expect(result.current.inventoryMode).toBe('public_redacted');
        expect(result.current.pendingActions).toEqual({});
        expect(result.current.apps?.[0].status).toBe('not_installed');
        expect(result.current.apps?.[0].progress).toBeUndefined();
    });

    it('clears and suppresses pendingActions, pendingJobs, and unconfirmedJobs when transitioning to public_redacted', () => {
        jest.useFakeTimers();
        const { result, rerender, unmount } = renderHook(() => useMarketplace());

        expect(result.current.inventoryAuthenticated).toBe(true);
        expect(result.current.inventoryMode).toBe('authenticated');

        // Populate an unconfirmed job via timeout
        act(() => {
            result.current.markPending('fixture-1', 'updating');
            result.current.registerJob('fixture-1', { job_id: 'job-1' });
        });
        act(() => {
            jest.advanceTimersByTime(LIFECYCLE_RECEIPT_TIMEOUT_MS);
        });
        expect(result.current.unconfirmedJobs.get('fixture-1')).toBe('job-1');

        // Populate active pendingJobs and pendingActions
        act(() => {
            result.current.markPending('fixture-2', 'installing');
        });

        // Verify all 3 maps/records are populated in authenticated mode
        expect(result.current.pendingJobs.size).toBe(1);
        expect(result.current.pendingJobs.get('fixture-2')).toBe('installing');
        expect(result.current.pendingActions).toEqual({ 'fixture-2': 'installing' });
        expect(result.current.unconfirmedJobs.size).toBe(1);
        expect(result.current.unconfirmedJobs.get('fixture-1')).toBe('job-1');

        // Transition to public_redacted mode
        mockApps = [
            fixtureApp({
                inventory_known: false,
                inventory_authenticated: false,
                inventory_mode: 'public_redacted',
            }),
        ];
        rerender();

        // Verify all 3 maps/records are suppressed to empty in the hook return value
        expect(result.current.inventoryAuthenticated).toBe(false);
        expect(result.current.inventoryMode).toBe('public_redacted');
        expect(result.current.pendingActions).toEqual({});
        expect(result.current.pendingJobs.size).toBe(0);
        expect(result.current.pendingJobs).toEqual(new Map());
        expect(result.current.unconfirmedJobs.size).toBe(0);
        expect(result.current.unconfirmedJobs).toEqual(new Map());

        unmount();
        expect(jest.getTimerCount()).toBe(0);
        jest.useRealTimers();
    });
});

describe('real SWR cache & auth state transitions', () => {
    beforeEach(() => {
        useRealSwr = true;
        latestTransportAuthByEndpoint.clear();
        mockApiFetch.mockReset();
    });

    afterEach(() => {
        useRealSwr = false;
        latestTransportAuthByEndpoint.clear();
        mockApiFetch.mockReset();
    });

    const createWrapper = (customCache?: Map<unknown, unknown>) => {
        const cache = customCache ?? new Map();
        return function TestSwrWrapper({ children }: { children: React.ReactNode }) {
            return React.createElement(
                SWRConfig,
                { value: { provider: () => cache, dedupingInterval: 0 } },
                children
            );
        };
    };

    it('transitions authenticated -> public_redacted on byte-identical JSON arrays when headers change', async () => {
        const samplePayload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        mockApiFetch
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'authenticated',
                }),
                json: async () => JSON.parse(JSON.stringify(samplePayload)),
            })
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'public_redacted',
                }),
                json: async () => JSON.parse(JSON.stringify(samplePayload)),
            });

        const { result } = renderHook(() => useMarketplace(), { wrapper: createWrapper() });

        await waitFor(() => {
            expect(result.current.isLoading).toBe(false);
            expect(result.current.inventoryAuthenticated).toBe(true);
            expect(result.current.inventoryMode).toBe('authenticated');
        });

        await act(async () => {
            await result.current.mutate();
        });

        await waitFor(() => {
            expect(result.current.inventoryAuthenticated).toBe(false);
            expect(result.current.inventoryMode).toBe('public_redacted');
        });
    });

    it('transitions authenticated -> public_redacted on empty arrays [] -> [] when headers change', async () => {
        mockApiFetch
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'authenticated',
                }),
                json: async () => [],
            })
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'public_redacted',
                }),
                json: async () => [],
            });

        const { result } = renderHook(() => useMarketplace(), { wrapper: createWrapper() });

        await waitFor(() => {
            expect(result.current.isLoading).toBe(false);
            expect(result.current.inventoryAuthenticated).toBe(true);
            expect(result.current.inventoryMode).toBe('authenticated');
        });

        await act(async () => {
            await result.current.mutate();
        });

        await waitFor(() => {
            expect(result.current.inventoryAuthenticated).toBe(false);
            expect(result.current.inventoryMode).toBe('public_redacted');
        });
    });

    it('transitions public_redacted -> authenticated on identical JSON arrays when headers change', async () => {
        const samplePayload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        mockApiFetch
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'public_redacted',
                }),
                json: async () => JSON.parse(JSON.stringify(samplePayload)),
            })
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'authenticated',
                }),
                json: async () => JSON.parse(JSON.stringify(samplePayload)),
            });

        const { result } = renderHook(() => useMarketplace(), { wrapper: createWrapper() });

        await waitFor(() => {
            expect(result.current.isLoading).toBe(false);
            expect(result.current.inventoryAuthenticated).toBe(false);
            expect(result.current.inventoryMode).toBe('public_redacted');
        });

        await act(async () => {
            await result.current.mutate();
        });

        await waitFor(() => {
            expect(result.current.inventoryAuthenticated).toBe(true);
            expect(result.current.inventoryMode).toBe('authenticated');
        });
    });

    it('notifies two concurrent useMarketplace subscribers sharing the same real SWR cache of the transition to public_redacted', async () => {
        const samplePayload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        mockApiFetch
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'authenticated',
                }),
                json: async () => JSON.parse(JSON.stringify(samplePayload)),
            })
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'public_redacted',
                }),
                json: async () => JSON.parse(JSON.stringify(samplePayload)),
            });

        const sharedCache = new Map();
        const wrapper = createWrapper(sharedCache);

        const sub1 = renderHook(() => useMarketplace(), { wrapper });
        const sub2 = renderHook(() => useMarketplace(), { wrapper });

        await waitFor(() => {
            expect(sub1.result.current.isLoading).toBe(false);
            expect(sub2.result.current.isLoading).toBe(false);
            expect(sub1.result.current.inventoryAuthenticated).toBe(true);
            expect(sub1.result.current.inventoryMode).toBe('authenticated');
            expect(sub2.result.current.inventoryAuthenticated).toBe(true);
            expect(sub2.result.current.inventoryMode).toBe('authenticated');
        });

        await act(async () => {
            await sub1.result.current.mutate();
        });

        await waitFor(() => {
            expect(sub1.result.current.inventoryAuthenticated).toBe(false);
            expect(sub1.result.current.inventoryMode).toBe('public_redacted');
            expect(sub2.result.current.inventoryAuthenticated).toBe(false);
            expect(sub2.result.current.inventoryMode).toBe('public_redacted');
        });
    });

    it('suppresses and clears active pendingActions, pendingJobs, and unconfirmedJobs during real SWR transition to public_redacted', async () => {
        const authPayload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];
        const redactedPayload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                inventory_known: false,
                inventory_authenticated: false,
                inventory_mode: 'public_redacted',
            },
        ];

        mockApiFetch
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'authenticated',
                }),
                json: async () => JSON.parse(JSON.stringify(authPayload)),
            })
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'public_redacted',
                }),
                json: async () => JSON.parse(JSON.stringify(redactedPayload)),
            });

        const { result } = renderHook(() => useMarketplace(), { wrapper: createWrapper() });

        await waitFor(() => {
            expect(result.current.isLoading).toBe(false);
            expect(result.current.inventoryAuthenticated).toBe(true);
            expect(result.current.inventoryMode).toBe('authenticated');
        });

        act(() => {
            result.current.markPending('sonarr', 'updating');
        });

        expect(result.current.pendingJobs.size).toBe(1);
        expect(result.current.pendingActions).toEqual({ sonarr: 'updating' });

        await act(async () => {
            await result.current.mutate();
        });

        await waitFor(() => {
            expect(result.current.inventoryAuthenticated).toBe(false);
            expect(result.current.inventoryMode).toBe('public_redacted');
            expect(result.current.pendingActions).toEqual({});
            expect(result.current.pendingJobs.size).toBe(0);
            expect(result.current.unconfirmedJobs.size).toBe(0);
        });
    });

    it('transitions authenticated 200 -> 403 Forbidden error in real SWR, fails closed to public_redacted, sanitizes cached packages, and clears pending/unconfirmed jobs', async () => {
        const authPayload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                desc: 'Smart PVR',
                hits: 10,
                category: 'Media',
                status: 'installed',
                installed: true,
                installed_version: '3.0.0',
                latest_version: '3.1.0',
                version: '3.0.0',
                current_version: '3.0.0',
                target_version: '3.1.0',
                achieved_version: '3.0.0',
                update_available: true,
                checked_at: '2026-11-09T00:00:00Z',
                last_checked_at: '2026-11-09T00:00:00Z',
                update_checked_at: '2026-11-09T00:00:00Z',
                update_error: 'Stale error',
                last_error: 'Previous error',
                error: 'Previous error',
                update_url: 'https://example.com/update',
                source_key: 'custom-src',
                port: 8989,
                active_port: 8989,
                assigned_port: 8989,
                domains: ['sonarr.local'],
                domain: 'sonarr.local',
                local_domain: 'sonarr.local',
                public_domain: 'sonarr.example.com',
                ingress: { enabled: true },
                url: 'http://localhost:8989',
                access_url: 'http://localhost:8989',
                service_status: 'running',
                health: 'healthy',
                pid: 12345,
                memory_mb: 256,
                cpu_percent: 1.5,
                uptime: 3600,
                config_path: '/etc/sonarr',
                install_path: '/opt/sonarr',
                progress: 100,
                log_line: 'running',
                job_id: 'job-123',
                active_job: { action: 'install' },
                last_job: { action: 'install', status: 'completed' },
                last_job_outcome: { action: 'install' },
                started_at: '2026-11-09T00:00:00Z',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        mockApiFetch
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'authenticated',
                    'X-Aetherflow-Inventory-Auth': 'true',
                }),
                json: async () => JSON.parse(JSON.stringify(authPayload)),
            })
            .mockResolvedValueOnce({
                ok: false,
                status: 403,
                headers: new Headers(),
                json: async () => ({ message: 'Forbidden' }),
            });

        const sharedCache = new Map();
        const wrapper = createWrapper(sharedCache);
        const { result } = renderHook(() => useMarketplace(), { wrapper });

        await waitFor(() => {
            expect(result.current.isLoading).toBe(false);
            expect(result.current.inventoryAuthenticated).toBe(true);
            expect(result.current.inventoryMode).toBe('authenticated');
            expect(result.current.apps?.[0].latest_version).toBe('3.1.0');
            expect(result.current.apps?.[0].installed_version).toBe('3.0.0');
        });

        // Set pending actions and jobs
        act(() => {
            result.current.markPending('sonarr', 'updating');
            result.current.registerJob('sonarr', { job_id: 'job-403' });
        });

        expect(result.current.pendingJobs.size).toBe(1);
        expect(result.current.pendingActions).toEqual({ sonarr: 'updating' });

        // Mutate triggers refetch, which encounters 403 Forbidden
        await act(async () => {
            try {
                await result.current.mutate();
            } catch {
                // SWR mutate re-throws error
            }
        });

        await waitFor(() => {
            expect(result.current.isError).toBe(true);
            expect(result.current.inventoryAuthenticated).toBe(false);
            expect(result.current.inventoryMode).toBe('public_redacted');
        });

        // Pending and unconfirmed jobs/actions are cleared/empty
        expect(result.current.pendingActions).toEqual({});
        expect(result.current.pendingJobs.size).toBe(0);
        expect(result.current.unconfirmedJobs.size).toBe(0);

        // Cached apps/packages are sanitized via sanitizePublicPackage
        const pkg = result.current.apps?.[0];
        expect(pkg).toBeDefined();
        expect(pkg?.installed).toBe(false);
        expect(pkg?.status).toBe('not_installed');
        expect(pkg?.update_available).toBe(false);
        expect(pkg?.installed_version).toBeUndefined();
        expect(pkg?.latest_version).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.version).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.current_version).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.target_version).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.achieved_version).toBeUndefined();
        expect(pkg?.checked_at).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.last_checked_at).toBeUndefined();
        expect(pkg?.update_checked_at).toBeUndefined();
        expect(pkg?.update_error).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.last_error).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.error).toBeUndefined();
        expect(pkg?.update_url).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.source_key).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.port).toBeUndefined();
        expect(pkg?.active_port).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.assigned_port).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.domains).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.domain).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.local_domain).toBeUndefined();
        expect(pkg?.public_domain).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.ingress).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.url).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.access_url).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.service_status).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.health).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.pid).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.memory_mb).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.cpu_percent).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.uptime).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.config_path).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.install_path).toBeUndefined();
        expect(pkg?.progress).toBeUndefined();
        expect(pkg?.log_line).toBeUndefined();
        expect(pkg?.job_id).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.active_job).toBeUndefined();
        expect(pkg?.last_job).toBeUndefined();
        expect((pkg as unknown as Record<string, unknown>)?.last_job_outcome).toBeUndefined();
        expect(pkg?.started_at).toBeUndefined();
        expect(pkg?.inventory_known).toBe(false);
        expect(pkg?.inventory_mode).toBe('public_redacted');
        expect(pkg?.inventory_authenticated).toBe(false);
        expect(result.current.packages).toEqual(result.current.apps);
    });

    it('prevents a stale 200 response from overriding a newer 403 revocation across marketplace requests', async () => {
        let resolveReq1!: (value: unknown) => void;
        const req1Promise = new Promise(resolve => {
            resolveReq1 = resolve;
        });

        // Request 1 is slow, Request 2 fails with 403 Forbidden
        mockApiFetch
            .mockImplementationOnce(() => req1Promise)
            .mockResolvedValueOnce({
                ok: false,
                status: 403,
                headers: new Headers(),
                json: async () => ({ message: 'Forbidden' }),
            });

        // Initiate slow Request 1
        const p1 = fetchMarketplaceData('/api/v1/public/marketplace');

        // Initiate fast Request 2 which settles first with 403
        let p2Error: unknown;
        try {
            await fetchMarketplaceData('/api/v1/public/marketplace');
        } catch (err) {
            p2Error = err;
        }
        expect(p2Error).toBeDefined();

        // After Request 2, transport state is revoked to public_redacted
        const transportAuthAfter403 = latestTransportAuthByEndpoint.get('/api/v1/public/marketplace');
        const isPublicRedacted = (auth: unknown) =>
            auth === 'public_redacted' || (typeof auth === 'object' && (auth as unknown as Record<string, unknown>)?.mode === 'public_redacted');
        expect(isPublicRedacted(transportAuthAfter403)).toBe(true);

        // Now settle slow Request 1 with 200 OK and authenticated body
        const authPayload = [
            {
                id: 'radarr',
                name: 'Radarr',
                desc: 'Movie collection manager',
                category: 'Media',
                status: 'installed',
                installed: true,
                internal_domain: 'radarr.internal',
                external_access_enabled: true,
                tls_enabled: true,
                latest_version: '5.0.0',
                installed_version: '4.9.0',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        resolveReq1({
            ok: true,
            status: 200,
            headers: new Headers({
                'X-Aetherflow-Inventory-Mode': 'authenticated',
                'X-Aetherflow-Inventory-Auth': 'true',
            }),
            json: async () => JSON.parse(JSON.stringify(authPayload)),
        });

        const res1 = await p1;

        // Transport auth MUST remain public_redacted and NOT flip back to authenticated
        const transportAuthAfterStale200 = latestTransportAuthByEndpoint.get('/api/v1/public/marketplace');
        expect(isPublicRedacted(transportAuthAfterStale200)).toBe(true);

        // The returned payload must have been sanitized in-place and marked public_redacted
        expect((res1 as unknown as Record<string, unknown>).inventory_authenticated).toBe(false);
        expect((res1 as unknown as Record<string, unknown>).inventory_mode).toBe('public_redacted');
        expect(res1[0].internal_domain).toBeUndefined();
        expect(res1[0].external_access_enabled).toBeUndefined();
        expect(res1[0].tls_enabled).toBeUndefined();
        expect(res1[0].installed).toBe(false);
        expect(res1[0].status).toBe('not_installed');

        // Hook subscriber using this data must also remain public_redacted
        const sharedCache = new Map();
        sharedCache.set('/api/v1/public/marketplace', {
            data: res1,
            isValidating: false,
            isLoading: false,
        });
        const { result } = renderHook(() => useMarketplace(), { wrapper: createWrapper(sharedCache) });
        expect(result.current.inventoryAuthenticated).toBe(false);
        expect(result.current.inventoryMode).toBe('public_redacted');
    });

    it('forces external/custom SWR payloads lacking __resolvedInventoryAuth to transition to public_redacted upon 403 revocation', async () => {
        const sharedCache = new Map();
        const wrapper = createWrapper(sharedCache);

        const authPayload = [
            {
                id: 'radarr',
                name: 'Radarr',
                category: 'Media',
                status: 'installed',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        mockApiFetch
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'authenticated',
                    'X-Aetherflow-Inventory-Auth': 'true',
                }),
                json: async () => JSON.parse(JSON.stringify(authPayload)),
            })
            .mockResolvedValueOnce({
                ok: false,
                status: 403,
                headers: new Headers(),
                json: async () => ({ message: 'Forbidden' }),
            });

        // Subscriber 1 is a standard useMarketplace subscriber
        const sub1 = renderHook(() => useMarketplace(), { wrapper });

        await waitFor(() => {
            expect(sub1.result.current.isLoading).toBe(false);
            expect(sub1.result.current.inventoryAuthenticated).toBe(true);
            expect(sub1.result.current.inventoryMode).toBe('authenticated');
        });

        // Subscriber 2 uses a custom/external SWR payload lacking __resolvedInventoryAuth
        // with affirmative flags in its payload body
        const customExternalPayload: App[] = [
            {
                id: 'custom-package',
                name: 'Custom Package',
                desc: 'External payload',
                hits: 5,
                category: 'System',
                status: 'installed',
                progress: 100,
                update_available: false,
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        sharedCache.set('/api/v1/public/marketplace?require_auth=1', {
            data: customExternalPayload,
            isValidating: false,
            isLoading: false,
        });

        const sub2 = renderHook(() => useMarketplace({ requireAuth: true }), { wrapper });

        await waitFor(() => {
            expect(sub2.result.current.inventoryAuthenticated).toBe(true);
            expect(sub2.result.current.inventoryMode).toBe('authenticated');
        });

        // Trigger 403 on subscriber 1
        await act(async () => {
            try {
                await sub1.result.current.mutate();
            } catch {
                // SWR mutate re-throws error
            }
        });

        // BOTH subscribers must transition to public_redacted
        await waitFor(() => {
            expect(sub1.result.current.inventoryAuthenticated).toBe(false);
            expect(sub1.result.current.inventoryMode).toBe('public_redacted');
            expect(sub2.result.current.inventoryAuthenticated).toBe(false);
            expect(sub2.result.current.inventoryMode).toBe('public_redacted');
        });
    });

    it('completely removes internal_domain, external_access_enabled, tls_enabled, latest_version, installed_version, checked_at, port, and domains from packages and SWR cache upon revocation', async () => {
        const sensitivePackage = {
            id: 'sonarr',
            name: 'Sonarr',
            desc: 'Smart PVR',
            category: 'Media',
            status: 'installed',
            installed: true,
            progress: 100,
            internal_domain: 'sonarr.internal.lan',
            external_access_enabled: true,
            tls_enabled: true,
            latest_version: '3.1.0',
            installed_version: '3.0.0',
            checked_at: '2026-11-09T00:00:00Z',
            port: 8989,
            domains: ['sonarr.internal.lan'],
            inventory_known: true,
            inventory_authenticated: true,
            inventory_mode: 'authenticated',
        };

        mockApiFetch
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'authenticated',
                    'X-Aetherflow-Inventory-Auth': 'true',
                }),
                json: async () => [JSON.parse(JSON.stringify(sensitivePackage))],
            })
            .mockResolvedValueOnce({
                ok: false,
                status: 403,
                headers: new Headers(),
                json: async () => ({ message: 'Forbidden' }),
            });

        const sharedCache = new Map();
        const wrapper = createWrapper(sharedCache);
        const { result } = renderHook(() => useMarketplace(), { wrapper });

        await waitFor(() => {
            expect(result.current.isLoading).toBe(false);
            expect(result.current.inventoryAuthenticated).toBe(true);
            expect(result.current.inventoryMode).toBe('authenticated');
            expect((result.current.packages?.[0] as unknown as Record<string, unknown>)?.internal_domain).toBe('sonarr.internal.lan');
            expect((result.current.packages?.[0] as unknown as Record<string, unknown>)?.external_access_enabled).toBe(true);
            expect((result.current.packages?.[0] as unknown as Record<string, unknown>)?.tls_enabled).toBe(true);
        });

        // Trigger revocation via 403
        await act(async () => {
            try {
                await result.current.mutate();
            } catch {
                // SWR mutate re-throws error
            }
        });

        await waitFor(() => {
            expect(result.current.inventoryAuthenticated).toBe(false);
            expect(result.current.inventoryMode).toBe('public_redacted');
        });

        // 1. Verify result.current.packages[0] has all sensitive fields stripped
        const returnedPkg = result.current.packages?.[0] as unknown as Record<string, unknown>;
        expect(returnedPkg).toBeDefined();
        expect(returnedPkg.internal_domain).toBeUndefined();
        expect(returnedPkg.external_access_enabled).toBeUndefined();
        expect(returnedPkg.tls_enabled).toBeUndefined();
        expect(returnedPkg.latest_version).toBeUndefined();
        expect(returnedPkg.installed_version).toBeUndefined();
        expect(returnedPkg.checked_at).toBeUndefined();
        expect(returnedPkg.port).toBeUndefined();
        expect(returnedPkg.domains).toBeUndefined();
        expect(returnedPkg.installed).toBe(false);
        expect(returnedPkg.status).toBe('not_installed');
        expect(returnedPkg.inventory_mode).toBe('public_redacted');
        expect(returnedPkg.inventory_authenticated).toBe(false);

        // 2. Verify original cached object in SWR cache also has all sensitive fields stripped
        const cacheEntry = sharedCache.get('/api/v1/public/marketplace') as unknown as Record<string, unknown>;
        const cachedPkg = Array.isArray(cacheEntry)
            ? cacheEntry[0]
            : (Array.isArray(cacheEntry?.data) ? cacheEntry.data[0] : undefined);
        expect(cachedPkg).toBeDefined();
        expect(cachedPkg.internal_domain).toBeUndefined();
        expect(cachedPkg.external_access_enabled).toBeUndefined();
        expect(cachedPkg.tls_enabled).toBeUndefined();
        expect(cachedPkg.latest_version).toBeUndefined();
        expect(cachedPkg.installed_version).toBeUndefined();
        expect(cachedPkg.checked_at).toBeUndefined();
        expect(cachedPkg.port).toBeUndefined();
        expect(cachedPkg.domains).toBeUndefined();
        expect(cachedPkg.installed).toBe(false);
        expect(cachedPkg.status).toBe('not_installed');
    });
});

describe('Category 5 P2: In-place cache scrubbing of envelopes and field restrictions', () => {
    it('scrubs items envelopes to public allowlist and deletes unknown envelope-level fields', () => {
        const payload: Record<string, unknown> = {
            items: [
                {
                    id: 'sonarr',
                    installed: true,
                    internal_domain: 'sonarr.aether.local',
                    port: 8989,
                },
            ],
            meta: { user: 'admin' },
            host_ip: '192.168.1.50',
        };

        const result = scrubMarketplacePayloadInPlace(payload) as Record<string, unknown>;
        expect(result).toBe(payload);

        // Envelope-level meta and host_ip MUST be deleted from payload
        expect(payload.meta).toBeUndefined();
        expect(payload.host_ip).toBeUndefined();
        expect('meta' in payload).toBe(false);
        expect('host_ip' in payload).toBe(false);

        // Envelope auth metadata must be public_redacted
        expect(payload.inventory_known).toBe(false);
        expect(payload.inventory_mode).toBe('public_redacted');
        expect(payload.inventory_authenticated).toBe(false);
        expect((payload as unknown as Record<string, unknown>).__resolvedInventoryAuth).toBe('public_redacted');

        // Verify PUBLIC_ENVELOPE_ALLOWLIST contents
        expect(PUBLIC_ENVELOPE_ALLOWLIST.has('apps')).toBe(true);
        expect(PUBLIC_ENVELOPE_ALLOWLIST.has('packages')).toBe(true);
        expect(PUBLIC_ENVELOPE_ALLOWLIST.has('items')).toBe(true);
        expect(PUBLIC_ENVELOPE_ALLOWLIST.has('data')).toBe(true);
        expect(PUBLIC_ENVELOPE_ALLOWLIST.has('inventory_known')).toBe(true);
        expect(PUBLIC_ENVELOPE_ALLOWLIST.has('inventory_mode')).toBe(true);
        expect(PUBLIC_ENVELOPE_ALLOWLIST.has('inventory_authenticated')).toBe(true);
        expect(PUBLIC_ENVELOPE_ALLOWLIST.has('__resolvedInventoryAuth')).toBe(true);
        expect(PUBLIC_ENVELOPE_ALLOWLIST.has('meta')).toBe(false);
        expect(PUBLIC_ENVELOPE_ALLOWLIST.has('host_ip')).toBe(false);

        // payload.items[0] must be scrubbed to public allowlist
        const items = payload.items as Record<string, unknown>[];
        expect(Array.isArray(items)).toBe(true);
        expect((items as unknown as Record<string, unknown>).__resolvedInventoryAuth).toBe('public_redacted');

        const item0 = items[0];
        expect(item0.id).toBe('sonarr');
        expect(item0.installed).toBe(false);
        expect(item0.status).toBe('not_installed');
        expect(item0.internal_domain).toBeUndefined();
        expect(item0.port).toBeUndefined();
        expect('internal_domain' in item0).toBe(false);
        expect('port' in item0).toBe(false);
    });

    it('scrubs nested data envelope objects and arrays in-place while restricting fields', () => {
        const payload: Record<string, unknown> = {
            data: {
                items: [
                    {
                        id: 'radarr',
                        installed: true,
                        internal_domain: 'radarr.internal',
                        secret_token: 'secret123',
                    },
                ],
                secret_config: { key: 'val' },
            },
            admin_user: 'root',
        };

        scrubMarketplacePayloadInPlace(payload);
        expect(payload.admin_user).toBeUndefined();
        expect('admin_user' in payload).toBe(false);

        const dataObj = payload.data as Record<string, unknown>;
        expect(dataObj.secret_config).toBeUndefined();
        expect('secret_config' in dataObj).toBe(false);

        const items = dataObj.items as Record<string, unknown>[];
        expect(items[0].id).toBe('radarr');
        expect(items[0].installed).toBe(false);
        expect(items[0].internal_domain).toBeUndefined();
        expect(items[0].secret_token).toBeUndefined();
    });
});

describe('Category 5 P3: Bidirectional monotonic request ordering', () => {
    beforeEach(() => {
        useRealSwr = true;
        latestTransportAuthByEndpoint.clear();
        mockApiFetch.mockReset();
    });

    afterEach(() => {
        useRealSwr = false;
        latestTransportAuthByEndpoint.clear();
        mockApiFetch.mockReset();
    });

    const createWrapper = (customCache?: Map<unknown, unknown>) => {
        const cache = customCache ?? new Map();
        return function TestSwrWrapper({ children }: { children: React.ReactNode }) {
            return React.createElement(
                SWRConfig,
                { value: { provider: () => cache, dedupingInterval: 0 } },
                children
            );
        };
    };

    const isAuth = (auth: unknown) =>
        auth === 'authenticated' || (typeof auth === 'object' && (auth as unknown as Record<string, unknown>)?.mode === 'authenticated' && (auth as unknown as Record<string, unknown>)?.authenticated);

    const isPublicRedacted = (auth: unknown) =>
        auth === 'public_redacted' || (typeof auth === 'object' && (auth as unknown as Record<string, unknown>)?.mode === 'public_redacted');

    it('Order 1: Request #1 (authenticated 200, slow) starts before Request #2 (403 Forbidden, fast). Request #2 finishes first, then Request #1 finishes -> hook remains public_redacted', async () => {
        let resolveReq1!: (value: unknown) => void;
        const req1Promise = new Promise(resolve => {
            resolveReq1 = resolve;
        });

        const authPayload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                desc: 'Smart PVR',
                category: 'Media',
                status: 'installed',
                installed: true,
                internal_domain: 'sonarr.internal',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        mockApiFetch
            .mockImplementationOnce(() => req1Promise)
            .mockResolvedValueOnce({
                ok: false,
                status: 403,
                headers: new Headers(),
                json: async () => ({ message: 'Forbidden' }),
            });

        // Request #1 starts (slow)
        const p1 = fetchMarketplaceData('/api/v1/public/marketplace');

        // Request #2 starts and finishes first with 403 Forbidden
        let p2Error: unknown;
        try {
            await fetchMarketplaceData('/api/v1/public/marketplace');
        } catch (err) {
            p2Error = err;
        }
        expect(p2Error).toBeDefined();

        // Transport auth is revoked to public_redacted by Request #2
        expect(isPublicRedacted(latestTransportAuthByEndpoint.get('/api/v1/public/marketplace'))).toBe(true);

        // Now Request #1 finishes with 200 OK (authenticated payload)
        resolveReq1({
            ok: true,
            status: 200,
            headers: new Headers({
                'X-Aetherflow-Inventory-Mode': 'authenticated',
                'X-Aetherflow-Inventory-Auth': 'true',
            }),
            json: async () => JSON.parse(JSON.stringify(authPayload)),
        });

        const res1 = await p1;

        // Transport auth MUST remain public_redacted
        expect(isPublicRedacted(latestTransportAuthByEndpoint.get('/api/v1/public/marketplace'))).toBe(true);

        // res1 payload must be scrubbed in-place
        expect((res1 as unknown as Record<string, unknown>).inventory_authenticated).toBe(false);
        expect((res1 as unknown as Record<string, unknown>).inventory_mode).toBe('public_redacted');
        expect(res1[0].installed).toBe(false);
        expect(res1[0].internal_domain).toBeUndefined();

        // Hook remains public_redacted
        const sharedCache = new Map();
        sharedCache.set('/api/v1/public/marketplace', {
            data: res1,
            isValidating: false,
            isLoading: false,
        });
        const { result } = renderHook(() => useMarketplace(), { wrapper: createWrapper(sharedCache) });
        expect(result.current.inventoryAuthenticated).toBe(false);
        expect(result.current.inventoryMode).toBe('public_redacted');
    });

    it('Order 2: Request #1 (401/403 or public_redacted, slow) starts before Request #2 (authenticated 200, fast). Request #2 finishes first (authenticating the session), then Request #1 finishes with 401 -> hook remains authenticated with valid inventory intact', async () => {
        let rejectReq1!: (err: unknown) => void;
        const req1Promise = new Promise((_, reject) => {
            rejectReq1 = reject;
        });

        const authPayload = [
            {
                id: 'radarr',
                name: 'Radarr',
                desc: 'Movie collection manager',
                category: 'Media',
                status: 'installed',
                installed: true,
                internal_domain: 'radarr.internal',
                external_access_enabled: true,
                tls_enabled: true,
                latest_version: '5.0.0',
                installed_version: '4.9.0',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        mockApiFetch
            .mockImplementationOnce(() => req1Promise)
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'authenticated',
                    'X-Aetherflow-Inventory-Auth': 'true',
                }),
                json: async () => JSON.parse(JSON.stringify(authPayload)),
            });

        // Request #1 starts (slow)
        const p1 = fetchMarketplaceData('/api/v1/public/marketplace');

        // Request #2 starts and finishes first with 200 OK (authenticated)
        const res2 = await fetchMarketplaceData('/api/v1/public/marketplace');
        expect((res2 as unknown as Record<string, unknown>).inventory_authenticated).toBe(true);
        expect((res2 as unknown as Record<string, unknown>).inventory_mode).toBe('authenticated');

        // Transport auth is authenticated
        expect(isAuth(latestTransportAuthByEndpoint.get('/api/v1/public/marketplace'))).toBe(true);
        expect(globalRevokedAuth).toBe(false);

        // Mount hook with Request #2's authenticated data
        const sharedCache = new Map();
        sharedCache.set('/api/v1/public/marketplace', {
            data: res2,
            isValidating: false,
            isLoading: false,
        });
        const { result } = renderHook(() => useMarketplace(), { wrapper: createWrapper(sharedCache) });
        expect(result.current.inventoryAuthenticated).toBe(true);
        expect(result.current.inventoryMode).toBe('authenticated');
        expect(result.current.apps?.[0].installed).toBe(true);
        expect((result.current.apps?.[0] as unknown as Record<string, unknown>).internal_domain).toBe('radarr.internal');

        // Now Request #1 finishes later with 401 error
        const err401 = new Error('Request failed with status 401');
        (err401 as unknown as Record<string, unknown>).status = 401;
        rejectReq1(err401);

        let p1Error: unknown;
        try {
            await p1;
        } catch (err) {
            p1Error = err;
        }
        expect(p1Error).toBeDefined();
        // Request #1 error must be tagged as a stale request
        expect((p1Error as unknown as Record<string, unknown>).__staleRequest).toBe(true);

        // Transport auth MUST remain authenticated!
        expect(isAuth(latestTransportAuthByEndpoint.get('/api/v1/public/marketplace'))).toBe(true);
        expect(globalRevokedAuth).toBe(false);

        // Hook remains authenticated with valid inventory intact!
        expect(result.current.inventoryAuthenticated).toBe(true);
        expect(result.current.inventoryMode).toBe('authenticated');
        expect(result.current.apps?.[0].id).toBe('radarr');
        expect(result.current.apps?.[0].installed).toBe(true);
        expect((result.current.apps?.[0] as unknown as Record<string, unknown>).internal_domain).toBe('radarr.internal');
        expect(result.current.packages).toEqual(result.current.apps);
    });

    it('Order 2 (public_redacted 200 variant): Request #1 (slow public_redacted 200) starts before Request #2 (fast authenticated 200). Request #2 finishes first, then Request #1 finishes -> hook remains authenticated', async () => {
        let resolveReq1!: (value: unknown) => void;
        const req1Promise = new Promise(resolve => {
            resolveReq1 = resolve;
        });

        const redactedPayload = [
            {
                id: 'radarr',
                name: 'Radarr',
                desc: 'Movie collection manager',
                category: 'Media',
                status: 'not_installed',
                installed: false,
                inventory_known: false,
                inventory_authenticated: false,
                inventory_mode: 'public_redacted',
            },
        ];

        const authPayload = [
            {
                id: 'radarr',
                name: 'Radarr',
                desc: 'Movie collection manager',
                category: 'Media',
                status: 'installed',
                installed: true,
                internal_domain: 'radarr.internal',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        mockApiFetch
            .mockImplementationOnce(() => req1Promise)
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'authenticated',
                    'X-Aetherflow-Inventory-Auth': 'true',
                }),
                json: async () => JSON.parse(JSON.stringify(authPayload)),
            });

        // Request #1 starts (slow, public_redacted)
        const p1 = fetchMarketplaceData('/api/v1/public/marketplace');

        // Request #2 finishes first (authenticated)
        const res2 = await fetchMarketplaceData('/api/v1/public/marketplace');
        expect(isAuth(latestTransportAuthByEndpoint.get('/api/v1/public/marketplace'))).toBe(true);

        const sharedCache = new Map();
        sharedCache.set('/api/v1/public/marketplace', {
            data: res2,
            isValidating: false,
            isLoading: false,
        });
        const { result } = renderHook(() => useMarketplace(), { wrapper: createWrapper(sharedCache) });
        expect(result.current.inventoryAuthenticated).toBe(true);
        expect(result.current.inventoryMode).toBe('authenticated');

        // Request #1 finishes later with public_redacted 200
        resolveReq1({
            ok: true,
            status: 200,
            headers: new Headers({
                'X-Aetherflow-Inventory-Mode': 'public_redacted',
            }),
            json: async () => JSON.parse(JSON.stringify(redactedPayload)),
        });

        const res1 = await p1;
        // Stale public request does not return stale public_redacted payload; returns latest settled authenticated payload
        expect((res1 as unknown as Record<string, unknown>).inventory_mode).toBe('authenticated');
        expect(res1[0].installed).toBe(true);

        // But global and transport auth MUST remain authenticated!
        expect(isAuth(latestTransportAuthByEndpoint.get('/api/v1/public/marketplace'))).toBe(true);
        expect(globalRevokedAuth).toBe(false);

        // Hook remains authenticated with valid inventory
        expect(result.current.inventoryAuthenticated).toBe(true);
        expect(result.current.inventoryMode).toBe('authenticated');
        expect(result.current.apps?.[0].installed).toBe(true);
    });

    it('Order 2 (SWR-integrated overlapping fetches): Request #1 (slow public_redacted 200 envelope) and Request #2 (fast authenticated 200 envelope via mutate). Request #2 settles first into SWR, then Request #1 resolves inside SWR -> hook remains full authenticated', async () => {
        let resolveReq1!: (value: unknown) => void;
        const req1Promise = new Promise(resolve => {
            resolveReq1 = resolve;
        });

        const publicEnvelope = {
            packages: [
                {
                    id: 'sonarr',
                    name: 'Sonarr',
                    version: '4.0.0',
                    installed: false,
                },
            ],
            inventory_known: false,
            inventory_mode: 'public_redacted',
            inventory_authenticated: false,
        };

        const authEnvelope = {
            packages: [
                {
                    id: 'sonarr',
                    name: 'Sonarr',
                    version: '4.0.0',
                    installed: true,
                    port: 8989,
                    internal_domain: 'sonarr.local',
                },
            ],
            inventory_known: true,
            inventory_mode: 'full',
            inventory_authenticated: true,
        };

        mockApiFetch
            .mockImplementationOnce(() => req1Promise)
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'full',
                    'X-Aetherflow-Inventory-Auth': 'true',
                }),
                json: async () => JSON.parse(JSON.stringify(authEnvelope)),
            });

        const sharedCache = new Map();
        const wrapper = createWrapper(sharedCache);

        // Mount hook -> starts Request #1 inside SWR
        const { result } = renderHook(() => useMarketplace(), { wrapper });

        // Trigger Request #2 via mutate() while Request #1 is in flight
        let mutatePromise: Promise<unknown>;
        act(() => {
            mutatePromise = result.current.mutate();
        });

        // Request #2 finishes first (authenticated)
        await act(async () => {
            await mutatePromise;
        });

        expect(result.current.inventoryAuthenticated).toBe(true);
        expect(result.current.inventoryKnown).toBe(true);
        expect(result.current.inventoryMode).toBe('full');
        expect(result.current.packages?.[0].port).toBe(8989);

        // Request #1 finishes later with public_redacted 200 inside SWR
        await act(async () => {
            resolveReq1({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'public_redacted',
                }),
                json: async () => JSON.parse(JSON.stringify(publicEnvelope)),
            });
            await new Promise(r => setTimeout(r, 50));
        });

        // Hook STILL reports full authenticated inventory!
        await waitFor(() => {
            expect(result.current.inventoryKnown).toBe(true);
            expect(result.current.inventoryMode).toBe('full');
            expect(result.current.inventoryAuthenticated).toBe(true);
            expect(result.current.packages?.[0].port).toBe(8989);
        });
    });

    it('P2: Request #2 (fast 500 transport failure) does not suppress Request #1 (slow 403 Forbidden) revocation', async () => {
        // Seed authenticated inventory (port: 8989, internal_domain: 'sonarr.local')
        const seededInventory = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                category: 'Media',
                status: 'installed',
                installed: true,
                port: 8989,
                internal_domain: 'sonarr.local',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        mockApiFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            headers: new Headers({
                'X-Aetherflow-Inventory-Mode': 'authenticated',
                'X-Aetherflow-Inventory-Auth': 'true',
            }),
            json: async () => JSON.parse(JSON.stringify(seededInventory)),
        });

        const sharedCache = new Map();
        const wrapper = createWrapper(sharedCache);
        const { result } = renderHook(() => useMarketplace(), { wrapper });

        await waitFor(() => {
            expect(result.current.isLoading).toBe(false);
            expect(result.current.inventoryAuthenticated).toBe(true);
            expect(result.current.inventoryMode).toBe('authenticated');
            expect(result.current.apps?.[0].port).toBe(8989);
            expect(result.current.apps?.[0].internal_domain).toBe('sonarr.local');
        });

        // Set up Request #1 (slow 403 Forbidden) and Request #2 (fast 500 Internal Server Error)
        let rejectReq1!: (err: unknown) => void;
        const req1Promise = new Promise((_, reject) => {
            rejectReq1 = reject;
        });

        mockApiFetch
            .mockImplementationOnce(() => req1Promise)
            .mockResolvedValueOnce({
                ok: false,
                status: 500,
                headers: new Headers(),
                json: async () => ({ message: 'Internal Server Error' }),
            });

        // Start Request #1 (slow)
        const p1 = fetchMarketplaceData('/api/v1/public/marketplace');

        // Start Request #2 (fast 500)
        let p2Error: unknown;
        try {
            await fetchMarketplaceData('/api/v1/public/marketplace');
        } catch (err) {
            p2Error = err;
        }
        expect(p2Error).toBeDefined();
        expect((p2Error as unknown as Record<string, unknown>)?.status).toBe(500);

        // Before Request #1 finishes, auth remains authenticated (500 must not revoke or advance authoritative auth seq)
        expect(isAuth(latestTransportAuthByEndpoint.get('/api/v1/public/marketplace'))).toBe(true);
        expect(globalRevokedAuth).toBe(false);

        // Now Request #1 finishes with 403 Forbidden
        let p1Error: unknown;
        await act(async () => {
            const err403 = new Error('Request failed with status 403');
            (err403 as unknown as Record<string, unknown>).status = 403;
            rejectReq1(err403);
            try {
                await p1;
            } catch (err) {
                p1Error = err;
            }
        });
        expect(p1Error).toBeDefined();
        // Assert that Request #1's 403 is NOT suppressed as stale!
        expect((p1Error as unknown as Record<string, unknown>)?.__staleRequest).toBeUndefined();

        // Assert that global/transport auth transitions to public_redacted
        expect(globalRevokedAuth).toBe(true);
        expect(isPublicRedacted(latestTransportAuthByEndpoint.get('/api/v1/public/marketplace'))).toBe(true);

        // Wait for hook to update and reflect revocation
        await waitFor(() => {
            expect(result.current.inventoryAuthenticated).toBe(false);
            expect(result.current.inventoryMode).toBe('public_redacted');
        });

        // Assert cached private inventory is scrubbed in-place
        expect(result.current.apps?.[0].installed).toBe(false);
        expect(result.current.apps?.[0].port).toBeUndefined();
        expect(result.current.apps?.[0].internal_domain).toBeUndefined();

        // SWR cached item is also scrubbed in-place
        const cachedRaw = sharedCache.get('/api/v1/public/marketplace') as unknown as Record<string, unknown>;
        const cachedItem = Array.isArray(cachedRaw)
            ? cachedRaw[0]
            : (Array.isArray(cachedRaw?.data) ? cachedRaw.data[0] : undefined);
        if (cachedItem) {
            expect(cachedItem.port).toBeUndefined();
            expect(cachedItem.internal_domain).toBeUndefined();
            expect(cachedItem.installed).toBe(false);
        }
    });

    it('P3: Request #2 (fast 200 with port: 9090) settles first, then Request #1 (slow 200 with port: 8989) settles -> returns newer settled inventory (port: 9090), never reverting to 8989', async () => {
        let resolveReq1!: (value: unknown) => void;
        const req1Promise = new Promise(resolve => {
            resolveReq1 = resolve;
        });

        const olderPayload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                category: 'Media',
                status: 'installed',
                installed: true,
                port: 8989,
                internal_domain: 'sonarr.local',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        const newerPayload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                category: 'Media',
                status: 'installed',
                installed: true,
                port: 9090,
                internal_domain: 'sonarr.local',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        mockApiFetch
            .mockImplementationOnce(() => req1Promise)
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'authenticated',
                    'X-Aetherflow-Inventory-Auth': 'true',
                }),
                json: async () => JSON.parse(JSON.stringify(newerPayload)),
            });

        // Start Request #1 (slow authenticated 200 with port: 8989)
        const p1 = fetchMarketplaceData('/api/v1/public/marketplace');

        // Start Request #2 (fast authenticated 200 with port: 9090)
        const p2 = fetchMarketplaceData('/api/v1/public/marketplace');

        // Request #2 settles first with port: 9090
        const res2 = await p2;
        expect((res2 as Array<Record<string, unknown>>)[0].port).toBe(9090);

        // Mount useMarketplace with SWR cache initialized with Request #2's settled data
        const sharedCache = new Map();
        sharedCache.set('/api/v1/public/marketplace', {
            data: res2,
            isValidating: false,
            isLoading: false,
        });
        const { result, rerender } = renderHook(() => useMarketplace(), { wrapper: createWrapper(sharedCache) });
        expect(result.current.inventoryAuthenticated).toBe(true);
        expect(result.current.inventoryMode).toBe('authenticated');
        expect(result.current.apps?.[0].port).toBe(9090);

        // Now Request #1 settles with older port: 8989
        resolveReq1({
            ok: true,
            status: 200,
            headers: new Headers({
                'X-Aetherflow-Inventory-Mode': 'authenticated',
                'X-Aetherflow-Inventory-Auth': 'true',
            }),
            json: async () => JSON.parse(JSON.stringify(olderPayload)),
        });

        // Assert fetchMarketplaceData for Request #1 returns the newer settled inventory (port: 9090)
        const res1 = await p1;
        expect((res1 as Array<Record<string, unknown>>)[0].port).toBe(9090);

        // Even if SWR cache receives res1 (or a stale payload marked with __staleRequest)
        sharedCache.set('/api/v1/public/marketplace', {
            data: res1,
            isValidating: false,
            isLoading: false,
        });
        rerender();

        // Assert hook returns newer settled inventory (port: 9090), never reverting to 8989
        expect(result.current.inventoryAuthenticated).toBe(true);
        expect(result.current.apps?.[0].port).toBe(9090);
        expect(result.current.packages?.[0].port).toBe(9090);
    });

    it('Regression Test 1: Callback Sequence Race: 401 -> in-flight 200 -> 500', async () => {
        let rejectReq1!: (err: unknown) => void;
        const req1Promise = new Promise((_, reject) => {
            rejectReq1 = reject;
        });

        let resolveReq2!: (value: unknown) => void;
        const req2Promise = new Promise(resolve => {
            resolveReq2 = resolve;
        });

        let rejectReq3!: (err: unknown) => void;
        const req3Promise = new Promise((_, reject) => {
            rejectReq3 = reject;
        });

        mockApiFetch
            .mockImplementationOnce(() => req1Promise)
            .mockImplementationOnce(() => req2Promise)
            .mockImplementationOnce(() => req3Promise);

        // Mount useMarketplace hook -> SWR initiates Request #1 (seq = 1, will fail with 401)
        const sharedCache = new Map();
        const { result, rerender } = renderHook(() => useMarketplace(), { wrapper: createWrapper(sharedCache) });

        // Start Request #2 (seq = 2, succeeds with authenticated 200 port: 8989)
        const p2 = fetchMarketplaceData('/api/v1/public/marketplace');

        // Start Request #3 (seq = 3, fails with 500)
        const p3 = fetchMarketplaceData('/api/v1/public/marketplace');

        expect(globalRequestSeq).toBe(3);

        // 1. Settle Request #1 first (401, triggering onError)
        const err401 = new Error('Request failed with status 401');
        (err401 as unknown as Record<string, unknown>).status = 401;
        await act(async () => {
            rejectReq1(err401);
            await new Promise(r => setTimeout(r, 20));
        });

        // Request #1's 401 set authoritative auth seq to 1 (NEVER globalRequestSeq = 3!)
        expect(latestAuthoritativeAuthSeq).toBe(1);
        expect(globalRevokedAuth).toBe(true);

        // 2. Settle Request #3 next (500, triggering onError)
        let p3Error: unknown;
        const err500 = new Error('Request failed with status 500');
        (err500 as unknown as Record<string, unknown>).status = 500;
        rejectReq3(err500);
        try {
            await p3;
        } catch (err) {
            p3Error = err;
        }
        expect(p3Error).toBeDefined();
        expect((p3Error as unknown as Record<string, unknown>).__requestSeq).toBe(3);

        // Trigger onError callback for Request #3
        act(() => {
            lastSwrOptions?.onError?.(p3Error, '/api/v1/public/marketplace');
        });

        // 500 error must NOT advance latestAuthoritativeAuthSeq (remains 1)
        expect(latestAuthoritativeAuthSeq).toBe(1);

        // 3. Settle Request #2 (authenticated 200 with port: 8989, triggering onSuccess)
        const authPayload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                category: 'Media',
                status: 'installed',
                installed: true,
                port: 8989,
                internal_domain: 'sonarr.local',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        let res2: unknown;
        await act(async () => {
            resolveReq2({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'authenticated',
                    'X-Aetherflow-Inventory-Auth': 'true',
                }),
                json: async () => JSON.parse(JSON.stringify(authPayload)),
            });
            res2 = await p2;
        });
        // Assert Request #2 (seq = 2 > 1) is NOT treated as stale!
        expect((res2 as unknown as Record<string, unknown>).__requestSeq).toBe(2);
        expect((res2 as unknown as Record<string, unknown>).__staleRequest).toBeUndefined();

        // Assert latestAuthoritativeAuthSeq is recognized as 2
        expect(latestAuthoritativeAuthSeq).toBe(2);
        expect(globalRevokedAuth).toBe(false);

        // Trigger SWR onSuccess callback for Request #2 and update sharedCache
        act(() => {
            lastSwrOptions?.onSuccess?.(res2, '/api/v1/public/marketplace');
            sharedCache.set('/api/v1/public/marketplace', {
                data: res2,
                isValidating: false,
                isLoading: false,
            });
        });
        rerender();

        // Assert hook transitions to 'authenticated' with full inventory (port: 8989)
        expect(result.current.inventoryAuthenticated).toBe(true);
        expect(result.current.inventoryMode).toBe('authenticated');
        expect(result.current.apps?.[0].port).toBe(8989);
        expect(result.current.apps?.[0].installed).toBe(true);
        expect(result.current.packages?.[0].port).toBe(8989);
    });

    it('Regression Test 2: Query-Specific Stale Payload Race', async () => {
        // 1. Settle an initial request to /v1/marketplace/packages?filter=all with port: 8000
        const initialPayload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                category: 'Media',
                status: 'installed',
                installed: true,
                port: 8000,
                internal_domain: 'sonarr.local',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        mockApiFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            headers: new Headers({
                'X-Aetherflow-Inventory-Mode': 'authenticated',
                'X-Aetherflow-Inventory-Auth': 'true',
            }),
            json: async () => JSON.parse(JSON.stringify(initialPayload)),
        });

        const resInit = await fetchMarketplaceData('/v1/marketplace/packages?filter=all');
        expect((resInit as Array<Record<string, unknown>>)[0].port).toBe(8000);

        // 2. Start slow Request #1 to /v1/marketplace/packages?filter=all (port: 8111)
        // and fast Request #2 to /v1/marketplace/packages (port: 9090)
        let resolveReq1!: (value: unknown) => void;
        const req1Promise = new Promise(resolve => {
            resolveReq1 = resolve;
        });

        const req1Payload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                category: 'Media',
                status: 'installed',
                installed: true,
                port: 8111,
                internal_domain: 'sonarr.local',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        const req2Payload = [
            {
                id: 'sonarr',
                name: 'Sonarr',
                category: 'Media',
                status: 'installed',
                installed: true,
                port: 9090,
                internal_domain: 'sonarr.local',
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];

        mockApiFetch
            .mockImplementationOnce(() => req1Promise)
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                headers: new Headers({
                    'X-Aetherflow-Inventory-Mode': 'authenticated',
                    'X-Aetherflow-Inventory-Auth': 'true',
                }),
                json: async () => JSON.parse(JSON.stringify(req2Payload)),
            });

        // Start slow Request #1 to /v1/marketplace/packages?filter=all
        const p1 = fetchMarketplaceData('/v1/marketplace/packages?filter=all');

        // Fast Request #2 to /v1/marketplace/packages
        const p2 = fetchMarketplaceData('/v1/marketplace/packages');

        // 3. Settle Request #2 first (port: 9090), then settle Request #1
        const res2 = await p2;
        expect((res2 as Array<Record<string, unknown>>)[0].port).toBe(9090);

        // Now settle Request #1 (slow, port: 8111)
        resolveReq1({
            ok: true,
            status: 200,
            headers: new Headers({
                'X-Aetherflow-Inventory-Mode': 'authenticated',
                'X-Aetherflow-Inventory-Auth': 'true',
            }),
            json: async () => JSON.parse(JSON.stringify(req1Payload)),
        });

        const res1 = await p1;

        // 4. Assert that Request #1 returns the newest settled payload (port: 9090),
        // never the older query-specific cache entry (8000 or 8111)!
        expect((res1 as Array<Record<string, unknown>>)[0].port).toBe(9090);
        expect((res1 as Array<Record<string, unknown>>)[0].port).not.toBe(8000);
        expect((res1 as Array<Record<string, unknown>>)[0].port).not.toBe(8111);
    });
});

describe('Category 5 P1: isAuthFailureError classification and transient error handling', () => {
    beforeEach(() => {
        useRealSwr = true;
        latestTransportAuthByEndpoint.clear();
        mockApiFetch.mockReset();
    });

    afterEach(() => {
        useRealSwr = false;
        latestTransportAuthByEndpoint.clear();
        mockApiFetch.mockReset();
    });

    const createWrapper = (customCache?: Map<unknown, unknown>) => {
        const cache = customCache ?? new Map();
        return function TestSwrWrapper({ children }: { children: React.ReactNode }) {
            return React.createElement(
                SWRConfig,
                { value: { provider: () => cache, dedupingInterval: 0 } },
                children
            );
        };
    };

    it('returns false for explicit non-auth status codes even when error message mentions 401 or 403', () => {
        expect(isAuthFailureError({ status: 500, message: 'HTTP 401 upstream' })).toBe(false);
        expect(isAuthFailureError({ statusCode: 502, message: 'Unauthorized upstream' })).toBe(false);
        expect(isAuthFailureError({ response: { status: 503 }, message: '403' })).toBe(false);
        expect(isAuthFailureError({ status: '500', message: 'HTTP 401 upstream' })).toBe(false);
    });

    it('returns false for incidental numbers like 401 ms on worker 403 when no numeric status is present', () => {
        expect(isAuthFailureError(new Error('Timed out after 401 ms on worker 403'))).toBe(false);
        expect(isAuthFailureError(new Error('Line 403 syntax error'))).toBe(false);
        expect(isAuthFailureError('Request timed out after 401 ms')).toBe(false);
        expect(isAuthFailureError('Job 403 failed')).toBe(false);
    });

    it('returns true for 401/403 status codes and genuine auth error messages', () => {
        expect(isAuthFailureError({ status: 401 })).toBe(true);
        expect(isAuthFailureError({ status: 403 })).toBe(true);
        expect(isAuthFailureError({ statusCode: 401 })).toBe(true);
        expect(isAuthFailureError({ response: { status: 403 } })).toBe(true);
        expect(isAuthFailureError({ status: '401' })).toBe(true);
        expect(isAuthFailureError({ statusCode: '403' })).toBe(true);
        expect(isAuthFailureError(new Error('HTTP 401'))).toBe(true);
        expect(isAuthFailureError(new Error('Status: 403'))).toBe(true);
        expect(isAuthFailureError(new Error('Unauthorized'))).toBe(true);
        expect(isAuthFailureError(new Error('Forbidden'))).toBe(true);
        expect(isAuthFailureError('401')).toBe(true);
        expect(isAuthFailureError('403')).toBe(true);
        expect(isAuthFailureError('unauthorized')).toBe(true);
        expect(isAuthFailureError('forbidden')).toBe(true);
    });

    it('hook behavior test: fetch failure with { status: 500, message: "Error 401 in worker" } does NOT downgrade viewerAuthMode to public_redacted or scrub cached authenticated package fields', async () => {
        const seededPackage = {
            id: 'sonarr',
            name: 'Sonarr',
            desc: 'Smart PVR',
            category: 'Media',
            status: 'installed',
            installed: true,
            latest_version: '3.1.0',
            installed_version: '3.0.0',
            port: 8989,
            internal_domain: 'sonarr.internal',
            external_access_enabled: true,
            tls_enabled: true,
            inventory_known: true,
            inventory_authenticated: true,
            inventory_mode: 'authenticated',
        };

        mockApiFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            headers: new Headers({
                'X-Aetherflow-Inventory-Mode': 'authenticated',
                'X-Aetherflow-Inventory-Auth': 'true',
            }),
            json: async () => [JSON.parse(JSON.stringify(seededPackage))],
        });

        const sharedCache = new Map();
        const wrapper = createWrapper(sharedCache);
        const { result } = renderHook(() => useMarketplace(), { wrapper });

        await waitFor(() => {
            expect(result.current.isLoading).toBe(false);
            expect(result.current.inventoryAuthenticated).toBe(true);
            expect(result.current.inventoryMode).toBe('authenticated');
            expect(result.current.apps?.[0].installed).toBe(true);
            expect(result.current.apps?.[0].port).toBe(8989);
            expect((result.current.apps?.[0] as unknown as Record<string, unknown>).internal_domain).toBe('sonarr.internal');
        });

        // Transient 500 error whose message mentions 401
        const transient500Error = Object.assign(new Error('Error 401 in worker'), {
            status: 500,
        });
        mockApiFetch.mockRejectedValueOnce(transient500Error);

        await act(async () => {
            try {
                await result.current.mutate();
            } catch {
                // SWR mutate re-throws error
            }
        });

        await waitFor(() => {
            expect(result.current.isError).toBe(true);
        });

        // Auth mode MUST NOT be downgraded to public_redacted
        expect(result.current.inventoryAuthenticated).toBe(true);
        expect(result.current.inventoryMode).toBe('authenticated');
        expect(result.current.inventoryMode).not.toBe('public_redacted');

        // Global and transport auth remain untouched
        expect(globalRevokedAuth).toBe(false);
        const transportAuth = latestTransportAuthByEndpoint.get('/api/v1/public/marketplace');
        const isAuthEntry =
            transportAuth === 'authenticated' ||
            (typeof transportAuth === 'object' && transportAuth?.mode === 'authenticated' && transportAuth?.authenticated);
        expect(isAuthEntry).toBe(true);

        // Cached package fields must NOT be scrubbed
        const pkg = result.current.apps?.[0];
        expect(pkg).toBeDefined();
        expect(pkg?.installed).toBe(true);
        expect(pkg?.status).toBe('installed');
        expect(pkg?.port).toBe(8989);
        expect((pkg as unknown as Record<string, unknown>)?.internal_domain).toBe('sonarr.internal');
        expect(pkg?.installed_version).toBe('3.0.0');
        expect(pkg?.latest_version).toBe('3.1.0');
        expect(result.current.packages).toEqual(result.current.apps);
    });

    it('verifies that fetchMarketplaceData with HTTP 500 status does not revoke transport auth', async () => {
        mockApiFetch.mockResolvedValueOnce({
            ok: false,
            status: 500,
            headers: new Headers(),
            json: async () => ({ message: 'Error 401 in worker' }),
        });

        let err: unknown;
        try {
            await fetchMarketplaceData('/api/v1/public/marketplace');
        } catch (e) {
            err = e;
        }
        expect(err).toBeDefined();
        expect(globalRevokedAuth).toBe(false);
        expect(latestTransportAuthByEndpoint.get('/api/v1/public/marketplace')).toBeUndefined();
    });
});
