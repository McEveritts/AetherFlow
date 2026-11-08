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
import { act, renderHook } from '@testing-library/react';
import { useMarketplace, App, lifecycleIdentity, matchingJobOutcome, LIFECYCLE_RECEIPT_TIMEOUT_MS } from './useMarketplace';

let mockApps: App[] = [];
let mockError: Error | undefined;
let mockIsValidating = false;
let mockOptions: { refreshInterval: (apps?: App[]) => number; onSuccess: (apps: App[]) => void };
jest.mock('swr', () => ({
    ...jest.requireActual('swr'),
    __esModule: true,
    default: (_key: string, options: typeof mockOptions) => {
        mockOptions = options;
        return { data: mockApps, error: mockError, isValidating: mockIsValidating, mutate: jest.fn(), isLoading: false };
    },
}));

const fixtureApp = (extra: Partial<App> = {}): App => ({
    id: 'fixture', name: 'Fixture', desc: '', hits: 0, category: 'Media', status: 'installed', progress: 0, update_available: false, ...extra,
});

describe('useMarketplace identity matching', () => {
    beforeEach(() => { mockApps = [fixtureApp()]; mockError = undefined; mockIsValidating = false; });
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
        mockApps = variant === 'missing' ? [] : [fixtureApp({ last_job: { job_id: 'client-B', action: 'update', status: 'completed', started_at: 'later', finished_at: 'later' } })];
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
