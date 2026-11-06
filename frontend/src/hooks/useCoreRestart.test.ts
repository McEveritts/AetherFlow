import { act, renderHook } from '@testing-library/react';
import { apiFetch } from '@/lib/fetcher';
import { CORE_RESTART_TIMEOUT_MS, useCoreRestart } from './useCoreRestart';

jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
const request = jest.mocked(apiFetch);
const unit = 'aetherflow-self-update-restart-aetherflow-api-12345678.service';
const response = (payload: unknown, ok = true) => ({ ok, json: async () => payload }) as Response;
const ready = { service: 'aetherflow-api', status: 'ready', database: 'ok' };

describe('core restart receipt and readiness tracking', () => {
    beforeEach(() => { jest.useFakeTimers(); request.mockReset(); });
    afterEach(() => { jest.useRealTimers(); });

    it('requires its terminal receipt before checking a fresh API response, recovering through disappearance', async () => {
        const notify = jest.fn();
        request.mockRejectedValueOnce(new Error('API offline'))
            .mockResolvedValueOnce(response({ job_unit: unit, status: 'running', completed: false, success: false }))
            .mockResolvedValueOnce(response({ job_unit: unit, status: 'succeeded', completed: true, success: true }))
            .mockResolvedValueOnce(response({}, false))
            .mockResolvedValueOnce(response({ job_unit: unit, status: 'succeeded', completed: true, success: true }))
            .mockResolvedValueOnce(response(ready));
        const { result, unmount } = renderHook(() => useCoreRestart(notify));
        act(() => result.current.trackRestart('API', { job_unit: unit }));
        await act(async () => { await jest.advanceTimersByTimeAsync(2000); });
        await act(async () => { await jest.advanceTimersByTimeAsync(1500); });
        expect(request.mock.calls.some(([url]) => url === '/api/v1/auth/ready')).toBe(false);
        expect(notify.mock.calls.some(([, kind]) => kind === 'success')).toBe(false);
        await act(async () => { await jest.advanceTimersByTimeAsync(1500); });
        expect(result.current.restarts.has('API')).toBe(true);
        await act(async () => { await jest.advanceTimersByTimeAsync(1500); });
        expect(notify).toHaveBeenCalledWith(expect.stringContaining('API readiness confirmed'), 'success');
        expect(result.current.restarts.size).toBe(0);
        expect(request.mock.calls.some(([url]) => url === '/api/v1/auth/services')).toBe(false);
        expect(request).toHaveBeenCalledWith('/api/v1/auth/ready', expect.objectContaining({ cache: 'no-store', signal: expect.any(AbortSignal) }));
        unmount(); expect(jest.getTimerCount()).toBe(0);
    });

    it.each([null, {}, [], { status: 'ready', database: 'ok' }, { ...ready, database: 'unreachable' }, { ...ready, status: 'not_ready' }, { ...ready, service: 'another-api' }])('rejects malformed or unready readiness payload %j', async payload => {
        const notify = jest.fn();
        request.mockImplementation(async url => response(url === '/api/v1/auth/ready' ? payload : { job_unit: unit, status: 'succeeded', completed: true, success: true }));
        const { result, unmount } = renderHook(() => useCoreRestart(notify));
        act(() => result.current.trackRestart('API', { job_unit: unit }));
        await act(async () => { await jest.advanceTimersByTimeAsync(2000); });
        expect(result.current.restarts.has('API')).toBe(true);
        expect(notify.mock.calls.some(([, kind]) => kind === 'success')).toBe(false);
        unmount(); expect(jest.getTimerCount()).toBe(0);
    });

    it('keeps the request deadline through readiness body parsing and cleans up at the overall deadline', async () => {
        const notify = jest.fn();
        request.mockResolvedValueOnce(response({ job_unit: unit, status: 'succeeded', completed: true, success: true }))
            .mockResolvedValueOnce({ ok: true, json: () => new Promise(() => {}) } as Response);
        const { result, unmount } = renderHook(() => useCoreRestart(notify));
        act(() => result.current.trackRestart('API', { job_unit: unit }));
        await act(async () => { await jest.advanceTimersByTimeAsync(2000); });
        const signal = request.mock.calls[1][1]?.signal;
        expect(signal?.aborted).toBe(false);
        await act(async () => { await jest.advanceTimersByTimeAsync(8000); });
        expect(signal?.aborted).toBe(true);
        await act(async () => { await jest.advanceTimersByTimeAsync(CORE_RESTART_TIMEOUT_MS); });
        expect(notify).toHaveBeenCalledWith(expect.stringContaining('could not be confirmed'), 'error');
        expect(result.current.restarts.size).toBe(0);
        unmount(); expect(jest.getTimerCount()).toBe(0);
    });

    it.each(['failed', 'unknown', 'foreign'])('never invents success for %s status', async variant => {
        const notify = jest.fn();
        request.mockResolvedValue(response({ job_unit: variant === 'foreign' ? 'different' : unit, status: variant, completed: variant === 'failed', success: false, error: 'activation failed' }));
        const { result, unmount } = renderHook(() => useCoreRestart(notify));
        act(() => result.current.trackRestart('API', { job_unit: unit }));
        await act(async () => { await jest.advanceTimersByTimeAsync(2000); });
        if (variant !== 'failed') await act(async () => { await jest.advanceTimersByTimeAsync(CORE_RESTART_TIMEOUT_MS); });
        expect(notify).toHaveBeenCalledWith(expect.stringContaining(variant === 'failed' ? 'activation failed' : 'could not be confirmed'), 'error');
        expect(notify.mock.calls.some(([, kind]) => kind === 'success')).toBe(false);
        expect(result.current.restarts.size).toBe(0);
        unmount(); expect(jest.getTimerCount()).toBe(0);
    });

    it.each([
        { job_unit: 'foreign', status: 'succeeded', completed: true, success: true },
        { job_unit: unit, status: 'running', completed: true, success: true },
        { job_unit: unit, status: 'succeeded', completed: false, success: true },
        { job_unit: unit, status: 'succeeded', completed: true, success: 'true' },
        null,
    ])('never checks readiness without a matching successful receipt %j', async receipt => {
        const notify = jest.fn();
        request.mockResolvedValue(response(receipt));
        const { result, unmount } = renderHook(() => useCoreRestart(notify));
        act(() => result.current.trackRestart('API', { job_unit: unit }));
        await act(async () => { await jest.advanceTimersByTimeAsync(2000); });
        expect(request).toHaveBeenCalledTimes(1);
        expect(result.current.restarts.has('API')).toBe(true);
        expect(notify.mock.calls.some(([, kind]) => kind === 'success')).toBe(false);
        unmount(); expect(jest.getTimerCount()).toBe(0);
    });

    it('retries after a readiness body times out and confirms only a later valid response', async () => {
        const notify = jest.fn();
        const receipt = { job_unit: unit, status: 'succeeded', completed: true, success: true };
        request.mockResolvedValueOnce(response(receipt)).mockImplementationOnce(async (_url, options) => ({
            ok: true,
            json: () => new Promise((_resolve, reject) => {
                options?.signal?.addEventListener('abort', () => reject(new Error('body aborted')), { once: true });
            }),
        } as Response)).mockResolvedValueOnce(response(receipt)).mockResolvedValueOnce(response(ready));
        const { result, unmount } = renderHook(() => useCoreRestart(notify));
        act(() => result.current.trackRestart('API', { job_unit: unit }));
        await act(async () => { await jest.advanceTimersByTimeAsync(10000); });
        expect(request.mock.calls[1][1]?.signal?.aborted).toBe(true);
        expect(notify.mock.calls.some(([, kind]) => kind === 'success')).toBe(false);
        await act(async () => { await jest.advanceTimersByTimeAsync(1500); });
        expect(notify).toHaveBeenCalledWith(expect.stringContaining('API readiness confirmed'), 'success');
        expect(result.current.restarts.size).toBe(0);
        unmount(); expect(jest.getTimerCount()).toBe(0);
    });

    it('does not begin readiness when an aborted receipt request resolves after unmount', async () => {
        let resolveReceipt!: (value: Response) => void;
        request.mockReturnValue(new Promise<Response>(resolve => { resolveReceipt = resolve; }));
        const notify = jest.fn();
        const { result, unmount } = renderHook(() => useCoreRestart(notify));
        act(() => result.current.trackRestart('API', { job_unit: unit }));
        await act(async () => { await jest.advanceTimersByTimeAsync(2000); });
        unmount();
        expect(jest.getTimerCount()).toBe(0);
        await act(async () => {
            resolveReceipt(response({ job_unit: unit, status: 'succeeded', completed: true, success: true }));
            await jest.advanceTimersByTimeAsync(0);
        });
        expect(request).toHaveBeenCalledTimes(1);
        expect(notify.mock.calls.some(([, kind]) => kind === 'success')).toBe(false);
        expect(jest.getTimerCount()).toBe(0);
    });

    it('rejects a missing identity and cancels pending work on unmount', () => {
        const { result, unmount } = renderHook(() => useCoreRestart(jest.fn()));
        expect(() => result.current.trackRestart('API', {})).toThrow('receipt identity');
        act(() => result.current.trackRestart('API', { job_unit: unit }));
        unmount(); expect(jest.getTimerCount()).toBe(0);
    });

    it('aborts an in-flight status request and all timers when unmounted', async () => {
        request.mockReturnValue(new Promise<Response>(() => {}));
        const notify = jest.fn();
        const { result, unmount } = renderHook(() => useCoreRestart(notify));
        act(() => result.current.trackRestart('API', { job_unit: unit }));
        await act(async () => { await jest.advanceTimersByTimeAsync(2000); });
        const signal = request.mock.calls[0][1]?.signal;
        expect(signal?.aborted).toBe(false);
        unmount();
        expect(signal?.aborted).toBe(true);
        expect(jest.getTimerCount()).toBe(0);
    });
});
