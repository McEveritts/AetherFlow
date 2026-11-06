import React from 'react';
import { act, render } from '@testing-library/react';
import useSWR, { SWRConfig } from 'swr';
import { isTransientLifecycleError, useLifecyclePollRecovery } from './useLifecyclePollRecovery';

function Probe() {
    const state = useSWR('/fixture/lifecycle', { shouldRetryOnError: false });
    useLifecyclePollRecovery('/fixture/lifecycle', state.error, () => state.mutate());
    return <span>{state.data || 'unknown'}</span>;
}

beforeEach(() => { jest.useFakeTimers(); });
afterEach(() => { jest.useRealTimers(); });

it('shares slow retries, survives the initiating subscriber unmount, and stops after the last unmount', async () => {
    let offline = true;
    const fetcher = jest.fn(async () => {
        if (offline) throw new Error('offline');
        return 'recovered';
    });
    const cache = new Map();
    const config = { provider: () => cache, fetcher, dedupingInterval: 5000, revalidateOnFocus: false };
    const tree = (first: boolean) => <SWRConfig value={config}>{first && <Probe key="first" />}<Probe key="second" /></SWRConfig>;
    const view = render(tree(true));
    await act(async () => { await jest.advanceTimersByTimeAsync(100); });
    expect(fetcher).toHaveBeenCalledTimes(1);
    await act(async () => { await jest.advanceTimersByTimeAsync(60000); });
    expect(fetcher).toHaveBeenCalledTimes(5);
    view.rerender(tree(false));
    offline = false;
    await act(async () => { await jest.advanceTimersByTimeAsync(15000); });
    expect(view.getByText('recovered')).toBeInTheDocument();
    expect(fetcher).toHaveBeenCalledTimes(6);
    offline = true;
    view.unmount();
    await act(async () => { await jest.advanceTimersByTimeAsync(60000); });
    expect(fetcher).toHaveBeenCalledTimes(6);
    expect(jest.getTimerCount()).toBe(0);
});

it.each([401, 403, 404])('does not automatically retry a non-transient HTTP %s', async status => {
    const fetcher = jest.fn(async () => { throw Object.assign(new Error('rejected'), { status }); });
    const view = render(<SWRConfig value={{ provider: () => new Map(), fetcher }}><Probe /></SWRConfig>);
    await act(async () => { await jest.advanceTimersByTimeAsync(90000); });
    expect(fetcher).toHaveBeenCalledTimes(1);
    view.unmount();
    await act(async () => { await jest.advanceTimersByTimeAsync(15000); });
    expect(jest.getTimerCount()).toBe(0);
});

it.each([408, 429, 500, 502, 503, 599])('classifies transient HTTP %s consistently', status => {
    expect(isTransientLifecycleError(Object.assign(new Error('unavailable'), { status }))).toBe(true);
});

it.each([200, 400, 401, 403, 404, 409, 422, 600])('does not recover permanent or malformed HTTP %s automatically', status => {
    expect(isTransientLifecycleError(Object.assign(new Error('rejected'), { status }))).toBe(false);
});

it('recovers transport failures, but not missing errors', () => {
    expect(isTransientLifecycleError(new TypeError('Network error'))).toBe(true);
    expect(isTransientLifecycleError(undefined)).toBe(false);
    expect(isTransientLifecycleError(null)).toBe(false);
});
