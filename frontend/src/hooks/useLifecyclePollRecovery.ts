import { useEffect, useRef } from 'react';
import { useSWRConfig } from 'swr';

export const LIFECYCLE_RECOVERY_INTERVAL_MS = 15000;
type Revalidate = () => Promise<unknown>;
interface Recovery {
    subscribers: Set<Revalidate>;
    timer?: ReturnType<typeof setTimeout>;
}
// One slow recovery request per SWR cache/key, including shared subscribers.
const recoveries = new WeakMap<object, Map<string, Recovery>>();

export function isTransientLifecycleError(error: unknown): boolean {
    const status = (error as { status?: number } | undefined)?.status;
    return Boolean(error) && (status === undefined || (status >= 500 && status < 600) || status === 408 || status === 429);
}

export function useLifecyclePollRecovery(
    key: string, error: unknown, revalidate: Revalidate, intervalMs = LIFECYCLE_RECOVERY_INTERVAL_MS,
) {
    const { cache } = useSWRConfig();
    const latestRevalidate = useRef(revalidate);
    useEffect(() => { latestRevalidate.current = revalidate; }, [revalidate]);
    const recover = isTransientLifecycleError(error);

    useEffect(() => {
        if (!recover) return;
        let byKey = recoveries.get(cache);
        if (!byKey) {
            byKey = new Map();
            recoveries.set(cache, byKey);
        }
        let recovery = byKey.get(key);
        if (!recovery) {
            recovery = { subscribers: new Set() };
            byKey.set(key, recovery);
            const state = recovery;
            const schedule = () => {
                state.timer = setTimeout(async () => {
                    const subscriber = state.subscribers.values().next().value;
                    if (!subscriber) return;
                    try { await subscriber(); } catch { /* SWR retains the fetch error. */ }
                    if (state.subscribers.size) schedule();
                }, intervalMs);
            };
            schedule();
        }
        const subscriber = () => latestRevalidate.current();
        recovery.subscribers.add(subscriber);
        return () => {
            recovery.subscribers.delete(subscriber);
            if (!recovery.subscribers.size) {
                clearTimeout(recovery.timer);
                byKey.delete(key);
            }
        };
    }, [cache, key, recover, intervalMs]);
}
