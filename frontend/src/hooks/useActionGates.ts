import useSWR from 'swr';
import { useCallback } from 'react';
import { apiFetch } from '@/lib/fetcher';
import type { PendingAction, PendingActionsResponse, ActionStatus } from '@/types/api';

const ACTIONS_KEY = '/api/v1/admin/actions/pending';

/**
 * SWR hook for the action approval gate system.
 * Fetches pending actions with automatic polling and provides
 * typed approve/reject mutation helpers.
 */
export function useActionGates(options?: {
    /** Filter by action status. Defaults to 'pending'. */
    status?: ActionStatus | 'all';
    /** Auto-refresh interval in ms. 0 to disable. Default: 10000 (10s). */
    refreshInterval?: number;
}) {
    const status = options?.status ?? 'pending';
    const refreshInterval = options?.refreshInterval ?? 10_000;

    const key = `${ACTIONS_KEY}?status=${status}`;

    const { data, error, isLoading, isValidating, mutate } = useSWR<PendingActionsResponse>(
        key,
        {
            refreshInterval,
            revalidateOnFocus: true,
            dedupingInterval: 2000,
        }
    );

    const approveAction = useCallback(async (actionId: number): Promise<boolean> => {
        const res = await apiFetch(`/api/v1/admin/actions/${actionId}/approve`, {
            method: 'POST',
        });
        if (res.ok) {
            // Optimistic update: remove the approved action from local cache
            await mutate(
                (current) => {
                    if (!current) return current;
                    return {
                        ...current,
                        actions: current.actions.filter(a => a.id !== actionId),
                        count: current.count - 1,
                    };
                },
                { revalidate: true }
            );
            return true;
        }
        return false;
    }, [mutate]);

    const rejectAction = useCallback(async (actionId: number): Promise<boolean> => {
        const res = await apiFetch(`/api/v1/admin/actions/${actionId}/reject`, {
            method: 'POST',
        });
        if (res.ok) {
            await mutate(
                (current) => {
                    if (!current) return current;
                    return {
                        ...current,
                        actions: current.actions.filter(a => a.id !== actionId),
                        count: current.count - 1,
                    };
                },
                { revalidate: true }
            );
            return true;
        }
        return false;
    }, [mutate]);

    return {
        /** The list of pending actions */
        actions: data?.actions ?? [] as PendingAction[],
        /** Total count from the server */
        count: data?.count ?? 0,
        /** Active filter label */
        filter: data?.filter ?? status,
        /** True during initial load */
        isLoading,
        /** True during background revalidation */
        isValidating,
        /** Error object if the request failed */
        isError: !!error,
        error,
        /** Approve a pending action by ID. Returns true on success. */
        approveAction,
        /** Reject a pending action by ID. Returns true on success. */
        rejectAction,
        /** Force a manual revalidation */
        refresh: () => mutate(),
    };
}
