import useSWR from 'swr';
import { useLifecyclePollRecovery } from './useLifecyclePollRecovery';
import { useState, useEffect, useRef, useCallback } from 'react';

export function useGithubDownloads() {
  const [downloads, setDownloads] = useState<number | null>(null);

  useEffect(() => {
    fetch('https://api.github.com/repos/mceveritts/aetherflow/releases')
      .then((res) => res.json())
      .then((releases) => {
        let total = 0;
        releases.forEach((release: { assets: { download_count: number }[] }) => {
          release.assets.forEach((asset: { download_count: number }) => {
            total += asset.download_count;
          });
        });
        setDownloads(total);
      })
      .catch(() => setDownloads(4320));
  }, []);

  return downloads;
}

export interface App {
    id: string;
    name: string;
    desc: string;
    hits: number;
    category: string;
    status: string;
    default_port?: number;
    active_port?: number;
    internal_domain?: string;
    public_domain?: string;
    external_access_enabled?: boolean;
    tls_enabled?: boolean;
    web_path?: string;
    web_scheme?: string;
    bind_scope?: 'loopback' | 'network' | string;
    control_scope?: 'shared-vhost' | 'service' | string;
    progress: number;
    started_at?: string;
    job_id?: string;
    log_line?: string;
    installed_version?: string;
    latest_version?: string;
    update_available: boolean;
    update_checked_at?: string;
    update_url?: string;
    update_error?: string;
    /** Public terminal outcome of the most recent lifecycle job (no failure detail). */
    last_job?: MarketplaceJobOutcome;
}

export interface MarketplaceJobOutcome {
    job_id?: string;
    message?: string;
    action: 'install' | 'update' | 'remove' | string;
    status: 'completed' | 'failed' | string;
    started_at: string;
    finished_at: string;
}

export type PendingAction = 'installing' | 'uninstalling' | 'updating';
export const LIFECYCLE_RECEIPT_TIMEOUT_MS = 120000;

const PENDING_TO_JOB_ACTION: Record<PendingAction, string> = {
    installing: 'install',
    updating: 'update',
    uninstalling: 'remove',
};

/** A receipt is authoritative only when its identity and action both match. */
export function lifecycleIdentity(job: { job_id?: string; started_at?: string } | undefined): string | undefined {
    return job?.job_id || job?.started_at || undefined;
}
export function matchingJobOutcome(app: Pick<App, 'last_job'>, action: PendingAction, identity?: string): MarketplaceJobOutcome | undefined {
    const job = app.last_job;
    return identity && lifecycleIdentity(job) === identity && job?.action === PENDING_TO_JOB_ACTION[action]
        ? job : undefined;
}
export function lastJobFailed(app: Pick<App, 'last_job'>, pending: string | undefined): boolean {
    return Boolean(pending && app.last_job?.status === 'failed' && app.last_job.action === PENDING_TO_JOB_ACTION[pending as PendingAction]);
}
/** Only a fresh observation of the accepted job and action renews its deadline. */
export function matchingActiveJob(job: { job_id?: string; started_at?: string; status?: string; job_status?: string }, action: PendingAction, identity?: string): boolean {
    const phase = isLifecycleStatus(job.job_status) ? job.job_status : job.status;
    return Boolean(identity && lifecycleIdentity(job) === identity && phase === action);
}
export function isLifecycleStatus(status?: string): status is PendingAction {
    return status === 'installing' || status === 'updating' || status === 'uninstalling';
}

export function useMarketplace() {
    // Map of appId -> action type so we know if it's an install, uninstall, or update
    const pendingRef = useRef<Map<string, PendingAction>>(new Map());
    const expectedRef = useRef<Map<string, string>>(new Map());
    const deadlineRef = useRef<Map<string, number>>(new Map());
    const [unconfirmedJobs, setUnconfirmedJobs] = useState<Map<string, string>>(new Map());
    const [receiptRevision, setReceiptRevision] = useState(0);
    const [pendingJobs, setPendingJobs] = useState<Map<string, PendingAction>>(new Map());

    const renewActiveJobs = useCallback((apps?: App[]) => {
        apps?.forEach(app => {
            const action = pendingRef.current.get(app.id);
            if (action && matchingActiveJob(app, action, expectedRef.current.get(app.id))) {
                deadlineRef.current.set(app.id, Date.now() + LIFECYCLE_RECEIPT_TIMEOUT_MS);
            }
        });
    }, []);

    const { data, error, isLoading, isValidating, mutate } = useSWR<App[]>(
        '/api/v1/public/marketplace',
        {
            refreshInterval: (currentData) => {
                // Fast-poll while we have locally pending actions waiting for server pickup
                if (pendingRef.current.size > 0) return 1000;
                if (!currentData) return 15000;
                // Keep polling while ANY app is in a transient state
                const hasActiveJobs = currentData.some(
                    app => app.status === 'installing' || app.status === 'uninstalling' || app.status === 'updating'
                );
                return hasActiveJobs ? 2000 : 15000;
            },
            // SWR can retain the same data reference after equal successful polls.
            // This heartbeat must not be renewed by stale cache on fetch failures.
            onSuccess: renewActiveJobs,
            shouldRetryOnError: false,
        }
    );

    useLifecyclePollRecovery('/api/v1/public/marketplace', error, () => mutate());

    // A deduplicated request initiated by another subscriber still changes
    // isValidating, even when SWR preserves deeply equal cached data.
    useEffect(() => {
        if (!error && !isValidating) renewActiveJobs(data);
    }, [data, error, isValidating, renewActiveJobs]);

    useEffect(() => {
        let changed = false;
        data?.forEach(app => {
            const action = pendingRef.current.get(app.id);
            if (action && matchingJobOutcome(app, action, expectedRef.current.get(app.id))) {
                pendingRef.current.delete(app.id);
                expectedRef.current.delete(app.id);
                deadlineRef.current.delete(app.id);
                changed = true;
            }
        });
        if (changed) setPendingJobs(new Map(pendingRef.current));
    }, [data, receiptRevision]);

    useEffect(() => {
        if (!deadlineRef.current.size) return;
        let timeout: ReturnType<typeof setTimeout>;
        const schedule = () => {
            if (deadlineRef.current.size) timeout = setTimeout(checkDeadlines, Math.max(0, Math.min(...deadlineRef.current.values()) - Date.now()));
        };
        const checkDeadlines = () => {
            const expired = new Map<string, string>();
            deadlineRef.current.forEach((deadline, appId) => {
                if (deadline > Date.now()) return;
                expired.set(appId, expectedRef.current.get(appId) || `unconfirmed-${deadline}`);
                pendingRef.current.delete(appId);
                expectedRef.current.delete(appId);
                deadlineRef.current.delete(appId);
            });
            if (expired.size) {
                setUnconfirmedJobs(current => new Map([...current, ...expired]));
                setPendingJobs(new Map(pendingRef.current));
            }
            // A heartbeat may have extended the earliest deadline without a render.
            schedule();
        };
        schedule();
        return () => clearTimeout(timeout);
    }, [pendingJobs, receiptRevision]);

    const registerJob = (appId: string, receipt: { job_id?: string; started_at?: string }) => {
        const identity = lifecycleIdentity(receipt);
        if (!identity) throw new Error('The server did not return a job identity. Refresh status and check logs before retrying.');
        if (!pendingRef.current.has(appId)) throw new Error('Acceptance arrived after status tracking expired. Check application state and logs before retrying.');
        expectedRef.current.set(appId, identity);
        setReceiptRevision(value => value + 1);
        setPendingJobs(new Map(pendingRef.current));
        return identity;
    };

    const markPending = (appId: string, action: PendingAction) => {
        expectedRef.current.delete(appId);
        pendingRef.current.set(appId, action);
        deadlineRef.current.set(appId, Date.now() + LIFECYCLE_RECEIPT_TIMEOUT_MS);
        setUnconfirmedJobs(current => { const next = new Map(current); next.delete(appId); return next; });
        setPendingJobs(new Map(pendingRef.current));
    };

    const clearPending = (appId: string) => {
        expectedRef.current.delete(appId);
        pendingRef.current.delete(appId);
        deadlineRef.current.delete(appId);
        setPendingJobs(new Map(pendingRef.current));
    };

    return {
        apps: data,
        isLoading,
        isError: !!error,
        error,
        mutate,
        pendingJobs,
        unconfirmedJobs,
        markPending,
        registerJob,
        clearPending
    };
}
