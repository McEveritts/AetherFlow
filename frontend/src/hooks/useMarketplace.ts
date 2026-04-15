import useSWR from 'swr';
import { useState, useEffect, useRef } from 'react';

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
    progress: number;
    started_at?: string;
    log_line?: string;
    installed_version?: string;
    latest_version?: string;
    update_available: boolean;
    update_checked_at?: string;
    update_url?: string;
    update_error?: string;
}

export type PendingAction = 'installing' | 'uninstalling';

const TERMINAL_STATES = new Set(['installed', 'uninstalled', 'failed']);

export function useMarketplace() {
    // Map of appId -> action type so we know if it's an install or uninstall
    const pendingRef = useRef<Map<string, PendingAction>>(new Map());
    const [pendingJobs, setPendingJobs] = useState<Map<string, PendingAction>>(new Map());

    const { data, error, isLoading, mutate } = useSWR<App[]>(
        '/api/v1/public/marketplace',
        {
            refreshInterval: (currentData) => {
                // Fast-poll while we have locally pending actions waiting for server pickup
                if (pendingRef.current.size > 0) return 1000;
                if (!currentData) return 0;
                // Keep polling while ANY app is in a transient state
                const hasActiveJobs = currentData.some(
                    app => app.status === 'installing' || app.status === 'uninstalling'
                );
                return hasActiveJobs ? 2000 : 0;
            },
            onSuccess: (serverData) => {
                if (pendingRef.current.size === 0) return;
                // Only clear pending for apps that have reached a TERMINAL state.
                // This ensures we keep fast-polling until the job is truly done,
                // even if the script finishes before our first poll.
                let changed = false;
                serverData.forEach(app => {
                    if (pendingRef.current.has(app.id) && TERMINAL_STATES.has(app.status)) {
                        pendingRef.current.delete(app.id);
                        changed = true;
                    }
                });
                if (changed) {
                    setPendingJobs(new Map(pendingRef.current));
                }
            }
        }
    );

    const markPending = (appId: string, action: PendingAction) => {
        pendingRef.current.set(appId, action);
        setPendingJobs(new Map(pendingRef.current));
    };

    const clearPending = (appId: string) => {
        pendingRef.current.delete(appId);
        setPendingJobs(new Map(pendingRef.current));
    };

    return {
        apps: data,
        isLoading,
        isError: !!error,
        error,
        mutate,
        pendingJobs,
        markPending,
        clearPending
    };
}
