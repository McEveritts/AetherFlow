import useSWR from 'swr';

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

export function useMarketplace() {
    const { data, error, isLoading, mutate } = useSWR<App[]>(
        '/api/marketplace',
        {
            refreshInterval: (currentData) => {
                if (!currentData) return 0;
                const hasActiveJobs = currentData.some(
                    app => app.status === 'installing' || app.status === 'uninstalling'
                );
                return hasActiveJobs ? 2000 : 0;
            }
        }
    );

    return {
        apps: data,
        isLoading,
        isError: !!error,
        error,
        mutate
    };
}
