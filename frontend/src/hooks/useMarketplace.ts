import useSWR from 'swr';

export interface App {
    id: string;
    name: string;
    desc: string;
    hits: number;
    category: string;
    status: string;
}

const fetcher = (url: string) => fetch(url).then(res => {
    if (!res.ok) {
        throw new Error('Failed to fetch marketplace catalog.');
    }
    return res.json();
});

export function useMarketplace() {
    const { data, error, isLoading, mutate } = useSWR<App[]>(
        '/api/marketplace',
        fetcher,
        {
            revalidateOnFocus: false,
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
