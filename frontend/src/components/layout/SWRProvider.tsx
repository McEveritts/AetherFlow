'use client';

import { SWRConfig } from 'swr';
import { fetcher } from '@/lib/fetcher';

export default function SWRProvider({ children }: { children: React.ReactNode }) {
    return (
        <SWRConfig
            value={{
                fetcher,
                dedupingInterval: 5000,
                errorRetryCount: 3,
                revalidateOnFocus: false,
                shouldRetryOnError: true,
            }}
        >
            {children}
        </SWRConfig>
    );
}
