'use client';

import { useAuth } from '@/contexts/AuthContext';
import { useRouter, usePathname } from 'next/navigation';
import { useEffect } from 'react';

export default function AuthGuard({ children }: { children: React.ReactNode }) {
    const { isAuthenticated } = useAuth();
    const router = useRouter();
    const pathname = usePathname();

    useEffect(() => {
        if (!isAuthenticated && pathname !== '/login') {
            router.push('/login');
        }
    }, [isAuthenticated, pathname, router]);

    // Optionally, show a loader while checking auth state
    // if (!isAuthenticated && pathname !== '/login') return null;

    return <>{children}</>;
}
