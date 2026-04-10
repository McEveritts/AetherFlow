import React from 'react';
import { useAuth } from '@/contexts/AuthContext';

interface RequireClaimProps {
    children: React.ReactNode;
    role?: string;
    fallback?: React.ReactNode;
}

export default function RequireClaim({ children, role = 'admin', fallback = null }: RequireClaimProps) {
    const { user, isAuthenticated } = useAuth();

    if (!isAuthenticated || !user) {
        return fallback;
    }

    if (user.role !== role) {
        return fallback;
    }

    return <>{children}</>;
}
