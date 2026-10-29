'use client';

import React, { createContext, useContext, useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { apiFetch } from '@/lib/fetcher';
import { mutate as globalMutate } from 'swr';
import { useConnectionStore } from '@/store/useConnectionStore';

export interface User {
    id: number;
    username: string;
    email: string;
    avatar_url: string;
    role: string;
    is_oauth: boolean;
    totp_enabled: boolean;
}

interface AuthContextType {
    isAuthenticated: boolean;
    isLoading: boolean;
    user: User | null;
    login: () => void;
    loginLocal: () => void;
    logout: () => void;
    refreshSession: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
    isAuthenticated: false,
    isLoading: true,
    user: null,
    login: () => { },
    loginLocal: () => { },
    logout: () => { },
    refreshSession: async () => { },
});

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [user, setUser] = useState<User | null>(null);
    const router = useRouter();
    const sessionCheckGenRef = useRef(0);
    const lastAuthenticatedAtRef = useRef(0);

    const checkSession = async () => {
        const gen = ++sessionCheckGenRef.current;
        try {
            const res = await apiFetch('/api/v1/auth/session');
            if (gen !== sessionCheckGenRef.current) return;
            if (res.ok) {
                const userData = await res.json();
                if (gen !== sessionCheckGenRef.current) return;
                lastAuthenticatedAtRef.current = Date.now();
                setUser(userData);
                setIsAuthenticated(true);
            } else {
                setIsAuthenticated(false);
                setUser(null);
            }
        } catch (err) {
            if (gen !== sessionCheckGenRef.current) return;
            console.error("Auth check failed:", err);
            setIsAuthenticated(false);
        } finally {
            if (gen === sessionCheckGenRef.current) {
                setIsLoading(false);
            }
        }
    };

    useEffect(() => {
        checkSession();

        // Multi-tab session synchronization listener
        const handleStorageChange = (e: StorageEvent) => {
            if (e.key === 'af_logout_sync') {
                // Another tab either logged out or expired cleanly. Re-evaluate session state.
                checkSession();
            }
            if (e.key === 'af_login_sync') {
                checkSession();
            }
        };

        // Same-tab hard 401 listener when silent token refresh also fails
        const handleSessionExpired = () => {
            // Guard against delayed pre-login requests resolving right after login succeeded
            if (Date.now() - lastAuthenticatedAtRef.current < 10_000) {
                void checkSession();
                return;
            }
            setIsAuthenticated(false);
            setUser(null);
            useConnectionStore.getState().reset();
            globalMutate(() => true, undefined, { revalidate: false });
        };

        window.addEventListener('storage', handleStorageChange);
        window.addEventListener('af:session-expired', handleSessionExpired);
        return () => {
            window.removeEventListener('storage', handleStorageChange);
            window.removeEventListener('af:session-expired', handleSessionExpired);
        };
    }, []);

    // Proactive session rotation while authenticated so 15-minute JWTs never expire mid-session
    useEffect(() => {
        if (!isAuthenticated) return;

        let lastRefreshAt = Date.now();
        const rotateSession = async () => {
            lastRefreshAt = Date.now();
            try {
                await apiFetch('/api/v1/auth/refresh', { method: 'POST' });
            } catch {
                // Silent failure; apiFetch handles hard 401 expiration dispatch
            }
        };

        const intervalId = window.setInterval(rotateSession, 10 * 60 * 1000);

        const handleVisibilityChange = () => {
            if (document.visibilityState === 'visible' && Date.now() - lastRefreshAt >= 60 * 1000) {
                void rotateSession();
            }
        };

        document.addEventListener('visibilitychange', handleVisibilityChange);
        return () => {
            window.clearInterval(intervalId);
            document.removeEventListener('visibilitychange', handleVisibilityChange);
        };
    }, [isAuthenticated]);

    const login = () => {
        // Redirect to the Go backend to start the OAuth2 flow
        window.location.href = '/api/v1/public/auth/google/login';
    };

    const loginLocal = () => {
        lastAuthenticatedAtRef.current = Date.now();
        // Re-check session after local login set the cookie, then redirect
        checkSession().then(() => {
            window.localStorage.setItem('af_login_sync', String(Date.now()));
            router.push('/');
        });
    };

    const logout = async () => {
        sessionCheckGenRef.current++;
        lastAuthenticatedAtRef.current = 0;
        try {
            await apiFetch('/api/v1/auth/logout', { method: 'POST' });
        } catch (err) {
            console.error("Logout failed:", err);
        }

        window.localStorage.setItem('af_logout_sync', String(Date.now()));

        // Clear authentication state
        setIsAuthenticated(false);
        setUser(null);

        // Reset WebSocket connection store to prevent stale connections
        useConnectionStore.getState().reset();

        // Clear all SWR cache to prevent stale data leaks across sessions
        globalMutate(() => true, undefined, { revalidate: false });

        router.push('/login');
    };

    return (
        <AuthContext.Provider value={{ isAuthenticated, isLoading, user, login, loginLocal, logout, refreshSession: checkSession }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);
