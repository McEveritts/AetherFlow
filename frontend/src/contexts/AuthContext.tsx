'use client';

import React, { createContext, useContext, useState, useEffect } from 'react';
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
}

const AuthContext = createContext<AuthContextType>({
    isAuthenticated: false,
    isLoading: true,
    user: null,
    login: () => { },
    loginLocal: () => { },
    logout: () => { },
});

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [user, setUser] = useState<User | null>(null);
    const router = useRouter();

    const checkSession = async () => {
        try {
            const res = await apiFetch('/api/v1/auth/session');
            if (res.ok) {
                const userData = await res.json();
                setUser(userData);
                setIsAuthenticated(true);
            } else {
                setIsAuthenticated(false);
                setUser(null);
            }
        } catch (err) {
            console.error("Auth check failed:", err);
            setIsAuthenticated(false);
        } finally {
            setIsLoading(false);
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

        window.addEventListener('storage', handleStorageChange);
        return () => window.removeEventListener('storage', handleStorageChange);
    }, []);

    const login = () => {
        // Redirect to the Go backend to start the OAuth2 flow
        window.location.href = '/api/v1/public/auth/google/login';
    };

    const loginLocal = () => {
        // Re-check session after local login set the cookie, then redirect
        checkSession().then(() => {
            window.localStorage.setItem('af_login_sync', String(Date.now()));
            router.push('/');
        });
    };

    const logout = async () => {
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
        <AuthContext.Provider value={{ isAuthenticated, isLoading, user, login, loginLocal, logout }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);
