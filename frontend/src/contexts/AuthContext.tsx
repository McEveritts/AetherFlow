'use client';

import React, { createContext, useContext, useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

interface AuthContextType {
    isAuthenticated: boolean;
    login: () => void;
    logout: () => void;
}

const AuthContext = createContext<AuthContextType>({
    isAuthenticated: false,
    login: () => { },
    logout: () => { },
});

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const router = useRouter();

    useEffect(() => {
        // Check local storage for an existing session on mount
        const session = localStorage.getItem('aetherflow_session');
        if (session === 'valid') {
            setIsAuthenticated(true);
        }
    }, []);

    const login = () => {
        localStorage.setItem('aetherflow_session', 'valid');
        setIsAuthenticated(true);
        router.push('/');
    };

    const logout = () => {
        localStorage.removeItem('aetherflow_session');
        setIsAuthenticated(false);
        router.push('/login');
    };

    return (
        <AuthContext.Provider value={{ isAuthenticated, login, logout }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);
