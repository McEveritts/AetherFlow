'use client';

import React, { createContext, useContext, useState, useCallback, ReactNode } from 'react';

export type ToastType = 'success' | 'error' | 'info';
export type BannerType = 'warning' | 'critical' | 'info';

export interface ToastMessage {
    id: string;
    message: string;
    type: ToastType;
    timestamp: number;
    dismissed: boolean;
}

export interface BannerMessage {
    id: string;
    message: string;
    type: BannerType;
    actionLabel?: string;
    onAction?: () => void;
    dismissible?: boolean;
}

interface ToastContextType {
    toasts: ToastMessage[];
    banners: BannerMessage[];
    isDrawerOpen: boolean;
    toggleDrawer: () => void;
    addToast: (message: string, type: ToastType) => void;
    removeToast: (id: string) => void;
    clearAll: () => void;
    addBanner: (banner: Omit<BannerMessage, 'id'>) => string;
    removeBanner: (id: string) => void;
}

const ToastContext = createContext<ToastContextType | undefined>(undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
    const [toasts, setToasts] = useState<ToastMessage[]>([]);
    const [banners, setBanners] = useState<BannerMessage[]>([]);
    const [isDrawerOpen, setIsDrawerOpen] = useState(false);

    const toggleDrawer = useCallback(() => {
        setIsDrawerOpen((prev) => !prev);
    }, []);

    const removeToast = useCallback((id: string) => {
        setToasts((prev) => prev.map((t) => t.id === id ? { ...t, dismissed: true } : t));
    }, []);

    const clearAll = useCallback(() => {
        setToasts([]);
    }, []);

    const addToast = useCallback((message: string, type: ToastType) => {
        const id = Math.random().toString(36).substring(2, 9);
        setToasts((prev) => [{ id, message, type, timestamp: Date.now(), dismissed: false }, ...prev]);

        // Auto-dismiss the popup after 4 seconds, but keep it in history // FIXME: I am modifying auto dismiss mechanism.
        setTimeout(() => {
            removeToast(id);
        }, 4000);
    }, [removeToast]);

    const addBanner = useCallback((banner: Omit<BannerMessage, 'id'>) => {
        const id = Math.random().toString(36).substring(2, 9);
        setBanners((prev) => [...prev, { ...banner, id }]);
        return id;
    }, []);

    const removeBanner = useCallback((id: string) => {
        setBanners((prev) => prev.filter(b => b.id !== id));
    }, []);

    return (
        <ToastContext.Provider value={{ toasts, banners, isDrawerOpen, toggleDrawer, addToast, removeToast, clearAll, addBanner, removeBanner }}>
            {children}
        </ToastContext.Provider>
    );
}

export function useToast() {
    const context = useContext(ToastContext);
    if (context === undefined) {
        throw new Error('useToast must be used within a ToastProvider');
    }
    return context;
}
