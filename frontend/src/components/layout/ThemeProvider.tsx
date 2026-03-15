'use client';

import { useEffect, useState } from 'react';
import { useSystemStore } from '@/store/useSystemStore';

export default function ThemeProvider({ children }: { children: React.ReactNode }) {
    const { theme, language } = useSystemStore();
    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        // eslint-disable-next-line react-hooks/set-state-in-effect
        setMounted(true);
    }, []);

    useEffect(() => {
        if (!mounted) return;

        const root = document.documentElement;
        
        // Handle Theme
        root.classList.remove('light', 'dark');
        if (theme === 'system') {
            const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
            root.classList.add(systemTheme);
        } else {
            root.classList.add(theme);
        }

        // Handle Language
        root.lang = language;
    }, [theme, language, mounted]);

    // Prevent hydration mismatch by not rendering theme classes on server
    if (!mounted) {
        return <>{children}</>;
    }

    return <>{children}</>;
}
