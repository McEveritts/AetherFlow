'use client';

import { useEffect, useState } from 'react';
import { useSystemStore } from '@/store/useSystemStore';

export default function ThemeProvider({ children }: { children: React.ReactNode }) {
    const { theme, language, ambientColor1, ambientColor2 } = useSystemStore();
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
        return (
            <>
                <div className="fixed inset-0 overflow-hidden pointer-events-none z-[-1] transition-colors duration-1000">
                    <div 
                        className="absolute top-0 right-0 w-[500px] h-[500px] blur-[100px] rounded-full translate-x-1/3 -translate-y-1/3 transition-colors duration-1000"
                        style={{ backgroundColor: '#2563eb', opacity: 0.15 }}
                    />
                    <div 
                        className="absolute bottom-0 left-0 w-[400px] h-[400px] blur-[100px] rounded-full -translate-x-1/3 translate-y-1/3 transition-colors duration-1000"
                        style={{ backgroundColor: '#4f46e5', opacity: 0.15 }}
                    />
                </div>
                {children}
            </>
        );
    }

    return (
        <>
            <div className="fixed inset-0 overflow-hidden pointer-events-none z-[-1] transition-colors duration-1000">
                <div 
                    className="absolute top-0 right-0 w-[500px] h-[500px] blur-[100px] rounded-full translate-x-1/3 -translate-y-1/3 transition-colors duration-1000"
                    style={{ backgroundColor: ambientColor1, opacity: 0.15 }}
                />
                <div 
                    className="absolute bottom-0 left-0 w-[400px] h-[400px] blur-[100px] rounded-full -translate-x-1/3 translate-y-1/3 transition-colors duration-1000"
                    style={{ backgroundColor: ambientColor2, opacity: 0.15 }}
                />
            </div>
            {children}
        </>
    );
}
