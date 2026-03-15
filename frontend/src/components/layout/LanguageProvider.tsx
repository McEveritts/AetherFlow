'use client';

import { NextIntlClientProvider } from 'next-intl';
import { useSystemStore } from '@/store/useSystemStore';
import { useEffect, useState } from 'react';
import SkeletonBox from '@/components/layout/SkeletonBox';

export default function LanguageProvider({ children }: { children: React.ReactNode }) {
    const { language } = useSystemStore();
    const [messages, setMessages] = useState<Record<string, unknown> | null>(null);

    useEffect(() => {
        let mounted = true;
        import(`../../../messages/${language}.json`)
            .then((module) => {
                if (mounted) setMessages(module.default);
            })
            .catch(() => {
                // fallback to english
                import(`../../../messages/en.json`).then(m => {
                    if (mounted) setMessages(m.default);
                });
            });
            
        return () => { mounted = false; };
    }, [language]);

    // Don't render until dictionary is loaded to prevent hydration mismatches
    if (!messages) {
        return (
            <div className="min-h-screen bg-slate-950 flex flex-col p-6 space-y-4">
                <SkeletonBox className="h-16 w-full max-w-[200px]" />
                <SkeletonBox className="h-[200px] w-full max-w-4xl" />
            </div>
        );
    }

    return (
        <NextIntlClientProvider locale={language} messages={messages}>
            {children}
        </NextIntlClientProvider>
    );
}
