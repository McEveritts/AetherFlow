'use client';

import { useEffect, useState } from 'react';
import { useSystemStore } from '@/store/useSystemStore';

function quantizeRefreshRate(fps: number): number {
    const buckets = [60, 75, 90, 120, 144, 165, 240];
    let closest = 60;
    let minDiff = Infinity;
    for (const b of buckets) {
        const diff = Math.abs(fps - b);
        if (diff < minDiff) {
            minDiff = diff;
            closest = b;
        }
    }
    return closest;
}

export default function ThemeProvider({ children }: { children: React.ReactNode }) {
    const { 
        theme, 
        language, 
        auroraOpacity, 
        auroraAnimation, 
        grainDisplay, 
        cardLift,
        highRefreshMode,
        detectedRefreshRate,
        setDetectedRefreshRate,
        touchMode,
        detectedTouchDevice,
        setDetectedTouchDevice,
    } = useSystemStore();
    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        setMounted(true);

        // 1. Detect Touch / Coarse Pointer Capability
        const detectTouch = () => {
            if (typeof window === 'undefined') return false;
            const coarseMatch = typeof window.matchMedia === 'function'
                ? window.matchMedia('(pointer: coarse), (hover: none)').matches
                : false;
            return Boolean(coarseMatch);
        };
        setDetectedTouchDevice(detectTouch());

        let mql: MediaQueryList | null = null;
        const onPointerChange = () => setDetectedTouchDevice(detectTouch());
        if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
            mql = window.matchMedia('(pointer: coarse)');
            if (typeof mql.addEventListener === 'function') {
                mql.addEventListener('change', onPointerChange);
            }
        }

        // 2. Probe Display Refresh Rate Cadence via requestAnimationFrame (non-blocking 18-frame sample)
        let rafId: number | null = null;
        if (typeof window !== 'undefined' && typeof window.requestAnimationFrame === 'function') {
            let frames = 0;
            let startTime = 0;
            const sampleFrames = (timestamp: number) => {
                if (frames === 0) {
                    startTime = timestamp;
                }
                frames++;
                if (frames <= 18) {
                    rafId = window.requestAnimationFrame(sampleFrames);
                } else {
                    const elapsed = timestamp - startTime;
                    if (elapsed > 0) {
                        const rawFps = (18 * 1000) / elapsed;
                        setDetectedRefreshRate(quantizeRefreshRate(rawFps));
                    }
                }
            };
            rafId = window.requestAnimationFrame(sampleFrames);
        }

        return () => {
            if (mql && typeof mql.removeEventListener === 'function') {
                mql.removeEventListener('change', onPointerChange);
            }
            if (rafId !== null && typeof window !== 'undefined' && typeof window.cancelAnimationFrame === 'function') {
                window.cancelAnimationFrame(rafId);
            }
        };
    }, [setDetectedRefreshRate, setDetectedTouchDevice]);

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

        // Synchronize Obsidian V2 Atmosphere variables
        root.style.setProperty('--obs-aurora-opacity', String(auroraOpacity ?? 0.55));
        root.style.setProperty(
            '--obs-aurora-animation', 
            auroraAnimation ? 'obs-aurora-shift 24s ease-in-out infinite' : 'none'
        );
        root.style.setProperty(
            '--obs-grain-display', 
            grainDisplay ? 'block' : 'none'
        );
        root.style.setProperty(
            '--obs-card-lift', 
            typeof cardLift === 'number' ? `${cardLift}px` : '-4px'
        );

        // Synchronize 120Hz High-Refresh Engine
        const isHighRefresh =
            highRefreshMode === '120hz' ||
            (highRefreshMode === 'auto' && detectedRefreshRate >= 90);
        root.dataset.highRefresh = isHighRefresh ? 'true' : 'false';
        root.style.setProperty('--obs-duration-fast', isHighRefresh ? '110ms' : '160ms');
        root.style.setProperty('--obs-duration-card', isHighRefresh ? '150ms' : '200ms');

        // Synchronize Touchscreen Ergonomics Engine
        const isTouchActive =
            touchMode === 'enabled' ||
            (touchMode === 'auto' && detectedTouchDevice);
        root.dataset.touchMode = isTouchActive ? 'true' : 'false';
    }, [
        theme,
        language,
        auroraOpacity,
        auroraAnimation,
        grainDisplay,
        cardLift,
        highRefreshMode,
        detectedRefreshRate,
        touchMode,
        detectedTouchDevice,
        mounted,
    ]);

    // Transparent passthrough with zero redundant floating blur divs
    return <>{children}</>;
}
