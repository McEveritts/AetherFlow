export const ObsidianColors = {
    bgBase: '#000000',
    bgPrimary: '#000000',
    bgSecondary: '#0f172a',
    slate950: '#000000',
    slate900: '#0f172a',
    slate800: '#1e293b',
    slate700: '#334155',
    slate500: '#64748b',
    slate400: '#94a3b8',
    slate300: '#cbd5e1',
    slate200: '#e2e8f0',
    white: '#ffffff',
    black: '#000000',

    accentPrimary: '#6366f1',
    accentIndigo: '#6366f1',
    indigo600: '#4f46e5',
    indigo500: '#6366f1',
    indigo400: '#818cf8',
    indigo300: '#a5b4fc',
    fuchsia500: '#d946ef',
    fuchsia400: '#e879f9',
    emerald400: '#34d399',
    amber400: '#fbbf24',
    rose500: '#f43f5e',
    sky400: '#38bdf8',
    accentRose: '#f43f5e',
    accentTeal: '#14b8a6',
    accentAmber: '#f59e0b',
    accentEmerald: '#10b981',
} as const;

export const ObsidianGradients = {
    primaryButton: 'linear-gradient(135deg, rgba(99, 102, 241, 0.88) 0%, rgba(217, 70, 239, 0.88) 100%)',
    primaryButtonHover: 'linear-gradient(135deg, rgba(99, 102, 241, 0.98) 0%, rgba(217, 70, 239, 0.98) 100%)',
    cardBg: 'linear-gradient(135deg, rgba(255, 255, 255, 0.06) 0%, rgba(99, 102, 241, 0.03) 55%, rgba(217, 70, 239, 0.025) 100%)',
    cardBgHover: 'linear-gradient(135deg, rgba(255, 255, 255, 0.09) 0%, rgba(99, 102, 241, 0.06) 55%, rgba(217, 70, 239, 0.05) 100%)',
    panelBg: 'linear-gradient(180deg, rgba(16, 18, 38, 0.80) 0%, rgba(12, 10, 30, 0.86) 100%)',
    heroBg: 'linear-gradient(180deg, rgba(10, 12, 26, 0.72) 0%, rgba(16, 14, 38, 0.78) 55%, rgba(24, 12, 48, 0.76) 100%)',
    chromaticEdge: 'linear-gradient(135deg, rgba(255, 255, 255, 0.90) 0%, rgba(56, 189, 248, 0.82) 18%, rgba(129, 140, 248, 0.86) 44%, rgba(217, 70, 239, 0.84) 70%, rgba(168, 85, 247, 0.80) 86%, rgba(56, 189, 248, 0.75) 100%)',
    chromaticEdgeHover: 'linear-gradient(135deg, rgba(255, 255, 255, 0.98) 0%, rgba(56, 189, 248, 0.92) 18%, rgba(129, 140, 248, 0.94) 44%, rgba(217, 70, 239, 0.92) 70%, rgba(168, 85, 247, 0.90) 86%, rgba(56, 189, 248, 0.86) 100%)',
    auroraBase: 'linear-gradient(180deg, #000000 0%, #020108 20%, #09041a 46%, #14082e 74%, #1e0b42 100%)',
    tabPillActive: 'linear-gradient(135deg, rgba(99, 102, 241, 0.24) 0%, rgba(217, 70, 239, 0.14) 100%)',
} as const;

export const ObsidianBorders = {
    specularTop: 'rgba(255, 255, 255, 0.28)',
    specularLeft: 'rgba(56, 189, 248, 0.38)',
    specularSubtle: 'rgba(255, 255, 255, 0.14)',
    glassBorder: 'rgba(129, 140, 248, 0.34)',
    glassBorderHover: 'rgba(168, 85, 247, 0.68)',
    chromaticCyan: 'rgba(56, 189, 248, 0.44)',
    chromaticIndigo: 'rgba(129, 140, 248, 0.48)',
    chromaticFuchsia: 'rgba(217, 70, 239, 0.44)',
} as const;

export const ObsidianEasing = {
    easeOut120: [0.22, 1, 0.36, 1] as const,
    easeSpring120: [0.25, 1, 0.5, 1] as const,
    spring120: {
        type: 'spring',
        stiffness: 350,
        damping: 28,
        mass: 0.8,
    } as const,
} as const;

export const MotionPresets = {
    slideUp: {
        hidden: { opacity: 0, y: 16 },
        visible: { 
            opacity: 1, 
            y: 0, 
            transition: { duration: 0.22, ease: [0.22, 1, 0.36, 1] } 
        },
        exit: { 
            opacity: 0, 
            y: -12, 
            transition: { duration: 0.15, ease: [0.22, 1, 0.36, 1] } 
        }
    },
    fadeIn: {
        hidden: { opacity: 0 },
        visible: { 
            opacity: 1,
            transition: { duration: 0.18, ease: [0.22, 1, 0.36, 1] }
        },
        exit: { 
            opacity: 0,
            transition: { duration: 0.12, ease: [0.22, 1, 0.36, 1] }
        }
    },
    springConfig: {
        type: 'spring',
        stiffness: 420,
        damping: 30,
        mass: 0.75,
    },
    obsidianCardLift: {
        rest: { y: 0, transition: { duration: 0.18, ease: [0.25, 1, 0.5, 1] } },
        hover: { y: -4, transition: { duration: 0.18, ease: [0.25, 1, 0.5, 1] } },
    }
} as const;

export const DesignTokens = {
    spacing: {
        cardPadding: 'p-6 sm:p-8',
        sectionGap: 'space-y-6 sm:space-y-8',
    },
    typography: {
        cardTitle: 'text-xl md:text-2xl font-extrabold tracking-tight text-white',
        cardSubtitle: 'text-sm text-slate-400',
    },
    radii: {
        sm: 'rounded',
        md: 'rounded-lg',
        xl: 'rounded-xl',
        '2xl': 'rounded-2xl',
        full: 'rounded-full',
    },
    touchTargets: {
        huge: 'min-h-[64px] min-w-[64px]',
        large: 'min-h-[52px] min-w-[52px]',
        standard: 'min-h-[44px] min-w-[44px]',
    }
} as const;

/**
 * Triggers a light tactile haptic pulse on supported touch devices when enabled.
 */
export function triggerHaptic(durationMs = 8, enabled = true): void {
    if (!enabled || typeof window === 'undefined' || typeof navigator === 'undefined') return;
    try {
        if ('vibrate' in navigator && typeof navigator.vibrate === 'function') {
            navigator.vibrate(durationMs);
        }
    } catch {
        // Ignore on unsupported browsers
    }
}
