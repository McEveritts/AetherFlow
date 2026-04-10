export const MotionPresets = {
    slideUp: {
        hidden: { opacity: 0, y: 20 },
        visible: { 
            opacity: 1, 
            y: 0, 
            transition: { duration: 0.4, ease: 'circOut' } 
        },
        exit: { 
            opacity: 0, 
            y: -15, 
            transition: { duration: 0.3, ease: 'easeIn' } 
        }
    },
    fadeIn: {
        hidden: { opacity: 0 },
        visible: { 
            opacity: 1,
            transition: { duration: 0.3, ease: 'easeOut' }
        },
        exit: { 
            opacity: 0,
            transition: { duration: 0.2, ease: 'easeIn' }
        }
    },
    springConfig: {
        type: 'spring',
        stiffness: 300,
        damping: 30,
        mass: 1,
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
    }
} as const;
