import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { TabId } from '@/types/dashboard';

interface SystemState {
    // Persisted preferences
    theme: 'light' | 'dark' | 'system';
    language: string;
    ambientColor1: string;
    ambientColor2: string;

    // Obsidian V2 Atmosphere settings
    auroraOpacity: number;
    auroraAnimation: boolean;
    grainDisplay: boolean;
    cardLift: number;

    // 120Hz High-Refresh & Touchscreen Engine settings
    highRefreshMode: 'auto' | '120hz' | 'standard';
    detectedRefreshRate: number;
    touchMode: 'auto' | 'enabled' | 'desktop';
    detectedTouchDevice: boolean;
    hapticFeedback: boolean;

    // UI state (not persisted)
    activeTab: TabId;
    activeSettingsTab: 'preferences' | 'ai' | 'system' | 'dashboard' | 'backups' | 'security' | 'profile' | 'oidc-clients' | 'notifications';
    isSidebarHovered: boolean;
    isMobileMenuOpen: boolean;
    isCommandPaletteOpen: boolean;

    // Actions
    setTheme: (theme: 'light' | 'dark' | 'system') => void;
    setLanguage: (lang: string) => void;
    setAmbientColor1: (color: string) => void;
    setAmbientColor2: (color: string) => void;
    setAuroraOpacity: (opacity: number) => void;
    setAuroraAnimation: (anim: boolean) => void;
    setGrainDisplay: (grain: boolean) => void;
    setCardLift: (lift: number) => void;
    setHighRefreshMode: (mode: 'auto' | '120hz' | 'standard') => void;
    setDetectedRefreshRate: (hz: number) => void;
    setTouchMode: (mode: 'auto' | 'enabled' | 'desktop') => void;
    setDetectedTouchDevice: (isTouch: boolean) => void;
    setHapticFeedback: (enabled: boolean) => void;
    setActiveTab: (tab: TabId) => void;
    setActiveSettingsTab: (tab: 'preferences' | 'ai' | 'system' | 'dashboard' | 'backups' | 'security' | 'profile' | 'oidc-clients' | 'notifications') => void;
    setIsSidebarHovered: (hovered: boolean) => void;
    setIsMobileMenuOpen: (open: boolean) => void;
    setIsCommandPaletteOpen: (open: boolean) => void;
}

export const useSystemStore = create<SystemState>()(
    persist(
        (set) => ({
            theme: 'system',
            language: 'en',
            ambientColor1: '#2563eb', // default blue
            ambientColor2: '#4f46e5', // default indigo
            auroraOpacity: 0.55,
            auroraAnimation: false,
            grainDisplay: true,
            cardLift: -4,
            highRefreshMode: 'auto',
            detectedRefreshRate: 60,
            touchMode: 'auto',
            detectedTouchDevice: false,
            hapticFeedback: true,
            activeTab: 'overview',
            activeSettingsTab: 'preferences',
            isSidebarHovered: false,
            isMobileMenuOpen: false,
            isCommandPaletteOpen: false,

            setTheme: (theme) => set({ theme }),
            setLanguage: (language) => set({ language }),
            setAmbientColor1: (ambientColor1) => set({ ambientColor1 }),
            setAmbientColor2: (ambientColor2) => set({ ambientColor2 }),
            setAuroraOpacity: (auroraOpacity) => set({ auroraOpacity }),
            setAuroraAnimation: (auroraAnimation) => set({ auroraAnimation }),
            setGrainDisplay: (grainDisplay) => set({ grainDisplay }),
            setCardLift: (cardLift) => set({ cardLift }),
            setHighRefreshMode: (highRefreshMode) => set({ highRefreshMode }),
            setDetectedRefreshRate: (detectedRefreshRate) => set({ detectedRefreshRate }),
            setTouchMode: (touchMode) => set({ touchMode }),
            setDetectedTouchDevice: (detectedTouchDevice) => set({ detectedTouchDevice }),
            setHapticFeedback: (hapticFeedback) => set({ hapticFeedback }),
            setActiveTab: (activeTab) => set({ activeTab, isMobileMenuOpen: false }),
            setActiveSettingsTab: (activeSettingsTab) => set({ activeSettingsTab }),
            setIsSidebarHovered: (isSidebarHovered) => set({ isSidebarHovered }),
            setIsMobileMenuOpen: (isMobileMenuOpen) => set({ isMobileMenuOpen }),
            setIsCommandPaletteOpen: (isCommandPaletteOpen) => set({ isCommandPaletteOpen }),
        }),
        {
            name: 'aetherflow-system-storage',
            // Only persist preferences, not volatile UI state
            partialize: (state) => ({ 
                theme: state.theme, 
                language: state.language,
                ambientColor1: state.ambientColor1,
                ambientColor2: state.ambientColor2,
                auroraOpacity: state.auroraOpacity,
                auroraAnimation: state.auroraAnimation,
                grainDisplay: state.grainDisplay,
                cardLift: state.cardLift,
                highRefreshMode: state.highRefreshMode,
                touchMode: state.touchMode,
                hapticFeedback: state.hapticFeedback,
            }),
        }
    )
);
