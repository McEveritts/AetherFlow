import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { TabId } from '@/types/dashboard';

interface BackgroundTask {
    id: string;
    description: string;
    progress?: number;
}

interface SystemState {
    // Persisted preferences
    theme: 'light' | 'dark' | 'system';
    language: string;

    // UI state (not persisted)
    activeTab: TabId;
    isSidebarHovered: boolean;
    isMobileMenuOpen: boolean;
    activeTasks: BackgroundTask[];
    
    // Actions
    setTheme: (theme: 'light' | 'dark' | 'system') => void;
    setLanguage: (lang: string) => void;
    setActiveTab: (tab: TabId) => void;
    setIsSidebarHovered: (hovered: boolean) => void;
    setIsMobileMenuOpen: (open: boolean) => void;
    addTask: (task: BackgroundTask) => void;
    removeTask: (taskId: string) => void;
    updateTaskProgress: (taskId: string, progress: number) => void;
}

export const useSystemStore = create<SystemState>()(
    persist(
        (set) => ({
            theme: 'system',
            language: 'en',
            activeTab: 'overview',
            isSidebarHovered: false,
            isMobileMenuOpen: false,
            activeTasks: [],
            
            setTheme: (theme) => set({ theme }),
            setLanguage: (language) => set({ language }),
            setActiveTab: (activeTab) => set({ activeTab, isMobileMenuOpen: false }),
            setIsSidebarHovered: (isSidebarHovered) => set({ isSidebarHovered }),
            setIsMobileMenuOpen: (isMobileMenuOpen) => set({ isMobileMenuOpen }),
            addTask: (task) => set((state) => ({ 
                activeTasks: [...state.activeTasks, task] 
            })),
            removeTask: (taskId) => set((state) => ({ 
                activeTasks: state.activeTasks.filter(t => t.id !== taskId) 
            })),
            updateTaskProgress: (taskId, progress) => set((state) => ({
                activeTasks: state.activeTasks.map(t => 
                    t.id === taskId ? { ...t, progress } : t
                )
            })),
        }),
        {
            name: 'aetherflow-system-storage',
            // Only persist preferences, not volatile UI state
            partialize: (state) => ({ theme: state.theme, language: state.language }),
        }
    )
);
