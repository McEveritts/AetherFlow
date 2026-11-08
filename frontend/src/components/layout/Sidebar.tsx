'use client';

import { useEffect, useRef, useState } from 'react';
import useSWR from 'swr';
import { useShallow } from 'zustand/react/shallow';
import { TabId } from '@/types/dashboard';
import type { PendingActionsResponse } from '@/types/api';
import { useAuth } from '@/contexts/AuthContext';
import { useSystemStore } from '@/store/useSystemStore';
import { useConnectionStore } from '@/store/useConnectionStore';
import { triggerHaptic } from '@/lib/design';
import {
    LayoutDashboard,
    Server,
    Sparkles,
    Settings,
    LogOut,
    Store,
    Folder,
    FolderUp,
    Users,
    Mail,
    ClipboardList,
    Film,
    Tv,
    ChevronLeft,
    ChevronRight,
    Menu,
    X,
    Radio,
    Boxes
} from 'lucide-react';

export const NAVIGATION = [
    { id: 'overview' as TabId, label: 'Overview', icon: <LayoutDashboard size={19} /> },
    { id: 'inbox' as TabId, label: 'Approval Inbox', icon: <Mail size={19} /> },
    { id: 'services' as TabId, label: 'Services', icon: <Server size={19} /> },
    { id: 'marketplace' as TabId, label: 'Marketplace', icon: <Store size={19} /> },
    { id: 'mcbrowser' as TabId, label: 'McBrowser', icon: <Folder size={19} /> },
    { id: 'fileshare' as TabId, label: 'File Share', icon: <FolderUp size={19} /> },
    { id: 'streaming' as TabId, label: 'Streaming', icon: <Tv size={19} /> },
    { id: 'mediaflow' as TabId, label: 'MediaFlow', icon: <Film size={19} /> },
    { id: 'ai' as TabId, label: 'FlowAI', icon: <Sparkles size={19} /> },
];

export const BOTTOM_NAVIGATION = [
    { id: 'network' as TabId, label: 'Network', icon: <Radio size={19} /> },
    { id: 'cluster' as TabId, label: 'Cluster', icon: <Boxes size={19} /> },
    { id: 'users' as TabId, label: 'Users', icon: <Users size={19} /> },
    { id: 'audit' as TabId, label: 'Audit Trail', icon: <ClipboardList size={19} /> },
    { id: 'settings' as TabId, label: 'Settings', icon: <Settings size={19} /> },
    { id: 'logout' as TabId, label: 'Log Out', icon: <LogOut size={19} /> },
];

export const MOBILE_DOCK_ITEMS: { id: TabId; label: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview', icon: <LayoutDashboard size={20} /> },
    { id: 'services', label: 'Services', icon: <Server size={20} /> },
    { id: 'streaming', label: 'Streaming', icon: <Tv size={20} /> },
];

export default function Sidebar() {
    const { user, logout } = useAuth();
    const {
        activeTab,
        setActiveTab,
        setIsSidebarHovered,
        isMobileMenuOpen,
        setIsMobileMenuOpen,
        hapticFeedback,
    } = useSystemStore(
        useShallow((state) => ({
            activeTab: state.activeTab,
            setActiveTab: state.setActiveTab,
            setIsSidebarHovered: state.setIsSidebarHovered,
            isMobileMenuOpen: state.isMobileMenuOpen,
            setIsMobileMenuOpen: state.setIsMobileMenuOpen,
            hapticFeedback: state.hapticFeedback,
        }))
    );
    const connectionState = useConnectionStore((state) => state.connectionState);
    const { data: pendingActionsData } = useSWR<PendingActionsResponse>(
        user?.role === 'admin' ? '/api/v1/admin/actions/pending?status=pending' : null
    );
    const pendingCount = pendingActionsData?.count ?? pendingActionsData?.actions?.length ?? 0;
    const touchStartXRef = useRef<number | null>(null);
    const drawerRef = useRef<HTMLElement | null>(null);
    const closeButtonRef = useRef<HTMLButtonElement | null>(null);
    const previouslyFocusedElementRef = useRef<HTMLElement | null>(null);
    const [isCollapsed, setIsCollapsed] = useState(false);

    useEffect(() => {
        if (!isMobileMenuOpen) return;

        previouslyFocusedElementRef.current = (document.activeElement as HTMLElement) || null;

        const timer = setTimeout(() => {
            closeButtonRef.current?.focus();
        }, 50);

        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === 'Escape') {
                event.preventDefault();
                setIsMobileMenuOpen(false);
                return;
            }

            if (event.key === 'Tab' && drawerRef.current) {
                const focusableElements = drawerRef.current.querySelectorAll<HTMLElement>(
                    'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
                );
                if (focusableElements.length === 0) return;

                const firstElement = focusableElements[0];
                const lastElement = focusableElements[focusableElements.length - 1];

                if (event.shiftKey) {
                    if (document.activeElement === firstElement) {
                        event.preventDefault();
                        lastElement.focus();
                    }
                } else {
                    if (document.activeElement === lastElement) {
                        event.preventDefault();
                        firstElement.focus();
                    }
                }
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => {
            clearTimeout(timer);
            window.removeEventListener('keydown', handleKeyDown);
            previouslyFocusedElementRef.current?.focus();
        };
    }, [isMobileMenuOpen, setIsMobileMenuOpen]);

    const getBeaconClass = () => {
        if (connectionState === 'CONNECTED') {
            return 'obs-beacon-live';
        }
        if (connectionState === 'RECONNECTING' || connectionState === 'CONNECTING' || connectionState === 'FALLBACK') {
            return 'obs-beacon-reconnecting';
        }
        return 'obs-beacon-danger';
    };

    const handleDrawerTouchStart = (touchEvent: React.TouchEvent) => {
        touchStartXRef.current = touchEvent.touches[0]?.clientX ?? null;
    };

    const handleDrawerTouchEnd = (touchEvent: React.TouchEvent) => {
        if (touchStartXRef.current === null) return;
        const touchEndX = touchEvent.changedTouches[0]?.clientX ?? touchStartXRef.current;
        const deltaX = touchEndX - touchStartXRef.current;
        touchStartXRef.current = null;
        if (deltaX < -55) {
            triggerHaptic(6, hapticFeedback);
            setIsMobileMenuOpen(false);
        }
    };

    const handleToggleCollapse = () => {
        triggerHaptic(6, hapticFeedback);
        const nextCollapsed = !isCollapsed;
        setIsCollapsed(nextCollapsed);
        setIsSidebarHovered(!nextCollapsed);
    };

    return (
        <>
            <nav 
                aria-label="Mobile Bottom Navigation"
                className="md:hidden fixed bottom-0 left-0 right-0 z-40 h-16 glass-panel border-t border-white/10 px-2 pb-[max(0.5rem,env(safe-area-inset-bottom))] flex items-center justify-around"
            >
                <div className="absolute inset-x-0 top-0 h-px bg-indigo-500/20" />

                {MOBILE_DOCK_ITEMS.map((item) => {
                    const isActive = activeTab === item.id;
                    return (
                        <button
                            key={item.id}
                            type="button"
                            onClick={() => {
                                triggerHaptic(8, hapticFeedback);
                                setActiveTab(item.id);
                                setIsMobileMenuOpen(false);
                            }}
                            className={`flex flex-col items-center justify-center flex-1 h-full obs-touch-target-standard obs-gpu-120hz-interactive relative ${
                                isActive ? 'text-indigo-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            {isActive && (
                                <span className="absolute top-1 w-8 h-1 bg-indigo-500 rounded-full" />
                            )}
                            <div className="p-1">
                                {item.icon}
                            </div>
                            <span className="text-xs tracking-tight leading-none mt-0.5">{item.label}</span>
                        </button>
                    );
                })}

                <button
                    type="button"
                    onClick={() => {
                        triggerHaptic(8, hapticFeedback);
                        setIsMobileMenuOpen(!isMobileMenuOpen);
                    }}
                    aria-label="Toggle Navigation Drawer"
                    aria-expanded={isMobileMenuOpen}
                    aria-controls="mobile-navigation-drawer"
                    aria-haspopup="dialog"
                    className={`flex flex-col items-center justify-center flex-1 h-full obs-touch-target-standard obs-gpu-120hz-interactive relative ${
                        isMobileMenuOpen ? 'text-indigo-300 font-semibold' : 'text-slate-400 hover:text-slate-200'
                    }`}
                >
                    <div className="p-1">
                        <Menu size={20} />
                    </div>
                    <span className="text-xs tracking-tight leading-none mt-0.5">Menu</span>
                </button>
            </nav>

            {isMobileMenuOpen && (
                <div
                    className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 md:hidden transition-opacity"
                    onClick={() => setIsMobileMenuOpen(false)}
                >
                    <aside
                        id="mobile-navigation-drawer"
                        ref={drawerRef}
                        role="dialog"
                        aria-modal="true"
                        aria-label="Navigation Menu"
                        tabIndex={-1}
                        className="fixed inset-y-0 left-0 w-72 max-w-[85vw] glass-panel bg-[#0a0e18]/98 p-5 flex flex-col z-50 border-r border-white/10 shadow-2xl overflow-y-auto no-scrollbar outline-none"
                        onClick={(clickEvent) => clickEvent.stopPropagation()}
                        onTouchStart={handleDrawerTouchStart}
                        onTouchEnd={handleDrawerTouchEnd}
                    >
                        <div className="flex items-center justify-between pb-4 mb-4 border-b border-white/10">
                            <div className="flex items-center gap-3">
                                <div className="w-9 h-9 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center">
                                    <img src="/img/aetherflow-mark.svg" alt="AetherFlow Logo" className="w-6 h-6" />
                                </div>
                                <div>
                                    <h2 className="text-base font-bold text-white tracking-tight">AetherFlow</h2>
                                    <div className="flex items-center gap-2 mt-0.5">
                                        <span className={getBeaconClass()} />
                                        <span className="text-xs font-mono text-slate-400 uppercase">{connectionState}</span>
                                    </div>
                                </div>
                            </div>
                            <button
                                ref={closeButtonRef}
                                type="button"
                                onClick={() => setIsMobileMenuOpen(false)}
                                className="obs-touch-target-standard min-h-[40px] min-w-[40px] p-2 rounded-xl text-slate-400 hover:text-white hover:bg-white/10 flex items-center justify-center transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
                                aria-label="Close Navigation Drawer"
                                title="Close Navigation Drawer"
                            >
                                <X size={20} />
                            </button>
                        </div>

                        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-2 mb-2 select-none">Workspace</div>
                        <div className="space-y-1 mb-6">
                            {NAVIGATION.map((item) => {
                                const isActive = activeTab === item.id;
                                return (
                                    <button
                                        key={item.id}
                                        type="button"
                                        onClick={() => {
                                            triggerHaptic(8, hapticFeedback);
                                            setActiveTab(item.id);
                                            setIsMobileMenuOpen(false);
                                        }}
                                        className={`w-full flex items-center gap-3 px-3 py-2.5 min-h-[44px] obs-touch-target-standard rounded-xl transition-colors ${
                                            isActive
                                                ? 'bg-gradient-to-r from-indigo-500/25 to-fuchsia-500/20 text-white border border-indigo-500/40 shadow-[0_0_16px_rgba(99,102,241,0.25)]'
                                                : 'text-slate-400 hover:bg-white/5 hover:text-slate-200 border border-transparent'
                                        }`}
                                    >
                                        <div className={isActive ? 'text-indigo-400' : 'text-slate-400'}>
                                            {item.icon}
                                        </div>
                                        <span className="font-medium text-sm">{item.label}</span>
                                        {item.id === 'inbox' && pendingCount > 0 && (
                                            <span className="ml-auto bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 text-xs font-bold px-2 py-0.5 rounded-full shrink-0">
                                                {pendingCount}
                                            </span>
                                        )}
                                    </button>
                                );
                            })}
                        </div>

                        <div className="mt-auto pt-4 border-t border-white/10 space-y-1">
                            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-2 mb-2 select-none">System</div>
                            {BOTTOM_NAVIGATION.filter((item) => {
                                if (['settings', 'security', 'users', 'audit', 'oidc-clients', 'network', 'cluster'].includes(item.id)) {
                                    return user?.role === 'admin';
                                }
                                return true;
                            }).map((item) => {
                                const isActive = activeTab === item.id;
                                const isLogout = item.id === 'logout';
                                return (
                                    <button
                                        key={item.id}
                                        type="button"
                                        onClick={() => {
                                            triggerHaptic(8, hapticFeedback);
                                            setIsMobileMenuOpen(false);
                                            if (isLogout) logout();
                                            else setActiveTab(item.id);
                                        }}
                                        className={`w-full flex items-center gap-3 px-3 py-2.5 min-h-[44px] obs-touch-target-standard rounded-xl transition-colors ${
                                            isActive
                                                ? 'bg-gradient-to-r from-indigo-500/25 to-fuchsia-500/20 text-white border border-indigo-500/40 shadow-[0_0_16px_rgba(99,102,241,0.25)]'
                                                : isLogout
                                                ? 'text-slate-400 hover:bg-rose-500/10 hover:text-rose-300 border border-transparent'
                                                : 'text-slate-400 hover:bg-white/5 hover:text-slate-200 border border-transparent'
                                        }`}
                                    >
                                        <div className={isLogout ? 'text-rose-400' : 'text-slate-400'}>{item.icon}</div>
                                        <span className="text-sm font-medium">{item.label}</span>
                                    </button>
                                );
                            })}
                        </div>
                    </aside>
                </div>
            )}

            <div
                className={`hidden md:block shrink-0 relative z-40 transition-all duration-200 ${
                    isCollapsed ? 'md:w-16' : 'md:w-52'
                }`}
            >
                <aside
                    id="desktop-sidebar-navigation"
                    className={`fixed inset-y-0 left-0 z-40 flex flex-col transition-all duration-200 ${
                        isCollapsed ? 'md:w-16' : 'md:w-52'
                    }`}
                >
                    <div className="w-full h-full obs-sidebar-surface overflow-hidden flex flex-col">
                        <div
                            className={`flex h-16 md:h-20 items-center border-b border-white/[0.08] relative shrink-0 ${
                                isCollapsed ? 'justify-center px-0' : 'px-4 justify-between'
                            }`}
                        >
                            <div className={`flex items-center ${isCollapsed ? 'justify-center' : 'gap-2.5 min-w-0'}`}>
                                <button
                                    type="button"
                                    onClick={handleToggleCollapse}
                                    aria-label={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
                                    aria-expanded={!isCollapsed}
                                    aria-controls="desktop-sidebar-navigation"
                                    title={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
                                    className="w-10 h-10 min-h-[40px] min-w-[40px] shrink-0 rounded-xl shadow-[0_0_20px_rgba(99,102,241,0.35)] relative overflow-hidden bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center obs-inline-action obs-gpu-120hz-interactive focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950"
                                >
                                    <img src="/img/aetherflow-mark.svg" alt="AetherFlow Logo" className="w-7 h-7" />
                                </button>
                                {!isCollapsed && (
                                    <div className="flex flex-col min-w-0">
                                        <span className="text-sm font-bold tracking-tight text-white whitespace-nowrap leading-tight truncate">
                                            AetherFlow
                                        </span>
                                        <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider truncate">
                                            Nexus OS
                                        </span>
                                    </div>
                                )}
                            </div>
                        </div>

                        <nav className="flex-1 px-2.5 py-3 flex flex-col overflow-y-auto no-scrollbar relative z-10">
                            <div className="space-y-1">
                                {!isCollapsed && (
                                    <div className="px-2.5 pb-1 text-xs font-semibold text-slate-400 uppercase tracking-wider whitespace-nowrap select-none">
                                        Workspace
                                    </div>
                                )}
                                {NAVIGATION.map((item) => {
                                    const isActive = activeTab === item.id;
                                    return (
                                        <button
                                            key={item.id}
                                            type="button"
                                            onClick={() => {
                                                triggerHaptic(8, hapticFeedback);
                                                setActiveTab(item.id);
                                            }}
                                            aria-label={item.label}
                                            aria-current={isActive ? 'page' : undefined}
                                            title={isCollapsed ? item.label : undefined}
                                            className={`flex items-center relative rounded-lg transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 ${
                                                !isCollapsed
                                                    ? 'w-full min-h-[40px] px-2.5 py-2 gap-3 justify-start'
                                                    : 'w-10 h-10 min-h-[40px] min-w-[40px] mx-auto justify-center'
                                            } ${
                                                isActive
                                                    ? 'bg-gradient-to-r from-indigo-500/25 to-fuchsia-500/20 text-white border border-indigo-500/40 shadow-[0_0_16px_rgba(99,102,241,0.18)]'
                                                    : 'text-slate-400 border border-transparent hover:bg-white/[0.05] hover:text-slate-200'
                                            }`}
                                        >
                                            {isActive && (
                                                <span className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-5 bg-indigo-400 rounded-r-full" />
                                            )}

                                            <div
                                                className={`shrink-0 flex items-center justify-center transition-colors ${
                                                    isActive
                                                        ? 'text-indigo-400'
                                                        : item.id === 'ai'
                                                        ? 'text-indigo-400/80'
                                                        : 'text-slate-400'
                                                }`}
                                            >
                                                {item.icon}
                                            </div>

                                            {!isCollapsed && (
                                                <span className="font-medium whitespace-nowrap text-sm tracking-tight truncate">
                                                    {item.label}
                                                </span>
                                            )}

                                            {item.id === 'inbox' && pendingCount > 0 && (
                                                !isCollapsed ? (
                                                    <span className="ml-auto bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-xs font-semibold px-2 py-0.5 rounded-full shrink-0">
                                                        {pendingCount}
                                                    </span>
                                                ) : (
                                                    <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-indigo-400" />
                                                )
                                            )}

                                            {isActive && item.id === 'ai' && (
                                                <span
                                                    className={`rounded-full bg-indigo-400 ${
                                                        !isCollapsed ? 'ml-auto w-1.5 h-1.5' : 'absolute top-1.5 right-1.5 w-1.5 h-1.5'
                                                    }`}
                                                />
                                            )}
                                        </button>
                                    );
                                })}
                            </div>

                            <div className="mt-auto pt-3 border-t border-white/[0.08] relative z-10 shrink-0 space-y-1">
                                {!isCollapsed && (
                                    <div className="px-2.5 pb-1 text-xs font-semibold text-slate-400 uppercase tracking-wider whitespace-nowrap select-none">
                                        System
                                    </div>
                                )}
                                {BOTTOM_NAVIGATION.filter((item) => {
                                    if (['settings', 'security', 'users', 'audit', 'oidc-clients', 'network', 'cluster'].includes(item.id)) {
                                        return user?.role === 'admin';
                                    }
                                    return true;
                                }).map((item) => {
                                    const isActive = activeTab === item.id;
                                    const isLogout = item.id === 'logout';
                                    return (
                                        <button
                                            key={item.id}
                                            type="button"
                                            onClick={() => {
                                                triggerHaptic(8, hapticFeedback);
                                                if (isLogout) logout();
                                                else setActiveTab(item.id);
                                            }}
                                            aria-label={item.label}
                                            aria-current={isActive ? 'page' : undefined}
                                            title={isCollapsed ? item.label : undefined}
                                            className={`flex items-center relative rounded-lg transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 ${
                                                !isCollapsed
                                                    ? 'w-full min-h-[40px] px-2.5 py-2 gap-3 justify-start'
                                                    : 'w-10 h-10 min-h-[40px] min-w-[40px] mx-auto justify-center'
                                            } ${
                                                isActive
                                                    ? 'bg-indigo-500/15 text-indigo-200 border border-indigo-500/30'
                                                    : isLogout
                                                    ? 'text-slate-400 border border-transparent hover:bg-rose-500/10 hover:text-rose-300'
                                                    : 'text-slate-400 border border-transparent hover:bg-white/[0.05] hover:text-slate-200'
                                            }`}
                                        >
                                            {isActive && (
                                                <span className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-5 bg-indigo-400 rounded-r-full" />
                                            )}
                                            <div
                                                className={`shrink-0 flex items-center justify-center transition-colors ${
                                                    isActive
                                                        ? 'text-indigo-400'
                                                        : isLogout
                                                        ? 'text-slate-400'
                                                        : 'text-slate-400'
                                                }`}
                                            >
                                                {item.icon}
                                            </div>
                                            {!isCollapsed && (
                                                <span className="text-sm font-medium tracking-tight whitespace-nowrap truncate">
                                                    {item.label}
                                                </span>
                                            )}
                                        </button>
                                    );
                                })}
                            </div>
                        </nav>
                    </div>
                </aside>
            </div>
        </>
    );
}
