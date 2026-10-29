'use client';

import { useRef } from 'react';
import useSWR from 'swr';
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
    FolderUp,
    Users,
    Mail,
    ClipboardList,
    Film,
    Tv,
    ChevronLeft,
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

// Quick items for the Mobile Bottom Glass Dock (44px+ touch targets)
const MOBILE_DOCK_ITEMS: { id: TabId; label: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview', icon: <LayoutDashboard size={20} /> },
    { id: 'services', label: 'Services', icon: <Server size={20} /> },
    { id: 'mediaflow', label: 'MediaFlow', icon: <Film size={20} /> },
    { id: 'ai', label: 'FlowAI', icon: <Sparkles size={20} className="text-indigo-400" /> },
];

export default function Sidebar() {
    const { user, logout } = useAuth();
    const {
        activeTab,
        setActiveTab,
        isSidebarHovered,
        setIsSidebarHovered,
        isMobileMenuOpen,
        setIsMobileMenuOpen,
        hapticFeedback,
    } = useSystemStore();
    const { connectionState, preferredMode } = useConnectionStore();
    const { data: pendingActionsData } = useSWR<PendingActionsResponse>(
        user?.role === 'admin' ? '/api/v1/admin/actions/pending?status=pending' : null
    );
    const pendingCount = pendingActionsData?.count ?? pendingActionsData?.actions?.length ?? 0;
    const touchStartXRef = useRef<number | null>(null);

    // Map connection state to Obsidian beacon class
    const getBeaconClass = () => {
        if (connectionState === 'CONNECTED' || (connectionState === 'FALLBACK' && preferredMode === 'poll')) {
            return 'obs-beacon-live';
        }
        if (connectionState === 'RECONNECTING' || connectionState === 'CONNECTING' || connectionState === 'FALLBACK') {
            return 'obs-beacon-reconnecting';
        }
        return 'obs-beacon-danger';
    };

    const handleDrawerTouchStart = (e: React.TouchEvent) => {
        touchStartXRef.current = e.touches[0]?.clientX ?? null;
    };

    const handleDrawerTouchEnd = (e: React.TouchEvent) => {
        if (touchStartXRef.current === null) return;
        const endX = e.changedTouches[0]?.clientX ?? touchStartXRef.current;
        const deltaX = endX - touchStartXRef.current;
        touchStartXRef.current = null;
        if (deltaX < -55) {
            triggerHaptic(6, hapticFeedback);
            setIsMobileMenuOpen(false);
        }
    };

    return (
        <>
            {/* ========================================================================= */}
            {/* 1. MOBILE BOTTOM GLASS DOCK (md:hidden)                                  */}
            {/* Height: 64px, safe-area padding, >= 44px touch targets, connection beacon */}
            {/* ========================================================================= */}
            <nav 
                aria-label="Mobile Bottom Navigation"
                className="md:hidden fixed bottom-0 left-0 right-0 z-40 h-16 glass-panel border-t border-white/10 backdrop-blur-2xl px-2 pb-[max(0.5rem,env(safe-area-inset-bottom))] flex items-center justify-around"
            >
                {/* Chromatic Top Edge Accent */}
                <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-cyan-400/50 via-indigo-500/80 to-fuchsia-400/50" />

                {MOBILE_DOCK_ITEMS.map((item) => {
                    const isActive = activeTab === item.id;
                    return (
                        <button
                            key={item.id}
                            onClick={() => {
                                triggerHaptic(8, hapticFeedback);
                                setActiveTab(item.id);
                                setIsMobileMenuOpen(false);
                            }}
                            className={`flex flex-col items-center justify-center flex-1 h-full obs-touch-target-standard obs-gpu-120hz-interactive relative group ${
                                isActive ? 'text-indigo-400 font-bold' : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            {isActive && (
                                <span className="absolute top-1 w-8 h-1 bg-gradient-to-r from-indigo-500 to-fuchsia-500 rounded-full shadow-[0_0_8px_#6366f1]" />
                            )}
                            <div className={`p-1 transition-transform ${isActive ? 'scale-110 drop-shadow-[0_0_8px_rgba(99,102,241,0.5)]' : ''}`}>
                                {item.icon}
                            </div>
                            <span className="text-xs tracking-tight leading-none mt-0.5">{item.label}</span>
                        </button>
                    );
                })}

                {/* Mobile Drawer Trigger with Live Status Beacon */}
                <button
                    onClick={() => {
                        triggerHaptic(8, hapticFeedback);
                        setIsMobileMenuOpen(!isMobileMenuOpen);
                    }}
                    aria-label="Toggle Navigation Drawer"
                    className={`flex flex-col items-center justify-center flex-1 h-full obs-touch-target-standard obs-gpu-120hz-interactive relative ${
                        isMobileMenuOpen ? 'text-indigo-300' : 'text-slate-400 hover:text-slate-200'
                    }`}
                >
                    <div className="relative p-1">
                        <Menu size={20} />
                        <span 
                            className={`absolute top-0 right-0 ${getBeaconClass()}`} 
                            title={`Status: ${connectionState}`}
                        />
                    </div>
                    <span className="text-xs tracking-tight leading-none mt-0.5">More</span>
                </button>
            </nav>

            {/* ========================================================================= */}
            {/* 2. MOBILE EXPANDABLE DRAWER OVERLAY (md:hidden)                          */}
            {/* ========================================================================= */}
            {isMobileMenuOpen && (
                <div
                    className="fixed inset-0 bg-black/75 backdrop-blur-md z-50 md:hidden transition-opacity"
                    onClick={() => setIsMobileMenuOpen(false)}
                >
                    <aside 
                        className="fixed inset-y-0 left-0 w-72 max-w-[85vw] glass-panel obs-sidebar-surface bg-[#080915]/96 backdrop-blur-2xl p-5 flex flex-col z-50 border-r border-indigo-500/30 shadow-[0_24px_60px_rgba(0,0,0,0.9)] overflow-y-auto no-scrollbar obs-gpu-120hz-rail"
                        onClick={(e) => e.stopPropagation()}
                        onTouchStart={handleDrawerTouchStart}
                        onTouchEnd={handleDrawerTouchEnd}
                    >
                        {/* Drawer Header */}
                        <div className="flex items-center justify-between pb-4 mb-4 border-b border-white/10">
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-2xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center shadow-[0_0_20px_rgba(99,102,241,0.4)]">
                                    <img src="/img/af-logo.png" alt="AetherFlow Logo" className="w-[120%] h-[120%] object-cover" />
                                </div>
                                <div>
                                    <h2 className="text-lg font-bold text-white tracking-tight">AetherFlow</h2>
                                    <div className="flex items-center gap-2 mt-0.5">
                                        <span className={getBeaconClass()} />
                                        <span className="text-xs font-mono text-slate-400 uppercase">{connectionState}</span>
                                    </div>
                                </div>
                            </div>
                            <button
                                onClick={() => setIsMobileMenuOpen(false)}
                                className="obs-touch-target-standard p-2 rounded-xl text-slate-400 hover:text-white hover:bg-white/10 obs-gpu-120hz-interactive flex items-center justify-center"
                                aria-label="Close Navigation Drawer"
                            >
                                <X size={20} />
                            </button>
                        </div>

                        {/* Navigation Items (All touch targets >= 44px) */}
                        <div className="text-xs font-bold text-slate-500 uppercase tracking-widest px-2 mb-2">Nexus Navigation</div>
                        <div className="space-y-1 mb-6">
                            {NAVIGATION.map((item) => {
                                const isActive = activeTab === item.id;
                                return (
                                    <button
                                        key={item.id}
                                        onClick={() => {
                                            triggerHaptic(8, hapticFeedback);
                                            setActiveTab(item.id);
                                            setIsMobileMenuOpen(false);
                                        }}
                                        className={`w-full flex items-center gap-3.5 px-3 py-2.5 min-h-[44px] obs-touch-target-standard rounded-xl obs-gpu-120hz-interactive ${
                                            isActive
                                                ? 'bg-gradient-to-r from-indigo-500/25 to-fuchsia-500/20 text-white border border-indigo-500/40 shadow-[0_0_16px_rgba(99,102,241,0.25)]'
                                                : 'text-slate-400 hover:bg-white/5 hover:text-slate-200'
                                        }`}
                                    >
                                        <div className={isActive ? 'text-indigo-400 drop-shadow-[0_0_8px_rgba(129,140,248,0.5)]' : ''}>
                                            {item.icon}
                                        </div>
                                        <span className="font-semibold text-sm">{item.label}</span>
                                    </button>
                                );
                            })}
                        </div>

                        {/* Admin Section */}
                        <div className="mt-auto pt-4 border-t border-white/10 space-y-1">
                            <div className="text-xs font-bold text-slate-500 uppercase tracking-widest px-2 mb-2">System</div>
                            {BOTTOM_NAVIGATION.filter(item => {
                                if (['settings', 'security', 'users', 'audit', 'oidc-clients', 'network', 'cluster'].includes(item.id)) {
                                    return user?.role === 'admin';
                                }
                                return true;
                            }).map((item) => (
                                <button
                                    key={item.id}
                                    onClick={() => {
                                        triggerHaptic(8, hapticFeedback);
                                        setIsMobileMenuOpen(false);
                                        if (item.id === 'logout') logout();
                                        else setActiveTab(item.id);
                                    }}
                                    className={`w-full flex items-center gap-3.5 px-3 py-2.5 min-h-[44px] obs-touch-target-standard rounded-xl text-slate-400 hover:text-slate-200 hover:bg-white/5 obs-gpu-120hz-interactive ${
                                        activeTab === item.id ? 'bg-gradient-to-r from-indigo-500/20 to-fuchsia-500/20 text-white' : ''
                                    }`}
                                >
                                    <div className="text-slate-400">{item.icon}</div>
                                    <span className="text-sm font-semibold">{item.label}</span>
                                </button>
                            ))}
                        </div>
                    </aside>
                </div>
            )}

            {/* ========================================================================= */}
            {/* 3. TABLET & DESKTOP DOCKED RAIL (md:block)                               */}
            {/* Spacer syncs width with rail so expanded sidebar never covers content    */}
            {/* ========================================================================= */}
            <div
                className={`hidden md:block shrink-0 relative z-50 obs-gpu-120hz-rail ${
                    isSidebarHovered ? 'md:w-64' : 'md:w-[4.5rem]'
                }`}
            >
                <aside
                    className={`fixed inset-y-0 left-0 z-50 flex flex-col obs-gpu-120hz-rail ${
                        isSidebarHovered ? 'md:w-64' : 'md:w-[4.5rem]'
                    }`}
                    onMouseEnter={() => setIsSidebarHovered(true)}
                    onMouseLeave={() => setIsSidebarHovered(false)}
                >
                    <div className="w-full h-full obs-sidebar-surface overflow-hidden flex flex-col">
                        {/* Top Header Area — flush height h-20 aligned with Header.tsx */}
                        <div
                            className={`flex h-20 items-center border-b border-white/[0.06] relative shrink-0 ${
                                isSidebarHovered ? 'px-4 justify-between' : 'justify-center px-0'
                            }`}
                        >
                            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-indigo-500/40 via-purple-500/60 to-transparent" />

                            <div className={`flex items-center ${isSidebarHovered ? 'gap-3' : 'justify-center'}`}>
                                <button
                                    type="button"
                                    onClick={() => {
                                        triggerHaptic(6, hapticFeedback);
                                        setIsSidebarHovered(!isSidebarHovered);
                                    }}
                                    aria-label={isSidebarHovered ? 'Collapse Sidebar' : 'Expand Sidebar'}
                                    title={isSidebarHovered ? 'Collapse Sidebar' : 'Expand Sidebar'}
                                    className="w-10 h-10 shrink-0 rounded-xl shadow-[0_0_20px_rgba(99,102,241,0.35)] relative overflow-hidden bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center obs-inline-action obs-gpu-120hz-interactive focus:outline-none focus-visible:outline-none"
                                >
                                    <img src="/img/af-logo.png" alt="AetherFlow Logo" className="w-[125%] h-[125%] object-cover" />
                                </button>
                                {isSidebarHovered && (
                                    <div className="flex flex-col min-w-0">
                                        <h1 className="text-base font-bold tracking-tight text-white whitespace-nowrap leading-tight">
                                            AetherFlow
                                        </h1>
                                        <div className="flex items-center gap-1.5 mt-0.5">
                                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_#34d399]" />
                                            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider truncate">
                                                Nexus OS
                                            </span>
                                        </div>
                                    </div>
                                )}
                            </div>

                            {isSidebarHovered && (
                                <button
                                    type="button"
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        triggerHaptic(6, hapticFeedback);
                                        setIsSidebarHovered(false);
                                    }}
                                    aria-label="Collapse Sidebar Rail"
                                    className="w-7 h-7 obs-inline-action rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] text-slate-400 hover:text-white flex items-center justify-center transition-colors focus:outline-none focus-visible:outline-none"
                                >
                                    <ChevronLeft size={15} />
                                </button>
                            )}
                        </div>

                        {/* Primary Navigation List */}
                        <nav className="flex-1 px-2.5 py-3 space-y-1 overflow-y-auto no-scrollbar relative z-10">
                            {isSidebarHovered && (
                                <div className="px-2.5 pb-1.5 text-xs font-bold text-slate-500 uppercase tracking-widest whitespace-nowrap">
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
                                        title={!isSidebarHovered ? item.label : undefined}
                                        className={`flex items-center relative rounded-xl obs-gpu-120hz-interactive group obs-inline-action focus:outline-none focus-visible:outline-none ${
                                            isSidebarHovered
                                                ? 'w-full px-3 py-2.5 gap-3 justify-start'
                                                : 'w-11 h-11 mx-auto justify-center'
                                        } ${
                                            isActive
                                                ? 'bg-indigo-500/[0.16] text-white border border-indigo-500/30 shadow-[0_0_16px_rgba(99,102,241,0.18)]'
                                                : 'text-slate-400 border border-transparent hover:bg-white/[0.05] hover:text-slate-200'
                                        }`}
                                    >
                                        {isActive && (
                                            <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-5 bg-indigo-400 rounded-r-full shadow-[0_0_8px_#6366f1]" />
                                        )}

                                        <div
                                            className={`shrink-0 flex items-center justify-center transition-colors ${
                                                isActive
                                                    ? 'text-indigo-400 drop-shadow-[0_0_8px_rgba(129,140,248,0.45)]'
                                                    : item.id === 'ai'
                                                    ? 'text-indigo-400/80 group-hover:text-indigo-300'
                                                    : 'text-slate-400 group-hover:text-slate-200'
                                            }`}
                                        >
                                            {item.icon}
                                        </div>

                                        {isSidebarHovered && (
                                            <span className="font-medium whitespace-nowrap text-sm tracking-tight truncate">
                                                {item.label}
                                            </span>
                                        )}

                                        {item.id === 'inbox' && pendingCount > 0 && (
                                            isSidebarHovered ? (
                                                <span className="ml-auto bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 text-xs font-bold px-2 py-0.5 rounded-full shrink-0">
                                                    {pendingCount}
                                                </span>
                                            ) : (
                                                <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-indigo-400 shadow-[0_0_8px_#818CF8]" />
                                            )
                                        )}

                                        {isActive && item.id === 'ai' && (
                                            <div
                                                className={`rounded-full bg-indigo-400 shadow-[0_0_8px_#818CF8] animate-pulse ${
                                                    isSidebarHovered ? 'ml-auto w-1.5 h-1.5' : 'absolute top-1.5 right-1.5 w-1.5 h-1.5'
                                                }`}
                                            />
                                        )}
                                    </button>
                                );
                            })}
                        </nav>

                        {/* Bottom System & Admin Navigation — continuous surface, no opaque black overlay */}
                        <div className="px-2.5 py-3 border-t border-white/[0.06] relative z-10 shrink-0 space-y-1">
                            {isSidebarHovered && (
                                <div className="px-2.5 pb-1 text-xs font-bold text-slate-500 uppercase tracking-widest whitespace-nowrap">
                                    System
                                </div>
                            )}
                            {BOTTOM_NAVIGATION.filter(item => {
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
                                        title={!isSidebarHovered ? item.label : undefined}
                                        className={`flex items-center relative rounded-xl obs-gpu-120hz-interactive group obs-inline-action focus:outline-none focus-visible:outline-none ${
                                            isSidebarHovered
                                                ? 'w-full px-3 py-2.5 gap-3 justify-start'
                                                : 'w-11 h-11 mx-auto justify-center'
                                        } ${
                                            isActive
                                                ? 'bg-indigo-500/[0.16] text-white border border-indigo-500/30 shadow-[0_0_16px_rgba(99,102,241,0.18)]'
                                                : isLogout
                                                ? 'text-slate-400 border border-transparent hover:bg-rose-500/10 hover:text-rose-300'
                                                : 'text-slate-400 border border-transparent hover:bg-white/[0.05] hover:text-slate-200'
                                        }`}
                                    >
                                        {isActive && (
                                            <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-5 bg-indigo-400 rounded-r-full shadow-[0_0_8px_#6366f1]" />
                                        )}
                                        <div
                                            className={`shrink-0 flex items-center justify-center transition-colors ${
                                                isActive
                                                    ? 'text-indigo-400 drop-shadow-[0_0_8px_rgba(129,140,248,0.45)]'
                                                    : isLogout
                                                    ? 'text-slate-400 group-hover:text-rose-400'
                                                    : 'text-slate-400 group-hover:text-slate-200'
                                            }`}
                                        >
                                            {item.icon}
                                        </div>
                                        {isSidebarHovered && (
                                            <span className="text-sm font-medium tracking-tight whitespace-nowrap truncate">
                                                {item.label}
                                            </span>
                                        )}
                                    </button>
                                );
                            })}
                        </div>
                    </div>
                </aside>
            </div>
        </>
    );
}
