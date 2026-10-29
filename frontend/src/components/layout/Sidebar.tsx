'use client';

import { useRef } from 'react';
import { TabId } from '@/types/dashboard';
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
    ChevronLeft,
    Menu,
    X,
    Radio,
    Boxes
} from 'lucide-react';

export const NAVIGATION = [
    { id: 'overview' as TabId, label: 'Overview', icon: <LayoutDashboard size={20} /> },
    { id: 'inbox' as TabId, label: 'Approval Inbox', icon: <Mail size={20} /> },
    { id: 'services' as TabId, label: 'Services', icon: <Server size={20} /> },
    { id: 'marketplace' as TabId, label: 'Marketplace', icon: <Store size={20} /> },
    { id: 'fileshare' as TabId, label: 'File Share', icon: <FolderUp size={20} /> },
    { id: 'mediaflow' as TabId, label: 'MediaFlow', icon: <Film size={20} className="text-zinc-400 group-hover:text-zinc-200 transition-colors" /> },
    { id: 'ai' as TabId, label: 'FlowAI', icon: <Sparkles size={20} className="text-indigo-400 group-hover:text-indigo-300 transition-colors" /> },
];

export const BOTTOM_NAVIGATION = [
    { id: 'network' as TabId, label: 'Network', icon: <Radio size={18} /> },
    { id: 'cluster' as TabId, label: 'Cluster', icon: <Boxes size={18} /> },
    { id: 'users' as TabId, label: 'Users', icon: <Users size={18} /> },
    { id: 'audit' as TabId, label: 'Audit Trail', icon: <ClipboardList size={18} /> },
    { id: 'settings' as TabId, label: 'Settings', icon: <Settings size={18} /> },
    { id: 'logout' as TabId, label: 'Log Out', icon: <LogOut size={18} /> },
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
                        className="fixed inset-y-0 left-0 w-72 max-w-[85vw] glass-panel p-5 flex flex-col z-50 border-r border-indigo-500/30 shadow-[0_24px_60px_rgba(0,0,0,0.9)] overflow-y-auto no-scrollbar obs-gpu-120hz-rail"
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
            {/* 3. TABLET & DESKTOP GLASS RAIL (md:block)                                */}
            {/* Ghost Spacer holds w-20 in document flow so the page never shifts        */}
            {/* ========================================================================= */}
            <div className="hidden md:block md:sticky md:top-4 z-50 shrink-0 md:w-20 md:h-[calc(100vh-2rem)]">
                <aside
                    className={`fixed inset-y-0 left-0 md:absolute md:top-0 md:bottom-0 md:h-full flex flex-col obs-gpu-120hz-rail ${
                        isSidebarHovered ? 'md:w-64 md:shadow-[0_20px_50px_rgba(0,0,0,0.8)]' : 'md:w-20 md:shadow-none'
                    }`}
                    onMouseEnter={() => setIsSidebarHovered(true)}
                    onMouseLeave={() => setIsSidebarHovered(false)}
                >
                    <div className="absolute inset-0 glass-panel rounded-none md:rounded-2xl overflow-hidden flex flex-col">
                        {/* Header Area with Chromatic Top Accent */}
                        <div className="flex h-20 items-center px-5 border-b border-white/5 relative shrink-0">
                            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-cyan-400/40 via-indigo-500/80 to-fuchsia-400/40" />

                            <div className="flex items-center gap-4 w-full relative z-10 mt-1">
                                <button
                                    type="button"
                                    onClick={() => {
                                        triggerHaptic(6, hapticFeedback);
                                        setIsSidebarHovered(!isSidebarHovered);
                                    }}
                                    aria-label={isSidebarHovered ? 'Collapse Sidebar' : 'Expand Sidebar'}
                                    title={isSidebarHovered ? 'Collapse Sidebar' : 'Expand Sidebar'}
                                    className="w-10 h-10 shrink-0 rounded-2xl shadow-[0_0_24px_rgba(99,102,241,0.5)] relative overflow-hidden bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center obs-inline-action obs-gpu-120hz-interactive"
                                >
                                    <img src="/img/af-logo.png" alt="AetherFlow Logo" className="w-[130%] h-[130%] object-cover" />
                                </button>
                                <h1 className={`text-xl font-bold tracking-tight bg-gradient-to-r from-slate-100 to-slate-400 bg-clip-text text-transparent transition-opacity duration-200 whitespace-nowrap ${
                                    isSidebarHovered ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden'
                                }`}>
                                    AetherFlow
                                </h1>
                            </div>
                        </div>

                        {/* Navigation List */}
                        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto no-scrollbar relative z-10">
                            <div className={`px-4 pb-1.5 text-[10px] font-bold text-slate-500 uppercase tracking-widest transition-opacity duration-200 whitespace-nowrap ${
                                isSidebarHovered ? 'opacity-100' : 'opacity-0'
                            }`}>
                                Nexus
                            </div>
                            {NAVIGATION.map((item) => {
                                const isActive = activeTab === item.id;
                                return (
                                    <button
                                        key={item.id}
                                        onClick={() => {
                                            triggerHaptic(8, hapticFeedback);
                                            setActiveTab(item.id);
                                        }}
                                        className={`w-full flex items-center relative gap-3 px-2 py-1.5 rounded-xl obs-gpu-120hz-interactive group overflow-hidden obs-inline-action ${
                                            isActive
                                                ? 'bg-gradient-to-r from-indigo-500/20 to-purple-500/20 text-white shadow-[0_0_15px_rgba(99,102,241,0.2)]'
                                                : 'text-slate-400 hover:bg-white/5 hover:text-slate-200'
                                        }`}
                                    >
                                        <div className={`absolute left-0 top-1/2 -translate-y-1/2 w-1 h-3/5 bg-indigo-500 rounded-r-full transition-all duration-200 shadow-[0_0_8px_#6366f1] ${
                                            isActive ? 'scale-y-100 opacity-100' : 'scale-y-0 opacity-0'
                                        }`} />

                                        <div className={`w-10 h-9 shrink-0 flex items-center justify-center transition-colors ${
                                            isActive ? 'text-indigo-400 drop-shadow-[0_0_8px_rgba(129,140,248,0.5)]' : 'group-hover:text-slate-300'
                                        }`}>
                                            {item.icon}
                                        </div>

                                        <span className={`font-semibold transition-all duration-200 whitespace-nowrap text-sm tracking-wide ${
                                            isSidebarHovered ? 'opacity-100 translate-x-0' : 'opacity-0 md:-translate-x-4 pointer-events-none'
                                        }`}>
                                            {item.label}
                                        </span>

                                        {isActive && item.id === 'ai' && (
                                            <div className="absolute right-4 w-1.5 h-1.5 rounded-full bg-indigo-400 shadow-[0_0_8px_#818CF8] animate-pulse" />
                                        )}
                                    </button>
                                );
                            })}
                        </nav>

                        {/* Bottom Admin Navigation */}
                        <div className="p-3 border-t border-white/5 bg-slate-950/50 backdrop-blur-md relative z-10 shrink-0 space-y-0.5">
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
                                        if (item.id === 'logout') logout();
                                        else setActiveTab(item.id);
                                    }}
                                    className={`w-full flex items-center gap-3 px-2 py-1 rounded-xl text-slate-400 hover:text-slate-200 hover:bg-white/5 obs-gpu-120hz-interactive group overflow-hidden obs-inline-action ${
                                        activeTab === item.id ? 'bg-gradient-to-r from-indigo-500/20 to-purple-500/20 text-white shadow-[0_0_15px_rgba(99,102,241,0.2)]' : ''
                                    }`}
                                >
                                    <div className="w-10 h-8 shrink-0 flex items-center justify-center group-hover:scale-110 transition-transform">
                                        {item.icon}
                                    </div>
                                    <span className={`text-sm font-semibold tracking-wide transition-all duration-200 whitespace-nowrap ${
                                        isSidebarHovered ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4 pointer-events-none'
                                    }`}>
                                        {item.label}
                                    </span>
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Floating Collapse Button on right edge (vertically centered, never overlaps nav items) */}
                    <button
                        type="button"
                        className={`hidden md:flex absolute -right-3.5 top-1/2 -translate-y-1/2 w-7 h-7 obs-inline-action rounded-full bg-slate-800 border border-slate-700 text-slate-400 hover:text-white items-center justify-center shadow-lg transition-all duration-200 z-[60] ${
                            isSidebarHovered ? 'opacity-100 scale-100' : 'opacity-0 scale-50 pointer-events-none'
                        }`}
                        onClick={(e) => {
                            e.stopPropagation();
                            triggerHaptic(6, hapticFeedback);
                            setIsSidebarHovered(!isSidebarHovered);
                        }}
                        aria-label={isSidebarHovered ? 'Collapse Sidebar Rail' : 'Expand Sidebar Rail'}
                    >
                        <ChevronLeft size={16} />
                    </button>
                </aside>
            </div>
        </>
    );
}
