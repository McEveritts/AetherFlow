'use client';

import { User, Menu, LogOut, ChevronDown, Bell, Loader2, Database, UploadCloud, Search } from 'lucide-react';
import { NAVIGATION, BOTTOM_NAVIGATION } from './Sidebar';
import { useShallow } from 'zustand/react/shallow';
import { useSystemStore } from '@/store/useSystemStore';
import { useConnectionStore } from '@/store/useConnectionStore';
import { useTaskStore } from '@/store/useTaskStore';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/contexts/ToastContext';
import { triggerHaptic } from '@/lib/design';
import { useState, useRef, useEffect } from 'react';
import Image from 'next/image';

export default function Header() {
    const {
        activeTab,
        isMobileMenuOpen,
        setIsMobileMenuOpen,
        setIsCommandPaletteOpen,
        hapticFeedback,
    } = useSystemStore(
        useShallow((state) => ({
            activeTab: state.activeTab,
            isMobileMenuOpen: state.isMobileMenuOpen,
            setIsMobileMenuOpen: state.setIsMobileMenuOpen,
            setIsCommandPaletteOpen: state.setIsCommandPaletteOpen,
            hapticFeedback: state.hapticFeedback,
        }))
    );
    const { connectionState, reconnectAttempt } = useConnectionStore(
        useShallow((state) => ({
            connectionState: state.connectionState,
            reconnectAttempt: state.reconnectAttempt,
        }))
    );
    const tasks = useTaskStore((state) => state.tasks);
    const { user, logout } = useAuth();
    const { toasts, toggleDrawer } = useToast();
    const [dropdownOpen, setDropdownOpen] = useState(false);
    const [tasksOpen, setTasksOpen] = useState(false);
    const dropdownRef = useRef<HTMLDivElement>(null);
    const tasksRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const handleClickOutside = (event: PointerEvent | MouseEvent) => {
            if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
                setDropdownOpen(false);
            }
            if (tasksRef.current && !tasksRef.current.contains(event.target as Node)) {
                setTasksOpen(false);
            }
        };
        document.addEventListener('pointerdown', handleClickOutside);
        return () => document.removeEventListener('pointerdown', handleClickOutside);
    }, []);

    const getTabLabel = () => {
        return (
            NAVIGATION.find((item) => item.id === activeTab)?.label ||
            BOTTOM_NAVIGATION.find((item) => item.id === activeTab)?.label ||
            activeTab
        );
    };

    const getSectionLabel = () => {
        const isSystemTab = BOTTOM_NAVIGATION.some((item) => item.id === activeTab);
        return isSystemTab ? 'System' : 'Workspace';
    };

    const statusConfig: Record<string, { beaconClass: string, label: string, containerClass?: string }> = {
        CONNECTED: {
            beaconClass: 'obs-beacon-live',
            label: 'Connected',
            containerClass: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
        },
        RECONNECTING: {
            beaconClass: 'obs-beacon-reconnecting',
            label: `Reconnecting (${reconnectAttempt})`,
            containerClass: 'border-amber-500/30 bg-amber-500/10 text-amber-300'
        },
        DEGRADED: {
            beaconClass: 'obs-beacon-reconnecting',
            label: 'Degraded',
            containerClass: 'border-amber-500/30 bg-amber-500/10 text-amber-300'
        },
        STALE: {
            beaconClass: 'obs-beacon-offline',
            label: 'Stale Data',
            containerClass: 'border-slate-700 bg-slate-800/40 text-slate-400'
        },
        EMPTY: {
            beaconClass: 'obs-beacon-offline',
            label: 'Initial Setup',
            containerClass: 'border-slate-700 bg-slate-800/40 text-slate-400'
        },
        UNAUTHORIZED: {
            beaconClass: 'obs-beacon-danger',
            label: 'Unauthorized',
            containerClass: 'bg-rose-500/10 border-rose-500/30 text-rose-300'
        },
        BLOCKED: {
            beaconClass: 'obs-beacon-danger',
            label: 'Pending Approval',
            containerClass: 'bg-amber-500/10 border-amber-500/30 text-amber-300'
        },
        CONNECTING: {
            beaconClass: 'obs-beacon-reconnecting',
            label: 'Connecting...',
            containerClass: 'border-indigo-500/30 bg-indigo-500/10 text-indigo-300'
        },
        FALLBACK: {
            beaconClass: 'obs-beacon-reconnecting',
            label: 'HTTP Fallback',
            containerClass: 'border-amber-500/30 bg-amber-500/10 text-amber-300'
        },
        DISCONNECTED: {
            beaconClass: 'obs-beacon-danger',
            label: 'Offline',
            containerClass: 'border-slate-700 bg-slate-800/40 text-slate-400'
        },
        OFFLINE: {
            beaconClass: 'obs-beacon-danger',
            label: 'Offline',
            containerClass: 'border-slate-700 bg-slate-800/40 text-slate-400'
        },
    };

    const status = statusConfig[connectionState] || statusConfig.DISCONNECTED;

    return (
        <header className="h-16 md:h-20 px-3 sm:px-4 md:px-8 flex items-center justify-between border-b border-white/[0.08] bg-[#0a0e18]/95 backdrop-blur-md sticky top-0 z-30 min-w-0">
            <div className="flex items-center gap-2 sm:gap-3 md:gap-5 min-w-0 flex-1 mr-2">
                <button
                    type="button"
                    onClick={() => {
                        triggerHaptic(8, hapticFeedback);
                        setIsMobileMenuOpen(!isMobileMenuOpen);
                    }}
                    className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 -ml-2 md:hidden text-slate-400 hover:text-white hover:bg-white/10 rounded-xl flex items-center justify-center shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
                    aria-label="Toggle Menu"
                    aria-expanded={isMobileMenuOpen}
                    aria-controls="mobile-navigation-drawer"
                >
                    <Menu size={22} />
                </button>
                <div className="flex flex-col justify-center min-w-0 flex-1">
                    <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-xs font-medium text-slate-400 min-w-0">
                        <div className="md:hidden flex items-center gap-1.5 min-w-0 flex-wrap">
                            <span className={`${status.beaconClass} shrink-0`} aria-hidden="true" />
                            <span className="text-slate-300 break-words leading-tight">
                                {status.label}
                            </span>
                        </div>
                        <span className="hidden md:inline shrink-0">AetherFlow</span>
                        <span className="hidden md:inline text-slate-600 select-none">/</span>
                        <span className="hidden md:inline truncate">{getSectionLabel()}</span>
                    </nav>
                    <h1 className="text-base sm:text-lg md:text-2xl font-bold text-slate-100 tracking-tight leading-tight truncate">
                        {getTabLabel()}
                    </h1>
                </div>
            </div>

            <div className="flex items-center gap-1.5 sm:gap-2 md:gap-4 shrink-0">
                <div className={`hidden md:flex items-center space-x-2.5 px-3.5 py-1.5 rounded-full border text-xs font-medium transition-colors ${status.containerClass || ''}`}>
                    <span className={status.beaconClass} />
                    <span className="tracking-wide">
                        {status.label}
                    </span>
                </div>

                <button
                    type="button"
                    onClick={() => {
                        triggerHaptic(8, hapticFeedback);
                        setIsCommandPaletteOpen(true);
                    }}
                    className="min-h-[40px] obs-gpu-120hz-interactive flex items-center gap-2 px-2.5 sm:px-3 py-2 text-slate-300 hover:text-white bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 rounded-xl transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
                    aria-label="Open Command Palette"
                    title="Command Palette (Ctrl+K)"
                >
                    <Search size={16} className="text-slate-400" />
                    <span className="hidden lg:inline text-xs font-medium text-slate-300">Command</span>
                    <kbd className="hidden lg:inline-block rounded bg-white/5 px-1.5 py-0.5 text-xs font-mono text-slate-400 border border-white/10">⌘K</kbd>
                </button>

                <button
                    type="button"
                    onClick={() => {
                        triggerHaptic(8, hapticFeedback);
                        toggleDrawer();
                    }}
                    className="min-h-[40px] min-w-[40px] obs-gpu-120hz-interactive relative p-2.5 text-slate-300 hover:text-white hover:bg-white/[0.08] border border-transparent hover:border-white/10 rounded-xl flex items-center justify-center transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
                    aria-label="Notifications"
                >
                    <Bell size={18} />
                    {toasts.length > 0 && (
                        <span className="absolute top-2 right-2 w-2 h-2 bg-indigo-500 rounded-full animate-pulse" />
                    )}
                </button>

                {tasks.length > 0 && (
                    <div className="relative" ref={tasksRef}>
                        <button
                            type="button"
                            onClick={() => setTasksOpen(!tasksOpen)}
                            className="min-h-[40px] relative flex items-center gap-2 px-3 py-2 bg-indigo-500/10 text-indigo-300 hover:text-white hover:bg-indigo-500/20 border border-indigo-500/30 rounded-xl transition-colors"
                            aria-label="Background Tasks"
                        >
                            <Loader2 size={16} className="animate-spin text-indigo-400" />
                            <span className="text-xs font-bold mr-1">{tasks.filter((taskItem) => taskItem.status === 'running').length}</span>
                        </button>

                        {tasksOpen && (
                            <div className="absolute right-0 mt-2 w-72 glass-panel border border-indigo-500/30 rounded-2xl shadow-2xl overflow-hidden z-50">
                                <div className="p-3 border-b border-white/5 bg-white/[0.02]">
                                    <p className="text-xs uppercase font-bold text-slate-400 tracking-wider">Active Background Processes</p>
                                </div>
                                <div className="max-h-64 overflow-y-auto p-2 space-y-1 no-scrollbar">
                                    {tasks.map((taskItem) => (
                                        <div key={taskItem.id} className="p-3 bg-black/40 rounded-xl border border-white/5">
                                            <div className="flex items-center gap-3 mb-2">
                                                <div className="w-8 h-8 rounded-lg bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center shrink-0">
                                                    {taskItem.type === 'backup' ? <Database size={14} className="text-indigo-400" /> :
                                                     taskItem.type === 'upload' ? <UploadCloud size={14} className="text-indigo-400" /> :
                                                     <Loader2 size={14} className="text-indigo-400 animate-spin" />}
                                                </div>
                                                <div className="flex-1 min-w-0">
                                                    <p className="text-sm font-bold text-slate-200 truncate">{taskItem.title}</p>
                                                    <p className="text-xs text-slate-500 uppercase tracking-widest">{taskItem.status}</p>
                                                </div>
                                            </div>
                                            <div className="w-full bg-slate-800 rounded-full h-1 mt-3">
                                                <div 
                                                    className="bg-indigo-500 h-1 rounded-full transition-all duration-500" 
                                                    style={{ width: `${taskItem.progress}%` }}
                                                />
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                )}

                <div className="relative" ref={dropdownRef}>
                    <button 
                        type="button"
                        onClick={() => setDropdownOpen(!dropdownOpen)}
                        className="min-h-[40px] flex items-center gap-2.5 rounded-full bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 hover:border-indigo-500/40 pl-1 pr-3 md:pr-4 py-1 transition-colors group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
                        aria-label="User Menu"
                    >
                        <div className="relative h-8 w-8 md:h-9 md:w-9 rounded-full bg-slate-900 border border-indigo-400/30 flex items-center justify-center overflow-hidden">
                            {user?.avatar_url ? (
                                <Image src={user.avatar_url} alt="Avatar" fill sizes="(max-width: 768px) 32px, 36px" className="object-cover" />
                            ) : (
                                <User size={16} className="text-slate-400 group-hover:text-indigo-300 transition-colors" />
                            )}
                        </div>
                        <div className="hidden md:block text-left">
                            <div className="text-xs font-semibold text-slate-200">{user?.username || 'Admin'}</div>
                            <div className="text-[11px] text-slate-400 uppercase tracking-wider">{user?.role || 'User'}</div>
                        </div>
                        <ChevronDown size={14} className={`text-slate-400 transition-transform ${dropdownOpen ? 'rotate-180' : ''}`} />
                    </button>

                    {dropdownOpen && (
                        <div className="absolute right-0 mt-2 w-56 glass-panel border border-indigo-500/30 rounded-2xl shadow-2xl overflow-hidden z-50">
                            <div className="p-4 border-b border-white/5 bg-white/[0.02]">
                                <p className="text-sm font-bold text-slate-200">{user?.username || 'Admin'}</p>
                                <p className="text-xs text-slate-400 truncate">{user?.email || 'admin@aetherflow.local'}</p>
                            </div>
                            <div className="p-2">
                                <button
                                    type="button"
                                    onClick={logout}
                                    className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-semibold text-rose-400 hover:bg-rose-500/10 hover:text-rose-300 transition-colors min-h-[40px]"
                                >
                                    <LogOut size={16} />
                                    Sign Out
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </header>
    );
}
