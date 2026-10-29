'use client';

import { Wifi, WifiOff, Radio, User, Menu, LogOut, ChevronDown, Bell, Shield, AlertTriangle, Loader2, Database, UploadCloud, Search } from 'lucide-react';
import { NAVIGATION, BOTTOM_NAVIGATION } from './Sidebar';
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
    } = useSystemStore();
    const { connectionState, reconnectAttempt, preferredMode } = useConnectionStore();
    const { tasks } = useTaskStore();
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
            NAVIGATION.find(n => n.id === activeTab)?.label ||
            BOTTOM_NAVIGATION.find(n => n.id === activeTab)?.label ||
            activeTab
        );
    };

    // Trust States mapped to Obsidian Beacons and Tokens
    const statusConfig: Record<string, { beaconClass: string, label: string, containerClass?: string }> = {
        CONNECTED: { 
            beaconClass: 'obs-beacon-live', 
            label: preferredMode === 'websocket' ? 'Hyperspeed (Live)' : 'Nexus Poll',
            containerClass: 'border-emerald-500/30 bg-emerald-500/5'
        },
        RECONNECTING: { 
            beaconClass: 'obs-beacon-reconnecting', 
            label: `Reconnecting (${reconnectAttempt})`, 
            containerClass: 'shadow-[0_0_15px_rgba(99,102,241,0.4)] border-indigo-500/50 bg-indigo-500/5' 
        },
        DEGRADED: { 
            beaconClass: 'obs-beacon-reconnecting', 
            label: 'Degraded',
            containerClass: 'border-amber-500/30 bg-amber-500/5 text-amber-200'
        },
        STALE: { 
            beaconClass: 'obs-beacon-offline', 
            label: 'Stale Data', 
            containerClass: 'opacity-60 grayscale' 
        },
        EMPTY: { 
            beaconClass: 'obs-beacon-offline', 
            label: 'Onboarding' 
        },
        UNAUTHORIZED: { 
            beaconClass: 'obs-beacon-danger', 
            label: 'Unauthorized', 
            containerClass: 'bg-red-500/10 border-red-500/30 text-red-200' 
        },
        BLOCKED: { 
            beaconClass: 'obs-beacon-danger', 
            label: 'Pending Approval', 
            containerClass: 'bg-amber-500/10 border-amber-500/30 text-amber-200' 
        },
        CONNECTING: { 
            beaconClass: 'obs-beacon-reconnecting', 
            label: 'Connecting...', 
            containerClass: 'shadow-[0_0_15px_rgba(99,102,241,0.4)] border-indigo-500/50 bg-indigo-500/5' 
        },
        FALLBACK: { 
            beaconClass: 'obs-beacon-reconnecting', 
            label: preferredMode === 'poll' ? 'Nexus Poll' : 'Degraded (Polling)',
            containerClass: 'border-amber-500/20 bg-amber-500/5 text-amber-200'
        },
        DISCONNECTED: { 
            beaconClass: 'obs-beacon-danger', 
            label: 'Offline', 
            containerClass: 'opacity-70 grayscale' 
        },
    };

    const status = statusConfig[connectionState] || statusConfig.DISCONNECTED;

    return (
        <header className="h-20 px-6 md:px-10 flex items-center justify-between border-b border-white/[0.08] bg-slate-950/40 backdrop-blur-2xl sticky top-0 z-30">
            {/* Chromatic Bottom Rim */}
            <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-indigo-500/30 to-transparent pointer-events-none" />

            <div className="flex items-center gap-4 md:gap-6">
                <button
                    onClick={() => {
                        triggerHaptic(8, hapticFeedback);
                        setIsMobileMenuOpen(!isMobileMenuOpen);
                    }}
                    className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 -ml-2.5 md:hidden text-slate-400 hover:text-white hover:bg-white/10 rounded-xl flex items-center justify-center"
                    aria-label="Toggle Menu"
                >
                    <Menu size={24} />
                </button>
                <h2 className="text-xl md:text-2xl font-extrabold bg-gradient-to-r from-white via-indigo-200 to-slate-400 bg-clip-text text-transparent capitalize tracking-tight flex items-center gap-3">
                    {getTabLabel()}
                </h2>
            </div>

            <div className="flex items-center gap-2 md:gap-4">
                {/* Connection Trust State with Obsidian Live Beacon */}
                <div className={`hidden md:flex items-center space-x-2.5 glass-panel px-4 py-2 rounded-full mr-2 transition-all duration-200 ${status.containerClass || ''}`}>
                    <span className={status.beaconClass} />
                    <span className="text-xs font-bold tracking-wider uppercase text-slate-200">
                        {status.label}
                    </span>
                </div>

                {/* Touch-Accessible Command Palette Trigger (>= 44px touch target) */}
                <button
                    type="button"
                    onClick={() => {
                        triggerHaptic(8, hapticFeedback);
                        setIsCommandPaletteOpen(true);
                    }}
                    className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-2.5 md:px-3.5 py-2 text-slate-400 hover:text-white bg-white/[0.03] hover:bg-white/10 border border-white/10 rounded-xl"
                    aria-label="Open Command Palette"
                    title="Command Palette (Ctrl+K)"
                >
                    <Search size={18} />
                    <span className="hidden lg:inline text-xs font-medium text-slate-400">Command</span>
                    <kbd className="hidden lg:inline-block rounded bg-white/5 px-1.5 py-0.5 text-xs font-mono text-slate-400 border border-white/10">⌘K</kbd>
                </button>

                {/* Application Notifications (>= 44px touch target) */}
                <button
                    onClick={() => {
                        triggerHaptic(8, hapticFeedback);
                        toggleDrawer();
                    }}
                    className="obs-touch-target-standard obs-gpu-120hz-interactive relative p-2.5 text-slate-400 hover:text-white hover:bg-white/10 rounded-xl flex items-center justify-center"
                    aria-label="Notifications"
                >
                    <Bell size={20} />
                    {toasts.length > 0 && (
                        <span className="absolute top-2 right-2 w-2 h-2 bg-rose-500 rounded-full animate-pulse border border-black" />
                    )}
                </button>

                {/* Background Tasks Tracker (>= 44px touch target) */}
                {tasks.length > 0 && (
                    <div className="relative" ref={tasksRef}>
                        <button
                            onClick={() => setTasksOpen(!tasksOpen)}
                            className="obs-touch-target-standard relative flex items-center gap-2 px-3 py-2 bg-indigo-500/10 text-indigo-400 hover:text-indigo-300 hover:bg-indigo-500/20 border border-indigo-500/30 rounded-xl transition-all"
                            aria-label="Background Tasks"
                        >
                            <Loader2 size={18} className="animate-spin" />
                            <span className="text-xs font-bold mr-1">{tasks.filter(t => t.status === 'running').length}</span>
                        </button>
                        
                        {tasksOpen && (
                            <div className="absolute right-0 mt-2 w-72 glass-panel border border-indigo-500/30 rounded-2xl shadow-2xl overflow-hidden z-50">
                                <div className="p-3 border-b border-white/5 bg-white/[0.02]">
                                    <p className="text-xs uppercase font-bold text-slate-400 tracking-wider">Active Background Processes</p>
                                </div>
                                <div className="max-h-64 overflow-y-auto p-2 space-y-1 no-scrollbar">
                                    {tasks.map(task => (
                                        <div key={task.id} className="p-3 bg-black/40 rounded-xl border border-white/5">
                                            <div className="flex items-center gap-3 mb-2">
                                                <div className="w-8 h-8 rounded-lg bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center shrink-0">
                                                    {task.type === 'backup' ? <Database size={14} className="text-indigo-400" /> : 
                                                     task.type === 'upload' ? <UploadCloud size={14} className="text-indigo-400" /> :
                                                     <Loader2 size={14} className="text-indigo-400 animate-spin" />}
                                                </div>
                                                <div className="flex-1 min-w-0">
                                                    <p className="text-sm font-bold text-slate-200 truncate">{task.title}</p>
                                                    <p className="text-xs text-slate-500 uppercase tracking-widest">{task.status}</p>
                                                </div>
                                            </div>
                                            <div className="w-full bg-slate-800 rounded-full h-1 mt-3">
                                                <div 
                                                    className="bg-indigo-500 h-1 rounded-full transition-all duration-500" 
                                                    style={{ width: `${task.progress}%` }}
                                                />
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {/* User Profile Dropdown (>= 44px touch target) */}
                <div className="relative" ref={dropdownRef}>
                    <button 
                        onClick={() => setDropdownOpen(!dropdownOpen)}
                        className="obs-touch-target-standard flex items-center gap-2.5 rounded-full glass-button pl-1 pr-3 md:pr-4 py-1 hover:border-indigo-500/50 group transition-all"
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
                            <div className="text-xs font-bold text-slate-200">{user?.username || 'Admin'}</div>
                            <div className="text-xs text-slate-500 uppercase tracking-widest">{user?.role || 'User'}</div>
                        </div>
                        <ChevronDown size={14} className={`text-slate-500 transition-transform ${dropdownOpen ? 'rotate-180' : ''}`} />
                    </button>

                    {dropdownOpen && (
                        <div className="absolute right-0 mt-2 w-56 glass-panel border border-indigo-500/30 rounded-2xl shadow-2xl overflow-hidden z-50">
                            <div className="p-4 border-b border-white/5 bg-white/[0.02]">
                                <p className="text-sm font-bold text-slate-200">{user?.username || 'Admin'}</p>
                                <p className="text-xs text-slate-400 truncate">{user?.email || 'admin@aetherflow.local'}</p>
                            </div>
                            <div className="p-2">
                                <button
                                    onClick={logout}
                                    className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-semibold text-rose-400 hover:bg-rose-500/10 hover:text-rose-300 transition-colors obs-touch-target-standard"
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
