import { Wifi, WifiOff, Radio, User, Menu, LogOut, ChevronDown, Bell, Shield, AlertTriangle, Loader2, Database, UploadCloud } from 'lucide-react';
import { NAVIGATION, BOTTOM_NAVIGATION } from './Sidebar';
import { useSystemStore } from '@/store/useSystemStore';
import { useConnectionStore } from '@/store/useConnectionStore';
import { useTaskStore } from '@/store/useTaskStore';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/contexts/ToastContext';
import { useState, useRef, useEffect } from 'react';
import Image from 'next/image';

export default function Header() {
    const { activeTab, isMobileMenuOpen, setIsMobileMenuOpen } = useSystemStore();
    const { connectionState, reconnectAttempt, preferredMode } = useConnectionStore();
    const { tasks } = useTaskStore();
    const { user, logout } = useAuth();
    const { toasts, toggleDrawer } = useToast();
    const [dropdownOpen, setDropdownOpen] = useState(false);
    const [tasksOpen, setTasksOpen] = useState(false);
    const dropdownRef = useRef<HTMLDivElement>(null);
    const tasksRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
                setDropdownOpen(false);
            }
            if (tasksRef.current && !tasksRef.current.contains(event.target as Node)) {
                setTasksOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const getTabLabel = () => {
        if (activeTab === 'settings' || activeTab === 'security' || activeTab === 'logout') {
            return BOTTOM_NAVIGATION.find(n => n.id === activeTab)?.label;
        }
        return NAVIGATION.find(n => n.id === activeTab)?.label;
    };

    // Phase 13: Trust States
    const statusConfig: Record<string, { icon: React.ReactNode, label: string, containerClass?: string }> = {
        CONNECTED: { icon: <Wifi size={16} className="text-emerald-400" />, label: 'Connected' },
        RECONNECTING: { 
            icon: <WifiOff size={16} className="text-indigo-400 animate-pulse" />, 
            label: `Reconnecting (${reconnectAttempt})`, 
            containerClass: 'shadow-[0_0_15px_rgba(99,102,241,0.4)] border-indigo-500/50 bg-indigo-500/5' 
        },
        DEGRADED: { icon: <Radio size={16} className="text-amber-400" />, label: 'Degraded' },
        STALE: { icon: <Radio size={16} className="text-slate-500" />, label: 'Stale Data', containerClass: 'opacity-50 grayscale' },
        EMPTY: { icon: <Radio size={16} className="text-slate-400" />, label: 'Onboarding' },
        UNAUTHORIZED: { 
            icon: <Shield size={16} className="text-red-500" />, 
            label: 'Unauthorized', 
            containerClass: 'bg-red-500/10 border-red-500/30 text-red-200' 
        },
        BLOCKED: { 
            icon: <AlertTriangle size={16} className="text-amber-500" />, 
            label: 'Pending Approval', 
            containerClass: 'bg-amber-500/10 border-amber-500/30 text-amber-200' 
        },
        
        // Mappings for existing basic store states
        CONNECTING: { 
            icon: <Radio size={16} className="text-indigo-400 animate-pulse" />, 
            label: 'Connecting...', 
            containerClass: 'shadow-[0_0_15px_rgba(99,102,241,0.4)] border-indigo-500/50 bg-indigo-500/5' 
        },
        FALLBACK: { 
            icon: <Radio size={16} className="text-amber-400" />, 
            label: preferredMode === 'poll' ? 'Nexus Poll' : 'Degraded (Polling)',
            containerClass: preferredMode === 'poll' ? 'border-amber-500/20 bg-amber-500/5' : ''
        },
        DISCONNECTED: { icon: <WifiOff size={16} className="text-slate-500" />, label: 'Stale (Offline)', containerClass: 'opacity-50 grayscale' },
    };

    // Override CONNECTED logic if in Poll mode
    if (connectionState === 'CONNECTED' || (connectionState === 'FALLBACK' && preferredMode === 'poll')) {
        statusConfig.CONNECTED = { 
            icon: preferredMode === 'websocket' ? <Wifi size={16} className="text-emerald-400" /> : <Radio size={16} className="text-amber-400 animate-pulse" />, 
            label: preferredMode === 'websocket' ? 'Hyperspeed' : 'Nexus Poll' 
        };
    }

    const status = statusConfig[connectionState] || statusConfig.DISCONNECTED;

    return (
        <header className="h-20 px-6 md:px-10 flex items-center justify-between border-b border-white/[0.05] bg-slate-950/40 backdrop-blur-2xl sticky top-0 z-40">
            <div className="flex items-center gap-4 md:gap-6">
                <button
                    onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                    className="p-3 -ml-3 md:hidden text-slate-400 hover:text-white hover:bg-white/5 rounded-xl transition-all"
                    aria-label="Toggle Menu"
                >
                    <Menu size={24} />
                </button>
                <h2 className="text-xl md:text-2xl font-extrabold bg-gradient-to-r from-white via-indigo-200 to-slate-400 bg-clip-text text-transparent capitalize tracking-tight flex items-center gap-3">
                    {getTabLabel()}
                </h2>
            </div>

            <div className="flex items-center gap-2 md:gap-4">
                {/* Connection Trust State Validation Panel */}
                <div className={`hidden md:flex items-center space-x-3 glass-panel px-4 py-2.5 rounded-full mr-2 transition-all duration-300 ${status.containerClass || ''}`}>
                    {status.icon}
                    <span className={`text-[11px] font-bold tracking-wider uppercase ${status.containerClass?.includes('text-red') ? 'text-red-200' : status.containerClass?.includes('text-amber') ? 'text-amber-200' : 'text-slate-300'}`}>
                        {status.label}
                    </span>
                </div>

                {/* Application Notifications */}
                <button
                    onClick={toggleDrawer}
                    className="relative p-2 text-slate-400 hover:text-white hover:bg-white/5 rounded-xl transition-all"
                >
                    <Bell size={20} />
                    {toasts.length > 0 && (
                        <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full animate-pulse border border-slate-950" />
                    )}
                </button>

                {/* Background Tasks Tracker */}
                {tasks.length > 0 && (
                    <div className="relative" ref={tasksRef}>
                        <button
                            onClick={() => setTasksOpen(!tasksOpen)}
                            className="relative flex items-center gap-2 p-2 bg-indigo-500/10 text-indigo-400 hover:text-indigo-300 hover:bg-indigo-500/20 border border-indigo-500/20 rounded-xl transition-all"
                        >
                            <Loader2 size={18} className="animate-spin" />
                            <span className="text-xs font-bold mr-1">{tasks.filter(t => t.status === 'running').length}</span>
                        </button>
                        
                        {tasksOpen && (
                            <div className="absolute right-0 mt-2 w-72 bg-slate-900 border border-white/10 rounded-2xl shadow-xl shadow-black/50 overflow-hidden z-50 animate-fade-in-up">
                                <div className="p-3 border-b border-white/5 bg-white/[0.02]">
                                    <p className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Active Background Processes</p>
                                </div>
                                <div className="max-h-64 overflow-y-auto p-2 space-y-1">
                                    {tasks.map(task => (
                                        <div key={task.id} className="p-3 bg-slate-950/50 rounded-xl border border-white/5">
                                            <div className="flex items-center gap-3 mb-2">
                                                <div className="w-8 h-8 rounded-lg bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center shrink-0">
                                                    {task.type === 'backup' ? <Database size={14} className="text-indigo-400" /> : 
                                                     task.type === 'upload' ? <UploadCloud size={14} className="text-indigo-400" /> :
                                                     <Loader2 size={14} className="text-indigo-400 animate-spin" />}
                                                </div>
                                                <div className="flex-1 min-w-0">
                                                    <p className="text-sm font-bold text-slate-200 truncate">{task.title}</p>
                                                    <p className="text-[10px] text-slate-500 uppercase tracking-widest">{task.status}</p>
                                                </div>
                                            </div>
                                            <div className="w-full bg-slate-800 rounded-full h-1 mt-3">
                                                <div 
                                                    className="bg-indigo-500 h-1 rounded-full transition-all duration-500" 
                                                    style={{ width: `${task.progress}%` }}
                                                ></div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {/* User Profile Dropdown */}
                <div className="relative" ref={dropdownRef}>
                    <button 
                        onClick={() => setDropdownOpen(!dropdownOpen)}
                        className="flex items-center gap-2 rounded-full glass-button pl-1 pr-3 md:pr-4 py-1 hover:border-indigo-500/50 group transition-all"
                    >
                        <div className="relative h-8 w-8 md:h-9 md:w-9 rounded-full bg-slate-900 border border-white/10 flex items-center justify-center overflow-hidden">
                            {user?.avatar_url ? (
                                <Image src={user.avatar_url} alt="Avatar" fill sizes="(max-width: 768px) 32px, 36px" className="object-cover" />
                            ) : (
                                <User size={16} className="text-slate-400 group-hover:text-indigo-300 transition-colors" />
                            )}
                        </div>
                        <div className="hidden md:block text-left">
                            <div className="text-xs font-bold text-slate-200">{user?.username || 'Admin'}</div>
                            <div className="text-[10px] text-slate-500 uppercase tracking-widest">{user?.role || 'User'}</div>
                        </div>
                        <ChevronDown size={14} className={`text-slate-500 transition-transform ${dropdownOpen ? 'rotate-180' : ''}`} />
                    </button>

                    {dropdownOpen && (
                        <div className="absolute right-0 mt-2 w-56 bg-slate-900 border border-white/10 rounded-2xl shadow-xl shadow-black/50 overflow-hidden z-50 animate-fade-in-up">
                            <div className="p-4 border-b border-white/5 bg-white/[0.02]">
                                <p className="text-sm font-bold text-slate-200">{user?.username || 'Admin'}</p>
                                <p className="text-xs text-slate-400 truncate">{user?.email || 'admin@aetherflow.local'}</p>
                            </div>
                            <div className="p-2">
                                <button
                                    onClick={logout}
                                    className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-semibold text-red-400 hover:bg-red-500/10 hover:text-red-300 transition-colors"
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
