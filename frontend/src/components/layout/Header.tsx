import { Wifi, WifiOff, Radio, User, Menu, LogOut, ChevronDown } from 'lucide-react';
import { NAVIGATION, BOTTOM_NAVIGATION } from './Sidebar';
import { useSystemStore } from '@/store/useSystemStore';
import { useConnectionStore } from '@/store/useConnectionStore';
import { useAuth } from '@/contexts/AuthContext';
import { useState, useRef, useEffect } from 'react';

export default function Header() {
    const { activeTab, isMobileMenuOpen, setIsMobileMenuOpen } = useSystemStore();
    const connectionState = useConnectionStore((s) => s.connectionState);
    const { user, logout } = useAuth();
    const [dropdownOpen, setDropdownOpen] = useState(false);
    const dropdownRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
                setDropdownOpen(false);
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

    const statusConfig = {
        CONNECTED: { icon: <Wifi size={16} className="text-emerald-400" />, label: 'API Connected', className: '' },
        CONNECTING: { icon: <Radio size={16} className="text-amber-400 animate-pulse" />, label: 'Connecting...', className: '' },
        RECONNECTING: { icon: <WifiOff size={16} className="text-amber-400 animate-pulse" />, label: 'Reconnecting...', className: '' },
        FALLBACK: { icon: <Radio size={16} className="text-blue-400" />, label: 'Polling Mode', className: '' },
        DISCONNECTED: { icon: <WifiOff size={16} className="text-red-400" />, label: 'Disconnected', className: '' },
    };

    const status = statusConfig[connectionState];

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
                {/* Connection Status Badge — powered by Zustand connection store */}
                <div className="hidden md:flex items-center space-x-3 glass-panel px-4 py-2.5 rounded-full mr-2">
                    {status.icon}
                    <span className="text-[11px] font-bold text-slate-300 tracking-wider uppercase">
                        {status.label}
                    </span>
                </div>

                {/* User Profile Dropdown */}
                <div className="relative" ref={dropdownRef}>
                    <button 
                        onClick={() => setDropdownOpen(!dropdownOpen)}
                        className="flex items-center gap-2 rounded-full glass-button pl-1 pr-3 md:pr-4 py-1 hover:border-indigo-500/50 group transition-all"
                    >
                        <div className="h-8 w-8 md:h-9 md:w-9 rounded-full bg-slate-900 border border-white/10 flex items-center justify-center overflow-hidden">
                            {user?.avatar_url ? (
                                <img src={user.avatar_url} alt="Avatar" className="h-full w-full object-cover" />
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
