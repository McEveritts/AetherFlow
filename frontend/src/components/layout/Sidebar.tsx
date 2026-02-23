import { TabId } from '@/types/dashboard';
import { useAuth } from '@/contexts/AuthContext';
import {
    LayoutDashboard,
    Server,
    Sparkles,
    Settings,
    Shield,
    LogOut,
    Store,
    FolderUp,
    HardDriveDownload,
    UserCircle,
    Users
} from 'lucide-react';

export const NAVIGATION = [
    { id: 'overview' as TabId, label: 'Overview', icon: <LayoutDashboard size={20} /> },
    { id: 'services' as TabId, label: 'Services', icon: <Server size={20} /> },
    { id: 'marketplace' as TabId, label: 'Marketplace', icon: <Store size={20} /> },
    { id: 'fileshare' as TabId, label: 'File Share', icon: <FolderUp size={20} /> },
    { id: 'ai' as TabId, label: 'FlowAI', icon: <Sparkles size={20} className="text-indigo-400 group-hover:text-indigo-300 transition-colors" /> },
];

export const BOTTOM_NAVIGATION = [
    { id: 'backups' as TabId, label: 'Backups', icon: <HardDriveDownload size={18} /> },
    { id: 'security' as TabId, label: 'Security', icon: <Shield size={18} /> },
    { id: 'users' as TabId, label: 'Users', icon: <Users size={18} /> },
    { id: 'profile' as TabId, label: 'Profile', icon: <UserCircle size={18} /> },
    { id: 'settings' as TabId, label: 'Settings', icon: <Settings size={18} /> },
    { id: 'logout' as TabId, label: 'Log Out', icon: <LogOut size={18} /> },
];

interface SidebarProps {
    activeTab: TabId;
    setActiveTab: (tab: TabId) => void;
    isSidebarHovered: boolean;
    setIsSidebarHovered: (hovered: boolean) => void;
    isMobileMenuOpen: boolean;
    setIsMobileMenuOpen: (open: boolean) => void;
}

export default function Sidebar({
    activeTab,
    setActiveTab,
    isSidebarHovered,
    setIsSidebarHovered,
    isMobileMenuOpen,
    setIsMobileMenuOpen,
}: SidebarProps) {
    const { user, logout } = useAuth();

    return (
        <>
            {/* Mobile Overlay */}
            {isMobileMenuOpen && (
                <div
                    className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40 md:hidden transition-opacity border-none"
                    onClick={() => setIsMobileMenuOpen(false)}
                />
            )}

            <aside
                className={`fixed inset-y-0 left-0 z-50 flex flex-col bg-slate-950 border-r border-white/5 transition-all duration-300 ease-[cubic-bezier(0.4,0,0.2,1)] shadow-2xl 
                ${isMobileMenuOpen ? 'translate-x-0 w-64' : '-translate-x-full'} 
                md:translate-x-0 md:bg-slate-950/80 md:backdrop-blur-2xl ${isSidebarHovered ? 'md:w-64' : 'md:w-20'}`}
                onMouseEnter={() => setIsSidebarHovered(true)}
                onMouseLeave={() => setIsSidebarHovered(false)}
            >
                <div className="flex h-20 items-center px-6 border-b border-white/5 relative overflow-hidden shrink-0">
                    {/* Header Glow */}
                    <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-indigo-500/50 to-transparent"></div>

                    <div className="flex items-center gap-4 w-full relative z-10 mt-1">
                        <div className="h-9 w-9 min-w-[2.25rem] rounded-xl bg-gradient-to-br from-indigo-500 via-blue-600 to-indigo-800 flex items-center justify-center shadow-[0_0_20px_rgba(99,102,241,0.3)] relative overflow-hidden">
                            <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI4IiBoZWlnaHQ9IjgiPgo8cmVjdCB3aWR0aD0iOCIgaGVpZ2h0PSI4IiBmaWxsPSIjZmZmIiBmaWxsLW9wYWNpdHk9IjAuMSIvPgo8L3N2Zz4=')] opacity-30 mix-blend-overlay"></div>
                            <span className="font-extrabold text-white text-lg tracking-tighter mix-blend-screen drop-shadow-md">A</span>
                        </div>
                        <h1 className={`text-xl font-bold tracking-tight bg-gradient-to-r from-slate-100 to-slate-400 bg-clip-text text-transparent transition-opacity duration-300 truncate whitespace-nowrap ${isSidebarHovered ? 'opacity-100' : 'opacity-0 w-0'}`}>
                            AetherFlow
                        </h1>
                    </div>
                </div>

                <nav className="flex-1 px-3 py-6 space-y-1.5 overflow-y-auto no-scrollbar relative z-10">
                    <div className={`px-4 pb-2 text-[10px] font-bold text-slate-500 uppercase tracking-widest transition-opacity duration-300 ${isSidebarHovered ? 'opacity-100' : 'opacity-0'}`}>Nexus</div>
                    {NAVIGATION.map((item) => {
                        const isActive = activeTab === item.id;
                        return (
                            <button
                                key={item.id}
                                onClick={() => setActiveTab(item.id)}
                                className={`w-full flex items-center relative gap-4 px-3.5 py-3 rounded-xl transition-all duration-300 group overflow-hidden ${isActive
                                    ? 'bg-indigo-500/10 text-indigo-100 shadow-sm border border-indigo-500/20'
                                    : 'text-slate-400 hover:bg-white/5 hover:text-slate-200 border border-transparent'
                                    }`}
                            >
                                {/* Active Indicator Line */}
                                <div className={`absolute left-0 top-1/2 -translate-y-1/2 w-1 h-1/2 bg-indigo-500 rounded-r-full transition-all duration-300 ${isActive ? 'scale-y-100 opacity-100' : 'scale-y-0 opacity-0'}`}></div>

                                <div className={`min-w-[1.25rem] flex items-center justify-center transition-colors ${isActive ? 'text-indigo-400 drop-shadow-[0_0_8px_rgba(129,140,248,0.5)]' : 'group-hover:text-slate-300'}`}>
                                    {item.icon}
                                </div>
                                <span className={`font-semibold transition-all duration-300 whitespace-nowrap truncate text-sm tracking-wide ${isSidebarHovered || isMobileMenuOpen ? 'opacity-100 translate-x-0' : 'opacity-0 md:-translate-x-4'}`}>
                                    {item.label}
                                </span>

                                {/* AI Sparkle specific active state */}
                                {isActive && item.id === 'ai' && (
                                    <div className="absolute right-4 w-1.5 h-1.5 rounded-full bg-indigo-400 shadow-[0_0_8px_#818CF8] animate-pulse"></div>
                                )}
                            </button>
                        )
                    })}
                </nav>

                <div className="p-4 border-t border-white/5 bg-slate-950/50 backdrop-blur-md relative z-10 shrink-0">
                    {BOTTOM_NAVIGATION.filter(item => {
                        // Admin only tabs
                        if (['settings', 'security', 'users'].includes(item.id)) {
                            return user?.role === 'admin';
                        }
                        return true;
                    }).map((item) => (
                        <button
                            key={item.id}
                            onClick={() => {
                                if (item.id === 'logout') {
                                    logout();
                                } else {
                                    setActiveTab(item.id);
                                }
                            }}
                            className={`w-full flex items-center gap-4 px-3 py-2.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-white/5 transition-all duration-300 group overflow-hidden ${activeTab === item.id ? 'bg-white/10 text-white' : ''}`}
                        >
                            <div className="min-w-[1.125rem] flex items-center justify-center group-hover:scale-110 transition-transform">
                                {item.icon}
                            </div>
                            <span className={`text-sm font-semibold tracking-wide transition-all duration-300 whitespace-nowrap truncate ${isSidebarHovered ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4'}`}>
                                {item.label}
                            </span>
                        </button>
                    ))}
                </div>
            </aside>
        </>
    );
}
