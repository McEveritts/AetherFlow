import { TabId } from '@/types/dashboard';
import { useAuth } from '@/contexts/AuthContext';
import { useSystemStore } from '@/store/useSystemStore';
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
    Users,
    Mail,
    ClipboardList,
    KeyRound,
    Film,
    ChevronLeft // Added for your floating collapse button!
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
    { id: 'users' as TabId, label: 'Users', icon: <Users size={18} /> },
    { id: 'audit' as TabId, label: 'Audit Trail', icon: <ClipboardList size={18} /> },
    { id: 'settings' as TabId, label: 'Settings', icon: <Settings size={18} /> },
    { id: 'logout' as TabId, label: 'Log Out', icon: <LogOut size={18} /> },
];

export default function Sidebar() {
    const { user, logout } = useAuth();
    const { activeTab, setActiveTab, isSidebarHovered, setIsSidebarHovered, isMobileMenuOpen, setIsMobileMenuOpen } = useSystemStore();

    return (
        <>
            {/* Mobile Overlay */}
            {isMobileMenuOpen && (
                <div
                    className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40 md:hidden transition-opacity border-none"
                    onClick={() => setIsMobileMenuOpen(false)}
                />
            )}

            {/* THE "GHOST SPACER" FIX: This holds space in the document flow so the page NEVER shifts */}
            <div className={`md:sticky md:top-4 z-50 shrink-0 ${isMobileMenuOpen ? 'w-0' : 'hidden md:block md:w-20 md:h-[calc(100vh-2rem)]'}`}>
                
                {/* The actual Sidebar (Now positioned absolute on desktop to float OVER the page) */}
                <aside
                    className={`fixed inset-y-0 left-0 md:absolute md:top-0 md:bottom-0 md:h-full flex flex-col transition-all duration-300 ease-[cubic-bezier(0.4,0,0.2,1)]
                    ${isMobileMenuOpen ? 'translate-x-0 w-64' : '-translate-x-full md:translate-x-0'} 
                    ${isSidebarHovered ? 'md:w-64 md:shadow-[0_0_40px_rgba(0,0,0,0.6)]' : 'md:w-20 md:shadow-none'}`}
                    onMouseEnter={() => setIsSidebarHovered(true)}
                    onMouseLeave={() => setIsSidebarHovered(false)}
                >
                    
                    {/* THE BACKGROUND WRAPPER: Has hidden overflow so internal items wrap safely, while external buttons don't clip */}
                    <div className="absolute inset-0 glass-panel rounded-none md:rounded-2xl overflow-hidden flex flex-col">
                        
                        {/* Header Area */}
                        <div className="flex h-20 items-center px-5 border-b border-white/5 relative shrink-0">
                            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-indigo-500/80 to-transparent"></div>
                            
                            <div className="flex items-center gap-4 w-full relative z-10 mt-1">
                                {/* Fixed width icon wrapper to stop jumping */}
                                <div className="w-10 h-10 shrink-0 rounded-2xl shadow-[0_0_30px_rgba(99,102,241,0.5)] relative overflow-hidden bg-indigo-500/10 flex items-center justify-center">
                                    <img src="/img/af-logo.png" alt="AetherFlow Logo" className="w-[130%] h-[130%] object-cover" />
                                </div>
                                <h1 className={`text-xl font-bold tracking-tight bg-gradient-to-r from-slate-100 to-slate-400 bg-clip-text text-transparent transition-opacity duration-300 whitespace-nowrap ${isSidebarHovered ? 'opacity-100' : 'opacity-0 w-0'}`}>
                                    AetherFlow
                                </h1>
                            </div>
                        </div>

                        {/* Navigation List */}
                        <nav className="flex-1 px-3 py-6 space-y-1.5 overflow-y-auto no-scrollbar relative z-10">
                            <div className={`px-4 pb-2 text-[10px] font-bold text-slate-500 uppercase tracking-widest transition-opacity duration-300 whitespace-nowrap ${isSidebarHovered ? 'opacity-100' : 'opacity-0'}`}>Nexus</div>
                            {NAVIGATION.map((item) => {
                                const isActive = activeTab === item.id;
                                return (
                                    <button
                                        key={item.id}
                                        onClick={() => setActiveTab(item.id)}
                                        className={`w-full flex items-center relative gap-3 p-2 rounded-xl transition-all duration-300 group overflow-hidden ${isActive
                                            ? 'bg-gradient-to-r from-indigo-500/20 to-purple-500/20 text-white shadow-[0_0_15px_rgba(99,102,241,0.2)]'
                                            : 'text-slate-400 hover:bg-white/5 hover:text-slate-200'
                                        }`}
                                    >
                                        <div className={`absolute left-0 top-1/2 -translate-y-1/2 w-1 h-3/5 bg-indigo-500 rounded-r-full transition-all duration-300 shadow-[0_0_8px_#6366f1] ${isActive ? 'scale-y-100 opacity-100' : 'scale-y-0 opacity-0'}`}></div>

                                        {/* THE SQUASH FIX: Fixed width and height on icons */}
                                        <div className={`w-10 h-10 shrink-0 flex items-center justify-center transition-colors ${isActive ? 'text-indigo-400 drop-shadow-[0_0_8px_rgba(129,140,248,0.5)]' : 'group-hover:text-slate-300'}`}>
                                            {item.icon}
                                        </div>
                                        
                                        <span className={`font-semibold transition-all duration-300 whitespace-nowrap text-sm tracking-wide ${isSidebarHovered || isMobileMenuOpen ? 'opacity-100 translate-x-0' : 'opacity-0 md:-translate-x-4'}`}>
                                            {item.label}
                                        </span>

                                        {isActive && item.id === 'ai' && (
                                            <div className="absolute right-4 w-1.5 h-1.5 rounded-full bg-indigo-400 shadow-[0_0_8px_#818CF8] animate-pulse"></div>
                                        )}
                                    </button>
                                )
                            })}
                        </nav>

                        {/* Bottom Admin Navigation */}
                        <div className="p-3 border-t border-white/5 bg-slate-950/50 backdrop-blur-md relative z-10 shrink-0">
                            {BOTTOM_NAVIGATION.filter(item => {
                                if (['settings', 'security', 'users', 'audit', 'oidc-clients'].includes(item.id)) {
                                    return user?.role === 'admin';
                                }
                                return true;
                            }).map((item) => (
                                <button
                                    key={item.id}
                                    onClick={() => {
                                        if (item.id === 'logout') logout();
                                        else setActiveTab(item.id);
                                    }}
                                    className={`w-full flex items-center gap-3 p-2 rounded-xl text-slate-400 hover:text-slate-200 hover:bg-white/5 transition-all duration-300 group overflow-hidden ${activeTab === item.id ? 'bg-gradient-to-r from-indigo-500/20 to-purple-500/20 text-white shadow-[0_0_15px_rgba(99,102,241,0.2)]' : ''}`}
                                >
                                    {/* THE SQUASH FIX: Fixed width and height on icons */}
                                    <div className="w-10 h-10 shrink-0 flex items-center justify-center group-hover:scale-110 transition-transform">
                                        {item.icon}
                                    </div>
                                    <span className={`text-sm font-semibold tracking-wide transition-all duration-300 whitespace-nowrap ${isSidebarHovered ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4'}`}>
                                        {item.label}
                                    </span>
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* THE UNCLIPPED BACK BUTTON: Floats completely outside the hidden overflow! */}
                    <button 
                        className={`hidden md:flex absolute -right-3 top-[50%] -translate-y-1/2 w-7 h-7 rounded-full bg-slate-800 border border-slate-700 text-slate-400 hover:text-white items-center justify-center shadow-lg transition-all duration-300 z-[60]
                        ${isSidebarHovered ? 'opacity-100 scale-100' : 'opacity-0 scale-50 pointer-events-none'}`}
                        onClick={(e) => {
                            e.stopPropagation();
                            setIsSidebarHovered(false);
                        }}
                    >
                        <ChevronLeft size={16} />
                    </button>
                    
                </aside>
            </div>
        </>
    );
}
