import { Wifi, WifiOff, Radio, User, Menu } from 'lucide-react';
import { NAVIGATION, BOTTOM_NAVIGATION } from './Sidebar';
import { useSystemStore } from '@/store/useSystemStore';
import { useConnectionStore } from '@/store/useConnectionStore';

export default function Header() {
    const { activeTab, isMobileMenuOpen, setIsMobileMenuOpen } = useSystemStore();
    const connectionState = useConnectionStore((s) => s.connectionState);

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

                {/* User Profile Mock */}
                <button className="h-10 w-10 md:h-11 md:w-11 rounded-full glass-button p-0 flex items-center justify-center overflow-hidden hover:border-indigo-500/50 group">
                    <div className="absolute inset-0 bg-gradient-to-tr from-indigo-500/20 to-blue-500/20 group-hover:opacity-100 transition-opacity"></div>
                    <User size={20} className="text-slate-300 group-hover:text-indigo-300 transition-colors relative z-10" />
                </button>
            </div>
        </header>
    );
}
