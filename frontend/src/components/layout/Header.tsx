import { Wifi, User, Menu } from 'lucide-react';
import { TabId } from '@/types/dashboard';
import { NAVIGATION, BOTTOM_NAVIGATION } from './Sidebar';

interface HeaderProps {
    activeTab: TabId;
    error: string | null;
    toggleMobileMenu?: () => void;
}

export default function Header({ activeTab, error, toggleMobileMenu }: HeaderProps) {
    const getTabLabel = () => {
        if (activeTab === 'settings' || activeTab === 'security' || activeTab === 'logout') {
            return BOTTOM_NAVIGATION.find(n => n.id === activeTab)?.label;
        }
        return NAVIGATION.find(n => n.id === activeTab)?.label;
    };

    return (
        <header className="h-20 px-6 md:px-10 flex items-center justify-between border-b border-white/[0.02] bg-slate-950/40 backdrop-blur-xl sticky top-0 z-40">
            <div className="flex items-center gap-4 md:gap-6">
                <button
                    onClick={toggleMobileMenu}
                    className="p-2 md:hidden text-slate-400 hover:text-white transition-colors"
                >
                    <Menu size={24} />
                </button>
                <h2 className="text-xl md:text-2xl font-bold bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent capitalize tracking-tight flex items-center gap-3">
                    {getTabLabel()}
                </h2>
            </div>

            <div className="flex items-center gap-2 md:gap-4">
                {/* API Status Badge */}
                <div className="hidden md:flex items-center space-x-3 bg-slate-950 border border-white/10 px-4 py-2 rounded-full shadow-inner mr-2">
                    <Wifi size={14} className={error ? 'text-red-400' : 'text-emerald-400'} />
                    <span className="text-[11px] font-bold text-slate-300 tracking-wider uppercase">
                        {error ? 'API Offline (Mock Mode)' : 'API Connected'}
                    </span>
                </div>

                {/* User Profile Mock */}
                <div className="h-9 w-9 md:h-10 md:w-10 rounded-full bg-slate-800 border border-white/10 flex items-center justify-center overflow-hidden cursor-pointer hover:border-indigo-500/50 transition-colors">
                    <div className="absolute inset-0 bg-gradient-to-tr from-indigo-500/20 to-blue-500/20"></div>
                    <User size={18} className="text-slate-300" />
                </div>
            </div>
        </header>
    );
}
