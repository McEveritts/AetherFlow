'use client';

import { useToast } from '@/contexts/ToastContext';
import { X, CheckCircle, AlertCircle, Info, Bell, Trash2, Box } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useMarketplace } from '@/hooks/useMarketplace';
import { ProgressRing } from '@/components/ui/ProgressRing';

export default function NotificationDrawer() {
    const { toasts, isDrawerOpen, toggleDrawer, clearAll } = useToast();
    const { apps } = useMarketplace();
    const [isVisible, setIsVisible] = useState(false);

    const activeApps = apps ? apps.filter(app => app.status === 'installing' || app.status === 'uninstalling') : [];

    // Provide a small animation delay mount
    useEffect(() => {
        if (isDrawerOpen) setIsVisible(true);
        else setTimeout(() => setIsVisible(false), 300);
    }, [isDrawerOpen]);

    if (!isDrawerOpen && !isVisible) return null;

    return (
        <>
            {/* Backdrop */}
            <div 
                className={`fixed inset-0 bg-slate-950/20 backdrop-blur-sm z-50 transition-opacity duration-300 ${isDrawerOpen ? 'opacity-100' : 'opacity-0'}`}
                onClick={toggleDrawer}
            />

            {/* Drawer */}
            <div className={`fixed top-0 bottom-0 right-0 w-80 md:w-96 bg-slate-950/95 border-l border-white/10 z-50 shadow-2xl backdrop-blur-3xl transform transition-transform duration-300 ease-out flex flex-col ${isDrawerOpen ? 'translate-x-0' : 'translate-x-full'}`}>
                
                {/* Header */}
                <div className="flex items-center justify-between p-5 border-b border-white/5 bg-white/[0.02]">
                    <div className="flex items-center gap-2 text-slate-100 font-bold">
                        <Bell size={18} className="text-indigo-400" />
                        <h2>Notifications</h2>
                        {toasts.length > 0 && (
                            <span className="bg-indigo-500/20 text-indigo-300 text-[10px] px-2 py-0.5 rounded-full ml-1">
                                {toasts.length}
                            </span>
                        )}
                    </div>
                    <div className="flex items-center gap-2">
                        {toasts.length > 0 && (
                            <button 
                                onClick={clearAll}
                                className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-white/5 rounded-lg transition-colors"
                                title="Clear All"
                            >
                                <Trash2 size={16} />
                            </button>
                        )}
                        <button 
                            onClick={toggleDrawer}
                            className="p-1.5 text-slate-400 hover:text-white hover:bg-white/5 rounded-lg transition-colors"
                        >
                            <X size={20} />
                        </button>
                    </div>
                </div>

                {/* Content */}
                <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
                    {/* Active Marketplace Operations */}
                    {activeApps.length > 0 && (
                        <div className="mb-6 space-y-3">
                            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Active Operations</h3>
                            {activeApps.map(app => (
                                <div key={app.id} className="p-4 rounded-xl border flex items-center justify-between gap-3 backdrop-blur-md bg-indigo-500/5 hover:bg-indigo-500/10 transition-colors border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.1)]">
                                    <div className="flex flex-col gap-1 flex-1">
                                        <div className="flex items-center gap-2">
                                            <Box size={14} className="text-indigo-400" />
                                            <p className="text-sm font-bold text-slate-200">{app.name}</p>
                                        </div>
                                        <p className="text-xs text-slate-400">
                                            {app.status === 'uninstalling' ? 'Uninstalling...' : 'Installing...'}
                                        </p>
                                    </div>
                                    <div className="transform scale-75 origin-right">
                                        <ProgressRing 
                                            progress={app.progress || 0}
                                            status={app.status}
                                            startedAt={app.started_at}
                                            size={48}
                                            stroke={3}
                                        />
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}

                    {toasts.length === 0 && activeApps.length === 0 && (
                        <div className="flex flex-col items-center justify-center h-full text-slate-500 gap-3">
                            <Bell size={32} className="opacity-20" />
                            <p className="text-sm">No new notifications</p>
                        </div>
                    )}
                    
                    {toasts.length > 0 && (
                         <div className="space-y-3">
                            {activeApps.length > 0 && <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Recent Notifications</h3>}
                            {toasts.map(toast => {
                                const timeAgo = new Date(toast.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

                                let icon, bg;
                                switch (toast.type) {
                                    case 'success':
                                        icon = <CheckCircle size={16} className="text-emerald-400" />;
                                        bg = 'bg-emerald-500/10 border-emerald-500/20';
                                        break;
                                    case 'error':
                                        icon = <AlertCircle size={16} className="text-red-400" />;
                                        bg = 'bg-red-500/10 border-red-500/20';
                                        break;
                                    case 'info':
                                    default:
                                        icon = <Info size={16} className="text-blue-400" />;
                                        bg = 'bg-blue-500/10 border-white/10';
                                }

                                return (
                                    <div key={toast.id} className={`p-4 rounded-xl border flex items-start gap-3 backdrop-blur-md bg-white/[0.02] hover:bg-white/[0.04] transition-colors ${bg}`}>
                                        <div className="mt-0.5">{icon}</div>
                                        <div className="flex-1">
                                            <p className="text-sm font-medium text-slate-200">{toast.message}</p>
                                            <p className="text-[10px] text-slate-500 mt-1">{timeAgo}</p>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            </div>
        </>
    );
}
