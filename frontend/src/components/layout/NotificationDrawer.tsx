'use client';

import { useToast } from '@/contexts/ToastContext';
import { X, CheckCircle, AlertCircle, Info, Bell, Trash2, Box } from 'lucide-react';
import { useRef } from 'react';
import { useMarketplace } from '@/hooks/useMarketplace';
import { ProgressRing } from '@/components/ui/ProgressRing';
import { triggerHaptic } from '@/lib/design';
import { apiFetch } from '@/lib/fetcher';
import { useSystemStore } from '@/store/useSystemStore';
import { Modal } from '@/components/ui/Modal';
import useSWR from 'swr';

interface ServerNotification {
    id: number;
    title: string;
    message: string;
    level: 'error' | 'critical' | 'warning' | 'success' | 'info';
    read: boolean;
    created_at: string;
}

export default function NotificationDrawer() {
    const { toasts, isDrawerOpen, toggleDrawer, clearAll } = useToast();
    const { hapticFeedback } = useSystemStore();
    const { apps } = useMarketplace();
    const closeButtonRef = useRef<HTMLButtonElement>(null);
    const touchStartXRef = useRef<number | null>(null);

    const { data: serverData, mutate } = useSWR<{ notifications: ServerNotification[], unread_count: number }>(
        '/api/v1/auth/notifications',
        { refreshInterval: 5000 }
    );
    const serverNotifications = serverData?.notifications || [];

    const activeApps = apps ? apps.filter(applicationItem => applicationItem.status === 'installing' || applicationItem.status === 'uninstalling' || applicationItem.status === 'updating') : [];

    const handleClearAll = async () => {
        triggerHaptic(8, hapticFeedback);
        clearAll();
        if (serverNotifications.length > 0) {
            await apiFetch('/api/v1/auth/notifications/dismiss-all', { method: 'POST' });
            mutate();
        }
    };

    const handleTouchStart = (event: React.TouchEvent) => {
        touchStartXRef.current = event.touches[0]?.clientX ?? null;
    };

    const handleTouchEnd = (event: React.TouchEvent) => {
        if (touchStartXRef.current === null) return;
        const endPositionX = event.changedTouches[0]?.clientX ?? touchStartXRef.current;
        const deltaDistanceX = endPositionX - touchStartXRef.current;
        touchStartXRef.current = null;
        if (deltaDistanceX > 55) {
            triggerHaptic(6, hapticFeedback);
            toggleDrawer();
        }
    };

    const totalCount = toasts.length + serverNotifications.length;

    return (
        <Modal
            isOpen={isDrawerOpen}
            onClose={toggleDrawer}
            variant="drawer"
            aria-label="Notifications"
            id="notification-drawer"
            initialFocusRef={closeButtonRef}
            onTouchStart={handleTouchStart}
            onTouchEnd={handleTouchEnd}
        >
            <div className="h-full flex flex-col min-h-0">
                <div className="flex items-center justify-between p-5 border-b border-white/5 bg-white/[0.02]">
                    <div className="flex items-center gap-2 text-slate-100 font-bold">
                        <Bell size={18} className="text-indigo-400" />
                        <h2>Notifications</h2>
                        {totalCount > 0 && (
                            <span className="bg-indigo-500/20 text-indigo-300 text-xs px-2 py-0.5 rounded-full ml-1 font-medium">
                                {totalCount}
                            </span>
                        )}
                    </div>
                    <div className="flex items-center gap-2">
                        {totalCount > 0 && (
                            <button 
                                type="button"
                                onClick={handleClearAll}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive p-2 text-slate-400 hover:text-red-400 hover:bg-white/5 rounded-xl flex items-center justify-center"
                                title="Clear All"
                                aria-label="Clear All Notifications"
                            >
                                <Trash2 size={16} />
                            </button>
                        )}
                        <button 
                            ref={closeButtonRef}
                            type="button"
                            onClick={() => {
                                triggerHaptic(6, hapticFeedback);
                                toggleDrawer();
                            }}
                            className="obs-touch-target-standard obs-gpu-120hz-interactive p-2 text-slate-400 hover:text-white hover:bg-white/5 rounded-xl flex items-center justify-center"
                            aria-label="Close Notifications Drawer"
                        >
                            <X size={20} />
                        </button>
                    </div>
                </div>

                <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar obs-scroller">
                    {activeApps.length > 0 && (
                        <div className="mb-6 space-y-3">
                            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Active Operations</h3>
                            {activeApps.map(applicationItem => (
                                <div key={applicationItem.id} className="p-4 rounded-xl border flex items-center justify-between gap-3 backdrop-blur-md bg-indigo-500/5 hover:bg-indigo-500/10 transition-colors border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.1)]">
                                    <div className="flex flex-col gap-1 flex-1">
                                        <div className="flex items-center gap-2">
                                            <Box size={14} className="text-indigo-400" />
                                            <p className="text-sm font-bold text-slate-200">{applicationItem.name}</p>
                                        </div>
                                        <p className="text-xs text-slate-400">
                                            {applicationItem.status === 'uninstalling' ? 'Uninstalling...' : 'Installing...'}
                                        </p>
                                    </div>
                                    <div className="transform scale-75 origin-right">
                                        <ProgressRing 
                                            progress={applicationItem.progress || 0}
                                            status={applicationItem.status}
                                            startedAt={applicationItem.started_at}
                                            size={48}
                                            stroke={3}
                                        />
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}

                    {toasts.length === 0 && serverNotifications.length === 0 && activeApps.length === 0 && (
                        <div className="flex flex-col items-center justify-center h-full text-slate-500 gap-3">
                            <Bell size={32} className="opacity-20" />
                            <p className="text-sm">No new notifications</p>
                        </div>
                    )}
                    
                    {(toasts.length > 0 || serverNotifications.length > 0) && (
                         <div className="space-y-3">
                            {activeApps.length > 0 && <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Recent Notifications</h3>}
                            
                            {serverNotifications.map(notificationItem => {
                                const timeAgo = new Date(notificationItem.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                                let statusIcon;
                                let backgroundStyle;
                                switch (notificationItem.level) {
                                    case 'error': case 'critical':
                                        statusIcon = <AlertCircle size={16} className="text-red-400" />;
                                        backgroundStyle = 'bg-red-500/10 border-red-500/20'; break;
                                    case 'warning':
                                        statusIcon = <AlertCircle size={16} className="text-amber-400" />;
                                        backgroundStyle = 'bg-amber-500/10 border-amber-500/20'; break;
                                    case 'success':
                                        statusIcon = <CheckCircle size={16} className="text-emerald-400" />;
                                        backgroundStyle = 'bg-emerald-500/10 border-emerald-500/20'; break;
                                    default:
                                        statusIcon = <Info size={16} className="text-blue-400" />;
                                        backgroundStyle = 'bg-blue-500/10 border-white/10';
                                }

                                return (
                                    <div key={`server-${notificationItem.id}`} className={`p-4 rounded-xl border flex items-start gap-3 backdrop-blur-md bg-white/[0.02] hover:bg-white/[0.04] transition-colors ${notificationItem.read ? 'opacity-60' : ''} ${backgroundStyle}`}>
                                        <div className="mt-0.5">{statusIcon}</div>
                                        <div className="flex-1">
                                            <p className="text-xs font-bold text-slate-400">{notificationItem.title}</p>
                                            <p className="text-sm font-medium text-slate-200">{notificationItem.message}</p>
                                            <p className="text-xs text-slate-500 mt-1">{timeAgo}</p>
                                        </div>
                                    </div>
                                );
                            })}

                            {toasts.map(toastItem => {
                                const timeAgo = new Date(toastItem.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

                                let toastIcon;
                                let toastBackground;
                                switch (toastItem.type) {
                                    case 'success':
                                        toastIcon = <CheckCircle size={16} className="text-emerald-400" />;
                                        toastBackground = 'bg-emerald-500/10 border-emerald-500/20';
                                        break;
                                    case 'error':
                                        toastIcon = <AlertCircle size={16} className="text-red-400" />;
                                        toastBackground = 'bg-red-500/10 border-red-500/20';
                                        break;
                                    case 'info':
                                    default:
                                        toastIcon = <Info size={16} className="text-blue-400" />;
                                        toastBackground = 'bg-blue-500/10 border-white/10';
                                }

                                return (
                                    <div key={toastItem.id} className={`p-4 rounded-xl border flex items-start gap-3 backdrop-blur-md bg-white/[0.02] hover:bg-white/[0.04] transition-colors ${toastBackground}`}>
                                        <div className="mt-0.5">{toastIcon}</div>
                                        <div className="flex-1">
                                            <p className="text-sm font-medium text-slate-200">{toastItem.message}</p>
                                            <p className="text-xs text-slate-500 mt-1">{timeAgo}</p>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            </div>
        </Modal>
    );
}
