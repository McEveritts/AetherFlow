'use client';

import { useToast } from '@/contexts/ToastContext';
import { AlertCircle, ShieldAlert, Info, X } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export default function GlobalBanners() {
    const { banners, removeBanner } = useToast();

    if (banners.length === 0) return null;

    return (
        <div className="flex flex-col gap-2 mb-4 px-4 sm:px-6 w-full z-40 relative">
            <AnimatePresence>
                {banners.map((banner) => {
                    let Icon, bgColor, borderColor, textColor;

                    switch (banner.type) {
                        case 'critical':
                            Icon = ShieldAlert;
                            bgColor = 'bg-red-500/10';
                            borderColor = 'border-red-500/40';
                            textColor = 'text-red-400';
                            break;
                        case 'warning':
                            Icon = AlertCircle;
                            bgColor = 'bg-amber-500/10';
                            borderColor = 'border-amber-500/40';
                            textColor = 'text-amber-400';
                            break;
                        case 'info':
                        default:
                            Icon = Info;
                            bgColor = 'bg-indigo-500/10';
                            borderColor = 'border-indigo-500/40';
                            textColor = 'text-indigo-400';
                            break;
                    }

                    return (
                        <motion.div
                            key={banner.id}
                            initial={{ opacity: 0, y: -20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, scale: 0.95 }}
                            transition={{ duration: 0.2 }}
                            className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl border backdrop-blur-md shadow-lg ${bgColor} ${borderColor}`}
                        >
                            <div className="flex items-start sm:items-center gap-3">
                                <Icon size={20} className={`shrink-0 ${textColor}`} />
                                <p className="text-sm font-medium text-slate-200">
                                    {banner.message}
                                </p>
                            </div>
                            
                            <div className="flex items-center gap-2 sm:ml-auto">
                                {banner.actionLabel && banner.onAction && (
                                    <button 
                                        onClick={() => {
                                            banner.onAction?.();
                                            if (banner.dismissible !== false) removeBanner(banner.id);
                                        }}
                                        className={`px-3 py-1.5 text-xs font-bold rounded-lg transition-colors border ${
                                            banner.type === 'critical' ? 'bg-red-500/20 hover:bg-red-500/30 text-red-300 border-red-500/30' :
                                            banner.type === 'warning' ? 'bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border-amber-500/30' :
                                            'bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border-indigo-500/30'
                                        }`}
                                    >
                                        {banner.actionLabel}
                                    </button>
                                )}
                                {banner.dismissible !== false && (
                                    <button 
                                        onClick={() => removeBanner(banner.id)}
                                        className="p-1.5 text-slate-400 hover:text-white bg-white/5 hover:bg-white/10 rounded-lg transition-colors border border-white/5"
                                        aria-label="Dismiss banner"
                                    >
                                        <X size={16} />
                                    </button>
                                )}
                            </div>
                        </motion.div>
                    );
                })}
            </AnimatePresence>
        </div>
    );
}
