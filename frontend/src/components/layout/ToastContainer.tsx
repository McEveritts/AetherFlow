'use client';

import { useToast, ToastMessage } from '@/contexts/ToastContext';
import { CheckCircle, AlertCircle, Info, X } from 'lucide-react';
import { useRef, useState } from 'react';

export default function ToastContainer() {
    const { toasts, removeToast } = useToast();

    return (
        <div className="fixed bottom-20 md:bottom-6 right-4 md:right-6 z-50 flex flex-col gap-3 pointer-events-none max-w-[calc(100vw-2rem)]">
            {toasts
                .filter(toast => !toast.dismissed)
                .map((toast) => (
                    <ToastItem key={toast.id} toast={toast} onClose={() => removeToast(toast.id)} />
            ))}
        </div>
    );
}

function ToastItem({ toast, onClose }: { toast: ToastMessage; onClose: () => void }) {
    const [isLeaving, setIsLeaving] = useState(false);
    const touchStartXRef = useRef<number | null>(null);

    // Give it a brief moment to animate out before unmounting
    const handleClose = () => {
        setIsLeaving(true);
        setTimeout(onClose, 200);
    };

    const handleTouchStart = (e: React.TouchEvent) => {
        touchStartXRef.current = e.touches[0]?.clientX ?? null;
    };

    const handleTouchEnd = (e: React.TouchEvent) => {
        if (touchStartXRef.current === null) return;
        const deltaX = (e.changedTouches[0]?.clientX ?? touchStartXRef.current) - touchStartXRef.current;
        touchStartXRef.current = null;
        if (Math.abs(deltaX) > 45) {
            handleClose();
        }
    };

    const getStyles = () => {
        switch (toast.type) {
            case 'success':
                return {
                    bg: 'bg-emerald-950/85',
                    border: 'border-emerald-500/25',
                    icon: <CheckCircle className="text-emerald-400" size={20} />,
                    iconBg: 'bg-emerald-500/10'
                };
            case 'error':
                return {
                    bg: 'bg-red-950/85',
                    border: 'border-red-500/25',
                    icon: <AlertCircle className="text-red-400" size={20} />,
                    iconBg: 'bg-red-500/10'
                };
            case 'info':
            default:
                return {
                    bg: 'bg-slate-900/85',
                    border: 'border-white/10',
                    icon: <Info className="text-blue-400" size={20} />,
                    iconBg: 'bg-blue-500/10'
                };
        }
    };

    const styles = getStyles();

    return (
        <div
            onTouchStart={handleTouchStart}
            onTouchEnd={handleTouchEnd}
            className={`pointer-events-auto flex items-center gap-3 w-80 max-w-full p-4 rounded-2xl backdrop-blur-xl border shadow-2xl obs-gpu-120hz-interactive ${styles.bg} ${styles.border} ${isLeaving ? 'opacity-0 translate-x-12 translate-y-4 scale-95' : 'animate-toast-slide-up'}`}
        >
            <div className={`p-2 rounded-xl flex-shrink-0 ${styles.iconBg}`}>
                {styles.icon}
            </div>

            <div className="flex-1 text-sm font-medium text-slate-200">
                {toast.message}
            </div>

            <button
                onClick={handleClose}
                aria-label="Dismiss notification"
                className="obs-touch-target-standard p-2 text-slate-400 hover:bg-white/10 hover:text-slate-200 rounded-xl transition-colors flex items-center justify-center"
            >
                <X size={16} />
            </button>
        </div>
    );
}
