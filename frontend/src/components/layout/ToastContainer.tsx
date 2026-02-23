'use client';

import { useToast, ToastMessage } from '@/contexts/ToastContext';
import { CheckCircle, AlertCircle, Info, X } from 'lucide-react';
import { useState } from 'react';

export default function ToastContainer() {
    const { toasts, removeToast } = useToast();

    return (
        <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-3 pointer-events-none">
            {toasts.map((toast) => (
                <ToastItem key={toast.id} toast={toast} onClose={() => removeToast(toast.id)} />
            ))}
        </div>
    );
}

function ToastItem({ toast, onClose }: { toast: ToastMessage; onClose: () => void }) {
    const [isLeaving, setIsLeaving] = useState(false);

    // Give it a brief moment to animate out before unmounting
    const handleClose = () => {
        setIsLeaving(true);
        setTimeout(onClose, 300); // match transition duration
    };

    const getStyles = () => {
        switch (toast.type) {
            case 'success':
                return {
                    bg: 'bg-emerald-950/80',
                    border: 'border-emerald-500/20',
                    icon: <CheckCircle className="text-emerald-400" size={20} />,
                    iconBg: 'bg-emerald-500/10'
                };
            case 'error':
                return {
                    bg: 'bg-red-950/80',
                    border: 'border-red-500/20',
                    icon: <AlertCircle className="text-red-400" size={20} />,
                    iconBg: 'bg-red-500/10'
                };
            case 'info':
            default:
                return {
                    bg: 'bg-slate-900/80',
                    border: 'border-white/10',
                    icon: <Info className="text-blue-400" size={20} />,
                    iconBg: 'bg-blue-500/10'
                };
        }
    };

    const styles = getStyles();

    return (
        <div
            className={`pointer-events-auto flex items-center gap-3 w-80 p-4 rounded-2xl backdrop-blur-xl border shadow-2xl transition-all duration-300 ${styles.bg} ${styles.border} ${isLeaving ? 'opacity-0 translate-x-12 translate-y-4 scale-95' : 'animate-toast-slide-up'}`}
        >
            <div className={`p-2 rounded-xl flex-shrink-0 ${styles.iconBg}`}>
                {styles.icon}
            </div>

            <div className="flex-1 text-sm font-medium text-slate-200">
                {toast.message}
            </div>

            <button
                onClick={handleClose}
                className="p-1 text-slate-500 hover:bg-white/10 hover:text-slate-300 rounded-lg transition-colors"
            >
                <X size={16} />
            </button>
        </div>
    );
}
