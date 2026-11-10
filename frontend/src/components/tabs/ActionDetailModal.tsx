import { Modal } from '@/components/ui/Modal';
import { AlertTriangle, ShieldAlert, Clock, User, Terminal, CheckCircle, XCircle } from 'lucide-react';
import type { PendingAction } from '@/types/api';
import type { RefObject } from 'react';

interface ActionDetailModalProps {
    action: PendingAction | null;
    isOpen: boolean;
    onClose: () => void;
    onApprove: (id: number) => void;
    onReject: (id: number) => void;
    isProcessing: boolean;
    returnFocusRef?: RefObject<HTMLElement | null>;
}

const classificationConfig: Record<string, { label: string; color: string; icon: typeof AlertTriangle }> = {
    safe: { label: 'Safe', color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30', icon: CheckCircle },
    warn: { label: 'Warning', color: 'text-amber-400 bg-amber-500/10 border-amber-500/30', icon: AlertTriangle },
    critical: { label: 'Critical', color: 'text-red-400 bg-red-500/10 border-red-500/30', icon: ShieldAlert },
};

function formatTimestamp(isoTimestamp: string): string {
    try {
        return new Date(isoTimestamp).toLocaleString();
    } catch {
        return isoTimestamp;
    }
}

export function ActionDetailModal({ action, isOpen, onClose, onApprove, onReject, isProcessing, returnFocusRef }: ActionDetailModalProps) {
    if (!action) return null;

    const config = classificationConfig[action.classification] || classificationConfig.warn;
    const ClassIcon = config.icon;

    return (
        <Modal isOpen={isOpen} onClose={onClose} title={action.action} returnFocusRef={returnFocusRef} className="max-w-2xl">
            <div className="flex items-center gap-3 mb-5">
                <div className={`p-2 rounded-xl border ${config.color} flex items-center justify-center shrink-0`}>
                    <ClassIcon size={20} />
                </div>
                <div className="flex items-center gap-3 flex-wrap min-w-0">
                    <span className={`text-xs font-bold uppercase tracking-widest px-2.5 py-1 rounded border ${config.color}`}>
                        {config.label}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">#{action.id}</span>
                </div>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="bg-white/5 rounded-xl p-3 border border-white/5">
                    <div className="text-xs uppercase tracking-wider text-slate-400 mb-1 flex items-center gap-1.5 font-medium">
                        <Terminal size={12} /> Source
                    </div>
                    <p className="text-sm font-bold text-slate-200">{action.source}</p>
                </div>
                <div className="bg-white/5 rounded-xl p-3 border border-white/5">
                    <div className="text-xs uppercase tracking-wider text-slate-400 mb-1 flex items-center gap-1.5 font-medium">
                        <Clock size={12} /> Created
                    </div>
                    <p className="text-sm text-slate-200">{formatTimestamp(action.created_at)}</p>
                </div>
                {action.resolved_by && (
                    <div className="bg-white/5 rounded-xl p-3 border border-white/5">
                        <div className="text-xs uppercase tracking-wider text-slate-400 mb-1 flex items-center gap-1.5 font-medium">
                            <User size={12} /> Resolved By
                        </div>
                        <p className="text-sm text-slate-200">{action.resolved_by}</p>
                    </div>
                )}
                {action.resolved_at && (
                    <div className="bg-white/5 rounded-xl p-3 border border-white/5">
                        <div className="text-xs uppercase tracking-wider text-slate-400 mb-1 flex items-center gap-1.5 font-medium">
                            <Clock size={12} /> Resolved
                        </div>
                        <p className="text-sm text-slate-200">{formatTimestamp(action.resolved_at)}</p>
                    </div>
                )}
            </div>

            {action.reason && (
                <div className="bg-white/5 rounded-xl p-4 border border-white/5 mb-6">
                    <div className="text-xs font-bold text-slate-400 mb-2 uppercase tracking-wide flex items-center gap-2">
                        <AlertTriangle size={14} className="text-amber-400" /> Reason
                    </div>
                    <p className="text-sm text-slate-300 leading-relaxed">{action.reason}</p>
                </div>
            )}

            {action.execution_log && (
                <div className="bg-slate-950 rounded-xl p-4 border border-white/5 mb-6 overflow-x-auto max-h-48 overflow-y-auto">
                    <div className="text-xs font-bold text-slate-400 mb-2 uppercase tracking-wide flex items-center gap-2">
                        <Terminal size={14} className="text-indigo-400" /> Execution Log
                    </div>
                    <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap">{action.execution_log}</pre>
                </div>
            )}

            {action.status === 'pending' && (
                <div className="flex gap-3 pt-4 border-t border-white/10">
                    <button
                        type="button"
                        onClick={() => { onApprove(action.id); onClose(); }}
                        disabled={isProcessing}
                        data-tone="success"
                        className="flex-1 glass-button flex items-center justify-center gap-2 px-3 py-3 disabled:opacity-50"
                    >
                        <CheckCircle size={18} />
                        <span className="font-bold tracking-wide">AUTHORIZE EXECUTION</span>
                    </button>
                    <button
                        type="button"
                        onClick={() => { onReject(action.id); onClose(); }}
                        disabled={isProcessing}
                        data-tone="danger"
                        className="flex-1 glass-button flex items-center justify-center gap-2 px-3 py-3 disabled:opacity-50"
                    >
                        <XCircle size={18} />
                        <span className="font-bold tracking-wide">REJECT</span>
                    </button>
                </div>
            )}

            {action.status !== 'pending' && (
                <div className="flex items-center justify-center py-4 border-t border-white/10">
                    <span className={`text-sm font-bold uppercase tracking-wider px-4 py-2 rounded-xl border ${
                        action.status === 'approved' ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' :
                        action.status === 'rejected' ? 'text-red-400 bg-red-500/10 border-red-500/30' :
                        'text-slate-400 bg-white/5 border-white/10'
                    }`}>
                        {action.status}
                    </span>
                </div>
            )}
        </Modal>
    );
}
