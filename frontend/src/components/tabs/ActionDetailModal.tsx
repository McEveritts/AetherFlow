import { Modal } from '@/components/ui/Modal';
import { AlertTriangle, ShieldAlert, Clock, User, Terminal, CheckCircle, XCircle } from 'lucide-react';
import type { PendingAction } from '@/types/api';

interface ActionDetailModalProps {
    action: PendingAction | null;
    isOpen: boolean;
    onClose: () => void;
    onApprove: (id: number) => void;
    onReject: (id: number) => void;
    isProcessing: boolean;
}

const classificationConfig: Record<string, { label: string; color: string; icon: typeof AlertTriangle }> = {
    safe: { label: 'Safe', color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30', icon: CheckCircle },
    warn: { label: 'Warning', color: 'text-amber-400 bg-amber-500/10 border-amber-500/30', icon: AlertTriangle },
    critical: { label: 'Critical', color: 'text-red-400 bg-red-500/10 border-red-500/30', icon: ShieldAlert },
};

function formatTimestamp(iso: string): string {
    try {
        return new Date(iso).toLocaleString();
    } catch {
        return iso;
    }
}

export function ActionDetailModal({ action, isOpen, onClose, onApprove, onReject, isProcessing }: ActionDetailModalProps) {
    if (!action) return null;

    const config = classificationConfig[action.classification] || classificationConfig.warn;
    const ClassIcon = config.icon;

    return (
        <Modal isOpen={isOpen} onClose={onClose} className="max-w-2xl">
            {/* Header */}
            <div className="flex items-start gap-4 border-b border-white/10 pb-5 mb-5">
                <div className={`p-3 rounded-xl border ${config.color}`}>
                    <ClassIcon size={24} />
                </div>
                <div className="flex-1 min-w-0">
                    <h3 className="text-xl font-bold text-white truncate">{action.action}</h3>
                    <div className="flex items-center gap-3 mt-2">
                        <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-1 rounded border ${config.color}`}>
                            {config.label}
                        </span>
                        <span className="text-xs text-slate-500 font-mono">#{action.id}</span>
                    </div>
                </div>
            </div>

            {/* Metadata Grid */}
            <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="bg-white/5 rounded-xl p-3 border border-white/5">
                    <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 flex items-center gap-1">
                        <Terminal size={10} /> Source
                    </div>
                    <p className="text-sm font-bold text-slate-200">{action.source}</p>
                </div>
                <div className="bg-white/5 rounded-xl p-3 border border-white/5">
                    <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 flex items-center gap-1">
                        <Clock size={10} /> Created
                    </div>
                    <p className="text-sm text-slate-200">{formatTimestamp(action.created_at)}</p>
                </div>
                {action.resolved_by && (
                    <div className="bg-white/5 rounded-xl p-3 border border-white/5">
                        <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 flex items-center gap-1">
                            <User size={10} /> Resolved By
                        </div>
                        <p className="text-sm text-slate-200">{action.resolved_by}</p>
                    </div>
                )}
                {action.resolved_at && (
                    <div className="bg-white/5 rounded-xl p-3 border border-white/5">
                        <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 flex items-center gap-1">
                            <Clock size={10} /> Resolved
                        </div>
                        <p className="text-sm text-slate-200">{formatTimestamp(action.resolved_at)}</p>
                    </div>
                )}
            </div>

            {/* Reason */}
            {action.reason && (
                <div className="bg-white/5 rounded-xl p-4 border border-white/5 mb-6">
                    <div className="text-xs font-bold text-slate-400 mb-2 uppercase tracking-wide flex items-center gap-2">
                        <AlertTriangle size={14} className="text-amber-400" /> Reason
                    </div>
                    <p className="text-sm text-slate-300 leading-relaxed">{action.reason}</p>
                </div>
            )}

            {/* Execution Log */}
            {action.execution_log && (
                <div className="bg-slate-950 rounded-xl p-4 border border-white/5 mb-6 overflow-x-auto max-h-48 overflow-y-auto">
                    <div className="text-xs font-bold text-slate-400 mb-2 uppercase tracking-wide flex items-center gap-2">
                        <Terminal size={14} className="text-indigo-400" /> Execution Log
                    </div>
                    <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap">{action.execution_log}</pre>
                </div>
            )}

            {/* Action Buttons */}
            {action.status === 'pending' && (
                <div className="flex gap-3 pt-4 border-t border-white/10">
                    <button
                        onClick={() => { onApprove(action.id); onClose(); }}
                        disabled={isProcessing}
                        className="flex-1 glass-button-primary flex items-center justify-center gap-2 py-3 shadow-[0_0_15px_rgba(34,197,94,0.2)] hover:shadow-[0_0_20px_rgba(34,197,94,0.4)] border-emerald-500/50 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 disabled:opacity-50"
                    >
                        <CheckCircle size={18} />
                        <span className="font-bold tracking-wide">AUTHORIZE EXECUTION</span>
                    </button>
                    <button
                        onClick={() => { onReject(action.id); onClose(); }}
                        disabled={isProcessing}
                        className="flex-1 glass-button flex items-center justify-center gap-2 py-3 border-red-500/30 text-red-400 hover:bg-red-500/10 hover:border-red-500/50 disabled:opacity-50"
                    >
                        <XCircle size={18} />
                        <span className="font-bold tracking-wide">REJECT</span>
                    </button>
                </div>
            )}

            {/* Resolved Badge */}
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
