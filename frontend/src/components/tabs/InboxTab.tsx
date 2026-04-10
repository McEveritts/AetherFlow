import { useState } from 'react';
import { Mail, CheckCircle, XCircle, AlertTriangle, ShieldAlert, Code, RefreshCw, Loader2, Maximize2 } from 'lucide-react';
import { useToast } from '@/contexts/ToastContext';
import { useActionGates } from '@/hooks/useActionGates';
import { apiFetch } from '@/lib/fetcher';
import { ActionDetailModal } from '@/components/tabs/ActionDetailModal';
import type { PendingAction } from '@/types/api';

const classificationColors: Record<string, string> = {
    safe: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
    warn: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    critical: 'text-red-400 bg-red-500/10 border-red-500/30',
};

function formatTimestamp(iso: string): string {
    try {
        const date = new Date(iso);
        const now = new Date();
        const diffMs = now.getTime() - date.getTime();
        const diffMins = Math.floor(diffMs / 60000);
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins} min${diffMins > 1 ? 's' : ''} ago`;
        const diffHours = Math.floor(diffMins / 60);
        if (diffHours < 24) return `${diffHours} hr${diffHours > 1 ? 's' : ''} ago`;
        return date.toLocaleDateString();
    } catch {
        return iso;
    }
}

export default function InboxTab() {
    const { addToast } = useToast();
    const { actions, isLoading, isError, error, isValidating, approveAction, rejectAction, refresh } = useActionGates();
    const [processingIds, setProcessingIds] = useState<Set<number>>(new Set());
    const [selectedAction, setSelectedAction] = useState<PendingAction | null>(null);

    const handleApprove = async (id: number, actionTitle: string, source: string) => {
        setProcessingIds(prev => new Set(prev).add(id));
        try {
            const success = await approveAction(id);
            if (success) {
                // If it's an AI-proposed action, the UI explicitly triggers the executor
                // to bridge the human-in-the-loop boundary and run the real backend logic.
                if (source === 'FlowAI') {
                    const match = actionTitle.match(/^(Restart|Stop|Start)\s+(.+)$/i);
                    if (match) {
                        const verb = match[1].toLowerCase();
                        const target = match[2];
                        try {
                            const res = await apiFetch(`/api/v1/admin/services/${encodeURIComponent(target)}/control`, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ action: verb, process: target })
                            });
                            if (!res.ok) {
                                console.error("FlowAI executor failure", await res.text());
                            }
                        } catch (e) {
                            console.error("FlowAI executor boundary exception", e);
                        }
                    }
                }
                addToast(`Execution authorized: ${actionTitle}`, 'success');
            } else {
                addToast('Approval failed — action may already be resolved or missing.', 'error');
            }
        } catch (err) {
            addToast(err instanceof Error ? err.message : 'Approval failed', 'error');
        } finally {
            setProcessingIds(prev => {
                const next = new Set(prev);
                next.delete(id);
                return next;
            });
        }
    };

    const handleReject = async (id: number) => {
        setProcessingIds(prev => new Set(prev).add(id));
        try {
            const success = await rejectAction(id);
            if (success) {
                addToast('Action rejected. Execution halted.', 'info');
            } else {
                addToast('Rejection failed — action may already be resolved', 'error');
            }
        } catch (err) {
            addToast(err instanceof Error ? err.message : 'Rejection failed', 'error');
        } finally {
            setProcessingIds(prev => {
                const next = new Set(prev);
                next.delete(id);
                return next;
            });
        }
    };

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-h-screen">
            <div className="absolute inset-0 bg-indigo-500/5 rounded-full blur-[120px] pointer-events-none -translate-y-1/2 -translate-x-1/2"></div>

            <div className="glass-panel rounded-3xl p-6 md:p-10 relative overflow-hidden">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8 pb-4 border-b border-white/5 relative z-10">
                    <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
                        <Mail size={24} className="text-indigo-400" />
                        Action Approval Inbox
                        {actions.length > 0 && (
                            <span className="bg-indigo-500 text-white text-sm font-bold px-2 py-0.5 rounded-full">
                                {actions.length}
                            </span>
                        )}
                    </h2>
                    <div className="flex items-center gap-3">
                        <p className="text-sm text-slate-400">Strict operator consent required.</p>
                        <button
                            onClick={() => refresh()}
                            className="glass-button p-2 rounded-xl hover:border-indigo-500/30"
                            title="Refresh"
                        >
                            <RefreshCw size={16} className={isValidating ? 'animate-spin text-indigo-400' : 'text-slate-400'} />
                        </button>
                    </div>
                </div>

                <div className="space-y-6 relative z-10">
                    {/* Loading state */}
                    {isLoading && (
                        <div className="flex flex-col items-center justify-center py-20 text-slate-500">
                            <Loader2 size={48} className="text-indigo-500/30 mb-4 animate-spin" />
                            <h3 className="text-lg font-bold text-slate-300">Loading Actions</h3>
                            <p className="text-sm">Fetching pending actions from the trust spine...</p>
                        </div>
                    )}

                    {/* Error state */}
                    {isError && (
                        <div className="flex flex-col items-center justify-center py-20 text-slate-500">
                            <AlertTriangle size={48} className="text-red-500/30 mb-4" />
                            <h3 className="text-lg font-bold text-red-300">Connection Error</h3>
                            <p className="text-sm mb-4">{error instanceof Error ? error.message : 'Failed to load pending actions'}</p>
                            <button
                                onClick={() => refresh()}
                                className="glass-button-primary px-4 py-2 rounded-xl text-sm"
                            >
                                Retry
                            </button>
                        </div>
                    )}

                    {/* Empty state */}
                    {!isLoading && !isError && actions.length === 0 && (
                        <div className="flex flex-col items-center justify-center py-20 text-slate-500">
                            <CheckCircle size={48} className="text-emerald-500/20 mb-4" />
                            <h3 className="text-lg font-bold text-slate-300">Queue Empty</h3>
                            <p className="text-sm">No pending automated actions require your authorization.</p>
                        </div>
                    )}

                    {/* Action list */}
                    {!isError && actions.map(action => {
                        const isProcessing = processingIds.has(action.id);
                        return (
                            <div 
                                key={action.id} 
                                className="bg-slate-900/60 border border-white/10 rounded-2xl p-6 transition-all hover:border-indigo-500/30 cursor-pointer group"
                                onClick={() => setSelectedAction(action)}
                            >
                                <div className="flex flex-col lg:flex-row justify-between items-start gap-6">
                                    
                                    {/* Left Content Area */}
                                    <div className="flex-1 w-full space-y-4">
                                        <div className="flex flex-wrap items-center gap-3">
                                            <span className="text-xs font-bold uppercase tracking-wider text-slate-400 border border-white/10 px-2 py-1 rounded bg-white/5">
                                                {action.source}
                                            </span>
                                            <span className="text-xs text-slate-500">{formatTimestamp(action.created_at)}</span>
                                            <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-1 rounded border ${classificationColors[action.classification] || classificationColors.warn} flex items-center gap-1`}>
                                                {action.classification === 'critical' && <ShieldAlert size={12} />}
                                                {action.classification}
                                            </span>
                                            <button 
                                                onClick={(e) => { e.stopPropagation(); setSelectedAction(action); }}
                                                className="ml-auto opacity-0 group-hover:opacity-100 transition-opacity text-slate-500 hover:text-indigo-400"
                                                title="View Details"
                                            >
                                                <Maximize2 size={14} />
                                            </button>
                                        </div>

                                        <h3 className="text-lg font-bold text-slate-200">{action.action}</h3>

                                        {action.reason && (
                                            <div className="bg-white/5 rounded-xl p-4 border border-white/5">
                                                <div className="text-xs font-bold text-slate-400 mb-1 flex items-center gap-2 uppercase tracking-wide">
                                                    <AlertTriangle size={14} className="text-amber-400" /> Reason
                                                </div>
                                                <p className="text-sm text-slate-300 left-border-accent">{action.reason}</p>
                                            </div>
                                        )}

                                        {action.execution_log && (
                                            <div className="bg-slate-950 rounded-xl p-4 border border-white/5 overflow-x-auto">
                                                <div className="text-xs font-bold text-slate-400 mb-2 flex items-center gap-2 uppercase tracking-wide">
                                                    <Code size={14} className="text-indigo-400" /> Execution Log
                                                </div>
                                                <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap">
                                                    {action.execution_log}
                                                </pre>
                                            </div>
                                        )}
                                    </div>

                                    {/* Right Action Area */}
                                    <div className="flex flex-row lg:flex-col gap-3 w-full lg:w-48 shrink-0" onClick={(e) => e.stopPropagation()}>
                                        <button 
                                            onClick={() => handleApprove(action.id, action.action, action.source)}
                                            disabled={isProcessing}
                                            className="flex-1 glass-button-primary flex items-center justify-center gap-2 py-3 px-4 shadow-[0_0_15px_rgba(34,197,94,0.2)] hover:shadow-[0_0_20px_rgba(34,197,94,0.4)] border-emerald-500/50 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
                                        >
                                            {isProcessing ? <Loader2 size={18} className="animate-spin" /> : <CheckCircle size={18} />}
                                            <span className="font-bold tracking-wide">AUTHORIZE</span>
                                        </button>
                                        <button 
                                            onClick={() => handleReject(action.id)}
                                            disabled={isProcessing}
                                            className="flex-1 glass-button flex items-center justify-center gap-2 py-3 px-4 border-red-500/30 text-red-400 hover:bg-red-500/10 hover:border-red-500/50 disabled:opacity-50 disabled:cursor-not-allowed"
                                        >
                                            {isProcessing ? <Loader2 size={18} className="animate-spin" /> : <XCircle size={18} />}
                                            <span className="font-bold tracking-wide">REJECT</span>
                                        </button>
                                    </div>
                                    
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Action Detail Modal */}
            <ActionDetailModal
                action={selectedAction}
                isOpen={!!selectedAction}
                onClose={() => setSelectedAction(null)}
                onApprove={(id) => handleApprove(id, selectedAction?.action || '', selectedAction?.source || '')}
                onReject={handleReject}
                isProcessing={selectedAction ? processingIds.has(selectedAction.id) : false}
            />
        </div>
    );
}
