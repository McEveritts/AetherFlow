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
    const [filter, setFilter] = useState<'all' | 'critical' | 'warn' | 'safe'>('all');

    const criticalCount = actions.filter(a => a.classification === 'critical').length;
    const warnCount = actions.filter(a => a.classification === 'warn').length;
    const safeCount = actions.filter(a => a.classification === 'safe').length;

    const filteredActions = filter === 'all'
        ? actions
        : actions.filter(a => a.classification === filter);

    const handleApprove = async (id: number, actionTitle: string, source: string) => {
        setProcessingIds(prev => new Set(prev).add(id));
        try {
            const success = await approveAction(id);
            if (success) {
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
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-w-0">
            {/* Open Top Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-2 border-b border-white/[0.06] relative z-30 shrink-0">
                <div className="flex items-center gap-3.5">
                    <div className="h-10 w-10 rounded-xl flex items-center justify-center border bg-indigo-500/20 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.15)] text-indigo-400">
                        <Mail size={20} />
                    </div>
                    <div>
                        <div className="flex items-center gap-2.5">
                            <h2 className="text-lg font-bold text-slate-100 tracking-tight">Action Approval Inbox</h2>
                            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
                                Gated Execution
                            </span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className="relative flex h-1.5 w-1.5">
                                <span className="absolute inline-flex h-full w-full rounded-full opacity-75 bg-emerald-400"></span>
                                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                            </span>
                            <span className="text-xs text-slate-400 font-medium tracking-wide">
                                Live Queue · {actions.length} pending authorization
                            </span>
                        </div>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                    <button
                        onClick={() => refresh()}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all"
                        title="Refresh Queue"
                    >
                        <RefreshCw size={14} className={isValidating ? 'animate-spin text-indigo-400' : 'text-slate-400'} />
                        <span>Refresh</span>
                    </button>
                </div>
            </div>

            {/* Classification Filter Pills */}
            <div className="flex flex-wrap items-center gap-2">
                <button
                    type="button"
                    onClick={() => setFilter('all')}
                    className={`obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-semibold transition-all border ${
                        filter === 'all'
                            ? 'bg-indigo-500/20 border-indigo-500/30 text-indigo-300 shadow-lg shadow-indigo-500/10'
                            : 'bg-white/[0.04] border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white'
                    }`}
                >
                    All ({actions.length})
                </button>
                <button
                    type="button"
                    onClick={() => setFilter('critical')}
                    className={`obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-semibold transition-all border ${
                        filter === 'critical'
                            ? 'bg-red-500/20 border-red-500/30 text-red-300 shadow-lg shadow-red-500/10'
                            : 'bg-white/[0.04] border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white'
                    }`}
                >
                    <ShieldAlert size={13} className="text-red-400" />
                    Critical ({criticalCount})
                </button>
                <button
                    type="button"
                    onClick={() => setFilter('warn')}
                    className={`obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-semibold transition-all border ${
                        filter === 'warn'
                            ? 'bg-amber-500/20 border-amber-500/30 text-amber-300 shadow-lg shadow-amber-500/10'
                            : 'bg-white/[0.04] border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white'
                    }`}
                >
                    <AlertTriangle size={13} className="text-amber-400" />
                    Warnings ({warnCount})
                </button>
                <button
                    type="button"
                    onClick={() => setFilter('safe')}
                    className={`obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-semibold transition-all border ${
                        filter === 'safe'
                            ? 'bg-emerald-500/20 border-emerald-500/30 text-emerald-300 shadow-lg shadow-emerald-500/10'
                            : 'bg-white/[0.04] border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white'
                    }`}
                >
                    <CheckCircle size={13} className="text-emerald-400" />
                    Safe ({safeCount})
                </button>
            </div>

            {/* Open Telemetry Summary Strip */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Total Pending</p>
                        <p className="text-2xl font-bold text-slate-100 mt-1">{actions.length}</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                        <Mail size={20} />
                    </div>
                </div>
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Critical Actions</p>
                        <p className="text-2xl font-bold text-red-400 mt-1">{criticalCount}</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400">
                        <ShieldAlert size={20} />
                    </div>
                </div>
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Warnings</p>
                        <p className="text-2xl font-bold text-amber-400 mt-1">{warnCount}</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
                        <AlertTriangle size={20} />
                    </div>
                </div>
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Safe Routines</p>
                        <p className="text-2xl font-bold text-emerald-400 mt-1">{safeCount}</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                        <CheckCircle size={20} />
                    </div>
                </div>
            </div>

            {/* Action List Section */}
            <div className="space-y-4">
                {/* Loading state */}
                {isLoading && (
                    <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl flex flex-col items-center justify-center py-20 text-slate-500">
                        <Loader2 size={40} className="text-indigo-500/40 mb-4 animate-spin" />
                        <h3 className="text-base font-bold text-slate-300">Loading Actions</h3>
                        <p className="text-xs text-slate-400 mt-1">Fetching pending actions from the trust spine...</p>
                    </div>
                )}

                {/* Error state */}
                {isError && (
                    <div className="rounded-2xl border border-red-500/20 bg-red-950/20 backdrop-blur-xl flex flex-col items-center justify-center py-16 text-slate-400">
                        <AlertTriangle size={40} className="text-red-400 mb-3" />
                        <h3 className="text-base font-bold text-red-200">Connection Error</h3>
                        <p className="text-xs text-red-300/80 mb-4">{error instanceof Error ? error.message : 'Failed to load pending actions'}</p>
                        <button
                            onClick={() => refresh()}
                            className="obs-touch-target-standard obs-gpu-120hz-interactive px-4 py-2 rounded-xl text-xs font-semibold bg-red-500/20 border border-red-500/30 text-red-300 hover:bg-red-500/30 transition-all"
                        >
                            Retry
                        </button>
                    </div>
                )}

                {/* Empty state */}
                {!isLoading && !isError && actions.length === 0 && (
                    <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl flex flex-col items-center justify-center py-20 text-slate-500">
                        <div className="h-12 w-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mb-3">
                            <CheckCircle size={24} />
                        </div>
                        <h3 className="text-base font-bold text-slate-200">Queue Empty</h3>
                        <p className="text-xs text-slate-400 mt-1">No pending automated actions require your authorization.</p>
                    </div>
                )}

                {/* Filter Empty state */}
                {!isLoading && !isError && actions.length > 0 && filteredActions.length === 0 && (
                    <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl flex flex-col items-center justify-center py-16 text-slate-500">
                        <Mail size={32} className="text-slate-600 mb-2" />
                        <h3 className="text-sm font-semibold text-slate-300">No matching actions</h3>
                        <p className="text-xs text-slate-400 mt-1">No pending actions match the &quot;{filter}&quot; filter.</p>
                    </div>
                )}

                {/* Action cards (actions.map) */}
                {!isError && filteredActions.map(action => {
                    const isProcessing = processingIds.has(action.id);
                    return (
                        <div
                            key={action.id}
                            className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl hover:border-white/10 p-5 transition-all cursor-pointer group"
                            onClick={() => setSelectedAction(action)}
                        >
                            <div className="flex flex-col lg:flex-row justify-between items-start gap-6">
                                {/* Left Content Area */}
                                <div className="flex-1 w-full space-y-3">
                                    <div className="flex flex-wrap items-center gap-2.5">
                                        <span className="text-xs font-bold uppercase tracking-wider text-slate-400 border border-white/10 px-2 py-0.5 rounded-lg bg-white/5">
                                            {action.source}
                                        </span>
                                        <span className="text-xs text-slate-500">{formatTimestamp(action.created_at)}</span>
                                        <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-full border ${classificationColors[action.classification] || classificationColors.warn} flex items-center gap-1`}>
                                            {action.classification === 'critical' && <ShieldAlert size={12} />}
                                            {action.classification}
                                        </span>
                                        <button
                                            onClick={(e) => { e.stopPropagation(); setSelectedAction(action); }}
                                            className="ml-auto obs-touch-target-standard obs-touch-action-reveal opacity-100 md:opacity-0 md:group-hover:opacity-100 p-2 rounded-lg transition-opacity text-slate-500 hover:text-indigo-400 flex items-center justify-center"
                                            title="View Details"
                                        >
                                            <Maximize2 size={14} />
                                        </button>
                                    </div>

                                    <h3 className="text-base font-bold text-slate-100">{action.action}</h3>

                                    {action.reason && (
                                        <div className="bg-white/[0.02] rounded-xl p-3.5 border border-white/[0.06]">
                                            <div className="text-xs font-bold text-slate-400 mb-1 flex items-center gap-1.5 uppercase tracking-wide">
                                                <AlertTriangle size={13} className="text-amber-400" /> Reason
                                            </div>
                                            <p className="text-xs text-slate-300 leading-relaxed">{action.reason}</p>
                                        </div>
                                    )}

                                    {action.execution_log && (
                                        <div className="bg-slate-950/80 rounded-xl p-3.5 border border-white/[0.06] overflow-x-auto">
                                            <div className="text-xs font-bold text-slate-400 mb-1.5 flex items-center gap-1.5 uppercase tracking-wide">
                                                <Code size={13} className="text-indigo-400" /> Execution Log
                                            </div>
                                            <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap">
                                                {action.execution_log}
                                            </pre>
                                        </div>
                                    )}
                                </div>

                                {/* Right Action Area */}
                                <div className="flex flex-row lg:flex-col gap-2.5 w-full lg:w-44 shrink-0" onClick={(e) => e.stopPropagation()}>
                                    <button
                                        onClick={() => handleApprove(action.id, action.action, action.source)}
                                        disabled={isProcessing}
                                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex-1 flex items-center justify-center gap-2 py-2.5 px-3.5 rounded-xl border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 text-xs font-bold tracking-wide transition-all shadow-[0_0_15px_rgba(34,197,94,0.15)] disabled:opacity-50 disabled:cursor-not-allowed"
                                    >
                                        {isProcessing ? <Loader2 size={16} className="animate-spin" /> : <CheckCircle size={16} />}
                                        <span>AUTHORIZE</span>
                                    </button>
                                    <button
                                        onClick={() => handleReject(action.id)}
                                        disabled={isProcessing}
                                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex-1 flex items-center justify-center gap-2 py-2.5 px-3.5 rounded-xl border border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/20 text-xs font-bold tracking-wide transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                                    >
                                        {isProcessing ? <Loader2 size={16} className="animate-spin" /> : <XCircle size={16} />}
                                        <span>REJECT</span>
                                    </button>
                                </div>
                            </div>
                        </div>
                    );
                })}
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
