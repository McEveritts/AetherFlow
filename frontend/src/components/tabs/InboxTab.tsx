import { useState } from 'react';
import { Mail, CheckCircle, XCircle, AlertTriangle, ShieldAlert, Code, RefreshCw, Loader2, Maximize2 } from 'lucide-react';
import { useToast } from '@/contexts/ToastContext';
import { useActionGates } from '@/hooks/useActionGates';
import { apiFetch } from '@/lib/fetcher';
import { ActionDetailModal } from '@/components/tabs/ActionDetailModal';
import type { PendingAction } from '@/types/api';
import ResponsiveSummary from '@/components/ui/ResponsiveSummary';

const classificationColors: Record<string, string> = {
    safe: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
    warn: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    critical: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
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
        <div className="animate-fade-in relative z-10 w-full min-w-0 max-w-full">
            <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 border-b border-white/[0.07] relative z-30 shrink-0">
                <div className="flex items-center gap-3 min-w-0">
                    <div className="h-10 w-10 rounded-xl flex items-center justify-center border bg-indigo-500/15 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.15)] text-indigo-400 shrink-0">
                        <Mail size={20} />
                    </div>
                    <div className="min-w-0">
                        <div className="flex items-center gap-2.5 flex-wrap">
                            <h2 className="text-base sm:text-lg md:text-xl font-extrabold text-slate-100 tracking-tight">
                                Action Approval Inbox
                            </h2>
                            <span className="text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
                                Gated Execution
                            </span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className="relative flex h-1.5 w-1.5 shrink-0">
                                <span className="absolute inline-flex h-full w-full rounded-full opacity-75 bg-emerald-400 animate-pulse"></span>
                                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                            </span>
                            <span className="text-xs text-slate-400 font-medium tracking-wide truncate">
                                Live Queue &middot; {actions.length} pending authorization
                            </span>
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                    <button
                        type="button"
                        onClick={() => refresh()}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive min-h-[44px] sm:min-h-[40px] flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none"
                        title="Refresh Queue"
                    >
                        <RefreshCw size={14} className={isValidating ? 'animate-spin text-indigo-400' : 'text-slate-400'} />
                        <span>Refresh</span>
                    </button>
                </div>
            </div>

            <ResponsiveSummary label={`Queue summary · ${actions.length} pending`}>
                <div className="grid grid-cols-2 xl:grid-cols-4 min-w-0 border-b border-white/[0.07] [&>div]:border-white/[0.07] [&>div:nth-child(even)]:border-l [&>div:nth-child(n+3)]:border-t xl:[&>div:nth-child(n+3)]:border-t-0 xl:[&>div:not(:first-child)]:border-l">
                    <div className="p-4 sm:p-5 flex items-center justify-between min-w-0">
                        <div className="min-w-0 flex-1">
                            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block break-words">
                                Total Pending
                            </span>
                            <div className="text-xl sm:text-2xl font-bold font-mono text-slate-100 mt-1 break-words">
                                {actions.length}
                            </div>
                            <span className="text-xs text-slate-500 mt-0.5 block break-words">
                                Awaiting operator signoff
                            </span>
                        </div>
                        <div className="h-10 w-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 hidden sm:flex items-center justify-center text-indigo-400 shrink-0 ml-3">
                            <Mail size={18} />
                        </div>
                    </div>

                    <div className="p-4 sm:p-5 flex items-center justify-between min-w-0">
                        <div className="min-w-0 flex-1">
                            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block break-words">
                                Critical Actions
                            </span>
                            <div className="text-xl sm:text-2xl font-bold font-mono text-rose-400 mt-1 break-words">
                                {criticalCount}
                            </div>
                            <span className="text-xs text-slate-500 mt-0.5 block break-words">
                                Immediate review required
                            </span>
                        </div>
                        <div className="h-10 w-10 rounded-xl bg-rose-500/10 border border-rose-500/20 hidden sm:flex items-center justify-center text-rose-400 shrink-0 ml-3">
                            <ShieldAlert size={18} />
                        </div>
                    </div>

                    <div className="p-4 sm:p-5 flex items-center justify-between min-w-0">
                        <div className="min-w-0 flex-1">
                            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block break-words">
                                Warnings
                            </span>
                            <div className="text-xl sm:text-2xl font-bold font-mono text-amber-400 mt-1 break-words">
                                {warnCount}
                            </div>
                            <span className="text-xs text-slate-500 mt-0.5 block break-words">
                                Elevated caution
                            </span>
                        </div>
                        <div className="h-10 w-10 rounded-xl bg-amber-500/10 border border-amber-500/20 hidden sm:flex items-center justify-center text-amber-400 shrink-0 ml-3">
                            <AlertTriangle size={18} />
                        </div>
                    </div>

                    <div className="p-4 sm:p-5 flex items-center justify-between min-w-0">
                        <div className="min-w-0 flex-1">
                            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block break-words">
                                Safe Routines
                            </span>
                            <div className="text-xl sm:text-2xl font-bold font-mono text-emerald-400 mt-1 break-words">
                                {safeCount}
                            </div>
                            <span className="text-xs text-slate-500 mt-0.5 block break-words">
                                Low blast radius
                            </span>
                        </div>
                        <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 hidden sm:flex items-center justify-center text-emerald-400 shrink-0 ml-3">
                            <CheckCircle size={18} />
                        </div>
                    </div>
                </div>
            </ResponsiveSummary>

            <div role="group" aria-label="Action classification filters" className="flex flex-wrap items-center justify-between gap-3 px-5 py-3 border-b border-white/[0.07] bg-white/[0.005]">
                <div className="flex flex-wrap items-center gap-1.5">
                    <button
                        type="button"
                        onClick={() => setFilter('all')}
                        className={`obs-touch-target-standard px-3 py-1.5 rounded-lg text-xs font-medium transition-colors min-h-[40px] flex items-center ${
                            filter === 'all'
                                ? 'bg-indigo-600 text-white shadow-sm'
                                : 'bg-white/[0.03] text-slate-400 hover:text-slate-200 border border-white/[0.08]'
                        }`}
                    >
                        All ({actions.length})
                    </button>
                    <button
                        type="button"
                        onClick={() => setFilter('critical')}
                        className={`obs-touch-target-standard px-3 py-1.5 rounded-lg text-xs font-medium transition-colors min-h-[40px] flex items-center gap-1.5 ${
                            filter === 'critical'
                                ? 'bg-rose-600 text-white shadow-sm'
                                : 'bg-white/[0.03] text-slate-400 hover:text-slate-200 border border-white/[0.08]'
                        }`}
                    >
                        <ShieldAlert size={13} className={filter === 'critical' ? 'text-white' : 'text-rose-400'} />
                        Critical ({criticalCount})
                    </button>
                    <button
                        type="button"
                        onClick={() => setFilter('warn')}
                        className={`obs-touch-target-standard px-3 py-1.5 rounded-lg text-xs font-medium transition-colors min-h-[40px] flex items-center gap-1.5 ${
                            filter === 'warn'
                                ? 'bg-amber-600 text-white shadow-sm'
                                : 'bg-white/[0.03] text-slate-400 hover:text-slate-200 border border-white/[0.08]'
                        }`}
                    >
                        <AlertTriangle size={13} className={filter === 'warn' ? 'text-white' : 'text-amber-400'} />
                        Warnings ({warnCount})
                    </button>
                    <button
                        type="button"
                        onClick={() => setFilter('safe')}
                        className={`obs-touch-target-standard px-3 py-1.5 rounded-lg text-xs font-medium transition-colors min-h-[40px] flex items-center gap-1.5 ${
                            filter === 'safe'
                                ? 'bg-emerald-600 text-white shadow-sm'
                                : 'bg-white/[0.03] text-slate-400 hover:text-slate-200 border border-white/[0.08]'
                        }`}
                    >
                        <CheckCircle size={13} className={filter === 'safe' ? 'text-white' : 'text-emerald-400'} />
                        Safe ({safeCount})
                    </button>
                </div>
                {filter !== 'all' && (
                    <span className="text-xs text-slate-400">
                        Showing {filteredActions.length} of {actions.length} actions
                    </span>
                )}
            </div>

            {/* Action List Section */}
            <section aria-label="Action approval queue" className="min-w-0">
                {/* Loading state */}
                {isLoading && (
                    <div className="border-b border-white/[0.07] flex flex-col items-center justify-center py-20 text-slate-500">
                        <Loader2 size={36} className="text-indigo-400 mb-4 animate-spin" />
                        <h3 className="text-sm font-bold text-slate-300">Loading Actions</h3>
                        <p className="text-xs text-slate-400 mt-1">Fetching pending actions from the trust spine...</p>
                    </div>
                )}

                {/* Error state */}
                {isError && (
                    <div className="border-b border-rose-500/20 bg-rose-950/20 flex flex-col items-center justify-center py-16 px-4 text-slate-400 text-center">
                        <AlertTriangle size={36} className="text-rose-400 mb-3" />
                        <h3 className="text-sm font-bold text-rose-200">Connection Error</h3>
                        <p className="text-xs text-rose-300/80 mb-4">{error instanceof Error ? error.message : 'Failed to load pending actions'}</p>
                        <button
                            type="button"
                            onClick={() => refresh()}
                            className="obs-touch-target-standard min-h-[44px] px-4 py-2 rounded-lg text-xs font-semibold bg-rose-500/20 border border-rose-500/30 text-rose-300 hover:bg-rose-500/30 transition-all"
                        >
                            Retry
                        </button>
                    </div>
                )}

                {/* Empty state */}
                {!isLoading && !isError && actions.length === 0 && (
                    <div className="border-b border-white/[0.07] flex flex-col items-center justify-center py-20 text-slate-500 text-center px-4">
                        <div className="h-11 w-11 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mb-3">
                            <CheckCircle size={22} />
                        </div>
                        <h3 className="text-sm font-bold text-slate-200">Queue Empty</h3>
                        <p className="text-xs text-slate-400 mt-1">No pending automated actions require your authorization.</p>
                    </div>
                )}

                {/* Filter Empty state */}
                {!isLoading && !isError && actions.length > 0 && filteredActions.length === 0 && (
                    <div className="border-b border-white/[0.07] flex flex-col items-center justify-center py-16 text-slate-500 text-center px-4">
                        <Mail size={30} className="text-slate-600 mb-2" />
                        <h3 className="text-sm font-semibold text-slate-300">No matching actions</h3>
                        <p className="text-xs text-slate-400 mt-1">No pending actions match the &quot;{filter}&quot; filter.</p>
                    </div>
                )}

                {!isError && filteredActions.length > 0 && (
                    <div className="min-w-0 rounded-none shadow-none bg-transparent border-b border-white/[0.07] divide-y divide-white/[0.07]">
                        {filteredActions.map(action => {
                            const isProcessing = processingIds.has(action.id);
                            return (
                                <div
                                    key={action.id}
                                    role="article"
                                    aria-label={`${action.action} pending action`}
                                    className="relative min-w-0 p-5 hover:bg-white/[0.02] transition-colors cursor-pointer group overflow-hidden"
                                    onClick={() => setSelectedAction(action)}
                                >
                                    <div className={`absolute top-0 left-0 w-1 h-full ${
                                        action.classification === 'critical' ? 'bg-rose-500' :
                                        action.classification === 'warn' ? 'bg-amber-500' :
                                        'bg-emerald-500'
                                    } transition-colors z-20`} />

                                    <div className="flex flex-col lg:flex-row justify-between items-start gap-5">
                                        {/* Left Content Area */}
                                        <div className="flex-1 w-full space-y-3 min-w-0">
                                            <div className="flex flex-wrap items-center gap-2.5">
                                                <span className="text-xs font-bold uppercase tracking-wider text-slate-300 border border-white/10 px-2 py-0.5 rounded bg-white/5">
                                                    {action.source}
                                                </span>
                                                <span className="text-xs text-slate-400">{formatTimestamp(action.created_at)}</span>
                                                <span className={`text-xs font-bold uppercase tracking-widest px-2 py-0.5 rounded-full border ${classificationColors[action.classification] || classificationColors.warn} flex items-center gap-1`}>
                                                    {action.classification === 'critical' && <ShieldAlert size={12} />}
                                                    {action.classification}
                                                </span>
                                                <button
                                                    type="button"
                                                    onClick={(e) => { e.stopPropagation(); setSelectedAction(action); }}
                                                    className="ml-auto obs-touch-target-standard p-2 rounded-lg text-slate-400 hover:text-indigo-400 hover:bg-white/[0.04] transition-colors flex items-center justify-center min-h-[44px] min-w-[44px] sm:min-h-[44px] sm:min-w-[44px]"
                                                    title="View Details"
                                                    aria-label={`View details for ${action.action}`}
                                                >
                                                    <Maximize2 size={14} />
                                                </button>
                                            </div>

                                            <h3 className="text-sm sm:text-base font-bold text-slate-100 break-words">{action.action}</h3>

                                            {action.reason && (
                                                <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.06]">
                                                    <div className="text-xs font-bold text-slate-400 mb-1 flex items-center gap-1.5 uppercase tracking-wide">
                                                        <AlertTriangle size={13} className="text-amber-400 shrink-0" /> Reason
                                                    </div>
                                                    <p className="text-xs text-slate-300 leading-relaxed break-words">{action.reason}</p>
                                                </div>
                                            )}

                                            {action.execution_log && (
                                                <div className="bg-slate-950/80 rounded-lg p-3 border border-white/[0.06] overflow-x-auto">
                                                    <div className="text-xs font-bold text-slate-400 mb-1.5 flex items-center gap-1.5 uppercase tracking-wide">
                                                        <Code size={13} className="text-indigo-400 shrink-0" /> Execution Log
                                                    </div>
                                                    <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap break-all">
                                                        {action.execution_log}
                                                    </pre>
                                                </div>
                                            )}
                                        </div>

                                        {/* Right Action Area */}
                                        <div className="flex flex-row lg:flex-col gap-2.5 w-full lg:w-44 shrink-0" onClick={(e) => e.stopPropagation()}>
                                            <button
                                                type="button"
                                                onClick={() => handleApprove(action.id, action.action, action.source)}
                                                disabled={isProcessing}
                                                className="obs-touch-target-standard obs-gpu-120hz-interactive min-h-[44px] flex-1 flex items-center justify-center gap-2 py-2 px-3.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 text-xs font-bold tracking-wide transition-all shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
                                                aria-label={`Authorize ${action.action}`}
                                            >
                                                {isProcessing ? <Loader2 size={16} className="animate-spin" /> : <CheckCircle size={16} />}
                                                <span>AUTHORIZE</span>
                                            </button>
                                            <button
                                                type="button"
                                                onClick={() => handleReject(action.id)}
                                                disabled={isProcessing}
                                                className="obs-touch-target-standard obs-gpu-120hz-interactive min-h-[44px] flex-1 flex items-center justify-center gap-2 py-2 px-3.5 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 text-xs font-bold tracking-wide transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                                                aria-label={`Reject ${action.action}`}
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
                )}
            </section>

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
