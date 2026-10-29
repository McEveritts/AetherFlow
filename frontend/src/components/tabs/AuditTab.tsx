'use client';

import { useState, useCallback } from 'react';
import useSWR from 'swr';
import { Search, Filter, ChevronLeft, ChevronRight, Clock, User, Activity, FileText, RefreshCw, Shield, Zap, CheckCircle2 } from 'lucide-react';
import { useToast } from '@/contexts/ToastContext';
import { apiFetch } from '@/lib/fetcher';
import { ActionDetailModal } from '@/components/tabs/ActionDetailModal';
import ServiceLogsModal from '@/components/tabs/ServiceLogsModal';
import type { PendingAction } from '@/types/api';

interface AuditEntry {
    id: number;
    user_id: number;
    username: string;
    action: string;
    target_type: string;
    target_id: string;
    detail: string;
    ip_address: string;
    user_agent: string;
    created_at: string;
}

interface AuditResponse {
    entries: AuditEntry[];
    total: number;
    limit: number;
    offset: number;
}

const ACTION_BADGE_MAP: Record<string, { label: string; color: string }> = {
    action_approve: { label: 'Approved', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' },
    action_reject: { label: 'Rejected', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
    ai_action_proposed: { label: 'AI Proposed', color: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30' },
    service_start: { label: 'Start', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' },
    service_stop: { label: 'Stop', color: 'bg-amber-500/20 text-amber-400 border-amber-500/30' },
    service_restart: { label: 'Restart', color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
    user_role_change: { label: 'Role Change', color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
    user_delete: { label: 'User Delete', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
    oidc_client_create: { label: 'OIDC Create', color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
    oidc_client_delete: { label: 'OIDC Delete', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
    backup_download: { label: 'Backup DL', color: 'bg-slate-500/20 text-slate-300 border-slate-500/30' },
    system_update: { label: 'System Update', color: 'bg-amber-500/20 text-amber-400 border-amber-500/30' },
};

function ActionBadge({ action }: { action: string }) {
    const badge = ACTION_BADGE_MAP[action] || { label: action.replace(/_/g, ' '), color: 'bg-slate-500/20 text-slate-300 border-slate-500/30' };
    return (
        <span className={`inline-flex items-center px-2 py-0.5 text-xs font-semibold rounded-md border ${badge.color}`}>
            {badge.label}
        </span>
    );
}

function formatTimestamp(ts: string): string {
    try {
        const d = new Date(ts);
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ' ' +
            d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    } catch {
        return ts;
    }
}

const PAGE_SIZE = 25;

export default function AuditTab() {
    const { addToast } = useToast();
    const [page, setPage] = useState(0);
    const [actionFilter, setActionFilter] = useState('');
    const [usernameFilter, setUsernameFilter] = useState('');
    const [searchInput, setSearchInput] = useState('');

    const [selectedAction, setSelectedAction] = useState<PendingAction | null>(null);
    const [selectedService, setSelectedService] = useState<string | null>(null);
    const [isFetchingDetail, setIsFetchingDetail] = useState(false);

    const buildKey = useCallback(() => {
        const params = new URLSearchParams();
        params.set('limit', String(PAGE_SIZE));
        params.set('offset', String(page * PAGE_SIZE));
        if (actionFilter) params.set('action', actionFilter);
        if (usernameFilter) params.set('username', usernameFilter);
        return `/api/v1/admin/audit-log?${params.toString()}`;
    }, [page, actionFilter, usernameFilter]);

    const { data, isLoading, isValidating, error, mutate } = useSWR<AuditResponse>(buildKey(), {
        refreshInterval: 10000,
        revalidateOnFocus: true,
    });

    const entries = data?.entries || [];
    const total = data?.total || 0;
    const totalPages = Math.ceil(total / PAGE_SIZE);

    const handleSearch = () => {
        setUsernameFilter(searchInput.trim());
        setPage(0);
    };

    const handleRowClick = async (entry: AuditEntry) => {
        if (entry.target_type === 'pending_action') {
            const id = parseInt(entry.target_id, 10);
            if (isNaN(id)) return;
            
            setIsFetchingDetail(true);
            try {
                const res = await apiFetch(`/api/v1/admin/actions/${id}`);
                if (res.ok) {
                    const actionData = await res.json();
                    setSelectedAction(actionData);
                } else {
                    addToast('Failed to load action details', 'error');
                }
            } catch {
                addToast('Network error loading action', 'error');
            } finally {
                setIsFetchingDetail(false);
            }
        } else if (entry.target_type === 'service') {
            setSelectedService(entry.target_id);
        }
    };

    const availableActions = Object.keys(ACTION_BADGE_MAP);

    const operatorActionsCount = entries.filter(e => e.action.startsWith('action_')).length;
    const aiActionsCount = entries.filter(e => e.action.includes('ai_')).length;
    const systemActionsCount = entries.filter(e => e.action.includes('service_') || e.action.includes('system') || e.action.includes('user_')).length;

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-w-0">
            {/* Open Top Toolbar with Inline Controls */}
            <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-2 border-b border-white/[0.06] relative z-30 shrink-0">
                <div className="flex items-center gap-3.5">
                    <div className="h-10 w-10 rounded-xl flex items-center justify-center border bg-indigo-500/20 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.15)] text-indigo-400">
                        <FileText size={20} />
                    </div>
                    <div>
                        <div className="flex items-center gap-2.5">
                            <h2 className="text-lg font-bold text-slate-100 tracking-tight">Audit Trail &amp; Compliance</h2>
                            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
                                Immutable Spine
                            </span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className="relative flex h-1.5 w-1.5">
                                <span className="absolute inline-flex h-full w-full rounded-full opacity-75 bg-emerald-400"></span>
                                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                            </span>
                            <span className="text-xs text-slate-400 font-medium tracking-wide">
                                Live Event Logging &middot; {total} events indexed
                            </span>
                        </div>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                    {/* Inline Actor Search */}
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
                        <input
                            type="text"
                            value={searchInput}
                            onChange={(e) => setSearchInput(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                            placeholder="Filter by actor..."
                            className="pl-8 pr-3 py-1.5 bg-white/[0.04] border border-white/10 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50 w-40 sm:w-48 transition-all"
                        />
                    </div>

                    {/* Inline Action Filter Dropdown */}
                    <div className="relative">
                        <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none" />
                        <select
                            value={actionFilter}
                            onChange={(e) => { setActionFilter(e.target.value); setPage(0); }}
                            className="pl-8 pr-7 py-1.5 bg-white/[0.04] border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-indigo-500/50 appearance-none cursor-pointer"
                        >
                            <option value="" className="bg-slate-900 text-slate-200">All Actions</option>
                            {availableActions.map(a => (
                                <option key={a} value={a} className="bg-slate-900 text-slate-200">{ACTION_BADGE_MAP[a].label}</option>
                            ))}
                        </select>
                    </div>

                    <button
                        onClick={handleSearch}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold shadow-md shadow-indigo-500/20 transition-all"
                    >
                        Filter
                    </button>

                    <button
                        onClick={() => mutate()}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all"
                        title="Refresh Logs"
                    >
                        <RefreshCw size={13} className={isValidating ? 'animate-spin text-indigo-400' : 'text-slate-400'} />
                        <span>Refresh</span>
                    </button>
                </div>
            </div>

            {/* Open 4-Card Summary Strip */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Total Events</p>
                        <p className="text-2xl font-bold text-slate-100 mt-1">{total}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">Recorded in SQLite spine</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                        <FileText size={20} />
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Operator Approvals</p>
                        <p className="text-2xl font-bold text-emerald-400 mt-1">{operatorActionsCount}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">Resolved in active page</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                        <CheckCircle2 size={20} />
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">AI Operations</p>
                        <p className="text-2xl font-bold text-purple-400 mt-1">{aiActionsCount}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">FlowAI proposals</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                        <Zap size={20} />
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">System &amp; Roles</p>
                        <p className="text-2xl font-bold text-cyan-400 mt-1">{systemActionsCount}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">Service &amp; privilege events</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                        <Shield size={20} />
                    </div>
                </div>
            </div>

            {/* Error banner */}
            {error && (
                <div className="rounded-2xl border border-red-500/20 bg-red-950/20 p-4 text-center">
                    <Activity className="w-6 h-6 text-red-400 mx-auto mb-1" />
                    <p className="text-red-300 font-medium text-xs">Failed to load audit log</p>
                    <p className="text-[11px] text-slate-500 mt-0.5">Check admin access and backend connectivity.</p>
                </div>
            )}

            {/* Audit Log Table */}
            <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl overflow-hidden">
                {isLoading && !data ? (
                    <div className="p-12 text-center text-slate-500 text-xs flex items-center justify-center gap-2">
                        <RefreshCw size={16} className="animate-spin text-indigo-400" />
                        <span>Loading audit entries...</span>
                    </div>
                ) : entries.length === 0 ? (
                    <div className="p-12 text-center">
                        <FileText className="w-10 h-10 text-slate-600 mx-auto mb-2" />
                        <p className="text-sm font-semibold text-slate-300">No audit entries found</p>
                        <p className="text-xs text-slate-500 mt-1">Try adjusting your filters or actor search.</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-xs text-left border-collapse">
                            <thead>
                                <tr className="border-b border-white/[0.06] text-slate-400 uppercase tracking-wider text-[11px]">
                                    <th className="py-2.5 px-3.5 font-semibold">
                                        <div className="flex items-center gap-1.5"><Clock size={12} /> Time</div>
                                    </th>
                                    <th className="py-2.5 px-3.5 font-semibold">
                                        <div className="flex items-center gap-1.5"><User size={12} /> Actor</div>
                                    </th>
                                    <th className="py-2.5 px-3.5 font-semibold">Action</th>
                                    <th className="py-2.5 px-3.5 font-semibold">Target</th>
                                    <th className="py-2.5 px-3.5 font-semibold">Detail</th>
                                    <th className="py-2.5 px-3.5 font-semibold">IP</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-white/[0.04]">
                                {entries.map((entry) => (
                                    <tr 
                                        key={entry.id} 
                                        className={`transition-colors ${entry.target_type === 'pending_action' || entry.target_type === 'service' ? 'hover:bg-white/[0.04] cursor-pointer' : 'hover:bg-white/[0.02]'}`}
                                        onClick={() => handleRowClick(entry)}
                                    >
                                        <td className="py-3 px-3.5 text-slate-400 whitespace-nowrap font-mono text-[11px]">
                                            {formatTimestamp(entry.created_at)}
                                        </td>
                                        <td className="py-3 px-3.5">
                                            <span className="text-slate-200 font-semibold">{entry.username}</span>
                                        </td>
                                        <td className="py-3 px-3.5">
                                            <ActionBadge action={entry.action} />
                                        </td>
                                        <td className="py-3 px-3.5">
                                            <span className="text-slate-300 text-[11px] font-mono">
                                                {entry.target_type}/{entry.target_id}
                                            </span>
                                        </td>
                                        <td className="py-3 px-3.5">
                                            <span className="text-slate-400 text-xs max-w-[220px] truncate block" title={entry.detail}>
                                                {entry.detail || '—'}
                                            </span>
                                        </td>
                                        <td className="py-3 px-3.5 text-slate-500 text-[11px] font-mono">{entry.ip_address}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}

                {/* Pagination */}
                {totalPages > 1 && (
                    <div className="flex items-center justify-between px-4 py-3 border-t border-white/[0.06] text-xs">
                        <span className="text-slate-500">
                            Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total}
                        </span>
                        <div className="flex items-center gap-2">
                            <button
                                onClick={() => setPage(p => Math.max(0, p - 1))}
                                disabled={page === 0}
                                className="p-1.5 rounded-lg bg-white/[0.03] border border-white/[0.08] hover:bg-white/[0.06] disabled:opacity-30 disabled:cursor-not-allowed transition-all"
                            >
                                <ChevronLeft size={14} className="text-slate-400" />
                            </button>
                            <span className="text-slate-300 font-medium px-2">
                                {page + 1} / {totalPages}
                            </span>
                            <button
                                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                                disabled={page >= totalPages - 1}
                                className="p-1.5 rounded-lg bg-white/[0.03] border border-white/[0.08] hover:bg-white/[0.06] disabled:opacity-30 disabled:cursor-not-allowed transition-all"
                            >
                                <ChevronRight size={14} className="text-slate-400" />
                            </button>
                        </div>
                    </div>
                )}
            </div>

            {/* Context Modals */}
            <ActionDetailModal
                action={selectedAction}
                isOpen={!!selectedAction}
                onClose={() => setSelectedAction(null)}
                onApprove={async (id) => {
                    if (selectedAction?.source === 'FlowAI') {
                        const match = selectedAction.action.match(/^(Restart|Stop|Start)\s+(.+)$/i);
                        if (match) {
                            try {
                                await apiFetch(`/api/v1/admin/services/${encodeURIComponent(match[2])}/control`, {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ action: match[1].toLowerCase(), process: match[2] })
                                });
                            } catch {}
                        }
                    }
                    apiFetch(`/api/v1/admin/actions/${id}/approve`, { method: 'POST' }).then(() => {
                        addToast('Action authorized', 'success');
                        setSelectedAction(null);
                        mutate();
                    }).catch(() => addToast('Failed to authorize action', 'error'));
                }}
                onReject={(id) => {
                    apiFetch(`/api/v1/admin/actions/${id}/reject`, { method: 'POST' }).then(() => {
                        addToast('Action rejected', 'success');
                        setSelectedAction(null);
                        mutate();
                    }).catch(() => addToast('Failed to reject action', 'error'));
                }}
                isProcessing={isFetchingDetail}
            />

            {selectedService && (
                <ServiceLogsModal
                    serviceName={selectedService}
                    onClose={() => setSelectedService(null)}
                />
            )}
        </div>
    );
}
